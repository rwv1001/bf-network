#!/bin/bash
# firmware-manager.sh
#
# Manages git-based firmware updates for the bf-network stack.
# Called from inside the captive portal web container. The git repo and
# docker compose plugin are mounted into the container at their real host
# paths so git and docker compose work natively — no nsenter required.
#
# Configuration via environment variables (set in docker-compose.yml):
#   GIT_REPO_DIR   Root of the git repository (default: parent of this script's directory)
#
# Usage:
#   firmware-manager.sh status      — print JSON status blob
#   firmware-manager.sh update      — advance to next commit and restart affected stacks
#   firmware-manager.sh rollback    — revert to previous commit and restart affected stacks

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_REPO_DIR="${GIT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ACTION="${1:-status}"

_log() { echo "[firmware-manager] $*" >&2; }

# ---------------------------------------------------------------------------
# Helper: list of top-level directories that have a docker-compose.yml AND
#         appear in the provided newline-separated list of changed paths.
# ---------------------------------------------------------------------------
_compose_dirs_for_changes() {
    local changed_dirs="$1"
    local result=()
    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        if [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" ]]; then
            result+=("$d")
        fi
    done <<< "$changed_dirs"
    printf '%s\n' "${result[@]}"
}

# ---------------------------------------------------------------------------
# Helper: restart one docker-compose stack synchronously.
# Special-case: captive-portal restarts itself last and skips the explicit
# 'down' step — the container running this script lives inside that stack,
# so 'docker compose down' would kill us.  Instead we do
# 'docker compose up -d --build' which tells the Docker daemon to rebuild
# and recreate the container (the daemon handles stopping the old one).
# The SSE stream will disconnect when the old container dies; the frontend
# should detect this and prompt the user to refresh.
# ---------------------------------------------------------------------------
_SELF_STACK="captive-portal"   # directory name of the stack we're running in
RESTART_QUEUE_DIR="${RESTART_QUEUE_DIR:-/restart-queue}"

_restart_stack() {
    local dir="$1"
    local compose_dir="$GIT_REPO_DIR/$dir"
    cd "$compose_dir"

    if [[ "$dir" == "$_SELF_STACK" ]]; then
        # We cannot restart ourselves directly — Docker would kill this process
        # before the new container starts.  Instead, write a job script to the
        # shared restart-queue so the docker-agent sidecar picks it up and runs
        # the restart after we die.
        echo "=== Restarting stack: $dir (queuing for docker-agent) ==="
        local job_file="$RESTART_QUEUE_DIR/restart-${dir}-$(date +%s%N).sh"
        cat > "$job_file" <<JOBSCRIPT
#!/bin/bash
set -uo pipefail
echo "[docker-agent] Restarting $dir at \$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cd "$compose_dir"
docker compose up -d --build --force-recreate
echo "[docker-agent] $dir restart complete, exit \$?"
JOBSCRIPT
        chmod +x "$job_file"
        echo "  [job queued: $(basename "$job_file")]"
        echo "  NOTE: The docker-agent will restart this container momentarily."
        echo "  Please refresh the firmware page in ~30 seconds."
    else
        echo "=== Restarting stack: $dir ==="
        docker compose down   && echo "  [down OK]"
        docker compose build  && echo "  [build OK]"
        docker compose up -d  && echo "  [up OK]"
    fi

    cd "$GIT_REPO_DIR"
    echo "=== Done: $dir ==="
}


# ---------------------------------------------------------------------------
# Helper: safely get short hash — returns empty string on failure
# ---------------------------------------------------------------------------
_short() { git -C "$GIT_REPO_DIR" rev-parse --short "$1" 2>/dev/null || true; }
_subject() { git -C "$GIT_REPO_DIR" log -1 --pretty=format:'%s' "$1" 2>/dev/null || true; }
_full() { git -C "$GIT_REPO_DIR" rev-parse "$1" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# status — emit JSON describing current / next / previous commits
# ---------------------------------------------------------------------------
_cmd_status() {
    cd "$GIT_REPO_DIR"

    CURRENT_FULL=$(_full HEAD)
    CURRENT_SHORT=$(_short HEAD)
    CURRENT_SUBJECT=$(_subject HEAD)

    # Next commit: search all refs for a commit whose parent is HEAD.
    # Using --all ensures children of HEAD are visible even in detached-HEAD state.
    CURRENT_HASH=$(git rev-parse HEAD) 
    NEXT_FULL=$(git rev-list --children --all 2>/dev/null \
        | awk -v h="$CURRENT_HASH" '$1==h {print $2; exit}')
    NEXT_SHORT=""
    NEXT_SUBJECT=""
    if [[ -n "$NEXT_FULL" && "$NEXT_FULL" != "$CURRENT_FULL" ]]; then
        NEXT_SHORT=$(_short "$NEXT_FULL")
        NEXT_SUBJECT=$(_subject "$NEXT_FULL")
    else
        NEXT_FULL=""
    fi

    # Previous commit
    PREV_FULL=$(_full "HEAD^" 2>/dev/null || true)
    PREV_SHORT=""
    PREV_SUBJECT=""
    if [[ -n "$PREV_FULL" ]]; then
        PREV_SHORT=$(_short "$PREV_FULL")
        PREV_SUBJECT=$(_subject "$PREV_FULL")
    fi

    # Changed dirs for forward (HEAD → next)
    FORWARD_DIRS_JSON="[]"
    if [[ -n "$NEXT_FULL" ]]; then
        mapfile -t fdirs < <(
            git diff --name-only HEAD "$NEXT_FULL" 2>/dev/null \
                | cut -d/ -f1 | sort -u
        )
        compose_fdirs=()
        for d in "${fdirs[@]}"; do
            [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" ]] && compose_fdirs+=("\"$d\"")
        done
        FORWARD_DIRS_JSON="[$(IFS=,; echo "${compose_fdirs[*]}")]"
    fi

    # Changed dirs for rollback (HEAD^ → HEAD)
    BACK_DIRS_JSON="[]"
    if [[ -n "$PREV_FULL" ]]; then
        mapfile -t bdirs < <(
            git diff --name-only HEAD^ HEAD 2>/dev/null \
                | cut -d/ -f1 | sort -u
        )
        compose_bdirs=()
        for d in "${bdirs[@]}"; do
            [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" ]] && compose_bdirs+=("\"$d\"")
        done
        BACK_DIRS_JSON="[$(IFS=,; echo "${compose_bdirs[*]}")]"
    fi

    # JSON-escape a string (minimal: escape backslash, double-quote, and common control chars)
    _json_str() {
        local s="$1"
        s="${s//\\/\\\\}"
        s="${s//\"/\\\"}"
        echo -n "$s"
    }

    cat <<JSON
{
  "current_full":   "$(_json_str "$CURRENT_FULL")",
  "current_short":  "$(_json_str "$CURRENT_SHORT")",
  "current_subject":"$(_json_str "$CURRENT_SUBJECT")",
  "next_full":      "$(_json_str "$NEXT_FULL")",
  "next_short":     "$(_json_str "$NEXT_SHORT")",
  "next_subject":   "$(_json_str "$NEXT_SUBJECT")",
  "prev_full":      "$(_json_str "$PREV_FULL")",
  "prev_short":     "$(_json_str "$PREV_SHORT")",
  "prev_subject":   "$(_json_str "$PREV_SUBJECT")",
  "forward_dirs":   $FORWARD_DIRS_JSON,
  "back_dirs":      $BACK_DIRS_JSON,
  "repo_dir":       "$(_json_str "$GIT_REPO_DIR")"
}
JSON
}

# ---------------------------------------------------------------------------
# update — advance HEAD to next commit, restart affected compose stacks
# ---------------------------------------------------------------------------
_cmd_update() {
    cd "$GIT_REPO_DIR"

    CURRENT_HASH=$(git rev-parse HEAD)
    NEXT_FULL=$(git rev-list --children --all 2>/dev/null \
        | awk -v h="$CURRENT_HASH" '$1==h {print $2; exit}')
    if [[ -z "$NEXT_FULL" || "$NEXT_FULL" == "$(git rev-parse HEAD)" ]]; then
        echo "ERROR: Already on the latest commit — nowhere to go forward."
        exit 1
    fi

    echo "Current commit: $(git rev-parse --short HEAD) — $(git log -1 --pretty=format:'%s')"
    echo "Advancing to:   $(git rev-parse --short "$NEXT_FULL") — $(git log -1 --pretty=format:'%s' "$NEXT_FULL")"
    echo ""

    # Find affected compose dirs BEFORE checkout
    mapfile -t CHANGED < <(
        git diff --name-only HEAD "$NEXT_FULL" 2>/dev/null \
            | cut -d/ -f1 | sort -u
    )

    echo "Changed top-level directories:"
    for d in "${CHANGED[@]}"; do echo "  - $d"; done
    echo ""

    # Checkout the next commit
    git checkout "$NEXT_FULL"
    echo "Checked out: $(git rev-parse --short HEAD)"
    echo ""

    # Sort: captive-portal last so the self-restart happens after all others.
    declare -a RESTART_FIRST=() RESTART_LAST=()
    for d in "${CHANGED[@]}"; do
        [[ "$d" == "$_SELF_STACK" ]] && RESTART_LAST+=("$d") || RESTART_FIRST+=("$d")
    done

    # Restart each affected compose stack synchronously
    for d in "${RESTART_FIRST[@]}" "${RESTART_LAST[@]}"; do
        if [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" ]]; then
            _restart_stack "$d"
            echo ""
        else
            echo "--- $d: no docker-compose.yml, skipping container restart ---"
        fi
    done

    echo "UPDATE COMPLETE: now at $(git rev-parse --short HEAD)"
}

# ---------------------------------------------------------------------------
# rollback — revert HEAD to previous commit, restart affected compose stacks
# ---------------------------------------------------------------------------
_cmd_rollback() {
    cd "$GIT_REPO_DIR"

    PREV_FULL=$(_full "HEAD^" 2>/dev/null || true)
    if [[ -z "$PREV_FULL" ]]; then
        echo "ERROR: Already on the first commit — cannot roll back further."
        exit 1
    fi

    echo "Current commit:  $(git rev-parse --short HEAD) — $(git log -1 --pretty=format:'%s')"
    echo "Rolling back to: $(git rev-parse --short "$PREV_FULL") — $(git log -1 --pretty=format:'%s' "$PREV_FULL")"
    echo ""

    # Find affected compose dirs BEFORE checkout (diff HEAD^ → HEAD)
    mapfile -t CHANGED < <(
        git diff --name-only HEAD^ HEAD 2>/dev/null \
            | cut -d/ -f1 | sort -u
    )

    echo "Changed top-level directories:"
    for d in "${CHANGED[@]}"; do echo "  - $d"; done
    echo ""

    # Checkout the previous commit
    git checkout HEAD^
    echo "Checked out: $(git rev-parse --short HEAD)"
    echo ""

    # Sort: captive-portal last so the self-restart happens after all others.
    declare -a RESTART_FIRST=() RESTART_LAST=()
    for d in "${CHANGED[@]}"; do
        [[ "$d" == "$_SELF_STACK" ]] && RESTART_LAST+=("$d") || RESTART_FIRST+=("$d")
    done

    # Restart each affected compose stack synchronously
    for d in "${RESTART_FIRST[@]}" "${RESTART_LAST[@]}"; do
        if [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" ]]; then
            _restart_stack "$d"
            echo ""
        else
            echo "--- $d: no docker-compose.yml, skipping container restart ---"
        fi
    done

    echo "ROLLBACK COMPLETE: now at $(git rev-parse --short HEAD)"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$ACTION" in
    status)        _cmd_status        ;;
    update)        _cmd_update        ;;
    rollback)      _cmd_rollback      ;;
    restart-dirs)
        # Usage: firmware-manager.sh restart-dirs dir1 dir2 ...
        # Restarts the given compose-stack directories, captive-portal last.
        shift
        declare -a RESTART_FIRST=() RESTART_LAST=()
        for d in "$@"; do
            [[ "$d" == "$_SELF_STACK" ]] && RESTART_LAST+=("$d") || RESTART_FIRST+=("$d")
        done
        for d in "${RESTART_FIRST[@]}" "${RESTART_LAST[@]}"; do
            if [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" ]]; then
                _restart_stack "$d"
                echo ""
            else
                echo "--- $d: no docker-compose.yml, skipping ---"
            fi
        done
        echo "RESTART COMPLETE"
        ;;
    *)
        echo "Unknown action: $ACTION" >&2
        echo "Usage: $0 {status|update|rollback|restart-dirs [dirs...]}" >&2
        exit 1
        ;;
esac

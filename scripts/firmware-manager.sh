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
# Stack dependency mapping: if files in KEY directory change, also restart
# the VALUE stack.  Used when a directory has no docker-compose.yml of its
# own but its build artifacts are consumed by another stack — e.g. kea-hooks
# compiles a .so that is volume-mounted into the kea container.
# ---------------------------------------------------------------------------
declare -A STACK_DEPS=(
    ["kea-hooks"]="kea"
)

# Expand a list of changed top-level dirs into compose stacks to restart.
# Includes dirs that have their own docker-compose.yml *plus* any stacks
# declared in STACK_DEPS above.  Output is deduplicated, order preserved.
_dirs_to_stacks() {
    local -A seen=()
    local -a result=()
    for d in "$@"; do
        [[ -z "$d" ]] && continue
        if [[ -f "$GIT_REPO_DIR/$d/docker-compose.yml" && -z "${seen[$d]:-}" ]]; then
            result+=("$d")
            seen["$d"]=1
        fi
        local dep="${STACK_DEPS[$d]:-}"
        if [[ -n "$dep" && -z "${seen[$dep]:-}" ]]; then
            result+=("$dep")
            seen["$dep"]=1
        fi
    done
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
        # Non-self stacks also use the restart-queue so docker-agent (running
        # as root) performs the docker compose call.  The web container process
        # runs as an unprivileged UID and cannot access /var/run/docker.sock
        # directly.
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
        echo "  NOTE: docker-agent will restart this stack in the background."
    fi

    cd "$GIT_REPO_DIR"
    echo "=== Done: $dir ==="
}

# === Improved Changed Dirs Detection (more robust) ===

_get_affected_stacks() {
    local base="$1"
    local target="$2"

    local -A seen=()
    local -a stacks=()

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue

        dir=$(dirname "$path")

        # Walk up looking for docker-compose.yml
        found=false
        while [[ "$dir" != "." && "$dir" != "/" ]]; do
            if [[ -f "$GIT_REPO_DIR/$dir/docker-compose.yml" ]]; then
                if [[ -z "${seen[$dir]:-}" ]]; then
                    stacks+=("$dir")
                    seen["$dir"]=1
                fi
                found=true
                break
            fi
            dir=$(dirname "$dir")
        done

        # If we reached root and it has docker-compose.yml, treat root as the stack
        if [[ "$found" == false ]]; then
            if [[ -f "$GIT_REPO_DIR/docker-compose.yml" && -z "${seen[root]:-}" ]]; then
                stacks+=(".")
                seen["root"]=1
            fi
        fi

    done < <(git diff --name-only "$base" "$target" 2>/dev/null)

    printf '%s\n' "${stacks[@]}"
}

# ---------------------------------------------------------------------------
# Helper: safely get short hash — returns empty string on failure
# ---------------------------------------------------------------------------
_short() { git -C "$GIT_REPO_DIR" rev-parse --short "$1" 2>/dev/null || true; }
_subject() { git -C "$GIT_REPO_DIR" log -1 --pretty=format:'%s' "$1" 2>/dev/null || true; }
_full() { git -C "$GIT_REPO_DIR" rev-parse "$1" 2>/dev/null || true; }
# JSON-escape a string (minimal: escape backslash and double-quote)
_json_str() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; echo -n "$s"; }

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
                | cut -d/ -f1 | sort -u | grep -v '^$'
        )
        mapfile -t _fstacks < <(_get_affected_stacks "HEAD" "$NEXT_FULL")
        compose_fdirs=()
        for d in "${_fstacks[@]}"; do 
            [[ -n "$d" ]] && compose_fdirs+=("\"$d\"")
        done
        FORWARD_DIRS_JSON="[$(IFS=,; echo "${compose_fdirs[*]}")]"
    fi

    # Changed dirs for rollback (HEAD^ → HEAD)
    BACK_DIRS_JSON="[]"
    if [[ -n "$PREV_FULL" ]]; then
        mapfile -t bdirs < <(
            git diff --name-only HEAD^ HEAD 2>/dev/null \
                | cut -d/ -f1 | sort -u | grep -v '^$'
        )
        mapfile -t _bstacks < <(_get_affected_stacks "HEAD^" "HEAD")
        compose_bdirs=()
        for d in "${_bstacks[@]}"; do
            [[ -n "$d" ]] && compose_bdirs+=("\"$d\"")
        done
        BACK_DIRS_JSON="[$(IFS=,; echo "${compose_bdirs[*]}")]"
    fi

    # Walk ALL commits ahead to find latest and the full chain
    COMMITS_AHEAD_JSON="[]"
    LATEST_FULL=""
    LATEST_SHORT=""
    LATEST_SUBJECT=""
    if [[ -n "$NEXT_FULL" ]]; then
        AHEAD_HASHES=()
        CUR_WALK="$NEXT_FULL"
        PREV_WALK="$CURRENT_FULL"
        while true; do
            AHEAD_HASHES+=("$CUR_WALK:$PREV_WALK")
            N=$(git rev-list --children --all 2>/dev/null \
                | awk -v h="$CUR_WALK" '$1==h {print $2; exit}')
            [[ -z "$N" || "$N" == "$CUR_WALK" ]] && break
            PREV_WALK="$CUR_WALK"
            CUR_WALK="$N"
        done
        LATEST_FULL="$CUR_WALK"
        LATEST_SHORT=$(_short "$LATEST_FULL")
        LATEST_SUBJECT=$(_subject "$LATEST_FULL")

        # Changed dirs for full-forward (HEAD → latest)
        LATEST_DIRS_JSON="[]"
        mapfile -t ldirs < <(
            git diff --name-only HEAD "$LATEST_FULL" 2>/dev/null \
                | cut -d/ -f1 | sort -u | grep -v '^$'
        )
        mapfile -t _lstacks < <(_get_affected_stacks "HEAD" "$LATEST_FULL")
        compose_ldirs=()
        for d in "${_lstacks[@]}"; do 
            [[ -n "$d" ]] && compose_ldirs+=("\"$d\"")
        done
        LATEST_DIRS_JSON="[$(IFS=,; echo "${compose_ldirs[*]}")]"

        # Build commits_ahead JSON array: [{full, short, subject, from_full, from_short}]
        items=()
        for entry in "${AHEAD_HASHES[@]}"; do
            h="${entry%%:*}"
            p="${entry##*:}"
            s=$(_short "$h")
            sub=$(_subject "$h")
            ps=$(_short "$p")
            items+=("{\"full\":\"$(_json_str "$h")\",\"short\":\"$(_json_str "$s")\",\"subject\":\"$(_json_str "$sub")\",\"from_full\":\"$(_json_str "$p")\",\"from_short\":\"$(_json_str "$ps")\"}")
        done
        COMMITS_AHEAD_JSON="[$(IFS=,; echo "${items[*]}")]"
    fi

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
  "latest_full":    "$(_json_str "$LATEST_FULL")",
  "latest_short":   "$(_json_str "$LATEST_SHORT")",
  "latest_subject": "$(_json_str "$LATEST_SUBJECT")",
  "forward_dirs":   $FORWARD_DIRS_JSON,
  "back_dirs":      $BACK_DIRS_JSON,
  "latest_dirs":    ${LATEST_DIRS_JSON:-[]},
  "commits_ahead":  $COMMITS_AHEAD_JSON,
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

    # Checkout the next commit (force to overwrite any untracked working-tree changes)
    git checkout -f "$NEXT_FULL"
    echo "Checked out: $(git rev-parse --short HEAD)"
    echo ""

    # Expand CHANGED dirs with STACK_DEPS (e.g. kea-hooks → kea)
    mapfile -t CHANGED_STACKS < <(_dirs_to_stacks "${CHANGED[@]}")

    # Sort: captive-portal last so the self-restart happens after all others.
    declare -a RESTART_FIRST=() RESTART_LAST=()
    for d in "${CHANGED_STACKS[@]}"; do
        [[ "$d" == "$_SELF_STACK" ]] && RESTART_LAST+=("$d") || RESTART_FIRST+=("$d")
    done

    # Restart each affected compose stack synchronously
    for d in "${RESTART_FIRST[@]}" "${RESTART_LAST[@]}"; do
        _restart_stack "$d"
        echo ""
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

    # Checkout the previous commit (force to overwrite any untracked working-tree changes)
    git checkout -f HEAD^
    echo "Checked out: $(git rev-parse --short HEAD)"
    echo ""

    # Expand CHANGED dirs with STACK_DEPS (e.g. kea-hooks → kea)
    mapfile -t CHANGED_STACKS < <(_dirs_to_stacks "${CHANGED[@]}")

    # Sort: captive-portal last so the self-restart happens after all others.
    declare -a RESTART_FIRST=() RESTART_LAST=()
    for d in "${CHANGED_STACKS[@]}"; do
        [[ "$d" == "$_SELF_STACK" ]] && RESTART_LAST+=("$d") || RESTART_FIRST+=("$d")
    done

    # Restart each affected compose stack synchronously
    for d in "${RESTART_FIRST[@]}" "${RESTART_LAST[@]}"; do
        _restart_stack "$d"
        echo ""
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

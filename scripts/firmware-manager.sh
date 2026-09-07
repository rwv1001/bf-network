#!/bin/bash
#
# firmware-manager.sh
#
# Provides git status information for the firmware management system.
# No longer performs automatic container restarts.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_REPO_DIR="${GIT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ACTION="${1:-status}"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

_short()   { git -C "$GIT_REPO_DIR" rev-parse --short "$1" 2>/dev/null || true; }
_subject() { git -C "$GIT_REPO_DIR" log -1 --pretty=format:'%s' "$1" 2>/dev/null || true; }
_full()    { git -C "$GIT_REPO_DIR" rev-parse "$1" 2>/dev/null || true; }

_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    echo -n "$s"
}

# Improved detection: walks up the directory tree to find the nearest
# docker-compose.yml, and falls back to root if needed.
_get_affected_stacks() {
    local base="$1"
    local target="$2"
    local -A seen=()
    local -a stacks=()

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        dir=$(dirname "$path")

        while [[ "$dir" != "." && "$dir" != "/" ]]; do
            if [[ -f "$GIT_REPO_DIR/$dir/docker-compose.yml" ]]; then
                [[ -z "${seen[$dir]:-}" ]] && stacks+=("$dir") && seen["$dir"]=1
                break
            fi
            dir=$(dirname "$dir")
        done

        # Root fallback
        if [[ "$dir" == "." || "$dir" == "/" ]]; then
            if [[ -f "$GIT_REPO_DIR/docker-compose.yml" && -z "${seen[root]:-}" ]]; then
                stacks+=(".")
                seen["root"]=1
            fi
        fi
    done < <(git diff --name-only "$base" "$target" 2>/dev/null)

    printf '%s\n' "${stacks[@]}"
}

# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------
_cmd_status() {
    cd "$GIT_REPO_DIR" || exit 1

    # Pick up new commits from GitHub (tolerate offline/slow network)
    timeout 20 git -C "$GIT_REPO_DIR" fetch --quiet origin 2>/dev/null || true

    UPSTREAM=""
    for ref in origin/main origin/HEAD; do
        if git -C "$GIT_REPO_DIR" rev-parse --verify --quiet "$ref" >/dev/null 2>&1; then
            UPSTREAM="$ref"
            break
        fi
    done

    CURRENT_FULL=$(_full HEAD)
    CURRENT_SHORT=$(_short HEAD)
    CURRENT_SUBJECT=$(_subject HEAD)

    # First-parent chain of commits between HEAD and upstream, oldest first
    AHEAD=()
    if [[ -n "$UPSTREAM" ]]; then
        mapfile -t AHEAD < <(git -C "$GIT_REPO_DIR" rev-list --reverse --first-parent "HEAD..$UPSTREAM" 2>/dev/null)
    fi

    NEXT_FULL=""; NEXT_SHORT=""; NEXT_SUBJECT=""
    LATEST_FULL=""; LATEST_SHORT=""; LATEST_SUBJECT=""
    COMMITS_AHEAD_JSON="[]"
    if (( ${#AHEAD[@]} > 0 )); then
        NEXT_FULL="${AHEAD[0]}"
        NEXT_SHORT=$(_short "$NEXT_FULL")
        NEXT_SUBJECT=$(_subject "$NEXT_FULL")
        LATEST_FULL="${AHEAD[${#AHEAD[@]}-1]}"
        LATEST_SHORT=$(_short "$LATEST_FULL")
        LATEST_SUBJECT=$(_subject "$LATEST_FULL")

        prev="$CURRENT_FULL"
        entries=()
        for c in "${AHEAD[@]}"; do
            entries+=("{\"full\":\"$c\",\"short\":\"$(_short "$c")\",\"subject\":\"$(_json_str "$(_subject "$c")")\",\"from_full\":\"$prev\"}")
            prev="$c"
        done
        COMMITS_AHEAD_JSON="[$(IFS=,; echo "${entries[*]}")]"
    fi

    PREV_FULL=$(_full "HEAD^" 2>/dev/null || true)
    PREV_SHORT=""
    PREV_SUBJECT=""
    if [[ -n "$PREV_FULL" ]]; then
        PREV_SHORT=$(_short "$PREV_FULL")
        PREV_SUBJECT=$(_subject "$PREV_FULL")
    fi

    # Build affected stacks using improved detection
    FORWARD_DIRS_JSON="[]"
    if [[ -n "$NEXT_FULL" ]]; then
        mapfile -t _fstacks < <(_get_affected_stacks "HEAD" "$NEXT_FULL")
        compose_fdirs=()
        for d in "${_fstacks[@]}"; do [[ -n "$d" ]] && compose_fdirs+=("\"$d\""); done
        FORWARD_DIRS_JSON="[$(IFS=,; echo "${compose_fdirs[*]}")]"
    fi

    BACK_DIRS_JSON="[]"
    if [[ -n "$PREV_FULL" ]]; then
        mapfile -t _bstacks < <(_get_affected_stacks "HEAD^" "HEAD")
        compose_bdirs=()
        for d in "${_bstacks[@]}"; do [[ -n "$d" ]] && compose_bdirs+=("\"$d\""); done
        BACK_DIRS_JSON="[$(IFS=,; echo "${compose_bdirs[*]}")]"
    fi

    LATEST_DIRS_JSON="[]"
    if [[ -n "$LATEST_FULL" ]]; then
        mapfile -t _lstacks < <(_get_affected_stacks "HEAD" "$LATEST_FULL")
        compose_ldirs=()
        for d in "${_lstacks[@]}"; do [[ -n "$d" ]] && compose_ldirs+=("\"$d\""); done
        LATEST_DIRS_JSON="[$(IFS=,; echo "${compose_ldirs[*]}")]"
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
  "latest_dirs":    $LATEST_DIRS_JSON,
  "commits_ahead":  $COMMITS_AHEAD_JSON,
  "repo_dir":       "$(_json_str "$GIT_REPO_DIR")"
}
JSON
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$ACTION" in
    status)
        _cmd_status
        ;;
    *)
        echo "Usage: $0 status"
        exit 1
        ;;
esac
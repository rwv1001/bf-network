#!/usr/bin/env bash
set -euo pipefail

# Use all args as the commit message; default to a timestamp if none given
msg="${*:-"update: $(date -Iseconds)"}"

# Ensure we're inside a git repo
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "Not in a git repo. cd into your repo first." >&2
  exit 1
}

# Stage everything (new, modified, deleted)
git add -A

# Only commit if something is staged
if git diff --cached --quiet; then
  echo "No changes to commit."
else
  git commit -m "$msg"
fi

# Push (set upstream on first push, plain push thereafter)
branch="$(git rev-parse --abbrev-ref HEAD)"
if git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
  git push
else
  git push -u origin "$branch"
fi

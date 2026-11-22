# Backup sidecar: pg_dump that matches the server major version, plus gpg/curl.
# The script itself is bind-mounted from ./backup so a git update of the repo
# takes effect on the next container restart without rebuilding the image.
FROM postgres:15-alpine

RUN apk add --no-cache bash coreutils curl gnupg jq tar gzip

ENTRYPOINT ["/bin/bash", "/opt/bf-backup/bf-backup.sh"]
CMD ["daemon"]

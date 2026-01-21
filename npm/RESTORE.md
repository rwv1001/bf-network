# NPM (Nginx Proxy Manager) restore notes

This repo ignores NPM runtime data and certificates:

- npm/data/
- npm/letsencrypt/
- **/keys.json
- .env / any .env.*

If these are missing after a fresh clone/reset, NPM will start with an empty state.

## Quick restore (non‑secret)

1. Create the required directories:
   - npm/data
   - npm/letsencrypt
2. Start the stack:
   - docker compose up -d

## What you must restore from backup

To get existing hosts/certs/users back, restore:

- npm/data/ (database + config)
- npm/letsencrypt/ (certs)
- any NPM env file used for credentials

## Optional: helper script

Run `scripts/npm-setup.sh` to create directories and restart NPM.

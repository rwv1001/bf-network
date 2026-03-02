# Commit Migration Manifests

Each file in this directory describes the changes an admin must make to
environment variables and the database when **upgrading to** or **rolling back
from** a specific commit.

## File naming

```
<full_commit_hash>.json
```

The file is committed **in the same commit it describes** — so the manifest for
commit `abc1234…` lives at `commit-migrations/abc1234….json` inside that commit.
The firmware management page reads it via `git show <hash>:captive-portal/commit-migrations/<hash>.json`
so it is always read from the target commit, not the current working tree.

## Format

```json
{
  "description": "Human-readable summary of what this commit introduces",

  "env": {
    "add": [
      {
        "key":         "MY_NEW_VAR",
        "description": "What this variable controls",
        "default":     "",
        "required":    true,
        "sensitive":   false
      }
    ],
    "remove": ["OLD_VAR_NO_LONGER_NEEDED"]
  },

  "db": {
    "up":   "migrate-add-something.sh",
    "down": "migrate-remove-something.sh"
  },

  "notes": "Any extra information the admin should read before upgrading."
}
```

### Fields

| Field | Required | Description |
|---|---|---|
| `description` | yes | One-line summary shown on the firmware page |
| `env.add` | no | List of env vars the new code requires |
| `env.add[].key` | yes | The variable name (e.g. `SMTP_HOST`) |
| `env.add[].description` | yes | Plain-English description of the variable |
| `env.add[].default` | no | Suggested default value (empty string = no default) |
| `env.add[].required` | no | `true` → admin must fill it in before upgrade proceeds |
| `env.add[].sensitive` | no | `true` → rendered as a password input |
| `env.remove` | no | List of variable names that are no longer used |
| `db.up` | no | Script in `captive-portal/` to run **after** `git checkout` and **before** container restart |
| `db.down` | no | Script in `captive-portal/` to run **before** `git checkout HEAD^` on rollback |
| `notes` | no | Free-form text shown to the admin |

## Script conventions

Migration scripts live in the `captive-portal/` directory alongside
`migrate-add-*.sh`.  They must be idempotent (safe to run twice) and should
exit non-zero on failure so the firmware update aborts.

The scripts are executed inside the `captive-portal-web` container, which has
Docker socket access, so `docker exec captive-portal-db psql …` works as normal.

## Example

```json
{
  "description": "Add Microsoft Graph OAuth for admin login",
  "env": {
    "add": [
      {
        "key":         "MICROSOFT_CLIENT_ID",
        "description": "Azure app registration client ID",
        "default":     "",
        "required":    true,
        "sensitive":   false
      },
      {
        "key":         "MICROSOFT_CLIENT_SECRET",
        "description": "Azure app registration client secret",
        "default":     "",
        "required":    true,
        "sensitive":   true
      }
    ],
    "remove": []
  },
  "db": {
    "up":   "migrate-add-mfa.sh",
    "down": null
  },
  "notes": "Create the Azure app registration first — see MICROSOFT_GRAPH_SETUP.md."
}
```

## Commits with no migration

If a commit needs no env or database changes, **do not create a manifest file**
for it.  The firmware page will show a green "No migration needed" badge.

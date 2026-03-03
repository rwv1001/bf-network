# Commit Migration Manifests

Each file in this directory describes the changes an admin must make to
environment variables and the database when **upgrading to** or **rolling back
from** a specific commit.

## Naming convention

```
<from_commit_hash>.json
```

The file is named after the commit you are **leaving** (the current HEAD) and is
committed in the **next** commit (the one you are moving to).

Example: you are about to commit `B`.  Your current HEAD is `A`.  If `B` requires
new env vars or a DB migration, create `A.json` and include it in `B`'s commit.

When the firmware page evaluates an upgrade from `A → B` it runs:

```
git show B:captive-portal/commit-migrations/A.json
```

and when evaluating a rollback from `B → A` it runs the same command (still on
`B`'s tree) to find the `down` migration.

**If a commit introduces no env or DB changes, no manifest file is needed.**
The firmware page handles a missing file gracefully (no preflight form is shown).

### At‐a‐glance

| You are at | Moving to | File name | Committed in |
|---|---|---|---|
| `A` (current) | `B` (next) | `A.json` | `B` |
| `B` (current) | `A` (rollback) | `A.json` | `B` (still on B when rolling back) |

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
    "remove": [
      { "key": "OLD_VAR_NO_LONGER_NEEDED", "description": "What it was for", "required": false, "sensitive": false }
    ]
  },

  "db": {
    "up":   "migrate-add-something.sh",
    "down": "migrate-remove-something.sh",
    "verify_up": [
      {"type": "column", "table": "my_table", "column": "new_col"},
      {"type": "table",  "name":  "new_table"}
    ],
    "verify_down": [
      {"type": "column_absent", "table": "my_table", "column": "new_col"},
      {"type": "table_absent",  "name":  "new_table"}
    ]
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
| `env.remove` | no | List of variables removed by this commit. On **update** they are deleted from `.env`. On **rollback** the admin is prompted to re-enter their values. Never store actual values here — the form handles it. |
| `env.remove[].key` | yes | The variable name |
| `env.remove[].description` | no | Plain-English description shown in the rollback form |
| `env.remove[].required` | no | `true` → admin must fill in the value before rollback proceeds |
| `env.remove[].sensitive` | no | `true` → rendered as a password input |
| `db.up` | no | Script in `captive-portal/` to run **after** `git checkout` and **before** container restart |
| `db.down` | no | Script in `captive-portal/` to run **before** `git checkout HEAD^` on rollback |
| `db.verify_up` | no | Schema checks the **Test Update Successful** button runs to confirm the up-migration applied correctly |
| `db.verify_down` | no | Schema checks the **Test Rollback Successful** button runs to confirm the down-migration applied correctly |
| `notes` | no | Free-form text shown to the admin |

### `verify_up` / `verify_down` check types

| `type` | Required keys | Meaning |
|---|---|---|
| `column` | `table`, `column` | Assert the column **exists** |
| `column_absent` | `table`, `column` | Assert the column **does not exist** |
| `table` | `name` | Assert the table **exists** |
| `table_absent` | `name` | Assert the table **does not exist** |

## Script conventions

Migration scripts live in the `captive-portal/` directory alongside
`migrate-add-*.sh`.  They must be idempotent (safe to run twice) and should
exit non-zero on failure so the firmware update aborts.

The scripts are executed inside the `captive-portal-web` container, which has
Docker socket access, so `docker exec captive-portal-db psql …` works as normal.

## Example

Suppose your current HEAD is `abc1234…` and your next commit (`def5678…`) adds
Microsoft Graph OAuth.  In the same commit as `def5678…` you include the file
`captive-portal/commit-migrations/abc1234….json`:

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

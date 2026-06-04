# Blackfriars Network Portal — Current Project Context

## Current Architecture (Post-Refactor)

The application has been refactored into a clean structure:

- **`app.py`** — Slim application factory only. Contains `create_app()`, config, extension initialisation, blueprint registration, error handlers, and startup of background threads. **Do not put business logic here.**
- **`blueprints/portal.py`** — All public captive portal and user-facing routes (registration, login, user home, adoption, etc.).
- **`blueprints/admin/`** — Admin section. Uses nested blueprints (e.g. `admin.unregistered`, `admin.traffic`, `admin.firmware`, etc.).
- **`core/`** — Shared business logic and utilities (auth, device utils, network control, VLAN logic, sweepers, etc.).
- **`models.py`** — SQLAlchemy models.
- **`extensions.py`** — Flask extensions (`db`, `login_manager`, `csrf`).

## Key Principles

- **Database is the source of truth**.
- `internet_accessible = true` must **only** be set *after* DNS hijacks and HP5130 ACL blocks have actually been removed.
- DNS hijack + HP5130 ACL block must always be added/removed **together**.
- Background threads (sweepers + central client) manage their own `app.app_context()` inside their loops.
- Kea DHCP behaviour, RADIUS, and switch ACL logic must be respected exactly as described in `SYSTEM_SPEC.md`.

## Important Reminders

- **Kea + DHCP logic**: Always respect `mac_status` + `ip_status` tables and the blocked-pool vs main-pool rules.
- **Network enforcement**: DNS hijack (Pi) + ACL block (HP5130) must be applied/removed as a pair.
- **Wired devices**: Changing VLAN usually requires updating the RADIUS table + queuing `hp5130-replug.sh`.
- **5130 startup configs**: `5130-startup.cfg` and `5130-startup2.cfg` are **not** live configs. They are nightly TFTP copies from the switches.
- **Kea config**: `dhcp4.json` is generated at runtime. Permanent changes must be made in the code that writes it (look for `KEA_CONFIG_PATH`).
- **Central sync**: The central client thread creates its own fresh app context on every loop. Do **not** wrap `central_client.init_central_client()` in a `with app.app_context():` block in `create_app()`.

## Current Status (June 2026)

- Refactor into blueprints + `core/` package is complete.
- `app.py` is now a slim factory.
- Background threads (sweepers + central outbound worker) are running but still showing occasional context-related warnings.
- Main focus is now **debugging and stabilisation** rather than large structural changes.

## Coding Style / Preferences

- Keep changes **minimal and surgical**.
- Prefer clear, descriptive variable names.
- Add comments when modifying Kea-related logic or network enforcement code.
- When debugging, prefer reading specific functions or line ranges rather than the whole file.
- When making changes, consider impact on background threads and application context.

## Files Aider Should Prefer

When working on logic, read in this order of preference:

1. `blueprints/portal.py` or relevant file in `blueprints/admin/`
2. Relevant file in `core/` (e.g. `core/device_utils.py`, `core/network.py`)
3. `models.py`
4. `app.py` 
## Open / Recent Issues


Last updated: 2026-06-04
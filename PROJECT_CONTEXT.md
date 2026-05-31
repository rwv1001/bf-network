# Blackfriars Network Portal — Current Project Context

## Current Goals / Open Tasks
- [ ] 
- [ ] 
- [ ] 

## Recent Changes / Notes
- 

## Important Reminders
- Always respect the Kea DHCP hook logic (mac_status + ip_status tables)
- DNS hijack + ACL block must be added/removed together
- Use `undo` commands when changing switch port roles
- app.py is very large (~8500 lines) — read by function or line range when possible
- 5130-startup.cfg and 5130-startup2.cfg are not the live configs running on the HP5130s, but rather they are copies generated automatically everynight by the HP5130s written to the tftp-inbox. 
- dhcp4.json is not a permanent config for kea. Any permanent fixes/updates to dhcp4.json must therefore be in the relevant sections of app.py etc. where KEA_CONFIG_PATH is used with the open 'w' flag.

## Coding Style / Preferences
- Keep changes minimal and surgical
- Prefer clear variable names over short ones
- Add comments for any complex Kea hook logic

Last updated: [today's date]

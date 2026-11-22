# Backups and disaster recovery

This is the runbook for losing a piece of the network: a site server, a switch,
the central server (bf-central) or the tunnel VPS. Read the section for your
situation **before** running anything. Every recovery mode of `installer.sh`
prints what it will and will not do and waits for a typed confirmation; nothing
is changed before that.

> **Status of this document's procedures.** Making, replicating, opening and
> loading backups has been tested (see "What has been tested"). The four
> hardware procedures — rebuild a site server, clone a switch, rebuild central
> on a new VPS, move to a new tunnel VPS — have **not** yet been run on real
> replacement hardware. Do a drill of each on spare equipment before you depend
> on it, and correct this document with what you learn.

## 1. How it works

**Every night** (default 02:40) the `backup` container on each site server
makes one *bundle*:

| In the bundle | Why |
|---|---|
| Database dump, **without** DNS/NAT/Pi-hole traffic history | users, devices, admins, VLANs, switch ports, DHCP reservations |
| `.env` | every secret and setting of the site |
| Switch start-up configs (`5130-startup-<name>.cfg`) | to clone a dead switch |
| `~/.ssh` keys | the keys the switches and the VPS trust |
| NPM data and certificates, Pi-hole settings, acme.sh state | reverse proxy, TLS, DNS filtering |
| Kea config, switch policy files, mDNS peers | generated state |
| Host network files, tunnel service unit | reference; the tunnel VPS details |
| Installer state (if the installer has been run since this was added) | so a rebuild asks no questions |

It takes about a second and a few MB; traffic tables are skipped precisely so
that it cannot slow the server down. `BACKUP_EXCLUDE_TABLE_DATA` lists them.

**Encryption.** The bundle is encrypted to the organisation's *recovery public
key*. Servers hold only the public half: they can lock a bundle but not open
one. The private half and its passphrase stay with you, offline. That is why a
bundle — which contains every secret of a site — can safely be copied to other
servers.

**Copies.** Each site uploads its bundle to bf-central and downloads the newest
bundles of *every other site* and of *bf-central itself*. So after one night:

- each site holds: its own (14), each other site's (2), central's (2);
- central holds: every site's (7) and its own (14).

Any one surviving site server therefore has what is needed to rebuild anything
else. Download them from **Admin → Backups** on any site.

**Limits you must know**

- **Lose the recovery private key or its passphrase and every backup is
  unreadable.** There is no back door.
- A bundle is encrypted, **not signed**. Whoever holds the public key could
  make one. Restore only bundles from a server you trust and check the site,
  date and commit that the installer shows you.
- A backup is up to a day old. Registrations made after it are not in it.
- Traffic history is never backed up.
- The UniFi controller is not in the bundle (its data is ~120 MB and changes
  constantly). Turn on UniFi's own auto-backup; those `.unf` files *are*
  picked up from `~/unifi/data/data/backup`.
- If bf-central is down, sites still make local bundles but cannot exchange
  them; the Backups page says so.
- Until `CENTRAL_API_URL` is `https://`, the site's API key crosses the
  internet in clear text (the bundle itself is still encrypted).

## 2. First-time set-up (once)

Do these in order.

1. **Create the recovery key** on your installer machine:
   `sudo ./installer.sh --init-recovery-key`
   It prints a fingerprint and a `BACKUP_PUBLIC_KEY=…` line. Copy
   `~/bf-recovery-key/bf-recovery-private.asc` to two offline places and store
   the passphrase separately. Do this before anything else relies on it.
2. **bf-central:** update `~/bf-central` to the version with backup support,
   add the `BACKUP_PUBLIC_KEY=…` line to `~/bf-central/.env`, then
   `docker compose up -d --build`.
3. **Each site:** update to this version, add the same `BACKUP_PUBLIC_KEY=…`
   line to `.env`, then
   `docker compose up -d --build backup && docker compose restart web`.
4. On each site open **Admin → Backups**, check the fingerprint equals the one
   from step 1, press **Back up now**, and see "Sent to central" fill in.
5. Next day, check "Other sites" and "bf-central" list files.
6. Next time you run the installer for a site it asks for the recovery public
   key. Give it the same value, or `.env` is regenerated without it.

**Monthly check:** Admin → Backups on each site shows state `ok`, a run from
last night, and peers' files from the last two days.

## 3. What died? Find your case

| What is lost | Use | You need |
|---|---|---|
| A site server (Pi) | `--restore-site` (§4) | a bundle of **that site**, recovery key, replacement machine |
| A switch | `--clone-switch` (§5) | its saved `.cfg` (site server or a bundle), serial cable, replacement switch |
| bf-central | `--restore-central` (§6) | a **central** bundle, recovery key, new server |
| The tunnel VPS | `--retarget-vps` (§7) | new VPS, the installer state of each site |
| The installer machine | §8 | a site bundle, recovery key |
| Just want to look inside a bundle | `--inspect-backup` | recovery key |

In every case: download the bundle from **Admin → Backups** on *any* surviving
site (section "Other sites" or "bf-central"), copy it and
`bf-recovery-private.asc` to the installer machine, and run the installer from
the repository's `installer/` directory (the whole directory — it needs
`lib/`).

`sudo ./installer.sh --inspect-backup FILE` changes nothing and shows what a
bundle is. Use it first if you are unsure which file you have.

## 4. A site server died — `--restore-site`

```
sudo ./installer.sh --config <site> --restore-site bfbackup-site-<site>-<date>.tar.gz.gpg
```

**What it does.** It is the normal installer, run against the replacement
machine, with the old site fed back in: the code at the backed-up commit, the
old secrets (so the switches' RADIUS secret still matches), the backed-up
`.env` (only machine-specific keys such as `WAN_IFACE` are refreshed), then the
backed-up database and files (NPM, Pi-hole, certificates, keys, policy files).

**What it does not do.** It does not touch any switch, does not re-register the
site with bf-central, does not restore traffic history or UniFi data.

**Danger.** Like a first install it **wipes** `~/bf-network` and the Docker
data on the machine it is pointed at. If the old server is in fact still alive
and you name it, you destroy it. Keep the dead server unplugged: two servers
with the same addresses break DHCP for the whole site.

**Steps**

1. Put Raspberry Pi OS on the replacement, enable SSH, join it to the same
   install network as the original was installed from, and add the installer's
   server key to its `authorized_keys`.
2. If its address or user differs from the old server's:
   `sudo ./installer.sh --config <site> --forget-answer PI_WIFI_IP` (and
   `PI_USER`).
3. Run the command above. Check the summary (site, date, commit), type the site
   id to confirm.
4. If the installer has its saved answers it asks almost nothing. If it has
   none, see §8 first — it is much safer than answering everything again.
5. Cable the replacement to the same switch port as the old server.
6. At the end it prints a checklist: admin login, a registered device online,
   Switch Health, Back up now.

**If it stops part-way.** Run the same command again; it resumes at the failed
step. Loading the database is repeatable. Nothing on the switches has changed,
so the site is no worse than with the server dead.

## 5. A switch died — `--clone-switch`

Each switch sends its start-up configuration to the site server every night
(`/var/lib/tftpboot/switch-backups/5130-startup-<name>.cfg`), and those files
are in every bundle.

```
# site server alive: copy the .cfg from it, or
sudo ./installer.sh --clone-switch <name> --from-backup bfbackup-site-<site>-<date>.tar.gz.gpg
# or with the file itself
sudo ./installer.sh --clone-switch <name> --switch-config 5130-startup-<name>.cfg
```

**What it does.** Over the serial cable it types a short *temporary*
configuration (management address and the uplink trunk) so the replacement can
reach the site server, makes it download the saved configuration by TFTP, sets
that as the start-up configuration and reboots **without saving**. The result
is an exact copy: name, address, VLANs, ACLs, port roles, RADIUS, logins.

**What it does not do.** It does not touch the other switches, the server or
the database. Nothing is saved on the replacement until the download has been
checked, so a failure leaves it as it was (power-cycle it).

**Before you start**

- Unplug the dead switch (same address).
- Same model; firmware at least as new as the dead one's (shown by the
  installer). Add `--wipe-switch` if the replacement is not factory-fresh.
- Serial cable in the console port; the uplink cable in the same port number as
  on the dead switch (the installer lists the trunk ports and asks).
- The installer compares the file on the TFTP server with the one you chose and
  tells you if they differ. TFTP is unauthenticated: if it reports a
  difference, find out why before continuing.

**Afterwards** (printed at the end): remove the dead switch's SSH host key on
the site server, check Switch Health, press "Reapply ACL blocks".

*Stacked (IRF) switches and switches whose config was not written by this
installer are not handled; clone those by hand.*

## 6. bf-central died — `--restore-central`

```
sudo ./installer.sh --restore-central bfbackup-central-<domain>-<date>.tar.gz.gpg
```

**What it does.** Installs bf-central on a **new** server with the old `.env`
(same `ADMIN_KEY`, database password, domain) and loads the backed-up database.
Because every site's API key and push secret come back, **no site needs
re-registering**.

**What it does not do.** It changes no site and no DNS. It refuses to run if
`~/bf-central` already exists on the target.

**Steps**

1. Create the server (Ubuntu, your SSH key, passwordless sudo; inbound TCP 80,
   and 443 if central uses HTTPS).
2. Run the command; give the new server's **IP** when asked; type `RESTORE`.
3. Point the central DNS name at the new server.
4. `curl http://<central domain>/health` → `{"status":"ok"}`.
5. On one site: Admin → Backups → Back up now → "Sent to central" updates.

While central is down the sites keep working from their own databases; only
cross-site sync and bundle exchange pause.

## 7. The tunnel VPS died — `--retarget-vps`

The VPS holds nothing that the sites do not also hold (nginx entries, TLS
certificates, SSH settings), so it is rebuilt from each site.

```
sudo ./installer.sh --config <site> --retarget-vps <new VPS address>
```

**What it does.** Re-runs the installer's normal VPS steps against the new
address: nginx and this site's proxy entries, the site's TLS certificate
(copied from the site server, so it works before DNS moves), the admin SSH
tunnel settings; then points the site's portal tunnel, UniFi tunnel and admin
SSH tunnel at it.

**What it does not do.** No DNS change, nothing on the old VPS, switches,
database or UniFi data. It moves **one site**: repeat per site.

**Before you start**

- Create the VPS with the **same SSH public key** as the old one
  (`~/.ssh/oracle_rsa.pub` on the site server, or `home/.ssh/` in a bundle) and
  passwordless sudo; allow inbound TCP 22, 80, 443.
- It needs that site's installer state (`--config <site>`). If lost: §8.
- `.env` on the site is regenerated from the installer's answers, as on any
  installer run. A copy is left at `.env.before-retarget`; compare afterwards.

**Afterwards:** point the site's DNS names at the new VPS.

## 8. The installer machine died — getting its state back

From this version on, each installer run copies its (already encrypted) state
to the site server, and it is then inside every bundle.

```
sudo ./installer.sh --inspect-backup <site bundle> --extract-to /root/bundle
sudo mkdir -p /var/lib/bf-network-installer
sudo cp /root/bundle/installer-store/state/*.gpg /var/lib/bf-network-installer/
sudo cp /root/bundle/home/.ssh/* ~/.ssh/          # the switch / VPS keys
sudo find /root/bundle -type f -exec shred -u {} + ; sudo rm -rf /root/bundle
```

You still need the installer-state passphrase you chose at install time.
`--extract-to` writes **plaintext secrets**; delete the directory as shown.
If the bundle has no `installer-store/state`, the installer has not been run
for that site since this feature was added — run it once now, while you can.

## 9. What has been tested

| Tested (in throwaway containers, 2026-11-18) | Not yet tested on real equipment |
|---|---|
| Bundle creation from the live database; contents; ~1 s | `--restore-site` end to end |
| Loading the dump into an empty and into an existing schema: row counts match | `--clone-switch` serial/TFTP dialogue with a real 5130 |
| Refusal without a key / with a private key / with garbage | `--restore-central` on a real server |
| Upload, validation, retention, pull and pruning via a scratch bf-central | `--retarget-vps` |
| bf-central export → restore: identical data; old site keys still accepted | bf-central HTTPS (`CENTRAL_SITE_ADDRESSES`) |
| Admin page routes, downloads, path-traversal rejection | The `backup` service running under compose on a site |
| `--init-recovery-key`, `--inspect-backup`, restore helpers, clone planning | |

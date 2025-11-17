# Security Checklist for Git Repository

## ✅ Completed Actions

### Files Removed from Git Tracking
- [x] `freeradius/raddb/clients.conf` - Contains RADIUS shared secrets

### .gitignore Updated
- [x] Environment files (`.env`) - All variations protected
- [x] Python virtual environments (`venv-*`)
- [x] Database data directories
- [x] Kea DHCP leases and sockets
- [x] FreeRADIUS client configuration
- [x] NPM keys and data
- [x] SSL certificates and private keys

## 🔒 Protected Sensitive Data

### Credentials & Secrets
- ✅ `captive-portal/.env` - Microsoft Graph API credentials
- ✅ `freeradius/.env` - RADIUS shared secret
- ✅ `freeradius/raddb/clients.conf` - NAS client secrets
- ✅ `npm/data/keys.json` - NPM encryption keys

### Passwords & Keys
- ✅ Database passwords (in .env files)
- ✅ Flask SECRET_KEY (in .env files)
- ✅ RADIUS secrets (sUp3rSecr3t)
- ✅ Microsoft Graph Client Secret

### Personal Information
- ✅ Email addresses (in .env - ADMIN_EMAIL, GRAPH_FROM_EMAIL)
- ✅ MAC addresses (in Kea leases)
- ✅ User data (in PostgreSQL data directory)

### System Data
- ✅ DHCP leases (IP to MAC mappings)
- ✅ SSL certificates and private keys
- ✅ Session data

## ⚠️ Still in Repository (Safe)

### Configuration Templates (No Secrets)
- ✅ `.env.example` files - Templates with placeholder values
- ✅ `clients.conf.example` - Template configuration
- ✅ `clients.conf.template` - Template configuration

### Public Configuration
- ✅ `docker-compose.yml` - Uses environment variables, no hardcoded secrets
- ✅ `dhcp4.json` - Network configuration (no secrets)
- ✅ Documentation files (*.md)

## 🚨 BEFORE PUSHING TO GITHUB

### 1. Verify No Secrets in Git History
```bash
# Check if any .env files were previously committed
git log --all --full-history -- "**/.env"

# Check for clients.conf in history
git log --all --full-history -- "freeradius/raddb/clients.conf"
```

If any secrets were previously committed, you MUST either:
- **Option A**: Create a new repository from scratch (safest)
- **Option B**: Use git filter-branch or BFG Repo-Cleaner to rewrite history

### 2. Double-Check Current Status
```bash
cd /home/admin/bf-network

# Verify .gitignore is working
git check-ignore -v captive-portal/.env freeradius/.env

# Check what will be committed
git status

# Verify no secrets in tracked files
git grep -i "sUp3rSecr3t" -- '*.conf' '*.yml' '*.py'
git grep -i "YK~8Q~" -- '*.py' '*.yml' '*.md'
```

### 3. Update .env.example Files
Ensure example files have placeholder values:
```bash
# captive-portal/.env.example should have:
GRAPH_CLIENT_SECRET=your_client_secret_here

# freeradius/.env.example should have:
RADIUS_SECRET=your_radius_secret_here
```

### 4. Create README Warning
Add to main README.md:
```markdown
## ⚠️ Security Warning

This repository does NOT contain sensitive credentials. You must:

1. Copy `.env.example` to `.env` in each directory
2. Fill in your actual credentials
3. NEVER commit `.env` files or `clients.conf`
```

## 📋 What's Safe to Commit

### Code & Scripts
- ✅ Python scripts (app.py, models.py, etc.)
- ✅ Shell scripts (without embedded credentials)
- ✅ Configuration scripts (configure-hp5130-acls.py)

### Documentation
- ✅ All Markdown files (*.md)
- ✅ README files
- ✅ Implementation guides

### Configuration Templates
- ✅ docker-compose.yml (uses env vars)
- ✅ .example files
- ✅ .template files

### Network Configuration
- ✅ Kea DHCP configuration (dhcp4.json - no host reservations)
- ✅ FreeRADIUS module configs (except clients.conf)

## 🔐 Rotation Required After Push

If you accidentally pushed secrets, IMMEDIATELY rotate:

1. **Microsoft Graph API**
   - Create new client secret in Azure Portal
   - Update local `.env` file
   - Revoke old secret

2. **RADIUS Secrets**
   - Generate new secret: `openssl rand -base64 32`
   - Update in UniFi AP configuration
   - Update in HP5130 switch
   - Update `clients.conf` and `.env` files

3. **Database Passwords**
   - Change PostgreSQL password
   - Update `.env` file
   - Restart containers

4. **Flask SECRET_KEY**
   - Generate new: `python -c 'import secrets; print(secrets.token_hex(32))'`
   - Update `.env` file
   - Invalidates all sessions

## 📝 Current Secrets Inventory

### In captive-portal/.env (NOT in git)
- DB_PASSWORD
- SECRET_KEY
- GRAPH_TENANT_ID (sensitive)
- GRAPH_CLIENT_ID (sensitive)
- GRAPH_CLIENT_SECRET (CRITICAL)
- RADIUS_SECRET

### In freeradius/.env (NOT in git)
- RADIUS_SECRET

### In freeradius/raddb/clients.conf (NOT in git)
- secret = sUp3rSecr3t (for APs and switch)
- coa_secret = testing123 (for captive portal)

### In npm/data/keys.json (NOT in git)
- NPM encryption keys

## ✅ Safe to Push Checklist

Before running `git push`:

- [ ] Verified `.gitignore` is comprehensive
- [ ] Removed `freeradius/raddb/clients.conf` from tracking
- [ ] Confirmed no `.env` files are tracked
- [ ] Checked git history for leaked secrets
- [ ] Updated `.env.example` files with placeholders
- [ ] Tested `git check-ignore` on sensitive files
- [ ] Reviewed `git status` output
- [ ] Added security warning to README
- [ ] Documented secret rotation procedures

## 🆘 If Secrets Are Leaked

1. **Immediately** rotate ALL credentials
2. Consider repository as compromised
3. Create new repository from clean state
4. Never force-push to remove secrets (doesn't work - forks exist)
5. Report to security team if organizational repo

## 📞 Emergency Contacts

If credentials are exposed:
- Azure Admin Portal: https://portal.azure.com
- Revoke Microsoft Graph secrets immediately
- Change network device passwords
- Rotate database credentials

---

**Last Updated**: 2025-11-17
**Status**: ✅ Repository secured, ready for push after verification

# FreeRADIUS Environment Variables Setup

## Overview

FreeRADIUS now uses environment variables for sensitive configuration like `RADIUS_SECRET`. This keeps secrets out of git and ensures consistency across services.

## How It Works

1. **`freeradius/.env`**: Contains the actual secret (not in git)
2. **`raddb/clients.conf.template`**: Config file with `${RADIUS_SECRET}` placeholder
3. **`entrypoint.sh`**: Substitutes environment variables at container startup
4. **`docker-compose.yml`**: Loads `.env` and passes to container

## Setup Steps

### 1. Create .env file

```bash
cd /home/admin/bf-network/freeradius
cp .env.example .env

# Edit with your actual secret
nano .env
```

Set the same value as in `captive-portal/.env`:
```bash
RADIUS_SECRET=testing123
```

### 2. Restart FreeRADIUS

```bash
cd /home/admin/bf-network/freeradius
docker compose down
docker compose up -d
```

### 3. Verify

Check that clients.conf was generated:
```bash
docker exec freeradius cat /etc/raddb/clients.conf
```

You should see the secret substituted in place of `${RADIUS_SECRET}`.

## Benefits

✅ **Secret not in git**: `.env` is in `.gitignore`  
✅ **Single source of truth**: Change secret in one place  
✅ **Consistent**: Same secret used in portal and FreeRADIUS  
✅ **Secure**: Can use different secrets per environment  

## Keeping Secrets in Sync

Both files must have the same `RADIUS_SECRET`:
- `/home/admin/bf-network/freeradius/.env`
- `/home/admin/bf-network/captive-portal/.env`

To generate a new secret:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then update both `.env` files and restart both services:
```bash
cd /home/admin/bf-network/freeradius
docker compose restart

cd /home/admin/bf-network/captive-portal
docker compose restart
```

## Troubleshooting

### Error: "Failed to bind to authentication address"

Check that `.env` exists and is readable:
```bash
ls -la /home/admin/bf-network/freeradius/.env
```

### Secret not substituted

Check container logs:
```bash
docker logs freeradius
```

Should show: "clients.conf generated with RADIUS_SECRET from environment"

### Container won't start

Check entrypoint.sh is executable:
```bash
ls -la /home/admin/bf-network/freeradius/entrypoint.sh
# Should show: -rwxr-xr-x
```

If not:
```bash
chmod +x /home/admin/bf-network/freeradius/entrypoint.sh
```

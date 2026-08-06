FROM python:3.11-slim

ARG PORTAL_UID=1000
ARG PORTAL_GID=1000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    curl \
    iptables \
    iproute2 \
    openssh-client \
    docker.io \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user with sudo access for iptables
RUN set -eux; \
    # Try to create group with exact GID, fall back if needed
    groupadd -g ${PORTAL_GID} portal 2>/dev/null || groupadd portal || true; \
    \
    # Try to create user with exact UID, fall back if needed
    useradd -m -u ${PORTAL_UID} -g portal -s /bin/bash portal 2>/dev/null || \
        useradd -m -g portal -s /bin/bash portal || true; \
    \
    # Safety net: manually add UID 1000 to /etc/passwd if it still doesn't exist
    if ! getent passwd ${PORTAL_UID} >/dev/null 2>&1; then \
        echo "portal:x:${PORTAL_UID}:${PORTAL_GID}:Portal User:/home/portal:/bin/bash" >> /etc/passwd; \
    fi; \
    \
    mkdir -p ./scripts/scriptdata; \
    \
    # Fix ownership (best effort)
    chown -R ${PORTAL_UID}:${PORTAL_GID} /app ./scripts/scriptdata 2>/dev/null || true; \
    \
    # Sudo rights
    echo "portal ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /usr/bin/docker, /usr/local/bin/python3, /usr/bin/python3, /sbin/ip, /usr/sbin/ip" >> /etc/sudoers

# Default; override at runtime via Compose environment
ENV PORTAL_FORWARD_PORT=8081
# Expose port
EXPOSE 8081

# Run the application
# --preload: create_app() runs once in the master process before workers fork,
# so db.init_app() and background sweeper threads are initialised exactly once.


ENV PORTAL_FORWARD_PORT=8081
CMD gunicorn --bind 0.0.0.0:${PORTAL_FORWARD_PORT:-8081} --workers 2 --timeout 120 --access-logfile - --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s %(D)s' --preload app:app
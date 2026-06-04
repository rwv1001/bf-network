FROM python:3.11-slim

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
RUN useradd -m -u 1000 portal && chown -R portal:portal /app \
    && echo "portal ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /usr/bin/docker, /usr/local/bin/python3, /usr/bin/python3, /sbin/ip, /usr/sbin/ip" >> /etc/sudoers
USER portal

# Expose port
EXPOSE 8080

# Run the application
# --preload: create_app() runs once in the master process before workers fork,
# so db.init_app() and background sweeper threads are initialised exactly once.


CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s %(D)s", "--preload", "app:app"]
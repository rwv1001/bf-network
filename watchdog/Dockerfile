FROM python:3.12-slim

# openssh-client  — for optional SSH peer reboot
# iputils-ping    — for optional peer ping fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY watchdog.py .

# Unbuffered output so logs appear immediately in `docker logs`
ENV PYTHONUNBUFFERED=1

CMD ["python3", "watchdog.py"]

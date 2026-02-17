FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir psycopg2-binary

# Copy parser script
COPY dns-parser.py /app/

# Create non-root user
RUN useradd -m -u 1000 parser && \
    chown -R parser:parser /app

USER parser

CMD ["python", "-u", "dns-parser.py"]

FROM alpine:3.19

# Create a dedicated non-root user + group for the agent
RUN addgroup -g 1200 docker-job-submitters && \
    addgroup -g 998 docker && \
    adduser -D -u 1200 -G docker-job-submitters docker-agent && \
    adduser docker-agent docker

# Install only what we need
RUN apk add --no-cache docker-cli bash

# Copy and prepare entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to the non-root user
USER docker-agent

ENTRYPOINT ["/entrypoint.sh"]
FROM freeradius/freeradius-dev:arm64v8-v3.2.x

# envsubst lives in gettext-base on Debian-based FreeRADIUS images
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends gettext-base \
 && rm -rf /var/lib/apt/lists/*
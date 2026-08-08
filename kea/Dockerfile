ARG KEA_VERSION=3.0.2-alpine

# Stage only used as a source for matching schema/admin files
FROM jonasal/kea-admin:${KEA_VERSION} AS kea-admin-src

FROM jonasal/kea-dhcp4:${KEA_VERSION} AS builder

RUN apk add --no-cache build-base cmake boost-dev openssl-dev postgresql-dev log4cplus-dev
COPY kea-hooks/dynamic_subnet/dns_hijack_hook.cc /src/
COPY kea-hooks/dynamic_subnet/CMakeLists.txt /src/
WORKDIR /src
RUN mkdir build && cd build && cmake .. && make

FROM jonasal/kea-dhcp4:${KEA_VERSION}

RUN apk add --no-cache \
    iptables \
    postgresql-client \
    openssh-client \
    gettext \
    python3 \
    py3-psycopg2

# Copy from the named stage (not from ${KEA_VERSION} directly)
COPY --from=kea-admin-src \
    /usr/local/share/kea/scripts/pgsql/ \
    /usr/local/share/kea/scripts/pgsql/

# Only if the binary exists in that image:
COPY --from=kea-admin-src \
    /usr/local/sbin/kea-admin \
    /usr/local/sbin/kea-admin

COPY --from=builder \
    /src/build/dhcp_dns_hijack.so \
    /usr/local/lib/kea/hooks/dhcp_dns_hijack.so

ENTRYPOINT ["/entrypoint.sh"]
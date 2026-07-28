# Pin the same version everywhere (adjust if you move to 3.0.3, 3.1.x, etc.)
ARG KEA_VERSION=3.0.2-alpine

FROM jonasal/kea-dhcp4:${KEA_VERSION} AS builder

RUN apk add --no-cache build-base cmake boost-dev openssl-dev postgresql-dev log4cplus-dev
COPY kea-hooks/dynamic_subnet/dns_hijack_hook.cc /src/
COPY kea-hooks/dynamic_subnet/CMakeLists.txt /src/
WORKDIR /src
RUN mkdir build && cd build && cmake .. && make

FROM jonasal/kea-dhcp4:${KEA_VERSION}

# Tools needed at runtime (do NOT apk add "kea" — that can pull a different version)
RUN apk add --no-cache iptables postgresql-client openssh-client gettext python3

# Matching schema scripts + kea-admin from the same Kea version
COPY --from=jonasal/kea-admin:${KEA_VERSION} /usr/local/share/kea/scripts/pgsql/ /usr/local/share/kea/scripts/pgsql/

# Optional: also copy kea-admin binary if present in that image
COPY --from=jonasal/kea-admin:${KEA_VERSION} /usr/local/sbin/kea-admin /usr/local/sbin/kea-admin

# Custom hook built against this exact Kea
COPY --from=builder /src/build/dhcp_dns_hijack.so /usr/local/lib/kea/hooks/dhcp_dns_hijack.so

# Keep using the image entrypoint (or wrap it — see below)
ENTRYPOINT ["/entrypoint.sh"]
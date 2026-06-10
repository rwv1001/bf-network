FROM jonasal/kea-dhcp4:3.0-alpine as builder

# Build the DNS hijack hook against this exact Kea version
RUN apk add --no-cache build-base cmake boost-dev openssl-dev postgresql-dev log4cplus-dev 
COPY kea-hooks/dynamic_subnet/dns_hijack_hook.cc /src/
COPY kea-hooks/dynamic_subnet/CMakeLists.txt /src/
WORKDIR /src
RUN mkdir build && cd build && cmake .. && make

FROM jonasal/kea-dhcp4:3.0-alpine

# Install iptables, kea (for kea-lfc), postgresql-client, ssh client for hook scripts,
# and gettext (provides envsubst, used to substitute env vars into dhcp4.json.template)
RUN apk add --no-cache iptables kea postgresql-client openssh-client gettext python3

# Copy hook compiled against this exact Kea version
COPY --from=builder /src/build/dhcp_dns_hijack.so /usr/local/lib/kea/hooks/dhcp_dns_hijack.so

# Use the original entrypoint
ENTRYPOINT ["/entrypoint.sh"]

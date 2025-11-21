# Build Kea hook library compatible with jonasal/kea-dhcp4:3.0-alpine
FROM jonasal/kea-dhcp4:3.0-alpine as builder

# Install build tools
RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    boost-dev \
    openssl-dev \
    postgresql-dev \
    log4cplus-dev

# Copy hook source
COPY dynamic_subnet.cc /src/
COPY CMakeLists.txt /src/

WORKDIR /src

# Build the hook
RUN mkdir build && cd build && \
    cmake .. && \
    make

# Final stage - just the compiled hook
FROM scratch
COPY --from=builder /src/build/dhcp_dynamic_subnet.so /

FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev gcc make cmake ninja perl coreutils

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# `[patch.crates-io]` points at the vendored smoltcp fork, so it has to be in
# the build context as well.
COPY third_party ./third_party

RUN cargo build --release -p nexapipe

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Default location of the log files; docker-compose mounts a volume on top.
RUN mkdir -p /app/logs

COPY --from=builder /app/target/release/nexapipe /usr/local/bin/nexapipe

# The proxy listens for HTTP (and TLS passthrough) on [server] listen_addr and
# for iroh on a UDP port. The TLS port belongs to the backend (Caddy), which this
# container only connects out to.
EXPOSE 8080

ENTRYPOINT ["nexapipe"]
CMD ["--config", "/app/config.toml"]

FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev gcc make cmake ninja perl coreutils

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/target/release/nexapipe /usr/local/bin/nexapipe

EXPOSE 80 443 8080 8081

ENTRYPOINT ["nexapipe"]
CMD ["--config", "/app/config.toml"]
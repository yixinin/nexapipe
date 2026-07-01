FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

ADD ../target/release/nexapipe /usr/local/bin/nexapipe

EXPOSE 80 443 8080 8081

ENTRYPOINT ["nexapipe"]
CMD ["--config", "/app/config.toml"]
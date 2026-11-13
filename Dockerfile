# Minimal scratch-based Docker image for skill-issues
# Reference: https://kerkour.com/rust-docker-small-secure-images
#
# Build:  docker build -t skill-issues .
# Run:    docker run --rm -v "$(pwd):/work" skill-issues /work
# Size:   ~5-6 MB (static musl binary on scratch)

####################################################################################################
## Build stage — static musl binary
####################################################################################################
FROM rust:alpine AS builder

RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release --locked && \
    strip /app/target/release/skill-issues

####################################################################################################
## Minimal user setup (scratch has no adduser)
####################################################################################################
FROM alpine:latest AS files

ENV USER=skillissues
ENV UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

####################################################################################################
## Final image — FROM scratch (nothing but the binary)
####################################################################################################
FROM scratch

COPY --from=files --chmod=444 /etc/passwd /etc/group /etc/

COPY --from=builder --chmod=555 /app/target/release/skill-issues /bin/skill-issues

USER skillissues:skillissues

WORKDIR /work

ENTRYPOINT ["/bin/skill-issues"]

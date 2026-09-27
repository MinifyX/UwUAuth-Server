# syntax=docker/dockerfile:1.7
#
# Builds UwUAuth Server from source:
#
#   docker build -f docker/Dockerfile -t uwuauth-server .
#
# CI uses docker/Dockerfile.release instead, with binaries it cross-compiled before, which is
# much faster for arm64. Both end in the same image.

# The web app: sign-in pages, self-service and admin portal.
FROM node:24-slim AS web
WORKDIR /web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY . .
# Embedded into the binary by crates/uwuauth-web/build.rs.
COPY --from=web /web/dist /src/web/dist
# `--locked` so the image is built from the versions in Cargo.lock and not from whatever was
# published this morning. The cached target directory can hold an earlier build whose sources
# look unchanged to cargo, so the server's own sources are touched first.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    find crates -name '*.rs' -exec touch {} + \
 && cargo build --release --locked -p uwuauth-server \
 && cp target/release/uwuauth-server /usr/local/bin/uwuauth-server

# Debian still has the tools distroless does not: make /data, owned by the user the server
# runs as.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS prep
COPY --from=build /usr/local/bin/uwuauth-server /usr/local/bin/uwuauth-server
RUN chmod 755 /usr/local/bin/uwuauth-server \
 && install -d -o 10001 -g 10001 /data

# The runtime is distroless: glibc, CA certificates and not much else — no shell, no package
# manager, so a break-in has almost nothing to build on. Pinned by digest; cc-debian13 is
# trixie, so its glibc matches the build. The server opens one port above 1024 and writes one
# directory, so it needs no capability at all and no root.
FROM gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750
COPY --from=prep /usr/local/bin/ /usr/local/bin/
COPY --from=prep --chown=10001:10001 /data /data
USER 10001:10001
ENV UWUAUTH_DATA=/data \
    UWUAUTH_LISTEN=0.0.0.0:8443 \
    HOME=/data
VOLUME /data
EXPOSE 8443
# No curl in here, so the server asks itself. With Let's Encrypt it is healthy once it has its
# certificate, which can take half a minute on the first start.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --start-interval=2s --retries=3 \
    CMD ["/usr/local/bin/uwuauth-server", "health"]
ENTRYPOINT ["/usr/local/bin/uwuauth-server"]
CMD ["serve"]

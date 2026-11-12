#
# Runtime image for openab-sb. It does not compile Rust. The release job in
# .github/workflows/release.yml unpacks the static musl binaries it already
# builds into image-bin/<arch>/openab-sb (amd64, arm64) and runs buildx with
# this file as the Dockerfile.
#
# The config is not baked in. Mount it at /etc/openab-sb/openab-sb.toml. It
# must set listen = "127.0.0.1:8796" and an audit_path under /var/lib/openab-sb.
# The switchboard binds loopback, so only processes in the same pod (the
# tailscale sidecar) can reach it.

FROM debian:bookworm-slim

ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system openab-sb \
 && useradd --system --gid openab-sb --no-create-home --home-dir /var/lib/openab-sb --shell /usr/sbin/nologin openab-sb \
 && install -d -o openab-sb -g openab-sb -m 0750 /var/lib/openab-sb /etc/openab-sb

COPY image-bin/${TARGETARCH}/openab-sb /usr/local/bin/openab-sb

USER openab-sb
WORKDIR /var/lib/openab-sb

ENTRYPOINT ["/usr/local/bin/openab-sb", "serve", "-c", "/etc/openab-sb/openab-sb.toml"]

#!/usr/bin/env bash
# Build uig/cowrie:<version> on the VPS without Docker Hub (Linux only, root).
#   1. uig/debian:trixie: a minimal rootfs from debootstrap, imported once
#   2. Cowrie source from GitHub's tarball endpoint, checked against a pinned SHA-256
#   3. Python packages from the PyPI mirror
# Run by ./hp build-image. Mirrors default to Aliyun's in-VPC ones.
set -euo pipefail
umask 022
cd "$(dirname "${BASH_SOURCE[0]}")"

COWRIE_VERSION=3.1.3
# sha256 of https://codeload.github.com/cowrie/cowrie/tar.gz/refs/tags/v3.1.3
# (tag v3.1.3 = commit c7773f4, the same one the official 3.1.3 image is built from)
COWRIE_SHA256=13d6e29ee8b5a850e7cd24880ad9a495082ee7681c4aaeaddaecd6d50af38887
DEBIAN_MIRROR=${DEBIAN_MIRROR:-http://mirrors.cloud.aliyuncs.com/debian}
SECURITY_MIRROR=${SECURITY_MIRROR:-http://mirrors.cloud.aliyuncs.com/debian-security}
# pip refuses plain-HTTP indexes, so PyPI uses the public HTTPS mirror.
PIP_INDEX_URL=${PIP_INDEX_URL:-https://mirrors.aliyun.com/pypi/simple/}
BASE=uig/debian:trixie
IMAGE=uig/cowrie:$COWRIE_VERSION

say() { echo "==> $*"; }

if [ "${1:-}" = "--rebuild-base" ] || ! docker image inspect "$BASE" >/dev/null 2>&1; then
    command -v debootstrap >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -yq debootstrap
    root=$(mktemp -d)
    trap 'rm -rf "$root"' EXIT
    say "debootstrap trixie from $DEBIAN_MIRROR"
    debootstrap --variant=minbase trixie "$root" "$DEBIAN_MIRROR" >/dev/null
    cat >"$root/etc/apt/sources.list" <<EOF
deb $DEBIAN_MIRROR trixie main
deb $DEBIAN_MIRROR trixie-updates main
deb $SECURITY_MIRROR trixie-security main
EOF
    rm -rf "$root"/var/cache/apt/archives/*.deb "$root"/var/lib/apt/lists/*
    say "Importing $BASE"
    tar -C "$root" -c . | docker import -c 'CMD ["/bin/bash"]' - "$BASE" >/dev/null
fi

say "Downloading Cowrie v$COWRIE_VERSION source"
rm -rf src cowrie.tar.gz
curl -fsSL --retry 3 -o cowrie.tar.gz \
    "https://codeload.github.com/cowrie/cowrie/tar.gz/refs/tags/v$COWRIE_VERSION"
echo "$COWRIE_SHA256  cowrie.tar.gz" | sha256sum -c --quiet - \
    || { echo "error: source tarball hash mismatch" >&2; exit 1; }
mkdir src
tar -xzf cowrie.tar.gz -C src --strip-components=1
rm cowrie.tar.gz
# setuptools-scm normally writes this from git metadata, which a tarball lacks;
# without it Cowrie exits with "Cowrie is not installed".
cat >src/src/cowrie/_version.py <<EOF
__version__ = version = "$COWRIE_VERSION"
__version_tuple__ = version_tuple = ($(echo "$COWRIE_VERSION" | tr . ,))
EOF

say "Building $IMAGE"
docker build -q --pull=false \
    --build-arg BASE="$BASE" --build-arg PIP_INDEX_URL="$PIP_INDEX_URL" \
    --label org.opencontainers.image.version="v$COWRIE_VERSION" \
    --label org.opencontainers.image.source=https://github.com/cowrie/cowrie \
    -t "$IMAGE" .
rm -rf src
docker image ls "$IMAGE"

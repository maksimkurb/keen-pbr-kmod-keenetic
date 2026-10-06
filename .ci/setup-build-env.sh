#!/usr/bin/env bash
set -euo pipefail

snapshot=20261001T000000Z
cat >/etc/apt/sources.list <<EOF
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${snapshot}/ bookworm main
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${snapshot}/ bookworm-updates main
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${snapshot}/ bookworm-security main
EOF
rm -f /etc/apt/sources.list.d/debian.sources
apt-get -o Acquire::Check-Valid-Until=false update
apt-get install -y --no-install-recommends attr autoconf automake bc binutils bison build-essential curl file flex \
  gawk gcc-12 gettext g++-12 git gperf help2man jq kmod libhtml-parser-perl libjson-perl \
  libncurses-dev libssl-dev libxml-libxml-perl locales lzip pkg-config protobuf-c-compiler rsync shellcheck \
  passwd subversion swig unzip wget xxd xz-utils zlib1g-dev zstd
rm -rf /var/lib/apt/lists/*
if ! getent passwd builder >/dev/null; then
  useradd --uid 1000 --create-home --shell /bin/bash builder
fi
[[ "$(id -u builder)" == 1000 ]] || { echo "builder must use UID 1000" >&2; exit 1; }
install -d -m 755 -o builder -g builder /build
install -d -m 755 -o builder -g builder /build/sdk
export TZ=UTC LANG=C LC_ALL=C SOURCE_DATE_EPOCH=1704067200
export KBUILD_BUILD_TIMESTAMP='2024-01-01 00:00:00 UTC'
export KBUILD_BUILD_USER=keenpbr-builder KBUILD_BUILD_HOST=keenpbr-build
export HOSTCC=gcc-12 HOSTCXX=g++-12
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf '%s\n' 'TZ=UTC' 'LANG=C' 'LC_ALL=C' 'SOURCE_DATE_EPOCH=1704067200' \
    'KBUILD_BUILD_TIMESTAMP=2024-01-01 00:00:00 UTC' 'KBUILD_BUILD_USER=keenpbr-builder' \
    'KBUILD_BUILD_HOST=keenpbr-build' 'HOSTCC=gcc-12' 'HOSTCXX=g++-12' >>"$GITHUB_ENV"
fi

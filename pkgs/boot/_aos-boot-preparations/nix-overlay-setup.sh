#!@bash@/bin/bash
set -euo pipefail

sysroot=/sysroot
mkdir -p "$sysroot/var/lib/nix-overlay/upper"
mkdir -p "$sysroot/var/lib/nix-overlay/work"

if ! mountpoint -q "$sysroot/nix"; then
  mount -t overlay overlay \
    -o nosuid,nodev,lowerdir="$sysroot/nix.lower",upperdir="$sysroot/var/lib/nix-overlay/upper",workdir="$sysroot/var/lib/nix-overlay/work" \
    "$sysroot/nix"
fi

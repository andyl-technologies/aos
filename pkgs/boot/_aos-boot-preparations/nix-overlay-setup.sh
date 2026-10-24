#!@bash@/bin/bash
set -euo pipefail

sysroot=/sysroot
mkdir -p "$sysroot/var/lib/nix-overlay/upper"
mkdir -p "$sysroot/var/lib/nix-overlay/work"

root_label=()
if [ "$AOS_CONFIGURATION_SELINUX_LABELS" = true ]; then
  # Overlay roots inherit the writable upper's label unless selected explicitly.
  # Label only the root; individual store inodes keep their immutable labels.
  root_label=(-o rootcontext=system_u:object_r:usr_t)
fi

if ! mountpoint -q "$sysroot/nix"; then
  mount -t overlay overlay \
    -o nosuid,nodev,lowerdir="$sysroot/usr/lib/aos/nix",upperdir="$sysroot/var/lib/nix-overlay/upper",workdir="$sysroot/var/lib/nix-overlay/work" \
    "${root_label[@]}" \
    "$sysroot/nix"
fi

#!@bash@/bin/bash
# Assemble committed arrays without creating, formatting, or adopting storage.
set -euo pipefail

expected_arrays=()
# A supplied receipt adds data-array availability diagnostics. Image bootstrap
# can still assemble system state from authenticated on-disk MD superblocks.
if [ "$#" -gt 0 ]; then
  array_names=$(@jq@/bin/jq -er '.storage.arrays // .arrays // {} | keys[]' "$1") || {
    status=$?
    [ "$status" -eq 4 ] || exit "$status"
  }
  if [ -n "$array_names" ]; then
    mapfile -t expected_arrays <<< "$array_names"
  fi
fi

@mdadm@/sbin/mdadm --assemble --scan >/dev/null 2>&1 || true
@systemd@/bin/udevadm settle --timeout=10 || true

# The root-disk member remains discoverable during a metadata outage.
if [ -e /dev/disk/by-partlabel/var ] &&
  [ "$(@util-linux@/sbin/blkid -p -s TYPE -o value /dev/disk/by-partlabel/var 2>/dev/null || true)" = linux_raid_member ]; then
  expected_arrays+=(var)
fi

missing=()
for name in "${expected_arrays[@]}"; do
  [ -e "/dev/md/$name" ] || missing+=("$name")
done

if [ "${#missing[@]}" -gt 0 ]; then
  printf 'aos-storage-topology: waiting for late members of: %s\n' "${missing[*]}" >&2
  @coreutils@/bin/sleep 5
  @systemd@/bin/udevadm settle --timeout=10 || true
  @mdadm@/sbin/mdadm --assemble --scan --run >/dev/null 2>&1 || true
  @systemd@/bin/udevadm settle --timeout=10 || true
fi

for name in "${expected_arrays[@]}"; do
  if [ ! -e "/dev/md/$name" ]; then
    printf 'aos-storage-topology: committed array %s is unavailable\n' "$name" >&2
    # System state is mandatory; data-volume mount units may degrade boot.
    [ "$name" != var ] || exit 1
  fi
done

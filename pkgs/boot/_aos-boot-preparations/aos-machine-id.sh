#!@bash@/bin/bash
set -euo pipefail

mkdir -p /sysroot/var/etc
# systemd machine IDs are the UUID's 32 lowercase hexadecimal digits.
tr -d '-' < /proc/sys/kernel/random/uuid > /sysroot/var/etc/machine-id
chmod 0444 /sysroot/var/etc/machine-id

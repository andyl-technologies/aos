#!@bash@/bin/bash
set -euo pipefail

mkdir -p /run/etc
mount -t tmpfs -o nosuid,nodev,mode=755 tmpfs /run/etc

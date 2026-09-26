#!@bash@/bin/bash
set -eu

aos-boot-identity /proc/cmdline

mkdir -p /run/aos
touch /run/aos/boot-identity-valid

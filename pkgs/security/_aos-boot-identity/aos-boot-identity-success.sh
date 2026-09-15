#!@bash@/bin/bash
set -eu

aos-boot-identity /proc/cmdline

mkdir -p /run/aos
staging=/run/aos/verity-generator.$$
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/normal" "$staging/early" "$staging/late"
/lib/systemd/aos-systemd-veritysetup-generator \
  "$staging/normal" "$staging/early" "$staging/late"

generated_verity_unit="$staging/normal/systemd-veritysetup@root.service"
if test ! -s "$generated_verity_unit"; then
  echo "AOS boot identity: upstream verity generator produced no root unit" >&2
  exit 1
fi

mkdir -p /run/systemd/system
cp "$generated_verity_unit" /run/systemd/system/systemd-veritysetup@root.service
systemctl daemon-reload
touch /run/aos/boot-identity-valid

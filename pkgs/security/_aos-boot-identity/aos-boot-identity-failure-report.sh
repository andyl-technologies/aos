#!@bash@/bin/bash
set -eu

! mountpoint -q /sysroot/var
if test -f /run/aos/boot-identity-valid; then
  test -e /dev/mapper/root
  test ! -f /run/aos/verity-root-valid
  echo "AOS root verification failure: corrupt root rejected; /var unmounted"
else
  test ! -e /dev/mapper/root
  echo "AOS boot identity failure: verity root absent; /var unmounted"
fi

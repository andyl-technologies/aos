#!@bash@/bin/bash
set -euo pipefail

# dm-verity validates blocks on read, so consume the complete mapper before
# persistent state becomes available.
@coreutils@/bin/dd \
  if=/dev/mapper/root \
  of=/dev/null \
  bs=4M \
  iflag=fullblock \
  status=none
@coreutils@/bin/touch /run/aos/verity-root-valid

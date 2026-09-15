#!@bash@/bin/bash
set -euo pipefail

# The identity validator publishes the generated unit at runtime. Starting it
# here joins the mapper setup to the same initrd-fs transaction as verification.
@systemd@/bin/systemctl start systemd-veritysetup@root.service

# libdevmapper is built without libudev synchronization. Republish the active
# mapper after setup and wait until udev has finished processing the event.
@systemd@/bin/udevadm trigger \
  --action=change \
  --subsystem-match=block \
  --sysname-match='dm-*'
@systemd@/bin/udevadm settle

# dm-verity validates blocks on read, so consume the complete mapper before
# persistent state becomes available.
@coreutils@/bin/dd \
  if=/dev/mapper/root \
  of=/dev/null \
  bs=4M \
  iflag=fullblock \
  status=none
@coreutils@/bin/touch /run/aos/verity-root-valid

# Actual post-admission spill write/sync failure on a private error-target filesystem.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-native-spill-writeback-eio-flight";
  gateId = "gate:ram-spill-io";
  testName = "packaged_qemu_executor::tests::paging_native::spill_io::production_spill_sync_failure_retains_original_cause_and_refuses_guest_cut";
  successMarker = "SPILL_WRITEBACK_EIO_NATIVE_PASS";
  lanes = ["spill-io"];
  outerCpuSlots = 4;
  outerMemoryMiB = 8192;
  writableMiB = 12288;
  evidencePrefix = "spill_io";
  extraRootfsDeps = [pkgs.device-mapper];
  innerPreparation = ''
    for kernel_config in ${pkgs.linux}/boot/config-*; do
      ${pkgs.grep}/bin/grep -qx 'CONFIG_BLK_DEV_DM=y' "$kernel_config"
      ${pkgs.grep}/bin/grep -qx 'CONFIG_BLK_DEV_LOOP=y' "$kernel_config"
    done
    fault_mount=/var/paging-spill-io
    ${pkgs.coreutils}/bin/truncate -s 2147483648 /var/paging-spill-io.img
    fault_loop=$(${pkgs.util-linux}/sbin/losetup --find --show /var/paging-spill-io.img)
    # Catalog and registry remain on the healthy shared filesystem. The
    # fixture switches only this original UUID after actual native admission.
    ${pkgs.device-mapper}/sbin/dmsetup create crucible-spill-io \
      --noudevsync --uuid crucible-spill-io-disposable-v1 \
      --table "0 4194304 linear $fault_loop 0"
    ${pkgs.device-mapper}/sbin/dmsetup mknodes crucible-spill-io
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project,^has_journal \
      -E quotatype=prjquota /dev/mapper/crucible-spill-io
    mkdir -m 700 "$fault_mount"
    ${pkgs.util-linux}/bin/mount -o prjquota,errors=continue \
      /dev/mapper/crucible-spill-io "$fault_mount"
    mkdir -m 700 "$fault_mount/spill-io"
    # Successful cleanup requires all original native borrowers to have
    # closed; a busy mount or target keeps this flight fail-closed.
    trap '${pkgs.util-linux}/bin/umount "$fault_mount" && \
      ${pkgs.device-mapper}/sbin/dmsetup remove --noudevsync crucible-spill-io && \
      ${pkgs.util-linux}/sbin/losetup -d "$fault_loop" || exit 1' EXIT
  '';
  innerEvidence = _: ''
    for evidence in \
      spill_io_initial_admission_and_authenticated_preservation=true \
      spill_io_actual_guest_write_requires_new_preservation=true \
      spill_io_actual_error_target_after_admission=true \
      spill_io_original_writeback_eio_retained=true \
      spill_io_controller_alive_no_install_or_cut=true \
      spill_io_original_full_vector_until_physical_cleanup=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
  '';
  # This flight claims retained spill I/O only, without a DMA/pin or worker
  # death claim. No production capability changes before actual execution.
  outerEvidence = _: "";
}

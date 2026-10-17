# Distinct authenticated repositories and a fresh cold receiver in one kernel VM.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-authenticated-ram-transfer-flight";
  gateId = "gate:ram-native-transfer";
  testName = "packaged_qemu_executor::tests::paging_native::transfer::production_authenticated_archive_transfer_restores_a_fresh_cold_receiver";
  successMarker = "MANAGED_AUTHENTICATED_TRANSFER_NATIVE_PASS";
  lanes = [ "transfer-source" "transfer-receiver" ];
  # Each independent instance has an explicitly admitted eight-CPU aggregate.
  outerCpuSlots = 16;
  outerMemoryMiB = 8192;
  writableMiB = 16384;
  storageImageBytes = 12 * 1024 * 1024 * 1024;
  innerTimeoutSeconds = 10500;
  outerTimeoutSeconds = 10800;
  evidencePrefix = "managed_transfer";
  innerEvidence = _: ''
    for evidence in \
      managed_transfer_distinct_backend_authority=true \
      managed_transfer_complete_archive_before_launch=true \
      managed_transfer_corrupt_missing_refused_unpublished=true \
      managed_transfer_first_quantum_identity=true \
      managed_transfer_ram_root_identity=true \
      managed_transfer_all_eight_resources_after_cleanup=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
    for counter in managed_transfer_missing_installs managed_transfer_first_quantum_ns; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$counter=[1-9][0-9]*$" "$log")" -eq 1
    done
  '';
  # These facts concern independently owned instances on one kernel. They do
  # not authorize a cross-host transport or a deployment capability receipt.
  outerEvidence = _: ''
    ${pkgs.grep}/bin/grep '^managed_transfer_' "$out/serial.log" \
      > "$out/transfer-evidence.txt"
  '';
}

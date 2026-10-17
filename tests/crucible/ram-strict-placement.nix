# Verified parent locks and authenticated disk cuts; no child or capability claim.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-strict-parent-placement-flight";
  gateId = "gate:ram-native-strict-placement";
  testName = "packaged_qemu_executor::tests::paging_native::strict_modes::production_strict_placement_has_verified_kernel_and_disk_evidence";
  successMarker = "STRICT_PLACEMENT_NATIVE_PASS";
  lanes = ["strict-reference" "strict-parent"];
  # Both independent owner rosters fit even while reference observations live.
  outerCpuSlots = 8;
  outerMemoryMiB = 8192;
  writableMiB = 10240;
  innerTimeoutSeconds = 10500;
  outerTimeoutSeconds = 10800;
  evidencePrefix = "strict_placement";
  innerEvidence = _: ''
    for evidence in \
      state_identity ram_root_identity modeled_time_identity \
      actual_parent_locks verified_unlock authenticated_disk_cut \
      historical_cut_preserved; do
      test "$(${pkgs.grep}/bin/grep -Fxc "strict_placement_$evidence=true" "$log")" -eq 1
    done
    for counter in missing_installs cold_discards; do
      test "$(${pkgs.grep}/bin/grep -Ec "^strict_placement_$counter=[1-9][0-9]*$" "$log")" -eq 1
    done
  '';
  outerEvidence = _: ''
    ${pkgs.grep}/bin/grep '^strict_placement_' "$out/serial.log" \
      > "$out/strict-parent-evidence.txt"
  '';
}

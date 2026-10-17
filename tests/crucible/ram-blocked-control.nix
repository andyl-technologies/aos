# Independent live control while a real authenticated UFFD page response is held.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-blocked-pager-control-flight";
  gateId = "gate:ram-native-blocked-control";
  testName = "packaged_qemu_executor::tests::paging_native::blocked_control::production_blocked_pager_control_preserves_identity_and_refuses_late_completion";
  successMarker = "BLOCKED_PAGER_NATIVE_PASS";
  lanes = [
    "blocked-reference"
    "blocked-policy"
    "blocked-expiry"
    "blocked-cancel"
  ];
  # Persistent catalog/registry namespaces remain charged between the four
  # sequential lanes. The image covers those hard quotas and the live child.
  outerCpuSlots = 16;
  outerMemoryMiB = 8192;
  writableMiB = 20480;
  storageImageBytes = 24 * 1024 * 1024 * 1024;
  innerTimeoutSeconds = 10500;
  outerTimeoutSeconds = 10800;
  evidencePrefix = "blocked_pager";
  innerEvidence = _: ''
    for evidence in \
      blocked_pager_live_policy_identity=true \
      blocked_pager_original_cap_expiry=true \
      blocked_pager_cancellation_before_response=true \
      blocked_pager_late_completion_refused=true \
      blocked_pager_full_vector_cleanup=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
    test "$(${pkgs.grep}/bin/grep -Ec '^blocked_pager_coordinate=[0-9]+:[0-9]+$' "$log")" -eq 4
    test "$(${pkgs.grep}/bin/grep -Ec '^blocked_pager_installs_before_response=[0-9]+$' "$log")" -eq 4
  '';
  # This native flight issues no deployment qualification receipt. A successful
  # run proves this exact delayed-completion/control profile on its actual VM.
  outerEvidence = _: ''
    ${pkgs.grep}/bin/grep '^blocked_pager_' "$out/serial.log" \
      > "$out/blocked-control-evidence.txt"
  '';
}

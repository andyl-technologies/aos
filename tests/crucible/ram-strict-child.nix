# Independent child locking and a real lower kernel entitlement refusal.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-strict-child-lock-flight";
  gateId = "gate:ram-native-strict-child-lock";
  testName = "packaged_qemu_executor::tests::paging_native::strict_child::production_strict_child_relocks_and_refuses_lower_kernel_entitlement";
  successMarker = "STRICT_CHILD_LOCK_NATIVE_PASS";
  lanes = ["strict-fork"];
  outerCpuSlots = 8;
  outerMemoryMiB = 8192;
  writableMiB = 10240;
  innerTimeoutSeconds = 10500;
  outerTimeoutSeconds = 10800;
  evidencePrefix = "strict_child";
  innerEvidence = _: ''
    for evidence in \
      actual_parent_locks lower_kernel_entitlement_refused \
      refusal_preserves_parent_locks fresh_verified_locks \
      independent_kernel_entitlement parent_root_preserved full_vector_cleanup; do
      test "$(${pkgs.grep}/bin/grep -Fxc "strict_child_$evidence=true" "$log")" -eq 1
    done
    ${pkgs.grep}/bin/grep -Eq \
      'guest RAM locking requires [1-9][0-9]*; kernel memlock entitlement admits 4096' "$log"
  '';
  outerEvidence = _: ''
    ${pkgs.grep}/bin/grep '^strict_child_' "$out/serial.log" \
      > "$out/strict-child-evidence.txt"
  '';
}

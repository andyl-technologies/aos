# Actual isolated fault-actor return while a leased cold-page response is pending.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-native-fault-actor-terminal-flight";
  gateId = "gate:ram-fault-actor";
  testName = "packaged_qemu_executor::tests::paging_native::source_failures::production_fault_actor_returns_without_releasing_controller_or_publishing_a_cut";
  successMarker = "FAULT_ACTOR_TERMINAL_NATIVE_PASS";
  lanes = ["fault-actor-exit"];
  outerCpuSlots = 6;
  outerMemoryMiB = 8192;
  writableMiB = 8192;
  evidencePrefix = "fault_actor";
  innerEvidence = _: ''
    for evidence in \
      fault_actor_wrong_entitlement_no_effect=true \
      fault_actor_wrong_generation_no_effect=true \
      fault_actor_pending_authenticated_page_before_exit=true \
      fault_actor_original_terminal_cause_retained=true \
      fault_actor_role1_membership_released_controller_alive=true \
      fault_actor_no_install_or_guest_cut=true \
      fault_actor_original_eight_dimension_owner_retained_until_cleanup=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
    test "$(${pkgs.grep}/bin/grep -Ec '^cold_source_completion=FaultActorExit:[0-9]+:[0-9]+:[1-9][0-9]*$' "$log")" -eq 1
  '';
  # This profile proves the isolated role's actual return, not process death,
  # arbitrary arena replacement, transient DMA pins or retained spill I/O.
  outerEvidence = _: "";
}

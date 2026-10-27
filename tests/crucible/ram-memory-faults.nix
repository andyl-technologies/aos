# Authored atomic cross-page RAM bitflips under real paging ownership.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-managed-memory-faults-flight";
  gateId = "gate:ram-native-memory-faults";
  testName = "packaged_qemu_executor::tests::paging_native::faults::production_managed_memory_faults_preserve_replay_state";
  successMarker = "MANAGED_MEMORY_FAULTS_NATIVE_PASS";
  lanes = [
    "fault-discovery"
    "fault-resident-7"
    "fault-cold-7"
    "fault-resident-42"
    "fault-cold-42"
    "fault-resident-991"
    "fault-cold-991"
  ];
  # Discovery retains four admitted CPU slots while each seeded replay lane
  # retains its complete six-slot capacity, including publication services.
  outerCpuSlots = 10;
  outerMemoryMiB = 8192;
  writableMiB = 8192;
  innerTimeoutSeconds = 10500;
  outerTimeoutSeconds = 10800;
  evidencePrefix = "managed_memory_faults";
  innerEvidence = _: ''
    for evidence in \
      managed_memory_faults_seed_count=3 \
      managed_memory_faults_state_identity=true \
      managed_memory_faults_ram_root_identity=true \
      managed_memory_faults_fault_trace_identity=true \
      managed_memory_faults_modeled_time_identity=true \
      managed_memory_faults_actual_target_manifest=true \
      managed_memory_faults_actual_checkpoint_promotion=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
    for counter in \
      managed_memory_faults_committed_bitflips \
      managed_memory_faults_missing_installs \
      managed_memory_faults_wp_transitions \
      managed_memory_faults_cold_discards; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$counter=[1-9][0-9]*$" "$log")" -eq 1
    done
  '';
  # This evidence proves the authored physical cross-page bitflip and replay
  # identity. Executable-code, GVA and rejection matrices need separate native
  # coverage; this gate does not issue deployment capability receipts.
  outerEvidence = _: ''
    ${pkgs.grep}/bin/grep '^managed_memory_faults_' "$out/serial.log" \
      > "$out/fault-evidence.txt"
  '';
}

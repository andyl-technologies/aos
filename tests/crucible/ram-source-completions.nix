# Actual leased page-completion refusal before a blocked guest can publish a cut.
{
  pkgs,
  lib,
  attrPath,
  nativeQemu ? pkgs.qemu-crucible,
  nativePlugin ? pkgs.crucible-qemu-plugin,
}:
import ./ram-native-flight.nix {
  inherit pkgs lib attrPath nativeQemu nativePlugin;
  pname = "crucible-cold-source-completion-flight";
  gateId = "gate:ram-source-completions";
  testName = "packaged_qemu_executor::tests::paging_native::source_failures::production_cold_source_rejects_damaged_page_completions_without_publishing_a_cut";
  successMarker = "COLD_SOURCE_COMPLETION_FAILURE_NATIVE_PASS";
  lanes = [
    "source-reference"
    "source-changed-byte"
    "source-short-page"
    "source-changed-wire-byte"
    "source-partial-wire-body"
    "source-disconnect"
    "source-stale-generation"
    "source-stored-cas-corruption"
  ];
  # Eight separately retained registry/catalog pairs coexist with the active
  # Service and Execution. The outer profile covers their full authored slots.
  outerCpuSlots = 20;
  outerMemoryMiB = 8192;
  writableMiB = 8192;
  innerTimeoutSeconds = 11400;
  outerTimeoutSeconds = 11700;
  evidencePrefix = "cold_source";
  innerEvidence = _: ''
    for evidence in \
      cold_source_genuine_accepted_restore=true \
      cold_source_changed_byte_proof_refused=true \
      cold_source_short_page_proof_refused=true \
      cold_source_changed_wire_page_refused=true \
      cold_source_partial_wire_body_refused=true \
      cold_source_response_disconnect_refused=true \
      cold_source_stale_response_generation_refused=true \
      cold_source_stored_cas_corruption_after_admission_refused=true \
      cold_source_stored_cas_original_cause_retained=true \
      cold_source_stored_inode_restored_after_join=true \
      cold_source_damaged_response_no_install=true \
      cold_source_failed_quantum_cut_unpublished=true \
      cold_source_worker_join_before_full_vector_discharge=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$log")" -eq 1
    done
    for case in Reference ChangedByte ShortPage ChangedWireByte PartialWireBody SourceDisconnect StaleSourceGeneration StoredCasCorruption; do
      test "$(${pkgs.grep}/bin/grep -Ec "^cold_source_completion=$case:[0-9]+:[0-9]+:[1-9][0-9]*$" "$log")" -eq 1
    done
  '';
  # No general storage-failure capability follows from these specific actual
  # completion, socket, and retained-CAS-inode adversaries.
  outerEvidence = _: "";
}

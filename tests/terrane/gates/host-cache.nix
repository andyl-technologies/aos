# Policy tests alone cannot qualify physical admission or recovery. Each owning
# gate also consumes the same source's complete ext4/quota/verity VM proofs.
{
  nativeSdkGate,
  hostCacheProof,
  initialEnrollmentProof,
  ...
}: let
  cases = label: module: names:
    import ../_native-cases.nix {
      inherit label;
      selectors = map (name: "host::cache::${module}::${name}") names;
    };
  physical = ''
    test "$(cat ${hostCacheProof.native}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.native}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.reassembly}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.sdk}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.sdkWipe}/result)" = PASS
    mkdir -p "$out/nix-support"
    printf '%s\n' \
      ${hostCacheProof.native} \
      ${initialEnrollmentProof.native} \
      ${initialEnrollmentProof.reassembly} \
      ${initialEnrollmentProof.sdk} \
      ${initialEnrollmentProof.sdkWipe} > "$out/nix-support/native-proofs"
  '';
  gate = name: module: names: message:
    nativeSdkGate name ''
      ${cases name module names}
      ${physical}
      printf '%s\n' '${message}' > "$out/result"
    '';
in {
  host-layout = gate "host-layout" "native_tests" [
    "host_cache_native_layout_rejects_byte_noncanonical_roots"
    "host_cache_native_rejects_replaced_root_and_symlinked_parent"
    "host_cache_native_enumeration_refuses_foreign_pack_directory"
    "host_cache_host_local_metadata_needs_no_repository_binding"
  ] "PASS: original domain roots, native layout and configured project enrollment";

  host-verify-before-admit = gate "host-verify-before-admit" "native_tests" [
    "host_cache_native_encoded_chunk_ranges_and_corruption"
    "host_cache_native_pack_body_range_never_returns_plaintext_encoding"
    "host_cache_native_dictionary_is_verified_before_decoding_its_dependent"
    "host_cache_residence_does_not_hide_corrupt_ordinary_content"
    "host_cache_residence_verifies_identity_and_honors_operator_capacity"
  ] "PASS: verified encoded inputs, real admission and policy-selected sealed objects";

  host-eviction-s3fifo = gate "host-eviction-s3fifo" "policy_tests" [
    "host_cache_probation_main_second_chance_and_retirement_charge"
    "host_cache_pin_grace_and_read_cancellation_restore_queue_membership"
    "host_cache_owner_quota_and_failed_reservation_are_exact"
    "host_cache_eviction_counts_reservations_and_large_incoming_allocations"
    "host_cache_external_quota_deficit_does_not_require_fictitious_reservations"
    "host_cache_inventory_departure_preserves_future_holds_and_other_fifo_order"
    "host_cache_external_deficit_preserves_pins_grace_and_main_second_chance"
    "host_cache_protected_queue_cannot_starve_the_other_eligible_queue"
  ] "PASS: bounded S3-FIFO, funded native retirement and live consumer protection";

  # This gate qualifies HOST-32 startup and adoption. T6 separately requires
  # killing every trunk role at every fsync point (T-TEST-4).
  host-crash-recovery = gate "host-crash-recovery" "native_tests" [
    "host_cache_native_durable_pin_snapshot_and_scope_refusal"
    "host_cache_native_enumeration_includes_standalone_and_checks_bodies"
    "host_cache_residence_returns_verified_raw_encoding_and_encoded_ranges"
    "host_cache_residence_inventory_budget_also_bounds_ordinary_identities"
  ] "PASS: native temporary cleanup, quarantine, adopted bindings and pending retirement recovery";
}

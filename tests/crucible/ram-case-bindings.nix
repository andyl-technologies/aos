# Executable component assertions and separately inventoried native VM cases.
# Binding a native case records its intended scope, never execution evidence or
# an advertised runtime capability.
{lib}: let
  case = name: role: requirementIds: scope: {
    inherit name role requirementIds scope;
  };
  # Read Cargo's owning manifest so a package rename cannot silently leave the
  # qualification runner selecting a predecessor package.
  group = cratePath: target: features: cases: let
    manifest = builtins.fromTOML (builtins.readFile (../../crates/crucible + "/${cratePath}/Cargo.toml"));
  in {
    package = manifest.package.name;
    inherit target features cases;
  };
  component = gateName: evidenceClass: testGroups: {
    inherit gateName evidenceClass testGroups;
    requirementIds = lib.unique (lib.concatMap (group: lib.concatMap (case: case.requirementIds) group.cases) testGroups);
  };
  components = {
    format = component "gate:ram-format" "format" [
      (group "protocol/crucible-ram" "conformance" [] [
        (case "canonical_golden_vectors" "positive" ["RAM-3" "RAM-4" "RAM-5" "RAM-7"] "Canonical construction and mathematical scope selection; no machine inventory admission.")
        (case "primitive_mode_and_output_are_fixed" "adversarial" ["RAM-7"] "Official unkeyed vectors and refusal of keyed or derived modes.")
        (case "canonical_codec_adversarial" "adversarial" ["RAM-1" "RAM-2" "RAM-6" "RAM-9"] "Canonical structural records and decoding bounds.")
        (case "proof_rejects_position_length_padding_and_root" "adversarial" ["RAM-6" "RAM-7" "RAM-8" "RAM-9"] "Proof position, valid length, padding and selected root binding.")
      ])
    ];
    merkle = component "gate:ram-merkle-oracle" "model" [
      (group "protocol/crucible-ram" "conformance" [] [
        (case "persistent_tree_sparse_extreme_geometry" "positive" ["RAM-3" "RAM-6" "RAM-7" "RAM-12"] "Sparse geometry and shared immutable metadata.")
        (case "persistent_updates_fork_isolation_and_budget_rollback" "adversarial" ["RAM-12" "FP-6" "FP-7"] "Immutable paths, content reversion and metadata budget rollback.")
        (case "persistent_batches_match_independent_oracle_across_geometry" "positive" ["RAM-7" "RAM-8" "RAM-12" "FP-12"] "Independent oracle over multiple geometries, reverse updates and every page proof.")
        (case "oracle_independent_full_recompute_detects_suppressed_dirty" "adversarial" ["FP-12" "TEST-4" "TEST-5"] "Deliberately omitted dirty notification in the logical model; no deployed writer coverage.")
        (case "owned_metadata_reservations_release_and_refuse_excess" "adversarial" ["RAM-12"] "Owned metadata reservation lifetime and bounded admission.")
      ])
      (group "protocol/crucible-ram" "opaque" [] [
        (case "opaque_snapshot_seeds_scoped_roots_without_page_reads" "positive" ["RAM-4" "RAM-5" "CHECK-3"] "Authenticated opaque scoped root construction does not read page bodies; no live source admission.")
        (case "opaque_hydration_preserves_changes_and_matches_independent_oracle" "positive" ["FP-6" "FP-12" "CHECK-5"] "Proof-backed hydration retains changed paths and agrees with an independent logical oracle.")
        (case "opaque_hydration_rejects_foreign_evidence_and_rolls_back_budget" "adversarial" ["RAM-8" "RAM-12"] "Foreign proof evidence and metadata exhaustion cannot publish a hydrated successor.")
        (case "opaque_geometry_and_execution_scope_fail_closed" "adversarial" ["RAM-3" "RAM-4" "RAM-5"] "Opaque descriptors refuse mismatched geometry and execution scope.")
        (case "snapshot_rejects_independent_tree_accounting_domains" "adversarial" ["RAM-12"] "Snapshots reject trees owned by independent metadata accounting domains.")
        (case "dense_metadata_bound_covers_distinct_versions_and_checks_overflow" "positive" ["RAM-12"] "Distinct dense persistent versions remain within the model bound; bound arithmetic rejects overflow.")
      ])
    ];
    dirty = component "gate:ram-dirty-epochs" "model" [
      (group "protocol/crucible-ram" "conformance" [] [
        (case "dirty_consumers_preserve_races_and_cancel" "positive" ["TRACK-8" "TRACK-9" "TRACK-10"] "Independent consumer capture, acknowledgement, cancellation and concurrent model versions.")
        (case "dirty_fork_and_restore_reject_stale_receipts" "adversarial" ["TRACK-14" "TRACK-15"] "Private tracking incarnations and stale receipts; no native fork or restore qualification.")
        (case "dirty_limits_reject_atomically" "adversarial" ["TRACK-11"] "Range bounds and atomic failure before admitted metadata mutation.")
        (case "dirty_chunks_bound_dense_metadata_and_private_forks" "positive" ["TRACK-8" "TRACK-14"] "Dense chunk accounting, acknowledgement order and private model forks.")
      ])
      (group "protocol/crucible-ram" "lib" [] [
        (case "dirty::tests::monotonic_counter_exhaustion_preserves_ledger" "adversarial" ["TRACK-11"] "Monotonic counter exhaustion leaves the prior ledger intact.")
      ])
    ];
    store = component "gate:ram-store-transfer" "model" [
      (group "storage/crucible-store" "lib" [] [
        (case "ram::tests::lazy_lookup_proves_partial_pages_and_persistent_updates" "positive" ["STORE-1" "STORE-2" "STORE-3" "CHECK-5"] "Authenticated partial bytes and immutable predecessors; no installation into a live guest.")
        (case "ram::tests::transfer_authenticates_existing_closure_and_copies_only_changed_content" "positive" ["TRANSFER-4" "TRANSFER-5" "TRANSFER-7" "TRANSFER-14" "CHECK-6"] "Component durability and missing-only copying; no whole-world handoff readiness.")
        (case "ram::tests::exact_scope_includes_immutable_images_but_execution_omits_them" "positive" ["CHECK-3" "STORE-1"] "Logical exact scope includes immutable images.")
        (case "ram::tests::operation_budget_and_cancellation_do_not_publish_a_root" "adversarial" ["STORE-10" "TRANSFER-12"] "Cancellation before RAM root receipt; no distributed asynchronous drain claim.")
        (case "ram::tests::destination_presence_hint_cannot_hide_missing_or_corrupt_actual_page" "adversarial" ["TRANSFER-4" "STORE-2"] "A lying presence hint cannot bypass actual content authentication.")
        (case "ram::tests::fallible_change_stream_cannot_publish_a_truncated_successor" "adversarial" ["CHECK-5" "STORE-10"] "Reader failure after a changed page leaves the predecessor readable.")
        (case "ram::tests::archive_wire_transfer_validates_repeated_and_changed_content" "positive" ["STORE-2" "TRANSFER-4" "TRANSFER-7"] "Archive wire transfer authenticates repeated and changed RAM objects; no whole-world handoff readiness.")
        (case "ram::tests::absolute_wire_credits_are_idempotent_and_coordinates_do_not_authorize_other_objects" "adversarial" ["STORE-2" "STORE-10"] "Absolute wire credits are bounded and idempotent, and coordinates cannot authorize a different object.")
        (case "ram::tests::corrupt_or_foreign_wire_chunk_never_publishes_a_destination_root" "adversarial" ["STORE-2" "TRANSFER-4"] "Corrupt or foreign wire chunks prevent destination RAM root publication.")
        (case "ram::tests::canceled_wire_transfer_leaves_root_unpublished_and_retries_from_actual_content" "adversarial" ["STORE-10" "TRANSFER-12"] "Canceled archive wire transfer leaves the root unpublished and retries actual content; no live restore or migration qualification.")
        (case "ram::tests::framed_transfer_operates_between_independent_socket_instances" "positive" ["STORE-2" "TRANSFER-4"] "Separate source and destination stores exchange bounded versioned Unix frames and authenticate a partial page; no VM restore readiness claim.")
        (case "ram::tests::inventory_walk_authenticates_actual_pages_under_borrowed_exclusive_authority" "adversarial" ["STORE-2" "STORE-10"] "Inventory traversal borrows the real ref fence and rejects corrupted page bodies or visitor cancellation; no full campaign GC qualification.")
        (case "content_store::tests::admission::packed_headroom_is_checked_before_publication_and_accounts_for_existing_objects" "adversarial" ["STORE-4"] "Packed store write admission counts existing objects and refuses insufficient worst-case headroom before publication; no initial native spool admission qualification.")
        (case "content_store::tests::admission::routed_headroom_aggregates_ram_kinds_sharing_one_index" "adversarial" ["STORE-4"] "RAM kinds routed to one physical index share its finite authoritative headroom; no live pager or large-store throughput claim.")
        (case "content_store::tests::admission::read_cache_capacity_never_grants_or_denies_authoritative_write_headroom" "positive" ["STORE-4"] "Read-cache headroom remains independent of authoritative write admission; no physical disk reservation claim.")
        (case "ram::tests::dense_ram_capture_declines_exhausted_original_before_reading_pages" "adversarial" ["STORE-4"] "Dense capture retains exhausted original admission before reading guest pages or invoking progress and refuses renewal after capacity returns; no native pre-spool capacity qualification.")
        (case "content_store::test_resources::finite_fixture_loans_refuse_excess_and_retain_until_last_clone" "adversarial" ["STORE-4"] "Portable finite descriptor and resident accounts reject empty, overflowing and excessive reservations and retain credit through the last shared loan; no filesystem quota proof.")
        (case "content_store::tests::quotas::directory_quota_handle_and_reader_keep_descriptor_custody_after_facade_drop" "positive" ["STORE-4" "STORE-7"] "Actual directory handles and readers retain their admitted descriptor loans after the facade closes; no native guest placement qualification.")
        (case "content_store::tests::quotas::directory_ref_publication_credit_outlives_facade" "positive" ["STORE-4" "STORE-7"] "Actual directory ref publication retains its original resource credit through publication after the facade closes; no whole-world lifecycle qualification.")
      ])
      (group "control/crucible-daemon" "lib" ["test-support"] [
        (case "campaign_gc::tests::ram_readers::live_lazy_ram_reader_and_fork_allow_unrelated_gc_then_release_the_exact_graph" "positive" ["STORE-7" "STORE-8"] "Actual durable reader claims preserve an authenticated RAM graph across unrelated GC and a final clone's cold partial-page read, then permit reclamation after final release; no QEMU fork, restore, or live migration qualification.")
        (case "exact_checkpoint_store::production::tests::root_credit::decoded_ram_root_credit_survives_the_last_delayed_reader_clone" "adversarial" ["STORE-4" "STORE-7"] "The production checkpoint loader refuses absent metadata authority, retains finite decode credit through Loaded metadata and a delayed authenticated RAM reader, and releases it after the final owner; no physical quota or native restore qualification.")
      ])
    ];
    checkpoint = component "gate:ram-continuation" "model" [
      (group "control/crucible-daemon" "lib" ["test-support"] [
        (case "vm_lifecycle::checkpoint_store::tests::paged_exact_fixture_retains_independent_complete_images" "positive" ["CHECK-1" "CHECK-3" "CHECK-5"] "Published host fixture contains a complete authenticated changed image, partial page and immutable image; no live restore qualification.")
        (case "vm_lifecycle::checkpoint_store::tests::paged_catalog_rejects_substituted_authenticated_root" "adversarial" ["STORE-2" "CHECK-6"] "A valid catalog identity cannot authorize a different logical image.")
        (case "vm_lifecycle::checkpoint_store::tests::paged_catalog_cancellation_refuses_capture_and_preserves_existing_root" "adversarial" ["CHECK-5" "STORE-10"] "Canceled host capture cannot publish a successor or overwrite prior bytes.")
        (case "vm_lifecycle::checkpoint_store::tests::exact_ram_manifest_rejects_wrong_scope_digest_and_root_codec" "adversarial" ["CHECK-3" "STORE-2"] "Host manifest refuses wrong exact scope, logical root and noncanonical record.")
        (case "vm_lifecycle::checkpoint_store::tests::paged_artifact_refusal::paged_loader_rejects_missing_or_corrupt_device_chunks" "adversarial" ["CHECK-6"] "Production loader authenticates actual device artifact bytes before restore admission.")
        (case "vm_lifecycle::checkpoint_store::tests::paged_artifact_refusal::paged_loader_rejects_corrupt_page_with_retained_root_metadata" "adversarial" ["CHECK-6" "STORE-2"] "Real catalog page body corruption fails with retained root metadata; restoration re-admits the original bytes.")
        (case "vm_lifecycle::checkpoint_store::tests::native_checkpoint_retirement_is_crash_safe_and_idempotent" "positive" ["STORE-7"] "Native deletion refuses live closure and independent root leases and proceeds only after release.")
      ])
    ];
    source = component "gate:ram-continuation" "model" [
      (group "qemu/crucible-qemu-host" "lib" [] [
        (case "qmp::checkpoint_paged_source_tests::paged_source_serves_complete_partial_pages_with_authenticated_proofs" "positive" ["STORE-2"] "Actual Unix-socket page service authenticates complete and partial logical pages against immutable model backing; no guest installation.")
        (case "qmp::checkpoint_paged_source_tests::independently_owned_sources_preserve_predecessor_and_changed_images" "positive" ["CHECK-5"] "Separately owned source endpoints preserve old and changed complete model images.")
        (case "qmp::checkpoint_paged_source_tests::paged_source_rejects_corrupt_bytes_before_response_publication" "adversarial" ["STORE-2" "STORE-7"] "Corrupt model backing cannot publish a page response and the failure retains source authority.")
        (case "qmp::checkpoint_paged_source_tests::paged_source_rejects_stale_owner_and_repeated_sequences" "adversarial" ["STORE-2"] "A source refuses foreign ownership and replayed sequence numbers.")
        (case "qmp::checkpoint_paged_source_tests::paged_source_child_requires_private_namespace_and_retains_backing" "positive" ["STORE-7"] "Fresh child source ownership retains immutable backing independently; no actual fork or rearm.")
        (case "qmp::checkpoint_paged_source_tests::paged_source_preserves_partial_frame_across_polling" "positive" ["STORE-2"] "A real Unix-socket source retains a partial frame across poll deadlines, authenticates the completed request and serves the next sequence; no guest installation.")
        (case "qmp::checkpoint_paged_source_tests::paged_source_cancellation_closes_admission_and_releases_after_join" "adversarial" ["STORE-7" "STORE-10"] "Cancellation shuts request admission and cleanup joins before final backing release.")
      ])
    ];
    policyControl = component "gate:ram-runtime-policy" "model" [
      (group "control/crucible-control-api" "lib" ["test-support"] [
        (case "host_operational::codec::tests::status_request_has_frozen_explicit_width_big_endian_bytes" "positive" ["POLICY-10"] "Frozen explicit-width operational status request encoding only.")
        (case "host_operational::codec::tests::policy_request_roundtrip_binds_independent_reservation_and_budget_roster" "positive" ["POLICY-6" "POLICY-10"] "Canonical request binds target, reservation and budget roster; no live application or reservation amendment.")
        (case "host_operational::codec::tests::operational_codec_refuses_unknown_tags_trailing_and_oversized_data" "adversarial" ["POLICY-10"] "Canonical operational decoder refuses unknown tags, trailing bytes and oversized envelopes.")
        (case "host_operational::codec::tests::configured_durations_preserve_exact_positive_nanoseconds" "positive" ["POLICY-10"] "Configured policy and outer-cap allowances preserve exact 1 ns and 500 us; no running deadline qualification.")
        (case "host_operational::codec::tests::configured_nanoseconds_refuse_zero_overflow_and_predecessor_schemas" "adversarial" ["POLICY-10"] "Configured duration bounds and predecessor request/response schemas refuse before dispatch.")
        (case "host_operational::codec::tests::request_digest_distinguishes_nanosecond_allowances_and_wire_editions" "adversarial" ["POLICY-6" "POLICY-10"] "Authenticated request identity distinguishes one-nanosecond changes and incompatible body editions.")
        (case "host_operational::codec::tests::request_digest_binds_authenticated_principal_every_incarnation_and_payload" "adversarial" ["POLICY-6"] "Canonical request digest binds principal, every incarnation and payload; no live revision or idempotency controller.")
        (case "host_operational::codec::tests::status_roundtrip_keeps_acceptance_convergence_reservation_and_deadline_sources_separate" "positive" ["POLICY-8"] "Status representation separates acceptance, physical convergence, reservations and deadline sources.")
        (case "host_operational::codec::tests::status_refuses_unbounded_or_ambiguous_rosters_before_publication" "adversarial" ["POLICY-8" "POLICY-10"] "Status codec rejects unbounded or ambiguous rosters before publication.")
        (case "host_operational::codec::tests::policy_acceptance_roundtrip_does_not_claim_physical_convergence" "positive" ["POLICY-8"] "An acceptance receipt is represented independently of physical convergence.")
        (case "host_operational::codec::tests::policy_receipt_rejects_invented_or_missing_acceptance" "adversarial" ["POLICY-8"] "Receipt validation refuses invented or missing acceptance metadata.")
        (case "host_operational::codec::tests::backend_preferences_do_not_imply_low_peak_or_lifecycle_qualification" "adversarial" ["POLICY-3"] "Backend preference encoding cannot imply strict peak or lifecycle qualification; no actual residency measurement.")
        (case "host_operational::codec::tests::remaining_time_preserves_exact_nanoseconds_and_expired_zero" "positive" ["POLICY-8"] "Status retains exact nanosecond remaining allowances and observed zero; no running timeout test.")
        (case "host_operational::codec::tests::outer_cap_acceptance_is_original_receipt_and_service_namespace_is_distinct" "positive" ["POLICY-6" "POLICY-8"] "Receipt representation preserves original acceptance and distinct service and execution namespaces.")
        (case "host_operational::codec::tests::admitted_status_topology_fits_the_canonical_envelope_at_all_field_ceilings" "positive" ["POLICY-10"] "Schema ceiling fixture fits the operational envelope; no arbitrary machine topology admission claim.")
        (case "host_operational::codec::tests::unavailable_measurements_do_not_present_physical_zero_as_observed_residency" "adversarial" ["POLICY-8"] "Unavailable measurement encoding cannot present physical zero as observed residency.")
        (case "host_operational::codec::tests::target_discovery_binds_owner_cursor_order_and_bounded_page" "adversarial" ["POLICY-10"] "Canonical discovery pages bind owner and cursor, fit 32 ordered targets within the envelope and reject foreign or unordered cursors; no frozen inventory, live authority or paging qualification.")
      ])
      (group "control/crucible-control-server" "lib" ["test-support"] [
        (case "server::host_operational::tests::operational_transport_rejects_unauthenticated_requests_before_controller_call" "adversarial" ["POLICY-6"] "HTTP authentication failure prevents controller dispatch.")
        (case "server::host_operational::tests::authenticated_transport_dispatches_exact_target_through_executor_authority" "positive" ["POLICY-6"] "Authenticated HTTP dispatch binds the exact target through a controlled executor authority; no native policy application.")
        (case "server::host_operational::tests::host_status_dispatch_does_not_wait_for_modeled_lifecycle_lock" "positive" ["POLICY-9"] "Status dispatch bypasses a held modeled lifecycle mutex; no native fault-blocked responsiveness qualification.")
        (case "server::host_operational::tests::malformed_and_read_only_mutations_never_reach_controller" "adversarial" ["POLICY-6" "POLICY-10"] "Malformed or read-only transport mutations cannot reach the controller.")
        (case "server::host_operational::tests::host_protocol_predecessor_is_rejected_before_live_dispatch" "adversarial" ["POLICY-10"] "Predecessor RPC transport schema is refused before controlled authority dispatch.")
      ])
    ];
    policyHistory = component "gate:ram-policy-history" "model" [
      (group "control/crucible-daemon" "lib" ["test-support"] [
        (case "host_operational_registry::tests::live_budget_updates_replay_original_receipts_after_later_changes" "positive" ["POLICY-6" "POLICY-7"] "Actual controller and disk history replay original receipts after later revisions; no native memory convergence.")
        (case "host_operational_registry::tests::outer_cap_retries_retain_original_allowances_after_later_amendments" "positive" ["TIME-9" "TIME-10"] "Shared operational cap amendments retain original acceptance and elapsed origin; no fault-blocked guest qualification.")
        (case "host_operational_registry::tests::exhausted_history_refuses_without_effect_and_does_not_forget_old_keys" "adversarial" ["POLICY-6" "POLICY-11" "TEST-16"] "History capacity refusal precedes controller mutation and retained accepted keys remain replayable; no complete rate/cache admission qualification.")
        (case "host_operational_registry::tests::unauthorized_principals_and_stale_generations_have_no_effect" "adversarial" ["POLICY-6" "POLICY-7"] "Controller refuses unauthenticated principals and stale operational incarnations before effects.")
        (case "host_operational_registry::tests::interrupted_durable_intent_is_fenced_after_restart" "adversarial" ["POLICY-6" "POLICY-11"] "Restart preserves and fences interrupted durable intent; no live native restart convergence.")
        (case "host_operational_registry::history::tests::restart_rolls_forward_an_exact_synced_charge_and_retains_quota" "positive" ["POLICY-11"] "Real disk history recovers a synced exact charge without losing its quota accounting.")
        (case "host_operational_registry::history::tests::restart_refuses_corrupt_staged_charge_without_forgetting_it" "adversarial" ["POLICY-11"] "Corrupt staged durable history fails closed and cannot release its accepted accounting charge.")
        (case "host_operational_registry::history::tests::predecessor_history_refuses_in_place_without_losing_charges_or_key_fences" "adversarial" ["POLICY-6" "POLICY-11"] "Valid predecessor journal records refuse in place without forgetting charges or treating a fenced key as absent.")
        (case "host_operational_registry::history::tests::nanosecond_acceptance_replays_after_restart_and_fences_changed_bytes" "positive" ["POLICY-6" "POLICY-11"] "Real disk history retains exact 1 ns and 500 us acceptance through restart and conflicts on changed bytes under the same key.")
      ])
    ];
    supervision = component "gate:ram-supervision" "model" [
      (group "qemu/crucible-qemu-plugin" "lib" [] [
        (case "runtime::command_receive::delivery::tests::ready_post_refusal_saves_consumption_and_still_attempts_both_actual_returns" "adversarial" ["TIME-9"] "The Rust keeper records modeled Ready consumption before a negative post and still attempts payload and pure lifetime return; this issues no Main borrower or Native authority.")
        (case "runtime::command_receive::delivery::tests::refused_ready_return_preserves_first_error_through_real_lifetime_retry" "adversarial" ["TIME-9"] "A modeled retained Ready dependency preserves its first error across later independent physical consumption; copied status grants no cleanup permission.")
        (case "runtime::command_receive::delivery::tests::copied_ready_output_never_substitutes_for_native_lifetime_consumption" "adversarial" ["TIME-9"] "A copied Ready output cannot make the Rust keeper report consumption when the modeled Native lifetime return refuses.")
        (case "runtime::command_receive::delivery::tests::malformed_ready_success_reports_protocol_error_after_independent_returns" "adversarial" ["TIME-9"] "Malformed modeled Ready success is reported after both independent return attempts, preserving consumed lifetime facts rather than reissuing custody.")
        (case "runtime::command_receive::delivery::tests::negative_payload_claim_keeps_born_delivery_for_actual_return" "adversarial" ["TIME-9"] "A local field-consumption model preserves delivery custody after a payload claim refusal and performs exact return without reissuing the same receive; no Native authority is modeled.")
        (case "runtime::command_receive::delivery::tests::payload_post_refusal_saves_real_lifetime_consumption_before_reporting_failure" "adversarial" ["TIME-9"] "The wrapper records modeled pure lifetime consumption before reporting a separate payload post refusal; this establishes no actual module or publisher return.")
        (case "runtime::command_receive::delivery::tests::retained_payload_refusal_preserves_custody_and_initiating_error" "adversarial" ["TIME-9"] "A modeled retained payload blocks lifetime consumption and preserves the first payload failure, projection, serial and canonical Runtime field.")
        (case "runtime::command_receive::tests::first_member_constructor_receives_the_exact_writer_before_negative_status" "adversarial" ["TIME-9"] "The actual constructor wrapper first-binds the exact Park writer and both payload callbacks before a modeled born-negative member result; model tokens issue no Native membership.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::canonical_return_destroys_actual_pending_payload_before_consuming_holder" "positive" ["TIME-9"] "The actual pinned module journal transfers its non-Copy payload to one exact holder and destroys it before clearing that holder; the mapped request stays pending and no Host epoch is returned.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::copied_holder_cannot_retire_the_actual_payload" "adversarial" ["TIME-9"] "A copied field cannot retire the actual module payload even with its matching local pointer and serial; only the exact recorded field can consume it.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::stale_serial_retains_holder_and_excludes_replacement" "adversarial" ["TIME-9"] "A stale local serial preserves the actual module payload and canonical field and prevents another read from replacing it; no Native Original is issued.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::second_claim_cannot_replace_the_exact_first_holder" "adversarial" ["TIME-9"] "A second local claim cannot redirect the actual pending payload into another output field or create a new local serial.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::negative_read_post_still_transfers_the_actual_retained_payload" "adversarial" ["TIME-9"] "A genuine read post refusal preserves its actual captured payload for exact module holder transfer; this grants no action or publisher loan.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::actual_locked_payload_borrow_refuses_return_without_consumption" "adversarial" ["TIME-9"] "A real module borrower retains the journal mutex and prevents payload destruction or holder clearing until it returns; Native uses require separate issuance.")
        (case "runtime::live_callbacks::control_facts::protected_read::payload::tests::poisoned_payload_borrow_keeps_actual_pending_owner_and_holder" "adversarial" ["TIME-9"] "An interrupted actual module borrower poisons the journal, preserves the complete pinned owner and canonical holder, and refuses local return instead of fabricating consumption.")
        (case "runtime::command_receive::delivery::tests::negative_birth_transfers_custody_before_reporting_first_failure" "adversarial" ["TIME-9"] "The Rust keeper transfers a born-negative output before returning its saved refusal in a local field-consumption model; no Native issuance or peer-return qualification.")
        (case "runtime::command_receive::delivery::tests::transfer_refusal_retains_the_exact_creation_output_field" "adversarial" ["TIME-9"] "A modeled unconsumed transfer retains and returns only the exact original creation output field; copied projections provide no consumption evidence.")
        (case "runtime::command_receive::delivery::tests::negative_transfer_after_consumption_keeps_the_canonical_field" "adversarial" ["TIME-9"] "A modeled consumed transfer retains its actual canonical destination despite negative status; this checks wrapper custody only.")
        (case "runtime::command_receive::delivery::tests::refused_return_preserves_projection_serial_and_canonical_custody" "adversarial" ["TIME-9"] "Modeled return refusal preserves the original projection, serial and holder and creates no replacement delivery.")
        (case "runtime::command_receive::delivery::tests::consumed_delivery_cannot_reissue_from_the_same_retained_receive" "adversarial" ["TIME-9"] "Pure modeled holder consumption cannot reissue from the same retained parent receive; no payload retirement, ACK or action permission.")
        (case "runtime::command_receive::delivery::tests::absent_born_output_refuses_rebirth_and_return" "adversarial" ["TIME-9"] "Malformed modeled construction cannot retry birth or invent a holder return from absent output.")
        (case "runtime::command_receive::delivery::tests::current_refusal_never_releases_or_recreates_delivery" "adversarial" ["TIME-9"] "A modeled current refusal neither frees custody nor starts a replacement receive or delivery.")
        (case "runtime::command_receive::tests::received_zero_facts_survive_negative_post_and_never_reenter_creation" "adversarial" ["TIME-9"] "Actual wrapper control flow preserves delivery custody before reporting a modeled negative receive post, then returns its exact delivery holder before refused parent return; no Native authority is issued by model tokens.")
        (case "runtime::live_callbacks::control_facts::protected_read::tests::received_payload_excludes_replacement_after_local_read_and_mapped_ack" "adversarial" ["TIME-9"] "The actual paid child retains its received payload after local read release and refuses replacement after a mapped ACK; no Host publisher loan, Native Original or physical-return qualification.")
        (case "runtime::live_callbacks::control_facts::protected_read::tests::pending_payload_borrow_retains_the_actual_journal_until_receiver_returns" "positive" ["TIME-9"] "A bounded receiver borrows the actual retained payload under its owning journal lock; ending that borrower neither retires the payload nor ACKs the mapped request.")
        (case "runtime::live_callbacks::control_facts::protected_read::tests::negative_post_retains_the_owned_payload_before_the_signed_result" "adversarial" ["TIME-9"] "Independent post refusal preserves the actual received tuple in the child owner and excludes reuse; no Native delivery or peer return claim.")
        (case "runtime::live_callbacks::control_facts::protected_read::tests::unwind_after_payload_deposit_retains_uncertain_custody_and_refuses_reuse" "adversarial" ["TIME-9"] "Unwind after actual payload deposit poisons the owning journal, retains the original tuple and blocks reuse without publishing reader completion or ACK.")
        (case "runtime::live_callbacks::control_facts::protected_read::tests::empty_read_does_not_create_a_pending_payload" "adversarial" ["TIME-9"] "An actual empty slot creates no payload owner and a subsequent genuine pending tuple can be received once; no semantic action authority.")
      ])
      (group "host/crucible-host-resources" "lib" [] [
        (case "host_services::process_birth::executor_purpose::source_host::roster_allocation::tests::sealed_roster_funding_excludes_all_later_upgrade_intervals" "adversarial" ["TIME-9"] "The actual funding gate excludes concurrent and later upgrade intervals while real paired mechanism charges survive every funding observer; no authenticated Main is issued.")
        (case "host_services::process_birth::executor_purpose::source_host::roster_allocation::tests::poisoned_roster_upgrade_gate_retains_original_funding" "adversarial" ["TIME-9"] "Poison in the real allocation gate refuses further upgrade intervals without refunding either paired charge while its owner remains; no Source is issued.")
        (case "host_services::process_birth::executor_purpose::source_host::roster_allocation::tests::roster_funding_prices_full_retained_allocation_and_its_control" "positive" ["TIME-9"] "Production pricing includes the entire retained allocation, funding control, constructor frame and both lease records, rejecting zero and overflow; a byte extent grants no Native authority.")
        (case "host_supervision::tests::native_cap_bindings_preserve_kernel_origin_across_owners_and_amendments" "positive" ["TIME-5" "TIME-10"] "Shared operational owners retain the original kernel monotonic anchor after amendment; no live native watcher or journal recovery qualification.")
        (case "host_supervision::tests::live_budget_updates_retain_original_operation_and_progress_coordinates" "positive" ["TIME-4"] "Class budget amendments retain the modeled operational start and progress coordinates; no guest fault-blocked control response claim.")
        (case "host_supervision::tests::infrastructure_cannot_lose_its_last_bound_and_cleanup_is_independent" "adversarial" ["TIME-9"] "Infrastructure phase admission refuses removal of its last finite allowance while cleanup retains its independent bound.")
        (case "host_supervision::tests::repeated_progress_does_not_renew_a_stalled_operation" "adversarial" ["TIME-2" "TIME-3"] "Repeated completed-work coordinates cannot renew component progress; no deployed guest quantum oracle.")
        (case "host_supervision::tests::saturated_work_inventory_retains_two_finite_control_records" "adversarial" ["TIME-9"] "Finite ordinary work saturation preserves separately bounded control and cleanup records; no native fault-service availability qualification.")
      ])
      (group "host/crucible-host-resources" "source_control_terminal" [] [
        (case "final_control_header_closes_before_original_paired_credit_returns" "positive" ["TIME-9"] "The production Source control owner closes its actual shared allocation while both original service loans remain charged; this component creates no Native Source or physical-return proof.")
        (case "concurrent_control_observers_close_before_one_paired_refund" "adversarial" ["TIME-9"] "Concurrent observers perform one actual control close before either paired account refunds; this control proves no native worker, process-family or complete diagnostic lifetime.")
      ])
      (group "qemu/crucible-qemu-host" "lib" ["test-support"] [
        (case "node::exact_snapshot::capture_original::tests::final_checkpoint_loan_frees_actual_allocation_before_original_credit" "positive" ["TIME-2" "TIME-9"] "Actual checkpoint-loan cloning allocates nothing; its final real Arc deallocation precedes original service-credit return after parent retirement. Component entry supplies no native receiving authority.")
        (case "node::exact_snapshot::capture_original::tests::checkpoint_loan_unwind_keeps_credit_through_actual_allocation_free" "adversarial" ["TIME-2" "TIME-9"] "Unwinding retains original service credit before and after the actual checkpoint-loan allocation free; no native receiving or operation authority qualification.")
        (case "spawn::helper_receiver::probe_output::tests::received_probe_buffers_close_before_their_original_paired_refund" "positive" ["TIME-9"] "Both actual received output allocations close while both original mechanism loans remain charged; this generic owner test issues no Native Source or diagnostic payload admission.")
        (case "spawn::helper_receiver::probe_output::tests::received_probe_move_keeps_both_buffers_funded_on_the_receiving_thread" "adversarial" ["TIME-9"] "Moving the actual captures to another thread preserves both original charges through both buffer frees, then returns them; no native process or full-owner return qualification.")
        (case "spawn::helper_first::tests::helper_first_control_retains_paired_credit_through_its_actual_free" "positive" ["TIME-9"] "The concrete helper cause retains real paired mechanism charges before and after its shared control is physically freed; no Native Source activation or error-payload funding qualification.")
        (case "spawn::helper_first::tests::concurrent_helper_first_observers_close_once_before_paired_refund" "adversarial" ["TIME-9"] "Eight concurrent observers close the shared helper cause exactly once while both original charges remain held through deallocation; no Native return receipt.")
        (case "linux_attempt_host::original_node::helper_receiver::tests::unfunded_helper_first_stays_in_preborn_journal_without_shared_birth" "adversarial" ["TIME-9"] "An unissued journal preserves its actual typed first cause without allocating a shared diagnostic or issuing replacement funding.")
      ])
      (group "control/crucible-control-api" "backend_error_terminal" [] [
        (case "lifecycle_error_frees_its_control_before_returning_original_paired_credit" "positive" ["TIME-9"] "The production lifecycle error frees its actual shared allocation with both original service loans still charged; no native process or full diagnostic payload qualification.")
        (case "mixed_typed_and_lifecycle_observers_close_once_before_the_paired_refund" "adversarial" ["TIME-9"] "Concurrent typed and lifecycle observers preserve the same downcastable error and one allocation, then observe one physical control close before either paired loan refunds; no Native Source is issued.")
      ])
      (group "qemu/crucible-qemu-host" "lib" [] [
        (case "linux_attempt_host::original_roster::storage::tests::funded_roster_returns_native_body_credit_while_weak_allocation_stays_paid" "positive" ["TIME-9"] "The production closed roster body returns real native mechanism pairs while actual Weak allocation custody retains a separate paid pair through observed final deallocation; no Main authentication or Source qualification.")
        (case "linux_attempt_host::original_roster::storage::tests::real_strong_borrow_refuses_retirement_without_sealing_later_cleanup" "adversarial" ["TIME-9"] "A real strong roster borrower blocks credit release without sealing the later cleanup route; only actual borrower destruction permits retirement.")
        (case "linux_attempt_host::original_roster::storage::tests::live_native_slot_refuses_retirement_without_sealing_its_physical_cleanup" "adversarial" ["TIME-9"] "A live original slot prevents funded body retirement and leaves its real cleanup route available until physical vector closure.")
        (case "linux_attempt_host::original_roster::storage::tests::weak_clones_allocate_nothing_and_keep_charge_through_last_real_free" "positive" ["TIME-9"] "Closed Weak clones allocate no storage and retain both actual allocation charges through the observed final Weak deallocation.")
        (case "linux_attempt_host::original_roster::storage::tests::active_upgrade_gate_refuses_retirement_and_preserves_native_credit" "adversarial" ["TIME-9"] "A genuinely held upgrade gate blocks funded retirement and preserves original native mechanism credit until that interval closes.")
        (case "linux_attempt_host::original_roster::storage::tests::sealed_retirement_excludes_real_weak_upgrade_before_sole_body_drop" "adversarial" ["TIME-9"] "After sealing, an actual Weak upgrade is refused while the real sole strong body still exists; allocation funding remains through final Weak closure.")
        (case "linux_attempt_host::original_roster::storage::tests::sole_roster_owner_keeps_main_allocation_charge_through_actual_deallocation" "positive" ["TIME-9"] "With no Weak observers, the closed owner keeps both real mechanism charges through its observed Arc deallocation before refund; this component authenticates no Main.")
        (case "spawn::helper_receiver::tests::probe_timeout_retains_both_partial_streams_and_the_live_child" "adversarial" ["TIME-7" "TIME-9"] "A real component probe times out with both actual partial diagnostic streams retained in its receiving slot and its child still owned for cleanup; no native Source, funding transfer or full-owner return qualification.")
        (case "spawn::helper_receiver::tests::probe_output_limit_keeps_the_first_bounded_bytes_and_child_custody" "adversarial" ["TIME-7" "TIME-9"] "The production probe rejects excess real output while preserving each bounded prefix and actual process custody; no native Source or final diagnostic funding qualification.")
        (case "linux_attempt_host::original_roster::process_purpose::source_cleanup::tests::nominal_helper_receiver_cannot_promote_an_unissued_source" "adversarial" ["TIME-9"] "Cloned nominal receivers preserve identity while changed roster, slot, generation or incarnation observers refuse; absent Source custody cannot return either original loan. This control creates no native authority.")
        (case "linux_attempt_host::original_node::helper_receiver::tests::unfunded_helper_refuses_before_buffers_or_process_birth" "adversarial" ["TIME-9"] "An absent authentic Main Source payer refuses the production helper body before probe storage or process birth; this negative component control issues no native credit.")
        (case "spawn::helper_receiver::tests::probe_capture_never_grows_beyond_its_prepaid_capacity" "adversarial" ["TIME-9"] "A capture refuses excess bytes without growing its admitted allocation; this allocation-bound control issues no native resource credit.")
        (case "spawn::helper_receiver::tests::image_wait_observes_success_under_the_existing_original" "positive" ["TIME-2" "TIME-9"] "A real component child completes under the same retained operation identity; no native Source, helper recipient or funding qualification.")
        (case "spawn::helper_receiver::tests::image_wait_retains_the_live_child_when_its_same_original_is_canceled" "adversarial" ["TIME-2" "TIME-7" "TIME-9"] "Cancellation after process birth refuses the production image wait with the same typed operation cause while the component retains the live child for containment; no native cleanup-return or funding qualification.")
      ])
    ];
    resources = component "gate:ram-runtime-policy" "model" [
      (group "control/crucible-daemon" "lib" ["test-support"] [
        (case "executor_supervisor::tests::host_resources::authored_assignment_peak_is_reserved_before_any_node_launch" "positive" ["RESOURCE-1" "RESOURCE-6"] "Actual actor reserves an authored eight-dimensional assignment peak before node launch and reports the remaining capacity; no measured native peak qualification.")
        (case "executor_supervisor::tests::host_resources::global_paging_task_and_descriptor_limits_are_independent" "adversarial" ["RESOURCE-1"] "Actor admission refuses independently exhausted paging, task and descriptor capacity; no kernel actor or physical residency proof.")
        (case "executor_supervisor::tests::host_resources::finished_execution_keeps_physical_template_and_service_charges_until_cleanup" "positive" ["RESOURCE-2" "RESOURCE-6"] "Actual actor retains template and service reservation ownership after modeled execution finishes until explicit cleanup; no physical final-close or native fork qualification.")
      ])
    ];
    cutover = component "gate:ram-cutover" "format" [
      (group "protocol/crucible-qemu-protocol" "ram_cutover" [] [
        (case "current_ram_contract_peer_receives_exact_ack" "positive" ["CUT-1" "TEST-14"] "Current control/shared-memory peer acknowledgement.")
        (case "predecessor_and_mixed_peers_are_rejected_without_ack" "adversarial" ["CUT-1" "TEST-14"] "Predecessor and mixed control/shared-memory combinations are refused.")
        (case "current_plugin_accepts_only_current_ack" "positive" ["CUT-1" "TEST-14"] "Current plugin handshake acknowledgement.")
        (case "predecessor_ack_cannot_authorize_setup" "adversarial" ["CUT-1" "TEST-14"] "Old acknowledgement cannot authorize setup.")
      ])
      (group "protocol/crucible-qemu-shmem" "ram_cutover" [] [
        (case "current_ram_semantic_header_is_admitted" "positive" ["CUT-1" "TEST-14"] "Current semantic shared-memory header admission.")
        (case "identical_layout_cannot_relabel_predecessor_ram_semantics" "adversarial" ["CUT-1" "TEST-14"] "An unchanged physical layout cannot disguise predecessor semantics.")
        (case "predecessor_is_refused_before_geometry_or_clock_admission" "adversarial" ["CUT-1" "TEST-14"] "Version refusal precedes hostile geometry or clock validation.")
      ])
      (group "control/crucible-daemon" "lib" ["test-support"] [
        (case "vm_lifecycle::checkpoint_store::tests::closure_manifest_round_trip_is_canonical" "positive" ["CUT-1" "TEST-14"] "Current host closure codec admission.")
        (case "vm_lifecycle::checkpoint_store::tests::predecessor_closure_is_refused_before_payload_decoding" "adversarial" ["CUT-1" "TEST-14"] "Prior closure prefix is refused before any current payload decoding.")
      ])
    ];
  };
  componentCaseBindings = lib.concatMap (
    name: let
      component = components.${name};
    in
      lib.concatMap (
        group:
          map (case:
            case
            // {
              inherit (component) gateName evidenceClass;
              inherit (group) package target features;
            })
          group.cases
      )
      component.testGroups
  ) (builtins.attrNames components);
  nativeCase = gateName: name: role: requirementIds: scope:
    (case name role requirementIds scope)
    // {
      inherit gateName;
      evidenceClass = "live-vm";
      package = "crucible-daemon";
      target = "lib";
      features = [];
      executionStatus = "requires-native-execution-evidence";
      qualified = false;
      advertisedCapabilities = [];
    };
  nativeTransferCase = nativeCase "gate:ram-native-transfer" "packaged_qemu_executor::tests::paging_native::transfer::production_authenticated_archive_transfer_restores_a_fresh_cold_receiver";
  nativeCases = [
    (nativeCase "gate:ram-live-paging" "packaged_qemu_executor::tests::paging_native::production_managed_paging_preserves_guest_state_and_cold_writes" "positive" ["PAGER-1" "PAGER-4" "PAGER-6" "PAGER-7" "PAGER-8" "PAGER-9" "TEST-7" "TEST-11"] "The disposable managed-kernel case compares a resident lane with actual missing-page reads, cold writes, write protection, preserved spill and paused reclamation under the same guest capacity and logical coordinates. It exercises only its declared machine and memory sizes, not the full storage-failure matrix, borrower profiles or general low-peak qualification. Naming the case is not execution evidence.")
    (nativeCase "gate:ram-live-paging" "packaged_qemu_executor::tests::paging_native::production_managed_paging_preserves_guest_state_and_cold_writes" "adversarial" ["PAGER-3"] "The native case refuses an unqualified backend or lifecycle request rather than presenting it as a strict low-peak capability. It does not establish every kernel-capability or storage-failure adversary.")
    (nativeCase "gate:ram-native-hot-fork" "packaged_qemu_executor::tests::hot_fork_native::production_managed_hot_fork_preserves_ram_and_reaps_fresh_child" "positive" ["FORK-2" "FORK-11" "FORK-12" "FORK-13" "CHECK-9" "CHECK-14" "TEST-12"] "An accepted promoted boundary supplies a retained local source and fresh managed child. The case checks actual cold reconstruction, private child writes preserving the source root, distinct operational ownership and cleanup before capacity discharge. This single admitted profile does not qualify resident-required locking, general low peak, all inherited dirty consumers or every fork failure.")
    (nativeCase "gate:checkpoint-delta-flight" "packaged_qemu_executor::tests::paging_native::lazy_restore::production_lazy_restore_first_cold_quantum_matches_resident_oracle" "positive" ["CHECK-9" "CHECK-10" "CHECK-11" "CHECK-14" "TEST-12"] "Two independently accepted resumed lanes compare the first completed quantum and published RAM identity; the cold lane must show real missing installs before subsequent oracle reads and preserve cleanup ownership. The measured launch-to-first-quantum interval includes owner discovery and policy setup. It is not an old descriptor-ack metric or qualification of arbitrary remote demand, all reconstruction devices or adversarial cancellation.")
    (nativeCase "gate:ram-native-memory-faults" "packaged_qemu_executor::tests::paging_native::faults::production_managed_memory_faults_preserve_replay_state" "positive" ["TRACK-17" "TRACK-18" "TRACK-20" "TEST-18"] "Resident and cold accepted executions repeat authored cross-page persistent bit mutations across three seeds and compare fault replay state, logical RAM roots and guest coordinates after real missing installs, write protection and reclaim. This case does not cover executable-code invalidation, GVA targets, retention/rowhammer, poison, hardware delivery or the complete rejection matrix.")
    (nativeCase "gate:ram-native-byte-service" "packaged_qemu_executor::tests::paging_native::byte_service::production_byte_service_latency_is_placement_independent" "positive" ["TRACK-17" "TEST-11" "TEST-18"] "The unchanged one-byte guest benchmark repeats its admitted memory-service model across resident and cold placement with three seeds and actual host service latency variation. It compares native service ledgers and semantic coordinates without granting qualification to other service models, fault mechanisms or the complete transparency corpus.")
    (nativeTransferCase "positive" ["TRANSFER-2" "TRANSFER-8" "TRANSFER-9" "TRANSFER-17"] "Two independently retained, quota-backed instances publish a complete authenticated executable archive before a separate fresh verification Replay Service restores the receiver. Its first cold quantum and RAM root must match the resident source. This named case is not execution evidence and grants no cross-host or maintenance ownership handoff capability.")
    (nativeTransferCase "adversarial" ["TRANSFER-6" "TRANSFER-8" "TRANSFER-17"] "The same native case requires missing actual source content, corrupt actual receiver content and read-only destination refusal to prevent archive publication. These controls do not establish restart, cancellation drain, remote serving or destructive source handoff qualification.")
    (nativeCase "gate:ram-native-blocked-control" "packaged_qemu_executor::tests::paging_native::blocked_control::production_blocked_pager_control_preserves_identity_and_refuses_late_completion" "positive" ["TEST-8" "TEST-9"] "An authenticated page completion is causally held while a real cold guest is fault-blocked. A separate control thread amends live policy and the released valid completion must preserve the complete first-quantum boundary; this profile does not cover simultaneous capture, hashing, prefetch or every revision/lost-response adversary.")
    (nativeCase "gate:ram-native-blocked-control" "packaged_qemu_executor::tests::paging_native::blocked_control::production_blocked_pager_control_preserves_identity_and_refuses_late_completion" "adversarial" ["TEST-9" "TEST-21"] "Independent original-cap expiry and cancellation must refuse the delayed authentic completion, preserve the published scheduler cut and retain all eight resource charges through actual reap/join. This is a causal blocked-read control profile, not every missing-budget, deadline-class or amendment race.")
    (nativeCase "gate:ram-source-completions" "packaged_qemu_executor::tests::paging_native::source_failures::production_cold_source_rejects_damaged_page_completions_without_publishing_a_cut" "adversarial" ["PAGER-5" "PAGER-8" "TEST-20"] "Accepted cold replay refuses changed or short authentic leased completions, changed encoded wire bytes, partial-body EOF, endpoint disconnect, stale generation and postadmission corruption of the requested stored CAS page before page installation or a published cut. The corruption lane preserves the typed storage cause and restores the fixture only after reap and source join. This does not exercise spill I/O failure, storage exhaustion, isolated native worker death, DMA/kernel pins or arena replacement.")
    (nativeCase "gate:ram-fault-actor" "packaged_qemu_executor::tests::paging_native::source_failures::production_fault_actor_returns_without_releasing_controller_or_publishing_a_cut" "adversarial" ["PAGER-5" "PAGER-8" "TEST-19"] "An entitled native fault actor actually returns while an authenticated cold-page response is pending. The live controller retains registration, source and spill authority; the original terminal cause must prevent page installation or a guest cut, and all eight charges remain until reap and join. Wrong entitlement and generation must have no effect. This covers the isolated actor-return profile only, not process death, device or child-initialization access, transient DMA/kernel pins, spill I/O or arena replacement.")
    (nativeCase "gate:ram-dma-borrowers" "qemu_hot_fork_world_factory::tests::native_acceptance::production_managed_dma_maps_block_reclaim_until_real_completion" "adversarial" ["TEST-19"] "A genuine managed virtqueue retains its native RAM bounce maps through the authenticated original block completion. A live policy request must remain pending without physical discard or a placement receipt while those maps are held; actual completion must release them before convergence and reclaim, preserving the complete canonical guest boundary and all eight resource charges through cleanup. This is the retained virtqueue-map profile only, not host-worker death, temporary kernel pins, arbitrary direct caches or arena reuse. The authored case remains unexecuted and unqualified.")
    (nativeCase "gate:ram-spill-io" "packaged_qemu_executor::tests::paging_native::spill_io::production_spill_sync_failure_retains_original_cause_and_refuses_guest_cut" "adversarial" ["PAGER-6" "PAGER-8" "TEST-20"] "After successful authenticated preservation and an actual write-protect guest store, a private device-mapper target injects retained spill writeback EIO under the original Writeback operation. The original typed cause must prevent installation and a guest cut while full-vector custody remains until physical cleanup. Catalog and registry stay on their independent healthy quota filesystem. This covers one postadmission spill I/O failure, not storage exhaustion, process death, retained DMA/kernel pins or arena replacement.")
    (nativeCase "gate:ram-native-strict-placement" "packaged_qemu_executor::tests::paging_native::strict_modes::production_strict_placement_has_verified_kernel_and_disk_evidence" "positive" ["POLICY-3"] "A genuine parent owner compares the reference boundary and RAM identity with verified kernel locks, unlock and authenticated disk cuts, including a later cut after intervening writes. The fixture retains the full execution peak and an independent finite memlock entitlement. It does not qualify child relocking, arbitrary platforms or a general low-residency execution peak.")
    (nativeCase "gate:ram-native-strict-child-lock" "packaged_qemu_executor::tests::paging_native::strict_child::production_strict_child_relocks_and_refuses_lower_kernel_entitlement" "positive" ["POLICY-12" "TEST-17"] "A fresh child establishes and verifies its own kernel locks under independent admitted entitlement while preserving the locked parent's root and ownership through cleanup. This single child profile does not establish descendant relocking or every reservation, prefault and verification failure required by the broader matrix.")
    (nativeCase "gate:ram-native-strict-child-lock" "packaged_qemu_executor::tests::paging_native::strict_child::production_strict_child_relocks_and_refuses_lower_kernel_entitlement" "adversarial" ["POLICY-12" "TEST-17"] "The same genuine fork flight lowers only the child's independently authored kernel memlock limit and requires refusal before readiness, unchanged parent locks and retained full-vector cleanup. This is the lower-entitlement refusal profile, not independent injection of every locking syscall, reservation, prefault or descendant failure.")
    (nativeCase "gate:ram-completed-throughput" "packaged_qemu_executor::tests::paging_native::throughput::completed_campaign_throughput_matrix" "positive" ["PERF-4"] "The authored wall-time matrix records 27 fixed placement/concurrency/repeat rows and 63 distinct newly Completed campaign attempts under pinned native inputs and retained full execution peaks. Failed rows remain recorded, and the zero safely evictable target requires actual discards and missing installs. The case reports source/profile and repeated wall rates only; it does not supply process CPU, controlled cold/warm storage, paired performance parity or broader campaign throughput qualification. Naming the case is not execution evidence.")
    (nativeCase "gate:ram-storage-scale" "packaged_qemu_executor::tests::paging_native::storage_scale::production_ram_storage_scales_past_packed_index_limit" "positive" ["PERF-3"] "A storage-only genuine Service publishes and verifies 131072 unique pages and their tree graph, performs bounded inventory/read/GC batches, and retains the rooted graph through the last reader under installed quota. It does not snapshot a guest, exercise every region/backlog/sibling workload or qualify paging performance.")
  ];
  caseBindings = componentCaseBindings ++ nativeCases;
in {
  inherit components nativeCases caseBindings;
}

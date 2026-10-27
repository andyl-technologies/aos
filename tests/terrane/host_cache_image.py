"""Installs exact source-bound native cache component executables and ELF closure."""

from collections import Counter
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import native_sdk_test_image as shared

TARGETS = {
    "host_cache_fixture": ("terrane-linux", "example", "examples/host_cache_fixture.rs", ["native-test-fixtures", "tokio"]),
    "terrane": ("terrane-cli", "bin", "src/main.rs", []),
    "aos-terrane-host": ("aos-terrane-integration", "bin", "src/bin/aos-terrane-host.rs", []),
}
PROFILE = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
           "overflow_checks": True, "test": False}

UNIT_NAME = "terrane-fs-unit"
# The five creator fixtures require the actual guest administrator; every other
# library case runs as an isolated ordinary user on ext4.
UNIT_PREFIXES = ("configured::", "configured_gc::", "configured_sdk::", "host_cache::", "host_quota::socket::",
                 "publisher_io::", "publisher_local::", "quota_confinement::")
ROOT_UNIT_TESTS = (
    'host_quota::initial_enrollment::tests::actual_initial_receipt_refuses_shared_and_other_root_guards_before_effects',
    'host_quota::initial_enrollment::tests::actual_initial_receipt_rejects_unknown_entries_before_scaffold_effects',
    'host_quota::initial_enrollment::tests::actual_scaffold_creation_retains_all_original_inodes_bytes_and_exclusions',
    'host_quota::initial_enrollment::tests::extended_observation_closes_on_original_preimages_after_actual_enumeration',
    'host_quota::initial_enrollment::tests::extended_scaffold_recheck_refuses_same_bytes_replacement_and_untracked_names',
)
UNIT_PROFILE = {"opt_level": "s", "debuginfo": 0, "debug_assertions": True,
                "overflow_checks": True, "test": True}
UNIT_TESTS = (
    'configured::tests::configured_cache_plan_checks_all_domains_without_opening_missing_helper',
    'configured::tests::configured_cache_plan_refuses_later_invalid_resources_before_native_startup',
    'configured::tests::configured_cache_plan_requires_exact_resource_domain_coverage',
    'configured::tests::configured_preflight_binds_distinct_explicit_administrative_roots',
    'configured::tests::configured_preflight_refuses_overlapping_roots_and_aliasing_endpoints',
    'configured::tests::configured_preflight_rejects_later_domain_policy_before_any_open',
    'configured::tests::configured_preflight_rejects_unrepresentable_unix_socket',
    'configured::tests::configured_preflight_requires_real_quota_inputs_before_startup',
    'configured_gc::preflight::tests::pure_preflight_accepts_unopened_local_inputs',
    'configured_gc::preflight::tests::pure_preflight_refuses_instance_credentials_and_missing_public_keys',
    'configured_gc::preflight::tests::pure_preflight_refuses_overlapping_authority_and_missing_settings',
    'configured_gc::preflight::tests::pure_preflight_refuses_remote_composite_and_conflicting_roles',
    'configured_sdk::tests::actual_original_profile_mismatch_requires_process_exit',
    'configured_sdk::tests::complete_exposure_list_rejects_late_unsupported_credentials_without_effects',
    'configured_sdk::tests::credential_references_have_no_provider_or_path_normalization_fallback',
    'configured_sdk::tests::encoded_bucket_traversal_is_rejected_without_path_normalization',
    'configured_sdk::tests::failure_display_debug_and_entire_source_chain_redact_private_data',
    'configured_sdk::tests::fifo_and_device_credentials_are_classified_before_any_read',
    'configured_sdk::tests::native_token_reads_are_regular_nofollow_and_bounded',
    'configured_sdk::tests::preflight_refuses_roles_and_missing_trust_without_installation',
    'configured_sdk::tests::preflight_refuses_unavailable_compositions_before_missing_authority_io',
    'configured_sdk::tests::preflight_rejects_endpoints_overlapping_repository_state',
    'configured_sdk::tests::pure_sdk_profile_matches_the_actual_compiled_registry',
    'configured_sdk::tests::role_selection_and_instance_credentials_fail_before_any_repository_open',
    'host_cache::content::driver::dictionaries::tests::corrupt_terminal_prevents_returning_a_partial_chain',
    'host_cache::content::driver::dictionaries::tests::cycles_refuse_before_fetching_a_repeated_dependency',
    'host_cache::content::driver::dictionaries::tests::dependency_count_and_encoded_and_plaintext_windows_are_bounded',
    'host_cache::content::driver::dictionaries::tests::missing_dependency_preserves_the_lower_failure',
    'host_cache::content::driver::dictionaries::tests::nested_dictionaries_verify_from_terminal_to_requested_body',
    'host_cache::content::driver::dictionaries::tests::terminal_content_never_fetches_a_dictionary',
    'host_cache::content::presentation::tests::sealed_storage_requires_effective_none_without_weakening_private_defaults',
    'host_cache::owner::admission::io::tests::actual_admission_byte_check_is_positioned_and_rejects_modified_inode_bytes',
    'host_cache::owner::admission::memory::tests::simultaneous_active_copies_and_state_headers_are_checked',
    'host_cache::owner::admission::metadata::tests::actual_metadata_pair_rejects_wrong_index_key_class_and_window',
    'host_cache::owner::admission::metadata_reads::tests::registry_absence_never_masks_native_missing_or_corrupt_backing',
    'host_cache::owner::admission::tests::cancelled_started_phase_faults_without_native_authority_or_mutexes',
    'host_cache::owner::admission::tests::untrusted_pair_input_is_bounded_with_checked_addition',
    'host_cache::owner::config::tests::native_host_cache_config_refuses_ambiguous_custody_and_unfunded_capacity',
    'host_cache::owner::config::tests::native_host_cache_config_validation_needs_no_existing_paths',
    'host_cache::owner::config::tests::native_index_repair_policy_defaults_closed_and_funds_payload_overlap',
    'host_cache::owner::consumer::sweep::tests::delayed_sweep_uses_original_expiry_and_never_restarts_grace',
    'host_cache::owner::consumer::sweep::tests::explicit_grace_has_no_second_grace_and_retained_producers_do_not_expire',
    'host_cache::owner::consumer::sweep::tests::partial_pin_expiry_is_persisted_without_releasing_the_remaining_owner',
    'host_cache::owner::index_io::tests::classified_index_open_reads_regular_inode_and_refuses_fifo_and_symlink',
    'host_cache::owner::index_io::tests::classified_index_open_refuses_character_device_before_read_open',
    'host_cache::owner::index_io::tests::invalid_index_error_preserves_typed_source',
    'host_cache::owner::publication::eviction::activity::tests::concurrent_verified_read_groups_keep_dictionary_hits_in_the_same_clock_cut',
    'host_cache::owner::publication::eviction::activity::tests::concurrent_verified_reads_share_one_order_without_losing_first_hits',
    'host_cache::owner::publication::eviction::activity::tests::reused_inode_starts_fresh_activity_without_changing_other_allocations',
    'host_cache::owner::publication::eviction::activity::tests::verified_read_group_overflow_preserves_body_and_dictionary_activity',
    'host_cache::owner::publication::eviction::activity::tests::verified_read_order_keeps_first_promotion_separate_from_later_hits',
    'host_cache::owner::publication::residence::view::tests::close_refuses_new_reads_until_started_backing_is_dropped',
    'host_cache::owner::publication::residence::view::tests::concurrent_close_does_not_report_quiescence_during_backing_destruction',
    'host_cache::owner::recovery_cold::tests::cold_metadata_pins_require_the_separate_verified_source_closure',
    'host_cache::owner::recovery_cold::tests::cold_pins_require_complete_verified_backing_without_erasing_candidates',
    'host_cache::owner::recovery_cold::tests::standalone_replacement_cannot_erase_an_original_cold_range',
    'host_cache::owner::recovery_encoded::tests::before_canonical_publish_the_verified_original_range_remains_selected',
    'host_cache::owner::recovery_encoded::tests::dependency_order_restores_nested_and_shared_dictionaries_before_dependents',
    'host_cache::owner::recovery_encoded::tests::dependency_order_refuses_missing_dictionary_and_disconnected_cycles',
    'host_cache::recovery_inspection::dictionaries::tests::packed_dictionary_discovery_preserves_nested_envelope_and_plaintext_budget',
    'host_cache::owner::recovery_encoded::tests::extraction_crash_selection_keeps_one_residence_and_checks_both_lengths',
    'host_cache::owner::recovery_inline::tests::inline_reconstruction_keeps_each_exact_whole_chunk_range',
    'host_cache::owner::recovery_manifest_state::tests::changed_exposure_cannot_pass_a_policy_snapshot_comparison',
    'host_cache::owner::recovery_manifest_state::tests::changed_residence_cannot_pass_a_policy_snapshot_comparison',
    'host_cache::owner::recovery_manifest_state::tests::extra_cold_rows_are_refused_and_preserved',
    'host_cache::owner::recovery_namespace::tests::actual_directory_reopen_retains_classified_inode_across_name_replacement',
    'host_cache::owner::recovery_namespace::tests::actual_name_scan_counts_coordination_unknown_and_non_utf8_entries',
    'host_cache::owner::recovery_residences::tests::conflicts_and_capacity_are_refused_without_clearing_prior_candidates',
    'host_cache::owner::recovery_residences::tests::repeated_occurrences_select_one_stable_range_independent_of_scan_order',
    'host_cache::owner::recovery_state_parent::tests::actual_state_parent_scan_refuses_unknown_file_and_directory_siblings',
    'host_cache::owner::retention::recovery_manifest::tests::abandoned_rpc_effect_faults_without_a_state_or_client_lock',
    'host_cache::owner::retention::recovery_manifest::tests::cancelled_in_flight_retention_never_reactivates_the_live_phase',
    'host_cache::owner::retention::recovery_manifest::tests::only_reconciled_retention_returns_to_active',
    'host_cache::owner::retention::recovery_manifest::tests::reconciled_rpc_effect_releases_the_exclusive_phase',
    'host_cache::owner::retention::snapshot_provenance_tests::previous_write_cannot_certify_new_generation_or_another_inode',
    'host_cache::owner::snapshot::tests::actual_snapshot_io_retains_readback_and_rejects_replaced_inode',
    'host_cache::reassembly::tests::streamed_manifest_handles_short_writes_without_collecting_an_output_buffer',
    'host_cache::reassembly::tests::streamed_manifest_preserves_write_failure_and_original_partial_output',
    'host_cache::reassembly::tests::streamed_manifest_refuses_truncated_trailing_reordered_and_modified_input',
    'host_cache::reassembly::tests::streamed_manifest_rejects_wrong_whole_hash_after_valid_ordered_chunks',
    'host_cache::recovery_inspection::collection::tests::duplicate_candidates_consume_the_occurrence_budget',
    'host_cache::recovery_inspection::collection::tests::native_names_reject_aliases_and_wrong_widths',
    'host_cache::recovery_inspection::packed_chunks::tests::original_raw_and_nested_envelopes_keep_the_single_payload_allocation',
    'host_cache::recovery_inspection::packed_chunks::tests::selection_checks_buffer_capacity_and_decoded_length_independently',
    'host_cache::recovery_inspection::packed_chunks::tests::selection_refuses_missing_wrong_kind_and_changed_codec_records',
    'host_cache::recovery_inspection::quarantine::tests::encoded_quarantine_names_are_closed_routing_fields_without_content_authority',
    'host_cache::recovery_inspection::tests::actual_metadata_pack_requires_the_exact_original_manifest_record_range',
    'host_cache::recovery_inspection::tests::actual_pack_bytes_derive_exact_index_but_corrupt_body_never_does',
    'host_cache::recovery_inspection::tests::compressed_pack_dictionary_respects_remaining_plaintext_budget',
    'host_cache::recovery_inspection::tests::compressed_standalone_plaintext_is_bounded_before_decode',
    'host_cache::recovery_inspection::tests::configured_custody_rejects_rebased_owner_and_group',
    'host_cache::recovery_inspection::tests::configured_directory_mode_is_not_rebased_to_current_metadata',
    'host_cache::recovery_inspection::tests::equal_sized_in_place_change_fails_actual_encoded_hash_recheck',
    'host_cache::recovery_inspection::tests::equal_sized_path_replacement_does_not_match_retained_inode',
    'host_cache::recovery_inspection::tests::oversized_actual_inode_is_rejected_before_encoded_allocation',
    'host_cache::recovery_inspection::tests::positioned_recovery_read_preserves_the_actual_open_description_cursor',
    'host_cache::recovery_inspection::tests::retained_manifest_inspection_requires_the_complete_manifest_key',
    'host_cache::recovery_inspection::tests::retained_manifest_plaintext_limit_is_checked_before_any_body_read',
    'host_cache::recovery_inspection::tests::retained_manifest_plaintext_uses_positioned_reads_without_changing_shared_cursor',
    'host_cache::recovery_inspection::tests::retained_manifest_residences_preserve_order_offsets_and_manifest_identity',
    'host_cache::recovery_inspection::tests::retained_manifest_verifies_full_plaintext_and_preserves_its_metadata_identity',
    'host_cache::recovery_inspection::tests::structural_pack_allocation_is_bounded_before_decoded_records',
    'host_cache::recovery_inspection::tests::unresolved_verification_failure_preserves_its_typed_source',
    'host_cache::source::tests::encoded_chain_verifies_terminal_dependencies_without_moving_original_cursors',
    'host_cache::source::tests::encoded_consumer_verifies_original_envelope_before_returning_bytes',
    'host_cache::source::tests::native_chunk_open_classifies_fifo_symlink_and_character_device_before_read_open',
    'host_cache::source::tests::native_chunk_read_enforces_owner_window_before_allocation_or_cursor_changes',
    'host_cache::source::tests::native_chunk_source_errors_preserve_typed_causes',
    'host_cache::tests::native_host_cache_rejects_symlink_ancestors',
    'host_quota::socket::signal_tests::interrupted_receive_keeps_the_same_connection',
    'host_quota::socket::signal_tests::repeated_interruptions_do_not_extend_the_original_deadline',
    'host_quota::socket::tests::descriptor_ancillary_is_rejected_without_returning_custody',
    'host_quota::socket::tests::kernel_peer_identity_is_not_a_packet_assertion',
    'host_quota::socket::tests::oversized_native_packet_is_rejected_after_receive_truncation',
    'publisher_io::manifest::tests::received_metapack_rejects_wrong_range_size_writer_budget_and_mutation',
    'publisher_io::manifest::tests::received_metapack_uses_positioned_reads_and_exact_canonical_claim',
    'publisher_io::worker::binding_repair::tests::actual_parent_sync_failure_withholds_repair_success',
    'publisher_io::worker::binding_repair::tests::binding_capture_refuses_special_inodes_before_read_open',
    'publisher_io::worker::binding_repair::tests::repair_refuses_replacement_and_same_inode_mutation',
    'publisher_io::worker::inventory::startup::tests::cleanup_grammar_matches_only_actual_generated_temporary_names',
    'publisher_io::worker::inventory::state::tests::retained_manifest_budget_includes_canonical_and_decoded_payloads',
    'publisher_io::worker::inventory::state::tests::retained_snapshot_rejects_mode_links_and_canonical_inode_replacement',
    'publisher_io::path::tests::directory_walk_rejects_symlinks_magic_links_and_parent_traversal',
    'publisher_io::worker::inventory::tests::key_parser_refuses_noncanonical_names',
    'publisher_io::worker::inventory::tests::physical_entry_budget_counts_directories_and_bodies',
    'publisher_io::worker::inventory::tests::private_remnant_names_prevent_empty_namespace_classification',
    'publisher_io::worker::inventory::tests::retained_open_rejects_symlinks_and_wrong_inode_kinds',
    'publisher_io::worker::inventory::tests::snapshot_pages_use_single_use_owner_cursors',
    'publisher_local::client::recovery_manifest::tests::candidate_comparison_requires_the_complete_registered_key',
    'publisher_local::client::recovery_manifest::tests::retained_claim_comparison_rejects_other_domains_and_content',
    'publisher_local::socket::tests::ancillary_truncation_and_unregistered_credentials_are_rejected',
    'publisher_local::socket::tests::configured_domain_selection_has_no_fallback',
    'publisher_local::socket::tests::duplicate_active_request_is_rejected_before_dispatch',
    'publisher_local::socket::tests::explicit_retirement_removes_original_name_and_allows_fresh_binding',
    'publisher_local::socket::tests::kernel_peer_credentials_cannot_be_claimed_in_packet',
    'publisher_local::socket::tests::ordinary_drop_preserves_name_for_failed_startup_diagnosis',
    'publisher_local::socket::tests::oversized_payload_and_excess_rights_are_rejected',
    'publisher_local::socket::tests::real_seqpacket_roundtrip_requires_response_correlation',
    'publisher_local::socket::tests::received_rights_are_close_on_exec_and_writable_sources_fail',
    'publisher_local::socket::tests::rejected_rights_do_not_accumulate_descriptors',
    'publisher_local::socket::tests::replaced_socket_name_is_rejected_without_changing_either_inode',
    'publisher_local::socket::tests::retained_socket_chmod_sets_exact_mode_without_changing_inode_or_group',
    'publisher_local::socket::tests::retirement_refuses_newly_writable_parent_without_removing_socket',
    'publisher_local::socket::tests::retirement_refuses_replacement_without_removing_either_inode',
    'publisher_local::socket::tests::retirement_uses_retained_parent_after_ancestor_replacement',
    'publisher_local::socket::tests::socket_chmod_rejects_wrong_type_and_owner_before_mutation',
    'publisher_local::socket::tests::unsolicited_and_mismatched_responses_are_rejected',
    'quota_confinement::policy::tests::setter_denial_survives_command_padding_and_preserves_get_and_verity',
)


PACKAGE_PATHS = {
    "terrane-format": "terrane/sdk/terrane-format",
    "terrane-sdk": "terrane/sdk/terrane-sdk",
    "terrane-linux": "terrane/linux/terrane-linux",
    "terrane-cli": "terrane/cli/terrane-cli",
    "aos-terrane-integration": "terrane/integration/aos-terrane-integration",
}


# The all-feature guest adds these cases without replacing the base inventory.
FUSE_UNIT_PREFIXES = (
    "fuse_backing::", "fuse_open::", "fuse_lifetime::", "fuse_dispatch::", "fuse_read::", "fuse_xattr::", "fuse_namespace::", "fuse_metadata::", "fuse_directory::",
    "fuse_protocol::", "inode_policy::", "maintenance_channel::",
    "structural_index::", "worker_channel::",
)
FUSE_UNIT_TESTS = (
    'fuse_backing::tests::distinct_nodes_install_independently_and_never_replace_original_resources',
    'fuse_backing::tests::exhausted_reservations_and_old_completions_preserve_retry_ownership',
    'fuse_backing::tests::expired_waiter_and_peer_release_keep_the_original_backing_until_retirement',
    'fuse_backing::tests::startup_bounds_include_pending_records_and_the_actual_resource_layout',

    'fuse_namespace::tests::touched_nodes_bound_storage_independently_of_paths_and_share_hardlink_records',
    'fuse_namespace::tests::touched_node_refusals_preserve_existing_mappings_and_reserved_capacity',
    'fuse_dispatch::tests::worker_lookup_retains_only_touched_nodes_and_faults_at_the_original_bound',
    'fuse_lifetime::tests::forget_waits_for_every_original_handle_and_pending_work_pin',
    'fuse_lifetime::tests::released_handles_never_alias_reopened_nodes_or_directory_handles',
    'fuse_lifetime::tests::batch_duplicates_are_summed_before_any_forget_changes_state',
    'fuse_lifetime::tests::malformed_forgets_and_over_forgets_preserve_all_references',
    'fuse_lifetime::tests::node_handle_and_counter_exhaustion_refuse_before_mutating_original_state',
    'fuse_lifetime::tests::expired_waiter_does_not_retire_a_still_pinned_shared_fetch',
    'fuse_open::tests::concurrent_same_inode_waiters_share_one_original_handoff',
    'fuse_open::tests::individual_deadlines_and_late_joiners_never_cancel_the_shared_fetch',
    'fuse_open::tests::stale_completions_cannot_resolve_a_new_fetch_for_the_same_node',
    'fuse_open::tests::refusals_leave_original_waiters_and_ticket_sequence_unchanged',
    'fuse_open::tests::abandoned_and_expired_waiters_preserve_handoffs_through_draining',
    'fuse_open::tests::startup_budgets_and_completed_deadlines_remain_fail_closed',

    'fuse_read::tests::native_read_binds_original_node_and_handle_without_changing_unsigned_ranges',
    'fuse_read::tests::native_read_refuses_foreign_records_handles_padding_and_unnegotiated_flags',

    'fuse_dispatch::tests::raw_lookup_getattr_and_readlink_share_one_original_namespace',
    'fuse_dispatch::tests::malformed_supported_requests_never_assign_inodes_or_change_scratch',
    'fuse_dispatch::tests::operation_errnos_and_unhandled_records_preserve_permanent_state',
    'fuse_dispatch::tests::absence_and_xattr_policy_remain_distinct_from_protocol_faults',
    'fuse_dispatch::tests::directory_pages_obey_original_handles_cookies_and_complete_record_bounds',

    'fuse_read::tests::open_keeps_cache_without_passthrough_or_direct_io_and_preserves_unused_bytes',
    'fuse_read::tests::positioned_ranges_clamp_only_at_prepared_eof_without_offset_overflow',
    'fuse_read::tests::invalid_limits_sizes_and_short_output_are_refused_before_io',

    'fuse_xattr::tests::raw_values_and_size_probes_preserve_exact_bytes_and_unused_output',
    'fuse_xattr::tests::list_and_get_hide_privileged_names_even_during_size_probes',
    'fuse_xattr::tests::disabled_empty_and_missing_attributes_have_distinct_kernel_results',
    'fuse_xattr::tests::short_requests_invalid_names_and_worker_capacity_leave_output_unchanged',
    'fuse_xattr::tests::linux_payload_limits_preserve_checked_tree_bounds_and_refuse_overflow',

    'fuse_namespace::tests::child_lookup_resolves_only_direct_names_and_namespace_dot_components',
    'fuse_namespace::tests::reverse_lookup_preserves_canonical_hardlinks_and_distinct_equal_content',
    'fuse_namespace::tests::graft_reverse_nodes_and_dotdot_keep_original_namespace_prefixes',
    'fuse_namespace::tests::raw_names_and_unknown_nodes_never_escape_the_original_index',
    'fuse_namespace::tests::startup_budgets_include_every_original_path_and_the_synthesized_root',

    'fuse_metadata::tests::lookup_and_getattr_preserve_recorded_fields_and_hardlink_identity',
    'fuse_metadata::tests::root_and_symlink_replies_keep_kernel_root_separate_and_target_bytes_exact',
    'fuse_metadata::tests::canonical_overrides_ignore_recorded_ownership_and_keep_explicit_timestamps',
    'fuse_metadata::tests::refused_metadata_or_capacity_never_assigns_an_inode_or_changes_output',
    'fuse_metadata::tests::negative_lookup_caches_absence_only_for_pinned_views_and_clears_payload',

    'fuse_directory::tests::encodes_only_direct_children_with_exact_names_types_padding_and_parent',
    'fuse_directory::tests::hard_link_names_share_one_presented_inode_but_equal_content_keeps_distinct_inodes',
    'fuse_directory::tests::inode_exhaustion_never_writes_a_partial_record_or_recycles_a_number',
    'fuse_directory::tests::raw_maximum_component_needs_one_complete_aligned_record_before_inode_assignment',
    'fuse_directory::tests::rejects_lazy_storage_absent_paths_and_non_directories_without_effects',
    'fuse_directory::tests::resumes_one_complete_record_at_a_time_and_rewind_preserves_original_numbers',
    'fuse_protocol::init::tests::caps_device_write_size_and_readahead_without_buffer_growth',
    'fuse_protocol::init::tests::negotiates_older_supported_read_protocols_without_extensions',
    'fuse_protocol::init::tests::newer_major_retries_without_interpreting_foreign_body',
    'fuse_protocol::init::tests::off_never_enables_offered_passthrough_or_writeback',
    'fuse_protocol::init::tests::refuses_non_init_headers_truncation_reserved_data_and_extra_body',
    'fuse_protocol::init::tests::requires_both_local_and_kernel_passthrough_support',
    'fuse_protocol::init::tests::selects_only_implemented_capabilities_with_bounded_native_fields',
    'fuse_protocol::tests::body_fields_refuse_overflow_and_truncation',
    'fuse_protocol::tests::checked_reply_preserves_identifier_and_signed_error',
    'fuse_protocol::tests::checked_reply_refuses_notification_identifiers_and_error_payloads',
    'fuse_protocol::tests::checked_reply_requires_a_complete_bounded_record',
    'fuse_protocol::tests::enforces_explicit_record_limits_and_keeps_zero_identifiers',
    'fuse_protocol::tests::errno_reply_uses_kernel_sign_and_never_contains_payload',
    'fuse_protocol::tests::filename_validation_preserves_bytes_and_namespace_dot_components',
    'fuse_protocol::tests::filename_validation_refuses_unterminated_trailing_or_multiple_names',
    'fuse_protocol::tests::preserves_unknown_operations_and_original_request_bytes',
    'fuse_protocol::tests::refused_reply_leaves_original_output_unchanged',
    'fuse_protocol::tests::refuses_unnegotiated_extensions_and_reserved_padding',
    'fuse_protocol::tests::rejects_every_truncated_header_and_inconsistent_record_length',
    'fuse_protocol::tests::successful_reply_does_not_expose_unused_output_capacity',
    'host_cache::owner::recovery_cold::tests::surface_tests::draining_file_pins_retain_policy_without_adoption_or_content_proof',
    'host_cache::owner::recovery_cold::tests::surface_tests::retired_surface_holds_preserve_all_other_cold_candidates_and_refuse_dependencies',
    'host_cache::owner::recovery_namespace::surface::tests::cold_surface_classification_is_exact_and_does_not_adopt_content',
    'host_cache::owner::surface_index::exposure::tests::exposure_read_denial_survives_native_adapter_without_policy_details',
    'inode_policy::tests::directory_pages_and_refusals_do_not_allocate_even_on_first_inode_touch',
    'inode_policy::tests::full_table_preserves_old_numbers_and_canonical_link_counts',
    'inode_policy::tests::internal_identity_is_independent_of_first_lookup_order',
    'inode_policy::tests::invalid_bounds_and_paths_fail_before_table_growth',
    'inode_policy::tests::metadata_refusal_consumes_no_number_or_existing_identity',
    'inode_policy::tests::reserved_budget_refuses_before_allocation_and_keeps_number_assignment_lazy',
    'inode_policy::tests::reserved_first_touch_and_checked_metadata_operations_allocate_nothing',
    'inode_policy::tests::reserved_probe_chains_keep_collisions_and_full_table_refusals_distinct',
    'inode_policy::tests::truncated_collision_cannot_alias_or_replace_a_retained_entry',
    'maintenance_channel::listener::tests::explicit_retirement_removes_original_name_and_allows_fresh_binding',
    'maintenance_channel::listener::tests::ordinary_drop_preserves_name_for_failed_startup_diagnosis',
    'maintenance_channel::listener::tests::retirement_refuses_newly_writable_parent_without_removing_socket',
    'maintenance_channel::listener::tests::retirement_refuses_replacement_without_removing_either_inode',
    'maintenance_channel::listener::tests::retirement_uses_retained_parent_after_ancestor_replacement',
    'maintenance_channel::tests::authenticated_remote_refusal_preserves_the_next_exact_sequence',
    'maintenance_channel::tests::bounded_client_receives_authenticated_counts_and_remote_refusals',
    'maintenance_channel::tests::bounded_client_refuses_forged_reply_without_returning_counts',
    'maintenance_channel::tests::bounded_client_refuses_invalid_limits_before_sending',
    'maintenance_channel::tests::bounded_client_timeout_and_cancellation_close_the_actual_connection',
    'maintenance_channel::tests::cancelled_client_request_faults_the_original_connection',
    'maintenance_channel::tests::closed_request_rejects_version_operation_sequence_and_trailing_bytes',
    'maintenance_channel::tests::endpoint_authenticates_each_kernel_message_and_faults_wrong_uid',
    'maintenance_channel::tests::endpoint_refuses_received_rights_and_truncated_records',
    'maintenance_channel::tests::incomplete_exchange_disconnects_and_complete_exchange_preserves_channel',
    'maintenance_channel::tests::malformed_reply_faults_before_the_pending_request_is_dropped',
    'maintenance_channel::tests::public_binding_refuses_colliding_and_incorrect_role_identities',
    'maintenance_channel::tests::reply_checks_exact_sequence_complete_counts_and_registered_errors',
    'maintenance_channel::tests::reply_rejects_count_overflow_and_unknown_outcomes',
    'structural_index::tests::arbitrary_short_inputs_and_single_byte_mutations_never_panic',
    'structural_index::tests::child_resume_skips_direct_indices_and_remains_exhausted_for_oversized_offsets',
    'structural_index::tests::compiled::canonical_compilation_refuses_a_valid_index_with_an_unchanged_root_tag',
    'structural_index::tests::compiled::streaming_copy_and_verification_preserve_short_io_failures_and_exact_length',
    'structural_index::tests::compiler_rejects_missing_nondirectory_duplicate_and_invalid_paths',
    'structural_index::tests::content_kind_size_symlink_bytes_and_graft_governance_survive_roundtrip',
    'structural_index::tests::empty_tree_and_exact_compiler_bounds_are_supported',
    'structural_index::tests::every_truncation_and_hostile_header_offset_is_rejected',
    'structural_index::tests::forged_parent_child_and_arena_relationships_are_rejected',
    'structural_index::tests::metadata::canonical_tree_preserves_modes_unknown_fields_and_graft_properties',
    'structural_index::tests::metadata::forged_link_runs_counts_and_canonical_entries_are_refused',
    'structural_index::tests::metadata::hardlinks_share_checked_inodes_but_repeated_grafts_and_equal_content_do_not',
    'structural_index::tests::metadata::malformed_metadata_maps_modes_and_cursors_are_refused',
    'structural_index::tests::metadata::metadata_key_order_duplicate_names_and_old_format_are_refused',
    'structural_index::tests::nested_tree_has_sorted_paths_and_contiguous_direct_child_indices',
    'structural_index::tests::trees::absent_misbound_nonordinary_and_wrong_geometry_grafts_are_refused',
    'structural_index::tests::trees::canonical_nested_grafts_compile_without_any_file_content_input',
    'structural_index::tests::trees::expanded_entries_bytes_and_full_paths_obey_compiler_limits',
    'structural_index::tests::trees::maximum_graft_depth_is_supported_and_the_next_edge_is_refused',
    'structural_index::tests::trees::raw_node_budget_charges_all_keys_before_decoding_or_expansion',
    'structural_index::tests::trees::raw_nodes_check_internal_summaries_after_individual_hashes_match',
    'structural_index::tests::trees::raw_nodes_compile_only_after_actual_identity_and_graft_validation',
    'structural_index::tests::trees::repeated_grafts_expand_at_distinct_paths_with_one_governing_root',
    'worker_channel::client::runtime::tests::invalid_limits_and_paths_refuse_before_send_without_faulting_connection',
    'worker_channel::client::runtime::tests::reply_timeout_and_cancellation_shutdown_retained_descriptor_aliases',
    'worker_channel::client::runtime::tests::send_backpressure_is_included_in_the_whole_exchange_deadline',
)


def unit_features():
    """Selects one explicit builder profile, never a caller-supplied feature set."""
    profile = os.environ.get("TERRANE_UNIT_PROFILE", "base")
    shared.require(profile in {"base", "all"}, "unknown native unit profile")
    return (["native-test-fixtures", "surface-fuse", "tokio"] if profile == "all"
            else ["native-test-fixtures", "tokio"])


def unit_selection():
    """Keeps both the ordinary selectors and feature prefixes closed."""
    if "surface-fuse" in unit_features():
        return (*UNIT_TESTS, *FUSE_UNIT_TESTS), (*UNIT_PREFIXES, *FUSE_UNIT_PREFIXES)
    return UNIT_TESTS, UNIT_PREFIXES


def unit_inventory(output):
    """Parses the complete real libtest inventory, rejecting unknown line types."""
    lines = [line for line in output.splitlines() if line]
    shared.require(lines and re.fullmatch(r"\d+ tests?, 0 benchmarks?", lines[-1]),
                   "missing complete FS unit inventory summary")
    names = [line.removesuffix(": test") for line in lines[:-1]]
    shared.require(all(line.endswith(": test") for line in lines[:-1])
                   and len(names) == len(set(names)) and 0 < len(names) <= 4096
                   and int(lines[-1].split()[0]) == len(names), "invalid FS unit inventory")
    expected, prefixes = unit_selection()
    selected = sorted(name for name in names if name.startswith(prefixes))
    shared.require(selected == sorted(expected) and len(selected) == len(expected),
                   "FS unit module-prefix inventory changed")
    shared.require(sorted(names) == sorted((*expected, *ROOT_UNIT_TESTS)),
                   "complete native feature test inventory changed")
    return sorted(names)


def source_unit_inventory(workspace):
    """Checks the retained selection against all test declarations in its scope."""
    root = workspace / "terrane/linux/terrane-linux/src"
    # The actual compiled inventory remains authoritative. Supplement it with
    # source declarations only after checking every excluded feature boundary.
    gated = [
        ("structural_index", "lib.rs", "pub mod structural_index;"),
        ("inode_policy", "lib.rs", "pub mod inode_policy;"),
        ("fuse_backing", "lib.rs", "pub mod fuse_backing;"),
        ("fuse_open", "lib.rs", "pub mod fuse_open;"),
        ("fuse_lifetime", "lib.rs", "pub mod fuse_lifetime;"),
        ("fuse_dispatch", "lib.rs", "pub mod fuse_dispatch;"),
        ("fuse_directory", "lib.rs", "pub mod fuse_directory;"),
        ("fuse_metadata", "lib.rs", "pub mod fuse_metadata;"),
        ("fuse_namespace", "lib.rs", "pub mod fuse_namespace;"),
        ("fuse_xattr", "lib.rs", "pub mod fuse_xattr;"),
        ("fuse_read", "lib.rs", "pub mod fuse_read;"),
        ("fuse_protocol", "lib.rs", "pub mod fuse_protocol;"),
        ("host_cache/owner/surface_index", "host_cache/owner/mod.rs", "mod surface_index;"),
        ("host_cache/owner/recovery_namespace/surface", "host_cache/owner/recovery_namespace.rs", "mod surface;"),
        ("host_cache/owner/recovery_cold/tests/surface_tests", "host_cache/owner/recovery_cold.rs", "    mod surface_tests;"),
    ]
    for prefix, owner, declaration in gated:
        shared.require('#[cfg(feature = "surface-fuse")]\n' + declaration
                       in (root / owner).read_text(),
                       "native inventory lost its explicit feature gate: " + prefix)
        shared.require((root / (prefix + ".rs")).is_file(),
                       "native inventory feature module missing: " + prefix)
    # The private GC channel requires both runtime and surface custody; its
    # native socket tests run separately in the matching feature profile.
    shared.require('#[cfg(all(feature = "surface-fuse", feature = "tokio"))]\n'
        'pub mod maintenance_channel;' in (root / "lib.rs").read_text(),
        "maintenance channel lost its explicit runtime/surface feature gate")
    shared.require((root / "maintenance_channel.rs").is_file(),
        "maintenance channel feature module missing")
    gated.append(("maintenance_channel", "lib.rs", "pub mod maintenance_channel;"))
    # Worker transport also requires FUSE custody. Its socket tests are absent
    # from this image's actual no-FUSE compilation, just like maintenance tests.
    shared.require('#[cfg(all(feature = "surface-fuse", feature = "tokio"))]\n'
        'pub mod worker_channel;' in (root / "lib.rs").read_text(),
        "worker channel lost its explicit runtime/surface feature gate")
    shared.require((root / "worker_channel/mod.rs").is_file(),
        "worker channel feature module missing")
    gated.append(("worker_channel", "lib.rs", "pub mod worker_channel;"))
    shared.require('#[cfg(all(feature = "surface-fuse", feature = "tokio"))]\n'
        'pub mod fuse_connection;' in (root / "lib.rs").read_text(),
        "FUSE connection lost its explicit runtime/surface feature gate")
    shared.require((root / "fuse_connection.rs").is_file(),
        "FUSE connection feature module missing")
    gated.append(("fuse_connection", "lib.rs", "pub mod fuse_connection;"))
    shared.require('#[cfg(all(feature = "surface-fuse", feature = "tokio"))]\n'
        'pub mod fuse_worker;' in (root / "lib.rs").read_text(),
        "FUSE worker lost its explicit runtime/surface feature gate")
    shared.require((root / "fuse_worker.rs").is_file(),
        "FUSE worker feature module missing")
    gated.append(("fuse_worker", "lib.rs", "pub mod fuse_worker;"))
    declared = []
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        if "surface-fuse" not in unit_features() and any(
                relative == prefix + ".rs" or relative.startswith(prefix + "/")
                for prefix, _, _ in gated):
            continue
        declared.extend(re.findall(r"#\[(?:tokio::)?test\]\s*(?:async\s+)?fn\s+(\w+)\s*\(", path.read_text()))
    selected, _ = unit_selection()
    expected = (*selected, *ROOT_UNIT_TESTS)
    actual_counts = Counter(declared)
    expected_counts = Counter(name.rsplit("::", 1)[1] for name in expected)
    shared.require(actual_counts == expected_counts,
                   "source native unit declarations differ from the complete inventory: "
                   f"unlisted={dict(actual_counts - expected_counts)}, "
                   f"undeclared={dict(expected_counts - actual_counts)}")


def unit_artifact(workspace, temporary, target, packages):
    """Selects the actual FS libtest ELF from its explicit test-profile build."""
    profile = tomllib.loads((workspace / "Cargo.toml").read_text()).get("profile", {}).get("test")
    shared.require(profile == {"debug": 0, "opt-level": "s"}, "unreviewed FS test profile")
    records = [json.loads(line) for line in (temporary / f"host-cache-{UNIT_NAME}.jsonl").read_text().splitlines()]
    package = [item for item in packages if pathlib.Path(item["manifest_path"]) == workspace / "terrane/linux/terrane-linux/Cargo.toml"]
    candidates = [item for item in records if item.get("reason") == "compiler-artifact"
                  and item.get("target", {}).get("name") == "terrane_linux" and item.get("executable")]
    shared.require(len(package) == len(candidates) == 1, "ambiguous FS libtest artifact")
    artifact = candidates[0]
    targets = [item for item in package[0]["targets"] if item["name"] == "terrane_linux" and item["kind"] == ["lib"]]
    executable = pathlib.Path(artifact["executable"])
    shared.require(len(targets) == 1 and artifact["target"] == targets[0]
                   and artifact["package_id"] == package[0]["id"] and package[0]["name"] == "terrane-linux"
                   and artifact["target"]["crate_types"] == ["lib"]
                   and pathlib.Path(artifact["target"]["src_path"]) == workspace / "terrane/linux/terrane-linux/src/lib.rs"
                   and artifact["profile"] == UNIT_PROFILE
                   and sorted(artifact["features"]) == unit_features()
                   and str(executable) in artifact["filenames"]
                   and executable.is_file() and os.access(executable, os.X_OK)
                   and executable.resolve().is_relative_to(target.resolve())
                   and executable.read_bytes().startswith(b"\x7fELF"), "FS libtest source/profile/ELF mismatch")
    source_unit_inventory(workspace)
    return artifact, executable, digest(executable)


def digest(path):
    """Hashes the exact retained bytes, without invoking an ELF rewriter."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flags(name):
    """Selects the exact package and explicitly enabled fixture features."""
    package, kind, _, features = TARGETS[name]
    result = ["--frozen", "--offline", "-p", package]
    if features:
        result += ["--features", "native-test-fixtures"]
    return result + ["--example" if kind == "example" else "--bin", name]


def selected_artifacts(workspace, temporary, target):
    """Binds real Cargo package/target/profile/features to each executable."""
    packages = json.loads((temporary / "host-cache-packages.json").read_text())["packages"]
    manifest = tomllib.loads((workspace / "Cargo.toml").read_text())
    shared.require(manifest.get("profile", {}).get("dev", {}) == {}, "unreviewed cache proof development profile")
    result = {}
    for name, (crate, kind, source, features) in TARGETS.items():
        records = [json.loads(line) for line in (temporary / f"host-cache-{name}.jsonl").read_text().splitlines()]
        package = [item for item in packages if pathlib.Path(item["manifest_path"]) == workspace / PACKAGE_PATHS[crate] / "Cargo.toml"]
        candidates = [item for item in records if item.get("reason") == "compiler-artifact"
                      and item.get("target", {}).get("name") == name and item.get("executable")]
        shared.require(len(package) == len(candidates) == 1, f"ambiguous cache proof artifact: {name}")
        artifact = candidates[0]
        targets = [item for item in package[0]["targets"] if item["name"] == name and item["kind"] == [kind]]
        executable = pathlib.Path(artifact["executable"])
        shared.require(len(targets) == 1 and artifact["target"] == targets[0]
                       and artifact["package_id"] == package[0]["id"] and package[0]["name"] == crate
                       and artifact["target"]["crate_types"] == ["bin"]
                       and pathlib.Path(artifact["target"]["src_path"]) == workspace / PACKAGE_PATHS[crate] / source
                       and artifact["profile"] == PROFILE and sorted(artifact["features"]) == features
                       and str(executable) in artifact["filenames"]
                       and executable.is_file() and os.access(executable, os.X_OK)
                       and executable.resolve().is_relative_to(target.resolve()),
                       f"cache proof source/target/profile/features mismatch: {name}")
        shared.require(executable.read_bytes().startswith(b"\x7fELF"), f"non-ELF artifact: {name}")
        result[name] = (artifact, executable, digest(executable))
    result[UNIT_NAME] = unit_artifact(workspace, temporary, target, packages)
    return result


def cargo_directories(name, executable, temporary, target, workspace):
    """Captures a genuine Cargo launch without executing any role entry point."""
    target_lib = pathlib.Path((temporary / "host-cache-target-libdir").read_text().strip())
    shared.require(target_lib.is_dir() and target_lib.resolve().is_relative_to("/nix/store"), "untrusted target library directory")
    capture = temporary / f"host-cache-{name}-library-path"
    working = temporary / f"host-cache-{name}-working-directory"
    runner = temporary / f"host-cache-{name}-runner"
    is_unit = name == UNIT_NAME
    expected_argument = "--list" if is_unit else "--discover"
    runner.write_text("\n".join([
        f'#!{os.environ["CONFIG_SHELL"]}', "set -euC",
        '[ "$#" -eq 2 ] && [ "$1" = ' + shlex.quote(str(executable)) + ' ] && [ "$2" = ' + expected_argument + ' ]',
        "printf '%s\\n' \"${LD_LIBRARY_PATH-}\" > " + shlex.quote(str(capture)),
        "pwd -P > " + shlex.quote(str(working)), "exit 0", "",
    ]))
    runner.chmod(0o755)
    environment = dict(os.environ)
    triple = target_lib.parent.name.upper().replace("-", "_")
    environment[f"CARGO_TARGET_{triple}_RUNNER"] = str(runner)
    with (temporary / f"host-cache-{name}-discovery.log").open("w") as log:
        command = (["cargo", "test", "--frozen", "--offline", "-p", "terrane-linux",
                    "--features", ",".join(unit_features()), "--lib", "--", "--list"] if is_unit
                   else ["cargo", "run", *flags(name), "--", "--discover"])
        subprocess.run(command, env=environment,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    text = capture.read_text()
    shared.require(text.endswith("\n") and text.count("\n") == 1 and text.strip(), "missing Cargo launch environment")
    expected_cwd = workspace / "terrane/linux/terrane-linux" if is_unit else workspace
    shared.require(working.read_text() == str(expected_cwd) + "\n", "Cargo launch working-directory mismatch")
    directories = [shared.allowed_directory(value, target) for value in text[:-1].split(":")]
    shared.require(all(path.is_dir() for path in directories), "missing Cargo runtime library directory")
    return directories


def main():
    """Publishes immutable artifacts without claiming native execution."""
    workspace = pathlib.Path.cwd()
    temporary = pathlib.Path(os.environ["TMPDIR"])
    target = pathlib.Path(os.environ["CARGO_TARGET_DIR"])
    source = pathlib.Path(os.environ["src"])
    output = pathlib.Path(os.environ["out"])
    # Nix file inputs have hash-prefixed store basenames. Their repository
    # identities are explicit; neither a basename guess nor a fallback may bind
    # the executed installer to another immutable source file.
    for path, name in [
        (pathlib.Path(__file__), "host_cache_image.py"),
        (pathlib.Path(shared.__file__), "native_sdk_test_image.py"),
    ]:
        relative = "tests/terrane/" + name
        shared.require(path.read_bytes() == (source / relative).read_bytes(), "executed proof helper differs from source")
    artifacts = selected_artifacts(workspace, temporary, target)
    source_hashes = shared.source_hashes(workspace, source)
    for name in ["host-cache-proof.nix", "host-cache-scenarios.nix", "host_cache_image.py", "host_cache_vm.py", "host_cache_temporaries_vm.py", "host_cache_encoded_recovery_vm.py", "host_cache_index_recovery_vm.py", "host_cache_pending_recovery_vm.py", "host_cache_pending_packs_vm.py", "manifest_publication_vm.py", "source_cleanup_vm.py", "admission_cache_vm.py", "encoded_eviction_vm.py", "shared_reextract_vm.py", "sealed_consumer_cold_vm.py", "native_feature_units_vm.py", "host_cache_mount_views_vm.py", "native_sdk_test_image.py"]:
        path = source / "tests/terrane" / name
        shared.require(path.read_bytes() == (workspace.parent / "tests/terrane" / name).read_bytes(), "mutable proof input: " + name)
        source_hashes["tests/terrane/" + name] = digest(path)
    libraries = {}
    store_paths = []
    for name, (artifact, executable, original_hash) in artifacts.items():
        directories = cargo_directories(name, executable, temporary, target, workspace)
        shared.require(digest(executable) == original_hash, "Cargo discovery changed selected ELF")
        reachable, stores = shared.runtime_closure(executable, directories, target)
        for library, path in reachable.items():
            shared.require(library not in libraries or libraries[library].read_bytes() == path.read_bytes(), "ambiguous cache proof runtime: " + library)
            libraries[library] = path
        for path in stores:
            if path not in store_paths:
                store_paths.append(path)
    for name in ["bin", "lib", "share"]:
        (output / name).mkdir()
    checksums = []
    identities = {}
    for name, (artifact, executable, original_hash) in artifacts.items():
        installed = output / "bin" / name
        shutil.copy2(executable, installed)
        shared.require(digest(installed) == digest(executable) == original_hash, "installed ELF differs from Cargo artifact")
        identities[name] = {"cargo_artifact": artifact, "cargo_elf_sha256": original_hash,
                            "installed_elf_sha256": digest(installed), "installed_path": "bin/" + name}
        checksums.append(f"{original_hash}  bin/{name}\n")
        for suffix in ["jsonl", "discovery.log", "library-path", "working-directory"]:
            filename = f"host-cache-{name}.{suffix}" if suffix == "jsonl" else f"host-cache-{name}-{suffix}"
            shutil.copy2(temporary / filename, output / "share" / filename)
    for name, path in libraries.items():
        installed = output / "lib" / name
        shutil.copy2(path, installed)
        shared.require(digest(installed) == digest(path), "installed runtime changed: " + name)
        checksums.append(f"{digest(installed)}  lib/{name}\n")
    # Retain the actual guest entry point in the image closure, with the same
    # immutable-source binding as the executable artifacts.
    supervisor_source = source / "tests/terrane/host_cache_vm.py"
    supervisor = output / "share/host_cache_vm.py"
    shutil.copy2(supervisor_source, supervisor)
    shared.require(supervisor.read_bytes() == supervisor_source.read_bytes(), "installed supervisor differs from source")
    supervisor_identity = {"source_path": "tests/terrane/host_cache_vm.py",
                           "installed_path": "share/host_cache_vm.py", "sha256": digest(supervisor)}
    checksums.append(f"{digest(supervisor)}  share/host_cache_vm.py\n")
    supervisor_helpers = {}
    for helper_name in ["manifest_publication_vm.py", "source_cleanup_vm.py", "admission_cache_vm.py", "host_cache_temporaries_vm.py", "host_cache_encoded_recovery_vm.py", "host_cache_index_recovery_vm.py", "host_cache_pending_recovery_vm.py", "host_cache_pending_packs_vm.py", "encoded_eviction_vm.py", "shared_reextract_vm.py", "sealed_consumer_cold_vm.py", "native_feature_units_vm.py", "host_cache_mount_views_vm.py"]:
        helper_source = source / "tests/terrane" / helper_name
        helper_installed = output / "share" / helper_name
        shared.require(source_hashes.get("tests/terrane/" + helper_name) == digest(helper_source),
                       "supervisor helper lacks its original source binding: " + helper_name)
        shutil.copy2(helper_source, helper_installed)
        shared.require(helper_installed.read_bytes() == helper_source.read_bytes(), "installed supervisor helper differs from source")
        supervisor_helpers[helper_name] = {"source_path": "tests/terrane/" + helper_name,
                                          "installed_path": "share/" + helper_name, "sha256": digest(helper_installed)}
        checksums.append(f"{digest(helper_installed)}  share/{helper_name}\n")

    library_path = ":".join(map(str, [output / "lib", *store_paths]))
    listed = subprocess.run([str(output / "bin/host_cache_fixture"), "--list"],
                            env=dict(os.environ, LD_LIBRARY_PATH=library_path), check=True,
                            text=True, capture_output=True).stdout.splitlines()
    expected = ["host-cache:" + name for name in [
        "prepare", "prepare-readonly-refuse", "empty", "refuse", "late-refuse", "cancel", "edquot", "hold", "start-refuse",
        "admit-chunk", "admit-metadata", "admit-cancel", "cache-admission-handoff", "dictionary-custody", "read-through-chunk", "encoded-read-failure", "encoded-dictionary-read-failure", "metadata-pack-read-failure", "metadata-index-read-failure",
        "seed-manifest", "seed-bad-manifest", "seed-unsealed-manifest",
        "seed-unsealed-writable-manifest", "seed-truncated-manifest", "seed-writable-manifest",
        "recover-manifest", "refuse-manifest", "refuse-unsealed-manifest",
        "refuse-unsealed-writable-manifest", "refuse-truncated-manifest", "recover-writable-manifest",
        "publisher-confinement", "publisher-reject-descriptor", "publisher-reject-stdio",
        "seed-mixed-manifest", "seed-mixed-bad-manifest",
        "recover-mixed-manifest", "refuse-mixed-manifest",
        "consumer-leases", "sealed-consumer", "seed-sealed-consumer-cold", "sealed-consumer-cold", "scoped-file", "publish-inline", "publish-inline-read-failure", "publish-inline-prepare-failure", "publish-inline-cancel", "publish-inline-transfer",
        "publish-inline-transfer-cancel", "publish-inline-transfer-conflict",
        "retain-running", "retain-running-cancel",
        "publish-manifest", "publish-manifest-cancel", "publish-manifest-bad-whole",
        "publish-manifest-dictionary",
        "publish-manifest-reuse",
        "publish-manifest-reuse-bad-whole",
        "source-cleanup", "source-cleanup-early",
        "seed-index-recovery",
        "seed-index-disabled",
        "seed-index-bound",
        "seed-index-mismatch",
        "recover-index-recovery",
        "refuse-index-disabled",
        "refuse-index-bound",
        "refuse-index-mismatch",
        "seed-pending-inline",
        "refuse-pending-inline",
        "recover-pending-inline",
        "seed-pending-raw",
        "seed-pending-zstd",
        "seed-pending-dictionary",
        "refuse-pending-chunk",
        "recover-pending-chunk",
        "seed-pending-pack",
        "refuse-pending-pack",
        "recover-pending-pack",
        "refuse-pending-pack-foreign",
        "seed-conflicting-binding",
        "refuse-conflicting-binding",
        "seed-bound-unsealed",
        "refuse-bound-unsealed",
        "inspect-quarantine",
        "seed-quarantine",
        "recover-quarantine",
        "refuse-quarantine",
        "encoded-eviction",
        "seed-encoded", "recover-encoded", "refuse-encoded",
        "shared-reextract",
    ]]
    shared.require(listed == expected, "cache fixture exact selector inventory mismatch")
    unit_elf = output / "bin" / UNIT_NAME
    unit_hash = digest(unit_elf)
    full_units = unit_inventory(subprocess.run([str(unit_elf), "--list"],
                               env=dict(os.environ, LD_LIBRARY_PATH=library_path),
                               cwd=workspace / "terrane/linux/terrane-linux", check=True, text=True,
                               capture_output=True).stdout)
    shared.require(digest(unit_elf) == unit_hash, "unit discovery changed installed FS ELF")
    selected_units, unit_prefixes = unit_selection()
    unit_identity = {"full_inventory": full_units, "selected_inventory": sorted(selected_units),
                     "features": unit_features(),
                     "root_inventory": sorted(ROOT_UNIT_TESTS),
                     "prefixes": list(unit_prefixes), "working_directory": "crates/terrane/linux/terrane-linux",
                     "profile": UNIT_PROFILE, "guest_uid": 842, "guest_gid": 842}
    identity = {"schema_version": 1, "source": str(source), "artifacts": identities,
                "input_sha256": source_hashes, "selectors": listed, "supervisor": supervisor_identity,
                "supervisor_helpers": supervisor_helpers,
                "runtime_library_path": library_path, "native_cases_executed": [], "unit_tests": unit_identity}
    (output / "share/identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (output / "share/runtime-library-path").write_text(library_path + "\n")
    (output / "share/elf-sha256sum").write_text("".join(checksums))
    shutil.copy2(temporary / "host-cache-packages.json", output / "share/host-cache-packages.json")


if __name__ == "__main__":
    main()

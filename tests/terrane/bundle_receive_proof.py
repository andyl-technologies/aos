"""Binds bundle framing and schema cases to the actual SDK integration artifact."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "registered_metadata_and_requested_opaque_profile_preserve_received_order",
    "all_held_empty_stream_and_omitted_optional_profile_are_valid",
    "chunks_unknown_and_wide_kinds_are_terminal_refusals",
    "absent_wrong_width_and_mismatching_hashes_release_prior_objects",
    "malformed_and_noncanonical_cbor_fail_before_completion",
    "canonical_cbor_is_insufficient_without_registered_metadata_schema",
    "duplicates_and_missing_variants_latch_rejection",
    "count_body_aggregate_and_profile_limits_are_enforced",
    "unrequested_and_nonfinal_profiles_release_all_retained_bytes",
]


if __name__ == "__main__":
    run_sdk_contract(
        "bundle_receive", CASES,
        "Private canonical metadata representation and configured schema checks; "
        "no backend authority, graph closure or deployed GetBundle claim",
    )

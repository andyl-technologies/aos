"""Binds opened-store validation to its actual native integration inventory."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "leaf_authority_modes_follow_opened_reports",
    "routed_spines_accept_zero_or_one_authority_in_configured_order",
    "multiple_authorities_refuse_direct_nested_and_cache_wrapped_routes",
    "cache_erases_ref_authority_and_guard_preserves_its_exact_mode",
    "shared_directory_never_supplies_ref_authority",
    "concurrent_writer_guard_requires_a_cas_authority",
    "required_presigning_checks_the_actual_configured_position",
    "misplaced_writer_policy_and_incompatible_parent_reports_refuse",
    "shape_mismatches_and_unavailable_combinators_do_not_validate",
    "native_validation_uses_actual_file_bucket_and_routed_reports",
]


def main():
    """Executes all logical controls and the genuine native report witness."""
    run_sdk_contract(
        "store_expression", CASES,
        "Opened report compatibility, actual file-bucket probe and routed controls; "
        "composite configuration opening and policy compilation remain separate",
    )


if __name__ == "__main__":
    main()

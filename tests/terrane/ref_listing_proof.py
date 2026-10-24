"""Binds genuine native ref enumeration to the actual public SDK artifact."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "canonical_patterns_preserve_order_whole_heads_and_reopened_inventory",
    "attenuation_filters_other_refs_and_grants_remain_intersected_with_actual_acl",
    "empty_matches_still_refuse_invalid_and_expired_credentials",
    "malformed_patterns_and_root_suffixes_are_rejected",
    "an_unreadable_candidate_failure_exports_no_private_name_or_partial_result",
]


if __name__ == "__main__":
    run_sdk_contract(
        "ref_listing", CASES,
        "Actual complete native inventory and guarded current ref metadata; "
        "no deployed RPC, cross-ref snapshot or bounded stream claim",
    )

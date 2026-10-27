"""Binds genuine native current-head reads to the actual public SDK artifact."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "current_whole_head_matches_committed_history_and_survives_reopen",
    "immutable_tag_point_read_preserves_its_complete_published_record",
    "authorized_absence_remains_distinct_from_invalid_credentials_and_scope_denial",
    "read_only_attenuation_permits_point_reads_but_expired_tokens_refuse",
    "genuine_issuer_signature_and_broad_grants_do_not_override_current_root_acl",
    "malformed_names_refuse_and_lost_original_evidence_is_not_absence",
]


if __name__ == "__main__":
    run_sdk_contract(
        "ref_head", CASES,
        "Actual native guarded current ref metadata; "
        "no deployed RPC or added distributed freshness claim",
    )

"""Binds the public workload-issuer contract tests to actual Cargo artifacts."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "private_file_mints_exact_authenticated_workload_claims",
    "ci_change_credentials_allow_only_baseline_fork_and_assigned_branch_writes",
    "every_lifetime_bound_can_narrow_but_never_widen_issuance",
    "real_entropy_produces_distinct_tokens_and_offline_attenuation_keys",
    "expired_overflowing_and_discontinuous_time_refuse_issuance",
    "missing_identity_and_invalid_canonical_grants_never_issue_credentials",
    "key_file_rejects_links_inode_kinds_permissions_lengths_and_wrong_public_keys",
    "policy_paths_and_local_errors_fail_closed_without_disclosing_key_material",
]


def main():
    """Executes the complete source-bound integration inventory."""
    run_sdk_contract(
        "workload_issuer", CASES,
        "Native static-key workload issuance only; no remote authentication, "
        "GCP exchange or repository authorization claim",
    )


if __name__ == "__main__":
    main()

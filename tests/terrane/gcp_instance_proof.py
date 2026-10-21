"""Binds the public gcp-instance-issuer contract tests to actual Cargo artifacts."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "signed_full_identity_mints_only_the_assigned_instance_and_job",
    "signed_ci_identity_cannot_mint_baseline_or_other_change_writes",
    "changed_signatures_unknown_keys_and_unsupported_headers_are_denied",
    "signed_claims_cannot_select_another_project_instance_account_or_job",
    "signed_identity_times_are_checked_with_the_injected_clock",
    "unavailable_ambiguous_and_excessive_key_responses_never_mint",
    "complete_exchange_deadline_drops_a_pending_key_stream",
    "duplicate_assignments_and_invalid_trusted_configuration_are_rejected",
]


def main():
    """Executes the complete source-bound integration inventory."""
    run_sdk_contract(
        "gcp_instance_issuer", CASES,
        "Recorded GCE claims and actual RSA verification with bounded injected "
        "HTTPS key transport; no live Google probe or deployed endpoint claim",
    )


if __name__ == "__main__":
    main()

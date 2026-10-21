"""Binds trusted issuer configuration and actual private-file opening to Cargo."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "strict_issuer_policy_loads_without_accessing_its_signing_path",
    "invalid_and_ambiguous_whole_configuration_refuses_before_opening",
    "role_and_name_checks_precede_private_signing_file_access",
    "configured_private_file_mints_bounded_ci_tokens_and_rejects_bad_authority",
]


def main():
    """Executes the complete configuration and native private-key inventory."""
    run_sdk_contract(
        "configured_workload_issuer", CASES,
        "Trusted static issuer configuration, selected serve-role opening and actual "
        "bounded CI token minting; no remote caller authentication or deployed endpoint",
    )


if __name__ == "__main__":
    main()

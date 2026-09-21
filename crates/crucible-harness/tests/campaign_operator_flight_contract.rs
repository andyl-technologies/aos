//! Validates the manual operator and dogfood evidence contract from RFC-0020.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;

use serde::Deserialize;

const CONTRACT_SOURCE: &str = include_str!(
    "../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-flight-contract.toml"
);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: String,
    acceptance_state: String,
    gates: Vec<String>,
    rfc_section: String,
    recorder: String,
    manifest_schema: String,
    command_record_schema: String,
    attestation_statement_schema: String,
    bundle_identity: String,
    cryptographic_attestation: String,
    operator_acceptance: OperatorAcceptance,
    dogfood: Dogfood,
    evidence: Evidence,
    sign_offs: SignOffs,
    automation: Automation,
    manual_remaining: ManualRemaining,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorAcceptance {
    minimum_duration_hours: u64,
    maximum_duration_hours: u64,
    required_participants: Vec<String>,
    required_lifecycle: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dogfood {
    minimum_duration_hours: u64,
    release_candidate_duration_hours: u64,
    minimum_hot_children: u64,
    minimum_promoted_template_generations: u64,
    minimum_admitted_attempts: u64,
    required_participants: Vec<String>,
    required_pressure_classes: Vec<String>,
    required_events: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    provenance: Vec<String>,
    command_journal: Vec<String>,
    authenticated_exports: Vec<String>,
    resource_audit: Vec<String>,
    required_artifacts: Vec<String>,
    required_result_fields: Vec<String>,
    allowed_outcomes: Vec<String>,
    allowed_defect_dispositions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignOffs {
    required_roles: Vec<String>,
    distinct_authorized_keys: bool,
    unsigned_result: String,
    automated_result: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Automation {
    service_start: String,
    service_restart: String,
    coordinator_restart: String,
    executor_restart: String,
    credential_refresh: String,
    store_repair: String,
    store_gc: String,
    store_transform_packed: String,
    evidence_export: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualRemaining {
    claims: Vec<String>,
    automated_result: String,
    unsigned_result: String,
}

#[test]
fn operator_contract_is_executable_without_claiming_manual_acceptance() -> Result<(), Box<dyn Error>>
{
    let contract: Contract = toml::from_str(CONTRACT_SOURCE)?;
    let required_roles = vec![
        String::from("driver"),
        String::from("independent-reviewer"),
        String::from("campaign-model-owner"),
        String::from("qemu-boundary-owner"),
        String::from("storage-owner"),
        String::from("guest-api-owner"),
        String::from("operations-owner"),
    ];

    assert_eq!(
        contract.schema,
        "aos.crucible.campaign-operator-flight-contract.v1"
    );
    assert_eq!(contract.acceptance_state, "manual-evidence-required");
    assert_eq!(
        contract.gates.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            String::from("gate:campaign-dogfood"),
            String::from("gate:campaign-operator-acceptance"),
        ])
    );
    assert!(contract.rfc_section.contains("14.9"));
    assert!(
        contract
            .recorder
            .ends_with("campaign-manual-flight-recorder.sh")
    );
    assert_eq!(
        contract.manifest_schema,
        "crucible.campaign-manual-flight-manifest.v1"
    );
    assert_eq!(
        contract.command_record_schema,
        "crucible.campaign-command-record.v1"
    );
    assert_eq!(
        contract.attestation_statement_schema,
        "crucible.campaign-manual-flight-attestation-statement.v1"
    );
    assert_eq!(
        contract.bundle_identity,
        "sha256-of-canonical-checksum-manifest"
    );
    assert_eq!(
        contract.cryptographic_attestation,
        "ed25519-over-canonical-attestation-statement"
    );

    assert_eq!(contract.operator_acceptance.minimum_duration_hours, 4);
    assert_eq!(contract.operator_acceptance.maximum_duration_hours, 8);
    assert_eq!(
        contract.operator_acceptance.required_participants,
        ["driver", "independent-reviewer"]
    );
    assert!(
        contract
            .operator_acceptance
            .required_lifecycle
            .contains(&String::from("pause-restart-resume"))
    );
    assert_eq!(contract.dogfood.minimum_duration_hours, 24);
    assert_eq!(contract.dogfood.release_candidate_duration_hours, 72);
    assert!(contract.dogfood.minimum_hot_children >= 10_000);
    assert!(contract.dogfood.minimum_promoted_template_generations >= 3);
    assert!(contract.dogfood.minimum_admitted_attempts >= 1_000_000);
    assert_eq!(
        contract.dogfood.required_participants,
        [
            "driver",
            "independent-reviewer",
            "handoff-operator",
            "release-owner",
        ]
    );
    assert_eq!(contract.dogfood.required_pressure_classes.len(), 4);
    assert!(
        contract
            .dogfood
            .required_events
            .contains(&String::from("planned-daemon-restart"))
    );

    assert!(
        contract
            .evidence
            .provenance
            .contains(&String::from("source-revision"))
    );
    assert!(
        contract
            .evidence
            .command_journal
            .contains(&String::from("exit-status"))
    );
    assert!(
        contract
            .evidence
            .authenticated_exports
            .contains(&String::from("store-verify"))
    );
    assert_eq!(contract.evidence.resource_audit.len(), 9);
    assert_eq!(contract.evidence.required_artifacts.len(), 8);
    assert!(
        contract
            .evidence
            .required_result_fields
            .contains(&String::from("defects"))
    );
    assert_eq!(contract.evidence.allowed_outcomes.len(), 4);
    assert_eq!(contract.evidence.allowed_defect_dispositions.len(), 3);
    assert_eq!(contract.sign_offs.required_roles, required_roles);
    assert!(contract.sign_offs.distinct_authorized_keys);
    assert_eq!(contract.sign_offs.unsigned_result, "blocked");
    assert_eq!(contract.sign_offs.automated_result, "prerequisite-only");
    assert!(
        contract
            .evidence
            .authenticated_exports
            .contains(&String::from("store-packed-transform-plan-and-result"))
    );
    assert_eq!(
        contract.automation.store_transform_packed,
        "crucible --format jsonl store transform packed --store STORE --node NODE --journal JOURNAL plan|apply"
    );
    for public_surface in [
        contract.automation.service_start,
        contract.automation.store_repair,
        contract.automation.store_gc,
        contract.automation.store_transform_packed,
    ] {
        assert!(public_surface.contains("crucible"));
    }
    for recorded_recovery in [
        contract.automation.service_restart,
        contract.automation.coordinator_restart,
        contract.automation.executor_restart,
        contract.automation.credential_refresh,
        contract.automation.evidence_export,
    ] {
        assert!(!recorded_recovery.is_empty());
    }
    assert_eq!(
        contract.manual_remaining.automated_result,
        "prerequisite-only"
    );
    assert_eq!(contract.manual_remaining.unsigned_result, "blocked");
    assert!(contract.manual_remaining.claims.len() >= 7);

    Ok(())
}

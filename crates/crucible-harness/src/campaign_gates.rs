//! Executable gate contracts for RFC-0020 campaign requirements.
//!
//! RFC-0020 defines gates beyond the original RFC-0010 determinism catalog.
//! This registry records whether each campaign gate has an isolable automated
//! target, a reviewable manual evidence contract, or no executable contract
//! yet. Catalog-only entries remain explicit so traceability fails with the
//! exact unsupported gate name instead of accepting a prose mention.

/// The executable contract attached to an RFC-0020 gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGateContract {
    /// One or more isolable Cargo integration tests wired to a Nix check.
    Automated {
        /// Cargo targets that jointly implement the contract.
        targets: &'static [CampaignGateTarget],
        /// Nix check attribute that runs the gate.
        nix_attr: &'static str,
    },
    /// A manual evidence schema and Nix validator for retained artifacts.
    Manual {
        /// Repository-relative evidence-contract path.
        artifact_contract: &'static str,
        /// Nix check attribute that validates retained evidence.
        nix_attr: &'static str,
    },
    /// No executable or manual artifact contract exists yet.
    Unsupported,
}

/// One isolable Cargo integration target in an automated campaign gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGateTarget {
    /// Cargo package that owns the integration test.
    pub package: &'static str,
    /// Cargo integration-test target name, without `.rs`.
    pub test_target: &'static str,
}

/// A canonical gate referenced by RFC-0020 requirement traceability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGateSpec {
    /// Canonical gate name, including the `gate:` prefix.
    pub name: &'static str,
    /// Workspace area responsible for completing the contract.
    pub owner: &'static str,
    /// Current executable contract.
    pub contract: CampaignGateContract,
}

const fn automated(
    name: &'static str,
    owner: &'static str,
    targets: &'static [CampaignGateTarget],
    nix_attr: &'static str,
) -> CampaignGateSpec {
    CampaignGateSpec {
        name,
        owner,
        contract: CampaignGateContract::Automated { targets, nix_attr },
    }
}

const fn unsupported(name: &'static str, owner: &'static str) -> CampaignGateSpec {
    CampaignGateSpec {
        name,
        owner,
        contract: CampaignGateContract::Unsupported,
    }
}

/// Canonical RFC-0020 campaign gate catalog.
pub const CAMPAIGN_GATES: &[CampaignGateSpec] = &[
    automated(
        "gate:abi-conformance",
        "crucible-harness",
        &[CampaignGateTarget {
            package: "crucible-harness",
            test_target: "gate_abi_conformance",
        }],
        "checks.crucible.phase2.gates.abiConformance",
    ),
    automated(
        "gate:attempt-idempotence",
        "crucible-campaign",
        &[CampaignGateTarget {
            package: "crucible-campaign",
            test_target: "gate_attempt_idempotence",
        }],
        "checks.crucible.phase4.gates.attemptIdempotence",
    ),
    unsupported("gate:branch-point-model", "crucible-campaign"),
    unsupported("gate:campaign-component-contract", "crucible-campaign"),
    unsupported("gate:campaign-continuity-v2", "crucible-campaign"),
    unsupported("gate:campaign-destructive-recovery", "crucible-daemon"),
    unsupported("gate:campaign-dogfood", "crucible-cli"),
    automated(
        "gate:campaign-model",
        "crucible-campaign",
        &[CampaignGateTarget {
            package: "crucible-campaign",
            test_target: "gate_campaign_model",
        }],
        "checks.crucible.phase1.gates.campaignModel",
    ),
    automated(
        "gate:campaign-mutation-scaling",
        "crucible-campaign",
        &[CampaignGateTarget {
            package: "crucible-campaign",
            test_target: "gate_campaign_mutation_scaling",
        }],
        "checks.crucible.phase4.gates.campaignMutationScaling",
    ),
    unsupported("gate:campaign-operator-acceptance", "crucible-cli"),
    unsupported("gate:campaign-replay", "crucible-campaign"),
    automated(
        "gate:campaign-statistics",
        "crucible-campaign",
        &[CampaignGateTarget {
            package: "crucible-campaign",
            test_target: "gate_campaign_statistics",
        }],
        "checks.crucible.phase4.gates.campaignStatistics",
    ),
    automated(
        "gate:campaign-store-composition",
        "crucible-cas",
        &[
            CampaignGateTarget {
                package: "crucible-cas",
                test_target: "gate_campaign_store_composition",
            },
            CampaignGateTarget {
                package: "crucible-cli",
                test_target: "gate_campaign_store_composition",
            },
        ],
        "checks.crucible.phase5.gates.campaignStoreComposition",
    ),
    automated(
        "gate:campaign-store-equivalence",
        "crucible-cas",
        &[CampaignGateTarget {
            package: "crucible-cas",
            test_target: "gate_campaign_store_equivalence",
        }],
        "checks.crucible.phase5.gates.campaignStoreEquivalence",
    ),
    automated(
        "gate:content-address",
        "crucible",
        &[CampaignGateTarget {
            package: "crucible",
            test_target: "gate_content_address",
        }],
        "checks.crucible.phase1.gates.contentAddress",
    ),
    unsupported("gate:control-responsiveness", "crucible-daemon"),
    unsupported("gate:e2e-determinism", "crucible-harness"),
    unsupported("gate:exact-closure-streaming", "crucible-cas"),
    unsupported("gate:hot-fork-equivalence", "crucible-daemon"),
    unsupported("gate:hot-fork-isolation", "crucible-daemon"),
    unsupported("gate:hot-fork-scaling", "crucible-daemon"),
    unsupported("gate:lazy-frontier", "crucible-campaign"),
    automated(
        "gate:license-boundary",
        "crucible-harness",
        &[CampaignGateTarget {
            package: "crucible-harness",
            test_target: "gate_license_boundary",
        }],
        "checks.crucible.phase1.gates.licenseBoundary",
    ),
    automated(
        "gate:typed-choice",
        "crucible-campaign",
        &[CampaignGateTarget {
            package: "crucible-campaign",
            test_target: "gate_typed_choice",
        }],
        "checks.crucible.phase2.gates.typedChoice",
    ),
    unsupported("gate:typed-choice-product-checkpoint", "crucible-daemon"),
    unsupported("gate:world-fork-atomicity", "crucible-daemon"),
];

/// Returns every RFC-0020 gate in stable lexical order.
#[must_use]
pub fn campaign_gates() -> &'static [CampaignGateSpec] {
    CAMPAIGN_GATES
}

/// Finds an RFC-0020 gate by its canonical name.
#[must_use]
pub fn find_campaign_gate(name: &str) -> Option<&'static CampaignGateSpec> {
    CAMPAIGN_GATES.iter().find(|gate| gate.name == name)
}

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
    /// One or more isolable Cargo targets wired to a Nix check.
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

/// How an automated campaign gate invokes one Cargo target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGateTargetKind {
    /// A normal Cargo integration-test target.
    Integration {
        /// Integration-test target name, without `.rs`.
        test_target: &'static str,
    },
    /// Exact tests in a package library, run by a Nix flight.
    LibExact {
        /// Exact selectors and the library source files that define them.
        selectors: &'static [LibraryExactSelector],
        /// Repository-relative Nix source that runs every selector.
        nix_source: &'static str,
        /// Whether the flight must opt into intentionally ignored tests.
        ignored: bool,
    },
}

/// One exact library selector and its defining source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LibraryExactSelector {
    /// Repository-relative Rust source containing the test function.
    pub source: &'static str,
    /// Full `cargo test --exact` selector.
    pub name: &'static str,
}

/// One isolable Cargo target in an automated campaign gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGateTarget {
    /// Cargo package that owns the target.
    pub package: &'static str,
    /// Exact target and invocation kind.
    pub kind: CampaignGateTargetKind,
}

const fn integration_target(
    package: &'static str,
    test_target: &'static str,
) -> CampaignGateTarget {
    CampaignGateTarget {
        package,
        kind: CampaignGateTargetKind::Integration { test_target },
    }
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

const HOT_FORK_EQUIVALENCE_SELECTORS: &[LibraryExactSelector] = &[
    LibraryExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/equivalence.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_matches_thin_and_exact_from_execution_and_exact_templates",
    },
    LibraryExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/equivalence.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_single_node_hot_fork_matches_thin_and_exact",
    },
    LibraryExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/failures.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_source_preparation_failure_exposes_no_template",
    },
];

const LAZY_FRONTIER_MERKLE_SELECTORS: &[LibraryExactSelector] = &[LibraryExactSelector {
    source: "crates/crucible-campaign/src/merkle/bulk.rs",
    name: "merkle::bulk::tests::million_dormant_continuations_use_bounded_production_frontier_pages",
}];

const LAZY_FRONTIER_DAEMON_SELECTORS: &[LibraryExactSelector] = &[LibraryExactSelector {
    source: "crates/crucible-daemon/src/executor_pool/tests.rs",
    name: "executor_pool::tests::campaign_controls_remain_responsive_while_every_executor_slot_is_busy",
}];

/// Canonical RFC-0020 campaign gate catalog.
pub const CAMPAIGN_GATES: &[CampaignGateSpec] = &[
    automated(
        "gate:abi-conformance",
        "crucible-harness",
        &[integration_target(
            "crucible-harness",
            "gate_abi_conformance",
        )],
        "checks.crucible.phase2.gates.abiConformance",
    ),
    automated(
        "gate:attempt-idempotence",
        "crucible-campaign",
        &[integration_target(
            "crucible-campaign",
            "gate_attempt_idempotence",
        )],
        "checks.crucible.phase4.gates.attemptIdempotence",
    ),
    automated(
        "gate:branch-point-model",
        "crucible-campaign",
        &[integration_target(
            "crucible-campaign",
            "gate_branch_point_model",
        )],
        "checks.crucible.phase4.gates.branchPointModel",
    ),
    automated(
        "gate:campaign-component-contract",
        "crucible-daemon",
        &[integration_target(
            "crucible-daemon",
            "gate_campaign_component_contract",
        )],
        "checks.crucible.phase5.gates.campaignStoreComposition",
    ),
    unsupported("gate:campaign-continuity-v2", "crucible-campaign"),
    unsupported("gate:campaign-destructive-recovery", "crucible-daemon"),
    unsupported("gate:campaign-dogfood", "crucible-cli"),
    automated(
        "gate:campaign-model",
        "crucible-campaign",
        &[integration_target(
            "crucible-campaign",
            "gate_campaign_model",
        )],
        "checks.crucible.phase1.gates.campaignModel",
    ),
    automated(
        "gate:campaign-mutation-scaling",
        "crucible-campaign",
        &[integration_target(
            "crucible-campaign",
            "gate_campaign_mutation_scaling",
        )],
        "checks.crucible.phase4.gates.campaignMutationScaling",
    ),
    unsupported("gate:campaign-operator-acceptance", "crucible-cli"),
    unsupported("gate:campaign-replay", "crucible-campaign"),
    automated(
        "gate:campaign-statistics",
        "crucible-campaign",
        &[integration_target(
            "crucible-campaign",
            "gate_campaign_statistics",
        )],
        "checks.crucible.phase4.gates.campaignStatistics",
    ),
    automated(
        "gate:campaign-store-composition",
        "crucible-cas",
        &[
            integration_target("crucible-cas", "gate_campaign_store_composition"),
            integration_target("crucible-cli", "gate_campaign_store_composition"),
        ],
        "checks.crucible.phase5.gates.campaignStoreComposition",
    ),
    automated(
        "gate:campaign-store-equivalence",
        "crucible-cas",
        &[integration_target(
            "crucible-cas",
            "gate_campaign_store_equivalence",
        )],
        "checks.crucible.phase5.gates.campaignStoreEquivalence",
    ),
    automated(
        "gate:content-address",
        "crucible",
        &[integration_target("crucible", "gate_content_address")],
        "checks.crucible.phase1.gates.contentAddress",
    ),
    unsupported("gate:control-responsiveness", "crucible-daemon"),
    unsupported("gate:e2e-determinism", "crucible-harness"),
    unsupported("gate:exact-closure-streaming", "crucible-cas"),
    automated(
        "gate:hot-fork-equivalence",
        "crucible-daemon",
        &[CampaignGateTarget {
            package: "crucible-daemon",
            kind: CampaignGateTargetKind::LibExact {
                selectors: HOT_FORK_EQUIVALENCE_SELECTORS,
                nix_source: "tests/crucible/phase7-qemu-hot-fork-equivalence-vm.nix",
                ignored: true,
            },
        }],
        "checks.crucible.phase7.qemuHotForkEquivalenceVm",
    ),
    unsupported("gate:hot-fork-isolation", "crucible-daemon"),
    unsupported("gate:hot-fork-scaling", "crucible-daemon"),
    automated(
        "gate:lazy-frontier",
        "crucible-campaign",
        &[
            integration_target("crucible-campaign", "gate_lazy_frontier"),
            CampaignGateTarget {
                package: "crucible-campaign",
                kind: CampaignGateTargetKind::LibExact {
                    selectors: LAZY_FRONTIER_MERKLE_SELECTORS,
                    nix_source: "tests/crucible/phase4-lazy-frontier.nix",
                    ignored: false,
                },
            },
            CampaignGateTarget {
                package: "crucible-daemon",
                kind: CampaignGateTargetKind::LibExact {
                    selectors: LAZY_FRONTIER_DAEMON_SELECTORS,
                    nix_source: "tests/crucible/phase4-lazy-frontier.nix",
                    ignored: false,
                },
            },
        ],
        "checks.crucible.phase4.gates.lazyFrontier",
    ),
    automated(
        "gate:license-boundary",
        "crucible-harness",
        &[integration_target(
            "crucible-harness",
            "gate_license_boundary",
        )],
        "checks.crucible.phase1.gates.licenseBoundary",
    ),
    automated(
        "gate:typed-choice",
        "crucible-campaign",
        &[integration_target("crucible-campaign", "gate_typed_choice")],
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

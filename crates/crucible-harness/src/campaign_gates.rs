//! Executable gate contracts for RFC-0020 campaign requirements.
//!
//! RFC-0020 defines gates beyond the original RFC-0010 determinism catalog.
//! This registry records whether each campaign gate has an isolable automated
//! target or a reviewable manual evidence contract.

/// The executable contract attached to an RFC-0020 gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGateContract {
    /// One or more isolable Cargo targets or product flights wired to a Nix check.
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
}

/// How an automated campaign gate invokes one Cargo target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGateTargetKind {
    /// A normal Cargo integration-test target.
    Integration {
        /// Integration-test target name, without `.rs`.
        test_target: &'static str,
    },
    /// Exact tests in an integration-test target, run by a Nix flight.
    IntegrationExact {
        /// Integration-test target name, without `.rs`.
        test_target: &'static str,
        /// Exact selectors and the Rust source files that define them.
        selectors: &'static [ExactSelector],
        /// Repository-relative Nix sources that select and run the target.
        nix_sources: &'static [&'static str],
        /// Installed test-binary name invoked by the flight.
        runner: &'static str,
        /// Evidence lines the flight must publish after the selector passes.
        evidence: &'static [&'static str],
        /// Whether the flight must opt into intentionally ignored tests.
        ignored: bool,
    },
    /// Exact tests in a package library, run by a Nix flight.
    LibExact {
        /// Exact selectors and the library source files that define them.
        selectors: &'static [ExactSelector],
        /// Repository-relative Nix source that runs every selector.
        nix_source: &'static str,
        /// Whether the flight must opt into intentionally ignored tests.
        ignored: bool,
    },
    /// Exact library tests whose retained result is authenticated by another Nix gate.
    LibExactAggregate {
        /// Exact selectors executed by the producer flight.
        selectors: &'static [ExactSelector],
        /// Repository-relative Nix source that executes the selectors.
        producer_nix_source: &'static str,
        /// Producer check attribute used by that source.
        producer_nix_attr: &'static str,
        /// Gate identity emitted by the producer result.
        producer_gate: &'static str,
        /// Repository-relative Nix source that authenticates producer evidence.
        aggregate_nix_source: &'static str,
        /// Exact evidence lines required from the producer result.
        evidence: &'static [&'static str],
        /// Whether the producer flight must opt into intentionally ignored tests.
        ignored: bool,
    },
}

/// One exact test selector and its defining source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactSelector {
    /// Repository-relative Rust source containing the test function.
    pub source: &'static str,
    /// Full `cargo test --exact` selector.
    pub name: &'static str,
}

/// One isolable target in an automated campaign gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGateTarget {
    /// Workspace package that owns the target or product runner.
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

const fn manual(
    name: &'static str,
    owner: &'static str,
    artifact_contract: &'static str,
    nix_attr: &'static str,
) -> CampaignGateSpec {
    CampaignGateSpec {
        name,
        owner,
        contract: CampaignGateContract::Manual {
            artifact_contract,
            nix_attr,
        },
    }
}

const HOT_FORK_EQUIVALENCE_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/equivalence.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_matches_thin_and_exact_from_execution_and_exact_templates",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/equivalence.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_single_node_hot_fork_matches_thin_and_exact",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/failures.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_source_preparation_failure_exposes_no_template",
    },
];

const LAZY_FRONTIER_MERKLE_SELECTORS: &[ExactSelector] = &[ExactSelector {
    source: "crates/crucible-campaign/src/merkle/bulk.rs",
    name: "merkle::bulk::tests::million_dormant_continuations_use_bounded_production_frontier_pages",
}];

const CAMPAIGN_CONTROL_RESPONSIVENESS_SELECTORS: &[ExactSelector] = &[ExactSelector {
    source: "crates/crucible-daemon/src/executor_pool/tests.rs",
    name: "executor_pool::tests::campaign_controls_remain_responsive_while_every_executor_slot_is_busy",
}];

const EXACT_CLOSURE_STREAMING_API_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-api/src/vm_lifecycle/checkpoint_store/tests.rs",
        name: "vm_lifecycle::checkpoint_store::tests::portable_closure_inventory_streams_only_authenticated_manifest_objects",
    },
    ExactSelector {
        source: "crates/crucible-api/src/vm_lifecycle/checkpoint_store/tests.rs",
        name: "vm_lifecycle::checkpoint_store::tests::file_artifact_stream_authenticates_sparse_file_contents",
    },
    ExactSelector {
        source: "crates/crucible-api/src/vm_lifecycle/checkpoint_store/tests.rs",
        name: "vm_lifecycle::checkpoint_store::tests::chunked_artifact_stream_recreates_sparse_zero_extents",
    },
];

const EXACT_CLOSURE_STREAMING_CAMPAIGN_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-campaign/src/merkle.rs",
        name: "merkle::tests::many_deterministic_permutations_produce_one_root_and_valid_closure",
    },
    ExactSelector {
        source: "crates/crucible-campaign/src/merkle.rs",
        name: "merkle::tests::incomplete_and_inconsistent_nodes_fail_closed",
    },
];

const HOT_FORK_SCALING_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/equivalence.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_scales_across_three_semantic_template_depths",
    },
];

const WORLD_FORK_ATOMICITY_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/failures.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_fork_fails",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/failures.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_adoption_fails",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/failures.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_until_target_cleanup_retries",
    },
    ExactSelector {
        source: "crates/crucible-daemon/src/qemu_hot_fork_world_factory/tests/native_acceptance/failures.rs",
        name: "qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_across_repository_publication_retry",
    },
];

const TYPED_CHOICE_PRODUCT_CHECKPOINT_SELECTORS: &[ExactSelector] = &[ExactSelector {
    source: "crates/crucible-cli/tests/support/campaign_packaged_process/guest_choice.rs",
    name: "packaged::guest_choice::public_guest_choices_survive_exact_checkpoint_and_daemon_restart",
}];

const TYPED_CHOICE_PRODUCT_CHECKPOINT_NIX_SOURCES: &[&str] = &[
    "tests/crucible/phase4-packaged-campaign-choice-vm.nix",
    "tests/crucible/phase4-packaged-campaign-vm.nix",
];

const CAMPAIGN_REPLAY_PRODUCTION_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-cli/tests/campaign_process.rs",
        name: "campaign_run_production_qemu_exact_checkpoint_then_replay_matches",
    },
    ExactSelector {
        source: "crates/crucible-cli/tests/campaign_process.rs",
        name: "interactive_session_captures_and_replays_exact_live_artifact",
    },
];

const CAMPAIGN_REPLAY_PRODUCTION_NIX_SOURCES: &[&str] =
    &["tests/crucible/phase4-packaged-campaign-vm.nix"];

const CAMPAIGN_OPERATIONAL_CONTINUITY_SELECTORS: &[ExactSelector] = &[
    ExactSelector {
        source: "crates/crucible-cli/tests/campaign_store_process.rs",
        name: "public_campaign_debug_opens_authenticated_finding_at_fast_midpoint",
    },
    ExactSelector {
        source: "crates/crucible-cli/tests/campaign_store_process.rs",
        name: "public_composed_store_flight_evicts_cache_and_flushes_write_back",
    },
    ExactSelector {
        source: "crates/crucible-cli/tests/campaign_store_process/archive_transfer.rs",
        name: "archive_transfer::public_offline_archive_transfer_reports_and_authenticates_sensitive_closure",
    },
    ExactSelector {
        source: "crates/crucible-cli/tests/campaign_store_process/archive_transfer.rs",
        name: "archive_transfer::public_archive_transfer_is_backend_neutral_across_compressed_stores",
    },
];

const CAMPAIGN_OPERATIONAL_CONTINUITY_NIX_SOURCES: &[&str] = &[
    "tests/crucible/phase4-packaged-campaign-vm.nix",
    "tests/crucible/phase9-campaign-operational-continuity.nix",
];

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
    automated(
        "gate:campaign-cold-continuity",
        "crucible-campaign",
        &[integration_target(
            "crucible-campaign",
            "gate_campaign_cold_continuity",
        )],
        "checks.crucible.phase5.gates.campaignColdContinuity",
    ),
    manual(
        "gate:campaign-destructive-recovery",
        "crucible-daemon",
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml",
        "checks.crucible.phase9.gates.campaignDestructiveRecoveryContract",
    ),
    manual(
        "gate:campaign-dogfood",
        "crucible-cli",
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml",
        "checks.crucible.phase9.gates.campaignDogfoodContract",
    ),
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
    automated(
        "gate:campaign-operational-continuity",
        "crucible-cli",
        &[CampaignGateTarget {
            package: "crucible-cli",
            kind: CampaignGateTargetKind::IntegrationExact {
                test_target: "campaign_store_process",
                selectors: CAMPAIGN_OPERATIONAL_CONTINUITY_SELECTORS,
                nix_sources: CAMPAIGN_OPERATIONAL_CONTINUITY_NIX_SOURCES,
                runner: "campaign-store-process-flight",
                evidence: &[
                    "gate=gate:campaign-operational-continuity",
                    "coordinator_executor_restart=true",
                    "exact_pause=true",
                    "backend_neutral_archival=true",
                    "offline_maintenance_transfer=true",
                    "fast_midpoint_debug=true",
                ],
                ignored: false,
            },
        }],
        "checks.crucible.phase9.gates.campaignOperationalContinuity",
    ),
    manual(
        "gate:campaign-operator-acceptance",
        "crucible-cli",
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml",
        "checks.crucible.phase9.gates.campaignOperatorAcceptanceContract",
    ),
    automated(
        "gate:campaign-replay",
        "crucible-campaign",
        &[
            integration_target("crucible-campaign", "gate_campaign_replay"),
            integration_target("crucible", "gate_campaign_replay"),
            CampaignGateTarget {
                package: "crucible-cli",
                kind: CampaignGateTargetKind::IntegrationExact {
                    test_target: "campaign_process",
                    selectors: CAMPAIGN_REPLAY_PRODUCTION_SELECTORS,
                    nix_sources: CAMPAIGN_REPLAY_PRODUCTION_NIX_SOURCES,
                    runner: "campaign-process-flight",
                    evidence: &[
                        "campaign_production_qemu_exact_checkpoint_replay=true",
                        "interactive_packaged_capture_replay=true",
                    ],
                    ignored: true,
                },
            },
        ],
        "checks.crucible.phase4.gates.campaignReplay.rawGate",
    ),
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
    automated(
        "gate:control-responsiveness",
        "crucible-daemon",
        &[CampaignGateTarget {
            package: "crucible-daemon",
            kind: CampaignGateTargetKind::LibExact {
                selectors: CAMPAIGN_CONTROL_RESPONSIVENESS_SELECTORS,
                nix_source: "tests/crucible/phase4-control-responsiveness.nix",
                ignored: false,
            },
        }],
        "checks.crucible.phase4.gates.controlResponsiveness",
    ),
    manual(
        "gate:e2e-determinism",
        "crucible-harness",
        "tests/crucible/e2e-determinism-evidence-contract.toml",
        "checks.crucible.phase7.gates.e2eDeterminismEvidenceContract",
    ),
    automated(
        "gate:exact-closure-streaming",
        "crucible-api",
        &[
            CampaignGateTarget {
                package: "crucible-api",
                kind: CampaignGateTargetKind::LibExact {
                    selectors: EXACT_CLOSURE_STREAMING_API_SELECTORS,
                    nix_source: "tests/crucible/phase5-exact-closure-streaming.nix",
                    ignored: false,
                },
            },
            CampaignGateTarget {
                package: "crucible-campaign",
                kind: CampaignGateTargetKind::LibExact {
                    selectors: EXACT_CLOSURE_STREAMING_CAMPAIGN_SELECTORS,
                    nix_source: "tests/crucible/phase5-exact-closure-streaming.nix",
                    ignored: false,
                },
            },
        ],
        "checks.crucible.phase5.gates.exactClosureStreaming",
    ),
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
    automated(
        "gate:hot-fork-isolation",
        "crucible-daemon",
        &[CampaignGateTarget {
            package: "crucible-daemon",
            kind: CampaignGateTargetKind::LibExactAggregate {
                selectors: WORLD_FORK_ATOMICITY_SELECTORS,
                producer_nix_source: "tests/crucible/phase7-qemu-hot-fork-atomic-world-vm.nix",
                producer_nix_attr: "checks.crucible.phase7.gates.worldForkAtomicity",
                producer_gate: "gate:world-fork-atomicity",
                aggregate_nix_source: "tests/crucible/phase7-crucible-hot-fork-isolation.nix",
                evidence: &[
                    "native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation",
                ],
                ignored: true,
            },
        }],
        "checks.crucible.phase7.gates.hotForkIsolation.rawGate",
    ),
    automated(
        "gate:hot-fork-scaling",
        "crucible-daemon",
        &[CampaignGateTarget {
            package: "crucible-daemon",
            kind: CampaignGateTargetKind::LibExact {
                selectors: HOT_FORK_SCALING_SELECTORS,
                nix_source: "tests/crucible/phase7-qemu-hot-fork-scaling-vm.nix",
                ignored: true,
            },
        }],
        "checks.crucible.phase7.gates.hotForkScaling.rawGate",
    ),
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
                    selectors: CAMPAIGN_CONTROL_RESPONSIVENESS_SELECTORS,
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
    automated(
        "gate:typed-choice-product-checkpoint",
        "crucible-cli",
        &[CampaignGateTarget {
            package: "crucible-cli",
            kind: CampaignGateTargetKind::IntegrationExact {
                test_target: "campaign_store_process",
                selectors: TYPED_CHOICE_PRODUCT_CHECKPOINT_SELECTORS,
                nix_sources: TYPED_CHOICE_PRODUCT_CHECKPOINT_NIX_SOURCES,
                runner: "campaign-process-flight",
                evidence: &[
                    "gate=gate:typed-choice-product-checkpoint",
                    "proven=typed-guest-registration,fresh-qemu-restore",
                ],
                ignored: true,
            },
        }],
        "checks.crucible.phase4.packagedCampaignChoiceVm",
    ),
    automated(
        "gate:world-fork-atomicity",
        "crucible-daemon",
        &[CampaignGateTarget {
            package: "crucible-daemon",
            kind: CampaignGateTargetKind::LibExact {
                selectors: WORLD_FORK_ATOMICITY_SELECTORS,
                nix_source: "tests/crucible/phase7-qemu-hot-fork-atomic-world-vm.nix",
                ignored: true,
            },
        }],
        "checks.crucible.phase7.gates.worldForkAtomicity",
    ),
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

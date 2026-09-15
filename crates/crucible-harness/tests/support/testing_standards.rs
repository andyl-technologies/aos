//! Shared testing-standard support.

use super::*;

#[path = "testing_standards/source_inventory.rs"]
mod source_inventory;
pub(super) use source_inventory::*;
pub(super) fn testing_standard_failures(
    targets: &[GateTargetSpec],
    source_overrides: &GateSourceOverrides,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut targets_by_gate: BTreeMap<&str, Vec<&GateTargetSpec>> = BTreeMap::new();
    let mut gates_by_package: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for target in targets {
        targets_by_gate.entry(target.gate).or_default().push(target);
        gates_by_package
            .entry(target.package)
            .or_default()
            .insert(target.gate);

        let Some(standard) = standard_for_gate(target.gate) else {
            failures.push(format!(
                "{}:{} has no per-layer testing standard",
                target.package, target.test_target
            ));
            continue;
        };

        let Some(layer) = package_layer(target.package) else {
            failures.push(format!(
                "{}:{} has unknown package layer",
                target.package, target.test_target
            ));
            continue;
        };

        if !standard.layers.contains(&layer) {
            failures.push(format!(
                "{}:{} covers {} from wrong layer {:?}; allowed layers are {:?}",
                target.package, target.test_target, target.gate, layer, standard.layers
            ));
        }

        failures.extend(backend_failures(target, standard));

        if let Some(content) = source_overrides.get(&(target.package, target.test_target)) {
            failures.extend(source_shape_failures(target, standard, content.as_str()));
            failures.extend(flaky_escape_failures(
                target.package,
                target.test_target,
                content.as_str(),
            ));
        }
    }

    for ownership in CRATE_TESTING_OWNERSHIP {
        let actual = gates_by_package
            .get(ownership.package)
            .cloned()
            .unwrap_or_default();
        let expected: BTreeSet<&str> = ownership.gates.iter().copied().collect();

        for required in expected.difference(&actual) {
            failures.push(format!(
                "{} missing crate-owned layer gate {}",
                ownership.package, required
            ));
        }
    }

    for standard in GATE_TESTING_STANDARDS {
        let actual: BTreeSet<&str> = targets_by_gate
            .get(standard.gate)
            .into_iter()
            .flatten()
            .map(|target| target.package)
            .collect();
        let expected: BTreeSet<&str> = standard.owner_packages.iter().copied().collect();

        if actual != expected {
            failures.push(format!(
                "{} owner package mismatch: expected {:?}, found {:?}",
                standard.gate, expected, actual
            ));
        }

        if HASH_COMPARE_GATES.contains(&standard.gate)
            && standard.shape != TestShape::TwiceReduceCompareByHash
        {
            failures.push(format!(
                "{} must use the twice-reduce compare-by-hash shape",
                standard.gate
            ));
        }
    }

    failures
}

pub(super) fn backend_failures(
    target: &GateTargetSpec,
    standard: &GateTestingStandard,
) -> Vec<String> {
    let mut failures = Vec::new();

    if standard.backend == TestBackend::SimDouble
        && matches!(package_layer(target.package), Some(Layer::L2))
    {
        failures.push(format!(
            "{}:{} must use SimDouble/in-process coverage, not an L2 real-QEMU owner",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::RealQemu
        && !matches!(package_layer(target.package), Some(Layer::L2))
    {
        failures.push(format!(
            "{}:{} is a real-QEMU-only gate but is not owned by an L2 crate",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::SimDouble
        && target.package == "crucible"
        && !target.required_features.contains(&"test-double")
    {
        failures.push(format!(
            "{}:{} must run with --features test-double for SimDouble coverage",
            target.package, target.test_target
        ));
    }

    failures
}

pub(super) fn flaky_escape_failures(
    package: &str,
    test_target: &str,
    content: &str,
) -> Vec<String> {
    let lower = scrub_comments_and_strings(content).to_ascii_lowercase();
    FLAKY_ESCAPE_PATTERNS
        .iter()
        .filter(|pattern| {
            if pattern.contains("::") {
                return lower.contains(**pattern);
            }
            lower.match_indices(**pattern).any(|(start, _)| {
                let before = lower[..start].chars().next_back();
                let after = lower[start + pattern.len()..].chars().next();
                before.is_none_or(|character| !character.is_ascii_alphanumeric())
                    && after.is_none_or(|character| !character.is_ascii_alphanumeric())
            })
        })
        .map(|pattern| {
            format!("{package}:{test_target} contains flaky-test escape pattern `{pattern}`")
        })
        .collect()
}

pub(super) fn source_shape_failures(
    target: &GateTargetSpec,
    standard: &GateTestingStandard,
    content: &str,
) -> Vec<String> {
    let code = scrub_comments_and_strings(content);
    let lower = code.to_ascii_lowercase();
    let mut failures = Vec::new();

    if standard.shape == TestShape::TwiceReduceCompareByHash && !code.contains(TWICE_REDUCE_HELPER)
    {
        failures.push(format!(
            "{}:{} must call {TWICE_REDUCE_HELPER} to drive twice and compare canonical digests",
            target.package, target.test_target,
        ));
    }

    if standard.shape == TestShape::ObservedInjectionIcountVectors
        && target.package == "crucible-protocol"
    {
        for required in [
            "RUNTIME_DATA_PLANE_CONTRACT",
            "control_channel_carries_runtime_frames",
            "control_channel_carries_delivery_icounts",
            "control_channel_silent_between_setup_ack_and_quit",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove runtime injection data stays out of the control protocol",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::ObservedInjectionIcountVectors
        && target.package != "crucible-protocol"
    {
        for required in [
            "run_two_vm_injection",
            "struct ObservedInjection",
            "producer_host_tick",
            "assert_eq!(producer_skewed, consumer_skewed);",
            "assert_ne!(producer_skewed, consumer_skewed);",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must compare observed injection icount vectors across host interleavings with a host-timing negative control",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if DUMP_COMPARE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        failures.push(format!(
            "{}:{} must compare canonical digests, not formatted dumps",
            target.package, target.test_target
        ));
    }

    if standard.backend == TestBackend::SimDouble && !code.contains("SimDouble") {
        failures.push(format!(
            "{}:{} must exercise the SimDouble backend",
            target.package, target.test_target
        ));
    }

    if standard.shape == TestShape::CampaignModel {
        for required in [
            "CampaignRepository::new",
            "CampaignLineage::new",
            "assert_eq!(lineage.id()?, reverse_lineage.id()?)",
            "CampaignRepositoryError::Stale",
            "derive_campaign",
            "assert_eq!(rebuilt.snapshot_id(), derived.new_snapshot)",
            "restarted.state",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove canonical identities, stale-command refusal, derivation, and restart through the public campaign repository",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignReplay {
        let required = if target.package == "crucible-campaign" {
            &[
                "CampaignRepository::with_component_authorities",
                "CanonicalFrontierPlanner",
                "restarted_repository",
                "assert_wrong_planner_authority_is_rejected",
                "assert_eq!(reordered.steps, ordered.steps)",
            ][..]
        } else {
            &[
                "env_clear",
                "offline_campaign_replay_consumer",
                "FindingTriageReplayEvidence::from_canonical_bytes",
                "FailureTriageReplayEvidence::from_compact_binary",
                "InvalidExport::MissingEvidence",
                "InvalidExport::CorruptEvidence",
                "InvalidExport::WrongObservedSignature",
            ][..]
        };
        if required.iter().any(|needle| !code.contains(needle)) {
            failures.push(format!(
                "{}:{} must prove every-step strict planner replay or separate-process rich finding reconstruction with fail-closed corruptions",
                target.package, target.test_target,
            ));
        }
    }

    if standard.shape == TestShape::CampaignStatistics {
        for required in [
            "CampaignRepository::with_component_authorities",
            "StatisticalDistribution::new",
            "with_statistical_sampling_design",
            "CanonicalFrontierPlanner",
            "project_statistical_estimate",
            "estimate_event",
            "CampaignRepositoryError::Integrity",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove finite static P/Q support, exact estimation, refusal, and restart through the public campaign repository",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::BranchPointModel {
        for required in [
            "opportunity.branch_point_id(lineage.genesis())",
            "CandidateSource::generated",
            "submit_debugger_branch_request",
            "AttemptAdmissionRole::AdditionalCause",
            "ExplainCampaignAttemptRequest::new",
            "collect_finite_statistical_evidence",
            "assert_eq!(raw_visits.parent_visits(), 3)",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove parent scope, finite/generated convergence, retained causes, authenticated execution basis, restart, and statistical intervention exclusion",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::LazyFrontier {
        for required in [
            "measure_allocations",
            "ContinuationState::Waiting",
            "ContinuationState::Ready",
            "CampaignRepository::with_component_authorities",
            "CampaignMode::Strict",
            "CampaignMode::Streaming",
            "CandidateGeneratorAlgorithm::ProgressiveInteger",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove bounded lazy polling, feedback suspension, cold recovery, and strict/streaming ordering",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::ControlResponsiveness {
        for required in [
            "CampaignClient::new(RepositoryCampaignService::new(",
            "CampaignControlAction::Pause(ActiveAttemptPolicy::Drain)",
            ".get_campaign_status(",
            ".pin_campaign(",
            "const CONTROL_BOUND: Duration = Duration::from_millis(250);",
            "assert_eq!(saturated.active(), 3);",
            "assert_eq!(saturated.queued(), 1);",
            "pool.request_shutdown();",
            "Err(LocalExecutorPoolServiceError::ShuttingDown)",
            "state.cancellations_observed, 2,",
            ".operational_activity_snapshot();",
            "assert!(activity.worker_in_flight);",
            "assert!(activity.cancellation_requested);",
            "assert_eq!(report.active(), 0);",
            "assert_eq!(report.queued(), 0);",
            "assert_eq!(report.executions(), 2,",
            "assert_eq!(report.terminal_stops(), 3);",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove bounded pause, status, pin, shutdown, admission closure, executing cancellation retention, queued draining, and final accounting under saturation",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::WorldForkAtomicity {
        for required in [
            "QemuProductionHotForkWorldLifecycleFactory",
            "production_factory_forks_complete_live_world_atomically",
            "production_factory_exposes_no_world_when_second_real_fork_fails",
            "production_factory_exposes_no_world_when_second_real_adoption_fails",
            "production_factory_keeps_source_private_until_target_cleanup_retries",
            "production_factory_keeps_source_private_across_repository_publication_retry",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove the production real-QEMU atomic-world success, rollback, cleanup-retry, and publication-retry matrix",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignComponentContract {
        for required in [
            "CampaignLoopbackServer::new",
            "serve_loopback_executor_component_connection_with_limits",
            "CampaignClient",
            "ExecutorClient",
            "kill_and_wait",
            "SubmitAttemptDisposition::AlreadyCompleted",
            "ExecutorRejection::Unauthorized",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} is missing `{required}` required to prove direct/loopback equivalence, independent component restart, idempotency, and authority refusal",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignContinuityV2 {
        for required in [
            "fn campaign_continuity_v2_survives_pause_restart_archive_restore_and_resume(",
            "fn continuity_process_helper()",
            "Command::new(std::env::current_exe()",
            ".arg(PROCESS_HELPER)",
            "output.status.success()",
            "DirectoryBlobBackend::new",
            "DirectoryRefBackend::new",
            "CampaignArchivePolicy::Executable",
            "publish_transferred_campaign(",
            "fn authenticate_checkpoint_closure(",
            "query_campaign_graph",
            "query_campaign_frontier",
            "query_campaign_findings",
            "assert_eq!(budget.spent_attempts, 2);",
            "assert_eq!(claimable, vec![initial_attempt]);",
            "assert!(replayed.replayed);",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove public graph/frontier/finding continuity, exact pin and checkpoint authentication, process restart, archive transfer, claim recovery, and single-charge resume accounting",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::AttemptIdempotence {
        for required in [
            "CampaignRepository::new",
            "ExecutorClient::new",
            "SubmitAttemptDisposition::AlreadyRunning",
            "CampaignRepositoryError::RefConflict",
            "publish_observation",
            "project_branch_edge_visits",
            "replayed",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove admission, executor, publication, restart, conflict, and credit idempotence through public seams",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignMutationScaling {
        for required in [
            "const MUTATIONS: u64 = 10_000;",
            "ReadCountingBackend",
            "validation_checkpoint_metrics",
            "has_retained_validation_checkpoint",
            "MAX_INCREMENTAL_READS",
            "MAX_LOCATOR_REPLAY_READS",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must run 10,000 instrumented mutations and prove hot, cold, failure-atomic, deep-closure, and locator bounds",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignStoreEquivalence {
        for required in [
            "assert_blob_leaf_conformance",
            "assert_blob_leaf_conformance_with_durability",
            "assert_ref_leaf_conformance",
            "MemoryBlobBackend",
            "DirectoryBlobBackend",
            "PackedBlobBackend",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must apply one shared immutable/ref semantic suite to every supported local leaf",
                    target.package, target.test_target,
                ));
                break;
            }
        }
    }

    if standard.shape == TestShape::CampaignStoreComposition {
        let required = if target.package == "crucible-cas" {
            &[
                "ALLOWED_LAYER_ORDERS",
                "StoreGraph",
                "PackedBlobBackend",
                "DurabilityRequirement",
            ][..]
        } else {
            &["mod campaign_store_process;"][..]
        };
        if required.iter().any(|needle| !code.contains(needle)) {
            failures.push(format!(
                "{}:{} must exercise its owned store-graph or public-process composition surface",
                target.package, target.test_target,
            ));
        }
    }

    if standard.shape == TestShape::CampaignContinuity {
        for required in [
            "seed_next_run_for_provenance",
            "CampaignContinuitySeedDecision",
            "SeedPriorCorpus",
            "RefuseCrossProvenanceReuse",
            "baseline_event_hash",
            "read_fresh_lineage_baseline_event",
            "seed_next_run(&prior_manifest",
            "accumulated_coverage_delta",
            "compare_and_swap_head",
        ] {
            if !code.contains(required) {
                failures.push(format!(
                    "{}:{} must prove seed replay, coverage monotonicity, and provenance refusal for campaign continuity",
                    target.package, target.test_target
                ));
                break;
            }
        }
    }

    failures
}

pub(super) fn standard_for_gate(gate: &str) -> Option<&'static GateTestingStandard> {
    GATE_TESTING_STANDARDS
        .iter()
        .find(|standard| standard.gate == gate)
}

pub(super) fn package_layer(package: &str) -> Option<Layer> {
    match package {
        "crucible-sim" | "crucible-assert" => Some(Layer::L0),
        "crucible-shmem" | "crucible-protocol" | "crucible-device" => Some(Layer::L1),
        "crucible-qemu" | "crucible-qemu-plugin" | "crucible-guest" | "crucible-linux-resource" => {
            Some(Layer::L2)
        }
        "crucible" | "crucible-cas" | "crucible-campaign" => Some(Layer::L3),
        "crucible-s3-store" | "crucible-session" | "crucible-api" | "crucible-daemon"
        | "crucible-cli" => Some(Layer::L4),
        "crucible-harness" => Some(Layer::CrossCutting),
        _ => None,
    }
}

pub(super) fn testing_standard_regression_failures() -> Vec<String> {
    let synthetic_targets = [
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible-qemu",
            test_target: "gate_replay_oracle",
            required_features: &[],
        },
        GateTargetSpec {
            gate: "gate:unknown",
            package: "crucible-harness",
            test_target: "unknown_gate",
            required_features: &[],
        },
        GateTargetSpec {
            gate: "gate:replay-oracle",
            package: "crucible",
            test_target: "gate_replay_oracle",
            required_features: &["test-double"],
        },
    ];
    let source_overrides = BTreeMap::from([(
        ("crucible", "gate_replay_oracle"),
        r#"
            // assert_twice_reduce_canonical_digest(canonical_digest);
            // SimDouble
            #[test]
            fn bad() {
                assert_twice_reduce_canonical_digest(|| canonical_digest());
                assert_eq!(human_formatted_dump(), human_formatted_dump());
            }
        "#
        .to_string(),
    )]);
    let findings = testing_standard_failures(&synthetic_targets, &source_overrides);
    let mut failures = Vec::new();

    if !findings
        .iter()
        .any(|finding| finding.contains("wrong layer"))
    {
        failures.push(
            "testing-standard regression failed to reject higher/lower layer ownership drift"
                .to_string(),
        );
    }
    if !findings.iter().any(|finding| finding.contains("SimDouble")) {
        failures.push(
            "testing-standard regression failed to reject missing SimDouble ownership".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("no per-layer testing standard"))
    {
        failures
            .push("testing-standard regression failed to reject unknown gate standard".to_string());
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("canonical digests"))
    {
        failures.push(
            "testing-standard regression failed to reject non-hash determinism assertions"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("SimDouble backend"))
    {
        failures.push(
            "testing-standard regression failed to reject missing SimDouble body coverage"
                .to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("crucible-qemu missing crate-owned layer gate"))
    {
        failures.push(
            "testing-standard regression failed to reject missing per-crate ownership".to_string(),
        );
    }

    failures
}

pub(super) fn testing_source_regression_failures() -> Vec<String> {
    let mut failures = Vec::new();
    let findings = flaky_escape_failures(
        "crucible",
        "gate_replay_oracle",
        r#"
            #[test]
            fn bad() {
                retry_until_not_flaky("rerun is forbidden"); // Comments may discuss retry and flaky rejection.
            }
        "#,
    );

    if findings.len() != 2 {
        failures
            .push("testing-standard regression failed to reject flaky/retry escapes".to_string());
    }

    let native_scenario_target = "src/qemu_hot_fork_world_factory/tests/native_acceptance/scenario";
    let modeled_retry = flaky_escape_failures(
        "crucible-daemon",
        native_scenario_target,
        "let retry_domain = modeled_guest_choice();",
    );
    let semantic_baseline = TestingStandardsBaseline {
        caps: BTreeMap::from([(
            TestingStandardsBaselineKey {
                package: "crucible-daemon".to_string(),
                test_target: native_scenario_target.to_string(),
                pattern: "retry".to_string(),
            },
            1,
        )]),
    };
    if !semantic_baseline
        .filter_flaky_findings(modeled_retry)
        .is_empty()
    {
        failures.push(
            "testing-standard regression rejected the scoped modeled-retry baseline".to_string(),
        );
    }

    let unrelated_retry =
        flaky_escape_failures("crucible-daemon", "tests/unrelated", "retry_failed_test();");
    if !semantic_baseline
        .filter_flaky_findings(unrelated_retry)
        .iter()
        .any(|finding| finding.starts_with("crucible-daemon:tests/unrelated "))
    {
        failures.push(
            "testing-standard regression allowed retry behavior outside its exact baseline target"
                .to_string(),
        );
    }

    failures
}

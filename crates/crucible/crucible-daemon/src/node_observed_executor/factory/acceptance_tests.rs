//! Checks source-selected classes and actual preallocation refusal in the factory.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These factory admission controls deliberately panic when exact source selection or no-allocation invariants fail.
#![allow(clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
    time::Duration,
};

use crate::node_scenario::NodeRunConfiguration;
use crucible_campaign::ExecutionId;
use crucible_node_format::{Continuation, Id};
use crucible_store::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use super::super::{InstalledNodeKind, InstalledNodeSelection, measure_executable};
use super::*;

struct MissingInstalledReport(Arc<AtomicUsize>);

impl InstalledAcceptancePolicy for MissingInstalledReport {
    fn scope_for_node(&self, _: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(QualificationError::Refused(
            "no complete original installed behavioral report",
        ))
    }
}

impl InstalledQualificationAuthority for MissingInstalledReport {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &crate::node_qualification::QualificationClaim,
    ) -> Result<(), QualificationError> {
        panic!("missing scope must refuse before original evidence authentication")
    }

    fn applicability(
        &self,
        _: &QualificationUnit,
        _: &BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        panic!("missing scope cannot select applicability")
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        panic!("missing scope cannot fetch evidence")
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        panic!("missing scope cannot authenticate a native case")
    }
}

fn selected_clock() -> Vec<InstalledNodeSelection> {
    vec![InstalledNodeSelection {
        node: Id::new("clock").unwrap(),
        owner: Id::new("clock-owner").unwrap(),
        kind: InstalledNodeKind::HostClock,
    }]
}

fn catalog(directory: &std::path::Path) -> InstalledNodeCatalog {
    // No device child is started by these Clock fixtures. The actual installed
    // source-built executable measurement is still required by the catalog.
    let device = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    InstalledNodeCatalog::new(
        device.clone(),
        measure_executable(&device).unwrap(),
        directory.to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap()
}

#[test]
fn installed_missing_acceptance_refuses_actual_ordinary_preparation_before_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = selected_clock();
    let scenario = catalog.scenario(&selections).unwrap();
    let original_bytes = scenario.canonical_bytes().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    catalog
        .install_behavioral_acceptance(
            Box::new(MissingInstalledReport(Arc::clone(&calls))),
            AcceptanceLimits::default(),
        )
        .unwrap();

    let result = catalog.prepare(
        &selections,
        scenario,
        NodeRunConfiguration {
            format: "crucible.node-run-configuration".into(),
            version: 1,
            horizon_ps: crucible_node_format::U64::new(10),
            maximum_rounds: crucible_node_format::U64::new(32),
        },
        ExecutionId::from_bytes([101; 16]).unwrap(),
        Arc::new(DirectoryBlobBackend::new(
            "acceptance",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    );

    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    // A selected but unavailable normal policy cannot describe a different
    // baseline as its accepted ordinary world. Preparation above still refused
    // before acquiring any native world custody.
    assert!(catalog.scenario(&selections).is_err());
    assert!(!original_bytes.is_empty());
    assert!(
        catalog
            .install_behavioral_acceptance(
                Box::new(MissingInstalledReport(Arc::clone(&calls))),
                AcceptanceLimits::default(),
            )
            .is_err()
    );
}

#[test]
fn unselected_original_host_factory_keeps_literal_scenario_and_native_admission() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = selected_clock();
    let scenario = catalog.scenario(&selections).unwrap();
    let original_bytes = scenario.canonical_bytes().unwrap();

    let original = catalog
        .prepare_world(
            &selections,
            scenario,
            ExecutionId::from_bytes([102; 16]).unwrap(),
        )
        .unwrap();

    assert_eq!(original.scenario.canonical_bytes().unwrap(), original_bytes);
    assert!(original.graph.binding(&Id::new("clock").unwrap()).is_some());
    assert_eq!(catalog.custody().reserved_worlds(), 1);
    drop(original);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..8 {
        let _ = catalog.custody().clone().poll_reclamation(&mut context);
        if catalog.custody().reserved_worlds() == 0 {
            break;
        }
    }
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[test]
fn required_classes_follow_each_actual_source_guarantee_axis_without_conflation() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = catalog(directory.path());
    let mut scenario = catalog.scenario(&selected_clock()).unwrap();
    let mut binding = scenario.compatibility[0].clone();
    let reference = binding.guarantees_ref.clone();
    let entry = scenario
        .content
        .iter()
        .find(|entry| entry.reference == reference)
        .unwrap();
    let mut guarantee: GuaranteeProfile = serde_json::from_slice(&entry.bytes).unwrap();
    guarantee.repeatability = Repeatability::Nondeterministic;
    guarantee.capture_scope = CaptureScope::None;
    guarantee.continuation = Continuation::Unsupported;
    guarantee.durable_restart = false;
    guarantee.isolated_fork = false;
    guarantee.conditional_replay = false;

    for (scope, class) in [
        (CaptureScope::None, None),
        (
            CaptureScope::Architectural,
            Some(QualificationClass::CaptureArchitectural),
        ),
        (
            CaptureScope::CompleteModel,
            Some(QualificationClass::CaptureModeledLive),
        ),
    ] {
        guarantee.capture_scope = scope;
        let bytes = canonical::canonical_json(&serde_json::to_value(&guarantee).unwrap()).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        binding.guarantees_ref = reference.clone();
        scenario
            .content
            .push(crate::node_scenario::ScenarioContent { reference, bytes });
        let mut expected = BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::RoleProfile,
            QualificationClass::ExactTiming,
        ]);
        if let Some(class) = class {
            expected.insert(class);
        }
        assert_eq!(required_classes(&scenario, &binding).unwrap(), expected);
    }

    guarantee.repeatability = Repeatability::Qualified;
    guarantee.durable_restart = true;
    guarantee.isolated_fork = true;
    guarantee.conditional_replay = true;
    let bytes = canonical::canonical_json(&serde_json::to_value(&guarantee).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    binding.guarantees_ref = reference.clone();
    binding.operating_contract.mode = OperatingMode::Quantized;
    scenario
        .content
        .push(crate::node_scenario::ScenarioContent { reference, bytes });
    let classes = required_classes(&scenario, &binding).unwrap();
    assert_eq!(classes.len(), 8);
    assert!(classes.contains(&QualificationClass::QuantizedTiming));
    assert!(!classes.contains(&QualificationClass::ExactTiming));
    for class in [
        QualificationClass::Repeatable,
        QualificationClass::CaptureModeledLive,
        QualificationClass::CaptureModeledDurable,
        QualificationClass::BranchIsolated,
        QualificationClass::ConditionalReplay,
    ] {
        assert!(classes.contains(&class));
    }
}

#[test]
fn malformed_installed_guarantees_refuse_before_original_policy_callbacks() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = catalog(directory.path());
    let mut scenario = catalog.scenario(&selected_clock()).unwrap();
    let binding = &scenario.compatibility[0];
    let reference = binding.guarantees_ref.clone();
    let entry = scenario
        .content
        .iter_mut()
        .find(|entry| entry.reference == reference)
        .unwrap();
    entry.bytes[0] ^= 1;

    assert!(required_classes(&scenario, &scenario.compatibility[0]).is_err());
}

struct ForgedInstalledScope {
    binding: BindingCompatibility,
    required: BTreeSet<QualificationClass>,
    original_bytes: Vec<u8>,
    original_ref: ContentRef,
    record: crate::node_qualification::AcceptanceRecord,
}

impl ForgedInstalledScope {
    fn new(scenario: &NodeScenario) -> Self {
        let binding = scenario.compatibility[0].clone();
        let reference = binding.qualification_refs[0].clone();
        let unit = QualificationUnit {
            implementation: reference.clone(),
            realization: reference.clone(),
            descriptors: reference.clone(),
            contracts: reference.clone(),
            port_profiles: reference.clone(),
            environment: reference.clone(),
            harness: reference.clone(),
            fixtures: reference.clone(),
            specification: reference.clone(),
        };
        let required = required_classes(scenario, &binding).unwrap();
        let original = crate::node_qualification::QualificationClaim {
            format: "crucible.node-qualification".into(),
            version: 1,
            unit: unit.clone(),
            classes: required.clone(),
            catalog: reference.clone(),
            applicability_policy: reference.clone(),
            requirements: vec![],
            supersedes: None,
            limitations: reference.clone(),
        };
        let original_bytes =
            canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
        Self {
            binding,
            required: required.clone(),
            original_bytes,
            original_ref: reference.clone(),
            record: crate::node_qualification::AcceptanceRecord {
                format: "crucible.node-acceptance".into(),
                version: 1,
                original_claim: reference,
                original,
                evaluated_unit: unit,
                required_classes: required,
                missing_requirements: BTreeSet::new(),
                decision: crate::node_qualification::AcceptanceDecision::Accepted,
            },
        }
    }
}

impl InstalledAcceptancePolicy for ForgedInstalledScope {
    fn scope_for_node(&self, _: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        Ok(AcceptanceScope {
            binding: &self.binding,
            current_unit: self.record.evaluated_unit.clone(),
            required_classes: self.required.clone(),
            original_bytes: &self.original_bytes,
            original_claim: &self.original_ref,
            record: &self.record,
        })
    }
}

impl InstalledQualificationAuthority for ForgedInstalledScope {
    fn authenticate_claim(
        &self,
        _: &ContentRef,
        _: &[u8],
        _: &crate::node_qualification::QualificationClaim,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "forged records are not installed originals",
        ))
    }

    fn applicability(
        &self,
        _: &QualificationUnit,
        _: &BTreeSet<QualificationClass>,
        _: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        Err(QualificationError::Refused(
            "no independently installed original applicability",
        ))
    }

    fn verify_evidence(
        &self,
        _: &ContentRef,
        _: u64,
        _: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        Err(QualificationError::Refused("no original evidence custody"))
    }

    fn authenticate_case(
        &self,
        _: &QualificationUnit,
        _: &str,
        _: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "no actual original native case",
        ))
    }
}

#[test]
fn actual_factory_rejects_reduced_classes_changed_binding_and_forged_accepted_data() {
    for change in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let mut catalog = catalog(directory.path());
        let selections = selected_clock();
        let scenario = catalog.scenario(&selections).unwrap();
        let mut policy = ForgedInstalledScope::new(&scenario);
        match change {
            0 => {
                policy.required.remove(&QualificationClass::ExactTiming);
            }
            1 => {
                policy.binding.implementation.implementation_id =
                    Id::new("wrong-implementation").unwrap();
            }
            _ => {}
        }
        catalog
            .install_behavioral_acceptance(Box::new(policy), AcceptanceLimits::default())
            .unwrap();

        let refused = catalog.prepare_world(
            &selections,
            scenario,
            ExecutionId::from_bytes([103; 16]).unwrap(),
        );

        assert!(refused.is_err());
        assert_eq!(catalog.custody().reserved_worlds(), 0);
    }
}

#[test]
fn installed_behavioral_mode_cannot_bypass_the_gate_via_specialized_native_selection() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let calls = Arc::new(AtomicUsize::new(0));
    catalog
        .install_behavioral_acceptance(
            Box::new(MissingInstalledReport(Arc::clone(&calls))),
            AcceptanceLimits::default(),
        )
        .unwrap();

    assert!(catalog.require_behavioral_host_scope().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}

#[test]
fn missing_policy_cannot_turn_closed_selection_into_a_general_vendor_or_wider_class() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = selected_clock();
    let original = catalog.scenario(&selections).unwrap();
    assert!(catalog.behavioral_acceptance.is_none());

    // The actual ordinary factory must authenticate the complete installed
    // binding before optional-mode lookup. A claimed wider report/class is not
    // a source-selected profile, even if no behavioral policy was installed.
    for (index, change_model) in [true, false].into_iter().enumerate() {
        let mut vendor = original.clone();
        if change_model {
            vendor.compatibility[0].profile_ref =
                canonical::content_ref(b"vendor-general-compute-v1", "application/json").unwrap();
        } else {
            let old = vendor.compatibility[0].guarantees_ref.clone();
            let entry = vendor
                .content
                .iter()
                .find(|entry| entry.reference == old)
                .unwrap();
            let mut guarantee: GuaranteeProfile = serde_json::from_slice(&entry.bytes).unwrap();
            guarantee.conditional_replay = true;
            let bytes =
                canonical::canonical_json(&serde_json::to_value(guarantee).unwrap()).unwrap();
            let reference = canonical::content_ref(&bytes, "application/json").unwrap();
            vendor.compatibility[0].guarantees_ref = reference.clone();
            vendor
                .content
                .push(crate::node_scenario::ScenarioContent { reference, bytes });
        }

        assert!(
            catalog
                .prepare_world(
                    &selections,
                    vendor,
                    ExecutionId::from_bytes([110 + index as u8; 16]).unwrap(),
                )
                .is_err()
        );
        assert_eq!(catalog.custody().reserved_worlds(), 0);
    }

    // No general/vendor native constructor exists in the current catalog. Its
    // portable selector cannot request the exemption by claiming a class name.
    assert!(
        serde_json::from_slice::<InstalledNodeKind>(
            br#"{"implementation":"vendor_general","classes":["base_provider","exact_timing"]}"#,
        )
        .is_err()
    );
    assert_eq!(
        catalog
            .scenario(&selections)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        original.canonical_bytes().unwrap()
    );
}

#[test]
fn missing_mixed_clock_checksum_acceptance_refuses_before_native_world_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = vec![
        InstalledNodeSelection {
            node: Id::new("checksum").unwrap(),
            owner: Id::new("owner/checksum").unwrap(),
            kind: InstalledNodeKind::ReferenceDevice {
                quantum_ps: 1000.into(),
                host_budget_ns: 1_000_000.into(),
            },
        },
        InstalledNodeSelection {
            node: Id::new("clock").unwrap(),
            owner: Id::new("owner/clock").unwrap(),
            kind: InstalledNodeKind::HostClock,
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    catalog
        .install_behavioral_acceptance(
            Box::new(MissingInstalledReport(Arc::clone(&calls))),
            AcceptanceLimits::default(),
        )
        .unwrap();
    assert!(catalog.scenario(&selections).is_err());
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert!(
        catalog
            .prepare_world(
                &selections,
                scenario,
                ExecutionId::from_bytes([117; 16]).unwrap()
            )
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
#[ignore = "requires genuine source-built native artifacts and externally admitted finite CPU/AS/FD limits plus a private quota-enforced CRUCIBLE_CLOCK_PROJECT_ROOT"]
fn original_clock_failure_population_enrolls_then_refuses_missing_second_checksum_before_reservation()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::node_observed_executor::{NormalClockProgramme, OriginalClockAggregateResources};
    use crate::node_qualification::{AcceptanceDecision, CaseVerdict, InstalledAcceptancePolicy};
    use crucible_node_format::ResourceLimits;
    use std::{path::PathBuf, rc::Rc};

    // This test never lowers or fabricates a quota. The invoking qualification
    // process must already own the real finite policy and private ext4 project.
    let root = PathBuf::from(std::env::var("CRUCIBLE_CLOCK_PROJECT_ROOT")?);
    let limits: ResourceLimits = serde_json::from_slice(&std::fs::read(std::env::var(
        "CRUCIBLE_CLOCK_AGGREGATE_LIMITS",
    )?)?)?;
    let project_id = std::env::var("CRUCIBLE_CLOCK_PROJECT_ID")?.parse()?;
    let maximum_inodes = std::env::var("CRUCIBLE_CLOCK_MAXIMUM_INODES")?.parse()?;
    let mut aggregate = None;
    OriginalClockAggregateResources::bind_current_into(
        &mut aggregate,
        &limits,
        &root,
        project_id,
        maximum_inodes,
    )?;
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE")?);
    let mut catalog = InstalledNodeCatalog::new_with_bounded_runtime_wake(
        executable.clone(),
        measure_executable(&executable)?,
        root.join("normal-enrollment-original"),
        Duration::from_secs(5),
        4,
    )?;
    let mut programme = NormalClockProgramme::new(&catalog, ExecutionId::from_bytes([131; 16])?)?;
    programme.prepare_original_bounded(
        &mut catalog,
        aggregate.take().ok_or("actual aggregate absent")?,
    )?;
    programme.prepare_original_state_bounded(
        &catalog,
        [
            ExecutionId::from_bytes([132; 16])?,
            ExecutionId::from_bytes([133; 16])?,
        ],
    )?;

    // The same actual Source/runner now owns exact timing, two fresh restores,
    // two independent failed publications and all four signed-index refusals.
    // Any missing prerequisite is a test failure, never a modeled Accepted row.
    programme.execute_normal_enrollment(
        &mut catalog,
        [
            ExecutionId::from_bytes([134; 16])?,
            ExecutionId::from_bytes([135; 16])?,
        ],
        [
            ExecutionId::from_bytes([136; 16])?,
            ExecutionId::from_bytes([137; 16])?,
        ],
    )?;
    let accepted = Rc::clone(
        programme
            .normal_acceptance_data()?
            .ok_or("genuine Clock enrollment absent")?,
    );
    let originals = accepted.originals()?;
    for name in [
        "clock/failed-publication-before-commit",
        "clock/failed-publication-after-commit",
        "clock/damaged-restoration-refusals",
    ] {
        let observation = originals
            .clock_adverse_observations
            .get(name)
            .ok_or("actual failure original absent")?;
        assert_eq!(observation.verdict(), Some(CaseVerdict::Passed));
        observation.reference().verify(observation.bytes())?;
    }
    let clock = InstalledNodeSelection {
        node: Id::new("clock")?,
        owner: Id::new("owner/clock")?,
        kind: InstalledNodeKind::HostClock,
    };
    let checksum = InstalledNodeSelection {
        node: Id::new("checksum")?,
        owner: Id::new("owner/checksum")?,
        kind: InstalledNodeKind::ReferenceDevice {
            quantum_ps: 1000.into(),
            host_budget_ns: 1_000_000.into(),
        },
    };
    let mixed = [clock.clone(), checksum];
    let raw_mixed = catalog.scenario(&mixed)?;
    let raw_clock = programme.profile_data().scenario().clone();
    let scope = accepted.scope_for_node(&clock.node)?;
    assert_eq!(scope.record.decision, AcceptanceDecision::Accepted);
    assert!(accepted.scope_for_node(&mixed[1].node).is_err());
    let original_report = scope.original_claim.clone();
    let original_bytes = scope.original_bytes.to_vec();
    catalog.install_shared_behavioral_acceptance(accepted.clone(), AcceptanceLimits::default())?;

    // A real single-Clock transformation must succeed first: this rules out
    // satisfying the mixed negative by refusing the accepted first participant.
    let ordinary = catalog.scenario(std::slice::from_ref(&clock))?;
    assert_eq!(
        ordinary.compatibility[0],
        *accepted.scope_for_node(&clock.node)?.binding
    );
    assert_eq!(ordinary.descriptors, raw_clock.descriptors);
    assert!(
        ordinary.compatibility[0]
            .qualification_refs
            .contains(&original_report)
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert!(catalog.scenario(&mixed).is_err());
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert!(
        catalog
            .prepare_world(&mixed, raw_mixed, ExecutionId::from_bytes([138; 16])?)
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(
        accepted.scope_for_node(&clock.node)?.original_bytes,
        original_bytes
    );
    programme.normal_acceptance_data()?;

    // Withdrawal of that same genuine owner cannot fall back to baseline Clock.
    accepted.revoke();
    assert!(catalog.scenario(std::slice::from_ref(&clock)).is_err());
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    Ok(())
}

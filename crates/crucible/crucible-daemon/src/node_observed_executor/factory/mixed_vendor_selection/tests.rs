//! Checks complete definition routing without qualifying or creating native peers.
//!
//! Installed manifest inspectors are test models. Canonical scenario generation,
//! registry partition checks and catalog dispatch are production code; the model
//! deliberately supplies no behavioral, live-source or readiness authority.

// crucible-lint: allow panic-shortcut -- These native-free controls deliberately fail on changed selection, scope or prebirth dispatch behavior.
#![allow(clippy::unwrap_used)]

use std::{cell::Cell, panic::AssertUnwindSafe, time::Duration};

use crucible_engine::{
    node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim},
    node_contract::{
        InstalledProviderBehavioral, InstalledProviderRegistry, InstalledProviderSource,
        InstalledProviderWorldSource, NodeProvider, OwnerIdentity, PreparedRealization,
        ProviderWorldAuthorizationScope, RealizationFailure, RealizationRequest,
    },
};
use crucible_node_format::{
    Extensions, ImplementationIdentity, IncarnationId, NodeBinding, Phase, Position,
    ProviderManifest, SchemaRef, U64,
};
use crucible_node_transport::reference_service::ReferenceProfile;

use super::*;
use crate::node_observed_executor::factory::measure_executable;

struct ManifestInspector {
    manifest: ProviderManifest,
    calls: Cell<usize>,
    unwind: Cell<bool>,
}

fn no_authority() -> EvidenceError {
    EvidenceError {
        message: "test inspector has no native or behavioral authority".into(),
    }
}

impl AdmissionEvidence for ManifestInspector {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(no_authority())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if implementation == &self.manifest.implementation {
            Ok(())
        } else {
            Err(no_authority())
        }
    }

    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(no_authority())
    }

    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(no_authority())
    }

    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        Err(no_authority())
    }
}

impl InstalledProviderSource for ManifestInspector {
    fn authenticate_provider(&self, manifest: &ProviderManifest) -> Result<(), EvidenceError> {
        self.calls.set(self.calls.get() + 1);
        assert!(!self.unwind.get(), "authored inspector unwind");
        if manifest == &self.manifest {
            Ok(())
        } else {
            Err(no_authority())
        }
    }

    fn authenticate_plan(
        &self,
        _: &ProviderManifest,
        _: ProviderPlanningRequest<'_>,
        _: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        Err(no_authority())
    }

    fn authenticate_prepared(
        &self,
        _: &ProviderManifest,
        _: &ProviderPreparationPlan,
        _: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        Err(no_authority())
    }
}

impl InstalledProviderBehavioral for ManifestInspector {}

impl InstalledProviderWorldSource for ManifestInspector {
    fn authenticate_world_plan(
        &self,
        _: &ProviderWorldAuthorizationScope,
        _: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        Err(no_authority())
    }
}

struct UnpreparedProvider(ProviderManifest);

impl NodeProvider for UnpreparedProvider {
    fn describe(&self) -> &ProviderManifest {
        &self.0
    }

    fn plan(
        &self,
        _: ProviderPlanningRequest<'_>,
    ) -> Result<ProviderPreparationPlan, RealizationFailure> {
        Err(RealizationFailure {
            reason: "test provider has no authenticated preparation".into(),
            retained: None,
        })
    }

    fn prepare(
        &mut self,
        _: RealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        panic!("native preparation must not be reached by definition controls")
    }
}

struct Fixture {
    catalog: InstalledNodeCatalog,
    directory: tempfile::TempDir,
    inspectors: Vec<Rc<ManifestInspector>>,
}

fn fixture(world_source: bool) -> (Fixture, InstalledMixedVendorWorldRequest) {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let identity = measure_executable(&executable).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable,
        identity,
        directory.path().to_path_buf(),
        Duration::from_secs(1),
        1,
    )
    .unwrap();
    let legacy: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|name| InstalledNodeSelection {
            node: Id::new(name).unwrap(),
            owner: Id::new(format!("owner/{name}")).unwrap(),
            kind: InstalledNodeKind::ReferenceDevice {
                quantum_ps: U64::new(100),
                host_budget_ns: U64::new(1_000_000),
            },
        })
        .collect();
    let scenario = catalog.scenario(&legacy).unwrap();
    let resources = ResourceLimits {
        cpu_budget_ns: U64::new(1_000_000),
        memory_bytes: U64::new(1024 * 1024),
        writable_bytes: U64::new(1024),
        processes: U64::new(1),
        descriptors: U64::new(8),
        pending_events: U64::new(1),
        content_bytes: U64::new(1024),
        maximum_operations: U64::new(1),
        extensions: Extensions::new(),
    };
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let mut inspectors = Vec::new();
    let mut selections = Vec::new();
    let mut contributions = Vec::new();
    for (index, selected) in legacy.iter().enumerate() {
        let profile = ReferenceProfile::build_closed(
            selected.node.clone(),
            selected.owner.clone(),
            catalog.host_identity.clone(),
            catalog.device_identity.clone(),
            U64::new(100),
            U64::new(1_000_000),
        )
        .unwrap();
        let mut manifest = profile.provider_manifest;
        manifest.provider_id = Id::new(format!("provider/{}", selected.node.as_str())).unwrap();
        assert_eq!(
            manifest.implementation,
            scenario.compatibility[index].implementation
        );
        let inspector = Rc::new(ManifestInspector {
            manifest: manifest.clone(),
            calls: Cell::new(0),
            unwind: Cell::new(false),
        });
        registry
            .install(
                &manifest,
                Box::new(UnpreparedProvider(manifest.clone())),
                inspector.clone(),
                inspector.clone(),
            )
            .unwrap();
        selections.push(InstalledNodeSelection {
            node: selected.node.clone(),
            owner: selected.owner.clone(),
            kind: InstalledNodeKind::InstalledVendor {
                provider: manifest.provider_id.clone(),
                profile: profile.node_manifest.profile_id.clone(),
                configuration: profile.configuration_ref.clone(),
            },
        });
        contributions.push(InstalledVendorContribution {
            provider: manifest.provider_id,
            profile: profile.node_manifest.profile_id,
            configuration: profile.configuration_ref,
            nodes: vec![selected.node.clone()],
            resources: resources.clone(),
            plan: ProviderPreparationPlan {
                descriptors: vec![scenario.descriptors[index].clone()],
                bindings: vec![scenario.compatibility[index].clone()],
            },
        });
        inspectors.push(inspector);
    }
    if world_source {
        registry
            .install_world_source(inspectors[0].clone())
            .unwrap();
    }
    catalog.install_vendor_providers(registry).unwrap();
    let activation = ActivationRecord {
        generation: U64::new(1),
        activation_id: Id::new("mixed-definition").unwrap(),
        world_binding_hash: scenario.world.identity().unwrap(),
        owners: scenario
            .owners
            .iter()
            .enumerate()
            .map(|(index, owner)| OwnerIdentity {
                owner: owner.owner.id.clone(),
                incarnation: IncarnationId::new(format!("instance-{index}")).unwrap(),
                generation: U64::new(1),
            })
            .collect(),
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let fixture = Fixture {
        catalog,
        directory,
        inspectors,
    };
    let request = InstalledMixedVendorWorldRequest {
        selections,
        contributions,
        scenario,
        execution: ExecutionId::from_bytes([181; 16]).unwrap(),
        activation,
        runtime_limits: RuntimeLimits::default(),
    };
    (fixture, request)
}

fn assert_no_native(fixture: &Fixture) {
    assert_eq!(fixture.catalog.custody().reserved_worlds(), 0);
    assert_eq!(
        std::fs::read_dir(fixture.directory.path()).unwrap().count(),
        0
    );
}

#[test]
fn complete_definition_resolves_exactly_and_portable_data_cannot_change_it() {
    let (
        Fixture {
            mut catalog,
            directory,
            inspectors: _,
        },
        request,
    ) = fixture(true);
    let selections = request.selections.clone();
    let expected = request.scenario.canonical_bytes().unwrap();
    catalog.install_mixed_vendor_world(request).unwrap();

    let (_, duplicate) = fixture(true);
    let error = catalog.install_mixed_vendor_world(duplicate).err().unwrap();
    assert!(error.to_string().contains("definition cannot be replaced"));
    assert_eq!(catalog.mixed_vendor_worlds.len(), 1);

    assert_eq!(
        catalog
            .scenario(&selections)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        expected
    );
    let bytes = serde_json::to_vec(&selections).unwrap();
    let decoded: Vec<InstalledNodeSelection> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        catalog
            .scenario(&decoded)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        expected
    );

    let mut foreign = selections.clone();
    foreign[1].owner = Id::new("foreign-owner").unwrap();
    assert!(catalog.scenario(&foreign).is_err());
    let mut reordered = selections;
    reordered.reverse();
    assert!(catalog.scenario(&reordered).is_err());
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn complete_definition_preparation_uses_common_class_gate_and_exact_execution() {
    let (
        Fixture {
            mut catalog,
            directory,
            inspectors: _,
        },
        request,
    ) = fixture(true);
    let selections = request.selections.clone();
    let scenario = request.scenario.clone();
    let execution = request.execution;
    catalog.install_mixed_vendor_world(request).unwrap();

    let changed = catalog
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([182; 16]).unwrap(),
        )
        .err()
        .unwrap();
    assert!(
        changed
            .to_string()
            .contains("mixed vendor execution or complete scenario differs")
    );
    let mut changed_scenario = scenario.clone();
    changed_scenario.requirements.deterministic = !changed_scenario.requirements.deterministic;
    assert_ne!(
        changed_scenario.canonical_bytes().unwrap(),
        scenario.canonical_bytes().unwrap()
    );
    let changed = catalog
        .prepare_world(&selections, changed_scenario, execution)
        .err()
        .unwrap();
    assert!(
        changed
            .to_string()
            .contains("mixed vendor execution or complete scenario differs")
    );

    let refusal = catalog
        .prepare_world(&selections, scenario, execution)
        .err()
        .unwrap();
    assert!(refusal.to_string().contains("normal behavioral acceptance"));
    assert_eq!(catalog.custody().reserved_worlds(), 0);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn missing_world_source_refuses_definition_without_retaining_or_creating_resources() {
    let (mut fixture, request) = fixture(false);
    let selections = request.selections.clone();
    let error = fixture
        .catalog
        .install_mixed_vendor_world(request)
        .err()
        .unwrap();

    assert!(
        error
            .to_string()
            .contains("mixed world source not installed")
    );
    assert!(fixture.catalog.mixed_vendor_worlds.is_empty());
    assert!(fixture.catalog.scenario(&selections).is_err());
    assert_no_native(&fixture);
}

#[test]
fn foreign_partition_or_owner_refuses_before_source_callback() {
    let (mut foreign, mut request) = fixture(true);
    let calls: Vec<_> = foreign
        .inspectors
        .iter()
        .map(|source| source.calls.get())
        .collect();
    request.contributions[1].provider = Id::new("foreign/provider").unwrap();
    let error = foreign
        .catalog
        .install_mixed_vendor_world(request)
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("contribution and portable selector differ")
    );
    assert_eq!(
        foreign
            .inspectors
            .iter()
            .map(|source| source.calls.get())
            .collect::<Vec<_>>(),
        calls
    );
    assert!(foreign.catalog.mixed_vendor_worlds.is_empty());
    assert_no_native(&foreign);

    let (mut owner, mut request) = fixture(true);
    request.selections[1].owner = Id::new("foreign-owner").unwrap();
    let error = owner
        .catalog
        .install_mixed_vendor_world(request)
        .err()
        .unwrap();
    assert!(error.to_string().contains("complete node ownership"));
    assert!(owner.catalog.mixed_vendor_worlds.is_empty());
    assert_no_native(&owner);
}

#[test]
fn malformed_local_plan_and_inspector_unwind_leave_definition_table_unchanged() {
    let (mut changed, mut request) = fixture(true);
    request.contributions[1].plan.bindings[0].configuration_ref =
        crucible_node_format::canonical::content_ref(b"foreign configuration", "text/plain")
            .unwrap();
    assert!(changed.catalog.install_mixed_vendor_world(request).is_err());
    assert!(changed.catalog.mixed_vendor_worlds.is_empty());
    assert_no_native(&changed);

    let (mut unwinding, request) = fixture(true);
    unwinding.inspectors[1].unwind.set(true);
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        unwinding.catalog.install_mixed_vendor_world(request)
    }));
    assert!(outcome.is_err());
    assert!(unwinding.catalog.mixed_vendor_worlds.is_empty());
    assert_no_native(&unwinding);
}

#[test]
fn serialized_credit_refuses_without_underflow_and_selection_nodes_are_unique() {
    let mut credit = MetadataCredit(4);
    credit.consume(&1234u32).unwrap();
    assert_eq!(credit.0, 0);
    assert!(credit.consume(&0u32).is_err());
    assert_eq!(credit.0, 0);

    let (fixture, mut request) = fixture(true);
    request.selections[1].node = request.selections[0].node.clone();
    assert!(selection_key(&request.selections).is_err());
    assert_no_native(&fixture);
}

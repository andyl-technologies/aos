//! Exercises registry authorization and custody without native allocation.

// crucible-lint: allow panic-shortcut -- Inert registry fixtures deliberately panic on malformed test records.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_contract::{
    InstalledProviderRevision, OwnerIdentity, ProviderAuthorityKind, RealizationRequest,
    RuntimeCustodySlot, WholeRuntimeCustody,
};
use crucible_node_contract::{
    Extensions, ImplementationIdentity, LiveAuthority, NodeBinding, Phase, Position, SchemaRef,
    U64, canonical,
};
use crucible_node_provider::reference_service::ReferenceProfile;
use std::{cell::Cell, rc::Rc};

struct Evidence {
    manifest: ProviderManifest,
    reject_source: bool,
    reject_claim: bool,
    current: Option<Rc<Cell<bool>>>,
    revoke: Option<Rc<Cell<bool>>>,
    revisions: [Option<Rc<InstalledProviderRevision>>; 3],
    revoke_class_on_source_lease: bool,
    accept_prepared: bool,
    revoke_on_prepared: Option<Rc<InstalledProviderRevision>>,
}

impl AdmissionEvidence for Evidence {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(refused("no content requested in this model"))
    }
    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if implementation == &self.manifest.implementation {
            Ok(())
        } else {
            Err(refused("foreign implementation"))
        }
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(refused("no native authority in this model"))
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(refused("no installed native schema in this model"))
    }
    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        if let Some(current) = &self.revoke {
            current.set(false);
        }
        if self.reject_claim || self.current.as_ref().is_some_and(|current| !current.get()) {
            Err(refused("independent ordinary acceptance absent"))
        } else {
            Ok(())
        }
    }
}

impl InstalledProviderSource for Evidence {
    fn current_source_revision(
        &self,
        _: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        if self.revoke_class_on_source_lease
            && let Some(revision) = &self.revisions[2]
        {
            revision.revoke();
        }
        self.revisions[0]
            .as_ref()
            .map(|revision| revision.lease())
            .ok_or_else(|| refused("inert source revision absent"))
    }

    fn authenticate_provider(&self, manifest: &ProviderManifest) -> Result<(), EvidenceError> {
        if self.reject_source
            || self.current.as_ref().is_some_and(|current| !current.get())
            || manifest != &self.manifest
        {
            Err(refused("source installation absent or changed"))
        } else {
            Ok(())
        }
    }
    fn authenticate_plan(
        &self,
        _: &ProviderManifest,
        _: ProviderPlanningRequest<'_>,
        _: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn authenticate_prepared(
        &self,
        _: &ProviderManifest,
        _: &ProviderPreparationPlan,
        _: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        if let Some(revision) = &self.revoke_on_prepared {
            revision.revoke();
        }
        if self.accept_prepared {
            Ok(())
        } else {
            Err(refused("this model supplies no native realization"))
        }
    }
}

impl InstalledProviderBehavioral for Evidence {
    fn current_behavioral_revision(
        &self,
        _: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        self.revisions[1]
            .as_ref()
            .map(|revision| revision.lease())
            .ok_or_else(|| refused("inert behavioral revision absent"))
    }
}

impl InstalledProviderClassAdmission for Evidence {
    fn current_class_revision(
        &self,
        _: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        self.revisions[2]
            .as_ref()
            .map(|revision| revision.lease())
            .ok_or_else(|| refused("inert class revision absent"))
    }
}

struct Provider {
    manifest: ProviderManifest,
    plan: ProviderPreparationPlan,
    preparations: Rc<Cell<usize>>,
    revoke_during_plan: Option<Rc<Cell<bool>>>,
    terminal_revoke: Option<Rc<InstalledProviderRevision>>,
    describe_calls: Cell<usize>,
    actual_nodes: Vec<Box<dyn super::super::SimulationNode>>,
}

impl NodeProvider for Provider {
    fn describe(&self) -> &ProviderManifest {
        let calls = self.describe_calls.get() + 1;
        self.describe_calls.set(calls);
        if calls == 3
            && let Some(revision) = &self.terminal_revoke
        {
            revision.revoke();
        }
        &self.manifest
    }
    fn plan(
        &self,
        _: ProviderPlanningRequest<'_>,
    ) -> Result<ProviderPreparationPlan, RealizationFailure> {
        if let Some(current) = &self.revoke_during_plan {
            current.set(false);
        }
        Ok(self.plan.clone())
    }
    fn prepare(
        &mut self,
        _: RealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        Err(RealizationFailure {
            reason: "legacy realization unused".into(),
            retained: None,
        })
    }
    fn prepare_original(
        &mut self,
        request: OriginalRealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        self.preparations.set(self.preparations.get() + 1);
        Ok(PreparedRealization::new(
            std::mem::take(&mut self.actual_nodes),
            request.activation.clone(),
            request.runtime_limits,
            request.custody_slot,
        ))
    }
}

struct Slot(Rc<Cell<usize>>);

impl RuntimeCustodySlot for Slot {
    fn validate_world(
        &self,
        _: &ActivationRecord,
        _: RuntimeLimits,
    ) -> Result<(), super::super::RuntimeError> {
        // This inert slot has no native authority; it only records transfer.
        Ok(())
    }
    fn retain(self: Box<Self>, _custody: WholeRuntimeCustody) {
        self.0.set(self.0.get() + 1);
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

struct Fixture {
    profile: ReferenceProfile,
    plan: ProviderPreparationPlan,
    resources: ResourceLimits,
    activation: ActivationRecord,
}

fn fixture() -> Fixture {
    let artifact =
        canonical::content_ref(b"inert source identity", "application/octet-stream").unwrap();
    let profile = ReferenceProfile::build(
        id("node"),
        id("owner"),
        artifact.clone(),
        artifact,
        U64::new(1000),
        U64::new(1_000_000),
    )
    .unwrap();
    let authority = LiveAuthority {
        schema_version: 1,
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        realization_id: id("realization"),
        activation_id: None,
        world_generation: U64::new(0),
        owner_generation: U64::new(1),
        input_epoch: id("epoch"),
        host_receipt: canonical::content_ref(b"inert admission", "text/plain").unwrap(),
        extensions: Extensions::new(),
    };
    let (binding, _) = profile.bind(authority).unwrap();
    let plan = ProviderPreparationPlan {
        descriptors: vec![profile.descriptor.clone()],
        bindings: vec![binding.compatibility],
    };
    let resources = ResourceLimits {
        cpu_budget_ns: U64::new(1_000_000),
        memory_bytes: U64::new(64 * 1024 * 1024),
        writable_bytes: U64::new(1024),
        processes: U64::new(1),
        descriptors: U64::new(8),
        pending_events: U64::new(1),
        content_bytes: U64::new(1024 * 1024),
        maximum_operations: U64::new(8),
        extensions: Extensions::new(),
    };
    let activation = ActivationRecord {
        generation: U64::new(1),
        activation_id: id("activation"),
        world_binding_hash: canonical::hash("cnp.world-binding.v1", b"inert world").unwrap(),
        owners: vec![OwnerIdentity {
            owner: id("owner"),
            incarnation: id("incarnation"),
            generation: U64::new(1),
        }],
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    Fixture {
        profile,
        plan,
        resources,
        activation,
    }
}

fn installed(
    fixture: &Fixture,
    reject_claim: bool,
    plan: ProviderPreparationPlan,
    preparations: Rc<Cell<usize>>,
) -> InstalledProviderRegistry {
    let revisions = revision_owners(fixture);
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let source = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions: revisions.clone(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    let behavioral = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim,
        current: None,
        revoke: None,
        revisions: revisions.clone(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    registry
        .install(
            &fixture.profile.provider_manifest,
            Box::new(Provider {
                manifest: fixture.profile.provider_manifest.clone(),
                plan,
                preparations,
                revoke_during_plan: None,
                terminal_revoke: None,
                describe_calls: Cell::new(0),
                actual_nodes: Vec::new(),
            }),
            source,
            behavioral,
        )
        .unwrap();
    registry
}

fn selection<'a>(fixture: &'a Fixture, nodes: &'a [Id]) -> ProviderPlanningRequest<'a> {
    ProviderPlanningRequest {
        profile: &fixture.profile.node_manifest.profile_id,
        configuration: &fixture.profile.configuration_ref,
        nodes,
        resources: &fixture.resources,
        limits: ProviderRegistryLimits::default(),
    }
}

#[test]
fn ordinary_refusal_precedes_provider_allocation() {
    let fixture = fixture();
    let preparations = Rc::new(Cell::new(0));
    let mut registry = installed(
        &fixture,
        true,
        fixture.plan.clone(),
        Rc::clone(&preparations),
    );
    let nodes = [id("node")];
    let result = registry.prepare_original(
        &fixture.profile.provider_manifest.provider_id,
        selection(&fixture, &nodes),
        &fixture.plan,
        &fixture.activation,
        RuntimeLimits::default(),
        Box::new(Slot(Rc::new(Cell::new(0)))),
    );
    assert!(result.is_err());
    assert_eq!(preparations.get(), 0);
}

#[test]
fn foreign_installed_plan_refuses_before_allocation() {
    let fixture = fixture();
    let preparations = Rc::new(Cell::new(0));
    let mut foreign = fixture.plan.clone();
    foreign.bindings[0].implementation.implementation_id = id("foreign");
    let mut registry = installed(&fixture, false, foreign, Rc::clone(&preparations));
    let nodes = [id("node")];
    let result = registry.prepare_original(
        &fixture.profile.provider_manifest.provider_id,
        selection(&fixture, &nodes),
        &fixture.plan,
        &fixture.activation,
        RuntimeLimits::default(),
        Box::new(Slot(Rc::new(Cell::new(0)))),
    );
    assert!(result.is_err());
    assert_eq!(preparations.get(), 0);
}

#[test]
fn actual_preparation_refusal_retains_original_world_slot() {
    let fixture = fixture();
    let preparations = Rc::new(Cell::new(0));
    let reclaimed = Rc::new(Cell::new(0));
    let mut registry = installed(
        &fixture,
        false,
        fixture.plan.clone(),
        Rc::clone(&preparations),
    );
    let nodes = [id("node")];
    let result = registry.prepare_original(
        &fixture.profile.provider_manifest.provider_id,
        selection(&fixture, &nodes),
        &fixture.plan,
        &fixture.activation,
        RuntimeLimits::default(),
        Box::new(Slot(Rc::clone(&reclaimed))),
    );
    let Err(failure) = result else {
        panic!("incomplete actual preparation must refuse")
    };
    assert_eq!(preparations.get(), 1);
    assert!(failure.retained.is_some());
    assert_eq!(reclaimed.get(), 0);
    drop(failure);
    assert_eq!(reclaimed.get(), 1);
}

#[test]
fn missing_source_installation_never_registers_provider() {
    let fixture = fixture();
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let source = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: true,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    let behavioral = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    let result = registry.install(
        &fixture.profile.provider_manifest,
        Box::new(Provider {
            manifest: fixture.profile.provider_manifest.clone(),
            plan: fixture.plan.clone(),
            preparations: Rc::new(Cell::new(0)),
            revoke_during_plan: None,
            terminal_revoke: None,
            describe_calls: Cell::new(0),
            actual_nodes: Vec::new(),
        }),
        source,
        behavioral,
    );
    assert!(result.is_err());
    assert!(
        registry
            .manifest(&fixture.profile.provider_manifest.provider_id)
            .is_none()
    );
}

#[test]
fn borrowed_metadata_credit_refuses_before_copy() {
    let fixture = fixture();
    let limits = ProviderRegistryLimits {
        metadata_bytes: 2,
        ..ProviderRegistryLimits::default()
    };
    let mut registry = InstalledProviderRegistry::new(limits).unwrap();
    let source = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    let behavioral = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    assert!(
        registry
            .install(
                &fixture.profile.provider_manifest,
                Box::new(Provider {
                    manifest: fixture.profile.provider_manifest.clone(),
                    plan: fixture.plan.clone(),
                    preparations: Rc::new(Cell::new(0)),
                    revoke_during_plan: None,
                    terminal_revoke: None,
                    describe_calls: Cell::new(0),
                    actual_nodes: Vec::new(),
                }),
                source,
                behavioral
            )
            .is_err()
    );
    assert!(
        registry
            .manifest(&fixture.profile.provider_manifest.provider_id)
            .is_none()
    );
}

#[test]
fn final_class_callback_cannot_revoke_source_and_launch() {
    let fixture = fixture();
    let live = Rc::new(Cell::new(true));
    let preparations = Rc::new(Cell::new(0));
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let source = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: Some(Rc::clone(&live)),
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    let behavioral = Rc::new(Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    });
    registry
        .install(
            &fixture.profile.provider_manifest,
            Box::new(Provider {
                manifest: fixture.profile.provider_manifest.clone(),
                plan: fixture.plan.clone(),
                preparations: Rc::clone(&preparations),
                revoke_during_plan: None,
                terminal_revoke: None,
                describe_calls: Cell::new(0),
                actual_nodes: Vec::new(),
            }),
            source,
            behavioral,
        )
        .unwrap();
    let final_class = Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: Some(Rc::clone(&live)),
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    };
    let nodes = [id("node")];
    let result = registry.prepare_original_with_admission(
        &fixture.profile.provider_manifest.provider_id,
        OriginalRealizationRequest {
            selection: selection(&fixture, &nodes),
            plan: &fixture.plan,
            activation: &fixture.activation,
            runtime_limits: RuntimeLimits::default(),
            custody_slot: Box::new(Slot(Rc::new(Cell::new(0)))),
        },
        &final_class,
    );
    assert!(result.is_err());
    assert!(!live.get());
    assert_eq!(preparations.get(), 0);
}

#[test]
fn planning_revocation_of_normal_class_refuses_before_preparation() {
    let fixture = fixture();
    let class_live = Rc::new(Cell::new(true));
    let preparations = Rc::new(Cell::new(0));
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let evidence = || {
        Rc::new(Evidence {
            manifest: fixture.profile.provider_manifest.clone(),
            reject_source: false,
            reject_claim: false,
            current: None,
            revoke: None,
            revisions: Default::default(),
            revoke_class_on_source_lease: false,
            accept_prepared: false,
            revoke_on_prepared: None,
        })
    };
    registry
        .install(
            &fixture.profile.provider_manifest,
            Box::new(Provider {
                manifest: fixture.profile.provider_manifest.clone(),
                plan: fixture.plan.clone(),
                preparations: Rc::clone(&preparations),
                revoke_during_plan: Some(Rc::clone(&class_live)),
                terminal_revoke: None,
                describe_calls: Cell::new(0),
                actual_nodes: Vec::new(),
            }),
            evidence(),
            evidence(),
        )
        .unwrap();
    let final_class = Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: Some(Rc::clone(&class_live)),
        revoke: None,
        revisions: Default::default(),
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    };
    let nodes = [id("node")];
    let result = registry.prepare_original_with_admission(
        &fixture.profile.provider_manifest.provider_id,
        OriginalRealizationRequest {
            selection: selection(&fixture, &nodes),
            plan: &fixture.plan,
            activation: &fixture.activation,
            runtime_limits: RuntimeLimits::default(),
            custody_slot: Box::new(Slot(Rc::new(Cell::new(0)))),
        },
        &final_class,
    );
    assert!(result.is_err());
    assert!(!class_live.get());
    assert_eq!(preparations.get(), 0);
}

fn revision_owners(fixture: &Fixture) -> [Option<Rc<InstalledProviderRevision>>; 3] {
    let nodes = [id("node")];
    let scope = ProviderAuthorizationScope::from_plan(selection(fixture, &nodes), &fixture.plan)
        .unwrap_or_else(|error| panic!("inert original scope refused: {error}"));
    [
        ProviderAuthorityKind::Source,
        ProviderAuthorityKind::Behavioral,
        ProviderAuthorityKind::CatalogClass,
    ]
    .map(|kind| Some(Rc::new(InstalledProviderRevision::new(scope.clone(), kind))))
}

fn revision_evidence(
    fixture: &Fixture,
    revisions: [Option<Rc<InstalledProviderRevision>>; 3],
) -> Evidence {
    Evidence {
        manifest: fixture.profile.provider_manifest.clone(),
        reject_source: false,
        reject_claim: false,
        current: None,
        revoke: None,
        revisions,
        revoke_class_on_source_lease: false,
        accept_prepared: false,
        revoke_on_prepared: None,
    }
}

fn terminal_revision_control(revoke_from_provider: bool) {
    let fixture = fixture();
    let revisions = revision_owners(&fixture);
    let preparations = Rc::new(Cell::new(0));
    let mut source = revision_evidence(&fixture, revisions.clone());
    source.revoke_class_on_source_lease = !revoke_from_provider;
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    registry
        .install(
            &fixture.profile.provider_manifest,
            Box::new(Provider {
                manifest: fixture.profile.provider_manifest.clone(),
                plan: fixture.plan.clone(),
                preparations: Rc::clone(&preparations),
                revoke_during_plan: None,
                terminal_revoke: if revoke_from_provider {
                    revisions[2].clone()
                } else {
                    None
                },
                describe_calls: Cell::new(0),
                actual_nodes: Vec::new(),
            }),
            Rc::new(source),
            Rc::new(revision_evidence(&fixture, revisions.clone())),
        )
        .unwrap();
    let final_class = revision_evidence(&fixture, revisions.clone());
    let nodes = [id("node")];

    let result = registry.prepare_original_with_admission(
        &fixture.profile.provider_manifest.provider_id,
        OriginalRealizationRequest {
            selection: selection(&fixture, &nodes),
            plan: &fixture.plan,
            activation: &fixture.activation,
            runtime_limits: RuntimeLimits::default(),
            custody_slot: Box::new(Slot(Rc::new(Cell::new(0)))),
        },
        &final_class,
    );
    assert!(result.is_err());
    assert_eq!(
        preparations.get(),
        0,
        "late withdrawal must precede native preparation"
    );
    let scope =
        ProviderAuthorizationScope::from_plan(selection(&fixture, &nodes), &fixture.plan).unwrap();
    assert!(
        final_class
            .current_class_revision(&scope)
            .unwrap()
            .authenticate(&scope, ProviderAuthorityKind::CatalogClass)
            .is_err()
    );
}

#[test]
fn terminal_source_callback_withdrawing_normal_class_cannot_prepare() {
    terminal_revision_control(false);
}

#[test]
fn terminal_provider_callback_withdrawing_normal_class_cannot_prepare() {
    terminal_revision_control(true);
}

#[test]
fn direct_revision_refuses_foreign_role_scope_and_dropped_owner() {
    let fixture = fixture();
    let nodes = [id("node")];
    let scope =
        ProviderAuthorizationScope::from_plan(selection(&fixture, &nodes), &fixture.plan).unwrap();
    let owner = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Source);
    let lease = owner.lease();
    assert!(
        lease
            .authenticate(&scope, ProviderAuthorityKind::Source)
            .is_ok()
    );
    assert!(
        lease
            .authenticate(&scope, ProviderAuthorityKind::CatalogClass)
            .is_err()
    );
    let mut foreign = selection(&fixture, &nodes);
    let configuration =
        canonical::content_ref(b"different original configuration", "text/plain").unwrap();
    foreign.configuration = &configuration;
    let foreign = ProviderAuthorizationScope::from_plan(foreign, &fixture.plan).unwrap();
    assert!(
        lease
            .authenticate(&foreign, ProviderAuthorityKind::Source)
            .is_err()
    );
    drop(owner);
    assert!(
        lease
            .authenticate(&scope, ProviderAuthorityKind::Source)
            .is_err()
    );
}

fn prepared_revision_fixture(
    revoke_during_validation: bool,
) -> (
    Fixture,
    PreparedRealization,
    [Option<Rc<InstalledProviderRevision>>; 3],
) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let actual_nodes = crate::node_contract::test_nodes(&graph);
    let mut fixture = fixture();
    fixture.plan = ProviderPreparationPlan {
        descriptors: actual_nodes
            .iter()
            .map(|node| node.descriptor().clone())
            .collect(),
        bindings: actual_nodes
            .iter()
            .map(|node| node.binding().compatibility.clone())
            .collect(),
    };
    fixture.profile.provider_manifest.implementation =
        fixture.plan.bindings[0].implementation.clone();
    let ids: Vec<_> = fixture
        .plan
        .bindings
        .iter()
        .map(|binding| binding.node_id.clone())
        .collect();
    let scope =
        ProviderAuthorizationScope::from_plan(selection(&fixture, &ids), &fixture.plan).unwrap();
    let revisions = [
        ProviderAuthorityKind::Source,
        ProviderAuthorityKind::Behavioral,
        ProviderAuthorityKind::CatalogClass,
    ]
    .map(|kind| Some(Rc::new(InstalledProviderRevision::new(scope.clone(), kind))));
    let mut source = revision_evidence(&fixture, revisions.clone());
    source.accept_prepared = true;
    source.revoke_on_prepared = if revoke_during_validation {
        revisions[2].clone()
    } else {
        None
    };
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let preparations = Rc::new(Cell::new(0));
    registry
        .install(
            &fixture.profile.provider_manifest,
            Box::new(Provider {
                manifest: fixture.profile.provider_manifest.clone(),
                plan: fixture.plan.clone(),
                preparations: Rc::clone(&preparations),
                revoke_during_plan: None,
                terminal_revoke: None,
                describe_calls: Cell::new(0),
                actual_nodes,
            }),
            Rc::new(source),
            Rc::new(revision_evidence(&fixture, revisions.clone())),
        )
        .unwrap();
    let result = registry.prepare_original_with_admission(
        &fixture.profile.provider_manifest.provider_id,
        OriginalRealizationRequest {
            selection: selection(&fixture, &ids),
            plan: &fixture.plan,
            activation: &fixture.activation,
            runtime_limits: RuntimeLimits::default(),
            custody_slot: Box::new(Slot(Rc::new(Cell::new(0)))),
        },
        &revision_evidence(&fixture, revisions.clone()),
    );
    assert_eq!(
        preparations.get(),
        1,
        "the actual inactive model was constructed"
    );
    if revoke_during_validation {
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("late validation revocation cannot return success"),
        };
        assert!(failure.reason.contains("withdrawn"));
        let original = failure.retained.unwrap();
        assert_eq!(original.participants().len(), fixture.plan.bindings.len());
        assert!(original.authenticate_provider_authorization().is_err());
        (fixture, *original, revisions)
    } else {
        let original =
            result.unwrap_or_else(|failure| panic!("inert model refused: {}", failure.reason));
        assert!(original.authenticate_provider_authorization().is_ok());
        (fixture, original, revisions)
    }
}

#[test]
fn prepared_source_validator_revocation_retains_same_original_capsule() {
    let (_, original, _) = prepared_revision_fixture(true);
    assert!(original.authenticate_provider_authorization().is_err());
}

struct RevokingGraphEvidence {
    blobs: std::collections::BTreeMap<String, Vec<u8>>,
    class: Rc<InstalledProviderRevision>,
    callbacks: Cell<usize>,
}

impl AdmissionEvidence for RevokingGraphEvidence {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        let body = self
            .blobs
            .get(&reference.hash.digest)
            .ok_or_else(|| refused("inert body absent"))?;
        if body.len() > maximum {
            return Err(refused("inert body credit"));
        }
        Ok(body.clone())
    }

    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Ok(())
    }

    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Ok(())
    }

    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Ok(())
    }

    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.callbacks.set(self.callbacks.get() + 1);
        self.class.revoke();
        Ok(())
    }
}

#[test]
fn graph_callback_revocation_is_seen_by_same_prepared_terminal_fences() {
    // Structural graph admission is real; installed authority and participants
    // are explicit inert fixtures. This test grants no ordinary native class.
    let (_, original, revisions) = prepared_revision_fixture(false);
    let (graph, blobs) = crate::node_admission::test_fixture_isolated_execution(false);
    let descriptors: Vec<_> = original
        .participants()
        .map(|node| node.descriptor().clone())
        .collect();
    let bindings: Vec<_> = original
        .participants()
        .map(|node| node.binding().clone())
        .collect();
    let owners: Vec<_> = graph.owners().cloned().collect();
    let evidence = RevokingGraphEvidence {
        blobs,
        class: revisions[2].as_ref().unwrap().clone(),
        callbacks: Cell::new(0),
    };

    let admitted = admit_graph(
        AdmissionRequest {
            world: graph.world(),
            descriptors: &descriptors,
            bindings: &bindings,
            owners: &owners,
            requirements: graph.requirements(),
        },
        &evidence,
        AdmissionLimits::default(),
    );
    assert!(
        admitted.is_ok(),
        "all original structural data remains valid"
    );
    assert!(
        evidence.callbacks.get() > 0,
        "real graph admission invoked the revoking callback"
    );
    assert!(original.authenticate_provider_authorization().is_err());
    assert_eq!(original.participants().len(), bindings.len());
}

#[test]
fn missing_normal_revision_refuses_and_revision_owner_supports_send_policy() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<InstalledProviderRevision>();
    let fixture = fixture();
    let nodes = [id("node")];
    let scope =
        ProviderAuthorizationScope::from_plan(selection(&fixture, &nodes), &fixture.plan).unwrap();
    let source = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Source);
    let behavioral =
        InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Behavioral);
    let authorization = super::super::provider_revision::ProviderPreparationAuthorization::new(
        scope,
        source.lease(),
        behavioral.lease(),
        None,
    );
    assert!(authorization.authenticate(false).is_ok());
    assert!(
        authorization.authenticate(true).is_err(),
        "source currency cannot replace ordinary accepted class"
    );
}

//! Exercises two independent inert implementation authorities in one actual slot.
//!
//! Source/class evidence is explicitly synthetic. Production partition routing,
//! borrowed contributor views, terminal fences and whole-world queue are real.

use super::*;
use crate::node_contract::*;
use crucible_node_format::{NodeDescriptor, ProviderManifest};
use std::{
    cell::RefCell,
    task::{Context, Poll, Waker},
};

struct ModelNode {
    original: Box<dyn SimulationNode>,
    binding: NodeBinding,
    reclaimed: Rc<Cell<usize>>,
}

impl SimulationNode for ModelNode {
    fn descriptor(&self) -> &NodeDescriptor {
        self.original.descriptor()
    }
    fn binding(&self) -> &NodeBinding {
        &self.binding
    }
    fn route(&self) -> &NodeRoute {
        self.original.route()
    }
    fn thread_affinity(&self) -> ThreadAffinity {
        self.original.thread_affinity()
    }
    fn facets(&self) -> &[FacetKind] {
        self.original.facets()
    }
    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.original.status()
    }
    fn arm(&mut self, _: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "mixed source model cannot Arm".into(),
        })
    }
    fn validate_readiness(
        &self,
        _: &ActivationRecord,
        _: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "mixed source model has no readiness".into(),
        })
    }
    fn begin_operation(&mut self, original: &OperationAdmission) -> Submission {
        self.original.begin_operation(original)
    }
    fn poll_operation(
        &mut self,
        original: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        self.original.poll_operation(original, context)
    }
    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.original.validate_outcome(original, outcome)
    }
    fn request_cancel(
        &mut self,
        original: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.original.request_cancel(original)
    }
    fn close_quantum(&mut self, original: &OperationAdmission) -> Submission {
        self.original.close_quantum(original)
    }
    fn acknowledge_publication(
        &mut self,
        original: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.original.acknowledge_publication(original, outputs)
    }
    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        self.original.facet(kind)
    }
    fn quarantine_resources(&mut self) {
        self.original.quarantine_resources();
    }
    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        self.original.poll_reclamation(owner, context)
    }
    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        self.original.validate_reclamation(receipt)?;
        self.reclaimed.set(self.reclaimed.get() + 1);
        Ok(())
    }
}

struct LocalEvidence {
    manifest: ProviderManifest,
    plan: ProviderPreparationPlan,
    scope: ProviderAuthorizationScope,
    revisions: [Rc<InstalledProviderRevision>; 3],
    claims: Cell<usize>,
}

impl AdmissionEvidence for LocalEvidence {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(refused("inert local source has no global bodies"))
    }
    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if implementation != &self.manifest.implementation {
            return Err(refused("foreign inert implementation"));
        }
        Ok(())
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(refused("inert model has no native authority"))
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(refused("inert local source cannot qualify global schemas"))
    }
    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        let binding = match claim {
            QualificationClaim::Node { binding, .. } => binding,
            _ => return Err(refused("foreign inert local claim")),
        };
        if !self.plan.bindings.contains(binding) {
            return Err(refused("foreign inert local binding"));
        }
        self.claims.set(self.claims.get() + 1);
        Ok(())
    }
}

impl InstalledProviderSource for LocalEvidence {
    fn authenticate_provider(&self, manifest: &ProviderManifest) -> Result<(), EvidenceError> {
        if manifest != &self.manifest {
            return Err(refused("changed inert manifest"));
        }
        Ok(())
    }
    fn authenticate_plan(
        &self,
        _: &ProviderManifest,
        _: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        if plan != &self.plan {
            return Err(refused("changed inert plan"));
        }
        Ok(())
    }
    fn current_source_revision(
        &self,
        scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        self.revisions[0]
            .lease()
            .authenticate(scope, ProviderAuthorityKind::Source)?;
        Ok(self.revisions[0].lease())
    }
    fn authenticate_prepared(
        &self,
        _: &ProviderManifest,
        _: &ProviderPreparationPlan,
        _: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        Err(refused("singleton source path not used"))
    }
    fn authenticate_contribution_plan(
        &self,
        _: &ProviderManifest,
        _: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
        scope: &ProviderWorldAuthorizationScope,
        _: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        if plan != &self.plan
            || !scope.contributions().iter().any(|(provider, local)| {
                provider == &self.manifest.provider_id && local == &self.scope
            })
        {
            return Err(refused("foreign inert contribution scope"));
        }
        Ok(())
    }
    fn authenticate_contribution_prepared(
        &self,
        _: &ProviderManifest,
        plan: &ProviderPreparationPlan,
        _: &ProviderWorldAuthorizationScope,
        prepared: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        for binding in &plan.bindings {
            if !prepared
                .participants()
                .any(|node| &node.binding().compatibility == binding)
            {
                return Err(refused("original inert participant missing"));
            }
        }
        Ok(())
    }
}

impl InstalledProviderBehavioral for LocalEvidence {
    fn current_behavioral_revision(
        &self,
        scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        self.revisions[1]
            .lease()
            .authenticate(scope, ProviderAuthorityKind::Behavioral)?;
        Ok(self.revisions[1].lease())
    }
}

struct ClassEvidence(Vec<Rc<LocalEvidence>>);

impl AdmissionEvidence for ClassEvidence {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(refused("no inert class content"))
    }
    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Err(refused("class is not source"))
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(refused("class is not custody"))
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(refused("class is not a codec"))
    }
    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        let QualificationClaim::Node { binding, .. } = claim else {
            return Err(refused("inert class supports node models only"));
        };
        let local = self
            .0
            .iter()
            .find(|local| local.plan.bindings.contains(binding))
            .ok_or_else(|| refused("foreign inert class"))?;
        local.revisions[2]
            .lease()
            .authenticate(&local.scope, ProviderAuthorityKind::CatalogClass)
    }
}

impl InstalledProviderClassAdmission for ClassEvidence {
    fn current_class_revision(
        &self,
        scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, EvidenceError> {
        let local = self
            .0
            .iter()
            .find(|local| &local.scope == scope)
            .ok_or_else(|| refused("foreign class scope"))?;
        local.revisions[2]
            .lease()
            .authenticate(scope, ProviderAuthorityKind::CatalogClass)?;
        Ok(local.revisions[2].lease())
    }
}

struct WorldEvidence {
    plan: ProviderPreparationPlan,
    activation: ActivationRecord,
    original: RefCell<Option<InstalledProviderWorldRevision>>,
    revoke_before: Option<Rc<InstalledProviderRevision>>,
    revoke_after: Option<Rc<InstalledProviderRevision>>,
}

impl AdmissionEvidence for WorldEvidence {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(refused("inert global source has no graph content"))
    }
    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Err(refused("global source cannot replace local implementation"))
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(refused("global source cannot replace original custody"))
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(refused("no global model schema"))
    }
    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        Err(refused("whole ordinary graph not qualified in model"))
    }
}

impl InstalledProviderWorldSource for WorldEvidence {
    fn authenticate_world_plan(
        &self,
        scope: &ProviderWorldAuthorizationScope,
        plan: &ProviderPreparationPlan,
    ) -> Result<(), EvidenceError> {
        if plan != &self.plan
            || scope.activation() != &self.activation
            || scope.plan_hash()
                != &canonical::json_hash("cnp.provider-world-plan.v1", plan).unwrap()
        {
            return Err(refused("foreign inert complete world"));
        }
        let mut original = self.original.borrow_mut();
        if original.is_none() {
            *original = Some(InstalledProviderWorldRevision::new(scope.clone()));
        }
        Ok(())
    }
    fn current_world_revision(
        &self,
        scope: &ProviderWorldAuthorizationScope,
    ) -> Result<ProviderWorldAuthorizationLease, EvidenceError> {
        if let Some(class) = &self.revoke_before {
            class.revoke();
        }
        let original = self.original.borrow();
        let lease = original
            .as_ref()
            .ok_or_else(|| refused("original inert world owner missing"))?
            .lease();
        lease.authenticate(scope)?;
        Ok(lease)
    }
    fn authenticate_world_prepared(
        &self,
        _: &ProviderWorldAuthorizationScope,
        prepared: &PreparedRealization,
    ) -> Result<(), EvidenceError> {
        if prepared.participants().len() != self.plan.descriptors.len() {
            return Err(refused("incomplete inert actual world"));
        }
        if let Some(class) = &self.revoke_after {
            class.revoke();
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    PanicAfter,
    RefuseAfter,
    ChangeManifest,
}

struct Contributor {
    manifest: ProviderManifest,
    plan: ProviderPreparationPlan,
    originals: Vec<Box<dyn SimulationNode>>,
    calls: Rc<Cell<usize>>,
    mode: Mode,
}

impl NodeProvider for Contributor {
    fn describe(&self) -> &ProviderManifest {
        &self.manifest
    }
    fn plan(
        &self,
        _: ProviderPlanningRequest<'_>,
    ) -> Result<ProviderPreparationPlan, RealizationFailure> {
        Ok(self.plan.clone())
    }
    fn prepare(
        &mut self,
        _: RealizationRequest<'_>,
    ) -> Result<PreparedRealization, RealizationFailure> {
        Err(RealizationFailure {
            reason: "inert legacy preparation unsupported".into(),
            retained: None,
        })
    }
    fn prepare_original_into(
        &mut self,
        request: ProviderContributionRequest<'_>,
        world: &mut ProviderWorldContribution<'_, '_>,
    ) -> Result<(), OperationFailure> {
        assert_eq!(world.activation_record(), request.activation);
        self.calls.set(self.calls.get() + 1);
        while !self.originals.is_empty() {
            let mut original = Some(self.originals.remove(0));
            world
                .append_original(&mut original)
                .map_err(|error| OperationFailure {
                    effects: EffectKnowledge::Unknown,
                    reason: error.message,
                })?;
            assert!(original.is_none());
        }
        match self.mode {
            Mode::Normal => Ok(()),
            Mode::ChangeManifest => {
                self.manifest.provider_id = id("inert/changed-provider");
                Ok(())
            }
            Mode::PanicAfter => panic!("injected original contributor unwind after adoption"),
            Mode::RefuseAfter => Err(OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: "inert contribution uncertainty".into(),
            }),
        }
    }
}

struct MixedFixture {
    registry: InstalledProviderRegistry,
    locals: Vec<Rc<LocalEvidence>>,
    nodes: Vec<Vec<Id>>,
    resources: ResourceLimits,
    configuration: ContentRef,
    profile: Id,
    plan: ProviderPreparationPlan,
    activation: ActivationRecord,
    calls: Vec<Rc<Cell<usize>>>,
    reclaimed: Rc<Cell<usize>>,
}

fn mixed_fixture(second: Mode) -> MixedFixture {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let actual = crate::node_contract::test_nodes(&graph);
    assert!(actual.len() > 1);
    let base = fixture();
    let mut registry = InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap();
    let mut originals: [Vec<Box<dyn SimulationNode>>; 2] = [Vec::new(), Vec::new()];
    let mut plan = ProviderPreparationPlan {
        descriptors: Vec::new(),
        bindings: Vec::new(),
    };
    let mut activation = base.activation.clone();
    activation.owners.clear();
    let reclaimed = Rc::new(Cell::new(0));
    for (index, original) in actual.into_iter().enumerate() {
        let mut binding = original.binding().clone();
        binding.compatibility.implementation.implementation_id = id(if index % 2 == 0 {
            "inert/mixed-a"
        } else {
            "inert/mixed-b"
        });
        activation
            .owners
            .extend(original.route().owners.iter().cloned());
        plan.descriptors.push(original.descriptor().clone());
        plan.bindings.push(binding.compatibility.clone());
        originals[index % 2].push(Box::new(ModelNode {
            original,
            binding,
            reclaimed: Rc::clone(&reclaimed),
        }));
    }
    activation.owners.sort();
    activation.owners.dedup();
    let mut locals = Vec::new();
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    for (index, originals) in originals.into_iter().enumerate() {
        let local_plan = ProviderPreparationPlan {
            descriptors: originals
                .iter()
                .map(|node| node.descriptor().clone())
                .collect(),
            bindings: originals
                .iter()
                .map(|node| node.binding().compatibility.clone())
                .collect(),
        };
        let node_ids: Vec<_> = local_plan
            .descriptors
            .iter()
            .map(|node| node.id.clone())
            .collect();
        let selection = ProviderPlanningRequest {
            nodes: &node_ids,
            ..selection(&base, &node_ids)
        };
        let scope = ProviderAuthorizationScope::from_plan(selection, &local_plan).unwrap();
        let mut manifest = base.profile.provider_manifest.clone();
        manifest.provider_id = id(if index == 0 {
            "inert/provider-a"
        } else {
            "inert/provider-b"
        });
        manifest.implementation = local_plan.bindings[0].implementation.clone();
        let local = Rc::new(LocalEvidence {
            manifest: manifest.clone(),
            plan: local_plan.clone(),
            scope: scope.clone(),
            revisions: [
                ProviderAuthorityKind::Source,
                ProviderAuthorityKind::Behavioral,
                ProviderAuthorityKind::CatalogClass,
            ]
            .map(|kind| Rc::new(InstalledProviderRevision::new(scope.clone(), kind))),
            claims: Cell::new(0),
        });
        let entered = Rc::new(Cell::new(0));
        registry
            .install(
                &manifest,
                Box::new(Contributor {
                    manifest: manifest.clone(),
                    plan: local_plan,
                    originals,
                    calls: Rc::clone(&entered),
                    mode: if index == 0 { Mode::Normal } else { second },
                }),
                local.clone(),
                local.clone(),
            )
            .unwrap();
        locals.push(local);
        nodes.push(node_ids);
        calls.push(entered);
    }
    MixedFixture {
        registry,
        locals,
        nodes,
        resources: base.resources,
        configuration: base.profile.configuration_ref,
        profile: base.profile.node_manifest.profile_id,
        plan,
        activation,
        calls,
        reclaimed,
    }
}

fn parts(fixture: &MixedFixture) -> Vec<ProviderWorldSelection<'_>> {
    fixture
        .locals
        .iter()
        .zip(&fixture.nodes)
        .map(|(local, nodes)| ProviderWorldSelection {
            provider: &local.manifest.provider_id,
            selection: ProviderPlanningRequest {
                profile: &fixture.profile,
                configuration: &fixture.configuration,
                nodes,
                resources: &fixture.resources,
                limits: ProviderRegistryLimits::default(),
            },
            plan: &local.plan,
        })
        .collect()
}

fn world_source(fixture: &MixedFixture, before: bool, after: bool) -> Rc<WorldEvidence> {
    Rc::new(WorldEvidence {
        plan: fixture.plan.clone(),
        activation: fixture.activation.clone(),
        original: RefCell::new(None),
        revoke_before: before.then(|| Rc::clone(&fixture.locals[0].revisions[2])),
        revoke_after: after.then(|| Rc::clone(&fixture.locals[0].revisions[2])),
    })
}

fn prepare(
    fixture: &mut MixedFixture,
    queue: &RuntimeCustodyQueue,
) -> Result<PreparedRealization, RealizationFailure> {
    // The request borrows only metadata; move the registry out to avoid borrowing
    // the owning fixture mutably while original plan references are live.
    let mut registry = std::mem::replace(
        &mut fixture.registry,
        InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap(),
    );
    let contributions = parts(fixture);
    let result = registry.prepare_mixed_original(
        ProviderMixedWorldRequest {
            contributions: &contributions,
            plan: &fixture.plan,
            activation: &fixture.activation,
            runtime_limits: RuntimeLimits::default(),
            custody_slot: queue
                .reserve_world(&fixture.activation, RuntimeLimits::default())
                .unwrap(),
        },
        &ClassEvidence(fixture.locals.clone()),
    );
    fixture.registry = registry;
    result
}

fn drain(queue: &RuntimeCustodyQueue) {
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(Ok(())) = queue.poll_reclamation(&mut context) {
            assert_eq!(queue.reserved_worlds(), 0);
            return;
        }
    }
    panic!("original model queue did not authenticate complete cleanup");
}

#[test]
fn mixed_originals_share_one_slot_and_preserve_global_node_order() {
    let mut fixture = mixed_fixture(Mode::Normal);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, false))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let prepared =
        prepare(&mut fixture, &queue).unwrap_or_else(|failure| panic!("{}", failure.reason));
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(prepared.activation_record(), &fixture.activation);
    assert!(prepared.authenticate_provider_authorization().is_ok());
    assert_eq!(
        prepared
            .participants()
            .map(|node| node.descriptor().id.clone())
            .collect::<Vec<_>>(),
        fixture
            .plan
            .descriptors
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        fixture
            .calls
            .iter()
            .map(|calls| calls.get())
            .collect::<Vec<_>>(),
        vec![1, 1]
    );
    drop(prepared);
    assert_eq!(queue.reserved_worlds(), 1);
    drain(&queue);
    assert_eq!(fixture.reclaimed.get(), fixture.plan.descriptors.len());
}

#[test]
fn missing_complete_world_source_refuses_both_contributors() {
    let mut fixture = mixed_fixture(Mode::Normal);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let failure = prepare(&mut fixture, &queue).err().unwrap();
    assert_eq!(failure.retained.as_ref().unwrap().participants().len(), 0);
    assert!(fixture.calls.iter().all(|calls| calls.get() == 0));
    drop(failure);
    drain(&queue);
    assert_eq!(fixture.reclaimed.get(), 0);
}

#[test]
fn late_world_callback_cannot_revoke_another_original_class_and_prepare() {
    let mut fixture = mixed_fixture(Mode::Normal);
    fixture
        .registry
        .install_world_source(world_source(&fixture, true, false))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let failure = prepare(&mut fixture, &queue).err().unwrap();
    assert!(failure.reason.contains("withdrawn"));
    assert!(fixture.calls.iter().all(|calls| calls.get() == 0));
    drop(failure);
    drain(&queue);
}

#[test]
fn contributor_unwind_after_adoption_keeps_same_whole_world() {
    let mut fixture = mixed_fixture(Mode::PanicAfter);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, false))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let failure = prepare(&mut fixture, &queue).err().unwrap();
    assert!(failure.reason.contains("unwound"));
    assert_eq!(
        failure.retained.as_ref().unwrap().participants().len(),
        fixture.plan.descriptors.len()
    );
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(fixture.reclaimed.get(), 0);
    drop(failure);
    drain(&queue);
    assert_eq!(fixture.reclaimed.get(), fixture.plan.descriptors.len());
}

#[test]
fn uncertain_contributor_error_retains_all_adopted_originals() {
    let mut fixture = mixed_fixture(Mode::RefuseAfter);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, false))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let failure = prepare(&mut fixture, &queue).err().unwrap();
    assert!(failure.reason.contains("uncertainty"));
    assert_eq!(
        failure.retained.as_ref().unwrap().participants().len(),
        fixture.plan.descriptors.len()
    );
    assert_eq!(fixture.reclaimed.get(), 0);
    drop(failure);
    drain(&queue);
    assert_eq!(fixture.reclaimed.get(), fixture.plan.descriptors.len());
}

#[test]
fn final_world_validation_cannot_withdraw_a_class_and_return_success() {
    let mut fixture = mixed_fixture(Mode::Normal);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, true))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let failure = prepare(&mut fixture, &queue).err().unwrap();
    assert!(failure.reason.contains("withdrawn"));
    assert_eq!(
        failure.retained.as_ref().unwrap().participants().len(),
        fixture.plan.descriptors.len()
    );
    drop(failure);
    drain(&queue);
}

#[test]
fn duplicate_partition_refuses_before_any_contributor() {
    let mut fixture = mixed_fixture(Mode::Normal);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, false))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let mut registry = std::mem::replace(
        &mut fixture.registry,
        InstalledProviderRegistry::new(ProviderRegistryLimits::default()).unwrap(),
    );
    let original = parts(&fixture);
    let repeated = [original[0], original[0]];
    let failure = registry
        .prepare_mixed_original(
            ProviderMixedWorldRequest {
                contributions: &repeated,
                plan: &fixture.plan,
                activation: &fixture.activation,
                runtime_limits: RuntimeLimits::default(),
                custody_slot: queue
                    .reserve_world(&fixture.activation, RuntimeLimits::default())
                    .unwrap(),
            },
            &ClassEvidence(fixture.locals.clone()),
        )
        .err()
        .unwrap();
    assert!(failure.reason.contains("unique"));
    assert!(fixture.calls.iter().all(|calls| calls.get() == 0));
    drop(failure);
    drain(&queue);
}

#[test]
fn finite_global_plan_credit_refuses_before_native_contribution() {
    let mut fixture = mixed_fixture(Mode::Normal);
    fixture.registry.limits.metadata_bytes = 128;
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let failure = prepare(&mut fixture, &queue).err().unwrap();
    assert!(failure.reason.contains("credit"));
    assert!(failure.retained.is_none());
    assert!(fixture.calls.iter().all(|calls| calls.get() == 0));
    assert_eq!(
        queue.reserved_worlds(),
        0,
        "same unused prebirth slot was released"
    );
}

#[test]
fn local_claim_routes_to_exact_declared_provider_without_trying_others() {
    let mut fixture = mixed_fixture(Mode::Normal);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, false))
        .unwrap();
    let contributions = parts(&fixture);
    let evidence = fixture
        .registry
        .mixed_admission_evidence(&contributions, &fixture.plan)
        .unwrap();
    let binding = &fixture.locals[1].plan.bindings[0];
    evidence
        .qualify(QualificationClaim::Node {
            binding,
            binding_hash: &binding.identity().unwrap(),
            qualification_refs: &binding.qualification_refs,
        })
        .unwrap();
    assert_eq!(fixture.locals[0].claims.get(), 0);
    assert_eq!(
        fixture.locals[1].claims.get(),
        2,
        "exact source and behavior conjuncts ran"
    );
    let mut foreign = binding.clone();
    foreign.node_id = id("inert/absent-node");
    assert!(
        evidence
            .qualify(QualificationClaim::Node {
                binding: &foreign,
                binding_hash: &binding.identity().unwrap(),
                qualification_refs: &foreign.qualification_refs
            })
            .is_err()
    );
    assert_eq!(fixture.locals[0].claims.get(), 0);
    assert_eq!(fixture.locals[1].claims.get(), 2);
}

#[test]
fn contributor_manifest_mutation_retains_same_originals_and_world_slot() {
    let mut fixture = mixed_fixture(Mode::ChangeManifest);
    fixture
        .registry
        .install_world_source(world_source(&fixture, false, false))
        .unwrap();
    let queue = RuntimeCustodyQueue::new(1).unwrap();

    let failure = prepare(&mut fixture, &queue).err().unwrap();

    assert!(failure.reason.contains("manifest"));
    assert_eq!(
        failure.retained.as_ref().unwrap().participants().len(),
        fixture.plan.descriptors.len()
    );
    assert!(fixture.calls.iter().all(|calls| calls.get() == 1));
    assert_eq!(fixture.reclaimed.get(), 0);
    assert_eq!(queue.reserved_worlds(), 1);

    drop(failure);
    assert_eq!(queue.reserved_worlds(), 1);
    drain(&queue);
    assert_eq!(fixture.reclaimed.get(), fixture.plan.descriptors.len());
}

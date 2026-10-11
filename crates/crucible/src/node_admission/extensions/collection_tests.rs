//! Models collecting-only extension delegation without native/class qualification.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These purpose models panic only when original scope or callback ordering fails.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_admission::{
    AdmissionEvidence, ConformanceAdmissionAuthority, ConformancePlanEvidence,
    InstalledConformancePlan, QualificationClaim, admit_conformance_graph, admit_graph,
};

struct Collection {
    evidence: ModelGraphEvidence,
    world: WorldBinding,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    requirements: crate::node_admission::ScenarioRequirements,
    plan_bytes: Vec<u8>,
    audit_bytes: Vec<u8>,
    current: Cell<bool>,
    allow: Cell<bool>,
    revoke: Cell<bool>,
    revoke_ordinary: Cell<bool>,
    late_world_refusal: Cell<bool>,
    revoke_final_world: Cell<bool>,
    ordinary_checked: Cell<bool>,
    checks: Cell<usize>,
    handlers: Rc<Cell<usize>>,
}

impl Collection {
    fn new() -> Rc<Self> {
        Self::with_dependency(false)
    }

    fn with_dependency(dependency: bool) -> Rc<Self> {
        let (graph, blobs) = crate::node_admission::test_fixture_with_content();
        let mut installation = ModelInstallation::default();
        // Ordinary qualification remains refused even when collection succeeds.
        let mut registration = installation.registration("model/collection-only", false);
        let mut registrations = Vec::new();
        if dependency {
            let prerequisite = installation.registration("model/collection-prerequisite", false);
            let mut declaration = installation.declaration(&registration.selection);
            declaration.dependencies = vec![ExtensionDependency::Extension {
                selection: prerequisite.selection.clone(),
            }];
            registration.selection = installation.selection(&declaration);
            registrations.push(prerequisite);
        }
        let mut world = graph.world().clone();
        world.extensions = selected_map(&registration.selection);
        let handlers = Rc::clone(&installation.callbacks);
        registrations.push(registration);
        Rc::new(Self {
            evidence: ModelGraphEvidence {
                registry: install(registrations, &installation).unwrap(),
                blobs,
            },
            world,
            descriptors: graph
                .node_ids()
                .map(|node| graph.descriptor(node).unwrap().clone())
                .collect(),
            bindings: graph
                .node_ids()
                .map(|node| graph.binding(node).unwrap().clone())
                .collect(),
            owners: graph.owners().cloned().collect(),
            requirements: graph.requirements().clone(),
            plan_bytes: canonical::canonical_json(
                &serde_json::json!({"complete":"model-only", "execution":"not-executed"}),
            )
            .unwrap(),
            audit_bytes: canonical::canonical_json(
                &serde_json::json!({"decision":"refused", "original":"not-executed"}),
            )
            .unwrap(),
            current: Cell::new(true),
            allow: Cell::new(true),
            revoke: Cell::new(false),
            revoke_ordinary: Cell::new(false),
            late_world_refusal: Cell::new(false),
            revoke_final_world: Cell::new(false),
            ordinary_checked: Cell::new(false),
            checks: Cell::new(0),
            handlers,
        })
    }

    fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            world: &self.world,
            descriptors: &self.descriptors,
            bindings: &self.bindings,
            owners: &self.owners,
            requirements: &self.requirements,
        }
    }

    fn plan(self: &Rc<Self>) -> InstalledConformancePlan {
        let plan = canonical::content_ref(&self.plan_bytes, "application/json").unwrap();
        let audit = canonical::content_ref(&self.audit_bytes, "application/json").unwrap();
        InstalledConformancePlan::install(
            ConformancePlanEvidence {
                plan_ref: &plan,
                plan_bytes: &self.plan_bytes,
                refused_ref: &audit,
                refused_bytes: &self.audit_bytes,
                world: &self.world.identity().unwrap(),
                sources: std::slice::from_ref(&self.world.initialization_ref),
            },
            self.clone(),
        )
        .unwrap()
    }
}

impl AdmissionEvidence for Collection {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        Some(&self.evidence.registry)
    }

    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.evidence.content(reference, maximum)
    }

    fn authenticate_implementation(
        &self,
        value: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.evidence.authenticate_implementation(value)
    }

    fn authenticate_authority(&self, value: &NodeBinding) -> Result<(), EvidenceError> {
        self.evidence.authenticate_authority(value)
    }

    fn authenticate_schema(&self, value: &SchemaRef) -> Result<(), EvidenceError> {
        self.evidence.authenticate_schema(value)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        if matches!(claim, QualificationClaim::Coordinator { .. }) {
            self.ordinary_checked.set(true);
            if self.revoke_ordinary.get() {
                self.current.set(false);
            }
        }
        self.evidence.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for Collection {
    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        if !self.current.get()
            || (self.ordinary_checked.get() && self.late_world_refusal.get())
            || plan.plan_bytes != self.plan_bytes
            || plan.refused_bytes != self.audit_bytes
            || plan.world != &self.world.identity().unwrap()
            || plan.sources != [self.world.initialization_ref.clone()]
            || request.world != &self.world
            || request.descriptors != self.descriptors
            || request.bindings != self.bindings
            || request.owners != self.owners
        {
            return Err(error("changed complete original model collection revision"));
        }
        Ok(())
    }

    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        if !self.current.get()
            || plan.plan_bytes != self.plan_bytes
            || plan.refused_bytes != self.audit_bytes
            || plan.world != &self.world.identity().unwrap()
            || plan.sources != [self.world.initialization_ref.clone()]
        {
            return Err(error("foreign or revoked original model collection plan"));
        }
        Ok(())
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        if (self.ordinary_checked.get() && self.late_world_refusal.get())
            || request.world != &self.world
            || request.descriptors != self.descriptors
            || request.bindings != self.bindings
            || request.owners != self.owners
        {
            return Err(error("changed complete original model collection world"));
        }
        if self.ordinary_checked.get() && self.revoke_final_world.get() {
            self.current.set(false);
        }
        Ok(())
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        self.evidence.qualify(claim)
    }

    fn authenticate_collection_extension(
        &self,
        plan: ConformancePlanEvidence<'_>,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.authenticate_collection_plan(plan)?;
        self.checks.set(self.checks.get() + 1);
        if !self.allow.get()
            || application.world() != &self.world
            || declaration.identifier != selected.selection.identifier
            || semantics.impact != ExtensionImpact::Metadata
        {
            return Err(error("model collecting extension refused"));
        }
        if self.revoke.get() {
            self.current.set(false);
        }
        Ok(())
    }
}

#[test]
fn collecting_extension_never_qualifies_ordinary_graph_or_serialized_world() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    let graph =
        admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default()).unwrap();
    assert!(graph.graph.collecting);
    assert_eq!(graph.graph.selected_extensions().applications().len(), 1);
    assert_eq!(fixture.checks.get(), 1);

    let ordinary_checks = fixture.checks.get();
    assert!(
        admit_graph(
            fixture.request(),
            fixture.as_ref(),
            AdmissionLimits::default()
        )
        .is_err()
    );
    let bytes = serde_json::to_vec(graph.world()).unwrap();
    let world: WorldBinding = serde_json::from_slice(&bytes).unwrap();
    let request = AdmissionRequest {
        world: &world,
        ..fixture.request()
    };
    assert!(admit_graph(request, fixture.as_ref(), AdmissionLimits::default()).is_err());
    assert_eq!(fixture.checks.get(), ordinary_checks);
}

#[test]
fn stale_collecting_plan_refuses_before_handler_or_qualification_callback() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    fixture.current.set(false);
    let handlers = fixture.handlers.get();
    assert!(admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default()).is_err());
    assert_eq!(fixture.handlers.get(), handlers);
    assert_eq!(fixture.checks.get(), 0);
}

#[test]
fn foreign_collecting_world_refuses_before_handler_or_qualification_callback() {
    let fixture = Collection::new();
    let other = Collection::new();
    let plan = fixture.plan();
    let mut changed = other.world.clone();
    changed.initialization_ref = changed.scenario_ref.clone();
    let request = AdmissionRequest {
        world: &changed,
        ..other.request()
    };
    let handlers = fixture.handlers.get();
    assert!(admit_conformance_graph(request, &plan, AdmissionLimits::default()).is_err());
    assert_eq!(fixture.handlers.get(), handlers);
    assert_eq!(fixture.checks.get(), 0);
    assert!(plan.authenticate_authority(other.as_ref()).is_err());
}

#[test]
fn refused_collecting_extension_never_returns_partial_seal() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    fixture.allow.set(false);
    assert!(admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default()).is_err());
    assert_eq!(fixture.checks.get(), 1);
}

#[test]
fn revoked_during_extension_callback_cannot_publish_collecting_seal() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    fixture.revoke.set(true);
    assert!(admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default()).is_err());
    assert_eq!(fixture.checks.get(), 1);
    assert!(!fixture.current.get());
}

#[test]
fn collection_dependency_default_refuses_without_inheriting_root_qualification() {
    let fixture = Collection::with_dependency(true);
    let plan = fixture.plan();
    let handlers = fixture.handlers.get();
    assert!(admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default()).is_err());
    assert_eq!(fixture.handlers.get(), handlers);
    assert_eq!(fixture.checks.get(), 0);
}

#[test]
fn late_ordinary_callback_revocation_cannot_seal_collecting_graph() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    fixture.revoke_ordinary.set(true);

    let refused = admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default());

    assert!(refused.is_err());
    assert_eq!(fixture.checks.get(), 1);
    assert!(fixture.ordinary_checked.get());
    assert!(!fixture.current.get());
}

#[test]
fn final_collection_seal_reauthenticates_whole_world_after_ordinary_callbacks() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    fixture.late_world_refusal.set(true);

    let refused = admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default());

    assert!(refused.is_err());
    assert_eq!(fixture.checks.get(), 1);
    assert!(fixture.ordinary_checked.get());
    assert!(fixture.current.get());
}

#[test]
fn final_world_callback_revocation_cannot_publish_collecting_seal() {
    let fixture = Collection::new();
    let plan = fixture.plan();
    fixture.revoke_final_world.set(true);

    let refused = admit_conformance_graph(fixture.request(), &plan, AdmissionLimits::default());

    assert!(refused.is_err());
    assert_eq!(fixture.checks.get(), 1);
    assert!(fixture.ordinary_checked.get());
    assert!(!fixture.current.get());
}

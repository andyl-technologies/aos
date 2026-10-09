//! Exercises host contracts with explicitly synthetic proof and native-custody fixtures.

// These model-only fixtures intentionally panic on preserved-state regressions.
// crucible-lint: allow panic-shortcut -- These node state tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::*;

use crate::node_admission::{
    AdmittedGraph, test_fixture_with_content, test_nondeterministic_fixture_with_content,
};
use crate::node_contract::{ActivationRecord, OwnerIdentity, SimulationNode};
use crate::node_scheduling::{
    SavedBound, SavedOwner, SavedPosition, SavedProducer, SchedulingSnapshot,
};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn cut() -> Position {
    Position {
        time_ps: 100.into(),
        microstep: 0.into(),
        phase: Phase::BoundaryControl,
    }
}

struct Evidence {
    blobs: BTreeMap<String, Vec<u8>>,
    snapshot: SchedulingSnapshot,
    reject_native: bool,
    omit_native_domain: bool,
    overstate_repeatability: bool,
    dependencies: BTreeMap<String, Vec<ContentRef>>,
    pending_native_acknowledgements: Vec<Id>,
    runtime: crate::node_contract::RuntimeSnapshot,
}

impl Evidence {
    fn put(&mut self, value: &impl serde::Serialize) -> ContentRef {
        let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        self.blobs.insert(reference.hash.digest.clone(), bytes);
        reference
    }
}

impl CaptureEvidence for Evidence {
    fn content(&self, reference: &ContentRef, maximum_bytes: usize) -> Result<Vec<u8>, StateError> {
        let bytes = self.blobs.get(&reference.hash.digest).ok_or_else(|| {
            StateError::new(StateErrorCode::Content, "fixture", "content missing")
        })?;
        if bytes.len() > maximum_bytes {
            return Err(super::closure::limit("fixture fetch"));
        }
        Ok(bytes.clone())
    }
    fn dependencies(
        &self,
        reference: &ContentRef,
        _: &[u8],
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let dependencies = self.dependencies.get(&reference.hash.digest);
        if dependencies.is_some_and(|dependencies| dependencies.len() > maximum_dependencies) {
            return Err(super::closure::limit("fixture dependency allocation"));
        }
        Ok(dependencies.cloned().unwrap_or_default())
    }
    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        manifest: &CaptureManifest,
        owner: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        if self.reject_native {
            return Err(StateError::new(
                StateErrorCode::NativeEvidence,
                owner.capture_owner_id.as_str(),
                "unchanged native cut unavailable",
            ));
        }
        let mut domains = owner.state_domain_ids.clone();
        if self.omit_native_domain {
            domains.pop();
        }
        Ok(NativeOwnerCaptureProof {
            owner_id: owner.capture_owner_id.clone(),
            state_domain_ids: domains,
            cut: manifest.cut,
            event_ordinal: manifest.event_ordinal,
        })
    }
    fn verify_coordinator_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        content: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        let bytes = content
            .get(&manifest.coordinator_state_ref)
            .ok_or_else(|| {
                StateError::new(
                    StateErrorCode::Content,
                    "synthetic coordinator",
                    "complete bound ledger absent",
                )
            })?;
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(super::schema)?;
        let scheduler: SchedulingSnapshot =
            serde_json::from_value(value["scheduler"].clone()).map_err(super::schema)?;
        let runtime: crate::node_contract::RuntimeSnapshot =
            serde_json::from_value(value["runtime"].clone()).map_err(super::schema)?;
        Ok(NativeCoordinatorCaptureProof {
            source_owners: scheduler
                .source_owners
                .iter()
                .map(|owner| OwnerIdentity {
                    owner: owner.owner.clone(),
                    incarnation: owner.incarnation.clone(),
                    generation: owner.generation,
                })
                .collect(),
            world_repeatability: if self.overstate_repeatability {
                Repeatability::Qualified
            } else {
                graph.world_repeatability()
            },
            scheduler,
            pending_native_acknowledgements: self.pending_native_acknowledgements.clone(),
            runtime,
        })
    }
}

fn setup(
    graph: &AdmittedGraph,
    blobs: BTreeMap<String, Vec<u8>>,
) -> (Evidence, CaptureManifest, StateRequirements) {
    let snapshot = SchedulingSnapshot {
        schema_version: 1,
        ordering_profile: "superdense-v1".into(),
        world_binding_hash: graph.world_binding_hash().clone(),
        source_activation_id: id("source/activation"),
        source_generation: 1.into(),
        source_boundary: Position {
            time_ps: 0.into(),
            microstep: 0.into(),
            phase: Phase::BoundaryControl,
        },
        capture_cut: cut(),
        capture_ordinal: 7.into(),
        source_owners: graph
            .owners()
            .map(|owner| SavedOwner {
                owner: owner.owner.id.clone(),
                incarnation: id(&format!("source/{}", owner.owner.id)),
                generation: 1.into(),
            })
            .collect(),
        maximum_microsteps: graph.coordinator_policy().maximum_microsteps_per_instant,
        positions: graph
            .owners()
            .filter(|owner| owner.owner_roles.contains(&id("execution")))
            .map(|owner| SavedPosition {
                owner: owner.owner.id.clone(),
                position: cut(),
            })
            .collect(),
        producers: graph
            .node_ids()
            .map(|node| SavedProducer {
                node: node.clone(),
                bound: SavedBound::Unknown,
                next_sequence: Some(42.into()),
                closed_prefix: cut(),
            })
            .collect(),
        native_sequences: vec![],
        external_closed_prefixes: vec![],
        payload_objects: vec![],
        pending_deliveries: vec![],
        used_operations: vec![id("operation/already-used")],
        reservations: vec![],
        input_batches: vec![],
        used_input_batches: vec![],
    };
    let runtime = crate::node_contract::RuntimeSnapshot {
        schema_version: 1,
        source_activation: crate::node_contract::SavedRuntimeActivation {
            generation: snapshot.source_generation,
            activation_id: snapshot.source_activation_id.clone(),
            world_binding_hash: snapshot.world_binding_hash.clone(),
            boundary: snapshot.source_boundary,
            owners: snapshot
                .source_owners
                .iter()
                .map(|owner| OwnerIdentity {
                    owner: owner.owner.clone(),
                    incarnation: owner.incarnation.clone(),
                    generation: owner.generation,
                })
                .collect(),
        },
        capture_cut: snapshot.capture_cut,
        capture_ordinal: snapshot.capture_ordinal,
        owners: snapshot
            .source_owners
            .iter()
            .map(|owner| crate::node_contract::SavedRuntimeOwner {
                identity: OwnerIdentity {
                    owner: owner.owner.clone(),
                    incarnation: owner.incarnation.clone(),
                    generation: owner.generation,
                },
                lifecycle: crate::node_contract::Lifecycle::Stopped,
                operation: None,
                domains: graph
                    .owner(&owner.owner)
                    .unwrap()
                    .owner
                    .state_domain_ids
                    .clone(),
            })
            .collect(),
        operations: vec![],
        inputs: vec![],
    };
    let mut evidence = Evidence {
        blobs,
        snapshot: snapshot.clone(),
        reject_native: false,
        omit_native_domain: false,
        overstate_repeatability: false,
        dependencies: BTreeMap::new(),
        pending_native_acknowledgements: Vec::new(),
        runtime,
    };
    let state = evidence.put(&serde_json::json!({"synthetic_native_state": true}));
    let coordinator =
        evidence.put(&serde_json::json!({"scheduler": snapshot, "runtime": evidence.runtime}));
    let mut owners = Vec::new();
    for owner in graph
        .owners()
        .filter(|owner| owner.owner_roles.contains(&id("capture")))
    {
        let mut hashes: Vec<_> = owner
            .node_bindings
            .iter()
            .map(|binding| binding.binding_hash.clone())
            .collect();
        hashes.sort();
        let binding = graph.binding(&owner.owner.participant_ids[0]).unwrap();
        owners.push(CapturedOwner {
            capture_owner_id: owner.owner.id.clone(),
            participant_ids: owner.owner.participant_ids.clone(),
            state_domain_ids: graph
                .ownership_policy()
                .domains
                .iter()
                .filter(|domain| domain.capture_owner_id == owner.owner.id)
                .map(|domain| domain.id.clone())
                .collect(),
            binding_hashes: hashes,
            state_schema: binding.compatibility.implementation.formats[0].clone(),
            representation: CaptureRepresentation::Durable,
            state_ref: Some(state.clone()),
            retained_source_ref: None,
            dependencies: graph
                .ownership_policy()
                .capture_owners
                .iter()
                .find(|policy| policy.owner_id == owner.owner.id)
                .unwrap()
                .dependencies
                .clone(),
            capture_receipt: state.clone(),
            extensions: Extensions::new(),
        });
    }
    let manifest = CaptureManifest {
        schema_version: 1,
        capture_id: id("capture/one"),
        world_binding_hash: graph.world_binding_hash().clone(),
        scenario_ref: graph.world().scenario_ref.clone(),
        preservation_contract: id("preservation/complete"),
        cut: cut(),
        event_ordinal: 7.into(),
        ordering_profile: "superdense-v1".into(),
        guarantees_ref: state.clone(),
        coordinator_state_ref: coordinator,
        owners,
        immutable_refs: super::validation::required_immutable_refs(graph, StateLimits::default())
            .unwrap(),
        provenance_ref: state,
        extensions: Extensions::new(),
    };
    let requirements = StateRequirements {
        preservation_contract: id("preservation/complete"),
        exact_model_continuation: true,
        deterministic: false,
        restore_mode: StateRestoreMode::DurableRestart,
    };
    (evidence, manifest, requirements)
}

fn verify(
    graph: &AdmittedGraph,
    evidence: &mut Evidence,
    manifest: &CaptureManifest,
    requirements: StateRequirements,
) -> Result<VerifiedCapture, StateError> {
    let mut bound = manifest.clone();
    bound.coordinator_state_ref = evidence.put(&serde_json::json!({
        "scheduler": evidence.snapshot, "runtime": evidence.runtime,
    }));
    let artifact = evidence.put(&bound);
    admit_capture(
        graph,
        &artifact,
        requirements,
        evidence,
        StateLimits::default(),
    )
}

#[test]
fn complete_capture_requires_authenticated_native_state_not_equal_metadata() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements.clone()).unwrap();
    assert_eq!(capture.manifest(), &manifest);
    assert!(
        capture
            .content()
            .get(&manifest.coordinator_state_ref)
            .is_some()
    );

    evidence.reject_native = true;
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements)
            .unwrap_err()
            .code,
        StateErrorCode::NativeEvidence
    );
}

#[test]
fn owner_domain_dependency_and_immutable_omissions_fail_closed() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let mut missing_owner = manifest.clone();
    missing_owner.owners.pop();
    let mut missing_domain = manifest.clone();
    missing_domain.owners[0].state_domain_ids.pop();
    let mut missing_dependency = manifest.clone();
    missing_dependency.owners[0].dependencies.clear();
    let mut missing_immutable = manifest.clone();
    missing_immutable.immutable_refs.clear();

    for changed in [
        missing_owner,
        missing_domain,
        missing_dependency,
        missing_immutable,
    ] {
        assert_eq!(
            verify(&graph, &mut evidence, &changed, requirements.clone())
                .unwrap_err()
                .code,
            StateErrorCode::IncompleteClosure
        );
    }
}

#[test]
fn actual_binding_and_native_schema_mismatch_refuse_backend_substitution() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let mut binding = manifest.clone();
    binding.owners[0].binding_hashes[0].digest = "0".repeat(64);
    let mut schema = manifest;
    schema.owners[0].state_schema.version += 1;

    for changed in [binding, schema] {
        assert_eq!(
            verify(&graph, &mut evidence, &changed, requirements.clone())
                .unwrap_err()
                .code,
            StateErrorCode::Incompatible
        );
    }
}

#[test]
fn durable_restart_refuses_retained_native_source() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, mut manifest, requirements) = setup(&graph, blobs);
    let owner = &mut manifest.owners[0];
    owner.representation = CaptureRepresentation::RetainedSource;
    owner.retained_source_ref = owner.state_ref.take();

    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements)
            .unwrap_err()
            .code,
        StateErrorCode::Incompatible
    );
}

#[test]
fn exact_state_does_not_upgrade_nondeterministic_execution() {
    let (graph, blobs) = test_nondeterministic_fixture_with_content();
    let (mut evidence, manifest, mut requirements) = setup(&graph, blobs);
    assert_eq!(graph.world_repeatability(), Repeatability::Nondeterministic);
    let captured = verify(&graph, &mut evidence, &manifest, requirements.clone()).unwrap();
    assert_eq!(
        captured.world_repeatability(),
        Repeatability::Nondeterministic
    );

    requirements.deterministic = true;
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements)
            .unwrap_err()
            .code,
        StateErrorCode::Incompatible
    );
    evidence.overstate_repeatability = true;
    let (_, _, requirements) = setup(&graph, BTreeMap::new());
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements)
            .unwrap_err()
            .code,
        StateErrorCode::IncompleteClosure
    );
}

#[test]
fn native_domain_or_coordinator_cut_omission_cannot_publish_complete_capture() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    evidence.omit_native_domain = true;
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements.clone())
            .unwrap_err()
            .code,
        StateErrorCode::IncompleteClosure
    );
    evidence.omit_native_domain = false;
    evidence.snapshot.capture_ordinal = 8.into();
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements)
            .unwrap_err()
            .code,
        StateErrorCode::IncompleteClosure
    );
}

#[test]
fn corrupt_content_and_missing_transitive_dependency_refuse_capture() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let dependency =
        canonical::content_ref(b"missing dependency", "application/octet-stream").unwrap();
    evidence.dependencies.insert(
        manifest.provenance_ref.hash.digest.clone(),
        vec![dependency],
    );
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements.clone())
            .unwrap_err()
            .code,
        StateErrorCode::Content
    );
    evidence.dependencies.clear();
    evidence
        .blobs
        .get_mut(&manifest.provenance_ref.hash.digest)
        .unwrap()[0] ^= 1;
    assert_eq!(
        verify(&graph, &mut evidence, &manifest, requirements)
            .unwrap_err()
            .code,
        StateErrorCode::Content
    );
}

#[test]
fn content_ceilings_are_enforced_before_verified_capture_is_created() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let artifact = evidence.put(&manifest);
    let limits = StateLimits {
        maximum_total_content_bytes: artifact.length.get() as usize,
        ..StateLimits::default()
    };
    assert_eq!(
        admit_capture(&graph, &artifact, requirements.clone(), &evidence, limits)
            .unwrap_err()
            .code,
        StateErrorCode::ResourceLimit
    );
    let limits = StateLimits {
        maximum_content_objects: 1,
        ..StateLimits::default()
    };
    assert_eq!(
        admit_capture(&graph, &artifact, requirements, &evidence, limits)
            .unwrap_err()
            .code,
        StateErrorCode::ResourceLimit
    );
}

#[test]
fn noncanonical_manifest_and_nested_extensions_are_refused() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, mut manifest, requirements) = setup(&graph, blobs);
    let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let artifact = canonical::content_ref(&bytes, "application/json").unwrap();
    evidence.blobs.insert(artifact.hash.digest.clone(), bytes);
    assert_eq!(
        admit_capture(
            &graph,
            &artifact,
            requirements.clone(),
            &evidence,
            StateLimits::default()
        )
        .unwrap_err()
        .code,
        StateErrorCode::Schema
    );
    manifest.owners[0]
        .state_schema
        .extensions
        .insert("unregistered".into(), serde_json::json!(true));
    assert!(verify(&graph, &mut evidence, &manifest, requirements).is_err());
}

struct Staging {
    nodes: Option<Vec<Box<dyn SimulationNode>>>,
    marker: ContentRef,
    prepared: Vec<Id>,
    fail_owner: Option<Id>,
    quarantine: Rc<Cell<usize>>,
    omit_domain: bool,
    fail_containment: bool,
    supervision: Rc<RefCell<Vec<(ActivationRecord, PublicationKnowledge)>>>,
    reject_continuation: bool,
    resource_watch: Option<Rc<Cell<bool>>>,
    owned_resource: Option<ModelNativeResource>,
}

struct ModelNativeResource(Rc<Cell<bool>>);

impl Drop for ModelNativeResource {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl crate::node_contract::NativeRuntimeContinuationVerifier for Staging {
    fn verify_runtime_continuation(
        &mut self,
        snapshot: &crate::node_contract::RuntimeSnapshot,
        _: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<
        crate::node_contract::NativeRuntimeContinuationEvidence,
        crate::node_contract::RuntimeError,
    > {
        if self.reject_continuation {
            return Err(crate::node_contract::RuntimeError::InvalidReceipt);
        }
        let input_acknowledgements = snapshot
            .inputs
            .iter()
            .filter_map(|input| input.acknowledgement.as_ref())
            .map(|ack| {
                let mut ack = ack.clone();
                ack.owners = ack
                    .owners
                    .iter()
                    .map(|source| {
                        target
                            .owners
                            .iter()
                            .find(|fresh| fresh.owner == source.owner)
                            .unwrap()
                            .clone()
                    })
                    .collect();
                ack.proof_ref = self.marker.clone();
                ack
            })
            .collect();
        Ok(crate::node_contract::NativeRuntimeContinuationEvidence {
            proof: self.marker.clone(),
            input_acknowledgements,
        })
    }
}

impl NativeRestoreStaging for Staging {
    fn reservations(&self) -> RestoreReservations {
        RestoreReservations {
            memory_bytes: 4096,
            processes: 2,
            descriptors: 4,
            ..RestoreReservations::default()
        }
    }
    fn original_disposition(&self) -> OriginalWorldDisposition {
        OriginalWorldDisposition::StoppedAwaitingReconciliation
    }
    fn prepare_owner(
        &mut self,
        capture: &VerifiedCapture,
        owner: &CapturedOwner,
        activation: &ActivationRecord,
    ) -> Result<RestoredOwnerAttestation, StateError> {
        if self.owned_resource.is_none()
            && let Some(watch) = &self.resource_watch
        {
            watch.set(true);
            self.owned_resource = Some(ModelNativeResource(Rc::clone(watch)));
        }
        if self.fail_owner.as_ref() == Some(&owner.capture_owner_id) {
            return Err(StateError::new(
                StateErrorCode::NativeEvidence,
                owner.capture_owner_id.as_str(),
                "native restore failed",
            ));
        }
        self.prepared.push(owner.capture_owner_id.clone());
        let mut domains = owner.state_domain_ids.clone();
        if self.omit_domain {
            domains.pop();
        }
        Ok(RestoredOwnerAttestation {
            identity: activation
                .owners
                .iter()
                .find(|identity| identity.owner == owner.capture_owner_id)
                .unwrap()
                .clone(),
            state_domain_ids: domains,
            binding_hashes: owner.binding_hashes.clone(),
            cut: capture.manifest.cut,
            event_ordinal: capture.manifest.event_ordinal,
            state_inventory: self.marker.clone(),
            ready_receipt: self.marker.clone(),
        })
    }
    fn verify_prepared_owner(
        &self,
        _: &VerifiedCapture,
        _: &ActivationRecord,
        _: &RestoredOwnerAttestation,
    ) -> Result<(), StateError> {
        Ok(())
    }
    fn prepare_coordinator(
        &mut self,
        _: &VerifiedCapture,
        _: &ActivationRecord,
    ) -> Result<ContentRef, StateError> {
        Ok(self.marker.clone())
    }
    fn verify_prepared_world(
        &self,
        capture: &VerifiedCapture,
        _: &ActivationRecord,
        owners: &[RestoredOwnerAttestation],
        _: &ContentRef,
    ) -> Result<(), StateError> {
        assert_eq!(self.prepared.len(), capture.manifest.owners.len());
        assert_eq!(owners.len(), capture.manifest.owners.len());
        Ok(())
    }
    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError> {
        self.nodes.take().ok_or_else(|| {
            StateError::new(
                StateErrorCode::Restoration,
                "fixture",
                "already transferred",
            )
        })
    }
    fn contain_uncertain_publication(&mut self, _: &ActivationRecord) -> Result<(), StateError> {
        if self.fail_containment {
            Err(StateError::new(
                StateErrorCode::NativeEvidence,
                "uncertain publication containment",
                "native containment could not be authenticated",
            ))
        } else {
            Ok(())
        }
    }
    fn quarantine_resources(
        &mut self,
        activation: &ActivationRecord,
        publication: PublicationKnowledge,
    ) {
        self.quarantine.set(self.quarantine.get() + 1);
        self.supervision
            .borrow_mut()
            .push((activation.clone(), publication));
    }
    fn poll_reclamation(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StateError>> {
        self.owned_resource.take();
        Poll::Ready(Ok(()))
    }
}

struct Driver {
    staging: Option<Staging>,
    calls: usize,
    supervision: Rc<RefCell<Vec<(ActivationRecord, PublicationKnowledge)>>>,
    runtime_supervision: Rc<RefCell<Option<crate::node_contract::WholeRuntimeCustody>>>,
    prepared_supervision: Rc<RefCell<Option<crate::node_contract::WholeRuntimeCustody>>>,
    reserved_slots: Cell<usize>,
}

struct RuntimeSlot(Rc<RefCell<Option<crate::node_contract::WholeRuntimeCustody>>>);

impl crate::node_contract::RuntimeCustodySlot for RuntimeSlot {
    fn validate_world(
        &self,
        _: &ActivationRecord,
        _: crate::node_contract::RuntimeLimits,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        Ok(())
    }

    fn retain(self: Box<Self>, custody: crate::node_contract::WholeRuntimeCustody) {
        let mut retained = self.0.borrow_mut();
        assert!(retained.is_none());
        *retained = Some(custody);
    }
}

impl crate::node_contract::RuntimeCustodySupervisor for Driver {
    fn reserve_world(
        &self,
        _: &ActivationRecord,
        _: crate::node_contract::RuntimeLimits,
    ) -> Result<Box<dyn crate::node_contract::RuntimeCustodySlot>, crate::node_contract::RuntimeError>
    {
        if self.runtime_supervision.borrow().is_some() {
            return Err(crate::node_contract::RuntimeError::ResourceLimit);
        }
        let mailbox = match self.reserved_slots.get() {
            0 => &self.prepared_supervision,
            1 => &self.runtime_supervision,
            _ => return Err(crate::node_contract::RuntimeError::ResourceLimit),
        };
        self.reserved_slots.set(self.reserved_slots.get() + 1);
        Ok(Box::new(RuntimeSlot(Rc::clone(mailbox))))
    }
}

impl WorldRestoreDriver for Driver {
    fn stage_world(
        &mut self,
        _: &AdmittedGraph,
        _: &VerifiedCapture,
        _: &ActivationRecord,
        _: StateLimits,
        allocation: &mut PreparedRestoreAllocation,
    ) -> Result<(), StateError> {
        self.calls += 1;
        allocation.install_capsule(Box::new(self.staging.take().unwrap()))
    }
}

fn activation(graph: &AdmittedGraph) -> ActivationRecord {
    ActivationRecord {
        generation: 2.into(),
        activation_id: id("replacement/activation"),
        world_binding_hash: graph.world_binding_hash().clone(),
        boundary: cut(),
        owners: graph
            .owners()
            .map(|owner| {
                let binding = graph.binding(&owner.owner.participant_ids[0]).unwrap();
                OwnerIdentity {
                    owner: owner.owner.id.clone(),
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                }
            })
            .collect(),
    }
}

fn driver(graph: &AdmittedGraph, marker: ContentRef, quarantine: Rc<Cell<usize>>) -> Driver {
    let supervision = Rc::new(RefCell::new(Vec::new()));
    Driver {
        staging: Some(Staging {
            nodes: Some(crate::node_contract::test_nodes(graph)),
            marker,
            prepared: Vec::new(),
            fail_owner: None,
            quarantine,
            omit_domain: false,
            fail_containment: false,
            supervision: Rc::clone(&supervision),
            reject_continuation: false,
            resource_watch: None,
            owned_resource: None,
        }),
        calls: 0,
        supervision,
        runtime_supervision: Rc::new(RefCell::new(None)),
        prepared_supervision: Rc::new(RefCell::new(None)),
        reserved_slots: Cell::new(0),
    }
}

#[test]
fn prepared_capsule_and_complete_source_survive_all_borrowers_and_callback_unwind() {
    use crate::node_contract::{RuntimeCustodyQueue, RuntimeCustodySupervisor, RuntimeLimits};

    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let source = Rc::new(verify(&graph, &mut evidence, &manifest, requirements).unwrap());
    let weak = Rc::downgrade(&source);
    let target = activation(&graph);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let slot = queue
        .reserve_world(&target, RuntimeLimits::default())
        .unwrap();
    let watch = Rc::new(Cell::new(false));
    let mut fixture = driver(&graph, manifest.provenance_ref, Rc::new(Cell::new(0)));
    let mut capsule = fixture.staging.take().unwrap();
    capsule.resource_watch = Some(Rc::clone(&watch));
    let mut allocation = PreparedRestoreAllocation::new(
        slot,
        Rc::clone(&source),
        target.clone(),
        RuntimeLimits::default(),
    );
    drop(fixture);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        allocation.install_capsule(Box::new(capsule)).unwrap();
        allocation
            .capsule_mut()
            .unwrap()
            .prepare_owner(&source, &source.manifest().owners[0], &target)
            .unwrap();
        assert!(watch.get());
        drop(source);
        panic!("model native preparation callback unwound");
    }));
    drop(allocation);

    assert!(result.is_err());
    assert!(watch.get());
    assert!(weak.upgrade().is_some());
    assert_eq!(queue.retained_worlds(), 1);
    assert!(
        queue
            .reserve_world(&target, RuntimeLimits::default())
            .is_err()
    );
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert!(!watch.get());
    assert!(weak.upgrade().is_none());
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn complete_restore_reserves_capsule_and_runtime_capacity_before_native_allocation() {
    use crate::node_contract::{
        RuntimeCustodyQueue, RuntimeCustodySlot, RuntimeCustodySupervisor, RuntimeError,
        RuntimeLimits,
    };
    struct QueueDriver {
        queue: RuntimeCustodyQueue,
        fixture: Driver,
    }
    impl RuntimeCustodySupervisor for QueueDriver {
        fn reserve_world(
            &self,
            activation: &ActivationRecord,
            limits: RuntimeLimits,
        ) -> Result<Box<dyn RuntimeCustodySlot>, RuntimeError> {
            self.queue.reserve_world(activation, limits)
        }
    }
    impl WorldRestoreDriver for QueueDriver {
        fn stage_world(
            &mut self,
            graph: &AdmittedGraph,
            capture: &VerifiedCapture,
            activation: &ActivationRecord,
            limits: StateLimits,
            allocation: &mut PreparedRestoreAllocation,
        ) -> Result<(), StateError> {
            self.fixture
                .stage_world(graph, capture, activation, limits, allocation)
        }
    }
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let watch = Rc::new(Cell::new(false));
    let mut fixture = driver(&graph, manifest.provenance_ref, Rc::new(Cell::new(0)));
    fixture.staging.as_mut().unwrap().resource_watch = Some(Rc::clone(&watch));
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let mut driver = QueueDriver {
        queue: queue.clone(),
        fixture,
    };

    let result = stage_restore(
        &graph,
        capture,
        activation(&graph),
        &mut driver,
        StateLimits::default(),
    );

    assert!(result.is_err());
    assert_eq!(driver.fixture.calls, 0);
    assert!(!watch.get());
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn saved_live_authority_cannot_start_native_restore() {
    let (graph, blobs) = test_fixture_with_content();
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let mut target = activation(&graph);
    target.owners[0] = capture.source_owners[0].clone();
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, quarantine);
    let failure = match stage_restore(&graph, capture, target, &mut driver, StateLimits::default())
    {
        Err(failure) => failure,
        Ok(_) => panic!("saved live authority accepted"),
    };
    assert_eq!(failure.error.code, StateErrorCode::StaleAuthority);
    assert_eq!(driver.calls, 0);
}

#[test]
fn committed_scheduler_state_does_not_erase_pending_native_acknowledgement() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    retain_pending_ack(&mut evidence);
    assert!(evidence.snapshot.reservations.is_empty());
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    assert_eq!(
        capture.pending_native_acknowledgements(),
        &[id("operation/already-used")]
    );
    let target = activation(&graph);
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    driver.staging.as_mut().unwrap().reject_continuation = true;

    let failure = match stage_restore(
        &graph,
        capture,
        target.clone(),
        &mut driver,
        StateLimits::default(),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("pending native acknowledgement custody disappeared on restore"),
    };

    assert_eq!(failure.error.component, "runtime continuation");
    assert_eq!(
        failure.publication_knowledge(),
        PublicationKnowledge::NotAttempted
    );
    assert_eq!(failure.original_activation(), Some(&target));
    assert_eq!(driver.calls, 1);
    assert!(quarantine.get() > 0);
}

fn retain_pending_ack(evidence: &mut Evidence) {
    use crate::node_contract::{
        ExactBoundaryPolicy, Lifecycle, NodeRoute, OperationOutcome, OperationRequest,
        ProgressEvidence, SavedRuntimeOperation, SavedRuntimeResult, SavedSchedulingCommit,
        StopReason,
    };
    let owner = evidence.runtime.owners[0].identity.clone();
    let operation = id("operation/already-used");
    evidence.runtime.owners[0].operation = Some(operation.clone());
    evidence.runtime.owners[0].lifecycle = Lifecycle::Executing;
    evidence.runtime.operations = vec![SavedRuntimeOperation {
        operation: operation.clone(),
        route: NodeRoute {
            node: id("a"),
            owners: vec![owner.clone()],
        },
        request: OperationRequest::ExactRun {
            start: Position::new(99.into(), 0.into(), Phase::BoundaryControl),
            limit: cut(),
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        },
        input_batch: None,
        result: SavedRuntimeResult::Complete(OperationOutcome {
            operation: operation.clone(),
            node: id("a"),
            owners: vec![owner],
            progress: ProgressEvidence::Exact {
                reached: cut(),
                stop: StopReason::HorizonPark,
            },
            retained_outputs: vec![],
            scheduling: None,
        }),
        close_submission: None,
        submission_effects: None,
        scheduling_commit: Some(SavedSchedulingCommit {
            node: id("a"),
            operation: operation.clone(),
            retained_outputs: vec![],
        }),
    }];
    evidence.pending_native_acknowledgements = vec![operation];
}

#[test]
fn authenticated_pending_ack_restores_cached_completion_without_rerunning_native_work() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    retain_pending_ack(&mut evidence);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::new(Cell::new(0)));
    let prepared = match stage_restore(
        &graph,
        capture,
        activation(&graph),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!(
            "authentic original ACK continuation refused: {}",
            failure.error
        ),
    };
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::Committed,
        reconcile: crate::node_contract::PublicationStatus::Committed,
        records: vec![],
    };
    let mut restored = match prepared.publish(&mut publisher) {
        RestorePublication::Committed(world) => world,
        _ => panic!("authentic original ACK continuation did not publish"),
    };
    let runtime = restored.runtime_mut();
    let token = runtime.recover(&id("operation/already-used")).unwrap();
    let commit = runtime.recover_scheduling_commit(&token).unwrap();
    assert_eq!(token.route().owners[0].generation.get(), 2);
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        runtime.poll(&token, &mut context),
        Poll::Ready(Ok(_))
    ));
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    assert!(
        runtime
            .runtime_snapshot(cut(), 7.into(), 8 * 1024 * 1024)
            .unwrap()
            .pending_acknowledgements()
            .is_empty()
    );
    drop(restored);
    let supervised = driver.runtime_supervision.borrow();
    let custody = supervised.as_ref().unwrap();
    assert_eq!(custody.operation_count(), 1);
    assert_eq!(
        custody.publication_status(),
        Some(crate::node_contract::PublicationStatus::Committed)
    );
}

struct Publisher {
    publish: crate::node_contract::PublicationStatus,
    reconcile: crate::node_contract::PublicationStatus,
    records: Vec<ActivationRecord>,
}

impl crate::node_contract::ActivationPublisher for Publisher {
    fn publish(&mut self, record: &ActivationRecord) -> crate::node_contract::PublicationStatus {
        self.records.push(record.clone());
        self.publish
    }

    fn reconcile(&mut self, record: &ActivationRecord) -> crate::node_contract::PublicationStatus {
        self.records.push(record.clone());
        self.reconcile
    }
}

#[test]
fn complete_restore_publishes_one_fresh_world_and_preserves_scheduler() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let artifact = capture.artifact().clone();
    let target = activation(&graph);
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    let prepared = match stage_restore(
        &graph,
        capture,
        target.clone(),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("model restore refused: {}", failure.error),
    };
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::Committed,
        reconcile: crate::node_contract::PublicationStatus::Committed,
        records: vec![],
    };
    assert_eq!(quarantine.get(), 0);
    let mut restored = match prepared.publish(&mut publisher) {
        RestorePublication::Committed(world) => world,
        _ => panic!("complete model restoration did not publish"),
    };
    assert_eq!(restored.activation().record(), &target);
    assert_eq!(restored.artifact(), &artifact);
    assert_eq!(publisher.records, vec![target]);

    let activation = restored.activation().clone();
    let scheduler = restored
        .runtime_mut()
        .scheduler(&graph, &activation)
        .unwrap();
    let snapshot = scheduler.snapshot(cut(), 7.into()).unwrap();
    assert_eq!(snapshot.positions, evidence.snapshot.positions);
    assert_eq!(snapshot.producers, evidence.snapshot.producers);
    assert_eq!(snapshot.used_operations, evidence.snapshot.used_operations);
    drop(restored);
    assert!(quarantine.get() > 0);
}

#[test]
fn uncertain_restore_retains_original_generation_until_reconciliation() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let target = activation(&graph);
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    let prepared = match stage_restore(
        &graph,
        capture,
        target.clone(),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("model restore refused: {}", failure.error),
    };
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::Unknown,
        reconcile: crate::node_contract::PublicationStatus::Committed,
        records: vec![],
    };
    let pending = match prepared.publish(&mut publisher) {
        RestorePublication::Uncertain(pending) => pending,
        _ => panic!("uncertain publication exposed a completed world"),
    };
    assert_eq!(pending.original_activation(), &target);
    assert_eq!(quarantine.get(), 0);
    let restored = match pending.reconcile(&mut publisher) {
        RestorePublication::Committed(world) => world,
        _ => panic!("committed reconciliation did not recover original world"),
    };
    assert_eq!(publisher.records, vec![target.clone(), target]);
    assert_eq!(driver.calls, 1);
    drop(restored);
    assert!(quarantine.get() > 0);
}

#[test]
fn failure_of_later_owner_contains_entire_staged_world() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    driver.staging.as_mut().unwrap().fail_owner = Some(id("owner/z"));
    let failure = match stage_restore(
        &graph,
        capture,
        activation(&graph),
        &mut driver,
        StateLimits::default(),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("partial world accepted as prepared"),
    };
    assert_eq!(failure.error.code, StateErrorCode::NativeEvidence);
    assert_eq!(
        failure.original,
        OriginalWorldDisposition::StoppedAwaitingReconciliation
    );
    assert!(quarantine.get() > 0);
    drop(failure);
    assert!(quarantine.get() > 1);
}

#[test]
fn restored_domain_omission_and_resource_excess_cannot_reach_publication() {
    for omit_domain in [true, false] {
        let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
        let (mut evidence, manifest, requirements) = setup(&graph, blobs);
        let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
        let quarantine = Rc::new(Cell::new(0));
        let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
        driver.staging.as_mut().unwrap().omit_domain = omit_domain;
        let limits = if omit_domain {
            StateLimits::default()
        } else {
            StateLimits {
                maximum_native_memory_bytes: 4095,
                ..StateLimits::default()
            }
        };
        let failure = match stage_restore(&graph, capture, activation(&graph), &mut driver, limits)
        {
            Err(failure) => failure,
            Ok(_) => panic!("incomplete or over-reserved world prepared"),
        };
        assert_eq!(
            failure.error.code,
            if omit_domain {
                StateErrorCode::IncompleteClosure
            } else {
                StateErrorCode::ResourceLimit
            }
        );
        assert!(quarantine.get() > 0);
    }
}

#[test]
fn denied_durable_publication_retains_failed_world_custody() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    let prepared = match stage_restore(
        &graph,
        capture,
        activation(&graph),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("model restore refused: {}", failure.error),
    };
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::NotCommitted,
        reconcile: crate::node_contract::PublicationStatus::NotCommitted,
        records: vec![],
    };
    let mut failure = match prepared.publish(&mut publisher) {
        RestorePublication::Failed(failure) => failure,
        _ => panic!("denied publication exposed replacement authority"),
    };
    assert_eq!(publisher.records.len(), 1);
    assert_eq!(failure.error.code, StateErrorCode::Restoration);
    assert_eq!(
        failure.publication_knowledge(),
        PublicationKnowledge::NotCommitted
    );
    assert!(failure.quarantined_runtime().is_some());
    assert!(quarantine.get() > 0);
}

#[test]
fn failed_uncertain_containment_preserves_original_publication_for_reconciliation() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let target = activation(&graph);
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    driver.staging.as_mut().unwrap().fail_containment = true;
    let prepared = match stage_restore(
        &graph,
        capture,
        target.clone(),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("model restore refused: {}", failure.error),
    };
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::Unknown,
        reconcile: crate::node_contract::PublicationStatus::Committed,
        records: vec![],
    };

    let mut failure = match prepared.publish(&mut publisher) {
        RestorePublication::Failed(failure) => failure,
        _ => panic!("unauthenticated containment exposed a replacement world"),
    };

    assert_eq!(
        failure.publication_knowledge(),
        PublicationKnowledge::Unknown
    );
    assert_eq!(failure.original_activation(), Some(&target));
    assert!(failure.quarantined_runtime().is_some());
    assert!(quarantine.get() > 0);
    assert_eq!(
        failure.reconcile_publication(&mut publisher).unwrap(),
        PublicationKnowledge::Committed
    );
    assert_eq!(failure.original_activation(), Some(&target));
    assert_eq!(publisher.records, vec![target.clone(), target]);
    assert_eq!(driver.calls, 1);
    assert!(failure.reconcile_publication(&mut publisher).is_err());
    assert_eq!(publisher.records.len(), 2);
    let supervision = Rc::clone(&driver.supervision);
    drop(failure);
    assert!(supervision.borrow().iter().all(|(record, knowledge)| {
        record == &publisher.records[0]
            && matches!(
                knowledge,
                PublicationKnowledge::Unknown | PublicationKnowledge::Committed
            )
    }));
    assert_eq!(
        supervision.borrow().last(),
        Some(&(
            publisher.records[0].clone(),
            PublicationKnowledge::Committed
        ))
    );
}

#[test]
fn post_commit_continuation_failure_cannot_erase_committed_generation() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(false);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let target = activation(&graph);
    let quarantine = Rc::new(Cell::new(0));
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::clone(&quarantine));
    let mut prepared = match stage_restore(
        &graph,
        capture,
        target.clone(),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("model restore refused: {}", failure.error),
    };
    // A local continuation invariant fails after durable publication. Failure
    // must preserve the committed record even though no runnable world returns.
    prepared.lose_prepared_scheduler_for_test();
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::Committed,
        reconcile: crate::node_contract::PublicationStatus::NotCommitted,
        records: vec![],
    };

    let mut failure = match prepared.publish(&mut publisher) {
        RestorePublication::Failed(failure) => failure,
        _ => panic!("missing continuation exposed a replacement world"),
    };

    assert_eq!(
        failure.publication_knowledge(),
        PublicationKnowledge::Committed
    );
    assert_eq!(failure.original_activation(), Some(&target));
    assert_eq!(failure.error.component, "restored scheduler");
    assert!(failure.quarantined_runtime().is_some());
    assert!(quarantine.get() > 0);
    assert!(failure.reconcile_publication(&mut publisher).is_err());
    assert_eq!(publisher.records, vec![target]);
    let supervision = Rc::clone(&driver.supervision);
    drop(failure);
    assert!(!supervision.borrow().is_empty());
    assert!(supervision.borrow().iter().all(|(record, knowledge)| {
        record == &publisher.records[0] && *knowledge == PublicationKnowledge::Committed
    }));
}

#[test]
fn exact_restoration_preserves_nondeterministic_world_classification() {
    let (graph, blobs) = crate::node_admission::test_restore_fixture_with_content(true);
    let (mut evidence, manifest, requirements) = setup(&graph, blobs);
    let capture = verify(&graph, &mut evidence, &manifest, requirements).unwrap();
    let mut driver = driver(&graph, manifest.provenance_ref, Rc::new(Cell::new(0)));
    let prepared = match stage_restore(
        &graph,
        capture,
        activation(&graph),
        &mut driver,
        StateLimits::default(),
    ) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("model restore refused: {}", failure.error),
    };
    let mut publisher = Publisher {
        publish: crate::node_contract::PublicationStatus::Committed,
        reconcile: crate::node_contract::PublicationStatus::Committed,
        records: vec![],
    };
    let restored = match prepared.publish(&mut publisher) {
        RestorePublication::Committed(world) => world,
        _ => panic!("complete model restoration did not publish"),
    };
    assert_eq!(
        restored.world_repeatability(),
        Repeatability::Nondeterministic
    );
}

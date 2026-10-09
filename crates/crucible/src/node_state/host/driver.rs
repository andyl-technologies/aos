//! Native host reconstruction beneath closed gates and original custody retention.

use std::{
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
};

use crucible_node_contract::{CapturedOwner, ContentRef, Id, canonical};

use crate::node_adapters::{HostModelNode, HostModelResources};
use crate::node_admission::AdmittedGraph;
use crate::node_contract::{
    ActivationRecord, NativeRuntimeContinuationEvidence, NativeRuntimeContinuationVerifier,
    RuntimeCustodyQueue, RuntimeCustodySlot, RuntimeCustodySupervisor, RuntimeError, RuntimeLimits,
    RuntimeSnapshot, SimulationNode,
};
use crate::node_scheduling::SchedulingSnapshot;

use super::super::{
    NativeRestoreStaging, OriginalWorldDisposition, PreparedRestoreAllocation,
    PublicationKnowledge, RestoreReservations, RestoredOwnerAttestation, StateError, StateLimits,
    VerifiedCapture, WorldRestoreDriver, schema,
};
use super::archive::refusal;
use super::{
    AuthenticatedHostSource, HostArchiveRecord, HostWorldFactory, native_failure,
    require_supported_extensions,
};

/// Restores actual local host models from an authenticated durable source archive.
///
/// The caller keeps the actor-local queue alive and polls authenticated cleanup
/// until every reserved slot is retired, including after borrower cancellation.
/// The factory belongs to the installed host and measures its actual models.
/// No legacy checkpoint writer or cross-backend conversion is introduced.
pub struct HostWorldRestoreDriver {
    graph: Rc<AdmittedGraph>,
    archive: HostArchiveRecord,
    factory: Rc<dyn HostWorldFactory>,
    custody: RuntimeCustodyQueue,
}

impl HostWorldRestoreDriver {
    /// Binds one authenticated archive, sealed fresh graph and installed factory.
    ///
    /// # Errors
    /// Refuses a changed world binding before any native resources are allocated.
    pub fn new(
        graph: Rc<AdmittedGraph>,
        archive: HostArchiveRecord,
        factory: Rc<dyn HostWorldFactory>,
        custody: RuntimeCustodyQueue,
    ) -> Result<Self, StateError> {
        require_supported_extensions(&graph)?;
        if graph.world_binding_hash() != &archive.manifest().world_binding_hash {
            return Err(refusal(
                "host restore backend or immutable world binding differs",
            ));
        }
        Ok(Self {
            graph,
            archive,
            factory,
            custody,
        })
    }
}

impl RuntimeCustodySupervisor for HostWorldRestoreDriver {
    fn reserve_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Box<dyn RuntimeCustodySlot>, RuntimeError> {
        self.custody.reserve_world(activation, limits)
    }
}

impl WorldRestoreDriver for HostWorldRestoreDriver {
    fn stage_world(
        &mut self,
        graph: &AdmittedGraph,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        limits: StateLimits,
        allocation: &mut PreparedRestoreAllocation,
    ) -> Result<(), StateError> {
        require_supported_extensions(graph)?;
        if capture.artifact() != self.archive.artifact()
            || capture.manifest() != self.archive.manifest()
            || graph.world() != self.graph.world()
            || graph
                .node_ids()
                .any(|node| graph.binding(node) != self.graph.binding(node))
        {
            return Err(refusal("signed source or actual fresh graph differs"));
        }
        // Revalidate the exact authenticated byte registry, not only its public
        // digest. This guards a caller offering a different trusted verifier's
        // VerifiedCapture under the same manifest artifact.
        for object in &self.archive.body.objects {
            if capture.content().get(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(refusal(
                    "verified capture differs from authenticated source closure",
                ));
            }
        }
        let mut reservations = RestoreReservations::default();
        let resources = HostModelResources {
            maximum_capture_bytes: limits.maximum_content_bytes,
            ..HostModelResources::default()
        };
        for owner in &capture.manifest().owners {
            if owner.participant_ids.len() != 1 {
                return Err(refusal(
                    "host restore requires exclusive one-node capture owners",
                ));
            }
            let node = &owner.participant_ids[0];
            let native = capture
                .content()
                .get(
                    owner
                        .state_ref
                        .as_ref()
                        .ok_or_else(|| refusal("host durable state absent"))?,
                )
                .ok_or_else(|| refusal("host native source absent"))?;
            self.factory.authenticate_source(
                graph,
                node,
                native,
                &capture.runtime,
                capture.content(),
            )?;
            let reservation = self.factory.reservation(graph, node, native, resources)?;
            add_reservation(&mut reservations, reservation, limits)?;
        }
        let capsule = HostStaging {
            graph: self.graph.clone(),
            archive: self.archive.clone(),
            factory: self.factory.clone(),
            target: activation.clone(),
            reservations,
            resources,
            nodes: BTreeMap::new(),
            proofs: BTreeMap::new(),
            owners: BTreeMap::new(),
            coordinator: None,
            quarantined: false,
        };
        // Install the owning empty native capsule before actual model allocation.
        // All later prepare callbacks mutate that capsule under reserved custody.
        allocation.install_capsule(Box::new(capsule))
    }
}

struct HostStaging {
    graph: Rc<AdmittedGraph>,
    archive: HostArchiveRecord,
    factory: Rc<dyn HostWorldFactory>,
    target: ActivationRecord,
    reservations: RestoreReservations,
    resources: HostModelResources,
    nodes: BTreeMap<Id, HostModelNode>,
    proofs: BTreeMap<Id, NativeRuntimeContinuationEvidence>,
    owners: BTreeMap<Id, RestoredOwnerAttestation>,
    coordinator: Option<ContentRef>,
    quarantined: bool,
}

impl NativeRuntimeContinuationVerifier for HostStaging {
    fn verify_runtime_continuation(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        let bytes = &self
            .archive
            .object(&self.archive.manifest.coordinator_state_ref)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?
            .bytes;
        let saved: super::capture::Coordinator = serde_json::from_slice(bytes)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        if self.quarantined
            || target != &self.target
            || &saved.runtime != snapshot
            || &saved.scheduler != scheduling
            || self.proofs.len() != self.archive.manifest.owners.len()
            || self.coordinator.is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut acknowledgements = Vec::new();
        for proof in self.proofs.values() {
            acknowledgements.extend(proof.input_acknowledgements.iter().cloned());
        }
        acknowledgements.sort_by(|left, right| left.stage_operation.cmp(&right.stage_operation));
        let proof = self
            .receipt(&serde_json::json!({
                "schema_version":1,"artifact":self.archive.artifact(),"target":crate::node_contract::SavedRuntimeActivation::from(target),
                "native_proofs":self.proofs.values().map(|proof| &proof.proof).collect::<Vec<_>>(),
            }))
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        Ok(NativeRuntimeContinuationEvidence {
            proof,
            input_acknowledgements: acknowledgements,
        })
    }
}

impl NativeRestoreStaging for HostStaging {
    fn reservations(&self) -> RestoreReservations {
        self.reservations
    }

    fn original_disposition(&self) -> OriginalWorldDisposition {
        OriginalWorldDisposition::Unknown
    }

    fn prepare_owner(
        &mut self,
        capture: &VerifiedCapture,
        owner: &CapturedOwner,
        activation: &ActivationRecord,
    ) -> Result<RestoredOwnerAttestation, StateError> {
        if self.quarantined
            || activation != &self.target
            || capture.artifact() != self.archive.artifact()
            || self.owners.contains_key(&owner.capture_owner_id)
        {
            return Err(refusal(
                "host staging source, target or original owner differs",
            ));
        }
        let node = owner
            .participant_ids
            .first()
            .ok_or_else(|| refusal("host participant absent"))?;
        let native = capture
            .content()
            .get(
                owner
                    .state_ref
                    .as_ref()
                    .ok_or_else(|| refusal("host native state absent"))?,
            )
            .ok_or_else(|| refusal("host native source unavailable"))?;
        let authenticated = AuthenticatedHostSource {
            node,
            native,
            runtime: &capture.runtime,
            content: capture.content(),
        };
        let (actual, proof) = self.factory.prepare_node(
            &self.graph,
            node,
            &authenticated,
            activation,
            self.resources,
        )?;
        self.nodes.insert(node.clone(), actual);
        self.proofs.insert(node.clone(), proof);
        let actual = self
            .nodes
            .get_mut(node)
            .ok_or_else(|| refusal("prepared host native owner unavailable"))?;
        let ready = actual.arm(activation).map_err(native_failure)?;
        actual
            .validate_readiness(activation, &ready)
            .map_err(native_failure)?;
        let identity = ready
            .owners
            .iter()
            .find(|identity| identity.owner == owner.capture_owner_id)
            .ok_or_else(|| refusal("actual ready host capture owner absent"))?
            .clone();
        let attestation = RestoredOwnerAttestation {
            identity,
            state_domain_ids: owner.state_domain_ids.clone(),
            binding_hashes: owner.binding_hashes.clone(),
            cut: capture.manifest().cut,
            event_ordinal: capture.manifest().event_ordinal,
            state_inventory: ready.state_inventory,
            ready_receipt: ready.ready_receipt,
        };
        self.owners
            .insert(owner.capture_owner_id.clone(), attestation.clone());
        Ok(attestation)
    }

    fn verify_prepared_owner(
        &self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        attestation: &RestoredOwnerAttestation,
    ) -> Result<(), StateError> {
        let owner = capture
            .manifest()
            .owners
            .iter()
            .find(|owner| owner.capture_owner_id == attestation.identity.owner)
            .ok_or_else(|| refusal("prepared host capture owner absent"))?;
        let actual = self
            .nodes
            .get(&owner.participant_ids[0])
            .ok_or_else(|| refusal("actual prepared host node absent"))?;
        let ready = crate::node_contract::ReadyAttestation {
            owners: vec![attestation.identity.clone()],
            boundary: attestation.cut,
            state_inventory: attestation.state_inventory.clone(),
            ready_receipt: attestation.ready_receipt.clone(),
        };
        if activation != &self.target
            || self
                .owners
                .get(&attestation.identity.owner)
                .is_none_or(|saved| {
                    saved.identity != attestation.identity
                        || saved.state_domain_ids != attestation.state_domain_ids
                        || saved.binding_hashes != attestation.binding_hashes
                        || saved.cut != attestation.cut
                        || saved.event_ordinal != attestation.event_ordinal
                        || saved.state_inventory != attestation.state_inventory
                        || saved.ready_receipt != attestation.ready_receipt
                })
        {
            return Err(refusal("actual native prepared owner receipt differs"));
        }
        actual
            .validate_readiness(activation, &ready)
            .map_err(native_failure)
    }

    fn prepare_coordinator(
        &mut self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
    ) -> Result<ContentRef, StateError> {
        if activation != &self.target || self.owners.len() != capture.manifest().owners.len() {
            return Err(refusal(
                "host world owners are not completely inactive-ready",
            ));
        }
        let receipt = self.receipt(&serde_json::json!({ "schema_version":1,"coordinator":capture.manifest().coordinator_state_ref,"target":crate::node_contract::SavedRuntimeActivation::from(activation) }))?;
        self.coordinator = Some(receipt.clone());
        Ok(receipt)
    }

    fn verify_prepared_world(
        &self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        owners: &[RestoredOwnerAttestation],
        coordinator_receipt: &ContentRef,
    ) -> Result<(), StateError> {
        if self.quarantined
            || activation != &self.target
            || self.coordinator.as_ref() != Some(coordinator_receipt)
            || owners.len() != self.owners.len()
            || owners.len() != capture.manifest().owners.len()
        {
            return Err(refusal("host world ready barrier or coordinator differs"));
        }
        for owner in owners {
            self.verify_prepared_owner(capture, activation, owner)?;
        }
        Ok(())
    }

    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError> {
        if self.quarantined || self.coordinator.is_none() || self.nodes.len() != self.owners.len() {
            return Err(refusal("host prepared native transfer unavailable"));
        }
        Ok(std::mem::take(&mut self.nodes)
            .into_values()
            .map(|node| Box::new(node) as Box<dyn SimulationNode>)
            .collect())
    }

    fn contain_uncertain_publication(
        &mut self,
        activation: &ActivationRecord,
    ) -> Result<(), StateError> {
        if activation != &self.target {
            return Err(refusal("host containment generation differs"));
        }
        // Host models have no autonomous execution. Retaining them under closed
        // global gates contains every native effect without advancing the model.
        Ok(())
    }

    fn quarantine_resources(
        &mut self,
        _activation: &ActivationRecord,
        _publication: PublicationKnowledge,
    ) {
        self.quarantined = true;
        for native in self.nodes.values_mut() {
            native.quarantine_resources();
        }
    }

    fn poll_reclamation(&mut self, context: &mut Context<'_>) -> Poll<Result<(), StateError>> {
        if !self.quarantined {
            return Poll::Ready(Err(refusal(
                "host staging is not under original quarantine",
            )));
        }
        let Some(node) = self.nodes.keys().next().cloned() else {
            return Poll::Ready(Ok(()));
        };
        let native = match self.nodes.get_mut(&node) {
            Some(native) => native,
            None => return Poll::Ready(Err(refusal("retained host node disappeared"))),
        };
        let owner = match native.route().owners.first() {
            Some(owner) => owner.clone(),
            None => return Poll::Ready(Err(refusal("retained host native owner absent"))),
        };
        match native.poll_reclamation(&owner, context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(native_failure(error))),
            Poll::Ready(Ok(receipt)) => {
                if let Err(error) = native.validate_reclamation(&receipt) {
                    return Poll::Ready(Err(native_failure(error)));
                }
                self.nodes.remove(&node);
                if self.nodes.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}

impl HostStaging {
    fn receipt(&self, value: &impl serde::Serialize) -> Result<ContentRef, StateError> {
        let bytes = canonical::canonical_json(&serde_json::to_value(value).map_err(schema)?)
            .map_err(schema)?;
        canonical::content_ref(&bytes, "application/json").map_err(schema)
    }
}

fn add_reservation(
    total: &mut RestoreReservations,
    added: RestoreReservations,
    limits: StateLimits,
) -> Result<(), StateError> {
    total.memory_bytes = total
        .memory_bytes
        .checked_add(added.memory_bytes)
        .ok_or_else(|| refusal("host memory reservation exhausted"))?;
    total.writable_bytes = total
        .writable_bytes
        .checked_add(added.writable_bytes)
        .ok_or_else(|| refusal("host storage reservation exhausted"))?;
    total.processes = total
        .processes
        .checked_add(added.processes)
        .ok_or_else(|| refusal("host process reservation exhausted"))?;
    total.descriptors = total
        .descriptors
        .checked_add(added.descriptors)
        .ok_or_else(|| refusal("host descriptor reservation exhausted"))?;
    if total.memory_bytes > limits.maximum_native_memory_bytes
        || total.writable_bytes > limits.maximum_native_writable_bytes
        || total.processes > limits.maximum_native_processes
        || total.descriptors > limits.maximum_native_descriptors
    {
        return Err(refusal(
            "host native peak reservation exceeds complete world limits",
        ));
    }
    Ok(())
}

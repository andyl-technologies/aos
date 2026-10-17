//! Eager opaque replay custody before the signed source archive is retired.
//!
//! Complete source seals are decoded and verified while the archive is readable.
//! Every later callback owns those seals; no source filename or signing key is
//! copied, and no semantic request is executed during reconstruction.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible::{
    node_adapters::transcript::{
        AuthenticatedReplayContinuation, TranscriptReplayNode, authenticate_replay_continuation,
    },
    node_contract::{
        NativeRuntimeContinuationEvidence, NativeRuntimeContinuationVerifier, NodeRoute,
        RuntimeCustodyQueue, RuntimeCustodySlot, RuntimeCustodySupervisor, RuntimeError,
        RuntimeLimits, RuntimeSnapshot,
    },
    node_scheduling::SchedulingSnapshot,
    node_state::{
        NativeArchiveRecord, NativeRestoreStaging, OriginalWorldDisposition,
        PreparedRestoreAllocation, PublicationKnowledge, RestoreReservations,
        RestoredOwnerAttestation, StateError, StateLimits, StateRequirements, VerifiedCapture,
        WorldRestoreDriver,
    },
};
use crucible_node_contract::{CaptureManifest, CapturedOwner};

use super::continuation_factory::state_error;
use super::*;

pub(super) struct ReplayColdDriver {
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) target: ActivationRecord,
    allocation: Rc<cursor_allocation::CursorAllocation>,
    artifact: ContentRef,
    manifest: CaptureManifest,
    runtime: RuntimeSnapshot,
    scheduler: SchedulingSnapshot,
    pending: Option<BTreeMap<Id, AuthenticatedReplayContinuation>>,
    custody: RuntimeCustodyQueue,
    retained_bytes: u64,
}

impl ReplayColdDriver {
    pub(super) fn prepare(
        allocation: Rc<cursor_allocation::CursorAllocation>,
        archive: &NativeArchiveRecord,
        requirements: StateRequirements,
        custody: RuntimeCustodyQueue,
    ) -> Result<(Self, VerifiedCapture), StateError> {
        let admitted = allocation.admit_graph().map_err(state_error)?;
        let graph = Rc::new(
            Rc::try_unwrap(admitted)
                .map_err(|_| state_error("fresh replay graph has unexpected shared custody"))?,
        );
        let factory = continuation_factory::ReplayArchiveFactory {
            allocation: allocation.clone(),
        };
        let capture = archive.admit(&graph, requirements, &factory)?;
        let runtime = archive.runtime_snapshot()?;
        let scheduler = archive.scheduling_snapshot()?;
        let mut pending = BTreeMap::new();
        for owner in &capture.manifest().owners {
            let [node] = owner.participant_ids.as_slice() else {
                return Err(state_error("eager replay source owner is not exclusive"));
            };
            let original = archive.authenticated_source(
                &owner.capture_owner_id,
                &runtime,
                capture.content(),
            )?;
            let sealed = authenticate_replay_continuation(&original, node)
                .map_err(|error| state_error(error.reason))?;
            pending.insert(node.clone(), sealed);
        }
        if pending.len() != graph.node_ids().count() {
            return Err(state_error("eager complete replay source roster differs"));
        }
        Ok((
            Self {
                graph,
                target: allocation.profile().record.clone(),
                allocation,
                artifact: capture.artifact().clone(),
                manifest: capture.manifest().clone(),
                runtime,
                scheduler,
                pending: Some(pending),
                custody,
                retained_bytes: u64::try_from(capture.content().total_bytes())
                    .map_err(state_error)?,
            },
            capture,
        ))
    }

    pub(super) fn publisher(
        &self,
        stored: StoredWorldActivationPublisher,
    ) -> Result<super::continuation_publication::ReplayRestoredPublisher, StateError> {
        #[derive(serde::Serialize)]
        struct OriginalSource<'a, W: serde::Serialize, R: serde::Serialize> {
            artifact: &'a ContentRef,
            manifest: &'a CaptureManifest,
            original_runtime: &'a RuntimeSnapshot,
            original_scheduler: &'a SchedulingSnapshot,
            world: &'a W,
            world_repeatability: R,
        }
        let source = super::continuation_publication::bounded_value(&OriginalSource {
            artifact: &self.artifact,
            manifest: &self.manifest,
            original_runtime: &self.runtime,
            original_scheduler: &self.scheduler,
            world: self.graph.world(),
            world_repeatability: self.graph.world_repeatability(),
        })
        .map_err(state_error)?;
        Ok(
            super::continuation_publication::ReplayRestoredPublisher::new(
                stored,
                source,
                self.target.clone(),
            ),
        )
    }

    pub(super) fn cursors(
        &self,
    ) -> Result<BTreeMap<Id, crucible::node_adapters::transcript::ReplayCursorSnapshot>, StateError>
    {
        Ok(self
            .pending
            .as_ref()
            .ok_or_else(|| state_error("original cursor custody was transferred"))?
            .iter()
            .map(|(node, source)| (node.clone(), source.cursor().clone()))
            .collect())
    }
}

impl RuntimeCustodySupervisor for ReplayColdDriver {
    fn reserve_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Box<dyn RuntimeCustodySlot>, RuntimeError> {
        if activation != &self.target {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.custody.reserve_world(activation, limits)
    }
}

impl WorldRestoreDriver for ReplayColdDriver {
    fn stage_world(
        &mut self,
        graph: &AdmittedGraph,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        limits: StateLimits,
        allocation: &mut PreparedRestoreAllocation,
    ) -> Result<(), StateError> {
        if target != &self.target
            || capture.artifact() != &self.artifact
            || capture.manifest() != &self.manifest
            || graph.world() != self.graph.world()
            || graph
                .node_ids()
                .any(|node| graph.binding(node) != self.graph.binding(node))
        {
            return Err(state_error(
                "eager original replay source or target changed",
            ));
        }
        let memory = self
            .pending
            .as_ref()
            .ok_or_else(|| state_error("original replay source already transferred"))?
            .values()
            .try_fold(self.retained_bytes, |sum, source| {
                sum.checked_add(source.transcript().bytes().len() as u64)
            })
            .and_then(|sum| sum.checked_mul(16))
            .ok_or_else(|| state_error("replay memory reservation overflow"))?;
        if memory > limits.maximum_native_memory_bytes {
            return Err(state_error(
                "eager complete replay exceeds memory reservation",
            ));
        }
        let capsule = ReplayStaging {
            graph: self.graph.clone(),
            target: target.clone(),
            artifact: self.artifact.clone(),
            manifest: self.manifest.clone(),
            runtime: self.runtime.clone(),
            scheduler: self.scheduler.clone(),
            allocation: self.allocation.clone(),
            pending: self
                .pending
                .take()
                .ok_or_else(|| state_error("original replay source transferred"))?,
            nodes: BTreeMap::new(),
            proofs: BTreeMap::new(),
            owners: BTreeMap::new(),
            coordinator: None,
            reservations: RestoreReservations {
                memory_bytes: memory,
                ..RestoreReservations::default()
            },
            quarantined: false,
        };
        // Only the installed empty capsule may subsequently allocate native
        // replay-model buffers. Drop always transfers this entire source roster.
        allocation.install_capsule(Box::new(capsule))
    }
}

struct ReplayStaging {
    graph: Rc<AdmittedGraph>,
    target: ActivationRecord,
    artifact: ContentRef,
    manifest: CaptureManifest,
    runtime: RuntimeSnapshot,
    scheduler: SchedulingSnapshot,
    allocation: Rc<cursor_allocation::CursorAllocation>,
    pending: BTreeMap<Id, AuthenticatedReplayContinuation>,
    nodes: BTreeMap<Id, TranscriptReplayNode>,
    proofs: BTreeMap<Id, NativeRuntimeContinuationEvidence>,
    owners: BTreeMap<Id, RestoredOwnerAttestation>,
    coordinator: Option<ContentRef>,
    reservations: RestoreReservations,
    quarantined: bool,
}

impl NativeRuntimeContinuationVerifier for ReplayStaging {
    fn verify_runtime_continuation(
        &mut self,
        source: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        if self.quarantined
            || target != &self.target
            || source != &self.runtime
            || scheduling != &self.scheduler
            || self.coordinator.is_none()
            || self.proofs.len() != self.manifest.owners.len()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut input_acknowledgements = self
            .proofs
            .values()
            .flat_map(|proof| proof.input_acknowledgements.iter().cloned())
            .collect::<Vec<_>>();
        input_acknowledgements.sort_by(|a, b| a.stage_operation.cmp(&b.stage_operation));
        let proof = self
            .receipt(&serde_json::json!({
                "schema":"crucible.complete-replay-world-custody.v1","source":self.artifact,
                "target":crucible::node_contract::SavedRuntimeActivation::from(target),
                "native_proofs":self.proofs.values().map(|proof| &proof.proof).collect::<Vec<_>>(),
            }))
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        Ok(NativeRuntimeContinuationEvidence {
            proof,
            input_acknowledgements,
        })
    }
}

impl NativeRestoreStaging for ReplayStaging {
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
        target: &ActivationRecord,
    ) -> Result<RestoredOwnerAttestation, StateError> {
        if self.quarantined
            || target != &self.target
            || capture.artifact() != &self.artifact
            || capture.manifest() != &self.manifest
            || self.owners.contains_key(&owner.capture_owner_id)
        {
            return Err(state_error("original replay preparation scope differs"));
        }
        let [node] = owner.participant_ids.as_slice() else {
            return Err(state_error("original replay owner is not exclusive"));
        };
        let binding = self
            .graph
            .binding(node)
            .ok_or_else(|| state_error("fresh replay binding absent"))?;
        let identity = target
            .owners
            .iter()
            .find(|identity| identity.owner == binding.compatibility.execution_owner.id)
            .cloned()
            .ok_or_else(|| state_error("fresh replay execution owner absent"))?;
        let source = self
            .pending
            .remove(node)
            .ok_or_else(|| state_error("original replay source was already prepared"))?;
        let context = source.transcript().transcript().origin.context.clone();
        let actual = TranscriptReplayNode::prepare_restored(
            source,
            &self.graph,
            NodeRoute {
                node: node.clone(),
                owners: vec![identity],
            },
            &context,
            self.allocation.as_ref(),
        )
        .map_err(state_error)?;
        self.nodes.insert(node.clone(), actual);
        let actual = self
            .nodes
            .get_mut(node)
            .ok_or_else(|| state_error("prepared replay native model absent"))?;
        let proof = actual
            .restored_continuation_evidence(&self.runtime, target)
            .map_err(|error| state_error(error.reason))?;
        let ready = actual
            .arm(target)
            .map_err(|error| state_error(error.reason))?;
        actual
            .validate_readiness(target, &ready)
            .map_err(|error| state_error(error.reason))?;
        let attestation = RestoredOwnerAttestation {
            identity: ready
                .owners
                .iter()
                .find(|identity| identity.owner == owner.capture_owner_id)
                .cloned()
                .ok_or_else(|| state_error("fresh replay capture owner absent"))?,
            state_domain_ids: owner.state_domain_ids.clone(),
            binding_hashes: owner.binding_hashes.clone(),
            cut: self.manifest.cut,
            event_ordinal: self.manifest.event_ordinal,
            state_inventory: ready.state_inventory,
            ready_receipt: ready.ready_receipt,
        };
        self.proofs.insert(node.clone(), proof);
        self.owners
            .insert(owner.capture_owner_id.clone(), attestation.clone());
        Ok(attestation)
    }

    fn verify_prepared_owner(
        &self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        attestation: &RestoredOwnerAttestation,
    ) -> Result<(), StateError> {
        let owner = capture
            .manifest()
            .owners
            .iter()
            .find(|owner| owner.capture_owner_id == attestation.identity.owner)
            .ok_or_else(|| state_error("original replay capture owner absent"))?;
        let actual = self
            .nodes
            .get(&owner.participant_ids[0])
            .ok_or_else(|| state_error("fresh actual replay native owner absent"))?;
        let expected = self
            .owners
            .get(&attestation.identity.owner)
            .ok_or_else(|| state_error("fresh replay preparation receipt absent"))?;
        if target != &self.target
            || expected.identity != attestation.identity
            || expected.state_domain_ids != attestation.state_domain_ids
            || expected.binding_hashes != attestation.binding_hashes
            || expected.cut != attestation.cut
            || expected.event_ordinal != attestation.event_ordinal
            || expected.state_inventory != attestation.state_inventory
            || expected.ready_receipt != attestation.ready_receipt
        {
            return Err(state_error("fresh replay owner attestation changed"));
        }
        actual
            .validate_readiness(
                target,
                &crucible::node_contract::ReadyAttestation {
                    owners: vec![attestation.identity.clone()],
                    boundary: attestation.cut,
                    state_inventory: attestation.state_inventory.clone(),
                    ready_receipt: attestation.ready_receipt.clone(),
                },
            )
            .map_err(|error| state_error(error.reason))
    }

    fn prepare_coordinator(
        &mut self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
    ) -> Result<ContentRef, StateError> {
        if target != &self.target
            || capture.artifact() != &self.artifact
            || self.owners.len() != self.manifest.owners.len()
            || !self.pending.is_empty()
        {
            return Err(state_error(
                "replay complete-world owners are not inactive-ready",
            ));
        }
        let receipt = self.receipt(&serde_json::json!({"schema":"crucible.restored-replay-coordinator.v1","original":self.manifest.coordinator_state_ref,"target":crucible::node_contract::SavedRuntimeActivation::from(target)}))?;
        self.coordinator = Some(receipt.clone());
        Ok(receipt)
    }

    fn verify_prepared_world(
        &self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        owners: &[RestoredOwnerAttestation],
        receipt: &ContentRef,
    ) -> Result<(), StateError> {
        if self.quarantined
            || target != &self.target
            || self.coordinator.as_ref() != Some(receipt)
            || owners.len() != self.owners.len()
            || owners.len() != self.manifest.owners.len()
        {
            return Err(state_error("replay complete-world ready barrier differs"));
        }
        for owner in owners {
            self.verify_prepared_owner(capture, target, owner)?;
        }
        Ok(())
    }

    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError> {
        if self.quarantined
            || self.coordinator.is_none()
            || self.nodes.len() != self.manifest.owners.len()
        {
            return Err(state_error("complete replay node transfer is unavailable"));
        }
        Ok(std::mem::take(&mut self.nodes)
            .into_values()
            .map(|node| Box::new(node) as Box<dyn SimulationNode>)
            .collect())
    }

    fn contain_uncertain_publication(
        &mut self,
        target: &ActivationRecord,
    ) -> Result<(), StateError> {
        if target != &self.target {
            return Err(state_error("replay containment target differs"));
        }
        Ok(())
    }

    fn quarantine_resources(&mut self, _: &ActivationRecord, _: PublicationKnowledge) {
        self.quarantined = true;
        for node in self.nodes.values_mut() {
            node.quarantine_resources();
        }
    }

    fn poll_reclamation(&mut self, context: &mut Context<'_>) -> Poll<Result<(), StateError>> {
        if !self.quarantined {
            return Poll::Ready(Err(state_error("replay capsule is not quarantined")));
        }
        let Some(node) = self.nodes.keys().next().cloned() else {
            self.pending.clear();
            return Poll::Ready(Ok(()));
        };
        let actual = match self.nodes.get_mut(&node) {
            Some(actual) => actual,
            None => return Poll::Ready(Err(state_error("retained replay model disappeared"))),
        };
        let owner = match actual.route().owners.first() {
            Some(owner) => owner.clone(),
            None => return Poll::Ready(Err(state_error("retained replay owner absent"))),
        };
        match actual.poll_reclamation(&owner, context) {
            Poll::Ready(Ok(receipt)) => {
                if let Err(error) = actual.validate_reclamation(&receipt) {
                    return Poll::Ready(Err(state_error(error.reason)));
                }
                self.nodes.remove(&node);
                if self.nodes.is_empty() {
                    self.pending.clear();
                    Poll::Ready(Ok(()))
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(state_error(error.reason))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl ReplayStaging {
    fn receipt(&self, value: &serde_json::Value) -> Result<ContentRef, StateError> {
        let bytes = canonical::canonical_json(value).map_err(state_error)?;
        canonical::content_ref(&bytes, "application/json").map_err(state_error)
    }
}

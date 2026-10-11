//! Owns complete original Clock custody before preparing any fresh native handle.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, NativeRuntimeContinuationEvidence, NativeRuntimeContinuationVerifier,
        ReadyAttestation, RuntimeError, RuntimeSnapshot, SimulationNode,
    },
    node_scheduling::SchedulingSnapshot,
    node_state::{
        NativeArchiveRecord, NativeRestoreStaging, OriginalWorldDisposition, PublicationKnowledge,
        RestoreReservations, RestoredOwnerAttestation, StateError, VerifiedCapture,
    },
};
use crucible_node_contract::{CapturedOwner, ContentRef, canonical};

use super::{native::resources, state_error};

pub(super) struct CapabilityClockStaging {
    graph: Rc<AdmittedGraph>,
    archive: NativeArchiveRecord,
    target: ActivationRecord,
    reservations: RestoreReservations,
    installed: Rc<super::super::InstalledHostStateFactory>,
    node: Option<Box<dyn SimulationNode>>,
    proof: Option<NativeRuntimeContinuationEvidence>,
    ready: Option<RestoredOwnerAttestation>,
    coordinator: Option<ContentRef>,
    quarantined: bool,
    transferred: bool,
}

impl CapabilityClockStaging {
    pub(super) fn empty(
        graph: Rc<AdmittedGraph>,
        archive: NativeArchiveRecord,
        target: ActivationRecord,
        reservations: RestoreReservations,
        installed: Rc<super::super::InstalledHostStateFactory>,
    ) -> Self {
        Self {
            graph,
            archive,
            target,
            reservations,
            installed,
            node: None,
            proof: None,
            ready: None,
            coordinator: None,
            quarantined: false,
            transferred: false,
        }
    }

    fn ready_projection(&self) -> Result<ReadyAttestation, StateError> {
        let ready = self
            .ready
            .as_ref()
            .ok_or_else(|| state_error("original native Clock readiness absent"))?;
        Ok(ReadyAttestation {
            owners: vec![ready.identity.clone()],
            boundary: ready.cut,
            state_inventory: ready.state_inventory.clone(),
            ready_receipt: ready.ready_receipt.clone(),
        })
    }

    fn valid_scope(
        &self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
    ) -> Result<(), StateError> {
        if self.quarantined
            || self.transferred
            || target != &self.target
            || capture.artifact() != self.archive.artifact()
            || capture.manifest() != self.archive.manifest()
        {
            return Err(state_error("original Clock source or fresh scope differs"));
        }
        Ok(())
    }
}

impl NativeRuntimeContinuationVerifier for CapabilityClockStaging {
    fn verify_runtime_continuation(
        &mut self,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        if self.quarantined
            || target != &self.target
            || self.coordinator.is_none()
            || self
                .archive
                .runtime_snapshot()
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?
                != *runtime
            || self
                .archive
                .scheduling_snapshot()
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?
                != *scheduler
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.proof.clone().ok_or(RuntimeError::ForeignAuthority)
    }
}

impl NativeRestoreStaging for CapabilityClockStaging {
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
        self.valid_scope(capture, target)?;
        if self.node.is_some()
            || self.ready.is_some()
            || owner.participant_ids.len() != 1
            || capture.manifest().owners.len() != 1
        {
            return Err(state_error(
                "Clock native owner is absent, shared, or already prepared",
            ));
        }
        let saved = self.archive.runtime_snapshot()?;
        let source = self.archive.authenticated_source(
            &owner.capture_owner_id,
            &saved,
            capture.content(),
        )?;
        let (actual, proof) = super::super::native_state::host::prepare_clock(
            &self.graph,
            &owner.participant_ids[0],
            &source,
            target,
            &InstalledClockQualification {
                installed: self.installed.as_ref(),
            },
            resources(),
        )?;
        // Custody precedes the first fallible readiness callback.
        self.node = Some(Box::new(actual));
        self.proof = Some(proof);
        let actual = self
            .node
            .as_mut()
            .ok_or_else(|| state_error("owned fresh Clock absent"))?;
        let ready = actual
            .arm(target)
            .map_err(|error| state_error(error.reason))?;
        actual
            .validate_readiness(target, &ready)
            .map_err(|error| state_error(error.reason))?;
        if ready.owners.len() != 1
            || ready.owners[0].owner != owner.capture_owner_id
            || ready.boundary != capture.manifest().cut
        {
            return Err(state_error("actual fresh Clock readiness scope differs"));
        }
        let attestation = RestoredOwnerAttestation {
            identity: ready.owners[0].clone(),
            state_domain_ids: owner.state_domain_ids.clone(),
            binding_hashes: owner.binding_hashes.clone(),
            cut: capture.manifest().cut,
            event_ordinal: capture.manifest().event_ordinal,
            state_inventory: ready.state_inventory,
            ready_receipt: ready.ready_receipt,
        };
        self.ready = Some(attestation.clone());
        Ok(attestation)
    }

    fn verify_prepared_owner(
        &self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        attestation: &RestoredOwnerAttestation,
    ) -> Result<(), StateError> {
        self.valid_scope(capture, target)?;
        let ready = self
            .ready
            .as_ref()
            .ok_or_else(|| state_error("owned original readiness absent"))?;
        if attestation.identity != ready.identity
            || attestation.state_domain_ids != ready.state_domain_ids
            || attestation.binding_hashes != ready.binding_hashes
            || attestation.cut != ready.cut
            || attestation.event_ordinal != ready.event_ordinal
            || attestation.state_inventory != ready.state_inventory
            || attestation.ready_receipt != ready.ready_receipt
        {
            return Err(state_error("original Clock readiness projection changed"));
        }
        self.node
            .as_ref()
            .ok_or_else(|| state_error("actual Clock native handle absent"))?
            .validate_readiness(target, &self.ready_projection()?)
            .map_err(|error| state_error(error.reason))
    }

    fn prepare_coordinator(
        &mut self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
    ) -> Result<ContentRef, StateError> {
        self.valid_scope(capture, target)?;
        let ready = self
            .ready
            .as_ref()
            .ok_or_else(|| state_error("whole Clock barrier incomplete"))?;
        self.verify_prepared_owner(capture, target, ready)?;
        if self.coordinator.is_some() {
            return Err(state_error("original coordinator already prepared"));
        }
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.installed-capability-clock.ready.v1","source":self.archive.artifact(),
            "coordinator":capture.manifest().coordinator_state_ref,
            "target":crucible::node_contract::SavedRuntimeActivation::from(target),
        }))
        .map_err(state_error)?;
        let receipt = canonical::content_ref(&bytes, "application/json").map_err(state_error)?;
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
        self.valid_scope(capture, target)?;
        if owners.len() != 1 || self.coordinator.as_ref() != Some(receipt) {
            return Err(state_error("complete capability Clock barrier differs"));
        }
        self.verify_prepared_owner(capture, target, &owners[0])
    }

    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError> {
        if self.quarantined
            || self.transferred
            || self.coordinator.is_none()
            || self.proof.is_none()
            || self.ready.is_none()
        {
            return Err(state_error(
                "Clock capsule cannot transfer incomplete custody",
            ));
        }
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(1).map_err(state_error)?;
        let node = self
            .node
            .take()
            .ok_or_else(|| state_error("Clock capsule already transferred"))?;
        nodes.push(node);
        self.transferred = true;
        Ok(nodes)
    }

    fn contain_uncertain_publication(
        &mut self,
        target: &ActivationRecord,
    ) -> Result<(), StateError> {
        if target != &self.target || self.transferred || self.quarantined {
            return Err(state_error("Clock containment scope differs"));
        }
        self.node
            .as_ref()
            .ok_or_else(|| state_error("Clock containment native handle absent"))?
            .validate_readiness(target, &self.ready_projection()?)
            .map_err(|error| state_error(error.reason))
    }

    fn quarantine_resources(&mut self, _: &ActivationRecord, _: PublicationKnowledge) {
        self.quarantined = true;
        if let Some(node) = &mut self.node {
            node.quarantine_resources();
        }
    }

    fn poll_reclamation(&mut self, context: &mut Context<'_>) -> Poll<Result<(), StateError>> {
        let Some(node) = &mut self.node else {
            return Poll::Ready(Ok(()));
        };
        let Some(owner) = self.target.owners.first() else {
            return Poll::Ready(Err(state_error("Clock reclamation scope absent")));
        };
        match node.poll_reclamation(owner, context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(state_error(error.reason))),
            Poll::Ready(Ok(receipt)) => {
                if let Err(error) = node.validate_reclamation(&receipt) {
                    return Poll::Ready(Err(state_error(error.reason)));
                }
                self.node = None;
                Poll::Ready(Ok(()))
            }
        }
    }
}

// Reuses the installed native constructor validator; this wrapper cannot
// authenticate source archives. Original custody stays in prepare_clock.
struct InstalledClockQualification<'a> {
    installed: &'a super::super::InstalledHostStateFactory,
}

impl crucible::node_adapters::HostModelQualification for InstalledClockQualification<'_> {
    fn authenticate_model(
        &self,
        model: &crucible::node_adapters::HostModel,
        descriptor: &crucible_node_contract::NodeDescriptor,
        binding: &crucible_node_contract::NodeBinding,
    ) -> Result<(), crucible::node_contract::OperationFailure> {
        self.installed.check_model(model, descriptor, binding)
    }
}

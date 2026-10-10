//! Preallocated owning native staging guards and complete source retention.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use super::validation::incomplete;
use super::{
    NativeRestoreStaging, OriginalWorldDisposition, PublicationKnowledge, RestoreReservations,
    RestoredOwnerAttestation, StateError, VerifiedCapture,
};
use crate::node_contract::{
    ActivationRecord, EffectKnowledge, NativeRuntimeContinuationEvidence,
    NativeRuntimeContinuationVerifier, OperationFailure, PreparedNativeResources,
    PublicationStatus, RuntimeCustodySlot, RuntimeError, RuntimeLimits, RuntimeSnapshot,
    SimulationNode, WholeRuntimeCustody,
};
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_contract::{CapturedOwner, ContentRef};

/// Owns reserved native staging capacity before a driver allocates resources.
///
/// The driver installs its empty native capsule first, then allocates into that
/// capsule. Drop and callback unwind transfer every installed resource together
/// with the entire authenticated source to the already reserved owning queue.
pub struct PreparedRestoreAllocation {
    slot: Option<Box<dyn RuntimeCustodySlot>>,
    native: Option<Box<dyn NativeRestoreStaging>>,
    capture: Rc<VerifiedCapture>,
    activation: ActivationRecord,
    limits: RuntimeLimits,
}

impl PreparedRestoreAllocation {
    pub(super) fn new(
        slot: Box<dyn RuntimeCustodySlot>,
        capture: Rc<VerifiedCapture>,
        activation: ActivationRecord,
        limits: RuntimeLimits,
    ) -> Self {
        Self {
            slot: Some(slot),
            native: None,
            capture,
            activation,
            limits,
        }
    }

    /// Installs an empty native capsule before allocating any external resource.
    ///
    /// # Errors
    /// Refuses a second capsule. The supplied capsule must still be empty;
    /// native allocation belongs to the installed capsule exclusively.
    pub fn install_capsule(
        &mut self,
        native: Box<dyn NativeRestoreStaging>,
    ) -> Result<(), StateError> {
        if self.native.is_some() {
            return Err(incomplete(
                "native allocation",
                "a capsule is already installed",
            ));
        }
        self.native = Some(native);
        Ok(())
    }

    /// Borrows the owned non-runnable capsule for bounded native allocation.
    ///
    /// # Errors
    /// Refuses allocation before the capsule is installed into owning custody.
    pub fn capsule_mut(&mut self) -> Result<&mut (dyn NativeRestoreStaging + '_), StateError> {
        match self.native.as_mut() {
            Some(native) => Ok(native.as_mut()),
            None => Err(incomplete(
                "native allocation",
                "owning capsule is not installed",
            )),
        }
    }

    pub(super) fn finish(mut self) -> Result<PreparedNativeCustody, StateError> {
        let native = self
            .native
            .take()
            .ok_or_else(|| incomplete("native allocation", "driver omitted the owning capsule"))?;
        let slot = self
            .slot
            .take()
            .ok_or_else(|| incomplete("native allocation", "reserved owning slot is absent"))?;
        Ok(PreparedNativeCustody {
            native: Some(native),
            slot: Some(slot),
            capture: Rc::clone(&self.capture),
            activation: self.activation.clone(),
            limits: self.limits,
            publication: PublicationKnowledge::NotAttempted,
        })
    }
}

impl Drop for PreparedRestoreAllocation {
    fn drop(&mut self) {
        if let (Some(native), Some(slot)) = (self.native.take(), self.slot.take()) {
            transfer(
                native,
                slot,
                Rc::clone(&self.capture),
                self.activation.clone(),
                PublicationKnowledge::NotAttempted,
                self.limits,
            );
        }
    }
}

/// Retains a complete native capsule and preservation source until authenticated cleanup.
pub struct PreparedNativeCustody {
    native: Option<Box<dyn NativeRestoreStaging>>,
    slot: Option<Box<dyn RuntimeCustodySlot>>,
    capture: Rc<VerifiedCapture>,
    activation: ActivationRecord,
    publication: PublicationKnowledge,
    limits: RuntimeLimits,
}

impl PreparedNativeCustody {
    fn native(&self) -> Result<&dyn NativeRestoreStaging, StateError> {
        self.native
            .as_deref()
            .ok_or_else(|| incomplete("native custody", "capsule was transferred"))
    }

    fn native_mut(&mut self) -> Result<&mut (dyn NativeRestoreStaging + '_), StateError> {
        match self.native.as_mut() {
            Some(native) => Ok(native.as_mut()),
            None => Err(incomplete("native custody", "capsule was transferred")),
        }
    }

    pub(super) fn as_mut(&mut self) -> &mut dyn NativeRestoreStaging {
        self
    }
}

impl NativeRuntimeContinuationVerifier for PreparedNativeCustody {
    fn preserve_scheduling_epochs(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<Option<crate::node_scheduling::SchedulingEpochEvidence>, RuntimeError> {
        self.native_mut()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .preserve_scheduling_epochs(snapshot, scheduling, target)
    }

    fn verify_fault_continuation(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.native_mut()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .verify_fault_continuation(snapshot, scheduling, target)
    }

    fn verify_terminal_continuation(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.native_mut()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .verify_terminal_continuation(snapshot, scheduling, target)
    }

    fn verify_input_provenance(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.native_mut()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .verify_input_provenance(snapshot, scheduling, target)
    }

    fn verify_runtime_continuation(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        self.native_mut()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .verify_runtime_continuation(snapshot, scheduling, target)
    }
}

impl NativeRestoreStaging for PreparedNativeCustody {
    fn reservations(&self) -> RestoreReservations {
        self.native().map_or(
            RestoreReservations {
                memory_bytes: u64::MAX,
                writable_bytes: u64::MAX,
                processes: u64::MAX,
                descriptors: u64::MAX,
            },
            |native| native.reservations(),
        )
    }

    fn original_disposition(&self) -> OriginalWorldDisposition {
        self.native()
            .map_or(OriginalWorldDisposition::Unknown, |native| {
                native.original_disposition()
            })
    }

    fn prepare_owner(
        &mut self,
        capture: &VerifiedCapture,
        owner: &CapturedOwner,
        activation: &ActivationRecord,
    ) -> Result<RestoredOwnerAttestation, StateError> {
        self.native_mut()?.prepare_owner(capture, owner, activation)
    }

    fn verify_prepared_owner(
        &self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        attestation: &RestoredOwnerAttestation,
    ) -> Result<(), StateError> {
        self.native()?
            .verify_prepared_owner(capture, activation, attestation)
    }

    fn prepare_coordinator(
        &mut self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
    ) -> Result<ContentRef, StateError> {
        self.native_mut()?.prepare_coordinator(capture, activation)
    }

    fn verify_prepared_world(
        &self,
        capture: &VerifiedCapture,
        activation: &ActivationRecord,
        owners: &[RestoredOwnerAttestation],
        receipt: &ContentRef,
    ) -> Result<(), StateError> {
        self.native()?
            .verify_prepared_world(capture, activation, owners, receipt)
    }

    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError> {
        self.native_mut()?.take_nodes()
    }

    fn contain_uncertain_publication(
        &mut self,
        activation: &ActivationRecord,
    ) -> Result<(), StateError> {
        self.native_mut()?.contain_uncertain_publication(activation)
    }

    fn quarantine_resources(
        &mut self,
        _activation: &ActivationRecord,
        publication: PublicationKnowledge,
    ) {
        self.publication = publication;
        if let Some(native) = &mut self.native {
            native.quarantine_resources(&self.activation, publication);
        }
    }

    fn poll_reclamation(&mut self, context: &mut Context<'_>) -> Poll<Result<(), StateError>> {
        match self.native_mut() {
            Ok(native) => native.poll_reclamation(context),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl Drop for PreparedNativeCustody {
    fn drop(&mut self) {
        if let (Some(native), Some(slot)) = (self.native.take(), self.slot.take()) {
            transfer(
                native,
                slot,
                Rc::clone(&self.capture),
                self.activation.clone(),
                self.publication,
                self.limits,
            );
        }
    }
}

struct RetainedPreparedRestore {
    native: Box<dyn NativeRestoreStaging>,
    _capture: Rc<VerifiedCapture>,
    activation: ActivationRecord,
    publication: PublicationKnowledge,
}

impl PreparedNativeResources for RetainedPreparedRestore {
    fn quarantine_resources(
        &mut self,
        activation: &ActivationRecord,
        publication: Option<PublicationStatus>,
    ) {
        self.publication = publication.map_or(
            PublicationKnowledge::NotAttempted,
            PublicationKnowledge::from,
        );
        self.native.quarantine_resources(
            activation,
            publication.map_or(
                PublicationKnowledge::NotAttempted,
                PublicationKnowledge::from,
            ),
        );
    }
    fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), OperationFailure>> {
        self.native
            .quarantine_resources(&self.activation, self.publication);
        self.native
            .poll_reclamation(context)
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.to_string(),
            })
    }
}

fn transfer(
    native: Box<dyn NativeRestoreStaging>,
    slot: Box<dyn RuntimeCustodySlot>,
    capture: Rc<VerifiedCapture>,
    activation: ActivationRecord,
    publication: PublicationKnowledge,
    limits: RuntimeLimits,
) {
    let status = match publication {
        PublicationKnowledge::NotAttempted => None,
        PublicationKnowledge::NotCommitted => Some(PublicationStatus::NotCommitted),
        PublicationKnowledge::Unknown => Some(PublicationStatus::Unknown),
        PublicationKnowledge::Committed => Some(PublicationStatus::Committed),
    };
    slot.retain(WholeRuntimeCustody::from_prepared_resources(
        Box::new(RetainedPreparedRestore {
            native,
            _capture: capture,
            activation: activation.clone(),
            publication,
        }),
        activation,
        status,
        limits,
    ));
}

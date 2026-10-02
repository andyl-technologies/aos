//! Protected preparation and reconciliation under two retained journal writers.
//!
//! The existing traffic writer is acquired first, this same-owner sidecar
//! second, and the sealed TPM transport last. The composition grants no
//! endpoint, method, readiness, or effect authority by itself.
//!
//! The separate sidecar owns namespace 47 and exactly these canonical keys:
//!
//! ```text
//! checkpoint = AOSBTF01 (156 bytes)
//! intent     = AOSBTI01 (324 bytes), present only with transaction
//! transaction = AOSJPT01, exact existing ordered JournalTransaction
//! ```

mod store;
pub(crate) use store::BrokerSidecarCustodyV1;
mod traffic;

use aos_sandbox::{JournalTransaction, ProtectedJournalLockCustodyV1};

use super::backend::{
    AuthenticatedTpmNvIoV1, FloorAdvanceV1, PhysicalTpmNvIoV1, TpmNvExtendFloorBackendV1,
};
use super::{FloorErrorV1, FloorIntentV1, FloorProfileV1, FloorRecoveryV1, reconcile_floor_v1};
use store::{
    BrokerSidecarOpenErrorV1, BrokerSidecarOpenV1, FinalSuffixPreflightV1, FloorStoreV1,
    StoredFloorV1,
};
use traffic::HeldTrafficWriterV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BrokerAttachmentPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Failed,
}

enum BrokerAttachmentFailureV1 {
    Floor(FloorErrorV1),
    Sidecar(BrokerSidecarOpenErrorV1),
    Native(aos_sandbox::JournalError),
    Endpoint(crate::BrokerSessionSecurityError),
    Unfinished,
    Deadline(crate::DormantBrokerSessionHandshakeErrorV1),
}

/// Keeps genuine partial attachment owners resident before each later gate.
pub(super) struct BrokerAttachmentAttemptV1 {
    // Preserve carrier/backend before sidecar destruction; traffic remains on
    // the whole original Journal owner, never borrowed into a sibling field.
    backend: Option<TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1>>,
    physical: Option<PhysicalTpmNvIoV1>,
    store: Option<FloorStoreV1>,
    opening: Option<BrokerSidecarOpenV1>,
    main_lock: Option<ProtectedJournalLockCustodyV1>,
    sidecar_lock: Option<ProtectedJournalLockCustodyV1>,
    phase: BrokerAttachmentPhaseV1,
    first_failure: Option<BrokerAttachmentFailureV1>,
    cold_deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    cold_failure: Option<crate::DormantBrokerSessionHandshakeErrorV1>,
}

impl BrokerAttachmentAttemptV1 {
    pub(super) fn bind_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Fresh || self.cold_deadline.is_some() {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        self.cold_deadline = Some(deadline);
        self.check_cold_deadline()
    }

    pub(super) fn check_cold_deadline(&mut self) -> Result<(), FloorErrorV1> {
        if let Some(deadline) = self.cold_deadline {
            if let Err(cause) = deadline.check() {
                self.record(BrokerAttachmentFailureV1::Deadline(cause));
                return Err(FloorErrorV1::Unavailable);
            }
        }
        Ok(())
    }

    pub(super) fn retire_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Ready
            || self.first_failure.is_some()
            || self.cold_failure.is_some()
            || self.cold_deadline != Some(deadline)
        {
            self.fence();
            return Err(FloorErrorV1::Unavailable);
        }
        let result = self.backend
            .as_mut()
            .ok_or(FloorErrorV1::Unavailable)?
            .require_cold_retirement(deadline);
        if let Err(cause) = result {
            self.record(BrokerAttachmentFailureV1::Floor(cause));
            return Err(cause);
        }
        self.check_cold_deadline()?;
        // No fallible work follows the final original-D observation.
        if let Some(backend) = self.backend.as_mut() {
            backend.clear_cold_deadline();
        }
        self.cold_deadline = None;
        Ok(())
    }

    pub(super) const fn fresh() -> Self {
        Self {
            backend: None,
            physical: None,
            store: None,
            opening: None,
            main_lock: None,
            sidecar_lock: None,
            phase: BrokerAttachmentPhaseV1::Fresh,
            first_failure: None,
            cold_deadline: None,
            cold_failure: None,
        }
    }

    pub(super) fn is_failed(&self) -> bool {
        matches!(
            self.phase,
            BrokerAttachmentPhaseV1::Checking | BrokerAttachmentPhaseV1::Failed
        )
    }

    pub(super) fn is_ready(&self) -> bool {
        self.phase == BrokerAttachmentPhaseV1::Ready
    }

    pub(super) fn fence(&mut self) {
        self.phase = BrokerAttachmentPhaseV1::Failed;
        if self.first_failure.is_none() {
            self.first_failure = Some(BrokerAttachmentFailureV1::Unfinished);
        }
    }

    pub(super) fn record_native_failure(&mut self, cause: aos_sandbox::JournalError) {
        self.record(BrokerAttachmentFailureV1::Native(cause));
    }

    pub(super) fn record_endpoint_failure(&mut self, cause: crate::BrokerSessionSecurityError) {
        self.record(BrokerAttachmentFailureV1::Endpoint(cause));
    }

    fn failure_projection(&self) -> FloorErrorV1 {
        match &self.first_failure {
            Some(BrokerAttachmentFailureV1::Floor(error)) => *error,
            Some(BrokerAttachmentFailureV1::Sidecar(error)) => error.projection(),
            // Endpoint and unfinished failures keep their actual cause here;
            // the original Broker facade has always projected Unavailable.
            _ => FloorErrorV1::Unavailable,
        }
    }

    fn record(&mut self, failure: BrokerAttachmentFailureV1) {
        if self.first_failure.is_none() {
            self.first_failure = Some(failure);
        }
        self.phase = BrokerAttachmentPhaseV1::Failed;
    }

    pub(super) fn begin(
        &mut self,
        expected: BrokerAttachmentPhaseV1,
    ) -> Result<BrokerAttachmentOperationV1<'_>, FloorErrorV1> {
        if self.phase != expected || self.first_failure.is_some() {
            let cause = self.failure_projection();
            self.fence();
            return Err(cause);
        }
        self.phase = BrokerAttachmentPhaseV1::Checking;
        Ok(BrokerAttachmentOperationV1 {
            attempt: self,
            complete: false,
        })
    }

    pub(super) fn admit(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
        salt_name: [u8; 34],
        auth: &[u8; 32],
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        self.check_cold_deadline()?;
        traffic::BrokerTrafficWriterV1::borrow(owner).cuts(profile, None)?;
        self.check_cold_deadline()?;
        self.require_endpoint(owner)?;
        self.opening = Some(BrokerSidecarOpenV1::prepare(
            owner.owner,
            &owner.directory,
            owner.limits,
        )?);
        self.check_cold_deadline()?;
        let result = self.opening.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?
            .open();
        if let Err(cause) = result {
            let projection = cause.projection();
            self.record(BrokerAttachmentFailureV1::Sidecar(cause));
            return Err(projection);
        }
        self.opening.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?
            .finish_into(&mut self.store)?;
        // Only the empty opening shell moves away; the actual sidecar is now
        // resident BEFORE traffic's original endpoint postcheck.
        self.opening = None;
        self.check_cold_deadline()?;
        self.require_endpoint(owner)?;

        self.main_lock = Some(
            traffic::BrokerTrafficWriterV1::borrow(owner).loan_lock_custody()?,
        );
        self.sidecar_lock = Some(
            self.store.as_ref()
                .ok_or(FloorErrorV1::Unavailable)?
                .loan_lock_custody()?,
        );
        let (main, sidecar) = (self.main_lock.take(), self.sidecar_lock.take());
        match (main, sidecar) {
            (Some(main), Some(sidecar)) => {
                // Retain is infallible on the restricted actual inputs. No gate
                // or callback can run between the OFD move and its owning slot.
                self.physical = Some(PhysicalTpmNvIoV1::retain(
                    profile,
                    salt_name,
                    auth,
                    [main, sidecar],
                    launch_image,
                ));
            }
            (main, sidecar) => {
                self.main_lock = main;
                self.sidecar_lock = sidecar;
                return Err(FloorErrorV1::Unavailable);
            }
        }
        if let Some(deadline) = self.cold_deadline {
            self.physical.as_mut().ok_or(FloorErrorV1::Unavailable)?
                .bind_cold_deadline(deadline)?;
        }
        self.check_cold_deadline()?;
        self.physical.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?
            .admit()?;
        self.check_cold_deadline()?;
        if let Some(physical) = self.physical.take() {
            self.backend = Some(TpmNvExtendFloorBackendV1::retain(profile, physical));
        } else {
            return Err(FloorErrorV1::Unavailable);
        }
        // Keep both original READs: physical admission's READ precedes this
        // backend READ; both execute only after their actual owners are parked.
        self.backend.as_mut()
            .ok_or(FloorErrorV1::Unavailable)?
            .read()?;
        let mut traffic = traffic::BrokerTrafficWriterV1::borrow(owner);
        let mut floor = self.borrow(&mut traffic, profile)?;
        floor.classify()?;
        if floor.recover()? != FloorProgressV1::Current {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    fn require_endpoint(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    ) -> Result<(), FloorErrorV1> {
        if let Err(cause) = owner.endpoint.revalidate() {
            self.record(BrokerAttachmentFailureV1::Endpoint(cause));
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(super) fn check(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
    ) -> Result<(), FloorErrorV1> {
        let mut traffic = traffic::BrokerTrafficWriterV1::borrow(owner);
        self.borrow(&mut traffic, profile)?.require_current()
    }

    pub(super) fn commit(
        &mut self,
        owner: &mut super::super::ProtectedBrokerSessionJournalV1,
        profile: FloorProfileV1,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        let mut traffic = traffic::BrokerTrafficWriterV1::borrow(owner);
        let mut floor = self.borrow(&mut traffic, profile)?;
        floor.prepare(transaction)?;
        if floor.recover()? != FloorProgressV1::Current {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    fn borrow<'operation, Traffic: HeldTrafficWriterV1>(
        &'operation mut self,
        traffic: &'operation mut Traffic,
        profile: FloorProfileV1,
    ) -> Result<BorrowedDurableFloorV1<'operation, Traffic, PhysicalTpmNvIoV1>, FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking {
            return Err(self.failure_projection());
        }
        Ok(BorrowedDurableFloorV1 {
            backend: self.backend.as_mut().ok_or(FloorErrorV1::Unavailable)?,
            store: self.store.as_mut().ok_or(FloorErrorV1::Unavailable)?,
            traffic,
            profile,
            cold_deadline: self.cold_deadline,
            cold_failure: Some(&mut self.cold_failure),
        })
    }
}

pub(super) struct BrokerAttachmentOperationV1<'operation> {
    pub(super) attempt: &'operation mut BrokerAttachmentAttemptV1,
    complete: bool,
}

impl BrokerAttachmentOperationV1<'_> {
    pub(super) fn finish<T>(mut self, result: Result<T, FloorErrorV1>) -> Result<T, FloorErrorV1> {
        let result = match result {
            Ok(value) => self.attempt.check_cold_deadline().map(|()| value),
            Err(cause) => Err(cause),
        };
        let result = match result {
            Ok(value)
                if self.attempt.phase == BrokerAttachmentPhaseV1::Checking
                    && self.attempt.first_failure.is_none()
                    && self.attempt.cold_failure.is_none() =>
            {
                self.attempt.phase = BrokerAttachmentPhaseV1::Ready;
                Ok(value)
            }
            Ok(_) => {
                self.attempt.fence();
                Err(self.attempt.failure_projection())
            }
            Err(cause) => {
                self.attempt.record(BrokerAttachmentFailureV1::Floor(cause));
                Err(cause)
            }
        };
        self.complete = true;
        result
    }
}

impl Drop for BrokerAttachmentOperationV1<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.attempt.fence();
        }
    }
}

pub(super) fn attach_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    profile: FloorProfileV1,
    make_io: impl FnOnce([ProtectedJournalLockCustodyV1; 2]) -> Result<Io, FloorErrorV1>,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor = DurableTpmFloorV1::open_with_factory(
        traffic::BrokerTrafficWriterV1::borrow(owner),
        profile,
        make_io,
    )?;
    if floor.recover()? != FloorProgressV1::Current {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(floor.detach())
}

pub(super) fn check_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    attached: AttachedFloorV1<Io>,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor =
        DurableTpmFloorV1::resume(traffic::BrokerTrafficWriterV1::borrow(owner), attached);
    floor.require_current()?;
    Ok(floor.detach())
}

pub(super) fn commit_broker_floor_v1<Io: AuthenticatedTpmNvIoV1>(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    attached: AttachedFloorV1<Io>,
    transaction: &JournalTransaction,
) -> Result<AttachedFloorV1<Io>, FloorErrorV1> {
    let mut floor =
        DurableTpmFloorV1::resume(traffic::BrokerTrafficWriterV1::borrow(owner), attached);
    floor.prepare(transaction)?;
    if floor.recover()? != FloorProgressV1::Current {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(floor.detach())
}

pub(super) fn commit_unfloored_broker_v1(
    owner: &mut super::super::ProtectedBrokerSessionJournalV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    owner
        .endpoint
        .revalidate()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    traffic::commit_traffic_transaction(
        owner.journal_mut().map_err(|_| FloorErrorV1::Unavailable)?,
        transaction,
    )?;
    owner
        .validate_schema_only()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    owner
        .endpoint
        .revalidate()
        .map_err(|_| FloorErrorV1::Unavailable)
}

/// Retains the actual traffic writer, sidecar flock, and authenticated NV backend.
pub(super) struct DurableTpmFloorV1<Traffic, Io> {
    // Stop the TPM carrier before releasing either retained writer.
    backend: TpmNvExtendFloorBackendV1<Io>,
    store: FloorStoreV1,
    traffic: Traffic,
    profile: FloorProfileV1,
}

/// Describes a completed local check, never a public readiness/effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FloorProgressV1 {
    Current,
    NvNotAdvanced,
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1> DurableTpmFloorV1<Traffic, Io> {
    /// Opens existing names only after the real fixed endpoint writer has revalidated.
    pub(super) fn open(
        traffic: Traffic,
        profile: FloorProfileV1,
        io: Io,
    ) -> Result<Self, FloorErrorV1> {
        Self::open_with_factory(traffic, profile, |_| Ok(io))
    }

    fn open_with_factory(
        mut traffic: Traffic,
        profile: FloorProfileV1,
        make_io: impl FnOnce([ProtectedJournalLockCustodyV1; 2]) -> Result<Io, FloorErrorV1>,
    ) -> Result<Self, FloorErrorV1> {
        traffic.cuts(profile, None)?;
        let store = traffic.open_floor_store()?;
        let locks = [traffic.loan_lock_custody()?, store.loan_lock_custody()?];
        let backend = TpmNvExtendFloorBackendV1::open(profile, make_io(locks)?)?;
        let mut owner = Self {
            traffic,
            store,
            backend,
            profile,
        };
        owner.classify()?;
        Ok(owner)
    }

    // Owning compatibility callers and resident production callers execute
    // this same algorithm through references to their exact original fields.
    fn borrow(&mut self) -> BorrowedDurableFloorV1<'_, Traffic, Io> {
        BorrowedDurableFloorV1 {
            backend: &mut self.backend,
            store: &mut self.store,
            traffic: &mut self.traffic,
            profile: self.profile,
            cold_deadline: None,
            cold_failure: None,
        }
    }

    pub(super) fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
        self.borrow().prepare(transaction)
    }

    pub(super) fn recover(&mut self) -> Result<FloorProgressV1, FloorErrorV1> {
        self.borrow().recover()
    }

    pub(super) fn require_current(&mut self) -> Result<(), FloorErrorV1> {
        self.borrow().require_current()
    }

    /// Releases only the temporary traffic borrow, retaining sidecar and TPM custody.
    pub(super) fn detach(self) -> AttachedFloorV1<Io> {
        AttachedFloorV1 {
            store: self.store,
            backend: self.backend,
            profile: self.profile,
        }
    }

    pub(super) fn resume(traffic: Traffic, attached: AttachedFloorV1<Io>) -> Self {
        Self {
            traffic,
            store: attached.store,
            backend: attached.backend,
            profile: attached.profile,
        }
    }

    fn classify(&mut self) -> Result<(StoredFloorV1, FloorRecoveryV1), FloorErrorV1> {
        self.borrow().classify()
    }
}

// A temporary borrow, never a second owner, cached authority or policy factory.
struct BorrowedDurableFloorV1<'operation, Traffic, Io> {
    backend: &'operation mut TpmNvExtendFloorBackendV1<Io>,
    store: &'operation mut FloorStoreV1,
    traffic: &'operation mut Traffic,
    profile: FloorProfileV1,
    cold_deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    cold_failure: Option<&'operation mut Option<crate::DormantBrokerSessionHandshakeErrorV1>>,
}

impl<Traffic: HeldTrafficWriterV1, Io: AuthenticatedTpmNvIoV1>
    BorrowedDurableFloorV1<'_, Traffic, Io>
{
    fn check_cold_deadline(&mut self) -> Result<(), FloorErrorV1> {
        check_borrowed_cold_deadline(self.cold_deadline, &mut self.cold_failure)
    }

    /// Persists the full exact transaction before the first possible NV extension.
    ///
    /// A failure after the append grants no vacant preparation or retry. The
    /// consuming compatibility owner must be reopened; Required production
    /// keeps its failed originals resident and refuses reopening that owner.
    pub(super) fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), FloorErrorV1> {
        self.check_cold_deadline()?;
        let stored = self.store.read(self.profile)?;
        self.check_cold_deadline()?;
        if stored.prepared.is_some() {
            return Err(FloorErrorV1::Diverged);
        }
        self.check_cold_deadline()?;
        let (current, target) = self.traffic.cuts(self.profile, Some(transaction))?;
        self.check_cold_deadline()?;
        if current != stored.checkpoint.cut()
            || self.backend.read()? != stored.checkpoint.nv_value()
        {
            return Err(FloorErrorV1::Diverged);
        }
        let target = target.ok_or(FloorErrorV1::Successor)?;
        let intent = FloorIntentV1::new(self.profile, stored.checkpoint, target, transaction)?;
        self.check_cold_deadline()?;
        self.store
            .prepare(self.profile, &stored, intent, transaction)?;
        self.check_cold_deadline()?;

        // A changed traffic name/cut after durable prepare closes recovery. It
        // does not replace the retained target or roll the preparation back.
        let (after, prospective) = self.traffic.cuts(self.profile, Some(transaction))?;
        if after != current || prospective != Some(target) {
            return Err(FloorErrorV1::Diverged);
        }
        self.check_cold_deadline()?;
        let retained = self.store.read(self.profile)?;
        self.check_cold_deadline()?;
        if retained.checkpoint != stored.checkpoint
            || !retained
                .prepared
                .as_ref()
                .is_some_and(|(retained_intent, retained_transaction)| {
                    *retained_intent == intent && retained_transaction == transaction
                })
        {
            return Err(FloorErrorV1::Diverged);
        }
        self.store.require_same(&retained, self.profile)?;
        if self.backend.read()? != stored.checkpoint.nv_value() {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(())
    }

    /// Finishes only the exact persisted transaction; no new request/nonce is allocated.
    pub(super) fn recover(&mut self) -> Result<FloorProgressV1, FloorErrorV1> {
        let (stored, phase) = self.classify()?;
        let Some((intent, transaction)) = stored.prepared.as_ref() else {
            return if phase == FloorRecoveryV1::Current {
                Ok(FloorProgressV1::Current)
            } else {
                Err(FloorErrorV1::Diverged)
            };
        };
        intent.require_transaction(transaction)?;

        if phase == FloorRecoveryV1::ExtendPrepared {
            let suffix = self.require_prospective(&stored, *intent, transaction)?;
            let profile = self.profile;
            let traffic = &mut *self.traffic;
            let store = &mut *self.store;
            let deadline = self.cold_deadline;
            let cold_failure = &mut self.cold_failure;
            let advanced = self.backend.advance_with_held_cut(*intent, || {
                check_borrowed_cold_deadline(deadline, cold_failure)?;
                require_prospective_cut(traffic, profile, *intent, transaction)?;
                store.validate_final_preflight(&suffix, &stored, profile)?;
                check_borrowed_cold_deadline(deadline, cold_failure)
            })?;
            if advanced == FloorAdvanceV1::NotAdvanced {
                self.classify()?;
                return Ok(FloorProgressV1::NvNotAdvanced);
            }
        }
        let (stored, phase) = self.classify()?;
        let (intent, transaction) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if phase == FloorRecoveryV1::CommitPrepared {
            let suffix = self.require_prospective(&stored, *intent, transaction)?;
            if self.backend.read()? != intent.target().nv_value() {
                return Err(FloorErrorV1::Diverged);
            }
            require_prospective_cut(&mut *self.traffic, self.profile, *intent, transaction)?;
            self.store
                .validate_final_preflight(&suffix, &stored, self.profile)?;
            self.check_cold_deadline()?;
            self.traffic
                .commit_exact(self.profile, *intent, transaction)?;
            self.check_cold_deadline()?;
        }

        let (stored, phase) = self.classify()?;
        if phase != FloorRecoveryV1::FinalizePrepared {
            return Err(FloorErrorV1::Diverged);
        }
        let (intent, _) = stored.prepared.as_ref().ok_or(FloorErrorV1::Diverged)?;
        if self.backend.read()? != intent.target().nv_value() {
            return Err(FloorErrorV1::Diverged);
        }
        self.check_cold_deadline()?;
        self.store.finalize(self.profile, &stored)?;
        self.check_cold_deadline()?;
        let (_, phase) = self.classify()?;
        if phase != FloorRecoveryV1::Current {
            return Err(FloorErrorV1::Diverged);
        }
        Ok(FloorProgressV1::Current)
    }

    /// Rejects pending recovery at ordinary read/use boundaries.
    pub(super) fn require_current(&mut self) -> Result<(), FloorErrorV1> {
        if self.classify()?.1 == FloorRecoveryV1::Current {
            Ok(())
        } else {
            Err(FloorErrorV1::Diverged)
        }
    }

    fn classify(&mut self) -> Result<(StoredFloorV1, FloorRecoveryV1), FloorErrorV1> {
        self.check_cold_deadline()?;
        let stored = self.store.read(self.profile)?;
        self.check_cold_deadline()?;
        let (cut, _) = self.traffic.cuts(self.profile, None)?;
        self.check_cold_deadline()?;
        let nv = self.backend.read()?;
        self.check_cold_deadline()?;
        self.store.require_same(&stored, self.profile)?;
        self.check_cold_deadline()?;
        let (after, _) = self.traffic.cuts(self.profile, None)?;
        self.check_cold_deadline()?;
        if after != cut {
            return Err(FloorErrorV1::Diverged);
        }
        let phase = reconcile_floor_v1(
            self.profile,
            stored.checkpoint,
            stored.prepared.as_ref().map(|(intent, _)| *intent),
            cut,
            nv,
        )?;
        Ok((stored, phase))
    }

    fn require_prospective(
        &mut self,
        stored: &StoredFloorV1,
        intent: FloorIntentV1,
        transaction: &JournalTransaction,
    ) -> Result<FinalSuffixPreflightV1, FloorErrorV1> {
        require_prospective_cut(&mut *self.traffic, self.profile, intent, transaction)?;
        self.check_cold_deadline()?;
        let suffix = self.store.preflight_final(stored, self.profile)?;
        self.check_cold_deadline()?;
        self.store.require_same(stored, self.profile)?;
        self.check_cold_deadline()?;
        Ok(suffix)
    }
}

fn check_borrowed_cold_deadline(
    deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    failure: &mut Option<&mut Option<crate::DormantBrokerSessionHandshakeErrorV1>>,
) -> Result<(), FloorErrorV1> {
    if let Some(deadline) = deadline {
        if let Err(cause) = deadline.check() {
            if let Some(slot) = failure.as_mut() {
                if slot.is_none() {
                    **slot = Some(cause);
                }
            }
            return Err(FloorErrorV1::Unavailable);
        }
    }
    Ok(())
}

fn require_prospective_cut(
    traffic: &mut impl HeldTrafficWriterV1,
    profile: FloorProfileV1,
    intent: FloorIntentV1,
    transaction: &JournalTransaction,
) -> Result<(), FloorErrorV1> {
    intent.require_transaction(transaction)?;
    let (current, target) = traffic.cuts(profile, Some(transaction))?;
    if current != intent.predecessor().cut() || target != Some(intent.target().cut()) {
        return Err(FloorErrorV1::Diverged);
    }
    Ok(())
}

#[cfg(test)]
mod cold_cutoff_data_tests {
    use super::check_borrowed_cold_deadline;

    #[test]
    fn legacy_none_performs_no_clock_check_or_cause_replacement() {
        let mut cause = Some(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        let mut slot = Some(&mut cause);

        assert!(check_borrowed_cold_deadline(None, &mut slot).is_ok());
        assert!(matches!(
            cause,
            Some(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        ));
    }
}

/// Retains the two non-traffic owners between opaque reconciliation borrows.
pub(super) struct AttachedFloorV1<Io> {
    backend: TpmNvExtendFloorBackendV1<Io>,
    store: FloorStoreV1,
    profile: FloorProfileV1,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod resident_attempt_tests {
    use super::*;

    #[test]
    fn only_the_same_successful_attempt_reopens_ready() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        attempt.begin(BrokerAttachmentPhaseV1::Fresh).unwrap()
            .finish(Ok(())).unwrap();
        assert!(attempt.is_ready());

        let error = attempt.begin(BrokerAttachmentPhaseV1::Ready).unwrap()
            .finish::<()>(Err(FloorErrorV1::Provisioning));
        assert_eq!(error, Err(FloorErrorV1::Provisioning));
        assert!(attempt.is_failed());
        assert!(attempt.begin(BrokerAttachmentPhaseV1::Ready).is_err());
        assert_eq!(attempt.failure_projection(), FloorErrorV1::Provisioning);
    }

    #[test]
    fn dropped_forgotten_and_caught_unwind_attempts_are_failed() {
        let mut dropped = BrokerAttachmentAttemptV1::fresh();
        drop(dropped.begin(BrokerAttachmentPhaseV1::Fresh).unwrap());
        assert!(dropped.is_failed());

        let mut forgotten = BrokerAttachmentAttemptV1::fresh();
        std::mem::forget(forgotten.begin(BrokerAttachmentPhaseV1::Fresh).unwrap());
        assert!(forgotten.is_failed());
        assert!(forgotten.begin(BrokerAttachmentPhaseV1::Fresh).is_err());

        let mut unwound = BrokerAttachmentAttemptV1::fresh();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _operation = unwound.begin(BrokerAttachmentPhaseV1::Fresh).unwrap();
            panic!("pure attempt unwind");
        }));
        assert!(caught.is_err());
        assert!(unwound.is_failed());
    }

    #[test]
    fn a_closed_attempt_cannot_be_restored_by_an_ok_result() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        let operation = attempt.begin(BrokerAttachmentPhaseV1::Fresh).unwrap();
        operation.attempt.record(BrokerAttachmentFailureV1::Floor(FloorErrorV1::Diverged));

        assert_eq!(operation.finish(Ok(())), Err(FloorErrorV1::Diverged));
        assert!(attempt.is_failed());
    }

    #[test]
    fn first_native_cause_is_not_replaced_by_projection_or_unfinished() {
        let mut attempt = BrokerAttachmentAttemptV1::fresh();
        attempt.record_native_failure(aos_sandbox::JournalError::ProtectedBoundary);
        attempt.record(BrokerAttachmentFailureV1::Floor(FloorErrorV1::Successor));
        attempt.fence();

        assert!(matches!(
            &attempt.first_failure,
            Some(BrokerAttachmentFailureV1::Native(aos_sandbox::JournalError::ProtectedBoundary))
        ));
        assert_eq!(attempt.failure_projection(), FloorErrorV1::Unavailable);
    }
}

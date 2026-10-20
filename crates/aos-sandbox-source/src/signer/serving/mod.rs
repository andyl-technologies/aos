//! Serves established Source recipes inside the original paid Source interval.
//!
//! One resident connection keeps request, native view, signed outcome and all
//! partial IO until its last independent post. Two exclusive operation lanes
//! reserve full22 capacity once from the same F; only actual positive disposal
//! permits a later flight. No request DATA, key, budget or caller Boolean can
//! create that original, replace its ledger or select a new signing recipe.

use std::error::Error;
use std::time::{Duration, Instant};

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{CurrentSelfPidFdCustodyV1, PidFdInfo, PidFdProcessIdentity};
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use ed25519_dalek::SigningKey;

use aos_sandbox_broker::receiving::RepresentationDemandDebitV1;
use aos_sandbox_broker::receiving::receiving_limits::ReceivingContainmentReadbackV1;
use aos_sandbox_broker::receiving::ObservationLifetimeV1 as ObserverLifetime;
use crate::signer::SourceReceivingGeometryErrorV1 as ResourceReservationErrorV1;
use crate::signer::root_observation::SourceRootPeerInputsV1;
use aos_sandbox_ledger_replay::source_signer_data::source_signer_wire::FLIGHT_TIMEOUT;

use super::currentness::SourceCurrentnessSampleV1;
use super::listener::SourceInheritedListenerV1;
use super::readonly::{SourceReadonlyPeakV1, SourceReadonlyReceivingContextV1};
use super::{SourceReceivingClosedV1, SourceSignerServiceOriginalV1, CLOSED};

mod budget;
mod chunk;
mod connection;
mod operation;
mod request;
mod simple;
mod stage;

use budget::SourceServingGeometryV1;
use connection::SourceConnectionV1;
use operation::SourceOperationV1;

#[derive(Debug, thiserror::Error)]
pub(super) enum SourceServingResidentErrorV1 {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Reservation(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Readonly(#[from] super::readonly::SourceReadonlyDemandErrorV1),
}

#[derive(Default)]
pub(super) struct SourceServingV1 {
    entered: bool,
    geometry: Option<Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>>,
    demand: Option<Result<SourceServingGeometryV1, ResourceReservationErrorV1>>,
    physical: Option<Result<(), AccountingError>>,
    reservation: Option<Result<(), SourceReceivingClosedV1>>,
    financial: Option<Result<ResourceVector, AccountingError>>,
    operation: Option<SourceOperationV1>,
    chunks: Option<SourceOperationV1>,
    lifetime: Option<ObserverLifetime>,
    connection: Option<SourceConnectionV1>,
    receive: Option<Result<(), SourceReceivingClosedV1>>,
    finish: Option<Result<(), SourceReceivingClosedV1>>,
    closed: Option<SourceReceivingClosedV1>,
}

// This loan has one private constructor below. Its fields are disjoint borrows
// of the same authenticated Source original, never values supplied by a caller.
pub(super) struct SourceServingOriginalLoanV1<'source> {
    pub(super) process: &'source mut CurrentSelfPidFdCustodyV1,
    pub(super) anchor: &'source RetainedCgroupAnchor,
    pub(super) limits: &'source ReceivingContainmentReadbackV1,
    pub(super) initial_info: PidFdInfo,
    pub(super) initial_identity: PidFdProcessIdentity,
    pub(super) inputs: &'source mut SourceRootPeerInputsV1,
    pub(super) ledger: &'source mut dyn RepresentationDemandDebitV1,
    pub(super) peak: &'source mut SourceReadonlyPeakV1,
    pub(super) listener: &'source SourceInheritedListenerV1,
    pub(super) controller_uid: u32,
}

impl SourceServingOriginalLoanV1<'_> {
    pub(super) fn observe_source_into(
        &mut self,
        sample: &mut SourceCurrentnessSampleV1,
    ) -> Result<(), SourceReceivingClosedV1> {
        sample.observe_once(self.process, self.anchor, self.limits, self.initial_info, self.initial_identity)
    }

    fn borrow_readonly_context<'borrow, 'expected>(&'borrow mut self) -> Result<SourceReadonlyReceivingContextV1<'borrow, 'expected>, SourceReceivingClosedV1> {
        // The sole constructor below checked the actual F3/profile/executable
        // and same-ledger permanent table. The immediately preceding stage
        // sample rechecks this original process, exact hard limit and cgroup.
        self.limits.require_current().map_err(|_| CLOSED)?;
        SourceReadonlyReceivingContextV1::new(self.ledger, self.peak)
    }
}

impl SourceServingV1 {
    fn initialize_once(
        &mut self,
        ledger: &mut dyn RepresentationDemandDebitV1,
        resident_files: u64,
        permanent_files: u64,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.entered { return self.close(); }
        self.entered = true;
        self.geometry = Some(crate::signer::root_observation::SourceRootPeerConnectionV1::receive_geometry());
        let geometry = self.geometry.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.demand = Some(SourceServingGeometryV1::derive(geometry));
        let demand = self.demand.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.physical = Some(resident_files.checked_add(demand.physical_files)
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })
            .and_then(|attempted| if attempted <= permanent_files { Ok(()) } else {
                Err(AccountingError::LimitExceeded { dimension: D::OpenFiles, limit: permanent_files, attempted })
            }));
        if !matches!(self.physical, Some(Ok(()))) { return Err(CLOSED); }
        self.financial = Some(demand.financial());
        let financial = self.financial.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        self.reservation = Some(ledger.reserve(financial).map_err(|_| CLOSED));
        if !matches!(self.reservation, Some(Ok(()))) { return Err(CLOSED); }

        // Arc and future request/worker owners are constructed only after this
        // same ledger's reservation; their capacities are never caller inputs.
        self.operation = Some(SourceOperationV1::new(demand.stage));
        self.chunks = Some(SourceOperationV1::new(demand.chunk));
        self.lifetime = Some(ObserverLifetime::begin());
        Ok(())
    }

    fn receive_once(&mut self, original: &mut SourceServingOriginalLoanV1<'_>) -> Result<(), SourceReceivingClosedV1> {
        if self.closed.is_some() || self.connection.is_some() || !self.entered { return self.close(); }
        self.connection = Some(SourceConnectionV1::new());
        let connection = self.connection.as_mut().ok_or(CLOSED)?;
        let operation = self.operation.as_mut().ok_or(CLOSED)?;
        let geometry = self.geometry.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.receive = Some(connection.accept_once(original, operation).and_then(|()| {
            connection.receive_once(original, operation, self.chunks.as_mut().ok_or(CLOSED)?,
                geometry, self.lifetime.as_ref().ok_or(CLOSED)?.clone())
        }));
        if matches!(self.receive, Some(Ok(()))) { Ok(()) } else { self.close() }
    }

    fn finish_once(
        &mut self,
        original: &mut SourceServingOriginalLoanV1<'_>,
        key: &SigningKey,
        generation: u64,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.closed.is_some() || !matches!(self.receive, Some(Ok(()))) || self.finish.is_some() {
            return self.close();
        }
        let connection = self.connection.as_mut().ok_or(CLOSED)?;
        self.finish = Some(connection.finish_once(original, self.operation.as_mut().ok_or(CLOSED)?,
            self.lifetime.as_ref().ok_or(CLOSED)?, key, generation));
        if !matches!(self.finish, Some(Ok(()))) || !connection.positive() {
            original.peak.retain_failed_lane();
            return self.close();
        }

        // Actual endpoint/EOF/request/view/raw send Results and every positive
        // native sample are disposed before the resident readonly peak reopens.
        // Operation capacities and old charged debts remain permanently paid.
        drop(self.connection.take());
        original.peak.finish_after_actual_positive_disposal();
        self.receive = None;
        self.finish = None;
        Ok(())
    }

    fn close(&mut self) -> Result<(), SourceReceivingClosedV1> {
        self.closed.get_or_insert(CLOSED);
        if let Some(lifetime) = &self.lifetime { lifetime.close(); }
        Err(CLOSED)
    }

    pub(super) fn failure<'a>(
        &'a self,
        inputs: &'a SourceRootPeerInputsV1,
        ledger: Option<&'a dyn RepresentationDemandDebitV1>,
        peak: &'a SourceReadonlyPeakV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        failure(&self.geometry).or_else(|| failure(&self.demand))
            .or_else(|| failure(&self.physical)).or_else(|| failure(&self.financial))
            .or_else(|| if matches!(self.reservation, Some(Err(_))) {
                ledger.and_then(|ledger| ledger.failure()).map(|error| error as _)
            } else { None })
            .or_else(|| self.connection.as_ref().and_then(|connection| {
                ledger.and_then(|ledger| connection.failure(inputs, ledger, peak))
            }))
            .or_else(|| self.operation.as_ref().and_then(SourceOperationV1::failure))
            .or_else(|| self.chunks.as_ref().and_then(SourceOperationV1::failure))
            .or_else(|| failure(&self.receive)).or_else(|| failure(&self.finish))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl SourceSignerServiceOriginalV1 {
    /// Receives one established request on the same paid Source original.
    ///
    /// No signing input is borrowed until strict Root identity, exact framing,
    /// genuine EOF and canonical decoding succeed. Source07 and Source16 refuse
    /// here without opening the native Source view or issuing a signed packet.
    ///
    /// # Errors
    /// Retains the entire first refused connection, native/post outcomes and
    /// accounting cause. Reentry cannot replace it or resume a failed service.
    pub fn receive_source_readonly_request_once_v1(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.receive_source_readonly_inner().is_err() {
            return Err(self.fail(super::Failure::Serving));
        }
        Ok(())
    }

    fn receive_source_readonly_inner(&mut self) -> Result<(), SourceReceivingClosedV1> {
        self.require_serving_original()?;
        if !self.serving.entered {
            self.serving_resident_geometry = Some(self.serving_resident_files());
            let resident = self.serving_resident_geometry.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(CLOSED)?;
            let permanent = self.common.permanent_open_files()?;
            if self.serving.initialize_once(self.common.representation.as_mut().ok_or(CLOSED)?, resident, permanent).is_err() {
                return Err(self.fail(super::Failure::Serving));
            }
        }
        let controller_uid = self.root_inputs.controller_uid().map_err(|_| CLOSED)?;
        let mut loan = SourceServingOriginalLoanV1 {
            process: &mut self.common.process, anchor: self.common.cgroup.as_ref().ok_or(CLOSED)?,
            limits: &self.common.limits,
            initial_info: self.common.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?,
            initial_identity: self.common.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?,
            inputs: &mut self.root_inputs, ledger: self.common.representation.as_mut().ok_or(CLOSED)?,
            peak: &mut self.readonly_peak, listener: &self.listener, controller_uid,
        };
        if self.serving.receive_once(&mut loan).is_err() {
            return Err(self.fail(super::Failure::Serving));
        }
        Ok(())
    }

    /// Completes only the resident canonical request with Source-owned inputs.
    ///
    /// The sole fixed-image Source executable lends its retained independently
    /// pinned private key and generation. These inputs choose no recipe, bytes,
    /// receiver, path, currentness token or budget; Native already owns them.
    ///
    /// # Errors
    /// Retains the whole view/signature, partial sends, shutdown and independent
    /// posts. Only full positive disposal allows another request on this F.
    pub fn finish_source_readonly_request_once_v1(
        &mut self,
        key: &SigningKey,
        generation: u64,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.finish_source_readonly_inner(key, generation).is_err() {
            return Err(self.fail(super::Failure::Serving));
        }
        Ok(())
    }

    fn finish_source_readonly_inner(
        &mut self,
        key: &SigningKey,
        generation: u64,
    ) -> Result<(), SourceReceivingClosedV1> {
        self.require_serving_original()?;
        let controller_uid = self.root_inputs.controller_uid().map_err(|_| CLOSED)?;
        let mut loan = SourceServingOriginalLoanV1 {
            process: &mut self.common.process, anchor: self.common.cgroup.as_ref().ok_or(CLOSED)?,
            limits: &self.common.limits,
            initial_info: self.common.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?,
            initial_identity: self.common.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?,
            inputs: &mut self.root_inputs, ledger: self.common.representation.as_mut().ok_or(CLOSED)?,
            peak: &mut self.readonly_peak, listener: &self.listener, controller_uid,
        };
        if self.serving.finish_once(&mut loan, key, generation).is_err() {
            return Err(self.fail(super::Failure::Serving));
        }
        Ok(())
    }

    fn serving_resident_files(&self) -> Result<u64, SourceServingResidentErrorV1> {
        let native = self.common.fixed_startup_demand()?;
        let credential = self.credential_receiving.physical_demand()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let inputs = self.root_inputs_receiving.physical_demand()?;
        let readonly = SourceReadonlyReceivingContextV1::fixed_demand()?;
        // Native startup includes Source listener and its second sample. The
        // actual Root inputs, private credential and readonly view survive
        // concurrently with the new connection, full Root stage and raw chunk.
        Ok(native.checked_add(credential)?.checked_add(inputs)?.checked_add(readonly)?.get(D::OpenFiles))
    }

    fn require_serving_original(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.require_permanent_fd_coverage_v1().is_err()
            || !self.credential_receiving.complete() || !self.root_inputs.complete()
        {
            return Err(self.fail(super::Failure::Serving));
        }
        Ok(())
    }
}

pub(super) fn remaining(started: Instant) -> Result<Duration, SourceReceivingClosedV1> {
    FLIGHT_TIMEOUT.checked_sub(started.elapsed()).filter(|duration| !duration.is_zero()).ok_or(CLOSED)
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_original_cannot_enter_serving_or_later_recapture_a_table() {
        // Even an unobserved original arms the production initial-table Drop fence.
        // Keep this inert destination resident; no descriptor was captured.
        let mut original = std::mem::ManuallyDrop::new(SourceSignerServiceOriginalV1::new());

        assert!(original.receive_source_readonly_request_once_v1().is_err());
        let cause = original.failure().unwrap() as *const dyn Error;

        assert!(!original.common.entered);
        assert!(!original.serving.entered);
        assert!(original.serving.connection.is_none());
        assert!(original.capture_once().is_err());
        assert!(!original.common.entered);
        assert!(std::ptr::eq(cause, original.failure().unwrap()));
    }

    #[test]
    fn a_key_is_not_an_original_or_a_resident_request() {
        // Even an unobserved original arms the production initial-table Drop fence.
        // Keep this inert destination resident; no descriptor was captured.
        let mut original = std::mem::ManuallyDrop::new(SourceSignerServiceOriginalV1::new());
        let key = SigningKey::from_bytes(&[9; 32]);

        assert!(original.finish_source_readonly_request_once_v1(&key, 1).is_err());

        assert!(!original.common.entered);
        assert!(!original.serving.entered);
        assert!(original.serving.connection.is_none());
    }
}

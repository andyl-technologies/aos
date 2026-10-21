//! Holds the genuine same-C18 Root Environment exchange through Source lease publication.
//!
//! The private concrete Source scope remains the payer and same-C original at
//! every growth boundary. The fixed Root connection and before/owed-after peer
//! engine are the existing canonical native recipes. Framing is DATA; only this
//! resident owner can lend the provisional input to the closed Source planner.

use std::error::Error;
use std::mem::size_of;
use std::sync::Arc;
use std::os::fd::AsFd as _;

use aos_sandbox_model::{ExecutionId, OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1 as Demand;
use crate::controller_resource_reservation::{ControllerResourceBankOpeningV1, ControllerExecutionSourceScopeV1};
use crate::controller_execution_operation::ControllerExecutionClockOriginalV1;
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::environment::deployment::{RootEnvironmentProvisionalDataV1,
    transport::{EnvironmentRootOpenDataV1, EnvironmentRootResponseDataV1, EnvironmentRootClosedDataV1,
        OPEN_BYTES, RESPONSE_BYTES, CLOSED_BYTES}};
use crate::journal::{Journal, JournalError};
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::bounded_stream_io::SliceDeadlineStreamIoV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1 as Direction;
use super::{ProductionControllerNormalRootProfileV1, root_connection::ControllerRootConnectionOriginalV1};
use super::peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1, StableRootPeerV1, sample::PeerSampleV1};

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
#[error("the genuine Root Environment exchange is incomplete or retains a refusal")]
struct Closed;

/// Holds the actual funded Root peer, exact frames and all native originals.
pub(crate) struct RootEnvironmentClientOriginalV1 {
    profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
    connection: ControllerRootConnectionOriginalV1,
    before: Option<Box<PeerSampleV1>>,
    after: Option<Box<PeerSampleV1>>,
    stable: Option<StableRootPeerV1>,
    opening: Option<EnvironmentRootOpenDataV1>,
    opening_bytes: [u8; OPEN_BYTES],
    response_bytes: [u8; RESPONSE_BYTES],
    response: Option<EnvironmentRootResponseDataV1>,
    body: Vec<u8>,
    provisional: Option<Result<RootEnvironmentProvisionalDataV1, crate::environment::EnvironmentModelError>>,
    closed_bytes: [u8; CLOSED_BYTES],
    closed: Option<EnvironmentRootClosedDataV1>,
    opening_io: FixedDeadlineStreamIoV1<OPEN_BYTES>,
    response_io: FixedDeadlineStreamIoV1<RESPONSE_BYTES>,
    body_io: SliceDeadlineStreamIoV1,
    closed_io: FixedDeadlineStreamIoV1<CLOSED_BYTES>,
    eof_io: FixedDeadlineStreamIoV1<1>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    funding: Option<Result<(), crate::ResourceReservationErrorV1>>,
    initial: Option<Result<(), Cause>>,
    final_result: Option<Result<(), Cause>>,
    native_after: Option<Result<(), super::NormalRootStartupErrorV1>>,
    settlement: Option<Result<(), super::NormalRootStartupErrorV1>>,
    closed_entry: Option<JournalError>,
}

impl RootEnvironmentClientOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { profile: None, connection: Default::default(), before: None, after: None, stable: None,
            opening: None, opening_bytes: [0; OPEN_BYTES], response_bytes: [0; RESPONSE_BYTES], response: None,
            body: Vec::new(), provisional: None, closed_bytes: [0; CLOSED_BYTES], closed: None,
            opening_io: Default::default(), response_io: Default::default(), body_io: Default::default(),
            closed_io: Default::default(), eof_io: Default::default(), shutdown: None, funding: None,
            initial: None, final_result: None, native_after: None, settlement: None, closed_entry: None }
    }

    pub(crate) fn fixed_receiving_demand_v1(profile: &ProductionControllerNormalRootProfileV1)
        -> Option<ResourceVector>
    {
        let bytes = size_of::<Self>().checked_mul(3)?;
        let (wire, log) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(2)?;
        CreateStorageRootPeerReceivingOriginalsV1::environment_native_peak_v1(profile)?
            .checked_add(ControllerRootConnectionOriginalV1::receiving_demand_v1()?).ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::NetworkBytes, wire.checked_add(u64::try_from(OPEN_BYTES + RESPONSE_BYTES + CLOSED_BYTES + 1).ok()?)?)
                .with(D::LogBytes, log)).ok()
    }

    /// Starts only under the actual same original Execution Source/C scope.
    ///
    /// # Errors
    /// Retains native, wire, financial and model refusals. An entered owner is
    /// not replaced; its independently funded native after remains owed.
    pub(crate) fn open_once_v1(&mut self, source: &mut ControllerExecutionSourceScopeV1<'_, '_>,
        complete: &mut ResourceVector, bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal, profile: &Arc<ProductionControllerNormalRootProfileV1>,
        operation: OperationId, execution: ExecutionId, parent: &ExecutionParentResourceSourceV1,
        assignment: &crate::runtime_scope::CurrentAssignmentTarget, clock: &mut ControllerExecutionClockOriginalV1,
    ) -> Result<(), JournalError> {
        if self.funding.is_some() || self.closed_entry.is_some() {
            self.closed_entry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let fixed = Self::fixed_receiving_demand_v1(profile).ok_or(JournalError::JournalTooLarge)?;
        self.fund_v1(source, complete, bank, controller, profile, fixed)?;
        self.profile = Some(Arc::clone(profile));
        self.before = Some(Box::new(PeerSampleV1::new()));
        self.after = Some(Box::new(PeerSampleV1::new()));
        self.initial = Some(self.open_inner_v1(source, complete, bank, controller,
            operation, execution, parent, assignment, clock));
        if matches!(self.initial, Some(Ok(()))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    fn fund_v1(&mut self, source: &mut ControllerExecutionSourceScopeV1<'_, '_>,
        complete: &mut ResourceVector, bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        additional: ResourceVector,
    ) -> Result<(), JournalError> {
        let next = complete.checked_add(additional).map_err(|_| JournalError::JournalTooLarge)?;
        self.funding = Some(bank.require_execution_source_complete_v1(source, controller, profile,
            Demand::from_demand_v1(next)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        *complete = next;
        Ok(())
    }

    fn open_inner_v1(&mut self, source: &mut ControllerExecutionSourceScopeV1<'_, '_>,
        complete: &mut ResourceVector, bank: &ControllerResourceBankOpeningV1, controller: &mut Journal,
        operation: OperationId, execution: ExecutionId, parent: &ExecutionParentResourceSourceV1,
        assignment: &crate::runtime_scope::CurrentAssignmentTarget, clock: &mut ControllerExecutionClockOriginalV1,
    ) -> Result<(), Cause> {
        let original = clock.sample_v1()?;
        let open = EnvironmentRootOpenDataV1 { operation: *operation.as_bytes(), original,
            cutoff: assignment.deadline_boottime_nanoseconds(), expires: assignment.expires_wall_seconds() };
        self.opening_bytes = open.encode()?;
        self.opening = Some(open);
        self.connection.connect_once()?;
        let profile = self.profile.as_ref().ok_or(Closed)?;
        let stream = self.connection.stream()?;
        let before = self.before.as_mut().ok_or(Closed)?;
        before.observe_with_cutoff_once_v1(profile, stream, None, None, false, open.cutoff)?;
        before.settle_positive_once()?;
        self.stable = before.take_initial_binding();
        if self.stable.is_none() { return Err(Closed.into()); }
        self.require_clock_v1(clock)?;
        let stream = self.connection.stream_mut()?;
        self.opening_io.run_once(stream, &mut self.opening_bytes, open.cutoff, Direction::Write)?;
        self.response_io.run_once(stream, &mut self.response_bytes, open.cutoff, Direction::Read)?;
        let response = EnvironmentRootResponseDataV1::decode(&self.response_bytes)?;
        if response.operation != open.operation || response.execution != *execution.as_bytes()
            || response.project != *parent.assignment().manifest().project().as_bytes()
            || response.sandbox != *parent.assignment().manifest().sandbox().as_bytes()
            || response.opening != open.digest()?
        { return Err(Closed.into()); }
        require_clock_data(open, response.observed)?;
        self.response = Some(response);
        let length = response.body_bytes()?;
        let additional = RootEnvironmentProvisionalDataV1::receiving_demand_v1(response)?;
        // The actual header announces the three sole canonical decoder extents.
        // No body allocation or parser collection precedes this same-C check.
        let profile = Arc::clone(self.profile.as_ref().ok_or(Closed)?);
        self.fund_v1(source, complete, bank, controller, &profile, additional)?;
        self.require_clock_v1(clock)?;
        self.body.try_reserve_exact(length)?;
        self.body.resize(length, 0);
        self.body_io.run_once(self.connection.stream_mut()?, &mut self.body, open.cutoff, Direction::Read)?;
        self.require_clock_v1(clock)?;
        self.provisional = Some(RootEnvironmentProvisionalDataV1::decode_v1(response, &self.body));
        let provisional = self.provisional.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Closed)?;
        if provisional.manifest_v1().environment_descriptor() != parent.assignment().manifest().environment()
            || provisional.manifest_v1().facade().descriptor() != parent.assignment().manifest().root_view()
        { return Err(Closed.into()); }
        Ok(())
    }

    fn require_clock_v1(&self, clock: &mut ControllerExecutionClockOriginalV1) -> Result<(), Cause> {
        require_clock_data(self.opening.ok_or(Closed)?, clock.sample_v1()?).map_err(Into::into)
    }

    /// Lends historical DATA only while the actual authenticated Root is held.
    pub(crate) fn provisional_v1(&self) -> Result<&RootEnvironmentProvisionalDataV1, JournalError> {
        if !matches!(self.initial, Some(Ok(()))) || self.final_result.is_some() || self.closed_entry.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.provisional.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
    }

    /// Completes Root's business interval after real Source lease readback.
    ///
    /// The caller supplies the privately completed Source publication, never a
    /// bool, EOF or decoded activation. Root independently checks its own native
    /// publication and posts; it does not attest the client's Source append.
    pub(crate) fn finish_once_v1(&mut self,
        publication: &crate::environment::deployment::EnvironmentSourcePublicationOriginalV1,
        clock: &mut ControllerExecutionClockOriginalV1,
    ) -> Result<(), JournalError> {
        if self.final_result.is_some() || !matches!(self.initial, Some(Ok(()))) {
            self.closed_entry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.final_result = Some(self.finish_inner_v1(publication, clock));
        self.finish_native_after_once_v1();
        if matches!(self.final_result, Some(Ok(()))) && matches!(self.native_after, Some(Ok(())))
            && matches!(self.settlement, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    fn finish_inner_v1(&mut self, publication: &crate::environment::deployment::EnvironmentSourcePublicationOriginalV1,
        clock: &mut ControllerExecutionClockOriginalV1,
    ) -> Result<(), Cause> {
        let open = self.opening.ok_or(Closed)?;
        let response = self.response.ok_or(Closed)?;
        publication.require_completed_for_root_v1(response)?;
        self.require_clock_v1(clock)?;
        self.shutdown = Some(rustix::net::shutdown(self.connection.stream()?.as_fd(), rustix::net::Shutdown::Write));
        if !matches!(self.shutdown, Some(Ok(()))) { return Err(Closed.into()); }
        self.closed_io.run_once(self.connection.stream_mut()?, &mut self.closed_bytes, open.cutoff, Direction::Read)?;
        let closed = EnvironmentRootClosedDataV1::decode(&self.closed_bytes)?;
        if closed.operation != open.operation || closed.response != response.complete_digest(&self.body)? {
            return Err(Closed.into());
        }
        require_clock_data(open, closed.observed)?;
        self.closed = Some(closed);
        self.require_clock_v1(clock)?;
        let mut eof = [0; 1];
        self.eof_io.run_once(self.connection.stream_mut()?, &mut eof, open.cutoff, Direction::Eof)?;
        Ok(())
    }

    /// Runs the already funded after even after an earlier native or body refusal.
    pub(crate) fn finish_native_after_once_v1(&mut self) {
        if self.native_after.is_some() || self.before.is_none() { return; }
        self.native_after = Some((|| {
            let profile = self.profile.as_ref().ok_or(super::NormalRootStartupErrorV1::Service)?;
            let stream = self.connection.stream().map_err(|_| super::NormalRootStartupErrorV1::Service)?;
            self.after.as_mut().ok_or(super::NormalRootStartupErrorV1::Service)?
                .observe_with_cutoff_once_v1(profile, stream, self.stable.as_ref(), None, true,
                    self.opening.ok_or(super::NormalRootStartupErrorV1::Service)?.cutoff)
        })());
        if matches!(self.native_after, Some(Ok(()))) {
            self.settlement = Some(self.after.as_mut().ok_or(super::NormalRootStartupErrorV1::Service)
                .and_then(|after| after.settle_positive_once()));
        }
    }

    pub(crate) fn completed_evidence_v1(&self) -> Result<&[u8], JournalError> {
        if !matches!(self.final_result, Some(Ok(()))) || !matches!(self.native_after, Some(Ok(())))
            || !matches!(self.settlement, Some(Ok(()))) || self.closed_entry.is_some()
        { return Err(JournalError::ProtectedBoundary); }
        self.provisional.as_ref().and_then(|value| value.as_ref().ok())
            .map(RootEnvironmentProvisionalDataV1::evidence_v1).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn response_data_v1(&self) -> Result<EnvironmentRootResponseDataV1, JournalError> {
        self.provisional_v1()?;
        self.response.ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn lease_cutoff_v1(&self) -> Result<u64, JournalError> {
        let provisional = self.provisional_v1()?;
        let expiry = provisional.valid_until_wall_seconds_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let root = self.response.ok_or(JournalError::ProtectedBoundary)?.observed;
        // The authenticated Root pair uses the same conservative integer-wall
        // conversion as every other non-renewable clock boundary. Its omitted
        // fractional second cannot extend this Source lease past expiry.
        let certificate = root.conservative_expiry_deadline_data_v1(expiry)
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(self.opening.ok_or(JournalError::ProtectedBoundary)?.cutoff.min(certificate))
    }

    /// Lends only the actual held interval's already-clamped comparison bound.
    pub(crate) fn source_publication_horizon_data_v1(&self) -> Result<EnvironmentRootOpenDataV1, JournalError> {
        self.provisional_v1()?;
        let mut bound = self.opening.ok_or(JournalError::ProtectedBoundary)?;
        bound.cutoff = self.lease_cutoff_v1()?;
        Ok(bound)
    }

    pub(crate) fn trusted_time_v1(&self, now: aos_sandbox_model::RawPairedClockSample)
        -> Result<crate::environment::EnvironmentTrustedTimeV1, JournalError>
    {
        let provisional = self.provisional_v1()?;
        require_clock_data(self.opening.ok_or(JournalError::ProtectedBoundary)?, now)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        crate::environment::trusted_provisioned_time_data_v1(provisional.evidence_v1(), now)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_completed_current_data_v1(&self, boot: aos_sandbox_model::ObjectDigest,
        boottime: u64,
    ) -> Result<(), JournalError> {
        self.completed_evidence_v1()?;
        let open = self.opening.ok_or(JournalError::ProtectedBoundary)?;
        if boot != crate::environment::provisioned_kernel_boot_data_v1(open.original.host_boot_id())
            || boottime < self.closed.ok_or(JournalError::ProtectedBoundary)?.observed.boottime_nanoseconds()
            || boottime >= open.cutoff
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.before.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| self.connection.failure())
            .or_else(|| self.opening_io.failure()).or_else(|| self.response_io.failure()).or_else(|| self.body_io.failure())
            .or_else(|| self.provisional.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.initial.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.closed_io.failure()).or_else(|| self.eof_io.failure())
            .or_else(|| self.shutdown.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.final_result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.after.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| self.native_after.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.settlement.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed_entry.as_ref().map(|cause| cause as _))
    }
}

fn require_clock_data(open: EnvironmentRootOpenDataV1, actual: aos_sandbox_model::RawPairedClockSample) -> Result<(), Closed> {
    open.require_later_sample_v1(actual).map_err(|_| Closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};

    fn sample(wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16], wall, boottime).unwrap()
    }

    #[test]
    fn comparison_reuses_the_canonical_paired_clock_law_and_original_cutoff() {
        let original = sample(100, 1_000_000_000);
        let open = EnvironmentRootOpenDataV1 {
            operation: [3; 16], original, cutoff: 10_000_000_000, expires: 110,
        };

        assert!(require_clock_data(open, sample(101, 2_000_000_000)).is_ok());
        assert!(require_clock_data(open, sample(99, 2_000_000_000)).is_err());
        assert!(require_clock_data(open, sample(101, 10_000_000_000)).is_err());
        assert!(require_clock_data(open, sample(110, 2_000_000_000)).is_err());
        assert_eq!(original.conservative_expiry_deadline_data_v1(105), Some(5_000_000_000));
        assert_eq!(original.conservative_expiry_deadline_data_v1(101), None);
    }
}

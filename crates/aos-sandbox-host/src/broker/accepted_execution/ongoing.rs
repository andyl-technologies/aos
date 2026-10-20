//! Owns the signed version-five ongoing execution permission.
//!
//! The initial Host effect remains acquisition-bounded. This owner retains the
//! WHOLE actual durably admitted Host reservation, native-backed full source and
//! exact original Launch association beyond Authorize scratch disposal. Its
//! only factory runs before Guest issue under actual acquisition checks. It
//! grants no KILL, thaw, replacement lease or physical completion.

use std::sync::{Arc, Mutex, Weak};

use aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1;
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
use aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2;
use aos_sandbox_protocol::host_execution::admission_content::HostExecutionAdmissionContentV5;
use crate::storage_existing_output::StorageExistingOutputOriginalV2;

use crate::plan::HostExecutionRequestBindingV2;
use crate::storage_existing_output::capture::StorageCapturePipeLoanV2;
use crate::{HostError, Result};
use super::super::{HostExecutionGrantReservationV1, HostExecutionGrantRequestV1};
use super::super::argument_handoff::ArgumentStageOriginalV2;
use super::super::launch_handoff::HostLaunchOriginalV2;

enum ExecutionSourceDataV5 {
    Stream(StorageCaptureExecutionLifetimeDataV2),
    Capture(StorageCaptureGrantSourceV2),
}

impl ExecutionSourceDataV5 {
    fn lifetime(&self) -> &StorageCaptureExecutionLifetimeDataV2 {
        match self {
            Self::Stream(lifetime) => lifetime,
            Self::Capture(source) => source.lifetime_v2(),
        }
    }

    fn digest(&self) -> aos_sandbox_core::ObjectDigest {
        match self {
            Self::Stream(lifetime) => lifetime.digest_v2(),
            Self::Capture(source) => source.source_digest_v2(),
        }
    }
}

pub(in crate::broker) struct HostExecutionOngoingOriginalV5 {
    reservation: HostExecutionGrantReservationV1,
    source: ExecutionSourceDataV5,
    stage: Weak<Mutex<ArgumentStageOriginalV2>>,
    launch: Weak<Mutex<HostLaunchOriginalV2>>,
    accept: HostExecutionRequestBindingV2,
    comparison: Option<aos_sandbox_broker::BrokerEffectClockComparisonV3>,
    deadline: Option<u64>,
    // The native baseline moves here only after actual Authorize Commit/Sent
    // and all independent posts. No later interval captures a replacement.
    original_clock: Option<super::super::argument_handoff::ArgumentClockV2>,
    preparation: Option<std::result::Result<(), HostExecutionOngoingErrorV5>>,
}

#[derive(Debug, thiserror::Error)]
enum HostExecutionOngoingErrorV5 {
    #[error(transparent)] Host(#[from] HostError),
    #[error(transparent)] Clock(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
    #[error(transparent)] Broker(#[from] aos_sandbox_broker::BrokerAdmissionError),
    #[error(transparent)] Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
}

impl HostExecutionOngoingOriginalV5 {
    pub(super) fn new(
        reservation: HostExecutionGrantReservationV1, content: &HostExecutionAdmissionContentV5<'_>,
        actual_stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        actual_launch: &Arc<Mutex<HostLaunchOriginalV2>>,
        accept: HostExecutionRequestBindingV2,
    ) -> Self {
        let source = match content.capture_source_v2() {
            Some(source) => ExecutionSourceDataV5::Capture(*source),
            None => ExecutionSourceDataV5::Stream(*content.lifetime_v2()),
        };
        Self { reservation, source, stage: Arc::downgrade(actual_stage),
            launch: Arc::downgrade(actual_launch), accept, comparison: None,
            deadline: None, original_clock: None, preparation: None }
    }

    pub(super) fn prepare_before_issue_v5(
        &mut self, authenticated: &AuthenticatedBrokerMethodRequestV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        logical: &StorageExistingOutputOriginalV2,
        pipes: Option<&StorageCapturePipeLoanV2<'_>>,
    ) -> Result<()> {
        if self.preparation.is_some() { return Err(refused().into()); }
        self.preparation = Some(self.prepare_inner(authenticated, claim, logical, pipes));
        if matches!(self.preparation, Some(Ok(()))) { Ok(()) } else { Err(refused()) }
    }

    fn prepare_inner(&mut self, authenticated: &AuthenticatedBrokerMethodRequestV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        logical: &StorageExistingOutputOriginalV2,
        pipes: Option<&StorageCapturePipeLoanV2<'_>>,
    ) -> std::result::Result<(), HostExecutionOngoingErrorV5> {
        self.require_storage_v5(logical, pipes)?;
        let lifetime = self.source.lifetime();
        let reservation = &self.reservation;
        let HostExecutionGrantRequestV1::Apply(apply) = reservation.request() else {
            return Err(refused().into());
        };
        if apply.content_version() != 5
            || apply.action() != aos_sandbox_core::runtime_backend::EffectOperationV1::AuthorizeExecution
            || !reservation.matches(authenticated.method(), authenticated.request_id(),
                authenticated.exact_body(), claim)
            || reservation.session_binding != authenticated.session_binding()
            || reservation.signed_request_digest != authenticated.signed_request_digest()
        { return Err(refused().into()); }
        let specification = apply.specification().ok_or_else(refused)?;
        let request = apply.admission_accepted_request_digest_v5().ok_or_else(refused)?;
        lifetime.require_specification_data_v2(specification,
            lifetime.original_create_operation_v2(),
            aos_sandbox_core::OperationId::from_bytes(apply.operation_id()), request)?;
        let verified = reservation.verified_lease();
        lifetime.require_original_lease_data_v2(verified.lease_digest(),
            verified.lease().lease_generation(), verified.lease().authority_expires_seconds(),
            verified.lease().maximum_clock_skew_seconds())?;

        let launch_arc = self.launch.upgrade().ok_or_else(refused)?;
        let launch = launch_arc.lock().map_err(|_| refused())?;
        if !launch.authenticated_sent || launch.first.is_some()
            || launch.agent_binding.is_none()
        { return Err(refused().into()); }
        let original_lease = launch.lease.as_ref().ok_or_else(refused)?;
        lifetime.require_original_lease_data_v2(original_lease.lease_digest(),
            original_lease.lease().lease_generation(), original_lease.lease().authority_expires_seconds(),
            original_lease.lease().maximum_clock_skew_seconds())?;
        let intersection = launch.intersection.as_ref().ok_or_else(refused)?;
        if intersection.lease_digest() != original_lease.lease_digest()
            || intersection.host_boot_id() != reservation.effect.host_boot_id()
        { return Err(refused().into()); }
        let effect = &reservation.effect;
        // These are immutable facts borrowed from this actual effect's native
        // admission, not a new clock sample or a replacement role proof.
        let admitted = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*effect.clock_provenance())?, *effect.host_boot_id(),
            effect.admitted_wall_seconds(), effect.admitted_boottime_nanoseconds(),
        )?;
        let comparison = aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(effect);
        comparison.require_fresh(&admitted)?;
        if let ExecutionSourceDataV5::Capture(source) = &self.source {
            if admitted.boottime_nanoseconds() >= source.original_source_v1().original_deadline_boottime_nanoseconds() {
                return Err(refused().into());
            }
        }
        let deadline = lifetime.tighten_admitted_deadline_data_v2(admitted,
            effect.plan_expires_seconds().min(intersection.plan_expires_seconds()),
            effect.local_lease_record().fail_stop_boottime_nanoseconds()
                .min(intersection.fail_stop_boottime_nanoseconds()))?
            .min(pipes.map_or(u64::MAX, StorageCapturePipeLoanV2::held_cutoff_v4));
        comparison.require_original_ongoing_clock_data_v4(&admitted, deadline)?;
        drop(launch);
        self.comparison = Some(comparison);
        self.deadline = Some(deadline);
        Ok(())
    }

    pub(super) fn retain_positive_original_clock_v5(
        &mut self,
        turn_clock: &mut Option<super::super::argument_handoff::ArgumentClockV2>,
    ) -> Result<()> {
        // Borrow before moving: every refusal leaves the actual native prefix
        // in its existing turn. This port creates no baseline or next interval.
        let actual = turn_clock.as_ref().ok_or_else(refused)?;
        if !matches!(self.preparation, Some(Ok(()))) || self.original_clock.is_some()
            || self.comparison.is_none() || actual.failure().is_some()
            || !actual.has_effect_comparison_v3()
        {
            return Err(refused());
        }
        self.original_clock = turn_clock.take();
        Ok(())
    }

    pub(super) fn reservation(&self) -> &HostExecutionGrantReservationV1 { &self.reservation }

    pub(in crate::broker) fn require_retained_storage_positive_v3(&self) -> Result<()> {
        if !matches!(self.preparation, Some(Ok(()))) || self.comparison.is_none()
            || self.deadline.is_none()
            || self.original_clock.as_ref().is_none_or(|clock| clock.failure().is_some())
        { return Err(refused()); }
        Ok(())
    }

    pub(in crate::broker) fn deadline_v5(&self) -> Result<u64> {
        if !matches!(self.preparation, Some(Ok(()))) { return Err(refused()); }
        self.deadline.ok_or_else(refused)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.preparation.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    pub(in crate::broker) fn require_same_v5(
        &self,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        accept: HostExecutionRequestBindingV2,
        logical: &StorageExistingOutputOriginalV2,
        pipes: Option<&StorageCapturePipeLoanV2<'_>>,
    ) -> Result<()> {
        self.require_same_stage_v5(stage, accept)?;
        self.require_storage_v5(logical, pipes)
    }

    fn require_storage_v5(
        &self,
        logical: &StorageExistingOutputOriginalV2,
        pipes: Option<&StorageCapturePipeLoanV2<'_>>,
    ) -> Result<()> {
        match (&self.source, pipes) {
            (ExecutionSourceDataV5::Stream(_), None) => {
                logical.held_proof_v2()?;
                if logical.failure().is_some() { return Err(refused()); }
            }
            (ExecutionSourceDataV5::Capture(expected), Some(pipes)) => {
                if pipes.borrowed_ongoing_source_v2().is_none_or(|actual|
                    actual.canonical_bytes_v2() != expected.canonical_bytes_v2())
                {
                    return Err(refused());
                }
            }
            _ => return Err(refused()),
        }
        Ok(())
    }

    pub(in crate::broker) fn source_digest_v5(&self) -> aos_sandbox_core::ObjectDigest {
        self.source.digest()
    }

    pub(in crate::broker) fn lifetime_v5(&self) -> &StorageCaptureExecutionLifetimeDataV2 {
        self.source.lifetime()
    }

    pub(in crate::broker) fn require_same_stage_v5(&self,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>, accept: HostExecutionRequestBindingV2) -> Result<()> {
        if !matches!(self.preparation, Some(Ok(())))
            || !self.stage.ptr_eq(&Arc::downgrade(stage)) || self.launch.upgrade().is_none()
            || self.accept != accept
        { return Err(refused()); }
        Ok(())
    }

    // Mechanical pre-admission clock custody for an actual fresh readonly
    // request. This returns no execution permission and evaluates no old
    // execution clock result. The query's actual native admission owns its
    // independent read scope and comparator before any result can be exposed.
    pub(in crate::broker) fn borrow_query_admission_clock_v3(&mut self,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>, accept: HostExecutionRequestBindingV2,
        query: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<&mut super::super::argument_handoff::ArgumentClockV2> {
        self.require_same_stage_v5(stage, accept)?;
        if query.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || query.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            || query.host_execution_query_data_v3().and_then(|query| query.monitor_v3()).is_none()
        { return Err(refused()); }
        let clock = self.original_clock.as_mut().ok_or_else(refused)?;
        if clock.failure().is_some() { return Err(refused()); }
        Ok(clock)
    }

    // The old execution clock supplies only its retained baseline here. The
    // actual new method58 admission owns its independent permission/clock law.
    pub(in crate::broker) fn borrow_transition_admission_clock_v5(&mut self,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>, accept: HostExecutionRequestBindingV2,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<&mut super::super::argument_handoff::ArgumentClockV2> {
        self.require_same_stage_v5(stage, accept)?;
        if request.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
            || request.authorization().is_none()
        { return Err(refused()); }
        let clock = self.original_clock.as_mut().ok_or_else(refused)?;
        if clock.failure().is_some() { return Err(refused()); }
        Ok(clock)
    }

    pub(in crate::broker) fn require_query_original_data_v3(&self,
        query: &aos_sandbox_protocol::host_execution::ValidatedHostExecutionQueryV1,
        first_observe: aos_sandbox_core::runtime_backend::BackendOperationIdV1,
    ) -> Result<()> {
        let selector = query.monitor_v3().ok_or_else(refused)?;
        let HostExecutionGrantRequestV1::Apply(apply) = self.reservation.request()
            else { return Err(refused()); };
        let content = apply.content_fields().ok_or_else(refused)?;
        if query.operation_id() != *self.source.lifetime().original_create_operation_v2().as_bytes()
            || query.execution_id() != self.source.lifetime().execution_v2()
            || query.source_commitment() != apply.source_commitment()
            || query.specification_digest() != self.source.lifetime().specification_digest_v2()
            || query.content_fields().bytes() != content.bytes()
            || query.content_fields().digest() != content.digest()
            || selector.runtime_v3() != self.reservation.runtime_handle
            || selector.source_v3() != self.source.digest() || selector.first_observe_v3() != first_observe
            || selector.source_kind_v3() != match &self.source { ExecutionSourceDataV5::Stream(_) => 1,
                ExecutionSourceDataV5::Capture(_) => 2 }
        { return Err(refused()); }
        Ok(())
    }

    pub(in crate::broker) fn borrow_monitor_v5<'permission>(
        &'permission mut self,
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        accept: HostExecutionRequestBindingV2,
    ) -> Result<(HostExecutionMonitorPermissionV5<'permission>,
        &'permission mut super::super::argument_handoff::ArgumentClockV2)> {
        self.require_same_stage_v5(stage, accept)?;
        let clock = self.original_clock.as_mut().ok_or_else(refused)?;
        if clock.failure().is_some() { return Err(refused()); }
        Ok((HostExecutionMonitorPermissionV5 {
            reservation: &self.reservation, source: &self.source,
            comparison: self.comparison.as_ref().ok_or_else(refused)?,
            deadline: self.deadline.ok_or_else(refused)?,
        }, clock))
    }

    pub(in crate::broker) fn require_clock_v5(&self, sample: &RawPairedClockSample) -> Result<()> {
        self.comparison.as_ref().ok_or_else(refused)?
            .require_original_ongoing_clock_data_v4(sample, self.deadline_v5()?)
            .map_err(HostError::from)
    }
}

// This borrower keeps the actual signed/native reservation continuously live.
// Only the owning preparation above constructs it; copied source DATA cannot.
pub(in crate::broker) struct HostExecutionMonitorPermissionV5<'permission> {
    reservation: &'permission HostExecutionGrantReservationV1,
    source: &'permission ExecutionSourceDataV5,
    comparison: &'permission aos_sandbox_broker::BrokerEffectClockComparisonV3,
    deadline: u64,
}

impl HostExecutionMonitorPermissionV5<'_> {
    pub(in crate::broker) fn lifetime_v5(&self) -> &StorageCaptureExecutionLifetimeDataV2 {
        self.source.lifetime()
    }

    pub(in crate::broker) fn source_digest_v5(&self) -> aos_sandbox_core::ObjectDigest {
        self.source.digest()
    }

    pub(in crate::broker) fn original_source_commitment_v5(&self) -> Result<aos_sandbox_core::ObjectDigest> {
        let HostExecutionGrantRequestV1::Apply(request) = self.reservation.request()
            else { return Err(refused()); };
        Ok(request.source_commitment())
    }

    pub(in crate::broker) fn deadline_v5(&self) -> u64 { self.deadline }

    pub(in crate::broker) fn require_clock_v5(&self, sample: &RawPairedClockSample) -> Result<()> {
        self.comparison.require_original_ongoing_clock_data_v4(sample, self.deadline)
            .map_err(HostError::from)
    }

    pub(in crate::broker) fn require_claim_binding_v5(
        &self, claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<()> {
        if self.reservation.assignment != super::super::execution_assignment(claim)?
            || self.reservation.runtime_handle != claim.currentness().runtime().handle()
            || self.source.lifetime().execution_v2().as_bytes() == &[0; 16]
        { return Err(refused()); }
        Ok(())
    }
}

fn refused() -> HostError {
    HostError::Fence("Host ongoing execution lacks its same signed native resident permission")
}

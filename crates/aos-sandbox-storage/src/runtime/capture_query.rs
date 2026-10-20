//! Retains a freshly authorized, observation-only Capture Query61.
//!
//! The same current Storage State and configured Output writer remain held
//! through signed admission, canonical historical readback, the fresh final
//! authority cut and both independently prepaid native service/Output posts.
//! No reserve lifetime, State encoder, ZFS operation or worker can enter here.

use super::*;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use crate::broker::CaptureQueryCutV3;
use crate::execution_output::{ExecutionOutputLedgerErrorV1, ProtectedCaptureQueryDataV2};
use crate::execution_output_credential::{StorageExecutionOutputCustodyV1, StorageOutputOwedAfterV1};

/// Keeps the actual typed pure and native-projection query refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureQueryErrorV3 {
    #[error("the actual signed historical Capture query is closed or changed")]
    Closed,
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Admission(#[from] crate::StorageAdmissionError),
    #[error(transparent)]
    State(#[from] crate::StorageStateError),
    #[error(transparent)]
    Output(#[from] ExecutionOutputLedgerErrorV1),
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)]
    Complete(#[from] aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordErrorV2),
    #[error(transparent)]
    Clock(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
}

#[derive(Clone, Copy)]
enum First { Shape, Before, Arm, Demand, Payment, AfterArm, Clock(usize), Cut(usize), Query, Response, Decode, Comparison, Post, After }

#[derive(Debug, thiserror::Error)]
enum CaptureQueryClockErrorV3 {
    #[error("the original Capture Query kernel clock is stale or unavailable")]
    Stale,
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for CaptureQueryClockErrorV3 {
    fn stale() -> Self { Self::Stale }
    fn kernel(error: aos_sandbox_linux::Error) -> Self { Self::Kernel(error) }
}

type KernelClock = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<CaptureQueryClockErrorV3>;
type Sample = Result<RawPairedClockSample, CaptureQueryClockErrorV3>;

/// Owns one attempt's actual readback and every reached negative prefix.
///
/// Construction is inert. Only the configured Runtime method enters this owner
/// using the actual ServerReceive61, same lifecycle original and Output custody.
pub(crate) struct OriginalStorageCaptureQueryV3 {
    request: Option<AuthenticatedBrokerMethodRequestV1>,
    clocks: [KernelClock; 2],
    samples: [Option<Sample>; 2],
    cuts: [Option<Result<CaptureQueryCutV3, CaptureQueryErrorV3>>; 2],
    before: Option<Result<(), crate::service::StorageServiceError>>,
    arm: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    demand: Option<Result<ResourceVector, CaptureQueryErrorV3>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    after_arm: Option<Result<(), crate::service::StorageServiceError>>,
    after: StorageOutputOwedAfterV1,
    query: Option<Result<Option<ProtectedCaptureQueryDataV2>, ExecutionOutputLedgerErrorV1>>,
    response: Option<Result<Vec<u8>, aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordErrorV2>>,
    decoded: Option<Result<aos_sandbox_protocol::storage_capture_grant::ValidatedStorageCaptureQueryResponseV2,
        aos_sandbox_protocol::ProtocolValidationError>>,
    comparison: Option<Result<(), CaptureQueryErrorV3>>,
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    after_result: Option<Result<(), crate::service::StorageServiceError>>,
    first: Option<First>,
    entered: bool,
}

impl OriginalStorageCaptureQueryV3 {
    pub(crate) fn new() -> Self {
        Self {
            request: None,
            clocks: std::array::from_fn(|_| KernelClock::default()), samples: [None, None],
            cuts: [None, None], before: None, arm: None, demand: None, payment: None,
            after_arm: None, after: StorageOutputOwedAfterV1::new(), query: None,
            response: None, decoded: None, comparison: None, post: None,
            after_result: None, first: None, entered: false,
        }
    }

    pub(crate) fn request_v3(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> { self.request.as_ref() }

    pub(crate) fn response_v3(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.comparison, Some(Ok(())))
            || !matches!(self.post, Some(Ok(()))) || !matches!(self.after_result, Some(Ok(())))
        { return None; }
        self.response.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    pub(crate) fn failure_v3<'cause>(&'cause self, output: &'cause StorageExecutionOutputCustodyV1)
        -> Option<&'cause (dyn std::error::Error + 'static)>
    {
        match self.first? {
            First::Shape => Some(&CaptureQueryErrorV3::Closed),
            First::Before => output.receiving_current_failure_v1()
                .or_else(|| self.before.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Arm => self.arm.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Demand => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Payment => self.payment.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AfterArm | First::After => self.after.failure(),
            First::Clock(index) => self.clocks.get(index)?.failure()
                .or_else(|| self.samples.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Cut(index) => self.cuts.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Query => self.query.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Response => self.response.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Decode => self.decoded.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Comparison => self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Post => self.post.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn query_original_capture_ongoing_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        output: &mut StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        original: &mut OriginalStorageCaptureQueryV3,
    ) {
        if original.entered { return; }
        original.entered = true;
        if self.readiness != StorageRuntimeReadiness::Ready
            || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1
            || request.storage_execution_capture_source_ongoing_v2().is_none()
        { original.first = Some(First::Shape); return; }

        original.before = Some(output.recheck_session_receiving_v1(lifecycle, session, socket));
        if !matches!(original.before, Some(Ok(()))) { original.first = Some(First::Before); return; }
        original.arm = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
        if !matches!(original.arm, Some(Ok(()))) { original.first = Some(First::Arm); return; }

        self.query_original_capture_inner_v3(request, output, lifecycle, session, socket, original);
        // The primary has no early escape from these already owed native
        // destinations. Neither later result overwrites its first real cause.
        original.post = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
        if !matches!(original.post, Some(Ok(()))) { original.first.get_or_insert(First::Post); }
        if matches!(original.after_arm, Some(Ok(()))) {
            original.after_result = Some(output.finish_owed_after_receiving_v1(lifecycle, &mut original.after));
            if !matches!(original.after_result, Some(Ok(()))) { original.first.get_or_insert(First::After); }
        }
    }

    fn query_original_capture_inner_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        output: &StorageExecutionOutputCustodyV1,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        original: &mut OriginalStorageCaptureQueryV3,
    ) {
        original.demand = Some((|| {
            let state = self.coordinator.receiving_inventory_geometry_v1()?.retained_model_demand_v1()?;
            let artifacts = request.authorization().ok_or(CaptureQueryErrorV3::Closed)?;
            let auth = crate::authorization::receiving_authorization_memory_v1(artifacts)?;
            let request_bytes = u64::try_from(request.canonical_packet().len())
                .ok().and_then(|bytes| bytes.checked_mul(4))
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            let auth = auth.checked_add(request_bytes)
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            let clocks = KernelClock::dominant_requested_bytes_v1()
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalStorageCaptureQueryV3>().checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            // Same fixed boot names are already in the actual Storage original;
            // native errors/files and all encoded/model copies remain priced.
            let files = u64::try_from(KernelClock::MAXIMUM_RETAINED_FILES_V1)
                .ok().and_then(|files| files.checked_mul(2))
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            let response = ProtectedCaptureQueryDataV2::query_response_receiving_demand_v3()?;
            Ok(state.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, auth)
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, clocks).with(D::OpenFiles, files))?)?
                .checked_add(response)?)
        })());
        let demand = match original.demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => { original.first = Some(First::Demand); return; }
        };
        original.payment = Some(lifecycle.reserve_domain_additional_v1(session, socket, demand));
        if !matches!(original.payment, Some(Ok(()))) { original.first = Some(First::Payment); return; }
        original.after_arm = Some(output.prepare_owed_after_receiving_v1(lifecycle, session, socket, &mut original.after));
        if !matches!(original.after_arm, Some(Ok(()))) { original.first = Some(First::AfterArm); return; }

        original.request = Some(request.clone());
        original.samples[0] = Some(original.clocks[0].observe_once(None));
        if let Some(Ok(clock)) = original.samples[0].as_ref() {
            original.cuts[0] = Some(self.coordinator.authenticate_capture_query_ongoing_v3(request, clock));
            if !matches!(original.cuts[0], Some(Ok(_))) { original.first = Some(First::Cut(0)); }
        } else { original.first = Some(First::Clock(0)); }
        if original.first.is_none() {
            let Some(Ok(cut)) = original.cuts[0].as_ref() else { std::process::abort(); };
            original.query = Some(output.ledger().query_capture_terminal_ongoing_data_v3(cut.source_v3()));
            match original.query.as_ref() {
                Some(Ok(value)) => {
                    original.response = Some(ProtectedCaptureQueryDataV2::canonical_query_response_v3(value.as_ref(), cut.source_v3()));
                    match original.response.as_ref() {
                        Some(Ok(body)) => {
                            original.decoded = Some(aos_sandbox_protocol::storage_capture_grant::decode_storage_capture_query_response_ongoing_v2(body, cut.source_v3()));
                            if !matches!(original.decoded, Some(Ok(_))) { original.first = Some(First::Decode); }
                        }
                        _ => original.first = Some(First::Response),
                    }
                }
                _ => original.first = Some(First::Query),
            }
        }
        // The independently allocated final pair and fresh signed fence check
        // run after any reached primary read/decode failure, before the owed
        // service and Output afters. Neither can renew the original header.
        original.samples[1] = Some(original.clocks[1].observe_once(None));
        if let Some(Ok(clock)) = original.samples[1].as_ref() {
            original.cuts[1] = Some(self.coordinator.authenticate_capture_query_ongoing_v3(request, clock));
            if !matches!(original.cuts[1], Some(Ok(_))) { original.first.get_or_insert(First::Cut(1)); }
        } else { original.first.get_or_insert(First::Clock(1)); }
        original.comparison = Some((|| {
            let (Some(Ok(before)), Some(Ok(after)), Some(Ok(initial)), Some(Ok(final_cut))) =
                (original.samples[0].as_ref(), original.samples[1].as_ref(), original.cuts[0].as_ref(), original.cuts[1].as_ref())
            else { return Err(CaptureQueryErrorV3::Closed); };
            before.validate_later_sample(*after)?;
            if !initial.matches_v3(final_cut) || after.boottime_nanoseconds() >= request.deadline_boottime_nanoseconds() {
                return Err(CaptureQueryErrorV3::Closed);
            }
            Ok(())
        })());
        if !matches!(original.comparison, Some(Ok(()))) { original.first.get_or_insert(First::Comparison); }
    }
}

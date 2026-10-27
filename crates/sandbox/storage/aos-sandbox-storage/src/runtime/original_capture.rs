//! Retains the actual two-stage Capture60 reserve and occupied native worker.
//!
//! The first stage holds current signed admission, State/catalog and protected
//! policy while building fresh Host45 DATA. Only the actual committed Host45
//! continuation can enter the second stage. It takes one State loan for pending,
//! native create, catalog, Output physical binding and mounted pipe handoff.
//! Its completed response does not retire that same resident worker or F debt.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::kernel_clock::{KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1};
use aos_sandbox_protocol::authenticated_session::all_methods::{AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerMethodOutcomeV1};
use crate::broker::CaptureReserveCutV3;
use crate::execution_capture_policy::OriginalCapturePolicyReadV1;
use crate::execution_output::{CaptureCreateIssuanceOriginalV3, ProtectedCaptureQueryDataV2};
use crate::execution_output_credential::{StorageExecutionOutputCustodyV1, StorageOutputOwedAfterV1};
use crate::resolver::protected_catalog::{ResolverPolicyReadOriginalV1, SelectedStorageResolverPolicyV1};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureReserveErrorV3 {
    #[error("the actual Capture reserve original is closed or changed")]
    Closed,
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Admission(#[from] crate::StorageAdmissionError),
    #[error(transparent)]
    State(#[from] crate::StorageStateError),
    #[error(transparent)]
    Allocation(#[from] crate::execution_capture_policy::CaptureAllocationPolicyErrorV1),
    #[error(transparent)]
    Append(#[from] aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    Broker(#[from] crate::broker::StorageBrokerError),
    #[error(transparent)]
    Output(#[from] crate::execution_output::ExecutionOutputLedgerErrorV1),
    #[error(transparent)]
    Resolver(#[from] crate::resolver::protected_catalog::StorageResolverPolicyError),
    #[error(transparent)]
    Native(#[from] crate::ZfsWorkerError),
    #[error(transparent)]
    Dataset(#[from] crate::catalog_transition::execution_capture::ExecutionCaptureDatasetErrorV1),
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)]
    Complete(#[from] aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordErrorV2),
}

#[derive(Debug, thiserror::Error)]
enum CaptureReserveClockErrorV3 {
    #[error("the actual Capture reserve paired clock is unavailable or stale")]
    Stale,
    #[error(transparent)]
    Native(aos_linux_descriptors::Error),
}
impl KernelPairedClockErrorV1 for CaptureReserveClockErrorV3 {
    fn stale() -> Self { Self::Stale }
    fn kernel(cause: aos_linux_descriptors::Error) -> Self { Self::Native(cause) }
}

type Clock = RetainedKernelPairedClockAttemptV1<CaptureReserveClockErrorV3>;
type Loan<'cut, 'original> = aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>;

#[derive(Clone, Copy)]
enum First { Before(usize), Arm(usize), Demand(usize), Payment(usize), AfterArm(usize),
    Clock(usize), Cut(usize), Resolver(usize), Policy(usize), Body(usize), Issuance,
    Pending, Physical, StatePost, Post(usize), After(usize), Held, StopPayment }

pub(crate) struct OriginalStorageCaptureReserveV3 {
    request: Option<AuthenticatedBrokerMethodRequestV1>,
    header: Option<aos_sandbox_api::aos::sandbox::local::v1::RequestHeader>,
    clocks: [Clock; 4],
    pairs: [Option<Result<RawPairedClockSample, CaptureReserveClockErrorV3>>; 4],
    cuts: [Option<Result<CaptureReserveCutV3, CaptureReserveErrorV3>>; 2],
    resolver_read: [ResolverPolicyReadOriginalV1; 2],
    resolver: [Option<Result<SelectedStorageResolverPolicyV1, crate::resolver::protected_catalog::StorageResolverPolicyError>>; 2],
    policies: [OriginalCapturePolicyReadV1; 2],
    before: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    arm: [Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>; 2],
    demand: [Option<Result<ResourceVector, CaptureReserveErrorV3>>; 2],
    payment: [Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>; 2],
    after_arm: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    after: [StorageOutputOwedAfterV1; 2],
    after_result: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    post: [Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>; 2],
    body: [Option<Result<(), CaptureReserveErrorV3>>; 2],
    host_body: Option<Vec<u8>>,
    issuance: CaptureCreateIssuanceOriginalV3,
    issue_result: Option<Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1>>,
    native_result: Option<Result<(), crate::StorageStateError>>,
    native: Option<crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3>,
    stop_demand: Option<Result<ResourceVector, CaptureReserveErrorV3>>,
    stop_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    stop_result: Option<Result<(), crate::ZfsWorkerError>>,
    physical: Option<crate::process::CapturePhysicalPreparationOriginalV3>,
    physical_result: Option<Result<(), CaptureReserveErrorV3>>,
    held_result: Option<Result<(), crate::ZfsWorkerError>>,
    state_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    response: Option<Vec<u8>>,
    query: Option<ProtectedCaptureQueryDataV2>,
    decoded: Option<aos_sandbox_protocol::storage_capture_grant::ValidatedStorageCaptureAttemptV1>,
    entered: [bool; 2],
    first: Option<First>,
}

impl OriginalStorageCaptureReserveV3 {
    pub(crate) fn new() -> Self {
        Self {
            request: None, header: None, clocks: std::array::from_fn(|_| Clock::default()), pairs: std::array::from_fn(|_| None),
            cuts: std::array::from_fn(|_| None), resolver_read: std::array::from_fn(|_| ResolverPolicyReadOriginalV1::new()),
            resolver: std::array::from_fn(|_| None), policies: std::array::from_fn(|_| OriginalCapturePolicyReadV1::empty()),
            before: [None, None], arm: [None, None], demand: [None, None], payment: [None, None],
            after_arm: [None, None], after: std::array::from_fn(|_| StorageOutputOwedAfterV1::new()),
            after_result: [None, None], post: [None, None], body: [None, None], host_body: None,
            issuance: CaptureCreateIssuanceOriginalV3::new(), issue_result: None, native_result: None,
            native: None, stop_demand: None, stop_payment: None, stop_result: None, physical: None, physical_result: None, held_result: None, state_post: None, response: None, query: None,
            decoded: None, entered: [false, false], first: None,
        }
    }

    pub(crate) fn host_body_v3(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.body[0], Some(Ok(())))
            || !matches!(self.post[0], Some(Ok(()))) || !matches!(self.after_result[0], Some(Ok(()))) { return None; }
        self.host_body.as_deref()
    }

    pub(crate) fn response_v3(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.body[1], Some(Ok(())))
            || !matches!(self.state_post, Some(Ok(()))) || !matches!(self.after_result[1], Some(Ok(())))
            || self.decoded.is_none() || !matches!(self.physical_result, Some(Ok(()))) { return None; }
        self.response.as_deref()
    }

    pub(crate) fn request_v3(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> { self.request.as_ref() }

    pub(crate) fn failure_v3<'cause>(&'cause self, output: &'cause StorageExecutionOutputCustodyV1)
        -> Option<&'cause (dyn std::error::Error + 'static)>
    {
        let cause = match self.first? {
            First::Before(index) => output.receiving_current_failure_v1()
                .or_else(|| self.before[index].as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Arm(index) => self.arm[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Demand(index) => self.demand[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Payment(index) => self.payment[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AfterArm(index) | First::After(index) => self.after[index].failure(),
            First::Clock(index) => self.clocks[index].failure()
                .or_else(|| self.pairs[index].as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Cut(index) => self.cuts[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Resolver(index) => self.resolver_read[index].failure()
                .or_else(|| self.resolver[index].as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Policy(index) => self.policies[index].failure().or_else(|| self.policies[index].postcheck_debt()),
            First::Body(index) => self.body[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Issuance => self.issuance.failure()
                .or_else(|| self.issue_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Pending => self.native.as_ref().and_then(|native| native.failure())
                .or_else(|| self.native_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Physical => self.physical.as_ref().and_then(|physical| physical.failure())
                .or_else(|| self.physical_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Held => self.physical.as_ref().and_then(|physical| physical.failure())
                .or_else(|| self.held_result.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::StopPayment => self
                .stop_demand
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.stop_payment
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::StatePost => self.state_post.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Post(index) => self.post[index].as_ref()?.as_ref().err().map(|cause| cause as _),
        };
        cause.or_else(|| self.body.iter().find_map(|body| body.as_ref()?.as_ref().err().map(|cause| cause as _)))
            .or_else(|| self.physical_result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl StorageBrokerRuntime {
    fn capture_reserve_demand_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
        output: &StorageExecutionOutputCustodyV1,
        stage: usize,
    ) -> Result<ResourceVector, CaptureReserveErrorV3> {
        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let original = request.storage_execution_capture_original_output_request_v2()
            .ok_or(CaptureReserveErrorV3::Closed)?;
        let artifacts = request.authorization().ok_or(CaptureReserveErrorV3::Closed)?;
        let authority = crate::authorization::receiving_authorization_memory_v1(artifacts)?;
        let host = aos_sandbox_protocol::host_storage_output_readback::host_storage_output_readback_receiving_bytes_v1(
            original.len(), usize::try_from(buffa::Message::encoded_len(header)).map_err(|_| overflow())?,
        )?;
        // The clone owns its packet, exact body, envelope body, artifact
        // quartet and Capture context's original46 body independently. Price
        // those retained buffers explicitly; Source944 itself is inline DATA.
        // Host45 construction and admission decoding have separate recipes.
        let request_clone = if stage == 0 {
            let artifact_clones = [artifacts.broker_plan(), artifacts.broker_plan_signature(),
                artifacts.ownership_lease(), artifacts.ownership_lease_signature()]
                .into_iter().try_fold(0usize, |bytes, artifact|
                    bytes.checked_add(artifact.len()).ok_or_else(overflow))?;
            request.canonical_packet().len()
                .checked_add(request.exact_body().len().checked_mul(2).ok_or_else(overflow)?)
                .and_then(|bytes| bytes.checked_add(original.len()))
                .and_then(|bytes| bytes.checked_add(artifact_clones)).ok_or_else(overflow)?
        } else { 0 };
        let request_planes = request_clone.checked_add(host).ok_or_else(overflow)?;
        let clocks = Clock::dominant_requested_bytes_v1().and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(request_planes)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let files = u64::try_from(Clock::MAXIMUM_RETAINED_FILES_V1).ok()
            .and_then(|files| files.checked_mul(2)).ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        let state = self.coordinator.receiving_inventory_geometry_v1()?.retained_model_demand_v1()?;
        let resolver = ResolverPolicyReadOriginalV1::receiving_demand_v3().ok_or_else(overflow)?;
        let allocation = OriginalCapturePolicyReadV1::receiving_demand_v3().ok_or_else(overflow)?;
        let sample = resolver.checked_add(allocation)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes, authority.checked_add(clocks).ok_or_else(overflow)?)
            .with(D::OpenFiles, files);
        let demand = fixed.checked_add(state)?.checked_add(sample)?;
        if stage == 1 {
            Ok(demand.checked_add(output.capture_issuance_receiving_demand_v3()?)?
                .checked_add(ProtectedCaptureQueryDataV2::query_response_receiving_demand_v3()?)?)
        } else { Ok(demand) }
    }

    fn observe_capture_cut_policy_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        original: &mut OriginalStorageCaptureReserveV3,
        index: usize,
    ) -> Result<(), CaptureReserveErrorV3> {
        let clock_index = index * 2;
        original.first = Some(First::Clock(clock_index));
        original.pairs[clock_index] = Some(original.clocks[clock_index].observe_once(None));
        let Some(Ok(clock)) = original.pairs[clock_index].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
        original.first = Some(First::Cut(index));
        original.cuts[index] = Some(self.coordinator.authenticate_capture_reserve_ongoing_v3(request, clock));
        let Some(Ok(cut)) = original.cuts[index].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
        let directory = self.resolver_policies.as_ref().ok_or(CaptureReserveErrorV3::Closed)?;
        original.first = Some(First::Resolver(index));
        original.resolver[index] = Some(directory.load_retaining_v1(&mut original.resolver_read[index])
            .and_then(|catalog| catalog.select(cut.source_v3().original_source_v1().assignment())));
        let Some(Ok(resolver)) = original.resolver[index].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
        original.first = Some(First::Policy(index));
        directory.read_original_capture_policy(&mut original.policies[index], self.configuration_binding);
        let policy = original.policies[index].allocation().ok_or(CaptureReserveErrorV3::Closed)?;
        if original.policies[index].failure().is_some() || original.policies[index].postcheck_debt().is_some()
            || resolver.binding().catalog_digest() != policy.resolver_catalog_digest()
            || resolver.policy().expected_pool_guid() != policy.expected_pool_guid()
        { return Err(CaptureReserveErrorV3::Closed); }
        let source = cut.source_v3().original_source_v1();
        let (allocation, headroom, floor) = source.space_policy();
        if allocation != policy.allocation_for(source.output_limits().0)?
            || headroom != policy.metadata_headroom_bytes() || floor != policy.minimum_remaining_bytes()
        { return Err(CaptureReserveErrorV3::Closed); }
        original.first = None;
        Ok(())
    }

    pub(crate) fn prepare_original_capture_ongoing_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        header: &aos_sandbox_api::aos::sandbox::local::v1::RequestHeader,
        output: &mut StorageExecutionOutputCustodyV1,
        lifecycle: &mut Loan<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        original: &mut OriginalStorageCaptureReserveV3,
    ) {
        if original.entered[0] || original.first.is_some() { return; }
        original.entered[0] = true;
        original.first = Some(First::Before(0));
        original.before[0] = Some(output.recheck_session_receiving_v1(lifecycle, session, socket));
        if !matches!(original.before[0], Some(Ok(()))) { return; }
        original.first = Some(First::Arm(0));
        original.arm[0] = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
        if !matches!(original.arm[0], Some(Ok(()))) { return; }
        original.first = Some(First::Demand(0));
        original.demand[0] = Some(self.capture_reserve_demand_v3(request, header, output, 0));
        if let Some(Ok(demand)) = original.demand[0].as_ref() {
            original.first = Some(First::Payment(0));
            original.payment[0] = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
            if matches!(original.payment[0], Some(Ok(()))) {
                original.first = Some(First::AfterArm(0));
                original.after_arm[0] = Some(output.prepare_owed_after_receiving_v1(lifecycle, session, socket, &mut original.after[0]));
                if matches!(original.after_arm[0], Some(Ok(()))) {
                    original.first = None;
                    original.body[0] = Some((|| {
                        original.request = Some(request.clone());
                        original.header = Some(header.clone());
                        self.observe_capture_cut_policy_v3(request, original, 0)?;
                        original.first = Some(First::Body(0));
                        original.host_body = Some(output.ledger().capture_host_readback_body_v3(request, header.clone())?);
                        original.first = Some(First::Clock(1));
                        original.pairs[1] = Some(original.clocks[1].observe_once(None));
                        let Some(Ok(clock)) = original.pairs[1].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
                        let Some(Ok(cut)) = original.cuts[0].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
                        cut.require_acquisition_clock_v3(clock)?;
                        original.first = None;
                        Ok(())
                    })());
                }
            }
        }
        let primary = original.first;
        original.post[0] = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
        if !matches!(original.post[0], Some(Ok(()))) && primary.is_none() { original.first = Some(First::Post(0)); }
        if matches!(original.after_arm[0], Some(Ok(()))) {
            original.after_result[0] = Some(output.finish_owed_after_receiving_v1(lifecycle, &mut original.after[0]));
            if !matches!(original.after_result[0], Some(Ok(()))) && original.first.is_none() { original.first = Some(First::After(0)); }
        }
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn finish_original_capture_with_host_ongoing_v3(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        host: &AuthenticatedBrokerMethodOutcomeV1,
        output: &mut StorageExecutionOutputCustodyV1,
        lifecycle: &mut Loan<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        original: &mut OriginalStorageCaptureReserveV3,
    ) {
        if original.entered[1] || original.host_body_v3().is_none() { return; }
        original.entered[1] = true;
        original.first = Some(First::Before(1));
        original.before[1] = Some(output.recheck_session_receiving_v1(lifecycle, session, socket));
        if !matches!(original.before[1], Some(Ok(()))) { return; }
        original.first = Some(First::Arm(1));
        original.arm[1] = Some(lifecycle.arm_operation_observation_post_v1(session, socket));
        if !matches!(original.arm[1], Some(Ok(()))) { return; }
        original.first = Some(First::Demand(1));
        original.demand[1] = Some(match original.header.as_ref() {
            Some(header) => self.capture_reserve_demand_v3(request, header, output, 1),
            None => Err(CaptureReserveErrorV3::Closed),
        });
        if let Some(Ok(demand)) = original.demand[1].as_ref() {
            original.first = Some(First::Payment(1));
            original.payment[1] = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
            if matches!(original.payment[1], Some(Ok(()))) {
                original.first = Some(First::AfterArm(1));
                original.after_arm[1] = Some(output.prepare_owed_after_receiving_v1(lifecycle, session, socket, &mut original.after[1]));
                if matches!(original.after_arm[1], Some(Ok(()))) {
                    original.first = None;
                    original.body[1] = Some((|| {
                        original.first = Some(First::Body(1));
                        if original.request.as_ref().is_none_or(|prior| prior.canonical_packet() != request.canonical_packet())
                            || original.host_body.as_deref() != Some(host.request().exact_body())
                        { return Err(CaptureReserveErrorV3::Closed); }
                        self.observe_capture_cut_policy_v3(request, original, 1)?;
                        original.first = Some(First::Body(1));
                        let (Some(Ok(before)), Some(Ok(after)), Some(Ok(old_policy)), Some(Ok(new_policy))) =
                            (original.cuts[0].as_ref(), original.cuts[1].as_ref(), original.resolver[0].as_ref(), original.resolver[1].as_ref())
                        else { return Err(CaptureReserveErrorV3::Closed); };
                        if !before.matches_v3(after) || old_policy.binding() != new_policy.binding()
                            || old_policy.policy() != new_policy.policy()
                            || original.policies[0].allocation() != original.policies[1].allocation()
                        { return Err(CaptureReserveErrorV3::Closed); }
                        original.first = None;
                        Ok(())
                    })());
                }
            }
        }
        // Complete the self-contained admission/policy prelude before taking
        // the one State loan. Its initial observation slot must not be nested.
        original.post[1] = Some(lifecycle.finish_operation_observation_post_v1(session, socket));
        if !matches!(original.post[1], Some(Ok(()))) && original.first.is_none() { original.first = Some(First::Post(1)); }
        if original.first.is_none() {
            let receiving = lifecycle.borrow_state_encoding_v1(session, socket, self.lifecycle_state_journal_v1());
            match receiving {
                Ok(mut receiving) => {
                    original.physical_result = Some((|| {
                        original.first = Some(First::Body(1));
                        self.coordinator.prepare_recovery_models_v1(&mut receiving)?;
                        let Some(Ok(cut)) = original.cuts[1].as_mut() else { return Err(CaptureReserveErrorV3::Closed); };
                        let source = *cut.source_v3();
                        let Some(Ok(resolver)) = original.resolver[1].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
                        let allocation = original.policies[1].allocation().ok_or(CaptureReserveErrorV3::Closed)?;
                        let base = source.original_source_v1();
                        let requirement = crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1::new(
                            base.settlement().execution(), base.settlement().create_operation(), base.output_claim_digest(),
                            base.storage_create_operation(), resolver.policy().root().clone(), resolver.policy().domains(),
                            base.output_limits().0, base.space_policy().0,
                        )?;
                        let admitted = cut.take_admitted_once_v3().ok_or(CaptureReserveErrorV3::Closed)?;
                        original.first = Some(First::StopPayment);
                        // Standing cancellation includes the hostile ingress,
                        // trust models, separate reader and all native/post
                        // destinations BEFORE durable Capture issuance/effects.
                        let stop_inspection_bytes = self.coordinator.root_export_authority_v2()
                            .storage_capture_stop_inspection_receiving_bytes_v4(
                                aos_sandbox_protocol::storage_capture_session::stop_cleanup::MAXIMUM_CAPTURE_STOP_REQUEST_BYTES_V4)
                            .ok_or(CaptureReserveErrorV3::Closed)?;
                        original.stop_demand = Some(crate::process::CapturePhysicalPreparationOriginalV3::
                            stop_receiving_demand_v4(stop_inspection_bytes).ok_or(CaptureReserveErrorV3::Closed));
                        let demand = original
                            .stop_demand
                            .as_ref()
                            .and_then(|result| result.as_ref().ok())
                            .copied()
                            .ok_or(CaptureReserveErrorV3::Closed)?;
                        original.stop_payment = Some(receiving.prepare_capture_stop_liability_v4(
                            self.coordinator.recovery_encoding_journal_v1(),
                            request,
                            admitted.lifetime_v3(),
                            demand,
                        ));
                        if !matches!(original.stop_payment, Some(Ok(()))) {
                            return Err(CaptureReserveErrorV3::Closed);
                        }
                        original.first = Some(First::Issuance);
                        original.issue_result = Some(output.issue_native_capture_ongoing_v3(
                            admitted, host, requirement, allocation, &mut original.issuance,
                        ));
                        if !matches!(original.issue_result, Some(Ok(()))) { return Err(CaptureReserveErrorV3::Closed); }
                        original.issuance.prepare_native_once_v3()?;
                        original.native = original.issuance.take_native_once_v3();
                        let Some(native) = original.native.as_mut() else { return Err(CaptureReserveErrorV3::Closed); };
                        original.first = Some(First::Pending);
                        original.native_result = Some(self.coordinator.prepare_capture_native_pending_v3(native, &mut receiving));
                        if !matches!(original.native_result, Some(Ok(()))) { return Err(CaptureReserveErrorV3::Closed); }
                        let Some(native) = original.native.take() else { return Err(CaptureReserveErrorV3::Closed); };
                        original.physical = Some(crate::process::CapturePhysicalPreparationOriginalV3::new(native, stop_inspection_bytes));
                        original.first = Some(First::Physical);
                        let Some(physical) = original.physical.as_mut() else { return Err(CaptureReserveErrorV3::Closed); };
                        self.helper.begin_capture_created_ongoing_v3(
                            physical, request, self.coordinator.recovery_encoding_journal_v1(), &mut receiving,
                        )?;
                        self.coordinator.complete_capture_created_catalog_v3(physical, output, &mut receiving)?;
                        physical.prepare_mounted_pipes_once_v3(self.coordinator.recovery_encoding_journal_v1(), &mut receiving)?;
                        if !physical.mounted_preparation_completed_v3() { return Err(CaptureReserveErrorV3::Closed); }
                        original.first = Some(First::Clock(3));
                        original.pairs[3] = Some(original.clocks[3].observe_once(None));
                        let Some(Ok(clock)) = original.pairs[3].as_ref() else { return Err(CaptureReserveErrorV3::Closed); };
                        physical.require_response_clock_v3(clock)?;
                        original.first = Some(First::Body(1));
                        original.query = output.ledger().query_capture_terminal_ongoing_data_v3(&source)?;
                        if original.query.as_ref().is_none_or(|value| value.complete_record_v2().is_some()) {
                            return Err(CaptureReserveErrorV3::Closed);
                        }
                        original.response = Some(ProtectedCaptureQueryDataV2::canonical_query_response_v3(original.query.as_ref(), &source)?);
                        let body = original.response.as_deref().ok_or(CaptureReserveErrorV3::Closed)?;
                        original.decoded = Some(aos_sandbox_protocol::storage_capture_grant::decode_storage_capture_attempt_response_ongoing_v2(
                            body, &source, false,
                        )?);
                        original.first = None;
                        Ok(())
                    })());
                    // This exact State/source/native post is owed on every
                    // reached native path. The physical owner remains parked
                    // and charged even when the Session response completes.
                    original.state_post = Some(self.coordinator.finish_recovery_posts_v1(&mut receiving));
                    if !matches!(original.state_post, Some(Ok(()))) && original.first.is_none() {
                        original.first = Some(First::StatePost);
                    }
                }
                Err(cause) => {
                    original.state_post = Some(Err(cause));
                    original.first = Some(First::StatePost);
                }
            }
        }
        // The separate prearmed Output reservoir works after State/action
        // poison and cannot reenter a healthy operation or renew the request.
        if matches!(original.after_arm[1], Some(Ok(()))) {
            original.after_result[1] = Some(output.finish_owed_after_receiving_v1(lifecycle, &mut original.after[1]));
            if !matches!(original.after_result[1], Some(Ok(()))) && original.first.is_none() { original.first = Some(First::After(1)); }
        }
        if original.first.is_none() && !matches!(original.physical_result, Some(Ok(()))) {
            original.first = Some(First::Physical);
        }
    }
}


impl OriginalStorageCaptureReserveV3 {
    pub(crate) fn has_resident_capture_v3(&self) -> bool {
        self.first.is_none() && self.response_v3().is_some()
            && self.physical.as_ref().is_some_and(|physical| physical.mounted_preparation_completed_v3())
            && !self.completed_physical_capture_v3()
    }

    pub(crate) fn awaiting_capture_begin_v3(&self) -> bool {
        self.has_resident_capture_v3() && self.physical.as_ref()
            .is_some_and(|physical| physical.awaiting_host_begin_v3())
    }

    pub(crate) fn push_capture_terminal_poll_v3<'fd>(&'fd self,
        polls: &mut Vec<rustix::event::PollFd<'fd>>) -> Option<usize> {
        if !self.has_resident_capture_v3() { return None; }
        self.physical.as_ref()?.push_host_terminal_poll_v3(polls)
    }

    pub(crate) fn completed_physical_capture_v3(&self) -> bool {
        self.first.is_none() && matches!(self.held_result, Some(Ok(())))
            && self.physical.as_ref().and_then(|physical| physical.native_complete_record_v3()).is_some()
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn serve_original_capture_held_v3(&mut self,
        original: &mut OriginalStorageCaptureReserveV3,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        output: &mut StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>) {
        if !original.has_resident_capture_v3() { return; }
        original.first = Some(First::Held);
        let Some(physical) = original.physical.as_mut() else { return; };
        original.held_result = Some(self.coordinator.serve_capture_held_native_v3(physical, listener, output, receiving));
        if matches!(original.held_result, Some(Ok(()))) { original.first = None; }
    }
}

impl OriginalStorageCaptureReserveV3 {
    pub(crate) fn can_receive_stop_cleanup_v4(&self) -> bool {
        self.physical
            .as_ref()
            .is_some_and(|physical| physical.can_receive_stop_cleanup_v4())
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn serve_original_capture_stop_v4(
        &self,
        original: &mut OriginalStorageCaptureReserveV3,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        output: &StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) {
        let Some(physical) = original.physical.as_mut() else {
            return;
        };
        original.stop_result = Some(physical.serve_stop_cleanup_once_v4(
            listener,
            self.coordinator.root_export_authority_v2(),
            self.coordinator.recovery_encoding_journal_v1(),
            output.ledger().held_journal_for_receiving_v1(),
            receiving,
        ));
    }
}

impl OriginalStorageCaptureReserveV3 {
    pub(crate) fn physical_for_stop_v4(
        &mut self,
    ) -> Option<&mut crate::process::CapturePhysicalPreparationOriginalV3> {
        self.physical.as_mut()
    }

    pub(crate) fn stop_failure_v4<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.physical
            .as_ref()
            .and_then(|physical| physical.stop_cleanup_failure_v4(receiving))
            .or_else(|| {
                self.stop_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    pub(crate) fn stopped_with_residual_v4(&self) -> bool {
        matches!(self.stop_result, Some(Ok(())))
            && self
                .physical
                .as_ref()
                .is_some_and(|physical| physical.stopped_with_residual_v4())
    }
}

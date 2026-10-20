//! Executes only the closed Capture branch of the existing inherited worker.
//!
//! The worker authenticates storaged through its actual socket/received subject
//! and exact cgroup before this private context exists. The parent alone owns
//! signature verification, protected journals/policy and the same-F lender.
//! No signing key, reconstructed grant, public DATA adopter or user-chosen
//! executable crosses this established privileged-worker boundary.

use super::*;
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;

pub(super) mod wire;
mod drain;
mod mounted;
mod run;
pub(super) use run::{run_authenticated_capture_v3, receiving_bytes_v3};
pub(crate) use drain::CaptureDrainReadBorrowV3;

pub(crate) struct AuthenticatedCaptureWorkerContextV3<'entry> {
    data: wire::CaptureWorkerRequestDataV3,
    _parent: worker_entry::CaptureParentBorrowV3<'entry>,
}

impl<'entry> AuthenticatedCaptureWorkerContextV3<'entry> {
    // Only this child module's inherited entry can construct the context, after
    // the actual shared entry/scope engines have completed their native checks.
    // The returned value borrows both originals and cannot outlive the worker.
    fn after_entry_v3(
        parent: worker_entry::CaptureParentBorrowV3<'entry>,
        execution: &worker_aggregate::WorkerExecutionScopeV1<'_>,
    ) -> Result<Self, ZfsWorkerError> {
        execution.require_capture_context_v3()?;
        let data = wire::decode_request(parent.request_v3().payload())?;
        Ok(Self { data, _parent: parent })
    }

    pub(crate) fn source_v3(&self) -> &StorageCaptureGrantSourceV2 { &self.data.source }
    pub(crate) fn clock_comparison_data_v3(&self) -> aos_sandbox_broker::BrokerEffectClockComparisonV3 {
        aos_sandbox_broker::BrokerEffectClockComparisonV3::from_original_clock_fields_data_v4(
            self.data.admitted_clock, self.data.plan_expires_seconds, self.data.authority_expires_seconds,
        )
    }

    // Only the authenticated inherited context selects these original native
    // ceilings. The Linux value denies operations; it is no execution grant.
    pub(super) fn process_cut_data_v3(&self)
        -> aos_sandbox_linux::Result<aos_sandbox_linux::process::FixedProcessCaptureCutV3> {
        let (_, _, _, _, _, _, cutoff) = crate::execution_output::capture_worker_inputs_v3(self)
            .map_err(|_| aos_sandbox_linux::Error::DeadlineExceeded {
                operation: "Capture process original association",
            })?;
        aos_sandbox_linux::process::FixedProcessCaptureCutV3::new(cutoff,
            self.data.plan_expires_seconds.min(self.data.authority_expires_seconds))
    }

    pub(crate) fn attempt_bytes_v3(&self) -> &[u8; 424] { &self.data.attempt }
    pub(crate) fn requirement_v3(&self) -> &CaptureDatasetRequirementV1 { &self.data.requirement }
    pub(crate) fn pool_guid_v3(&self) -> u64 { self.data.expected_pool_guid }
    pub(crate) fn metadata_headroom_v3(&self) -> u64 { self.data.metadata_headroom_bytes }
    pub(crate) fn remaining_floor_v3(&self) -> u64 { self.data.minimum_remaining_bytes }
    pub(super) fn prepaid_drain_ceiling_v3(&self) -> u64 { self.data.prepaid_drain_ceiling }
    pub(crate) fn request_digest_v3(&self) -> aos_sandbox_model::ObjectDigest { self.data.request_digest }
}

#[derive(Clone, Copy)]
enum CaptureWorkerFailureV3 { Parent, Source, ToolOpening, Create, CreateTools, CreatedPlan, Created }

// This complete native phase destination is declared before the actual worker
// execution scope by the eventual inherited branch. An unfinished scope cannot
// unwind past tool/source/native originals before its existing abort/hold fence.
struct CaptureWorkerCreateOriginalV3<'entry> {
    parent: Option<Result<AuthenticatedCaptureWorkerContextV3<'entry>, ZfsWorkerError>>,
    create: Option<Result<crate::execution_capture_zfs_worker::CaptureCreateExecutionOriginalV3,
        crate::execution_capture_zfs_worker::CaptureCreateWorkerErrorV1>>,
    tools: capture_observation::CaptureZfsObservationOriginalV3,
    opening: Option<Result<(), ZfsWorkerError>>,
    create_tools_disposal: Option<Result<(), ZfsWorkerError>>,
    created_plan: Option<Result<CaptureZfsReadbackPlanV1,
        crate::catalog_transition::execution_capture::readback::CaptureZfsReadbackErrorV1>>,
    created_native: capture_observation::CaptureZfsObservationOriginalV3,
    created: Option<Result<crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3, ()>>,
    first: Option<CaptureWorkerFailureV3>,
    entered: bool,
}

impl<'entry> CaptureWorkerCreateOriginalV3<'entry> {
    fn new() -> Self {
        Self { parent: None, create: None,
            tools: capture_observation::CaptureZfsObservationOriginalV3::new(),
            opening: None, create_tools_disposal: None, created_plan: None,
            created_native: capture_observation::CaptureZfsObservationOriginalV3::new(),
            created: None, first: None, entered: false }
    }

    fn prepare_parent_once_v3(
        &mut self, parent: worker_entry::CaptureParentBorrowV3<'entry>,
        execution: &worker_aggregate::WorkerExecutionScopeV1<'_>,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered || self.parent.is_some() { return Err(ZfsWorkerError::Authority); }
        self.first = Some(CaptureWorkerFailureV3::Parent);
        self.parent = Some(AuthenticatedCaptureWorkerContextV3::after_entry_v3(parent, execution));
        if matches!(self.parent, Some(Ok(_))) { self.first = None; Ok(()) }
        else { Err(worker_entry::retained()) }
    }

    fn enter_once_v3(
        &mut self,
        execution: &mut worker_aggregate::WorkerExecutionScopeV1<'_>,
        contract: &ZfsHelperContract,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(ZfsWorkerError::Authority); }
        self.entered = true;
        let Some(Ok(context)) = self.parent.as_ref() else { return Err(worker_entry::retained()); };
        self.first = Some(CaptureWorkerFailureV3::Source);
        self.create = Some(crate::execution_capture_zfs_worker::CaptureCreateExecutionOriginalV3::prepare_authenticated_worker_v3(context));
        let Some(Ok(create)) = self.create.as_mut() else { return Err(worker_entry::retained()); };
        self.first = Some(CaptureWorkerFailureV3::ToolOpening);
        let mut backend = match capture_create::FixedCaptureCreateBackendV1::new_retaining_in_scope_v3(
            contract, execution, &mut self.tools,
        ) {
            Ok(backend) => backend,
            Err(cause) => { self.opening = Some(Err(cause)); return Err(worker_entry::retained()); }
        };
        self.opening = Some(Ok(()));
        self.first = Some(CaptureWorkerFailureV3::Create);
        create.run_once_v3(&mut backend);
        backend.park_tools_once_v3();
        if !create.can_continue_after_create_v3() { return Err(worker_entry::retained()); }
        self.first = Some(CaptureWorkerFailureV3::CreateTools);
        self.create_tools_disposal = Some(self.tools.retire_positive());
        if !matches!(self.create_tools_disposal, Some(Ok(()))) { return Err(worker_entry::retained()); }
        self.first = Some(CaptureWorkerFailureV3::CreatedPlan);
        let Some(attempted) = create.attempted_v3() else { return Err(worker_entry::retained()); };
        self.created_plan = Some(CaptureZfsReadbackPlanV1::after_create_v3(
            context.requirement_v3(), &crate::execution_output::capture_worker_inputs_v3(context)
                .map_err(|_| worker_entry::retained())?.0,
            attempted, context.metadata_headroom_v3(), context.remaining_floor_v3(),
        ));
        let Some(Ok(plan)) = self.created_plan.as_ref() else { return Err(worker_entry::retained()); };
        self.first = Some(CaptureWorkerFailureV3::Created);
        self.created = Some(capture_observation::observe_created_capture_zfs_in_scope_v3(
            contract, plan, &mut self.created_native, execution, context,
            attempted.deadline_boottime_nanoseconds,
        ));
        if !matches!(self.created, Some(Ok(_))) { return Err(worker_entry::retained()); }
        self.first = None;
        Ok(())
    }

    fn failure<'owner>(&'owner self, execution: &'owner worker_aggregate::WorkerExecutionScopeV1<'_>)
        -> Option<&'owner (dyn std::error::Error + 'static)>
    {
        match self.first? {
            CaptureWorkerFailureV3::Parent => self.parent.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureWorkerFailureV3::Source => self.create.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureWorkerFailureV3::ToolOpening => self.opening.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureWorkerFailureV3::Create => execution.failure_v3()
                .or_else(|| self.create.as_ref()?.as_ref().ok()?.failure()),
            CaptureWorkerFailureV3::CreateTools => self.create_tools_disposal.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureWorkerFailureV3::CreatedPlan => self.created_plan.as_ref()?.as_ref().err().map(|cause| cause as _),
            CaptureWorkerFailureV3::Created => execution.failure_v3().or_else(|| self.created_native.failure()),
        }
    }
}


#[derive(Clone, Copy)]
enum CatalogFailureV3 { Receive, Subject, Membership, Decode, Writer }

pub(crate) struct CaptureWorkerCatalogOriginalV3 {
    received: Option<Result<ReceivedRecord,
        aos_sandbox_linux::seqpacket::bounded::ZfsWorkerReceiveErrorV1>>,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1,
    membership_result: Option<Result<(), aos_sandbox_linux::cgroup::ExactCgroupMembershipRefusalV1>>,
    decoded: Option<Result<wire::CaptureWorkerCatalogDataV3, ZfsWorkerError>>,
    authority: Option<Result<crate::execution_capture_zfs_worker::AuthorizedCaptureWriterAttemptV1,
        crate::execution_capture_zfs_worker::CaptureWriterWorkerErrorV1>>,
    writer: Option<Result<crate::execution_capture_zfs_worker::PreparedDetachedCaptureWriterV1,
        crate::execution_capture_zfs_worker::CaptureWriterPreparationFailureV2>>,
    entered: bool,
    first: Option<CatalogFailureV3>,
}

impl CaptureWorkerCatalogOriginalV3 {
    fn new() -> Self {
        Self { received: None, subject: None,
            membership: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::new(),
            membership_result: None, decoded: None, authority: None, writer: None,
            entered: false, first: None }
    }

    fn receive_and_prepare_once_v3(
        &mut self,
        socket: &mut SeqpacketSocket,
        created: &CaptureWorkerCreateOriginalV3<'_>,
        execution: &mut worker_aggregate::WorkerExecutionScopeV1<'_>,
        contract: &ZfsHelperContract,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered || created.first.is_some() { return Err(ZfsWorkerError::Authority); }
        self.entered = true;
        let Some(Ok(context)) = created.parent.as_ref() else { return Err(ZfsWorkerError::Authority); };
        let Some(Ok(observed)) = created.created.as_ref() else { return Err(ZfsWorkerError::Authority); };
        let Some(Ok(create)) = created.create.as_ref() else { return Err(ZfsWorkerError::Authority); };
        let Some(attempted) = create.attempted_v3() else { return Err(ZfsWorkerError::Authority); };
        self.first = Some(CatalogFailureV3::Receive);
        self.received = Some(aos_sandbox_linux::seqpacket::bounded::receive_zfs_worker_record_v1(
            socket, aos_sandbox_linux::seqpacket::bounded::ZfsWorkerRecordKindV1::Request,
            attempted.deadline_boottime_nanoseconds,
        ));
        let Some(Ok(received)) = self.received.as_ref() else { return Err(worker_entry::retained()); };
        self.first = Some(CatalogFailureV3::Subject);
        self.subject = Some(verify_same_live_subject(context._parent.request_v3().subject(), received.subject()));
        if !matches!(self.subject, Some(Ok(()))) { return Err(worker_entry::retained()); }
        self.first = Some(CatalogFailureV3::Membership);
        self.membership_result = Some(self.membership.capture_once(
            context._parent.parent_v3(), received.subject().pidfd(),
        ));
        if !matches!(self.membership_result, Some(Ok(()))) { return Err(worker_entry::retained()); }
        self.first = Some(CatalogFailureV3::Decode);
        self.decoded = Some(wire::decode_catalog_data_v3(context, observed, received.payload()));
        if !matches!(self.decoded, Some(Ok(_))) { return Err(worker_entry::retained()); }
        self.first = Some(CatalogFailureV3::Writer);
        self.authority = Some(crate::execution_capture_zfs_worker::AuthorizedCaptureWriterAttemptV1::
            from_authenticated_catalog_v3(context, self));
        if !matches!(self.authority, Some(Ok(_))) { return Err(worker_entry::retained()); }
        let Some(Ok(authority)) = self.authority.take() else { std::process::abort(); };
        self.writer = Some(authority.prepare_detached_in_scope_v3(contract, execution, context));
        if !matches!(self.writer, Some(Ok(_))) { return Err(worker_entry::retained()); }
        self.first = None;
        Ok(())
    }

    pub(crate) fn require_context_v3(&self, context: &AuthenticatedCaptureWorkerContextV3<'_>)
        -> Option<&wire::CaptureWorkerCatalogDataV3>
    {
        // The requested factory is called at Writer after all actual peer and
        // parser checks. It cannot be reached with a caller supplied enum/bool.
        if !self.entered || !matches!(self.first, Some(CatalogFailureV3::Writer) | None)
            || !matches!(self.subject, Some(Ok(())))
            || !matches!(self.membership_result, Some(Ok(())))
        { return None; }
        let decoded = self.decoded.as_ref()?.as_ref().ok()?;
        if decoded.source != context.source_v3().source_digest_v2()
            || decoded.request != context.request_digest_v3()
        { return None; }
        Some(decoded)
    }

    fn failure<'a>(&'a self, execution: &'a worker_aggregate::WorkerExecutionScopeV1<'_>)
        -> Option<&'a (dyn std::error::Error + 'static)>
    {
        match self.first? {
            CatalogFailureV3::Receive => self.received.as_ref()?.as_ref().err().map(|cause| cause as _),
            CatalogFailureV3::Subject => self.subject.as_ref()?.as_ref().err().map(|cause| cause as _),
            CatalogFailureV3::Membership => self.membership.failure().map(|cause| cause as _),
            CatalogFailureV3::Decode => self.decoded.as_ref()?.as_ref().err().map(|cause| cause as _),
            CatalogFailureV3::Writer => self.authority.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _)
                .or_else(|| execution.failure_v3())
                .or_else(|| self.writer.as_ref()?.as_ref().err()?.failure()),
        }
    }
}

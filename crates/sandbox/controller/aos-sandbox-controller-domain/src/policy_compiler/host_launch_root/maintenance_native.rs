//! Retains the distinct Maintenance Root flight's reached originals and posts.
//!
//! Every native capture and parser below is the existing shared engine. The
//! concrete purpose owns its actual current assignment and lease; it carries
//! no accepted Start, historical Root permission, or substitute Source owner.

use super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2;
use super::maintenance_request::RootMaintenanceStorageRequestOriginalV2;
use super::inputs::RootResourceInputsOriginalV2;
use super::plan::RootStartResourceUnsignedPlanOriginalV2;
use crate::normal_root::{RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{
    bounded_stream_io::{FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1},
    continuation_policy::{RootContinuationPolicyErrorV1, RootMaintenanceStoragePolicyOriginalV2},
    provisioning_current::{RootContinuationClockGateV1, RootProvisioningNativeViewsV1,
        finality_readonly::RootCreateFinalityReadonlyOriginalV1},
    root_subject_chunk::RootSubjectChunkReceivingV1,
};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::provisioning_root::{
    maintenance_storage::QUERY_BYTES_V2,
    host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2,
};

type Cause = Box<dyn std::error::Error>;

#[derive(Clone, Copy)]
pub(super) enum MaintenancePhaseV3 {
    Opening, Subject, Inputs, Readonly, Binding, Policy, Views,
    Assignment, Inventory, Ownership, Request, Compiler, Plan, Posts,
    Reply, Send, Final,
}

pub(super) struct RootMaintenanceNativeOriginalV3 {
    pub(super) phase: MaintenancePhaseV3,
    pub(super) query: [u8; QUERY_BYTES_V2],
    pub(super) remainder: [u8; QUERY_BYTES_V2 - 32],
    pub(super) remainder_io: FixedDeadlineStreamIoV1<{ QUERY_BYTES_V2 - 32 }>,
    pub(super) geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    pub(super) subject: RetainedSubjectStreamReadV1,
    pub(super) chunks: RootSubjectChunkReceivingV1,
    pub(super) reporting: Option<Result<(), SeqpacketError>>,
    pub(super) inputs: RootResourceInputsOriginalV2,
    pub(super) readonly: RootCreateFinalityReadonlyOriginalV1,
    pub(super) views: RootProvisioningNativeViewsV1,
    pub(super) assignment: RootMaintenanceAssignmentOriginalV2,
    pub(super) request: RootMaintenanceStorageRequestOriginalV2,
    pub(super) policy: RootMaintenanceStoragePolicyOriginalV2,
    pub(super) policy_begin: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pub(super) policy_verify: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pub(super) policy_post: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pub(super) clock: Option<Box<RootContinuationClockGateV1>>,
    pub(super) binding: Option<Result<(), Cause>>,
    pub(super) plan: RootStartResourceUnsignedPlanOriginalV2,
    pub(super) reply: Option<Vec<u8>>,
    pub(super) reply_digest: Option<[u8; 32]>,
    pub(super) sent: SliceDeadlineStreamIoV1,
    pub(super) posts: bool,
    pub(super) final_header: [u8; RESOURCE_PROOF_HEADER_BYTES_V2],
    pub(super) final_header_io: FixedDeadlineStreamIoV1<RESOURCE_PROOF_HEADER_BYTES_V2>,
    pub(super) final_exchange: Option<Box<super::maintenance_final::RootMaintenanceFinalExchangeOriginalV3>>,
}

impl RootMaintenanceNativeOriginalV3 {
    pub(super) fn new() -> Self {
        Self { phase: MaintenancePhaseV3::Opening, query: [0; QUERY_BYTES_V2],
            remainder: [0; QUERY_BYTES_V2 - 32], remainder_io: Default::default(),
            geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            subject: RetainedSubjectStreamReadV1::new(), chunks: Default::default(), reporting: None,
            inputs: RootResourceInputsOriginalV2::new(), readonly: RootCreateFinalityReadonlyOriginalV1::new(),
            views: RootProvisioningNativeViewsV1::new(), assignment: RootMaintenanceAssignmentOriginalV2::new(),
            request: RootMaintenanceStorageRequestOriginalV2::new(), policy: Default::default(),
            policy_begin: None, policy_verify: None, policy_post: None, clock: None, binding: None,
            plan: RootStartResourceUnsignedPlanOriginalV2::new(), reply: None, reply_digest: None,
            sent: Default::default(), posts: false, final_header: [0; RESOURCE_PROOF_HEADER_BYTES_V2],
            final_header_io: Default::default(), final_exchange: None }
    }

    pub(super) fn finish_posts_once_v3(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts { return; }
        self.posts = true;
        self.inputs.finish_posts_once_v2();
        self.readonly.finish_posts_once_v1();
        let _owed = self.views.finish_maintenance_storage_after_once_v2();
        if self.policy_begin.is_some() {
            self.policy_post = Some(flight.finish_maintenance_storage_policy_once_v2(&mut self.policy));
        }
    }

    pub(super) fn require_posts_v3(&self) -> Result<(), Cause> {
        self.inputs.require_complete_v2()?;
        self.readonly.require_complete_v1()?;
        self.views.completed_maintenance_storage_tree_v3()?;
        self.policy.require_complete_v1()?;
        if !matches!(self.policy_post, Some(Ok(()))) { return Err(crate::journal::JournalError::ProtectedBoundary.into()); }
        Ok(())
    }

    pub(super) fn phase_failure_v3(&self, phase: MaintenancePhaseV3)
        -> Option<&(dyn std::error::Error + 'static)> {
        match phase {
            MaintenancePhaseV3::Opening => self.remainder_io.failure(),
            MaintenancePhaseV3::Subject => self.geometry.as_ref().err().map(|cause| cause as _)
                .or_else(|| self.reporting.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.subject.failure()).or_else(|| self.chunks.failure_with_buffer(&self.subject)),
            MaintenancePhaseV3::Inputs | MaintenancePhaseV3::Ownership => self.inputs.failure(),
            MaintenancePhaseV3::Readonly => self.readonly.failure(),
            MaintenancePhaseV3::Binding => self.binding.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            MaintenancePhaseV3::Policy => self.policy.failure(),
            MaintenancePhaseV3::Views => self.views.failure(),
            MaintenancePhaseV3::Assignment | MaintenancePhaseV3::Compiler => self.assignment.failure(),
            MaintenancePhaseV3::Inventory | MaintenancePhaseV3::Request => self.request.failure(),
            MaintenancePhaseV3::Plan => self.plan.failure(),
            MaintenancePhaseV3::Posts => self.inputs.failure().or_else(|| self.readonly.failure())
                .or_else(|| self.views.failure()).or_else(|| self.policy.failure()),
            MaintenancePhaseV3::Reply => None,
            MaintenancePhaseV3::Send => self.sent.failure(),
            MaintenancePhaseV3::Final => self.final_header_io.failure()
                .or_else(|| self.final_exchange.as_ref().and_then(|owner| owner.failure())),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.phase_failure_v3(self.phase).or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
    }
}

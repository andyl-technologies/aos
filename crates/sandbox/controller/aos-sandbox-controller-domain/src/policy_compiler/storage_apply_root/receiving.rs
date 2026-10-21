//! Retains the actual initial Apply buffers, semantic owners and owed posts.

use std::error::Error;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1,
    SubjectStreamReadErrorV1};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::QUERY_BYTES_V1;
use crate::normal_root::{NormalRootStartupErrorV1, RootControllerChunkSubjectSampleV1,
    RootPolicyAcceptedFlightV1};
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::bounded_stream_io::SliceDeadlineStreamIoV1;
use crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1;
use crate::policy_compiler::continuation_policy::{RootApplyPolicyOriginalV1, RootContinuationPolicyErrorV1};
use crate::policy_compiler::provisioning_current::{RootProvisioningNativeViewsV1,
    apply_inputs::RootApplyInputsOriginalV1, apply_readonly::RootApplyReadonlyContextV1,
    apply_compiler::RootApplyCompilerOriginalV1};
use crate::policy_compiler::create_storage_current::controller_readonly::RootProspectiveStorageApplyPlanV1;

#[derive(Clone, Copy)]
pub(in crate::policy_compiler) enum PhaseV1 {
    Opening, Subject, Inputs, Readonly, StorageBinding, Policy, Views, Compiler,
    Plan, Posts, Reply, Send, Final,
}

pub(super) struct RootStorageApplyNativeOriginalV1 {
    pub(super) phase: PhaseV1,
    pub(super) bytes: [u8; QUERY_BYTES_V1],
    pub(super) remainder: [u8; QUERY_BYTES_V1 - 32],
    pub(super) remainder_io: FixedDeadlineStreamIoV1<{QUERY_BYTES_V1 - 32}>,
    pub(super) geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    pub(super) reporting: Option<Result<(), SeqpacketError>>,
    pub(super) subject_prepared: Option<Result<(), SubjectStreamReadErrorV1>>,
    pub(super) subject: RetainedSubjectStreamReadV1,
    pub(super) chunks: RootSubjectChunkReceivingV1,
    pub(super) inputs: RootApplyInputsOriginalV1,
    pub(super) readonly: RootApplyReadonlyContextV1,
    pub(super) views: RootProvisioningNativeViewsV1,
    pub(super) compiler: RootApplyCompilerOriginalV1,
    pub(super) policy: RootApplyPolicyOriginalV1,
    pub(super) clock: Option<Box<crate::policy_compiler::provisioning_current::RootContinuationClockGateV1>>,
    pub(super) policy_begin: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pub(super) policy_verified: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pub(super) policy_after: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pub(super) plan: Option<Result<RootProspectiveStorageApplyPlanV1, Box<dyn Error>>>,
    pub(super) reply: Option<Result<Vec<u8>, Box<dyn Error>>>,
    pub(super) reply_digest: Option<[u8;32]>,
    pub(super) sent: SliceDeadlineStreamIoV1,
    pub(super) primary: Option<Result<(), Box<dyn Error>>>,
    pub(super) posts_finished: bool,
    pub(super) final_entry: Option<Result<(), Box<dyn Error>>>,
    pub(super) final_geometry: Option<Result<aos_sandbox_model::ResourceVector, Box<dyn Error>>>,
    pub(super) final_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) final_exchange: Option<Box<super::final_exchange::RootApplyFinalExchangeOriginalV1>>,
}

impl RootStorageApplyNativeOriginalV1 {
    pub(super) fn new() -> Self {
        Self { phase: PhaseV1::Opening, bytes: [0; QUERY_BYTES_V1], remainder: [0; QUERY_BYTES_V1 - 32],
            remainder_io: Default::default(), geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            reporting: None, subject_prepared: None, subject: RetainedSubjectStreamReadV1::new(),
            chunks: Default::default(), inputs: RootApplyInputsOriginalV1::new(),
            readonly: RootApplyReadonlyContextV1::new(), views: RootProvisioningNativeViewsV1::new(),
            compiler: RootApplyCompilerOriginalV1::new(), policy: Default::default(), clock: None,
            policy_begin: None, policy_verified: None, policy_after: None,
            plan: None, reply: None, reply_digest: None, sent: Default::default(), primary: None,
            posts_finished: false, final_entry: None, final_geometry: None, final_funding: None, final_exchange: None }
    }

    pub(super) fn finish_initial_posts_once_v1(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts_finished { return; }
        self.posts_finished = true;
        // These independent posts do not reacquire a healthy financial grant.
        // Every entered owner retains its own failure and original raw state.
        self.inputs.finish_posts_once_v1();
        self.readonly.finish_after_once_v1();
        let _owed = self.views.finish_apply_after_once_v1();
        if self.policy_begin.is_some() {
            self.policy_after = Some(flight.finish_apply_policy_once_v1(&mut self.policy));
        }
    }

    pub(super) fn phase_failure_v1(&self, phase: PhaseV1) -> Option<&(dyn Error + 'static)> {
        // Resolve only the entered phase. Later independently owed native
        // posts cannot replace a semantic failure in an earlier invocation.
        match phase {
            PhaseV1::Opening => self.remainder_io.failure(),
            PhaseV1::Subject => self.geometry.as_ref().err().map(|cause| cause as _)
                .or_else(|| self.reporting.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.subject.failure())
                .or_else(|| self.chunks.failure_with_buffer(&self.subject)),
            PhaseV1::Inputs | PhaseV1::StorageBinding => self.inputs.failure(),
            PhaseV1::Readonly => self.readonly.failure(),
            PhaseV1::Policy => self.policy.failure(),
            PhaseV1::Views => self.views.failure(),
            PhaseV1::Compiler => self.compiler.failure(),
            PhaseV1::Plan => self.plan.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref()),
            PhaseV1::Posts => self.inputs.failure().or_else(|| self.readonly.failure())
                .or_else(|| self.views.failure()).or_else(|| self.policy.failure()),
            PhaseV1::Reply => self.reply.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref()),
            PhaseV1::Send => self.sent.failure(),
            PhaseV1::Final => self.final_geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref())
                .or_else(|| self.final_funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.final_exchange.as_ref().and_then(|exchange| exchange.failure()))
                .or_else(|| self.final_entry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref())),
        }
    }

    pub(super) fn clock_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.clock.as_ref().and_then(|clock| clock.failure())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.phase_failure_v1(self.phase).or_else(|| self.clock_failure_v1())
    }
}

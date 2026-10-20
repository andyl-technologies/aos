//! Holds one Start resource Root socket's reached models and owed posts.

use super::{
    compiler::RootStartResourceCompilerOriginalV2, history::RootHostHistoricalCreateOriginalV2,
    inputs::RootStartResourceInputsOriginalV2, plan::RootStartResourceUnsignedPlanOriginalV2,
};
use crate::normal_root::{RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{
    bounded_stream_io::{FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1},
    continuation_policy::{RootContinuationPolicyErrorV1, RootHostLaunchPolicyOriginalV1},
    provisioning_current::{
        RootContinuationClockGateV1, RootProvisioningNativeViewsV1,
        apply_readonly::RootHostReadonlyContextV2,
    },
    root_subject_chunk::RootSubjectChunkReceivingV1,
};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::QUERY_BYTES_V1;

type Cause = Box<dyn std::error::Error>;

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Opening,
    Subject,
    Inputs,
    Readonly,
    Binding,
    Policy,
    Views,
    Compiler,
    Historical,
    Ownership,
    Plan,
    CurrentStorage,
    MountBeforePrepare,
    HostCatalog,
    Posts,
    Reply,
    Send,
    Final,
}

pub(super) struct RootStartResourceNativeOriginalV2 {
    pub(super) kind: Option<super::kind::ResourceKindV2>,
    pub(super) current_storage: Option<Box<super::current_storage::RootCurrentStoragePublicationOriginalV2>>,
    pub(super) host_catalog: Option<Box<super::host_catalog::RootHostCatalogInputsOriginalV2>>,
    pub(super) mount_before: Option<crate::policy_compiler::provisioning_current::finality_readonly::RootStartPreparationSessionReadOriginalV2>,
    pub(super) mount_inventory: Option<Box<super::session::RootStartResourceFinalSessionOriginalV2>>,
    pub(super) mount_before_result: Option<Result<(), Cause>>,
    pub(super) phase: Phase,
    pub(super) query: [u8; QUERY_BYTES_V1],
    pub(super) remainder: [u8; QUERY_BYTES_V1 - 32],
    pub(super) remainder_io: FixedDeadlineStreamIoV1<{QUERY_BYTES_V1 - 32}>,
    pub(super) geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    pub(super) subject: RetainedSubjectStreamReadV1,
    pub(super) chunks: RootSubjectChunkReceivingV1,
    pub(super) reporting: Option<Result<(), SeqpacketError>>,
    pub(super) inputs: RootStartResourceInputsOriginalV2,
    pub(super) readonly: RootHostReadonlyContextV2,
    pub(super) views: RootProvisioningNativeViewsV1,
    pub(super) compiler: RootStartResourceCompilerOriginalV2,
    pub(super) historical: RootHostHistoricalCreateOriginalV2,
    pub(super) policy: RootHostLaunchPolicyOriginalV1,
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
    pub(super) final_header: [u8; aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2],
    pub(super) final_header_io: FixedDeadlineStreamIoV1<{aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2}>,
    pub(super) final_exchange: Option<Box<super::final_exchange::RootStartResourceFinalExchangeOriginalV2>>,
}

impl RootStartResourceNativeOriginalV2 {
    pub(super) fn new() -> Self {
        Self { kind: None, current_storage: None, host_catalog: None, mount_before: None, mount_inventory: None,
            mount_before_result: None, phase: Phase::Opening, query: [0; QUERY_BYTES_V1], remainder: [0; QUERY_BYTES_V1 - 32],
            remainder_io: Default::default(), geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            subject: RetainedSubjectStreamReadV1::new(), chunks: Default::default(), reporting: None,
            inputs: RootStartResourceInputsOriginalV2::new(), readonly: RootHostReadonlyContextV2::new(),
            views: RootProvisioningNativeViewsV1::new(), compiler: RootStartResourceCompilerOriginalV2::new(),
            historical: RootHostHistoricalCreateOriginalV2::new(), policy: Default::default(),
            policy_begin: None, policy_verify: None, policy_post: None, clock: None, binding: None,
            plan: RootStartResourceUnsignedPlanOriginalV2::new(), reply: None, reply_digest: None,
            sent: Default::default(), posts: false, final_header: [0; aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2], final_header_io: Default::default(), final_exchange: None }
    }

    pub(super) fn finish_posts_once_v2(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts {
            return;
        }
        self.posts = true;
        if let Some(reader) = self.mount_before.as_mut() { reader.finish_posts_once_v2(); }
        if let Some(catalog) = self.host_catalog.as_mut() { catalog.finish_posts_once_v2(); }
        self.inputs.finish_posts_once_v2();
        self.readonly.finish_after_once_v2();
        let _owed = self.views.finish_host_launch_after_once_v1();
        if self.policy_begin.is_some() {
            self.policy_post = Some(flight.finish_host_launch_policy_once_v1(&mut self.policy));
        }
    }

    pub(super) fn phase_failure_v2(
        &self,
        phase: Phase,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match phase {
            Phase::Opening => self.remainder_io.failure(),
            Phase::Subject => self
                .geometry
                .as_ref()
                .err()
                .map(|cause| cause as _)
                .or_else(|| {
                    self.reporting
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| self.subject.failure())
                .or_else(|| self.chunks.failure_with_buffer(&self.subject)),
            Phase::Inputs | Phase::Ownership => self.inputs.failure(),
            Phase::Readonly => self.readonly.failure(),
            Phase::Binding => self
                .binding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            Phase::Policy => self.policy.failure(),
            Phase::Views => self.views.failure(),
            Phase::Compiler => self.compiler.failure(),
            Phase::Historical => self.historical.failure(),
            Phase::Plan => self.plan.failure().or_else(|| self.inputs.failure()),
            Phase::HostCatalog => self.host_catalog.as_ref().and_then(|catalog| catalog.failure()),
            Phase::MountBeforePrepare => self.mount_before.as_ref().and_then(|reader| reader.failure())
                .or_else(|| self.mount_inventory.as_ref().and_then(|model| model.failure()))
                .or_else(|| self.mount_before_result.as_ref()?.as_ref().err().map(|cause| cause.as_ref())),
            Phase::CurrentStorage => self
                .current_storage
                .as_ref()
                .and_then(|owner| owner.failure()),
            Phase::Posts => self.host_catalog.as_ref().and_then(|catalog| catalog.failure())
                .or_else(|| self.mount_before.as_ref().and_then(|reader| reader.failure()))
                .or_else(|| self.inputs.failure())
                .or_else(|| self.readonly.failure())
                .or_else(|| self.views.failure())
                .or_else(|| self.policy.failure()),
            Phase::Reply => None,
            Phase::Send => self.sent.failure(),
            Phase::Final => self.final_header_io.failure().or_else(|| {
                self.final_exchange
                    .as_ref()
                    .and_then(|exchange| exchange.failure())
            }),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.phase_failure_v2(self.phase)
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
    }
}

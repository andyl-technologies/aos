//! Retains the explicit SSH Authorize record until its signed start reply.
//!
//! Only the selected authenticated descriptor transport constructs this owner.
//! Its plan is request-bound DATA; the existing process effect still validates
//! the complete specification and owns every execution/native permission.

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_guest_protocol::openssh_receiving::OpenSshDescendantPlanDataV1;
use aos_sandbox_guest_protocol::{
    AgentFrameV1, AgentOperationRequestV1, AgentRuntimeBindingV1,
    AgentSealedSshAuthorizeReferenceV1,
};
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;

use crate::protected_entry::ProtectedGuestAgentErrorV1;
use crate::sealed_authorize::SealedAuthorizeOriginalV1;

pub(crate) struct GuestSshAuthorizeOriginalV1 {
    wire: Vec<u8>,
    rights: Vec<OwnedFd>,
    _subject: KernelAuthorizedRecordSubject,
    specification: SealedAuthorizeOriginalV1,
    frame_failure: Option<aos_sandbox_guest_protocol::AgentProtocolError>,
    plan: Option<OpenSshDescendantPlanDataV1>,
    pub(crate) effect: Option<Result<(), ProtectedGuestAgentErrorV1>>,
    pub(crate) response: Option<Result<(), ProtectedGuestAgentErrorV1>>,
}

impl GuestSshAuthorizeOriginalV1 {
    pub(crate) fn new(
        wire: Vec<u8>,
        rights: Vec<OwnedFd>,
        subject: KernelAuthorizedRecordSubject,
    ) -> Self {
        Self {
            wire,
            rights,
            _subject: subject,
            specification: SealedAuthorizeOriginalV1::new(),
            frame_failure: None,
            plan: None,
            effect: None,
            response: None,
        }
    }

    pub(crate) fn decode_frame_once(&mut self) -> Result<AgentFrameV1, ProtectedGuestAgentErrorV1> {
        match aos_sandbox_guest_protocol::decode_frame_v1(&self.wire) {
            Ok(frame) => Ok(frame),
            Err(cause) => {
                self.frame_failure = Some(cause);
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
        }
    }

    pub(crate) fn reconstruct_once(
        &mut self,
        reference: AgentSealedSshAuthorizeReferenceV1,
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<AgentOperationRequestV1, ProtectedGuestAgentErrorV1> {
        if self.specification.was_entered() || self.rights.len() != 1 {
            return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
        }
        let descriptor = self.rights.remove(0);
        let request = self.specification.reconstruct_once(
            descriptor,
            reference.content_bytes(),
            |bytes| reference.reconstruct(bytes, runtime),
        )?;
        self.plan = Some(*reference.plan_data_v1());
        Ok(request)
    }

    pub(crate) fn plan(&self) -> Result<&OpenSshDescendantPlanDataV1, ProtectedGuestAgentErrorV1> {
        self.plan
            .as_ref()
            .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.frame_failure
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| self.specification.failure())
            .or_else(|| self.effect.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.response
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

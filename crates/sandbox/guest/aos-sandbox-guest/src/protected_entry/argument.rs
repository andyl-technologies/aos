//! Retains one actual argument challenge through measurement and response.
//!
//! The inherited authenticated channel supplies the original bytes, rights and
//! kernel subject. This owner creates no execution permission. Only a positive
//! response retires its scratch; failure stays beside the original process.

use super::*;
use std::error::Error;

pub(super) struct GuestArgumentObservationOriginalV1 {
    wire: Vec<u8>,
    rights: Vec<OwnedFd>,
    _subject: Option<aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject>,
    decoded: Option<Result<GuestRuntimeArgumentObserveRequestV1, GuestRuntimeArgumentObservationErrorV1>>,
    signed: Option<Result<Vec<u8>, GuestRuntimeArgumentObservationErrorV1>>,
    sent: Option<Result<(), ProtectedGuestAgentErrorV1>>,
    body: Option<Result<(), ProtectedGuestAgentErrorV1>>,
    entered: bool,
    pub(super) protocol_failure: Option<ProtectedGuestAgentErrorV1>,
}

// The Host prepays this dedicated declared control bound at real Accept20.
// Every named type below is an actual owner, argument or Result in this helper;
// this checks representation growth without an invented proxy header.
const _: () = {
    use std::mem::size_of;
    let bytes = 6 * size_of::<GuestArgumentObservationOriginalV1>()
        + 2 * size_of::<Option<GuestArgumentObservationOriginalV1>>()
        + 6 * size_of::<(&mut GuestArgumentObservationOriginalV1, &Provisioning,
            AgentSessionBindingV1, &mut SeqpacketSocket, bool,
            &mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>, Instant)>()
        + 6 * size_of::<Result<(), ProtectedGuestAgentErrorV1>>()
        + 6 * size_of::<Result<Vec<u8>, GuestRuntimeArgumentObservationErrorV1>>()
        + 6 * size_of::<(&GuestRuntimeArgumentObserveRequestV1, &SigningKey)>()
        + 6 * size_of::<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>()
        + 6 * size_of::<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>()
        + 12 * size_of::<Option<&(dyn Error + 'static)>>()
        + 12 * size_of::<&GuestArgumentObservationOriginalV1>();
    // These are distinct from the conservative owner/header bound above.
    // `new` receives the three owning values; mem::take has its own arguments
    // and owning returns. The two parent as_mut sites and one shared failure
    // query retain their concrete Option/Result interfaces separately.
    let constructor_arguments = 3 * size_of::<(Vec<u8>, Vec<OwnedFd>,
        Option<aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject>)>()
        + 3 * size_of::<(&mut Vec<u8>, &mut Vec<OwnedFd>)>()
        + 3 * size_of::<(Vec<u8>, Vec<OwnedFd>)>();
    let parent_borrows = 6 * size_of::<Option<&mut GuestArgumentObservationOriginalV1>>()
        + 3 * size_of::<Result<&mut GuestArgumentObservationOriginalV1, ProtectedGuestAgentErrorV1>>()
        + 3 * size_of::<Option<&GuestArgumentObservationOriginalV1>>()
        + 2 * size_of::<&Option<GuestArgumentObservationOriginalV1>>();
    // Each decoder/signing Result is resident in Self; these are the separate
    // constructor/return and as_ref/as_ref/ok/ok_or interface values at both
    // actual engine and diagnostic selector sites.
    let decode_interfaces = 3 * size_of::<Result<GuestRuntimeArgumentObserveRequestV1, GuestRuntimeArgumentObservationErrorV1>>()
        + 3 * size_of::<(&[u8], &GuestRuntimeArgumentObserveRequestV1)>()
        + 6 * size_of::<Option<&Result<GuestRuntimeArgumentObserveRequestV1, GuestRuntimeArgumentObservationErrorV1>>>()
        + 6 * size_of::<Result<&GuestRuntimeArgumentObserveRequestV1, &GuestRuntimeArgumentObservationErrorV1>>()
        + 3 * size_of::<Option<&GuestRuntimeArgumentObserveRequestV1>>()
        + 3 * size_of::<Result<&GuestRuntimeArgumentObserveRequestV1, ProtectedGuestAgentErrorV1>>();
    let signed_interfaces = 6 * size_of::<Option<&Result<Vec<u8>, GuestRuntimeArgumentObservationErrorV1>>>()
        + 6 * size_of::<Result<&Vec<u8>, &GuestRuntimeArgumentObservationErrorV1>>()
        + 3 * size_of::<Option<&Vec<u8>>>()
        + 3 * size_of::<Result<&Vec<u8>, ProtectedGuestAgentErrorV1>>()
        + 3 * size_of::<(&mut SeqpacketSocket,
            Option<&mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>>,
            &[u8], Instant)>()
        + 3 * size_of::<Option<&mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>>>();
    let failure_interfaces = 6 * size_of::<Option<&Result<(), ProtectedGuestAgentErrorV1>>>()
        + 6 * size_of::<Result<&(), &ProtectedGuestAgentErrorV1>>()
        + 9 * size_of::<Option<&ProtectedGuestAgentErrorV1>>()
        + 6 * size_of::<Option<&GuestRuntimeArgumentObservationErrorV1>>()
        + 15 * size_of::<Option<&(dyn Error + 'static)>>()
        // Four or_else environments capture this shared actual owner. The
        // and_then/map adapters capture nothing and have zero-sized environments.
        + 8 * size_of::<&GuestArgumentObservationOriginalV1>();
    // `completed` has two actual callers. Its is_empty/is_none methods have
    // separate bool returns; the selection bool in run_inner's argument tuple
    // does not cover these values or bool::then_some's own receiver/argument.
    let completion_predicates = 6 * size_of::<bool>()
        + 3 * size_of::<bool>()  // completed: rights.is_empty return
        + 3 * size_of::<bool>()  // completed: failure().is_none return
        + 3 * size_of::<&Option<&(dyn Error + 'static)>>()
        + 3 * size_of::<(bool,
            &mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>)>();
    let bytes = bytes + completion_predicates + constructor_arguments + parent_borrows
        + decode_interfaces + signed_interfaces + failure_interfaces;
    assert!(bytes <= aos_sandbox_guest_protocol::argument_receiving::ARGUMENT_GUEST_CONTROL_BYTES_V1);
};

impl GuestArgumentObservationOriginalV1 {
    pub(super) fn new(wire: Vec<u8>, rights: Vec<OwnedFd>,
        subject: Option<aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject>) -> Self
    {
        Self { wire, rights, _subject: subject, decoded: None, signed: None,
            sent: None, body: None, entered: false, protocol_failure: None }
    }

    pub(super) fn run_once(&mut self, provisioning: &Provisioning,
        binding: AgentSessionBindingV1, socket: &mut SeqpacketSocket,
        selected: bool, retained_send: &mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>,
        deadline: Instant) -> Result<(), ProtectedGuestAgentErrorV1>
    {
        if self.entered { return Err(ProtectedGuestAgentErrorV1::CaptureRefused); }
        self.entered = true;
        self.body = Some(self.run_inner(provisioning, binding, socket, selected, retained_send, deadline));
        if self.completed() { Ok(()) } else { Err(ProtectedGuestAgentErrorV1::CaptureRefused) }
    }

    fn run_inner(&mut self, provisioning: &Provisioning,
        binding: AgentSessionBindingV1, socket: &mut SeqpacketSocket,
        selected: bool, retained_send: &mut Option<aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>,
        deadline: Instant) -> Result<(), ProtectedGuestAgentErrorV1>
    {
        if !self.rights.is_empty() { return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame); }
        if !provisioning.features.contains(AgentFeatureV1::RuntimeArgumentObservation) {
            return Err(ProtectedGuestAgentErrorV1::UnsupportedFeature);
        }
        self.decoded = Some(GuestRuntimeArgumentObserveRequestV1::decode(&self.wire));
        let observe = self.decoded.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
        if observe.session() != binding || observe.runtime() != &provisioning.runtime
            || observe.channel() != provisioning.channel
        { return Err(ProtectedGuestAgentErrorV1::OperationMismatch); }
        check_deadline(deadline)?;
        self.signed = Some(sign_current_guest_argument_readback_v1(observe, &provisioning.signing_key));
        let packet = self.signed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)?;
        check_deadline(deadline)?;
        self.sent = Some(send_selected_v2(socket, selected.then_some(retained_send), packet, deadline));
        if matches!(self.sent, Some(Ok(()))) { Ok(()) }
        else { Err(ProtectedGuestAgentErrorV1::CaptureRefused) }
    }

    pub(super) fn completed(&self) -> bool {
        self.entered && self.rights.is_empty()
            && matches!(self.body, Some(Ok(()))) && matches!(self.sent, Some(Ok(())))
            && self.failure().is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.decoded.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.signed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.protocol_failure.as_ref().map(|cause| cause as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    fn provisioning() -> Provisioning {
        Provisioning {
            runtime: AgentRuntimeBindingV1::new(SandboxId::from_bytes([1; 16]),
                IncarnationId::from_bytes([2; 16]), AssignmentEpoch::new(3),
                ObjectDigest::from_bytes([4; 32]), DesiredGeneration::new(5),
                NamespaceGeneration::new(6), [7; 16]).unwrap(),
            channel: ObjectDigest::from_bytes([8; 32]), instance: [9; 16],
            signing_key: SigningKey::from_bytes(&[10; 32]),
            features: AgentFeatureSetV1::new(aos_sandbox_guest_protocol::guest_root_publication::CONCRETE_GUEST_FEATURES_V1.to_vec()).unwrap(),
            package_binding: ObjectDigest::from_bytes([11; 32]),
        }
    }

    #[test]
    fn received_rights_stay_on_the_actual_failed_original() {
        let file: OwnedFd = File::open("/dev/null").unwrap().into();
        let fd = file.as_raw_fd();
        let mut original = GuestArgumentObservationOriginalV1::new(vec![7; 8], vec![file], None);
        let (mut socket, _peer) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let binding = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([12; 32])).unwrap();
        let mut send_failure = None;

        assert!(original.run_once(&provisioning(), binding, &mut socket, true,
            &mut send_failure, Instant::now() + Duration::from_secs(1)).is_err());

        assert_eq!(original.rights[0].as_raw_fd(), fd);
        assert_eq!(original.wire, vec![7; 8]);
        assert!(matches!(original.body, Some(Err(ProtectedGuestAgentErrorV1::UnexpectedFrame))));
        assert!(original.failure().is_some());
        assert!(!original.completed());
        assert!(original.decoded.is_none());
        assert!(original.sent.is_none());
    }

    #[test]
    fn malformed_request_keeps_its_decode_cause_and_refuses_reentry() {
        let mut original = GuestArgumentObservationOriginalV1::new(vec![7; 8], Vec::new(), None);
        let (mut socket, _peer) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let binding = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([12; 32])).unwrap();
        let mut send_failure = None;
        let deadline = Instant::now() + Duration::from_secs(1);

        assert!(original.run_once(&provisioning(), binding, &mut socket, true, &mut send_failure, deadline).is_err());
        let first = original.failure().unwrap() as *const dyn Error;
        assert!(original.run_once(&provisioning(), binding, &mut socket, true, &mut send_failure, deadline).is_err());

        assert!(std::ptr::addr_eq(first, original.failure().unwrap() as *const dyn Error));
        assert!(original.signed.is_none());
        assert!(original.sent.is_none());
        assert!(!original.completed());
    }

    #[test]
    fn positive_original_measures_signs_and_sends_the_same_challenge() {
        let provisioning = provisioning();
        let binding = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([12; 32])).unwrap();
        let request = GuestRuntimeArgumentObserveRequestV1::new(provisioning.runtime,
            binding, provisioning.channel, [13; 32],
            aos_sandbox_model::FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            ObjectDigest::from_bytes([14; 32])).unwrap();
        let mut original = GuestArgumentObservationOriginalV1::new(request.encode(), Vec::new(), None);
        let (mut socket, _peer) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut send_failure = None;

        original.run_once(&provisioning, binding, &mut socket, true,
            &mut send_failure, Instant::now() + Duration::from_secs(1)).unwrap();

        assert!(original.completed());
        let packet = original.signed.as_ref().unwrap().as_ref().unwrap();
        let verified = aos_sandbox_guest_protocol::runtime_argument_observation::verify_guest_runtime_argument_readback_v1(
            packet, &request, &provisioning.signing_key.verifying_key()).unwrap();
        assert!(verified.evidence().runtime_limit_bytes() > 0);
        assert!(send_failure.is_none());
    }

}

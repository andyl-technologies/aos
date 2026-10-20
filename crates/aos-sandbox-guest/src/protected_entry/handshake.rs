//! Whole native receive custody of the selected normal Guest's first handshake.

use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, ReceivedRecord, RecordBindingError,
    RetainedSeqpacketReceiveErrorV1, SeqpacketSocket,
};

use super::{AgentSessionBindingV1, ProtectedGuestAgentErrorV1, RETRY_INTERVAL};

#[derive(Default)]
pub(super) struct InitialHandshakeOriginalV2 {
    receive: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    binding: Option<Result<(), RecordBindingError>>,
    packet: Option<(Vec<u8>, KernelAuthorizedRecordSubject)>,
    pub(super) body: Option<Result<AgentSessionBindingV1, ProtectedGuestAgentErrorV1>>,
}

impl InitialHandshakeOriginalV2 {
    pub(super) fn receive(
        &mut self,
        socket: &mut SeqpacketSocket,
        deadline: std::time::Instant,
        progress: &mut impl FnMut(),
    ) -> Result<(), ProtectedGuestAgentErrorV1> {
        if self.receive.is_some() || self.packet.is_some() {
            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
        }
        loop {
            progress();
            super::check_deadline(deadline)?;
            self.receive = Some(socket.receive_guest_initial_handshake_retaining_v2(
                aos_sandbox_agent::protocol::AGENT_HANDSHAKE_REQUEST_BYTES_V2,
            ));
            if self.receive.as_ref().is_some_and(|result| {
                result.as_ref().is_err_and(|cause| {
                    cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted()
                })
            }) {
                self.receive.take();
                std::thread::sleep(RETRY_INTERVAL);
                continue;
            }
            break;
        }
        let record = match self.receive.take() {
            Some(Ok(record)) => record,
            other => {
                self.receive = other;
                return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
            }
        };
        match socket.bind_received_retaining(record) {
            Ok(bound) => {
                let (bytes, subject, _) = bound.into_parts();
                self.packet = Some((bytes, subject));
                self.binding = Some(Ok(()));
                Ok(())
            }
            Err((cause, record)) => {
                self.binding = Some(Err(cause));
                self.receive = Some(Ok(record));
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
        }
    }

    pub(super) fn payload(&self) -> Result<&[u8], ProtectedGuestAgentErrorV1> {
        self.packet
            .as_ref()
            .map(|(bytes, _)| bytes.as_slice())
            .ok_or(ProtectedGuestAgentErrorV1::CaptureRefused)
    }

    pub(super) fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receive
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.binding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_entry::*;
    use aos_sandbox_agent::model::{AgentNonceV1, AgentSessionIdV1};
    use std::os::fd::AsFd as _;
    use std::time::{Duration, Instant};

    fn fixture() -> (Provisioning, AgentHandshakeRequestV1) {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
            DesiredGeneration::new(5),
            NamespaceGeneration::new(6),
            [7; 16],
        )
        .unwrap();
        let channel = ObjectDigest::from_bytes([8; 32]);
        let request = AgentHandshakeRequestV1::new(
            AgentSessionIdV1::new([9; 16]).unwrap(),
            runtime,
            AgentNonceV1::new([10; 32]).unwrap(),
            channel,
        )
        .unwrap();
        let provisioning = Provisioning {
            runtime,
            channel,
            instance: [11; 16],
            signing_key: SigningKey::from_bytes(&[12; 32]),
            features: AgentFeatureSetV1::new(vec![
                AgentFeatureV1::Readiness,
                AgentFeatureV1::ExecutionHandoff,
                AgentFeatureV1::CapturePipeHandoffV2,
            ])
            .unwrap(),
            package_binding: ObjectDigest::from_bytes([13; 32]),
        };
        (provisioning, request)
    }

    #[test]
    fn selected_handshake_uses_real_bounded_receive_and_keeps_authorize_rights_enabled() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        sender.enable_record_subjects().unwrap();
        let (provisioning, request) = fixture();
        sender
            .send(&encode_frame_v1(&AgentFrameV1::HandshakeRequest(request)))
            .unwrap();
        let mut original = InitialHandshakeOriginalV2::default();
        let mut send_failure = None;

        original.body = Some(authenticate_initial_handshake_v2(
            &mut receiver,
            &provisioning,
            Instant::now() + Duration::from_secs(1),
            Some(&mut original),
            Some(&mut send_failure),
            &mut || {},
        ));

        assert!(matches!(original.body, Some(Ok(_))));
        assert!(original.packet.is_some());
        assert!(original.native_failure().is_none());
        assert!(send_failure.is_none());
        assert_eq!(
            SeqpacketSocket::guest_initial_handshake_receive_obligations_v2(
                aos_sandbox_agent::protocol::AGENT_HANDSHAKE_REQUEST_BYTES_V2
            )
            .unwrap()
            .1,
            19
        );
        assert!(receiver.zero_rights_receive_obligations_v1(64).is_none());
        let descriptor = std::fs::File::open("/dev/null").unwrap();
        sender
            .send_with_descriptors(b"later Authorize table", &[descriptor.as_fd()])
            .unwrap();
        assert_eq!(
            receiver
                .receive_agent_authorize_retaining_v2(64)
                .unwrap()
                .descriptors()
                .len(),
            1
        );
    }

    #[test]
    fn forbidden_handshake_rights_keep_the_whole_native_failure() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let descriptor = std::fs::File::open("/dev/null").unwrap();
        sender
            .send_with_descriptors(b"forbidden handshake rights", &[descriptor.as_fd()])
            .unwrap();
        let mut original = InitialHandshakeOriginalV2::default();

        assert!(
            original
                .receive(
                    &mut receiver,
                    Instant::now() + Duration::from_secs(1),
                    &mut || {}
                )
                .is_err()
        );

        assert!(matches!(original.receive, Some(Err(_))));
        assert!(original.native_failure().is_some());
        assert!(
            original
                .receive(
                    &mut receiver,
                    Instant::now() + Duration::from_secs(1),
                    &mut || {}
                )
                .is_err()
        );
    }
}

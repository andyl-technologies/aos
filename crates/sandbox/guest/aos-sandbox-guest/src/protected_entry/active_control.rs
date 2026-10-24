//! Original Agent receive-mode transition across one actual execution lifetime.

use aos_sandbox_guest_protocol::model::AgentRuntimeBindingV1;
use aos_sandbox_model::ExecutionId;
use aos_sandbox_linux::seqpacket::{
    SeqpacketError, SeqpacketRightsRestrictionOriginalV6, SeqpacketSocket,
};

use super::ProtectedGuestAgentErrorV1;

pub(super) struct ActiveControlOriginalV2 {
    execution: ExecutionId,
    pub(super) restriction: SeqpacketRightsRestrictionOriginalV6,
    entry: Option<Result<(), SeqpacketError>>,
    restore: Option<Result<(), SeqpacketError>>,
    pub(super) protocol_failure: Option<ProtectedGuestAgentErrorV1>,
}

impl ActiveControlOriginalV2 {
    pub(super) fn new(execution: ExecutionId) -> Self {
        Self {
            execution,
            restriction: SeqpacketRightsRestrictionOriginalV6::new(),
            entry: None,
            restore: None,
            protocol_failure: None,
        }
    }

    pub(super) fn enter(
        &mut self,
        socket: &mut SeqpacketSocket,
    ) -> Result<(), ProtectedGuestAgentErrorV1> {
        if self.entry.is_some() {
            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
        }
        self.entry = Some(socket.restrict_incoming_rights_retaining_v6(&mut self.restriction));
        if matches!(self.entry, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ProtectedGuestAgentErrorV1::CaptureRefused)
        }
    }

    pub(super) fn is_restored(&self) -> bool {
        matches!(self.restore, Some(Ok(())))
    }

    pub(super) fn restore_after_retirement(
        &mut self,
        socket: &mut SeqpacketSocket,
        execution: ExecutionId,
        runtime: &AgentRuntimeBindingV1,
        retirement: &crate::OriginalExecutionTransportRetirementV2,
    ) -> Result<(), ProtectedGuestAgentErrorV1> {
        if self.execution != execution || !retirement.matches(execution, runtime) {
            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
        }
        // Fresh C2 Observe may report the same physically retired original.
        // It neither restores twice nor reactivates a discarded restriction.
        if self.is_restored() {
            return Ok(());
        }
        if self.restore.is_some() {
            return Err(ProtectedGuestAgentErrorV1::CaptureRefused);
        }
        socket.require_rights_restriction_current_v6(&self.restriction)?;
        self.restore = Some(socket.restore_rights_once_v1());
        if self.is_restored() {
            Ok(())
        } else {
            Err(ProtectedGuestAgentErrorV1::CaptureRefused)
        }
    }

    pub(super) fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.restriction
            .failure()
            .or_else(|| self.entry.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.restore
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
    use std::os::fd::AsFd as _;

    #[test]
    fn completed_authorize_packet_precedes_active_native_mode() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let sealed = std::fs::File::open("/dev/null").unwrap();
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/null").unwrap();
        sender
            .send_with_descriptors(
                b"actual original descriptor table",
                &[sealed.as_fd(), first.as_fd(), second.as_fd()],
            )
            .unwrap();
        let record = receiver.receive_agent_authorize_retaining_v2(256).unwrap();
        let (_, subject, rights) = record.into_parts();
        assert_eq!(rights.len(), 3);
        assert_eq!(rights.len() + 1, SeqpacketSocket::agent_authorize_verified_retained_files_v2());
        let mut original = ActiveControlOriginalV2::new(ExecutionId::from_bytes([1; 16]));

        original.enter(&mut receiver).unwrap();
        sender.send(b"active control").unwrap();
        let record = receiver
            .receive_agent_active_control_retaining_v2(256, &original.restriction)
            .unwrap();

        assert_eq!(record.payload(), b"active control");
        assert!(
            receiver
                .require_rights_restriction_current_v6(&original.restriction)
                .is_ok()
        );
        assert_eq!(
            SeqpacketSocket::agent_active_control_receive_obligations_v2(256)
                .unwrap()
                .1,
            3
        );
        assert_eq!(rights.len(), 3);
        assert_eq!(subject.credentials().pid().get(), std::process::id());
    }

    #[test]
    fn queued_next_operation_refuses_before_an_effect_can_start() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        sender.send(b"pipelined operation").unwrap();
        let mut original = ActiveControlOriginalV2::new(ExecutionId::from_bytes([2; 16]));

        assert!(original.enter(&mut receiver).is_err());

        assert!(original.native_failure().is_some());
        assert!(!original.is_restored());
        assert!(
            receiver
                .receive_agent_active_control_retaining_v2(256, &original.restriction)
                .is_err()
        );
        assert!(original.enter(&mut receiver).is_err());
    }
}

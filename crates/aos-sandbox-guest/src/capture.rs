//! Owns the exact Capture spec and two write-only pipe roles through launch.
//!
//! Only the authenticated kind14 receive branch creates this destination. Its
//! descriptors are transport inputs; Storage's regular files and drainer never
//! enter Guest custody. Failure retains reached native owners and actual causes.

use std::error::Error;
use std::os::fd::OwnedFd;
use std::process::{Child, ChildStdin, Command};

use aos_sandbox_agent::{AgentOperationRequestV1, AgentSealedAuthorizeReferenceV1};
use aos_sandbox_core::{ExecutionOutputModeV1, ExecutionTerminalModeV1};
use rustix::fs::{FileType, OFlags};

use crate::protected_entry::ProtectedGuestAgentErrorV1;
use crate::process::GuestProcessEffectErrorV1;

/// Retains a received Capture transport and its actual process-launch owners.
///
/// No public constructor or descriptor accessor exists. A custom effect owner
/// cannot manufacture an authenticated channel, spec, process or output grant.
pub struct GuestCaptureAuthorizeOriginalV2 {
    wire: Vec<u8>,
    rights: Vec<OwnedFd>,
    _subject: aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject,
    specification: crate::sealed_authorize::SealedAuthorizeOriginalV1,
    frame_failure: Option<aos_sandbox_agent::AgentProtocolError>,
    stats: [Option<Result<rustix::fs::Stat, rustix::io::Errno>>; 2],
    flags: [Option<Result<OFlags, rustix::io::Errno>>; 2],
    validation: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) command: Option<Command>,
    pub(super) spawned: Option<std::io::Result<Child>>,
    pub(super) input: Option<ChildStdin>,
    pub(super) effect: Option<Result<(), GuestProcessEffectErrorV1>>,
    pub(super) response: Option<Result<(), ProtectedGuestAgentErrorV1>>,
    pub(super) protocol_failure: Option<ProtectedGuestAgentErrorV1>,
    request_binding: Option<aos_sandbox_core::ObjectDigest>,
}

// The portable provider pays the same actual compiled native/launch layouts;
// a larger future owner must change the declared bound before this can build.
const _: () = {
    let receiving = std::mem::size_of::<GuestCaptureAuthorizeOriginalV2>() * 3
        + std::mem::size_of::<Command>() * 2
        + std::mem::size_of::<std::io::Result<Child>>() * 2
        + std::mem::size_of::<rustix::fs::Stat>() * 4
        + 4 * 4096 + 8 * 256;
    assert!(receiving <= aos_sandbox_agent::capture_receiving::CAPTURE_GUEST_CONTROL_BYTES_V2);
};

impl GuestCaptureAuthorizeOriginalV2 {
    pub(super) fn new(
        wire: Vec<u8>, rights: Vec<OwnedFd>,
        subject: aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject,
    ) -> Self {
        Self {
            wire, rights, _subject: subject,
            specification: crate::sealed_authorize::SealedAuthorizeOriginalV1::new(),
            frame_failure: None, stats: [None, None], flags: [None, None], validation: None,
            command: None, spawned: None, input: None, effect: None, response: None,
            protocol_failure: None,
            request_binding: None,
        }
    }

    pub(super) fn decode_frame_once(&mut self)
        -> Result<aos_sandbox_agent::AgentFrameV1, ProtectedGuestAgentErrorV1>
    {
        match aos_sandbox_agent::decode_frame_v1(&self.wire) {
            Ok(frame) => Ok(frame),
            Err(cause) => {
                self.frame_failure = Some(cause);
                Err(ProtectedGuestAgentErrorV1::CaptureRefused)
            }
        }
    }

    pub(super) fn reconstruct_once(&mut self, reference: AgentSealedAuthorizeReferenceV1)
        -> Result<AgentOperationRequestV1, ProtectedGuestAgentErrorV1>
    {
        if self.specification.was_entered() || self.rights.len() != 3 {
            return Err(ProtectedGuestAgentErrorV1::UnexpectedFrame);
        }
        // The two pipe originals remain in their exact stdout/stderr order.
        let specification = self.rights.remove(0);
        let request = self.specification.reconstruct_once(
            specification, reference.content_bytes(), |bytes| reference.reconstruct(bytes),
        )?;
        self.request_binding = Some(request.request_commitment());
        Ok(request)
    }

    pub(super) fn matches_request(&self, request: &AgentOperationRequestV1) -> bool {
        self.request_binding == Some(request.request_commitment())
            && matches!(request.operation(), aos_sandbox_agent::AgentExecutionOperationV1::Authorize { .. })
    }

    pub(super) fn validate_pipes_once(&mut self, request: &AgentOperationRequestV1)
        -> Result<(), GuestProcessEffectErrorV1>
    {
        if self.validation.is_some() || self.request_binding != Some(request.request_commitment()) {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        self.inspect_pipe_roles_once()
    }

    fn inspect_pipe_roles_once(&mut self) -> Result<(), GuestProcessEffectErrorV1> {
        if self.validation.is_some() { return Err(GuestProcessEffectErrorV1::InvalidRequest); }
        self.validation = Some((|| {
            if self.rights.len() != 2 { return Err(GuestProcessEffectErrorV1::InvalidRequest); }
            for index in 0..2 {
                self.stats[index] = Some(rustix::fs::fstat(&self.rights[index]));
                let stat = self.stats[index].as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::Fifo {
                    return Err(GuestProcessEffectErrorV1::InvalidRequest);
                }
                self.flags[index] = Some(rustix::fs::fcntl_getfl(&self.rights[index]));
                let flags = self.flags[index].as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
                if *flags & OFlags::ACCMODE != OFlags::WRONLY {
                    return Err(GuestProcessEffectErrorV1::InvalidRequest);
                }
            }
            let stdout = self.stats[0].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
            let stderr = self.stats[1].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
            if (stdout.st_dev, stdout.st_ino) == (stderr.st_dev, stderr.st_ino) {
                return Err(GuestProcessEffectErrorV1::InvalidRequest);
            }
            Ok(())
        })());
        if matches!(self.validation, Some(Ok(()))) { Ok(()) }
        else { Err(GuestProcessEffectErrorV1::InvalidRequest) }
    }

    pub(super) fn configure_command(&mut self, command: &mut Command)
        -> Result<(), GuestProcessEffectErrorV1>
    {
        if !matches!(self.validation, Some(Ok(()))) || self.rights.len() != 2 {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        let stderr = self.rights.pop().ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        let stdout = self.rights.pop().ok_or(GuestProcessEffectErrorV1::InvalidRequest)?;
        command.stdout(std::process::Stdio::from(stdout));
        command.stderr(std::process::Stdio::from(stderr));
        Ok(())
    }

    /// Borrows the chronological actual failed capture owner for diagnostics.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.frame_failure.as_ref().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.specification.failure())
            .or_else(|| {
                for index in 0..2 {
                    if let Some(cause) = error(&self.stats[index]) { return Some(cause); }
                    if let Some(cause) = error(&self.flags[index]) { return Some(cause); }
                }
                None
            })
            .or_else(|| error(&self.validation)).or_else(|| error(&self.spawned))
            .or_else(|| error(&self.effect)).or_else(|| error(&self.response))
            .or_else(|| self.protocol_failure.as_ref().map(|cause| cause as _))
    }

    pub(super) fn effect_completed(&self) -> bool {
        matches!(self.effect, Some(Ok(()))) && self.spawned.is_none()
            && self.command.is_some() && self.rights.is_empty()
            && matches!(self.validation, Some(Ok(())))
    }

    // Only the same protocol loop calls this after the actual signed response
    // send succeeds. Closing parent writers proves no output EOF or completion;
    // live descendants retain their own FDs1/2 until actual kernel closure.
    pub(super) fn complete_after_sent(&mut self) {
        if self.effect_completed() && matches!(self.response, Some(Ok(()))) {
            drop(self.command.take());
            drop(self.input.take());
        }
    }
}

pub(super) fn require_capture_shape(
    output: ExecutionOutputModeV1, terminal: ExecutionTerminalModeV1,
    capture: bool,
) -> Result<(), GuestProcessEffectErrorV1> {
    if matches!(output, ExecutionOutputModeV1::Capture { .. }) != capture
        || capture && terminal == ExecutionTerminalModeV1::Pty {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    // Core's canonical spec validator independently requires Capture/Continue/
    // Detached. Its zero limits are valid and are not changed into absence.
    Ok(())
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use aos_sandbox_linux::seqpacket::SeqpacketSocket;

    fn native_pipe_destination(rights: &[std::os::fd::BorrowedFd<'_>]) -> GuestCaptureAuthorizeOriginalV2 {
        let (mut receiver, sender) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        sender.send_with_descriptors(b"native-only-test", rights).unwrap();
        let (wire, subject, rights) = receiver.receive_with_descriptors(64, rights.len()).unwrap().into_parts();
        GuestCaptureAuthorizeOriginalV2::new(wire, rights, subject)
    }

    #[test]
    fn failed_spawn_retains_actual_write_ends_in_same_command() {
        let (stdout_reader, stdout) = rustix::pipe::pipe().unwrap();
        let (stderr_reader, stderr) = rustix::pipe::pipe().unwrap();
        let mut original = native_pipe_destination(&[stdout.as_fd(), stderr.as_fd()]);
        drop(stdout);
        drop(stderr);
        original.inspect_pipe_roles_once().unwrap();
        let mut command = Command::new("/aos-no-such-capture-test-executable");
        original.configure_command(&mut command).unwrap();
        original.command = Some(command);
        original.spawned = Some(original.command.as_mut().unwrap().spawn());
        assert!(original.spawned.as_ref().unwrap().is_err());

        rustix::fs::fcntl_setfl(&stdout_reader, OFlags::NONBLOCK).unwrap();
        rustix::fs::fcntl_setfl(&stderr_reader, OFlags::NONBLOCK).unwrap();
        let mut byte = [0];
        assert_eq!(rustix::io::read(&stdout_reader, &mut byte), Err(rustix::io::Errno::AGAIN));
        assert_eq!(rustix::io::read(&stderr_reader, &mut byte), Err(rustix::io::Errno::AGAIN));
        assert!(!original.effect_completed());
        assert!(original.failure().is_some());
    }

    #[test]
    fn read_end_and_alias_roles_refuse_without_losing_their_native_results() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut read_end = native_pipe_destination(&[reader.as_fd(), writer.as_fd()]);
        assert!(read_end.inspect_pipe_roles_once().is_err());
        assert!(read_end.stats[0].as_ref().unwrap().is_ok());
        assert!(read_end.flags[0].as_ref().unwrap().is_ok());
        assert_eq!(read_end.rights.len(), 2);

        let mut alias = native_pipe_destination(&[writer.as_fd(), writer.as_fd()]);
        assert!(alias.inspect_pipe_roles_once().is_err());
        assert_eq!(alias.rights.len(), 2);
    }

    #[test]
    fn zero_capture_limit_is_a_valid_mode_and_cannot_use_legacy_stream_transport() {
        let zero = ExecutionOutputModeV1::Capture {
            maximum_stdout_bytes: 0, maximum_stderr_bytes: 0,
        };
        assert!(require_capture_shape(zero, ExecutionTerminalModeV1::None, true).is_ok());
        assert!(require_capture_shape(zero, ExecutionTerminalModeV1::None, false).is_err());
        assert!(require_capture_shape(zero, ExecutionTerminalModeV1::Pty, true).is_err());
    }
}

//! Strict kernel-subject evidence for bounded chunks of one original stream.
//!
//! A stream has no record boundaries. Every nonempty returned chunk therefore
//! retains independent credentials, pidfd, and sending **socket** SID; framed
//! protocols must validate every chunk before assembling their exact message.
//! SCM_SECURITY does not identify a delegated descriptor's actual writer.
//! This carrier creates no application-role or live Root authority.

use super::RetainedUnixStream;
use crate::seqpacket::{
    KernelAuthorizedRecordSubject, SeqpacketError, map_kernel_error, validate_record_subject,
};
use crate::uapi::{self, RawAncillary};

const MAXIMUM_CHUNK_BYTES: usize = 4096;
const MAXIMUM_SECURITY_CONTEXT_BYTES: usize = 256;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum StreamSubjectState {
    Dormant,
    Ready,
    Poisoned,
}

impl RetainedUnixStream {
    /// Enables strict subject reporting on this same original retained stream.
    ///
    /// Call before the first request that can trigger a response. Previously
    /// queued bytes without complete subjects are rejected, never upgraded.
    /// Callers must exclusively own consumption and option changes, including
    /// every duplicate. No second connection or carrier is created.
    ///
    /// # Errors
    /// Rejects failure to enable credentials, pidfd, or security-context
    /// reporting. Adoption neither changes nonblocking status nor grants a role.
    pub fn enable_subject_reporting(&mut self) -> Result<(), SeqpacketError> {
        if self.subject_state != StreamSubjectState::Dormant {
            return Err(SeqpacketError::Closed);
        }
        if let Err(error) = uapi::enable_stream_subject(self.as_fd()) {
            self.subject_state = StreamSubjectState::Poisoned;
            return Err(error.into());
        }
        self.subject_state = StreamSubjectState::Ready;
        Ok(())
    }

    /// Tries to receive one bounded chunk and its independent kernel evidence.
    ///
    /// Credentials and SCM_PIDFD are kernel-authorized nominations. Security
    /// context is the sending socket inode's SID, not the sending task's SID.
    /// No comparison here promotes those facts to execution provenance.
    ///
    /// # Errors
    /// Returns WouldBlock/Interrupted without poisoning. Any missing, duplicate,
    /// truncated, malformed, foreign, descriptor-bearing or changed-option
    /// receive poisons this subject profile; EOF does too. Invalid bounds do
    /// not. Ordinary descriptor operations remain outside this profile, so the
    /// higher-level flight must never bypass it with a competing raw read.
    pub fn try_receive_subject_chunk(
        &mut self,
        maximum: usize,
    ) -> Result<UnixStreamSubjectChunk, SeqpacketError> {
        if self.subject_state != StreamSubjectState::Ready {
            return Err(SeqpacketError::Closed);
        }
        if maximum == 0 || maximum > MAXIMUM_CHUNK_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_chunk(maximum);
        if result.as_ref().is_err_and(|error| {
            !matches!(
                error,
                SeqpacketError::WouldBlock | SeqpacketError::Interrupted
            )
        }) {
            self.subject_state = StreamSubjectState::Poisoned;
        }
        result
    }

    fn receive_chunk(&self, maximum: usize) -> Result<UnixStreamSubjectChunk, SeqpacketError> {
        let fd = self.as_fd();
        uapi::require_stream_subject(fd)?;
        let mut payload = vec![0; maximum];
        // recvmsg/control ownership is shared with the existing strict carrier;
        // only its Unix transport-independent syscall/parser is reused here.
        let received = uapi::recv_seqpacket(fd, &mut payload, 0).map_err(map_kernel_error)?;
        if received.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::Ancillary("stream control data truncated"));
        }
        if received.flags & libc::MSG_TRUNC != 0 || received.bytes > maximum {
            return Err(SeqpacketError::PayloadTruncated);
        }
        if received.bytes == 0 {
            return Err(SeqpacketError::Closed);
        }
        let (subject, socket_context) = validate_stream_subject(received.ancillary)?;
        payload.truncate(received.bytes);
        uapi::require_stream_subject(fd)?;
        Ok(UnixStreamSubjectChunk {
            payload,
            subject,
            socket_context,
        })
    }
}

/// Retains one chunk's data, nominated process, and sending-socket context.
#[derive(Debug)]
pub struct UnixStreamSubjectChunk {
    payload: Vec<u8>,
    subject: KernelAuthorizedRecordSubject,
    socket_context: Vec<u8>,
}

impl UnixStreamSubjectChunk {
    /// Borrows only the bytes covered by this chunk's ancillary evidence.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrows this chunk's independently kernel-authorized nominated process.
    #[must_use]
    pub const fn subject(&self) -> &KernelAuthorizedRecordSubject {
        &self.subject
    }

    /// Borrows the canonical sending-socket SELinux context without its NUL.
    ///
    /// This identifies the socket's SID, not a post-delegation sending task.
    #[must_use]
    pub fn socket_context(&self) -> &[u8] {
        &self.socket_context
    }
}

fn validate_stream_subject(
    ancillary: Vec<RawAncillary>,
) -> Result<(KernelAuthorizedRecordSubject, Vec<u8>), SeqpacketError> {
    let mut identity = Vec::new();
    let mut security = None;
    for item in ancillary {
        match item {
            RawAncillary::SecurityContext(mut context) => {
                if security.is_some()
                    || context.len() < 2
                    || context.len() > MAXIMUM_SECURITY_CONTEXT_BYTES
                    || context.last() != Some(&0)
                    || context[..context.len() - 1]
                        .iter()
                        .any(|byte| !byte.is_ascii_graphic())
                {
                    return Err(SeqpacketError::Ancillary("inexact SCM_SECURITY context"));
                }
                context.pop();
                security = Some(context);
            }
            other => identity.push(other),
        }
    }
    let security = security.ok_or(SeqpacketError::Ancillary("missing SCM_SECURITY"))?;
    Ok((validate_record_subject(identity)?, security))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_context_is_required_and_has_exact_canonical_boundaries() {
        assert!(matches!(
            validate_stream_subject(Vec::new()),
            Err(SeqpacketError::Ancillary("missing SCM_SECURITY"))
        ));
        for context in [
            b"role".to_vec(),
            b"role\0extra\0".to_vec(),
            b"\0".to_vec(),
            vec![b'a'; 257],
        ] {
            assert!(matches!(
                validate_stream_subject(vec![RawAncillary::SecurityContext(context)]),
                Err(SeqpacketError::Ancillary("inexact SCM_SECURITY context"))
            ));
        }
        assert!(matches!(
            validate_stream_subject(vec![
                RawAncillary::SecurityContext(b"role\0".to_vec()),
                RawAncillary::SecurityContext(b"role\0".to_vec())
            ]),
            Err(SeqpacketError::Ancillary("inexact SCM_SECURITY context"))
        ));
        // A correct socket context never substitutes for process evidence.
        assert!(matches!(
            validate_stream_subject(vec![RawAncillary::SecurityContext(b"role\0".to_vec())]),
            Err(SeqpacketError::Ancillary("missing SCM_CREDENTIALS"))
        ));
    }
}

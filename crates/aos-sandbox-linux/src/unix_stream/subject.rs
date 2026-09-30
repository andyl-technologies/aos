//! Strict kernel-subject evidence for bounded chunks of one original stream.
//!
//! A stream has no record boundaries. Every nonempty returned chunk therefore
//! retains independent credentials, pidfd, and sending **socket** SID; framed
//! protocols must validate every chunk before assembling their exact message.
//! SCM_SECURITY does not identify a delegated descriptor's actual writer.
//! This carrier creates no application-role or live Root authority.

use super::RetainedUnixStream;
use crate::seqpacket::{
    KernelAuthorizedRecordSubject, SeqpacketError, map_kernel_error,
};
use crate::seqpacket::receive_custody::{self, ReceiveAttemptV1, SubjectProfileV1};
use crate::seqpacket::RetainedSeqpacketReceiveErrorV1;
use crate::uapi::{self, RawAncillary};

const MAXIMUM_CHUNK_BYTES: usize = 4096;

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

    /// Receives one strict chunk while retaining partial lower-layer custody.
    ///
    /// Every fatal attempt shuts down this same original socket before staged
    /// ordinary descriptors and subjects can drop. The legacy method above
    /// retains its original poisoning behavior without this shutdown policy.
    ///
    /// # Errors
    /// Returns an opaque owning error for incomplete evidence, changed options,
    /// invalid bounds, subject failure or kernel failure. Only an initial
    /// nonconsuming recvmsg EAGAIN/EINTR permits retry; later errno does not.
    pub fn try_receive_subject_chunk_retaining(
        &mut self, maximum: usize,
    ) -> Result<UnixStreamSubjectChunk, RetainedSeqpacketReceiveErrorV1> {
        let mut result = self.receive_chunk_retaining(maximum);
        if let Err(error) = &mut result {
            if !error.is_nonconsuming_would_block() && !error.is_nonconsuming_interrupted() {
                self.subject_state = StreamSubjectState::Poisoned;
                let failure = rustix::net::shutdown(self.as_fd(), rustix::net::Shutdown::Both)
                    .err().map(std::io::Error::from);
                error.record_shutdown_failure(failure);
            }
        }
        result
    }

    fn receive_chunk_retaining(&self, maximum: usize) -> Result<UnixStreamSubjectChunk, RetainedSeqpacketReceiveErrorV1> {
        if self.subject_state != StreamSubjectState::Ready {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed));
        }
        if maximum == 0 || maximum > MAXIMUM_CHUNK_BYTES {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum));
        }
        let mut attempt = ReceiveAttemptV1::capture(self.as_fd(), self.socket_cookie)?;
        if let Err(source) = uapi::require_stream_subject(self.as_fd()) {
            return Err(attempt.reject(source.into()));
        }
        let actual = match attempt.receive(maximum, 0) {
            Ok(bytes) => bytes,
            Err(failure) => return Err(attempt.syscall_failure(failure)),
        };
        let message = &mut attempt.messages[0];
        let validated = (|| {
            if message.raw.flags & libc::MSG_CTRUNC != 0 {
                return Err(SeqpacketError::Ancillary("stream control data truncated"));
            }
            if message.raw.flags & libc::MSG_TRUNC != 0 || actual > maximum {
                return Err(SeqpacketError::PayloadTruncated);
            }
            if actual == 0 { return Err(SeqpacketError::Closed); }
            message.validate(SubjectProfileV1::Stream, uapi::ReceiveCustodyPolicyV1::Retaining)?;
            // The complete subject is staged before this final option read.
            uapi::require_stream_subject(self.as_fd())?;
            Ok(())
        })();
        if let Err(source) = validated { return Err(attempt.reject(source)); }
        let message = &mut attempt.messages[0];
        if message.subject.is_none() || message.socket_context.is_none() {
            return Err(attempt.reject(SeqpacketError::Ancillary("incomplete stream subject")));
        }
        let Some(subject) = message.subject.take() else {
            return Err(attempt.reject(SeqpacketError::Ancillary("missing SCM_PIDFD")));
        };
        // The shape check above establishes this field without a fallible
        // observation after removing the subject from its guarded staging.
        let socket_context = message.socket_context.take().unwrap_or_default();
        message.payload.truncate(actual);
        let chunk = UnixStreamSubjectChunk {
            payload: std::mem::take(&mut message.payload), subject, socket_context,
        };
        attempt.disarm();
        Ok(chunk)
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
    let (subject, _, context) = receive_custody::validate_legacy(ancillary, SubjectProfileV1::Stream)?;
    Ok((subject, context.ok_or(SeqpacketError::Ancillary("missing SCM_SECURITY"))?))
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

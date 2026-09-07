//! Bounded descriptor replies with independent kernel-authorized record subjects.
//!
//! This is a separate carrier from holder/publisher ingress, which continues to
//! forbid `SCM_RIGHTS`. Each packet here requires one credential message, one
//! kernel-generated subject pidfd, and exactly the caller-selected number of
//! transferred descriptors, bounded to two (or the reply profile's zero/two).
//! A separate privileged mount-scope reply profile permits only zero or five
//! descriptors; it does not widen the controller reply profile. Descriptor
//! roles and application authority are validated by the higher-level protocol.
//!
//! The connection establisher is not authenticated as the response service:
//! socket activation can make that establisher PID 1. Services must instead
//! authenticate and retain the first accepted response subject, then require
//! later response subjects to match that same live service execution.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use super::{
    KernelAuthorizedRecordSubject, SeqpacketError, map_kernel_error, validate_record_subject,
};
use crate::uapi::{self, RawAncillary};

const MAXIMUM_PACKET_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_TRANSFERRED_DESCRIPTORS: usize = 2;

/// Owns a configured nonblocking descriptor-reply channel without service authority.
#[derive(Debug)]
pub struct DescriptorSubjectSocket {
    fd: Option<OwnedFd>,
}

impl DescriptorSubjectSocket {
    /// Adopts a connected Unix sequenced-packet socket and enables subject reporting.
    ///
    /// Call this before sending the first request that can trigger a reply.
    /// Previously queued packets without complete subjects are rejected, never
    /// upgraded into authenticated records. The caller must exclusively own
    /// socket configuration and consumption, including any duplicate descriptors.
    ///
    /// # Errors
    ///
    /// Rejects an incorrect socket type or connection state, or failure to set
    /// close-on-exec, nonblocking, credential, or pidfd-reporting options.
    pub fn from_owned(fd: OwnedFd) -> Result<Self, SeqpacketError> {
        uapi::prepare_seqpacket(fd.as_fd())?;
        uapi::enable_seqpacket_identity(fd.as_fd())?;
        Ok(Self { fd: Some(fd) })
    }

    /// Borrows the channel for readiness polling, not competing packet consumption.
    ///
    /// # Errors
    ///
    /// Rejects a channel closed after a fatal transport error.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, SeqpacketError> {
        self.fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or(SeqpacketError::Closed)
    }

    /// Sends one bounded packet without any transferred descriptors.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized packet, a closed channel, transport errors,
    /// or a short send. Backpressure and interruption are retryable.
    pub fn send(&mut self, payload: &[u8]) -> Result<(), SeqpacketError> {
        if payload.is_empty() || payload.len() > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = uapi::send_seqpacket(self.as_fd()?, payload).map_err(map_kernel_error);
        match result {
            Ok(written) if written == payload.len() => Ok(()),
            Ok(written) => {
                self.fd.take();
                Err(SeqpacketError::PartialSend {
                    expected: payload.len(),
                    actual: written,
                })
            }
            Err(error) => {
                if error.is_fatal() {
                    self.fd.take();
                }
                Err(error)
            }
        }
    }

    /// Receives one bounded packet with an exact descriptor count and kernel subject.
    ///
    /// Preflight peeking validates subject/control data and packet size before
    /// allocating the payload. Its temporary pidfd and descriptor copies close
    /// before the real receive. Consumed records are independently revalidated.
    ///
    /// # Errors
    ///
    /// Rejects a zero or above-two-MiB packet ceiling, a descriptor count above
    /// two, malformed/missing/extra ancillary data, truncation, size drift, EOF,
    /// or kernel errors. Fatal receives close the socket and all adopted FDs;
    /// backpressure and interruption preserve it for readiness-driven retries.
    pub fn receive(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_PACKET_BYTES
            || expected_descriptors > MAXIMUM_TRANSFERRED_DESCRIPTORS
        {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_inner(maximum_bytes, expected_descriptors, false);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.fd.take();
        }
        result
    }

    /// Receives a response with either no descriptors or exactly two descriptors.
    ///
    /// This closed alternative supports descriptor-free protocol errors. The
    /// higher-level decoder must require zero descriptors on errors and exactly
    /// two correctly ordered roles on success. One descriptor is always rejected.
    ///
    /// # Errors
    ///
    /// Returns the same bound, subject, transport, and fatal-close errors as
    /// [`Self::receive`], rejecting every descriptor count except zero and two.
    pub fn receive_reply(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        self.receive_reply_profile(maximum_bytes, 2)
    }

    /// Receives a privileged mount-scope reply with zero or five descriptors.
    ///
    /// The success profile carries a payload pidfd, cgroup, root directory,
    /// mount namespace, and user namespace, in that order. The caller must
    /// authenticate the response subject and validate the protocol's roles,
    /// scope, and authority before using any descriptor. This carrier alone
    /// neither identifies the Host broker nor authorizes namespace entry.
    /// Descriptor-free replies are reserved for protocol errors.
    ///
    /// # Errors
    ///
    /// Returns the same bound, subject, transport, and fatal-close errors as
    /// [`Self::receive`], rejecting every descriptor count except zero and five.
    pub fn receive_mount_scope_reply(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        self.receive_reply_profile(maximum_bytes, 5)
    }

    fn receive_reply_profile(
        &mut self,
        maximum_bytes: usize,
        expected_descriptors: usize,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_PACKET_BYTES {
            return Err(SeqpacketError::InvalidMaximum);
        }
        let result = self.receive_inner(maximum_bytes, expected_descriptors, true);
        if result.as_ref().is_err_and(SeqpacketError::is_fatal) {
            self.fd.take();
        }
        result
    }

    fn receive_inner(
        &self,
        maximum_bytes: usize,
        expected_descriptors: usize,
        allow_empty: bool,
    ) -> Result<ReceivedDescriptorRecord, SeqpacketError> {
        let mut probe = [0_u8; 1];
        let preview =
            uapi::recv_seqpacket(self.as_fd()?, &mut probe, libc::MSG_PEEK | libc::MSG_TRUNC)
                .map_err(map_kernel_error)?;
        if preview.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        drop(validate_ancillary(
            preview.ancillary,
            expected_descriptors,
            allow_empty,
        )?);
        if preview.bytes == 0 {
            return Err(SeqpacketError::EmptyRecord);
        }
        if preview.bytes > maximum_bytes {
            return Err(SeqpacketError::RecordTooLarge {
                actual: preview.bytes,
                maximum: maximum_bytes,
            });
        }

        let mut payload = vec![0_u8; preview.bytes];
        let received =
            uapi::recv_seqpacket(self.as_fd()?, &mut payload, 0).map_err(map_kernel_error)?;
        if received.flags & libc::MSG_CTRUNC != 0 {
            return Err(SeqpacketError::ControlTruncated);
        }
        if received.flags & libc::MSG_TRUNC != 0 {
            return Err(SeqpacketError::PayloadTruncated);
        }
        if received.bytes != preview.bytes {
            return Err(SeqpacketError::LengthChanged {
                previewed: preview.bytes,
                received: received.bytes,
            });
        }
        let (subject, descriptors) =
            validate_ancillary(received.ancillary, expected_descriptors, allow_empty)?;
        Ok(ReceivedDescriptorRecord {
            payload,
            subject,
            descriptors,
        })
    }
}

/// Retains a received record's kernel subject and exact transferred descriptor sequence.
#[derive(Debug)]
pub struct ReceivedDescriptorRecord {
    payload: Vec<u8>,
    subject: KernelAuthorizedRecordSubject,
    descriptors: Vec<OwnedFd>,
}

impl ReceivedDescriptorRecord {
    /// Borrows the packet bytes without asserting application authority.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrows the subject nominated under the writer's kernel credential authority.
    #[must_use]
    pub const fn subject(&self) -> &KernelAuthorizedRecordSubject {
        &self.subject
    }

    /// Borrows transferred descriptors in their original ancillary order.
    #[must_use]
    pub fn descriptors(&self) -> &[OwnedFd] {
        &self.descriptors
    }

    /// Transfers ownership of the packet, subject pin, and descriptor sequence.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, KernelAuthorizedRecordSubject, Vec<OwnedFd>) {
        (self.payload, self.subject, self.descriptors)
    }
}

fn validate_ancillary(
    ancillary: Vec<RawAncillary>,
    expected: usize,
    allow_empty: bool,
) -> Result<(KernelAuthorizedRecordSubject, Vec<OwnedFd>), SeqpacketError> {
    let mut identity = Vec::new();
    let mut descriptors = None;
    for item in ancillary {
        match item {
            RawAncillary::Rights(rights) => {
                if descriptors.is_some() || rights.len() != expected || expected == 0 {
                    return Err(SeqpacketError::Ancillary(
                        "inexact SCM_RIGHTS descriptor table",
                    ));
                }
                descriptors = Some(rights);
            }
            other => identity.push(other),
        }
    }
    let descriptors = descriptors.unwrap_or_default();
    if descriptors.len() != expected && !(allow_empty && descriptors.is_empty()) {
        return Err(SeqpacketError::Ancillary(
            "missing SCM_RIGHTS descriptor table",
        ));
    }
    Ok((validate_record_subject(identity)?, descriptors))
}

#[cfg(test)]
mod tests;

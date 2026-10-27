//! Staged native receive custody for the shared Storage root-export listener.
//!
//! Canary requests carry one sealed job descriptor; launch requests carry none.
//! This carrier permits either table and borrows only the native preview before
//! the caller funds actual payload and model growth. Protocol magic, descriptor
//! role, service identity and all financial authority remain caller checks.

use super::*;
use crate::seqpacket::receive_custody::{consume_packet, preview_packet};

const PREFIX_BYTES: usize = 8;
// The existing one-MiB broker request plus the closed launch framing. This
// carrier limit is not a role, a decoder permit or an execution deadline.
const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024 + 350;
const PROFILE: SubjectProfileV1 = SubjectProfileV1::Descriptors {
    expected: 1,
    allow_empty: true,
};

/// Retains the actual native preview while the same socket remains borrowed.
///
/// Its payload prefix and announced extent are comparison DATA only. A caller
/// must fund the actual consumed payload and decoded models before consuming.
/// An unfinished destructor aborts before releasing native custody; explicit
/// preparation refusal instead returns the whole retained failure to its owner.
pub struct StorageRootExportRequestPreviewV2<'socket> {
    observation: OriginalObservationV1<'socket>,
    attempt: Option<ReceiveAttemptV1>,
    origin: Option<ReceivedSocketOrigin>,
    expected: usize,
}

impl StorageRootExportRequestPreviewV2<'_> {
    /// Returns the kernel-reported length of the still-queued packet.
    #[must_use]
    pub fn previewed_extent_v2(&self) -> usize {
        self.expected
    }

    /// Borrows at most eight captured bytes without decoding a protocol body.
    #[must_use]
    pub fn previewed_prefix_v2(&self) -> &[u8] {
        match self.attempt.as_ref().and_then(|attempt| attempt.messages.first()) {
            Some(message) => &message.payload[..self.expected.min(PREFIX_BYTES)],
            None => &[],
        }
    }

    /// Bounds only the additional actual payload allocation before consumption.
    ///
    /// The separately prepaid preview bound includes both control samples,
    /// endpoint custody and all fixed result carriers. Decoded protocol models
    /// require their own actual-family bound before this method's next stage.
    #[must_use]
    pub fn consumption_receiving_bytes_v2(&self) -> usize {
        self.expected
    }

    /// Consumes and validates that same queued packet through the shared engine.
    ///
    /// # Errors
    /// Retains the actual consumed native prefix, subject and length/truncation
    /// failure. An initial preview has already succeeded, so failures here never
    /// restore a retryable socket epoch.
    pub fn consume_once_v2(mut self) -> Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let Some(attempt) = self.attempt.take() else {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed));
        };
        let mut attempt = consume_packet(attempt, self.expected, PROFILE)?;
        // The caller's next model bound selects a closed protocol branch from
        // these exact preview bytes. Same-length queue substitution must not
        // change that selection before any protocol body is decoded.
        let prefix_length = self.expected.min(PREFIX_BYTES);
        let preview_prefix = attempt.messages.first()
            .and_then(|message| message.payload.get(..prefix_length));
        let consumed_prefix = attempt.messages.get(1)
            .and_then(|message| message.payload.get(..prefix_length));
        if !preview_prefix.zip(consumed_prefix).is_some_and(|(preview, consumed)| preview == consumed) {
            return Err(attempt.reject(SeqpacketError::Ancillary("root-export previewed prefix changed")));
        }
        let Some(origin) = self.origin.take() else {
            return Err(attempt.reject(SeqpacketError::Closed));
        };
        let message = &mut attempt.messages[1];
        let Some(subject) = message.subject.take() else {
            return Err(attempt.reject(SeqpacketError::Ancillary("missing SCM_PIDFD")));
        };
        let record = ReceivedDescriptorRecord::from_parts(
            std::mem::take(&mut message.payload),
            subject,
            message.take_descriptors(),
            origin,
        );
        attempt.disarm();
        self.observation.complete();
        Ok(record)
    }

    /// Retains the preview when the caller's separately owned preparation fails.
    ///
    /// The returned marker does not replace that caller's original financial or
    /// model-bound error. It fences the same endpoint and preserves its actual
    /// preview descriptors and native observations for the enclosing owner.
    #[must_use]
    pub fn refuse_preparation_once_v2(mut self) -> RetainedSeqpacketReceiveErrorV1 {
        match self.attempt.take() {
            Some(attempt) => attempt.reject(SeqpacketError::Ancillary("root-export preparation refused")),
            None => RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::Closed),
        }
    }
}

impl Drop for StorageRootExportRequestPreviewV2<'_> {
    fn drop(&mut self) {
        if self.attempt.is_some() {
            std::process::abort();
        }
    }
}

impl DescriptorSubjectSocket {
    /// Previews a root-export request without allocating its full payload.
    ///
    /// This fixed eighty-byte control recipe permits the existing canary's one
    /// right and the launch request's zero rights. The actual protocol decoder
    /// must enforce its exact table after native consumption; this method grants
    /// no Storage/Host identity, model funding, worker or mount authority.
    ///
    /// # Errors
    /// Retains invalid bounds, actual native/control/subject failures and hostile
    /// truncation prefixes. Only a failed initial nonconsuming syscall can retry.
    pub fn preview_storage_root_export_request_retaining_v2(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<StorageRootExportRequestPreviewV2<'_>, RetainedSeqpacketReceiveErrorV1> {
        let mut observation = OriginalObservationV1::begin(&self.fd, &mut self.retention)
            .map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
        let result = (|| {
            if maximum_bytes == 0 || maximum_bytes > MAXIMUM_REQUEST_BYTES {
                return Err(RetainedSeqpacketReceiveErrorV1::before_receive(SeqpacketError::InvalidMaximum));
            }
            let fd = observation.fd().map_err(RetainedSeqpacketReceiveErrorV1::before_receive)?;
            let attempt = ReceiveAttemptV1::capture_with_control(
                fd, self.peer.socket_cookie(), uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80,
            )?;
            preview_packet(attempt, maximum_bytes, PROFILE, PREFIX_BYTES)
        })();
        match result {
            Ok((attempt, expected)) => Ok(StorageRootExportRequestPreviewV2 {
                observation,
                attempt: Some(attempt),
                origin: Some(self.peer.binding.received_origin()),
                expected,
            }),
            Err(error) => {
                if error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted() {
                    observation.complete();
                }
                Err(error)
            }
        }
    }

    /// Bounds the fixed preview, both control samples and all native carriers.
    ///
    /// The consumed payload and decoded models are excluded and must be prepaid
    /// from the actual previewed extent before consumption. FD custody includes
    /// hostile ancillary slots and the retained preview subject; it never counts
    /// a native error or a Rust field as a resident namespace entry.
    #[must_use]
    pub fn storage_root_export_preview_obligations_v2() -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::OrdinaryAuthenticated80;
        let bytes = super::super::SeqpacketSocket::requested_receive_bytes(0, control, 2)
            .checked_add(PREFIX_BYTES - 1)?
            .checked_add(3 * std::mem::size_of::<StorageRootExportRequestPreviewV2<'_>>())?
            .checked_add(3 * std::mem::size_of::<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>())?;
        let files = control.bytes() / std::mem::size_of::<std::os::fd::RawFd>() + 2 + 2;
        Some((bytes, files))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seqpacket::SeqpacketSocket;
    use std::os::fd::AsFd as _;

    fn pair() -> (DescriptorSubjectSocket, SeqpacketSocket) {
        let (receiver, sender) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        (
            DescriptorSubjectSocket::from_owned_retaining(receiver).unwrap(),
            SeqpacketSocket::from_owned(sender).unwrap(),
        )
    }

    #[test]
    fn preview_lends_actual_extent_before_complete_launch_consumption() {
        let (mut receiver, mut sender) = pair();
        let mut payload = b"AOSRME02".to_vec();
        payload.resize(8192, 19);
        sender.send(&payload).unwrap();

        let preview = receiver.preview_storage_root_export_request_retaining_v2(16_384).unwrap();
        assert_eq!(preview.attempt.as_ref().unwrap().messages.len(), 1);
        assert_eq!(preview.attempt.as_ref().unwrap().messages[0].payload.len(), 8);
        assert_eq!(preview.previewed_extent_v2(), payload.len());
        assert_eq!(preview.previewed_prefix_v2(), b"AOSRME02");
        assert_eq!(preview.consumption_receiving_bytes_v2(), payload.len());
        let record = preview.consume_once_v2().unwrap();

        assert_eq!(record.payload(), payload);
        assert!(record.descriptors().is_empty());
        assert!(record.subject().is_alive().unwrap());
        assert!(receiver.as_fd().is_ok());
    }

    #[test]
    fn canary_one_right_keeps_the_same_complete_native_record() {
        let (mut receiver, sender) = pair();
        let file = std::fs::File::open("/dev/null").unwrap();
        crate::uapi::send_seqpacket_rights(sender.as_fd().unwrap(), b"CANARY01", &[file.as_fd()]).unwrap();

        let preview = receiver.preview_storage_root_export_request_retaining_v2(1024).unwrap();
        let record = preview.consume_once_v2().unwrap();

        assert_eq!(record.payload(), b"CANARY01");
        assert_eq!(record.descriptors().len(), 1);
        assert!(receiver.as_fd().is_ok());
    }

    #[test]
    fn preparation_refusal_keeps_preview_and_fences_same_endpoint() {
        let (mut receiver, mut sender) = pair();
        sender.send(b"AOSRME02later-body").unwrap();
        let preview = receiver.preview_storage_root_export_request_retaining_v2(1024).unwrap();

        let failure = preview.refuse_preparation_once_v2();

        assert!(!failure.is_nonconsuming_would_block());
        assert!(!failure.is_nonconsuming_interrupted());
        assert!(receiver.as_fd().is_err());
        assert!(std::error::Error::source(&failure).is_some());
    }

    #[test]
    fn hostile_rights_keep_native_control_truncation_at_preview() {
        let (mut receiver, sender) = pair();
        let file = std::fs::File::open("/dev/null").unwrap();
        crate::uapi::send_seqpacket_rights(sender.as_fd().unwrap(), b"AOSRME02", &[file.as_fd(); 32]).unwrap();

        let failure = match receiver.preview_storage_root_export_request_retaining_v2(1024) {
            Ok(preview) => { let _ = preview.refuse_preparation_once_v2(); panic!("hostile rights accepted") }
            Err(failure) => failure,
        };

        assert!(matches!(std::error::Error::source(&failure)
            .and_then(|cause| cause.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::ControlTruncated)));
        assert!(receiver.as_fd().is_err());
    }

    #[test]
    fn same_length_queue_substitution_cannot_change_the_paid_model_branch() {
        let (mut receiver, mut sender) = pair();
        let competing = aos_linux_descriptors::native::duplicate_at_least(receiver.as_fd().unwrap(), 0).unwrap();
        let mut competing = SeqpacketSocket::from_owned(competing).unwrap();
        let mut first = b"AOSHCX02".to_vec();
        first.resize(418, 1);
        let mut second = b"AOSRME02".to_vec();
        second.resize(first.len(), 2);
        sender.send(&first).unwrap();
        let preview = receiver.preview_storage_root_export_request_retaining_v2(1024).unwrap();
        assert_eq!(preview.previewed_prefix_v2(), b"AOSHCX02");

        let old_record = competing.receive(1024).unwrap();
        assert_eq!(old_record.payload(), first);
        sender.send(&second).unwrap();
        let failure = preview.consume_once_v2().unwrap_err();

        assert!(matches!(std::error::Error::source(&failure)
            .and_then(|cause| cause.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::Ancillary("root-export previewed prefix changed"))));
        assert!(receiver.as_fd().is_err());
        assert!(!failure.is_nonconsuming_would_block());
    }
}

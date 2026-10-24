//! Retains one fixed worker send on the existing descriptor-subject carrier.
//!
//! The ordinary descriptor sender and this selected receipt share the same
//! native ancillary builder, flags and partial-send classifier. Socket origin
//! and native results are DATA; no worker identity, payment or retry permission
//! follows from this receipt alone.

use super::*;
use super::super::RecordBindingError;
use super::super::socket_binding::ConnectedSocketBinding;
use super::super::storage_session::{
    NativeSeqpacketSendObservationV1,
};

/// Retains an actual descriptor-channel send and both carrier observations.
///
/// Fatal or uncertain sends own the same original endpoint; the caller must
/// also retain its carrier's shutdown result and complete all upper posts.
#[derive(Debug)]
pub struct DescriptorWorkerNativeSendAttemptV1 {
    origin: ConnectedSocketBinding,
    before: Result<(), RecordBindingError>,
    before_native: Option<Result<u64, Error>>,
    native: Option<Result<usize, Error>>,
    framing: Option<SeqpacketError>,
    after: Result<(), RecordBindingError>,
    after_native: Option<Result<u64, Error>>,
    descriptor: Option<OwnedFd>,
}

impl DescriptorWorkerNativeSendAttemptV1 {
    /// Reports a full native send with both original carrier posts positive.
    #[must_use]
    pub fn is_sent(&self) -> bool {
        self.before.is_ok() && self.after.is_ok() && self.framing.is_none()
            && matches!(self.native, Some(Ok(_)))
    }

    /// Identifies only an actual nonconsuming native refusal and positive posts.
    ///
    /// This predicate grants no upper currentness, operation or retry authority.
    #[must_use]
    pub fn is_nonconsuming(&self) -> bool {
        self.before.is_ok() && self.after.is_ok() && self.framing.is_none()
            && self.native.as_ref().is_some_and(|native| match native {
                Err(Error::Syscall { source, .. }) => matches!(source.raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EINTR)),
                _ => false,
            })
    }

    /// Requires the original adopted socket used by this actual native send.
    ///
    /// # Errors
    ///
    /// Refuses a different, closed or no-longer-current socket. Sent state and
    /// positive upper physical completion remain independent requirements.
    pub fn require_same_socket(&self, socket: &DescriptorSubjectSocket)
        -> Result<(), RecordBindingError>
    {
        if self.origin != socket.peer.binding {
            return Err(RecordBindingError::origin_mismatch());
        }
        let fd = socket.fd.as_ref().ok_or_else(RecordBindingError::closed)?;
        self.origin.require_current(fd.as_fd())
    }

    /// Borrows the chronological native or framing refusal without dropping posts.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Err(error) = &self.before {
            return self.before_native.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)).or(Some(error));
        }
        if let Some(Err(error)) = &self.native {
            return Some(error);
        }
        if let Some(error) = &self.framing {
            return Some(error);
        }
        self.after_native.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.after.as_ref().err().map(|error| error as _))
    }

    /// Reports actual endpoint custody after fatal or uncertain native work.
    #[must_use]
    pub fn retains_descriptor(&self) -> bool {
        self.descriptor.is_some()
    }

    /// Prices the actual receipt, construction and bounded native sender frames.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<NativeSeqpacketSendObservationV1>())?
            .checked_add(rustix::cmsg_space!(ScmRights(MAXIMUM_TRANSFERRED_DESCRIPTORS)))?
            .checked_add(std::mem::size_of::<SendAncillaryBuffer<'_, '_, '_>>())?
            .checked_add(std::mem::size_of::<OriginalObservationV1<'_>>())?
            .checked_add(std::mem::size_of::<IoSlice<'_>>())?
            .checked_add(3 * 256)
    }
}

impl DescriptorSubjectSocket {
    /// Sends through the same native engine while retaining its whole receipt.
    ///
    /// The existing plain or zero-to-two-rights framing limits are preserved.
    /// Both actual carrier observations precede any fatal endpoint transfer.
    ///
    /// # Errors
    ///
    /// Returns the original carrier-entry refusal before native send. Once
    /// entered, the returned receipt owns every send failure and later post;
    /// fatal/partial sends cannot lend another IO operation through this socket.
    pub fn send_worker_record_retaining_v1(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError> {
        self.send_worker_record_with_gate_v4::<std::convert::Infallible>(payload, descriptors, None).0
    }

    pub(in crate::seqpacket) fn send_worker_record_with_gate_v4<E>(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
        gate: Option<&mut dyn FnMut() -> Result<(), E>>,
    ) -> (Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>, Option<E>) {
        self.send_worker_record_with_shape_v2::<E, MAXIMUM_TRANSFERRED_DESCRIPTORS,
            { rustix::cmsg_space!(ScmRights(MAXIMUM_TRANSFERRED_DESCRIPTORS)) }>(
                payload, descriptors, gate,
            )
    }

    pub(super) fn send_network_observer_record_with_gate_v2<E>(
        &mut self,
        payload: &[u8],
        descriptors: [BorrowedFd<'_>; 6],
        gate: &mut dyn FnMut() -> Result<(), E>,
    ) -> (Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>, Option<E>) {
        self.send_worker_record_with_shape_v2::<E, 6, { rustix::cmsg_space!(ScmRights(6)) }>(
            payload, &descriptors, Some(gate),
        )
    }

    fn send_worker_record_with_shape_v2<E, const RIGHTS: usize, const CONTROL: usize>(
        &mut self,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
        mut gate: Option<&mut dyn FnMut() -> Result<(), E>>,
    ) -> (Result<DescriptorWorkerNativeSendAttemptV1, SeqpacketError>, Option<E>) {
        let origin = self.peer.binding;
        let mut observation = match OriginalObservationV1::begin(&self.fd, &mut self.retention) {
            Ok(observation) => observation,
            Err(error) => return (Err(error), None),
        };
        let mut gate_failure = None;
        let mut before_native = None;
        let before = observe_binding(origin, &observation, &mut before_native);
        let native = if before.is_ok() {
            let fd = match observation.fd() {
                Ok(fd) => fd,
                Err(error) => return (Err(error), None),
            };
            if payload.is_empty() || payload.len() > MAXIMUM_PACKET_BYTES
                || descriptors.len() > RIGHTS
            {
                NativeSeqpacketSendObservationV1 {
                    native: None,
                    framing: Some(SeqpacketError::InvalidMaximum),
                }
            } else if descriptors.is_empty() {
                let (native, failure) = super::super::storage_session::observe_original_send_with_gate_v3(
                    Some(fd), payload, gate.take(),
                );
                gate_failure = failure;
                native
            } else {
                let (native, failure) = observe_descriptor_send_with_control_v2::<E, CONTROL>(
                    fd, payload, descriptors, gate.take(),
                );
                gate_failure = failure;
                native
            }
        } else {
            NativeSeqpacketSendObservationV1 { native: None, framing: None }
        };
        // Directly borrow the same held FD even after a primary refusal; the
        // ordinary positive accessor would suppress this owed observation.
        let mut after_native = None;
        let after = observe_binding(origin, &observation, &mut after_native);
        let mut receipt = DescriptorWorkerNativeSendAttemptV1 {
            origin, before, before_native, native: native.native, framing: native.framing,
            after, after_native, descriptor: None,
        };
        if receipt.is_sent() || receipt.is_nonconsuming() {
            observation.complete();
        }
        // Failed or unwound observations use the existing retaining shutdown
        // fence before the original FD can move into its failed receipt.
        drop(observation);
        if !receipt.is_sent() && !receipt.is_nonconsuming() {
            receipt.descriptor = self.fd.take();
        }
        (Ok(receipt), gate_failure)
    }
}

fn observe_binding(origin: ConnectedSocketBinding, observation: &OriginalObservationV1<'_>,
    native: &mut Option<Result<u64, Error>>,
)
    -> Result<(), RecordBindingError>
{
    let fd = observation.fd().map_err(|_| RecordBindingError::closed())?;
    origin.require_current_with_originals_v1(fd, Some(native))
}

// Only validated legacy/selected zero-to-two-rights callers enter this shared
// native body. The borrowed rights never change ownership at this boundary.
pub(super) fn observe_descriptor_send_v1(
    fd: BorrowedFd<'_>,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> NativeSeqpacketSendObservationV1 {
    observe_descriptor_send_with_gate_v4::<std::convert::Infallible>(fd, payload, descriptors, None).0
}

fn observe_descriptor_send_with_gate_v4<E>(
    fd: BorrowedFd<'_>,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    gate: Option<&mut dyn FnMut() -> Result<(), E>>,
) -> (NativeSeqpacketSendObservationV1, Option<E>) {
    observe_descriptor_send_with_control_v2::<E,
        { rustix::cmsg_space!(ScmRights(MAXIMUM_TRANSFERRED_DESCRIPTORS)) }>(
            fd, payload, descriptors, gate,
        )
}

fn observe_descriptor_send_with_control_v2<E, const CONTROL: usize>(
    fd: BorrowedFd<'_>,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    gate: Option<&mut dyn FnMut() -> Result<(), E>>,
) -> (NativeSeqpacketSendObservationV1, Option<E>) {
    let mut control_space = [MaybeUninit::uninit(); CONTROL];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return (NativeSeqpacketSendObservationV1 {
            native: None,
            framing: Some(SeqpacketError::Ancillary(
                "SCM_RIGHTS descriptor table exceeded its fixed buffer",
            )),
        }, None);
    }
    if let Some(gate) = gate {
        if let Err(error) = gate() {
            return (NativeSeqpacketSendObservationV1 { native: None, framing: None }, Some(error));
        }
    }
    let native = sendmsg(
        fd,
        &[IoSlice::new(payload)],
        &mut control,
        SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
    ).map_err(|source| Error::Syscall {
        operation: "sendmsg(SCM_RIGHTS)",
        source: source.into(),
    });
    (NativeSeqpacketSendObservationV1::from_native_result_v1(payload.len(), native), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (first, second) = aos_linux_descriptors::native::seqpacket_pair().unwrap();
        (
            DescriptorSubjectSocket::from_owned_retaining(first).unwrap(),
            DescriptorSubjectSocket::from_owned_retaining(second).unwrap(),
        )
    }

    #[test]
    fn actual_two_rights_send_retains_native_count_and_original_binding() {
        let (mut sender, mut receiver) = pair();
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/zero").unwrap();
        let (foreign, _foreign_peer) = pair();

        let receipt = sender.send_worker_record_retaining_v1(
            &[7; 4096], &[first.as_fd(), second.as_fd()],
        ).unwrap();
        let record = receiver.receive_worker_observer_retaining_v1(
            WorkerObserverRecordKindV1::Request,
        ).unwrap();

        assert!(receipt.is_sent());
        assert!(matches!(receipt.native, Some(Ok(4096))));
        assert!(!receipt.is_nonconsuming());
        assert!(!receipt.retains_descriptor());
        receipt.require_same_socket(&sender).unwrap();
        assert!(receipt.require_same_socket(&foreign).is_err());
        assert_eq!(record.payload(), &[7; 4096]);
        assert_eq!(record.descriptors().len(), 2);
        for (received, original) in record.descriptors().iter().zip([&first, &second]) {
            let received = rustix::fs::fstat(received).unwrap();
            let original = rustix::fs::fstat(original).unwrap();
            assert_eq!((received.st_dev, received.st_ino), (original.st_dev, original.st_ino));
        }
    }

    #[test]
    fn disconnected_native_refusal_keeps_endpoint_and_actual_first_error() {
        let (mut sender, peer) = pair();
        drop(peer);

        let receipt = sender.send_worker_record_retaining_v1(&[1], &[]).unwrap();
        let first = receipt.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(!receipt.is_sent());
        assert!(!receipt.is_nonconsuming());
        assert!(receipt.retains_descriptor());
        assert!(matches!(receipt.native, Some(Err(_))));
        assert!(sender.retention.shutdown_attempted);
        assert!(sender.send_worker_record_retaining_v1(&[2], &[]).is_err());
        assert_eq!(receipt.failure().unwrap() as *const dyn std::error::Error as *const (), first);
        assert!(rustix::fs::fstat(receipt.descriptor.as_ref().unwrap()).is_ok());
    }

    #[test]
    fn pin_result_uses_its_existing_larger_fixed_ceiling_without_rights() {
        let (mut sender, mut receiver) = pair();
        sender.send(&[9; 8192]).unwrap();

        let record = receiver.receive_worker_observer_retaining_v1(
            WorkerObserverRecordKindV1::PinResult,
        ).unwrap();

        assert_eq!(record.payload(), &[9; 8192]);
        assert!(record.descriptors().is_empty());
    }
}

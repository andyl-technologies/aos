//! Native send and shutdown observations for a resident Storage Session.
//!
//! These receipts retain native results and carrier binding observations. They
//! grant no Session admission, retry, effect completion, or resource credit.

use std::os::fd::{AsFd, OwnedFd};

use super::{RecordBindingError, SeqpacketError, SeqpacketSocket, map_kernel_error};
use super::socket_binding::ConnectedSocketBinding;
use crate::{Error, uapi};

/// Retains the existing kernel socket binding for passive continuity checks.
///
/// This is DATA captured from an actual adopted socket. It cannot construct a
/// socket, authorize a Session, prove end/drain or fund another operation.
#[derive(Debug)]
pub struct StorageSeqpacketSessionOriginV1(ConnectedSocketBinding);

impl StorageSeqpacketSessionOriginV1 {
    /// Compares the already captured socket identity without a native query.
    ///
    /// This only checks that the original private binding still belongs to an
    /// active Socket owner. It does not prove fresh kernel currentness, peer
    /// liveness, Native disposition, payment, Session or effect authority. A
    /// later genuine IO interval must run its independently paid native checks.
    ///
    /// # Errors
    /// Refuses a closed Socket or a different captured native binding.
    #[doc(hidden)]
    pub fn require_same_socket_data_v4(&self, socket: &SeqpacketSocket) -> Result<(), RecordBindingError> {
        if socket.fd.is_none() { return Err(RecordBindingError::closed()); }
        if self.0 != socket.peer.binding { return Err(RecordBindingError::origin_mismatch()); }
        Ok(())
    }

    /// Retains the actual current-cookie result for this original socket.
    ///
    /// # Errors
    /// Refuses another/closed socket or a changed native binding. The supplied
    /// once destination retains the original kernel error before projection.
    #[doc(hidden)]
    pub fn require_same_socket_retaining_v4(&self, socket: &SeqpacketSocket,
        native: &mut Option<Result<u64, Error>>,
    ) -> Result<(), RecordBindingError> {
        if self.0 != socket.peer.binding { return Err(RecordBindingError::origin_mismatch()); }
        let fd = socket.fd.as_ref().ok_or_else(RecordBindingError::closed)?;
        self.0.require_current_with_originals_v1(fd.as_fd(), Some(native))
    }

    /// Requires the same current adopted socket originally observed here.
    ///
    /// # Errors
    /// Refuses another socket, a closed descriptor or changed kernel binding.
    pub fn require_same_socket(&self, socket: &SeqpacketSocket) -> Result<(), RecordBindingError> {
        if self.0 != socket.peer.binding {
            return Err(RecordBindingError::origin_mismatch());
        }
        socket.storage_session_binding_v1()
    }
}

/// Retains one actual no-descriptor send and its independent carrier checks.
///
/// A fatal or uncertain result also owns the original socket descriptor. Only
/// full sends and kernel-classified nonconsuming interruption/backpressure leave
/// the same socket active; the upper owner must still complete all its posts.
#[derive(Debug)]
pub struct StorageSeqpacketSendAttemptV1 {
    origin: StorageSeqpacketSessionOriginV1,
    before: Result<(), RecordBindingError>,
    before_cookie: Option<Result<u64, Error>>,
    native: Option<Result<usize, Error>>,
    framing: Option<SeqpacketError>,
    after: Result<(), RecordBindingError>,
    after_cookie: Option<Result<u64, Error>>,
    descriptor: Option<OwnedFd>,
}

impl StorageSeqpacketSendAttemptV1 {
    /// Requires the same current socket used by this actual send attempt.
    ///
    /// # Errors
    /// Refuses another or no-longer-current socket. Positive native send,
    /// terminal closure and all upper posts remain separate requirements.
    pub fn require_same_socket(&self, socket: &SeqpacketSocket) -> Result<(), RecordBindingError> {
        self.origin.require_same_socket(socket)
    }

    /// Retains the actual same-socket current-cookie observation for this send.
    ///
    /// # Errors
    /// Preserves the original kernel result in the once destination and
    /// refuses a foreign, closed or changed carrier. Sent remains separate.
    #[doc(hidden)]
    pub fn require_same_socket_retaining_v4(&self, socket: &SeqpacketSocket,
        native: &mut Option<Result<u64, Error>>,
    ) -> Result<(), RecordBindingError> {
        self.origin.require_same_socket_retaining_v4(socket, native)
    }

    /// Reports a full native send with both carrier observations positive.
    #[must_use]
    pub fn is_sent(&self) -> bool {
        self.before.is_ok()
            && self.after.is_ok()
            && self.framing.is_none()
            && matches!(self.native, Some(Ok(_)))
    }

    /// Reports an actual nonconsuming native refusal with positive carrier posts.
    ///
    /// This establishes no upper currentness or retry permission. Partial sends,
    /// uncertain native errors and changed carriers never satisfy this predicate.
    #[must_use]
    pub fn is_nonconsuming(&self) -> bool {
        self.before.is_ok()
            && self.after.is_ok()
            && self.framing.is_none()
            && self.native.as_ref().is_some_and(|result| match result {
                Err(Error::Syscall { source, .. }) => {
                    matches!(source.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR))
                }
                _ => false,
            })
    }

    /// Borrows the earliest actual refusal without discarding later observations.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Err(error) = &self.before {
            return Some(self.before_cookie.as_ref().and_then(|result| result.as_ref().err())
                .map_or(error as &(dyn std::error::Error + 'static), |cause| cause));
        }

        if let Some(Err(error)) = &self.native {
            return Some(error);
        }

        if let Some(error) = &self.framing {
            return Some(error);
        }

        self.after.as_ref().err().map(|error| {
            self.after_cookie.as_ref().and_then(|result| result.as_ref().err())
                .map_or(error as &(dyn std::error::Error + 'static), |cause| cause)
        })
    }

    /// Reports custody of a socket fenced by this failed native attempt.
    #[must_use]
    pub fn retains_descriptor(&self) -> bool {
        self.descriptor.is_some()
    }
}

/// Retains a shutdown attempt while its original socket remains in its owner.
///
/// Positive completion means only shutdown of this local transport and unchanged
/// socket identity. Peer process death, physical-effect drain and resource reuse
/// require their own actual owners and observations.
#[derive(Debug)]
pub struct StorageSeqpacketEndAttemptV1 {
    origin: StorageSeqpacketSessionOriginV1,
    observation: NativeSocketEndingV1,
}

/// Retains an actual local Ownership shutdown and its original carrier checks.
///
/// This observes only local transport ending. It grants no lease completion,
/// peer death, service admission or financial reuse.
#[derive(Debug)]
pub struct LocalOwnershipSeqpacketEndAttemptV1 {
    binding: ConnectedSocketBinding,
    observation: NativeSocketEndingV1,
}

impl LocalOwnershipSeqpacketEndAttemptV1 {
    /// Requires the same current socket observed by this actual shutdown.
    ///
    /// # Errors
    /// Refuses a different, closed or changed original socket.
    pub fn require_same_socket(&self, socket: &SeqpacketSocket) -> Result<(), RecordBindingError> {
        if self.binding != socket.peer.binding {
            return Err(RecordBindingError::origin_mismatch());
        }
        socket.storage_session_binding_v1()
    }

    /// Reports successful local shutdown with both carrier checks positive.
    #[must_use]
    pub fn is_complete(&self) -> bool { self.observation.is_complete() }

    /// Borrows the first original native refusal while retaining later checks.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> { self.observation.failure() }
}

#[derive(Debug)]
struct NativeSocketEndingV1 {
    before: Result<(), RecordBindingError>,
    native: Option<Result<(), rustix::io::Errno>>,
    after: Result<(), RecordBindingError>,
}

impl NativeSocketEndingV1 {
    fn observe(socket: &SeqpacketSocket) -> Self {
        let before = socket.storage_session_binding_v1();
        let native = if before.is_ok() {
            socket.fd.as_ref().map(|fd| rustix::net::shutdown(fd, rustix::net::Shutdown::Both))
        } else {
            None
        };
        let after = socket.storage_session_binding_v1();
        Self { before, native, after }
    }

    fn is_complete(&self) -> bool {
        self.before.is_ok() && matches!(self.native, Some(Ok(()))) && self.after.is_ok()
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Err(error) = &self.before { return Some(error); }
        if let Some(Err(error)) = &self.native { return Some(error); }
        self.after.as_ref().err().map(|error| error as &dyn std::error::Error)
    }
}

impl StorageSeqpacketEndAttemptV1 {
    /// Requires the actual original socket used by this shutdown attempt.
    ///
    /// # Errors
    /// Refuses a different or no-longer-current socket. This comparison grants
    /// no completion; the actual end and all upper posts must also be positive.
    pub fn require_same_socket(&self, socket: &SeqpacketSocket) -> Result<(), RecordBindingError> {
        self.origin.require_same_socket(socket)
    }

    /// Reports successful shutdown and both positive socket observations.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.observation.is_complete()
    }

    /// Borrows the earliest actual refusal, retaining the other observations.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.observation.failure()
    }
}

/// Observes native framing without choosing descriptor disposal or retry.
pub(super) struct NativeSeqpacketSendObservationV1 {
    pub(super) native: Option<Result<usize, Error>>,
    pub(super) framing: Option<SeqpacketError>,
}

impl NativeSeqpacketSendObservationV1 {
    pub(super) fn from_native_result_v1(expected: usize, native: Result<usize, Error>) -> Self {
        let framing = match &native {
            Ok(actual) if *actual != expected => Some(SeqpacketError::PartialSend {
                expected,
                actual: *actual,
            }),
            _ => None,
        };
        Self { native: Some(native), framing }
    }

    pub(super) fn into_legacy_result(self) -> Result<(), SeqpacketError> {
        if let Some(error) = self.framing {
            return Err(error);
        }
        match self.native {
            Some(Ok(_)) => Ok(()),
            Some(Err(error)) => Err(map_kernel_error(error)),
            None => Err(SeqpacketError::Closed),
        }
    }
}

pub(super) fn observe_original_send_v1(
    fd: Option<std::os::fd::BorrowedFd<'_>>,
    packet: &[u8],
) -> NativeSeqpacketSendObservationV1 {
    observe_original_send_with_gate_v3::<std::convert::Infallible>(fd, packet, None).0
}

// The optional callback belongs immediately before the syscall, after framing
// and carrier checks. Ordinary and retained callers use this one native sender.
pub(super) fn observe_original_send_with_gate_v3<E>(
    fd: Option<std::os::fd::BorrowedFd<'_>>,
    packet: &[u8],
    gate: Option<&mut dyn FnMut() -> Result<(), E>>,
) -> (NativeSeqpacketSendObservationV1, Option<E>) {
    if packet.is_empty() {
        return (NativeSeqpacketSendObservationV1 {
            native: None,
            framing: Some(SeqpacketError::EmptyRecord),
        }, None);
    }
    let Some(fd) = fd else {
        return (NativeSeqpacketSendObservationV1 {
            native: None,
            framing: Some(SeqpacketError::Closed),
        }, None);
    };

    if let Some(gate) = gate {
        if let Err(error) = gate() {
            return (NativeSeqpacketSendObservationV1 { native: None, framing: None }, Some(error));
        }
    }

    (NativeSeqpacketSendObservationV1::from_native_result_v1(
        packet.len(), uapi::send_seqpacket(fd, packet),
    ), None)
}

// This is the sole existing SCM_RIGHTS syscall/framing engine. Ordinary
// callers immediately project its same result; selected callers retain it.
pub(super) fn observe_original_descriptor_send_v4<E>(
    fd: Option<std::os::fd::BorrowedFd<'_>>, packet: &[u8],
    descriptors: &[std::os::fd::BorrowedFd<'_>],
    gate: Option<&mut dyn FnMut() -> Result<(), E>>,
) -> (NativeSeqpacketSendObservationV1, Option<E>) {
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

    if packet.is_empty() || descriptors.is_empty() || descriptors.len() > 5 {
        return (NativeSeqpacketSendObservationV1 {
            native: None, framing: Some(SeqpacketError::InvalidMaximum),
        }, None);
    }
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return (NativeSeqpacketSendObservationV1 { native: None,
            framing: Some(SeqpacketError::Ancillary(
                "SCM_RIGHTS descriptor table exceeded its fixed buffer")),
        }, None);
    }
    let Some(fd) = fd else {
        return (NativeSeqpacketSendObservationV1 {
            native: None, framing: Some(SeqpacketError::Closed),
        }, None);
    };
    if let Some(gate) = gate {
        if let Err(error) = gate() {
            return (NativeSeqpacketSendObservationV1 { native: None, framing: None }, Some(error));
        }
    }
    let native = sendmsg(fd, &[IoSlice::new(packet)], &mut control,
        SendFlags::DONTWAIT | SendFlags::NOSIGNAL).map_err(|source| Error::Syscall {
            operation: "sendmsg(SCM_RIGHTS)", source: source.into(),
        });
    (NativeSeqpacketSendObservationV1::from_native_result_v1(packet.len(), native), None)
}

impl SeqpacketSocket {
    /// Captures passive continuity DATA from this actual current socket.
    ///
    /// # Errors
    /// Refuses a closed socket or changed adoption-time kernel binding.
    pub fn capture_storage_session_origin_v1(&self) -> Result<StorageSeqpacketSessionOriginV1, RecordBindingError> {
        self.storage_session_binding_v1()?;
        Ok(StorageSeqpacketSessionOriginV1(self.peer.binding))
    }

    /// Captures the same actual origin while retaining its native cookie result.
    ///
    /// # Errors
    /// Refuses a closed/changed socket or repeated once destination. The actual
    /// kernel result remains owned before its binding-error projection.
    #[doc(hidden)]
    pub fn capture_storage_session_origin_retaining_v4(&self,
        native: &mut Option<Result<u64, Error>>,
    ) -> Result<StorageSeqpacketSessionOriginV1, RecordBindingError> {
        let origin = StorageSeqpacketSessionOriginV1(self.peer.binding);
        origin.require_same_socket_retaining_v4(self, native)?;
        Ok(origin)
    }

    /// Sends one Storage response while retaining the complete native result.
    ///
    /// The existing atomic sender and flags are reused. No-descriptor framing
    /// remains unchanged. Every reached post runs even after native refusal;
    /// fatal/partial custody is fenced before the receipt returns.
    #[must_use]
    pub fn send_storage_session_retaining_v1(&mut self, packet: &[u8]) -> StorageSeqpacketSendAttemptV1 {
        self.send_session_retaining_engine_v3::<std::convert::Infallible>(packet, None).0
    }

    /// Sends one Network preparation packet with its same owned sealed content.
    ///
    /// This is transport only. The actual Session and Start loan separately
    /// authenticate the request and borrow this descriptor from its Prepared
    /// owner. The same retained sender and all native binding posts apply.
    #[must_use]
    pub fn send_network_preparation_retaining_v4(
        &mut self, packet: &[u8], content: std::os::fd::BorrowedFd<'_>,
    ) -> StorageSeqpacketSendAttemptV1 {
        self.send_session_retaining_engine_v4::<std::convert::Infallible>(
            packet, Some(&[content]), None).0
    }

    /// Sends a closed two-pipe worker reply through the sole retained sender.
    ///
    /// The caller retains both original rights. Every reached carrier post
    /// runs after native failure; uncertain sends fence the same socket in the
    /// returned receipt. This mechanical adapter grants no worker authority.
    #[must_use]
    pub fn send_capture_worker_pipes_retaining_v3(
        &mut self, packet: &[u8], pipes: [std::os::fd::BorrowedFd<'_>; 2],
    ) -> StorageSeqpacketSendAttemptV1 {
        self.send_session_retaining_engine_v4::<std::convert::Infallible>(
            packet, Some(&pipes), None,
        ).0
    }

    /// Sends an Agent handshake with a final callback at the native boundary.
    ///
    /// The callback runs after the original socket's leading binding check and
    /// immediately before each actual send syscall. Its returned error is moved
    /// back to the caller alongside the receipt, after the independent trailing
    /// binding check. Failure fences the same socket in that receipt; it does
    /// not authorize a retry or establish any upper completion.
    #[must_use]
    pub fn send_agent_handshake_retaining_v3<E>(
        &mut self,
        packet: &[u8],
        before_native_write: &mut dyn FnMut() -> Result<(), E>,
    ) -> (StorageSeqpacketSendAttemptV1, Option<E>) {
        self.send_session_retaining_engine_v3(packet, Some(before_native_write))
    }

    fn send_session_retaining_engine_v3<E>(
        &mut self,
        packet: &[u8],
        gate: Option<&mut dyn FnMut() -> Result<(), E>>,
    ) -> (StorageSeqpacketSendAttemptV1, Option<E>) {
        self.send_session_retaining_engine_v4(packet, None, gate)
    }

    /// Sends an actual Agent effect packet through the same retained native sender.
    ///
    /// The optional descriptor table is borrowed from the caller's real owning
    /// spec/pipe capsule. The callback is a final denial gate, not permission.
    /// Every reached carrier post is owed even after native or gate refusal;
    /// uncertain/fatal custody retains the SAME socket in the returned receipt.
    #[must_use]
    pub fn send_agent_effect_retaining_v4<E>(
        &mut self, packet: &[u8], descriptors: Option<&[std::os::fd::BorrowedFd<'_>]>,
        before_native_write: &mut dyn FnMut() -> Result<(), E>,
    ) -> (StorageSeqpacketSendAttemptV1, Option<E>) {
        self.send_session_retaining_engine_v4(packet, descriptors, Some(before_native_write))
    }

    /// Prices the fixed owning result and SCM_RIGHTS preparation carriers.
    ///
    /// This creates no socket, descriptor, receiving capacity or retry grant.
    #[must_use]
    pub fn agent_effect_send_receiving_bytes_v4() -> Option<usize> {
        std::mem::size_of::<StorageSeqpacketSendAttemptV1>().checked_mul(2)?
            .checked_add(std::mem::size_of::<NativeSeqpacketSendObservationV1>().checked_mul(2)?)?
            .checked_add(rustix::cmsg_space!(ScmRights(5)))
    }

    /// Prices the same retained one-descriptor Network sender's actual carriers.
    ///
    /// This passive bound creates no transport, descriptor or permission.
    #[must_use]
    pub fn network_preparation_send_receiving_bytes_v4() -> Option<usize> {
        Self::agent_effect_send_receiving_bytes_v4()
    }

    fn send_session_retaining_engine_v4<E>(
        &mut self, packet: &[u8], descriptors: Option<&[std::os::fd::BorrowedFd<'_>]>,
        gate: Option<&mut dyn FnMut() -> Result<(), E>>,
    ) -> (StorageSeqpacketSendAttemptV1, Option<E>) {
        let mut before_cookie = None;
        let before = self.storage_session_binding_retaining_v3(&mut before_cookie);
        let (observation, gate_failure) = if before.is_ok() {
            match descriptors {
                Some(descriptors) => observe_original_descriptor_send_v4(
                    self.fd.as_ref().map(AsFd::as_fd), packet, descriptors, gate),
                None => observe_original_send_with_gate_v3(self.fd.as_ref().map(AsFd::as_fd), packet, gate),
            }
        } else {
            (NativeSeqpacketSendObservationV1 { native: None, framing: None }, None)
        };

        // This post is independently owed even when the clock callback or send
        // refused. Keep its original native cookie Result before projection.
        let mut after_cookie = None;
        let after = self.storage_session_binding_retaining_v3(&mut after_cookie);
        let mut receipt = StorageSeqpacketSendAttemptV1 {
            origin: StorageSeqpacketSessionOriginV1(self.peer.binding),
            before, before_cookie,
            native: observation.native,
            framing: observation.framing,
            after, after_cookie,
            descriptor: None,
        };
        if !receipt.is_sent() && !receipt.is_nonconsuming() {
            receipt.descriptor = self.fd.take();
        }
        (receipt, gate_failure)
    }

    fn storage_session_binding_retaining_v3(
        &self,
        original: &mut Option<Result<u64, Error>>,
    ) -> Result<(), RecordBindingError> {
        let fd = self.fd.as_ref().ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current_with_originals_v1(fd.as_fd(), Some(original))
    }

    /// Shuts down this resident Storage transport without disposing its socket.
    ///
    /// The caller keeps this socket and the returned receipt through all upper
    /// currentness and same-Journal posts. Repeated shutdown is not a positive
    /// Session disposition; the upper retirement owner enforces one attempt.
    #[must_use]
    pub fn end_storage_session_retaining_v1(&mut self) -> StorageSeqpacketEndAttemptV1 {
        let observation = NativeSocketEndingV1::observe(self);
        StorageSeqpacketEndAttemptV1 {
            origin: StorageSeqpacketSessionOriginV1(self.peer.binding),
            observation,
        }
    }

    /// Shuts down the resident local Ownership socket without disposing it.
    ///
    /// The owning paid operation must retain this actual receipt and socket
    /// through all independent posts. Reentry or financial reuse is a separate
    /// decision of that same original; this receipt cannot establish either.
    #[must_use]
    pub fn end_local_ownership_session_retaining_v1(&mut self) -> LocalOwnershipSeqpacketEndAttemptV1 {
        let observation = NativeSocketEndingV1::observe(self);
        LocalOwnershipSeqpacketEndAttemptV1 { binding: self.peer.binding, observation }
    }

    fn storage_session_binding_v1(&self) -> Result<(), RecordBindingError> {
        let fd = self.fd.as_ref().ok_or_else(RecordBindingError::closed)?;
        self.peer.binding.require_current(fd.as_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SeqpacketSocket, OwnedFd) {
        SeqpacketSocket::pair_with_record_subjects().expect("actual subject socket pair")
    }

    #[test]
    fn retained_origin_comparison_keeps_the_actual_cookie_syscall_error() {
        let (mut socket, _peer) = pair();
        let origin = socket.capture_storage_session_origin_v1().unwrap();
        let replacement = std::fs::File::open("/dev/null").unwrap();
        let _original_socket = socket.fd.replace(replacement.into());
        let mut native = None;

        assert!(origin.require_same_socket_retaining_v4(&socket, &mut native).is_err());

        let error = native.as_ref().unwrap().as_ref().unwrap_err();
        assert!(matches!(error, Error::Syscall { .. }));
        assert!(std::error::Error::source(error).is_some());
    }

    #[test]
    fn passive_origin_comparison_uses_no_current_socket_query() {
        let (socket, _peer) = pair();
        let (foreign, _foreign_peer) = pair();
        let origin = socket.capture_storage_session_origin_v1().unwrap();
        super::super::socket_binding::reset_current_query_count();

        assert!(origin.require_same_socket_data_v4(&socket).is_ok());
        assert!(origin.require_same_socket_data_v4(&foreign).is_err());

        assert_eq!(super::super::socket_binding::current_query_count(), 0);
    }

    #[test]
    fn full_send_preserves_native_count_and_same_socket() {
        let (mut sender, peer) = pair();
        let cookie = sender.peer().socket_cookie();

        let sent = sender.send_storage_session_retaining_v1(b"terminal");

        assert!(sent.is_sent());
        assert!(matches!(sent.native, Some(Ok(8))));
        assert!(!sent.retains_descriptor());
        assert_eq!(sender.peer().socket_cookie(), cookie);
        assert!(sent.require_same_socket(&sender).is_ok());
        let (other, _other_peer) = pair();
        assert!(sent.require_same_socket(&other).is_err());
        let mut bytes = [0; 8];
        let received = uapi::recv_seqpacket(peer.as_fd(), &mut bytes, 0).expect("receive actual packet");
        assert_eq!(received.bytes, 8);
        assert_eq!(&bytes, b"terminal");
    }

    #[test]
    fn real_backpressure_preserves_actual_errno_and_retry_carrier() {
        let (mut sender, peer) = pair();
        rustix::net::sockopt::set_socket_send_buffer_size(sender.as_fd().expect("sender"), 4096)
            .expect("bound actual send queue");
        let packet = [7; 1024];
        let mut attempts = 0;
        let refused = loop {
            attempts += 1;
            assert!(attempts <= 64, "bounded queue must refuse without a reader");
            let sent = sender.send_storage_session_retaining_v1(&packet);
            if !sent.is_sent() {
                break sent;
            }
        };

        assert!(refused.is_nonconsuming());
        assert!(matches!(refused.native.as_ref(), Some(Err(Error::Syscall { source, .. }))
            if source.raw_os_error() == Some(libc::EAGAIN)));
        assert!(sender.as_fd().is_ok());
        let mut bytes = [0; 1024];
        while uapi::recv_seqpacket(peer.as_fd(), &mut bytes, libc::MSG_DONTWAIT).is_ok() {}
        assert!(sender.send_storage_session_retaining_v1(&packet).is_sent());
    }

    #[test]
    fn fatal_native_send_retains_endpoint_and_exact_errno() {
        let (mut sender, peer) = pair();
        drop(peer);

        let refused = sender.send_storage_session_retaining_v1(b"terminal");

        assert!(!refused.is_sent());
        assert!(!refused.is_nonconsuming());
        assert!(refused.retains_descriptor());
        assert!(matches!(refused.native, Some(Err(Error::Syscall { .. }))));
        assert!(sender.as_fd().is_err());
        assert!(refused.after.is_ok());
    }

    #[test]
    fn refused_agent_gate_retains_same_endpoint_and_both_cookie_samples() {
        let (mut sender, peer) = pair();
        let raw = std::os::fd::AsRawFd::as_raw_fd(&sender.as_fd().expect("actual sender"));
        let mut called = 0;
        let mut gate = || {
            called += 1;
            Err(std::io::Error::from_raw_os_error(libc::ETIME))
        };

        let (refused, gate_failure) = sender.send_agent_handshake_retaining_v3(b"handshake", &mut gate);

        assert_eq!(called, 1);
        assert_eq!(gate_failure.as_ref().and_then(std::io::Error::raw_os_error), Some(libc::ETIME));
        assert!(refused.native.is_none());
        assert!(refused.before.is_ok() && refused.after.is_ok());
        assert!(matches!(refused.before_cookie, Some(Ok(_))));
        assert!(matches!(refused.after_cookie, Some(Ok(_))));
        assert!(refused.retains_descriptor());
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(refused.descriptor.as_ref().expect("same original")), raw);
        assert!(sender.as_fd().is_err());
        let mut bytes = [0; 32];
        assert!(matches!(uapi::recv_seqpacket(peer.as_fd(), &mut bytes, libc::MSG_DONTWAIT),
            Err(Error::Syscall { source, .. }) if source.raw_os_error() == Some(libc::EAGAIN)));
    }

    #[test]
    fn failed_agent_native_send_keeps_original_socket_and_cause() {
        let (mut sender, peer) = pair();
        let raw = std::os::fd::AsRawFd::as_raw_fd(&sender.as_fd().expect("actual sender"));
        drop(peer);
        let mut gate = || Ok::<(), std::convert::Infallible>(());

        let (refused, gate_failure) = sender.send_agent_handshake_retaining_v3(b"handshake", &mut gate);

        assert!(gate_failure.is_none());
        assert!(!refused.is_sent() && !refused.is_nonconsuming());
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(refused.descriptor.as_ref().expect("same original")), raw);
        let native = refused.native.as_ref().expect("entered send").as_ref().expect_err("peer closed");
        assert!(std::ptr::eq(refused.failure().expect("same first cause").downcast_ref::<Error>().expect("native cause"), native));
        assert!(refused.after.is_ok());
        assert!(sender.as_fd().is_err());
    }

    #[test]
    fn network_preparation_sender_keeps_the_borrowed_descriptor_and_native_receipt() {
        let (mut sender, peer) = pair();
        let mut receiver = SeqpacketSocket::from_owned(peer).unwrap();
        let (read, _write) = rustix::pipe::pipe().unwrap();

        let sent = sender.send_network_preparation_retaining_v4(b"network", read.as_fd());

        assert!(sent.is_sent());
        assert!(sent.before.is_ok() && sent.after.is_ok());
        assert!(sent.require_same_socket(&sender).is_ok());
        let record = receiver.receive_with_descriptors(64, 1).unwrap();
        assert_eq!(record.payload(), b"network");
        assert_eq!(record.descriptors().len(), 1);
        assert!(rustix::fs::fstat(&read).is_ok());
    }

    #[test]
    fn effect_sender_preserves_one_and_three_descriptor_native_sends() {
        for descriptor_count in [1, 3] {
            let (mut sender, peer) = pair();
            let mut receiver = SeqpacketSocket::from_owned(peer).unwrap();
            let (read, write) = rustix::pipe::pipe().unwrap();
            let descriptors = [read.as_fd(), write.as_fd(), read.as_fd()];
            let mut called = 0;
            let mut gate = || { called += 1; Ok::<(), std::convert::Infallible>(()) };

            let (sent, refusal) = sender.send_agent_effect_retaining_v4(
                b"effect", Some(&descriptors[..descriptor_count]), &mut gate);

            assert_eq!(called, 1);
            assert!(refusal.is_none());
            assert!(sent.is_sent());
            assert!(matches!(sent.native, Some(Ok(6))));
            assert!(sent.before.is_ok() && sent.after.is_ok());
            assert!(sent.require_same_socket(&sender).is_ok());
            let record = receiver.receive_with_descriptors(64, descriptor_count).unwrap();
            assert_eq!(record.payload(), b"effect");
            assert_eq!(record.descriptors().len(), descriptor_count);
        }
    }

    #[test]
    fn effect_descriptor_native_failure_retains_socket_and_syscall_cause() {
        let (mut sender, peer) = pair();
        let raw = std::os::fd::AsRawFd::as_raw_fd(&sender.as_fd().unwrap());
        let (read, _write) = rustix::pipe::pipe().unwrap();
        drop(peer);
        let mut gate = || Ok::<(), std::convert::Infallible>(());

        let (refused, gate_failure) = sender.send_agent_effect_retaining_v4(
            b"effect", Some(&[read.as_fd()]), &mut gate);

        assert!(gate_failure.is_none());
        assert!(!refused.is_sent() && !refused.is_nonconsuming());
        assert!(refused.before.is_ok() && refused.after.is_ok());
        assert_eq!(std::os::fd::AsRawFd::as_raw_fd(refused.descriptor.as_ref().unwrap()), raw);
        let native = refused.native.as_ref().unwrap().as_ref().unwrap_err();
        assert!(matches!(native, Error::Syscall { operation: "sendmsg(SCM_RIGHTS)", .. }));
        assert!(std::ptr::eq(refused.failure().unwrap().downcast_ref::<Error>().unwrap(), native));
        assert!(sender.as_fd().is_err());
    }

    #[test]
    fn shutdown_keeps_original_socket_through_upper_posts() {
        let (mut sender, _peer) = pair();
        let cookie = sender.peer().socket_cookie();
        let origin = sender.capture_storage_session_origin_v1().expect("actual entry socket");

        let ended = sender.end_storage_session_retaining_v1();

        assert!(ended.is_complete());
        assert!(ended.failure().is_none());
        assert!(sender.as_fd().is_ok());
        assert_eq!(sender.peer().socket_cookie(), cookie);
        assert!(ended.require_same_socket(&sender).is_ok());
        assert!(origin.require_same_socket(&sender).is_ok());
        let (other, _other_peer) = pair();
        assert!(ended.require_same_socket(&other).is_err());
        assert!(origin.require_same_socket(&other).is_err());
        let refused = sender.send_storage_session_retaining_v1(b"after shutdown");
        assert!(!refused.is_sent());
        assert!(!refused.is_nonconsuming());
        assert!(refused.retains_descriptor());
    }
}

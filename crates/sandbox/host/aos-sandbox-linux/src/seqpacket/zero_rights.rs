//! Owns the actual pre-exposure zero-rights socket mode and native restore.
//!
//! SO_PASSRIGHTS prevents a descriptor-bearing message from entering the
//! receiver queue. Kernel credentials and PIDFD reporting remain unchanged.
//! Setup is native mechanics; genuine purpose admission remains at its caller.

use super::*;

#[derive(Debug)]
pub(super) struct ZeroRightsNativeV1 {
    pub(super) epoch: u64,
    pub(super) restore: Option<Result<(), SeqpacketError>>,
}

impl SeqpacketSocket {
    /// Connects a closed zero-rights interval before exposing the socket.
    ///
    /// Linux rejects rights-bearing sends before queueing them. Record
    /// credentials and kernel pidfd reporting retain their existing setup.
    ///
    /// # Errors
    /// Retains every created socket and the actual unsupported/setup/peer error.
    pub fn connect_zero_rights_retaining_v1(path: &Path) -> Result<Self, RetainedSeqpacketAdmissionErrorV1> {
        Self::require_connection_path(path)
            .map_err(RetainedSeqpacketAdmissionErrorV1::before_creation)?;
        let pending = connect_pending_with_rights(path, true)?;
        let mut socket = Self::from_pending_raw_peer_retaining_v1(pending)?;
        socket.zero_rights = Some(ZeroRightsNativeV1 { restore: None, epoch: 0 });
        Ok(socket)
    }

    /// Restores descriptor admission once before publishing the real Session.
    ///
    /// This native mode transition grants no Session or semantic completion.
    /// The actual caller retains this owner and performs its absolute cutoff.
    ///
    /// # Errors
    /// Retains the original restore error; reentry or absent setup stays closed.
    pub fn restore_rights_once_v1(&mut self) -> Result<(), SeqpacketError> {
        if self.zero_rights.as_ref().is_none_or(|original| original.restore.is_some()) {
            return Err(SeqpacketError::Closed);
        }
        let result = self.borrow_fd().and_then(|fd| uapi::set_seqpacket_passrights(fd, true).map_err(SeqpacketError::from));
        // Native setup failures remain in the actual socket owner; the return
        // is only the existing stopping class, never a cloned native cause.
        let original = self.zero_rights.as_mut().ok_or(SeqpacketError::Closed)?;
        original.restore = Some(result);
        if matches!(original.restore, Some(Ok(()))) { Ok(()) } else { Err(SeqpacketError::Closed) }
    }

    /// Borrows the actual retained native restore refusal.
    pub fn zero_rights_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.zero_rights.as_ref()?.restore.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    /// Reports receive DATA only for this actual un-restored native mode.
    ///
    /// This readonly borrower grants no role or native receive. The setup was
    /// completed before exposure and every selected receive rechecks it.
    pub fn zero_rights_receive_obligations_v1(&self, maximum: usize) -> Option<(usize, usize)> {
        if self.fd.is_none() || self.zero_rights.as_ref()?.restore.is_some() { return None; }
        Self::closed_zero_rights_receive_obligations_v1(maximum)
    }

    /// Supplies the closed pre-exposure zero-rights recipe's receive peak DATA.
    ///
    /// Actual constructors must disable SO_PASSRIGHTS before peer exposure.
    /// The unchanged 80-byte buffers and parser remain fully byte provisioned;
    /// two kernel pidfd samples and the original endpoint duplicate need3FDs.
    pub fn closed_zero_rights_receive_obligations_v1(maximum: usize) -> Option<(usize, usize)> {
        let (bytes, _) = Self::ordinary_authenticated_receive_obligations_v1(maximum)?;
        Some((bytes, 3))
    }

}


/// Retains one irreversible receive-rights restriction and its queue check.
///
/// The caller pays this finite native recipe before entry. The nonconsuming
/// peek has no ancillary buffer, so it cannot install SCM_RIGHTS or PIDFDs.
/// A queued packet, EOF, or any ambiguity stays owned and blocks completion.
/// This mechanical owner confers no application permission.
#[derive(Debug)]
pub struct SeqpacketRightsRestrictionOriginalV6 {
    entered: bool,
    epoch: u64,
    cookie_before: Option<crate::Result<u64>>,
    binding_before: Option<Result<(), SeqpacketError>>,
    set: Option<crate::Result<()>>,
    peek_payload: [u8; 1],
    peek: Option<rustix::io::Result<rustix::net::RecvMsg>>,
    queue_empty: Option<Result<(), SeqpacketError>>,
    cookie_after: Option<crate::Result<u64>>,
    binding_after: Option<Result<(), SeqpacketError>>,
    mode_after: Option<crate::Result<()>>,
}

impl SeqpacketRightsRestrictionOriginalV6 {
    /// Creates inert destinations without touching a socket.
    #[must_use]
    pub const fn new() -> Self {
        Self { entered: false, epoch: 0, cookie_before: None, binding_before: None,
            set: None, peek_payload: [0], peek: None, queue_empty: None,
            cookie_after: None, binding_after: None, mode_after: None }
    }

    /// Supplies the complete fixed carrier and native error-string byte peak.
    ///
    /// No descriptors are created. The caller separately debits one requested
    /// input byte for the queue peek; the peek never consumes queued data.
    #[must_use]
    pub fn receiving_obligations_v6() -> Option<(usize, usize)> {
        let cookie_message = "kernel returned an unexpected cookie length".len();
        let mode_message = "getsockopt(SO_PASSRIGHTS) returned an unexpected length".len()
            .max("SO_PASSRIGHTS must remain disabled".len());
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(cookie_message.checked_mul(2)?)?
            .checked_add(mode_message.checked_mul(2)?)?;
        Some((bytes, 0))
    }

    /// Reports full same-socket restriction and independent native post success.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.entered && self.failure().is_none()
            && matches!(self.mode_after, Some(Ok(())))
            && matches!(self.queue_empty, Some(Ok(())))
    }

    /// Borrows the first actual native or queue-contract refusal in call order.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.cookie_before { return Some(cause); }
        if let Some(Err(cause)) = &self.binding_before { return Some(cause); }
        if let Some(Err(cause)) = &self.set { return Some(cause); }
        if let Some(Err(cause)) = &self.peek {
            if *cause != rustix::io::Errno::AGAIN { return Some(cause); }
        }
        if let Some(Err(cause)) = &self.queue_empty { return Some(cause); }
        if let Some(Err(cause)) = &self.cookie_after { return Some(cause); }
        if let Some(Err(cause)) = &self.binding_after { return Some(cause); }
        if let Some(Err(cause)) = &self.mode_after { return Some(cause); }
        None
    }

    pub(super) fn entered(&self) -> bool { self.entered }

    pub(super) fn run(&mut self, fd: BorrowedFd<'_>, cookie: NonZeroU64, epoch: u64) -> Result<(), SeqpacketError> {
        if self.entered { return Err(SeqpacketError::Closed); }
        self.entered = true;
        self.epoch = epoch;
        self.cookie_before = Some(uapi::socket_cookie(fd));
        self.binding_before = Some(if matches!(self.cookie_before, Some(Ok(value)) if value == cookie.get()) {
            Ok(())
        } else { Err(SeqpacketError::Ancillary("rights restriction socket binding")) });
        self.set = Some(uapi::set_seqpacket_passrights(fd, false));

        // Zero ancillary capacity is essential: even MSG_PEEK can install
        // descriptors when supplied a receiving control buffer.
        let mut storage: [MaybeUninit<u8>; 0] = [];
        let mut control = rustix::net::RecvAncillaryBuffer::new(&mut storage);
        let mut payload = [std::io::IoSliceMut::new(&mut self.peek_payload)];
        self.peek = Some(rustix::net::recvmsg(fd, &mut payload, &mut control,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::TRUNC
                | rustix::net::RecvFlags::DONTWAIT | rustix::net::RecvFlags::CMSG_CLOEXEC));
        self.queue_empty = Some(if matches!(self.peek, Some(Err(rustix::io::Errno::AGAIN))) {
            Ok(())
        } else { Err(SeqpacketError::Ancillary("rights restriction requires an empty live queue")) });

        // Both posts are independent debts once the finite recipe enters.
        // Earlier set/peek failures never gate these actual observations.
        self.cookie_after = Some(uapi::socket_cookie(fd));
        self.binding_after = Some(if matches!(self.cookie_after, Some(Ok(value)) if value == cookie.get()) {
            Ok(())
        } else { Err(SeqpacketError::Ancillary("rights restriction socket binding after")) });
        self.mode_after = Some(uapi::require_seqpacket_zero_rights(fd));
        if self.completed() { Ok(()) } else { Err(SeqpacketError::Closed) }
    }

    pub(super) fn require_current(&self, cookie: NonZeroU64, mode: Option<&ZeroRightsNativeV1>) -> Result<(), SeqpacketError> {
        if self.completed()
            && matches!(self.cookie_after, Some(Ok(value)) if value == cookie.get())
            && mode.is_some_and(|mode| mode.restore.is_none() && mode.epoch == self.epoch) {
            Ok(())
        } else { Err(SeqpacketError::Closed) }
    }
}

impl Default for SeqpacketRightsRestrictionOriginalV6 {
    fn default() -> Self { Self::new() }
}

impl SeqpacketSocket {
    /// Restricts the same exposed socket after proving its prior queue empty.
    ///
    /// # Errors
    /// Keeps all reached native outcomes in `original`; reentry and any queued
    /// data refuse. The socket remains owned, and no receive-mode credit escapes.
    pub fn restrict_incoming_rights_retaining_v6(&mut self, original: &mut SeqpacketRightsRestrictionOriginalV6) -> Result<(), SeqpacketError> {
        if original.entered || self.zero_rights.as_ref()
            .is_some_and(|mode| matches!(mode.restore, Some(Err(_)))) {
            return Err(SeqpacketError::Closed);
        }
        let epoch = self.zero_rights.as_ref().map_or(0, |mode| mode.epoch)
            .checked_add(1).ok_or(SeqpacketError::Closed)?;
        // Fence the cached borrower before the first fallible native step.
        self.zero_rights = Some(ZeroRightsNativeV1 { restore: Some(Err(SeqpacketError::Closed)), epoch });
        original.run(self.borrow_fd()?, self.peer.socket_cookie(), epoch)?;
        self.zero_rights = Some(ZeroRightsNativeV1 { restore: None, epoch });
        Ok(())
    }

    /// Checks the completed restriction's same-socket and current-mode binding.
    ///
    /// This comparison performs no I/O and grants no role or effect authority.
    ///
    /// # Errors
    /// Refuses incomplete, restored, superseded, or different-socket originals.
    pub fn require_rights_restriction_current_v6(&self, original: &SeqpacketRightsRestrictionOriginalV6) -> Result<(), SeqpacketError> {
        self.borrow_fd()?;
        original.require_current(self.peer.socket_cookie(), self.zero_rights.as_ref())
    }
}

#[cfg(test)]
mod zero_rights_native_tests {
    use super::*;
    use std::io::IoSlice;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

    fn send_rights_without_disposing_sender(
        sender: &SeqpacketSocket,
        descriptor: BorrowedFd<'_>,
    ) -> rustix::io::Result<usize> {
        let descriptors = [descriptor];
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut storage);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            sender.as_fd().unwrap(), &[IoSlice::new(b"rights")],
            &mut ancillary, SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
    }

    #[test]
    fn preexposure_parent_rejects_rights_before_queue_but_keeps_subjects_and_child_rights() {
        let mut original = RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1();
        original.prepare().unwrap();
        let mut parent = original.take_parent_socket().unwrap();
        let mut child = SeqpacketSocket::from_owned(original.take_child_endpoint().unwrap()).unwrap();
        let descriptor = tempfile::tempfile().unwrap();

        assert_eq!(parent.zero_rights_receive_obligations_v1(4096).unwrap().1, 3);
        assert_eq!(SeqpacketSocket::storage_preparation_receive_obligations_v1(4096).unwrap().1, 19);
        assert_eq!(send_rights_without_disposing_sender(&child, descriptor.as_fd()), Err(rustix::io::Errno::PERM));
        let absent = parent.receive_storage_preparation_retaining_v1(4096).unwrap_err();
        assert!(absent.is_nonconsuming_would_block());

        child.send(b"legitimate reply").unwrap();
        let reply = parent.receive_storage_preparation_retaining_v1(4096).unwrap();
        assert_eq!(reply.payload(), b"legitimate reply");
        assert_eq!(reply.subject().credentials().pid().get(), std::process::id());

        parent.send_with_descriptors(b"lock delivery", &[descriptor.as_fd(), descriptor.as_fd()]).unwrap();
        let locks = child.receive_with_descriptors_retaining(4096, 2).unwrap();
        assert_eq!(locks.descriptors().len(), 2);
        assert_eq!(locks.payload(), b"lock delivery");
        assert!(original.failure().is_none());
    }

    #[test]
    fn descriptor_free_agent_parent_keeps_actual_three_rights_child_authorize() {
        let mut original = RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1();
        original.prepare().unwrap();
        let mut parent = original.take_parent_socket().unwrap();
        let mut child = SeqpacketSocket::from_owned(original.take_child_endpoint().unwrap()).unwrap();
        let descriptor = tempfile::tempfile().unwrap();

        assert_eq!(send_rights_without_disposing_sender(&child, descriptor.as_fd()), Err(rustix::io::Errno::PERM));
        child.send(b"signed Agent response").unwrap();
        let response = parent.receive_host_agent_response_retaining_v2(4096).unwrap();
        assert_eq!(response.payload(), b"signed Agent response");
        assert_eq!(parent.zero_rights_receive_obligations_v1(4096).unwrap().1, 3);
        assert_eq!(SeqpacketSocket::host_agent_response_receive_obligations_v2(4096).unwrap().1, 19);

        parent.send_with_descriptors(b"spec stdout stderr",
            &[descriptor.as_fd(), descriptor.as_fd(), descriptor.as_fd()]).unwrap();
        let request = child.receive_with_descriptors_retaining(4096, 3).unwrap();
        assert_eq!(request.descriptors().len(), 3);
        assert_eq!(request.payload(), b"spec stdout stderr");
        assert!(original.failure().is_none());
    }

    #[test]
    fn actual_restore_preserves_the_descriptor_capable_session_recipe() {
        let mut original = RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1();
        original.prepare().unwrap();
        let mut parent = original.take_parent_socket().unwrap();
        let mut child = SeqpacketSocket::from_owned(original.take_child_endpoint().unwrap()).unwrap();
        let descriptor = tempfile::tempfile().unwrap();

        parent.restore_rights_once_v1().unwrap();

        assert!(parent.zero_rights_receive_obligations_v1(4096).is_none());
        assert!(parent.zero_rights_failure_v1().is_none());
        child.send_with_descriptors(b"authorized descriptor stage", &[descriptor.as_fd()]).unwrap();
        let delivered = parent.receive_with_descriptors_retaining(4096, 1).unwrap();
        assert_eq!(delivered.descriptors().len(), 1);
        assert_eq!(delivered.payload(), b"authorized descriptor stage");
        assert!(matches!(parent.restore_rights_once_v1(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn changed_native_option_refuses_before_receive_and_keeps_original_failure() {
        let mut original = RecordSubjectSeqpacketPairOriginalV2::zero_rights_parent_v1();
        original.prepare().unwrap();
        let mut parent = original.take_parent_socket().unwrap();
        let child = original.take_child_endpoint().unwrap();
        uapi::set_seqpacket_passrights(parent.as_fd().unwrap(), true).unwrap();

        let error = parent.receive_storage_preparation_retaining_v1(4096).unwrap_err();

        assert!(!error.is_nonconsuming_would_block());
        assert!(!error.is_nonconsuming_interrupted());
        assert!(parent.as_fd().is_err());
        assert!(matches!(std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::Kernel(Error::InvalidInput { field: "closed zero-rights socket", .. }))));
        assert!(uapi::is_cloexec(child.as_fd()).unwrap());
    }
    #[test]
    fn exposed_empty_socket_restricts_and_keeps_descriptor_free_records() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let mut restriction = SeqpacketRightsRestrictionOriginalV6::new();
        receiver.restrict_incoming_rights_retaining_v6(&mut restriction).unwrap();
        receiver.require_rights_restriction_current_v6(&restriction).unwrap();
        assert!(restriction.completed());
        assert_eq!(SeqpacketRightsRestrictionOriginalV6::receiving_obligations_v6().unwrap().1, 0);
        assert!(matches!(restriction.peek, Some(Err(rustix::io::Errno::AGAIN))));
        assert!(matches!(restriction.cookie_after, Some(Ok(_))));
        assert!(matches!(restriction.mode_after, Some(Ok(()))));

        let file = tempfile::tempfile().unwrap();
        assert_eq!(send_rights_without_disposing_sender(&sender, file.as_fd()), Err(rustix::io::Errno::PERM));
        sender.send(b"authenticated terminal").unwrap();
        let record = receiver.receive_host_agent_response_retaining_v2(4096).unwrap();
        assert_eq!(record.payload(), b"authenticated terminal");
        assert!(receiver.restrict_incoming_rights_retaining_v6(&mut restriction).is_err());
        assert!(restriction.completed());
        receiver.require_rights_restriction_current_v6(&restriction).unwrap();
    }

    #[test]
    fn queued_rights_refuse_restriction_without_consumption_or_skipping_posts() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let file = tempfile::tempfile().unwrap();
        send_rights_without_disposing_sender(&sender, file.as_fd()).unwrap();
        let mut restriction = SeqpacketRightsRestrictionOriginalV6::new();

        assert!(receiver.restrict_incoming_rights_retaining_v6(&mut restriction).is_err());
        assert!(!restriction.completed());
        assert!(restriction.failure().is_some());
        assert!(matches!(restriction.peek, Some(Ok(_))));
        assert!(matches!(restriction.cookie_after, Some(Ok(_))));
        assert!(matches!(restriction.mode_after, Some(Ok(()))));
        assert!(receiver.zero_rights_receive_obligations_v1(4096).is_none());
        assert!(receiver.require_rights_restriction_current_v6(&restriction).is_err());
        let mut replacement = SeqpacketRightsRestrictionOriginalV6::new();
        assert!(receiver.restrict_incoming_rights_retaining_v6(&mut replacement).is_err());
        assert!(!replacement.entered);
        assert!(matches!(restriction.cookie_after, Some(Ok(_))));
        assert!(matches!(restriction.mode_after, Some(Ok(()))));
        // A second zero-control peek still sees the same queued packet. Neither
        // peek supplies any ancillary storage into which an FD could install.
        let mut byte = [0_u8; 1];
        let mut payload = [std::io::IoSliceMut::new(&mut byte)];
        let mut no_control = [];
        let mut control = rustix::net::RecvAncillaryBuffer::new(&mut no_control);
        let second = rustix::net::recvmsg(receiver.as_fd().unwrap(), &mut payload, &mut control,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::TRUNC | rustix::net::RecvFlags::DONTWAIT).unwrap();
        assert_eq!(second.bytes, b"rights".len());
        assert_eq!(byte, [b'r']);
        assert!(control.drain().next().is_none());
    }

    #[test]
    fn restriction_proof_rejects_foreign_socket_and_restored_generation() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let _sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let (other, other_endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let _other_sender = other_endpoint;
        let mut first = SeqpacketRightsRestrictionOriginalV6::new();
        receiver.restrict_incoming_rights_retaining_v6(&mut first).unwrap();
        assert!(other.require_rights_restriction_current_v6(&first).is_err());
        receiver.restore_rights_once_v1().unwrap();
        assert!(receiver.require_rights_restriction_current_v6(&first).is_err());
        let mut second = SeqpacketRightsRestrictionOriginalV6::new();
        receiver.restrict_incoming_rights_retaining_v6(&mut second).unwrap();
        assert!(receiver.require_rights_restriction_current_v6(&first).is_err());
        receiver.require_rights_restriction_current_v6(&second).unwrap();
    }

}

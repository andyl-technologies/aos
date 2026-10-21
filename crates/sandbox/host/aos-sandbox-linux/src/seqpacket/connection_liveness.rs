//! Shares the non-consuming native shutdown observation for retained channels.
//!
//! This is a transport observation only. Positive role admission and current
//! process/execution proofs remain with each actual caller.

use super::{SeqpacketError, SeqpacketSocket};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// Retains one actual same-socket identity observation after a native send.
///
/// Peer exit does not change this private kernel socket identity. This carrier
/// grants no writer, process, financial, monitor or effect authority.
#[derive(Default)]
pub struct SeqpacketSendAfterOriginalV1 {
    entered: bool,
    cookie: Option<aos_linux_descriptors::Result<u64>>,
    binding: Option<Result<(), super::RecordBindingError>>,
    refusal: bool,
}

impl SeqpacketSendAfterOriginalV1 {
    /// Creates empty destinations without sampling or opening a descriptor.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Observes only the retained socket, including its FD parked by send failure.
    ///
    /// A foreign failure FD must match the socket's private adoption-time
    /// kernel identity. No descriptor or raw cookie is exposed to the caller.
    ///
    /// # Errors
    /// Retains the actual kernel error and refuses missing/foreign descriptors
    /// or reentry without replacing the first observation.
    pub fn observe_once_v1(
        &mut self,
        socket: &SeqpacketSocket,
        failed_send: Option<&super::RetainedSeqpacketSendErrorV1>,
    ) -> Result<(), super::RecordBindingError> {
        use std::os::fd::AsFd as _;
        if self.entered {
            self.refusal = true;
            return Err(super::RecordBindingError::current_socket());
        }
        self.entered = true;
        let descriptor = match failed_send {
            Some(failure) => failure.descriptor.as_ref(),
            None => socket.fd.as_ref(),
        };
        let result = match descriptor {
            Some(descriptor) => socket.peer.binding.require_current_with_originals_v1(
                descriptor.as_fd(), Some(&mut self.cookie),
            ),
            None => Err(super::RecordBindingError::current_socket()),
        };
        let positive = result.is_ok();
        self.binding = Some(result);
        if positive { Ok(()) } else { Err(super::RecordBindingError::current_socket()) }
    }

    /// Borrows the original native or same-socket comparison cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cookie.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

/// Disables one actual owned socket while retaining its descriptor and syscall.
///
/// This native cleanup grants no process, monitor, financial or role authority.
#[derive(Default)]
pub struct SeqpacketOwnedShutdownOriginalV1 {
    entered: bool,
    descriptor: Option<std::os::fd::OwnedFd>,
    shutdown: Option<std::io::Result<()>>,
    refused: bool,
}

impl SeqpacketOwnedShutdownOriginalV1 {
    /// Creates inert destinations without opening or duplicating a descriptor.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Moves and shuts down only this actual socket's original active descriptor.
    ///
    /// The socket is disabled before the native call. No duplicate, retry or
    /// usable descriptor getter is supplied, including after a native failure.
    ///
    /// # Errors
    /// Retains native shutdown failure and refuses closed, unfinished or repeated input.
    pub fn shutdown_once_v1(&mut self, socket: &mut SeqpacketSocket) -> Result<(), SeqpacketError> {
        if self.entered {
            self.refused = true;
            return Err(SeqpacketError::Closed);
        }
        self.entered = true;
        if socket.retained_send_flight.is_some() || socket.fd.is_none() {
            self.refused = true;
            return Err(SeqpacketError::Closed);
        }
        self.descriptor = socket.fd.take();
        let descriptor = self.descriptor.as_ref().ok_or(SeqpacketError::Closed)?;
        self.shutdown = Some(SeqpacketSocket::shutdown_owned_descriptor_v1(descriptor));
        if self.completed_v1() { Ok(()) } else { Err(SeqpacketError::Closed) }
    }

    /// Reports only the actual full-positive shutdown of this still-retained FD.
    #[must_use]
    pub fn completed_v1(&self) -> bool {
        !self.refused && self.descriptor.is_some() && matches!(self.shutdown, Some(Ok(())))
    }

    /// Borrows the retained native shutdown cause.
    #[must_use]
    pub fn failure(&self) -> Option<&std::io::Error> {
        self.shutdown.as_ref().and_then(|result| result.as_ref().err())
    }
}

impl SeqpacketSocket {
    /// Checks for a locally observed shutdown without consuming queued records.
    ///
    /// A positive observation does not establish peer identity, application
    /// authority, or future connectivity. Callers retain their own process,
    /// execution-scope and protected-state checks around this observation.
    ///
    /// # Errors
    /// Returns the original socket or poll failure, or [`SeqpacketError::Closed`]
    /// when the current descriptor reports hangup, shutdown, error or invalidity.
    pub fn check_connected(&self) -> Result<(), SeqpacketError> {
        // A writer can close its channel while its process remains alive. Readable
        // queued records are allowed and must not be consumed by a liveness probe.
        let failures = PollFlags::HUP | PollFlags::RDHUP | PollFlags::ERR | PollFlags::NVAL;
        let observed = self.connection_events_retaining_v4(None)?;
        if observed.intersects(failures) {
            return Err(SeqpacketError::Closed);
        }
        Ok(())
    }

    fn connection_events_retaining_v4(
        &self,
        mut original: Option<&mut SeqpacketShutdownOriginalV4>,
    ) -> Result<PollFlags, SeqpacketError> {
        let descriptor = match self.as_fd() {
            Ok(descriptor) => {
                if let Some(original) = original.as_deref_mut() {
                    original.descriptor = Some(Ok(()));
                }
                descriptor
            }
            Err(cause) => {
                if let Some(original) = original.as_deref_mut() {
                    original.descriptor = Some(Err(cause));
                    return Err(SeqpacketError::Closed);
                }
                return Err(cause);
            }
        };
        let mut descriptors = [PollFd::from_borrowed_fd(descriptor, PollFlags::RDHUP)];
        let returned = poll(
            &mut descriptors,
            Some(&Timespec { tv_sec: 0, tv_nsec: 0 }),
        ).map_err(|source| aos_linux_descriptors::Error::Syscall {
            operation: "poll retained local connection",
            source: source.into(),
        });
        let events = descriptors[0].revents();
        if let Some(original) = original {
            original.poll = Some(returned);
            original.events = Some(events);
            if !matches!(original.poll, Some(Ok(_))) {
                return Err(SeqpacketError::Closed);
            }
        } else {
            returned?;
        }
        Ok(events)
    }

}


/// Retains the exact native poll result for one channel shutdown observation.
///
/// A hangup is transport DATA. It proves neither process death, application
/// completion nor any permission to dispose a role's retained native owners.
/// The actual caller must hold and verify those separate original proofs.
pub struct SeqpacketShutdownOriginalV4 {
    entered: bool,
    descriptor: Option<Result<(), SeqpacketError>>,
    poll: Option<aos_linux_descriptors::Result<usize>>,
    events: Option<PollFlags>,
    refusal: bool,
}

impl SeqpacketShutdownOriginalV4 {
    /// Creates empty fixed destinations without observing a descriptor.
    pub const fn new() -> Self {
        Self {
            entered: false,
            descriptor: None,
            poll: None,
            events: None,
            refusal: false,
        }
    }

    /// Samples the same socket once and reports only actual HUP/RDHUP.
    ///
    /// # Errors
    /// Retains descriptor/poll errors and rejects reentry, ERR or NVAL. A live
    /// channel returns false; a coarse Closed error cannot become a hangup.
    pub fn observe_once_v4(&mut self, socket: &SeqpacketSocket) -> Result<bool, SeqpacketError> {
        if self.entered {
            self.refusal = true;
            return Err(SeqpacketError::Closed);
        }
        self.entered = true;
        let events = socket.connection_events_retaining_v4(Some(self))?;
        if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
            return Err(SeqpacketError::Closed);
        }
        Ok(events.intersects(PollFlags::HUP | PollFlags::RDHUP))
    }

    /// Borrows the first reached native cause without moving its owner.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.descriptor.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.poll.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Supplies fixed construction/native stack bytes with zero new FD/name slots.
    pub fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<PollFd<'static>>())?
            .checked_add(2 * std::mem::size_of::<Timespec>())
            .map(|bytes| (bytes, 0, 0))
    }
}

impl Default for SeqpacketShutdownOriginalV4 {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Kernel fixture failures intentionally panic."
    )]
    #![allow(
        clippy::disallowed_methods,
        reason = "Host monotonic time only bounds a kernel fixture wait, not runtime state."
    )]

    use super::*;

    #[test]
    fn send_after_keeps_exact_socket_identity_when_recipient_exits() {
        let (mut sender, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut recipient = SeqpacketSocket::from_owned(endpoint).unwrap();
        sender.send_retaining(b"terminal").unwrap();
        assert_eq!(recipient.receive(16).unwrap().payload(), b"terminal");
        recipient.close();

        let mut after = SeqpacketSendAfterOriginalV1::new();
        after.observe_once_v1(&sender, None).unwrap();
        assert!(matches!(after.cookie, Some(Ok(_))));
        let actual = after.cookie.as_ref().unwrap() as *const _;
        assert!(after.observe_once_v1(&sender, None).is_err());
        assert_eq!(after.cookie.as_ref().unwrap() as *const _, actual);
    }

    #[test]
    fn send_after_uses_same_parked_failure_fd_and_rejects_foreign_fd() {
        let (mut sender, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        drop(endpoint);
        let failure = sender.send_retaining(b"terminal").err().unwrap();
        assert!(failure.retains_descriptor());
        let mut actual_after = SeqpacketSendAfterOriginalV1::new();
        actual_after.observe_once_v1(&sender, Some(&failure)).unwrap();

        let (foreign, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut foreign_after = SeqpacketSendAfterOriginalV1::new();
        assert!(foreign_after.observe_once_v1(&foreign, Some(&failure)).is_err());
        assert!(matches!(foreign_after.cookie, Some(Ok(_))));
        assert!(foreign_after.failure().is_some());
        assert!(failure.retains_descriptor());
    }

    #[test]
    fn send_after_native_failure_is_sticky_without_late_resample() {
        let (mut socket, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        socket.close();
        let mut after = SeqpacketSendAfterOriginalV1::new();

        assert!(after.observe_once_v1(&socket, None).is_err());
        assert!(after.cookie.is_none());
        assert!(after.failure().is_some());
        let (healthy, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        assert!(after.observe_once_v1(&healthy, None).is_err());
        assert!(after.cookie.is_none());
        assert!(after.failure().is_some());
    }

    #[test]
    fn owned_shutdown_disables_io_but_retains_same_fd_until_whole_owner_drop() {
        use std::os::fd::AsRawFd as _;
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        let path = format!("/proc/self/fd/{}", receiver.as_fd().unwrap().as_raw_fd());
        let mut original = SeqpacketOwnedShutdownOriginalV1::new();

        original.shutdown_once_v1(&mut receiver).unwrap();
        assert!(original.completed_v1());
        assert!(receiver.as_fd().is_err());
        assert!(std::fs::read_link(&path).is_ok());
        let mut observed = SeqpacketShutdownOriginalV4::new();
        assert!(observed.observe_once_v4(&sender).unwrap());

        drop(original);
        assert!(std::fs::read_link(path).is_err());
    }

    fn wait_for_peer_close(socket: &SeqpacketSocket) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);

        // Readiness notification can trail the final descriptor drop briefly
        // when the kernel test suite is heavily parallelized.
        while std::time::Instant::now() < deadline {
            match socket.check_connected() {
                Err(SeqpacketError::Closed) => return,
                Ok(()) => std::thread::yield_now(),
                Err(error) => panic!("unexpected liveness-probe failure: {error}"),
            }
        }

        assert!(matches!(
            socket.check_connected(),
            Err(SeqpacketError::Closed)
        ));
    }

    #[test]
    fn queued_record_is_not_consumed_and_last_endpoint_close_is_observed() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        receiver.check_connected().unwrap();
        sender.send(b"queued").unwrap();
        receiver.check_connected().unwrap();
        assert_eq!(receiver.receive(16).unwrap().payload(), b"queued");
        sender.close();
        wait_for_peer_close(&receiver);
    }

    #[test]
    fn shutdown_original_distinguishes_real_peer_hangup_from_local_closure() {
        let (receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        sender.close();
        wait_for_peer_close(&receiver);
        let mut original = SeqpacketShutdownOriginalV4::new();

        assert!(original.observe_once_v4(&receiver).unwrap());
        let actual = original.poll.as_ref().unwrap() as *const _;
        assert!(original.failure().is_none());
        assert!(original.observe_once_v4(&receiver).is_err());
        assert_eq!(original.poll.as_ref().unwrap() as *const _, actual);

        let (mut local, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        local.close();
        let mut closed = SeqpacketShutdownOriginalV4::new();
        assert!(closed.observe_once_v4(&local).is_err());
        assert!(closed.poll.is_none());
        assert!(matches!(closed.descriptor, Some(Err(SeqpacketError::Closed))));
        assert!(closed.events.is_none());
    }

    #[test]
    fn readable_packet_does_not_become_shutdown_or_get_consumed() {
        let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
        sender.send(b"still queued").unwrap();
        let mut original = SeqpacketShutdownOriginalV4::new();

        assert!(!original.observe_once_v4(&receiver).unwrap());

        assert_eq!(receiver.receive(32).unwrap().payload(), b"still queued");
        assert!(original.failure().is_none());
        assert!(!original.events.unwrap().intersects(PollFlags::HUP | PollFlags::RDHUP));
    }

}

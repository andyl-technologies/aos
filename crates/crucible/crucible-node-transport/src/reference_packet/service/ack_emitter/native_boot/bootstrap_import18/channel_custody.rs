//! Borrows original process, thread, deadline and inherited socket custody.
//!
//! A disjoint field borrow lets SDK callbacks check physical custody while the
//! original registrar is mutably borrowed. Constructing this view authenticates
//! nothing; every use must check its original fields and actual kernel peer.

use super::{OperationalDeadline, ThreadId, UnixStream, refused};
use crate::ProviderError;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use std::mem::size_of;

/// Borrows original physical fields without duplicating a descriptor or cut.
pub(super) struct BorrowedCustody<'a> {
    process: &'a u32,
    thread: &'a ThreadId,
    cut: &'a OperationalDeadline,
    stream: &'a UnixStream,
}

impl<'a> BorrowedCustody<'a> {
    /// Names the existing fields without checking, renewing or allocating them.
    pub(super) fn new_data(
        process: &'a u32,
        thread: &'a ThreadId,
        cut: &'a OperationalDeadline,
        stream: &'a UnixStream,
    ) -> Self {
        Self {
            process,
            thread,
            cut,
            stream,
        }
    }

    /// Checks the actual original process and thread before reading custody.
    ///
    /// # Errors
    /// Refuses a different current process or thread.
    pub(super) fn authenticate_origin_data(&self) -> Result<(), ProviderError> {
        if *self.process != std::process::id() || *self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the nonrenewing cut and actual parent/UID of the inherited socket.
    ///
    /// # Errors
    /// Refuses changed origin, expiry, peer credential lookup or a foreign peer.
    pub(super) fn authenticate_channel_data(&self) -> Result<(), ProviderError> {
        self.peer_credentials_data().map(|_| ())
    }

    /// Joins the launch to that same actual kernel parent and user.
    ///
    /// # Errors
    /// Refuses original channel custody or different launch controller claims.
    pub(super) fn authenticate_controller_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        let peer = self.peer_credentials_data()?;
        if launch.controller_pid.get() != u64::from(peer.pid.as_raw_nonzero().get() as u32)
            || launch.controller_uid.get() != u64::from(peer.uid.as_raw())
        {
            return Err(ProviderError::Correlation(
                "original import18 controller kernel DATA",
            ));
        }
        Ok(())
    }

    fn peer_credentials_data(&self) -> Result<rustix::net::UCred, ProviderError> {
        self.authenticate_origin_data()?;
        if self.cut.is_expired() {
            return Err(refused());
        }
        let peer =
            rustix::net::sockopt::socket_peercred(self.stream).map_err(std::io::Error::from)?;
        if Some(peer.pid) != rustix::process::getppid() || peer.uid != rustix::process::geteuid() {
            return Err(refused());
        }
        Ok(peer)
    }
}

/// Names the real borrowed owner and its physical guard controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<BorrowedCustody<'static>>()
        + size_of::<&BorrowedCustody<'static>>()
        + size_of::<std::thread::Thread>()
        + size_of::<ThreadId>()
        + size_of::<rustix::net::UCred>()
        + size_of::<Result<rustix::net::UCred, rustix::io::Errno>>()
        + size_of::<Result<rustix::net::UCred, std::io::Error>>()
        + size_of::<Result<rustix::net::UCred, ProviderError>>()
        + size_of::<Option<rustix::process::Pid>>()
        + size_of::<rustix::process::Uid>()
        + size_of::<u32>() * 2
        + size_of::<u64>() * 2
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Result<(), ProviderError>>() * 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_keeps_the_original_thread_and_checks_it_on_each_borrow() {
        let process = std::process::id();
        let thread = std::thread::current().id();
        let cut = OperationalDeadline::after(std::time::Duration::from_secs(5)).unwrap();
        let (stream, _peer) = UnixStream::pair().unwrap();
        let original = BorrowedCustody::new_data(&process, &thread, &cut, &stream);
        assert!(original.authenticate_origin_data().is_ok());

        std::thread::scope(|scope| {
            scope.spawn(|| assert!(original.authenticate_origin_data().is_err()));
        });

        assert!(original.authenticate_origin_data().is_ok());
    }

    #[test]
    fn a_socket_created_in_this_process_cannot_substitute_the_inherited_parent() {
        let process = std::process::id();
        let thread = std::thread::current().id();
        let cut = OperationalDeadline::after(std::time::Duration::from_secs(5)).unwrap();
        let (stream, _peer) = UnixStream::pair().unwrap();
        let original = BorrowedCustody::new_data(&process, &thread, &cut, &stream);

        assert!(original.authenticate_channel_data().is_err());
        assert!(original.authenticate_origin_data().is_ok());
        assert!(!cut.is_expired());
    }
}

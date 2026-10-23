//! Exchanges bounded records on one original, confined FUSE device descriptor.
//!
//! The launcher mounts the connection and installs worker network confinement
//! before constructing this transport. The dispatcher separately owns protocol
//! negotiation, inode policy, outstanding requests and scoped backing grants.
//! Dropping a descriptor does not acknowledge release of kernel-held backing.

use crate::{
    fuse_protocol::{Reply, Request},
    quota_confinement::WorkerNetworkInstalled,
};
use rustix::{
    fs::{FileType, OFlags, fcntl_getfl, fstat},
    io::{read, write},
};
use std::{io, os::fd::OwnedFd, sync::Arc, time::Duration};
use tokio::io::unix::AsyncFd;

/// Retains one original FUSE descriptor and its originating process confinement.
///
/// This transport never opens a pathname or clones the connection descriptor.
/// The launcher must close unrelated aliases and provide the remaining worker
/// isolation. Fault, timeout or cancellation during an accepted exchange closes
/// this transport; it cannot then be reused for a later request.
pub struct Connection {
    device: Option<AsyncFd<OwnedFd>>,
    confinement: Arc<WorkerNetworkInstalled>,
    maximum_request_bytes: usize,
    maximum_reply_bytes: usize,
}

impl Connection {
    /// Registers an original nonblocking read/write FUSE device with the reactor.
    ///
    /// The launcher sets nonblocking mode before transferring sole descriptor
    /// ownership. Limits include record headers; the request buffer must satisfy
    /// the kernel's 8192-byte minimum device-read requirement.
    ///
    /// # Errors
    /// Refuses invalid limits, another process's confinement, a descriptor other
    /// than a nonblocking read/write FUSE character device and reactor failures.
    ///
    /// # Panics
    /// Panics without a Tokio I/O driver after native descriptor validation.
    pub fn new(
        device: OwnedFd,
        confinement: Arc<WorkerNetworkInstalled>,
        maximum_request_bytes: usize,
        maximum_reply_bytes: usize,
    ) -> io::Result<Self> {
        if maximum_request_bytes < 8192
            || maximum_reply_bytes < 16
            || u32::try_from(maximum_request_bytes).is_err()
            || u32::try_from(maximum_reply_bytes).is_err()
        {
            return Err(invalid("invalid FUSE transport byte limits"));
        }
        confinement.check_current()?;
        let metadata = fstat(&device)?;
        let flags = fcntl_getfl(&device)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::CharacterDevice
            || metadata.st_rdev != libc::makedev(10, 229)
            || flags & OFlags::ACCMODE != OFlags::RDWR
            || !flags.contains(OFlags::NONBLOCK)
            || flags.contains(OFlags::PATH)
        {
            return Err(invalid(
                "FUSE transport requires the original nonblocking device",
            ));
        }
        Ok(Self {
            device: Some(AsyncFd::new(device)?),
            confinement,
            maximum_request_bytes,
            maximum_reply_bytes,
        })
    }

    /// Receives exactly one checked request into the caller's reusable buffer.
    ///
    /// The buffer must contain the configured maximum. No per-record allocation
    /// occurs, and a successful result borrows only initialized request bytes.
    /// After accepting the wait, every error or cancellation closes the original
    /// transport. Unmount/abort errors retain their actual native error codes.
    ///
    /// # Errors
    /// Refuses insufficient buffer capacity, a zero or excessive timeout, changed
    /// confinement, a closed transport, native IO, malformed input and deadline
    /// expiry. Timeouts are positive and at most 300 seconds.
    ///
    /// # Panics
    /// Panics without a Tokio I/O and time driver after argument validation.
    pub async fn receive<'a>(
        &mut self,
        buffer: &'a mut [u8],
        timeout: Duration,
    ) -> io::Result<Request<'a>> {
        check_timeout(timeout)?;
        let buffer = buffer
            .get_mut(..self.maximum_request_bytes)
            .ok_or_else(|| invalid("FUSE request buffer is smaller than its configured bound"))?;
        self.confinement.check_current()?;
        let mut exchange = Exchange::start(&mut self.device)?;
        let length = tokio::time::timeout(timeout, async {
            loop {
                let device = exchange.device()?;
                let mut ready = device.readable().await?;
                match ready
                    .try_io(|device| read(device.get_ref(), &mut *buffer).map_err(Into::into))
                {
                    Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(Ok(length)) => return Ok(length),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let request = Request::parse(&buffer[..length], self.maximum_request_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.confinement.check_current()?;
        exchange.complete = true;
        Ok(request)
    }

    /// Sends one complete checked ordinary reply in a single device write.
    ///
    /// A short write faults the transport; it is never retried as another record.
    /// The dispatcher must match the reply to its original outstanding request.
    /// Errors and cancellation after accepting the wait close this transport.
    ///
    /// # Errors
    /// Refuses replies exceeding the configured bound, a zero or excessive
    /// timeout, changed confinement, closed transport, native IO, short writes
    /// and deadline expiry. Timeouts are positive and at most 300 seconds.
    ///
    /// # Panics
    /// Panics without a Tokio I/O and time driver after argument validation.
    pub async fn send(&mut self, reply: Reply<'_>, timeout: Duration) -> io::Result<()> {
        check_timeout(timeout)?;
        let bytes = reply.as_bytes();
        if bytes.len() > self.maximum_reply_bytes {
            return Err(invalid("FUSE reply exceeds its configured bound"));
        }
        self.confinement.check_current()?;
        let mut exchange = Exchange::start(&mut self.device)?;
        tokio::time::timeout(timeout, async {
            loop {
                let device = exchange.device()?;
                let mut ready = device.writable().await?;
                match ready.try_io(|device| write(device.get_ref(), bytes).map_err(Into::into)) {
                    Ok(Ok(length)) if length == bytes.len() => return Ok(()),
                    Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        self.confinement.check_current()?;
        exchange.complete = true;
        Ok(())
    }
}

struct Exchange<'a> {
    device: &'a mut Option<AsyncFd<OwnedFd>>,
    complete: bool,
}

impl<'a> Exchange<'a> {
    fn start(device: &'a mut Option<AsyncFd<OwnedFd>>) -> io::Result<Self> {
        if device.is_none() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(Self {
            device,
            complete: false,
        })
    }

    fn device(&self) -> io::Result<&AsyncFd<OwnedFd>> {
        self.device
            .as_ref()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.device.take();
        }
    }
}

fn check_timeout(timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(300) {
        return Err(invalid(
            "FUSE exchange requires a timeout of at most 300 seconds",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

//! Bounds one backing exchange while retaining the original connection custody.

use super::{BackingReply, PendingBacking, RequestedBacking, WorkerClient};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

impl WorkerClient {
    /// Awaits disconnection or a protocol fault while no request is outstanding.
    ///
    /// An idle owner must send no packets. This future borrows the original
    /// socket without cloning it; cancellation while waiting retains the channel.
    /// Receiving EOF or any unsolicited packet faults it immediately. Previously
    /// disclosed backing and kernel-reference custody remain independently owned.
    ///
    /// # Errors
    /// Returns `UnexpectedEof` when the original owner disconnects, `InvalidData`
    /// for an unsolicited packet, or native reactor/transport errors. A completed
    /// wait always returns an error and disconnects the original channel.
    ///
    /// # Panics
    /// Panics without a Tokio I/O driver after validating the original client.
    pub async fn wait_idle_fault(&mut self) -> io::Result<()> {
        if !self.active {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let outcome = async {
            let socket = AsyncFd::new(self.socket.as_fd())?;
            loop {
                let mut ready = socket.readable().await?;
                match ready.try_io(|socket| {
                    let mut byte = [0];
                    // No ancillary buffer is supplied: Linux disposes of any
                    // unsolicited rights instead of importing a new descriptor.
                    match rustix::net::recv(
                        socket.get_ref(),
                        &mut byte,
                        rustix::net::RecvFlags::DONTWAIT,
                    ) {
                        Ok((0, _)) => Ok(io::Error::from(io::ErrorKind::UnexpectedEof)),
                        Ok(_) => Ok(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unsolicited idle backing reply",
                        )),
                        Err(error) => Err(io::Error::from(error)),
                    }
                }) {
                    Ok(Ok(failure)) => return Err(failure),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                }
            }
        }
        .await;
        self.abort();
        outcome
    }

    /// Requests and maps the structural index for this channel's exposure root.
    ///
    /// The private launcher context supplies the root; a caller cannot replace
    /// it with a root read from the returned bytes. The authenticated reply's
    /// original descriptor and measured seal pass directly to the read-only
    /// mapping owner. Mapping or index validation failure disconnects the
    /// channel and consumes the refused descriptor.
    ///
    /// The timeout bounds the complete channel exchange. Synchronous mapping
    /// and validation additionally obey `max_bytes`; they do not fetch content.
    /// Previously received backings retain their original custody on failure.
    ///
    /// # Errors
    /// Refuses zero or unaddressable mapping bounds before sending. Preserves
    /// transport and deadline failures from [`Self::request_bounded`]. Returns
    /// `InvalidData` for a refused mapping, including malformed index bytes,
    /// another root, an oversized file or a changed kernel measurement.
    ///
    /// # Panics
    /// Panics without a Tokio I/O or time driver after validating the bounds.
    pub async fn request_index_bounded(
        &mut self,
        max_bytes: usize,
        timeout: Duration,
    ) -> io::Result<crate::structural_index::MappedIndex> {
        if max_bytes == 0 || max_bytes > isize::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker index requires an addressable positive mapping bound",
            ));
        }
        let reply = self
            .request_bounded(RequestedBacking::Index, timeout)
            .await?;
        match crate::structural_index::MappedIndex::open(
            reply.file.into(),
            self.context.root,
            &reply.seal,
            max_bytes,
        ) {
            Ok(mapping) => Ok(mapping),
            Err(error) => {
                self.abort();
                Err(io::Error::new(io::ErrorKind::InvalidData, error))
            }
        }
    }

    /// Requests and validates one backing descriptor under a whole-exchange deadline.
    ///
    /// Kernel readiness drives both send backpressure and reply receipt. Success
    /// retains this connection for its next sequence. Timeout, cancellation or
    /// failure after registration disconnects it, including retained descriptor
    /// aliases. Accepted physical work and previously received kernel references
    /// keep their original custody; disconnection never acknowledges release.
    ///
    /// # Errors
    /// Refuses a zero timeout or one exceeding 300 seconds before registration
    /// or sending. Preserves request validation and authenticated reply failures
    /// from [`Self::request`] and [`PendingBacking::receive`], and returns reactor
    /// or deadline errors. The caller supplies a Tokio I/O and time driver.
    ///
    /// # Panics
    /// Panics when invoked without a Tokio I/O or time driver after validation.
    pub async fn request_bounded(
        &mut self,
        backing: RequestedBacking,
        timeout: Duration,
    ) -> io::Result<BackingReply> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker backing requires a positive timeout of at most 300 seconds",
            ));
        }
        let (next, expected) = self.prepare(backing)?;
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "worker deadline overflow")
        })?;
        // The existing pending-request guard owns cancellation before send too.
        // Register that borrow directly; no duplicated descriptor can outlive it.
        let mut socket = AsyncFd::new(Exchange(PendingBacking {
            client: self,
            expected,
            completed: false,
        }))?;
        tokio::time::timeout_at(deadline, async {
            loop {
                let mut ready = socket.writable_mut().await?;
                match ready.try_io(|socket| {
                    let pending = &mut socket.get_mut().0;
                    pending.client.send(&pending.expected)
                }) {
                    Ok(result) => {
                        result?;
                        break;
                    }
                    Err(_) => continue,
                }
            }
            socket.get_mut().0.client.next_sequence = next;

            loop {
                let mut ready = socket.readable_mut().await?;
                match ready.try_io(|socket| socket.get_mut().0.receive()) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

struct Exchange<'client>(PendingBacking<'client>);

impl AsRawFd for Exchange<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.client.socket.as_raw_fd()
    }
}

#[cfg(test)]
mod tests;

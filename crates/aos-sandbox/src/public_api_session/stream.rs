//! Keeps public peer evidence tied to the lifetime of its authenticated TLS stream.

use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

use super::PublicApiPeer;

/// Owns authenticated HTTP/2 transport without exposing mutable TLS identity state.
///
/// Pending reads, writes, flushes, and shutdowns register expiration wake-ups.
/// Expired I/O fails with [`io::ErrorKind::ConnectionAborted`] and invalidates
/// retained peer evidence. Request handlers must still recheck current peer
/// credentials and independently authorize each request.
pub struct AuthenticatedPublicApiStream<IO> {
    stream: TlsStream<IO>,
    peer: PublicApiPeer,
    expiration: StreamExpiration,
}

impl<IO> AuthenticatedPublicApiStream<IO> {
    pub(super) fn new(stream: TlsStream<IO>, peer: PublicApiPeer) -> Self {
        let remaining = super::boottime()
            .map(|now| peer.0.deadline.saturating_sub(now))
            .unwrap_or(0);
        Self {
            stream,
            peer,
            expiration: StreamExpiration::new(Duration::from_nanos(remaining)),
        }
    }

    /// Borrows peer evidence that becomes stale when this stream closes or drops.
    #[must_use]
    pub fn peer(&self) -> &PublicApiPeer {
        &self.peer
    }

    fn poll_current(&mut self, context: &mut Context<'_>, writing: bool) -> io::Result<()> {
        if !self.peer.0.active.load(Ordering::Acquire) {
            return Err(stale_session());
        }
        self.poll_deadline(context, writing)
    }

    fn poll_deadline(&mut self, context: &mut Context<'_>, writing: bool) -> io::Result<()> {
        // Register the reader/writer for expiration even when the socket has
        // no traffic. On each poll, BOOTTIME also catches expiry across machine
        // suspension, which Tokio's monotonic timer alone does not count.
        if self.expiration.poll(context, writing).is_ready()
            || !super::boottime().is_ok_and(|now| now < self.peer.0.deadline)
        {
            self.peer.close();
            return Err(stale_session());
        }
        Ok(())
    }
}

fn stale_session() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "public API session is no longer current",
    )
}

struct StreamExpiration {
    read: Pin<Box<tokio::time::Sleep>>,
    write: Pin<Box<tokio::time::Sleep>>,
}

impl StreamExpiration {
    fn new(remaining: Duration) -> Self {
        let deadline = tokio::time::Instant::now() + remaining;
        Self {
            read: Box::pin(tokio::time::sleep_until(deadline)),
            write: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    fn poll(&mut self, context: &mut Context<'_>, writing: bool) -> Poll<()> {
        // Split readers and writers may have different tasks. Separate timers
        // preserve both wakers instead of replacing one with the other.
        let expiration = if writing {
            &mut self.write
        } else {
            &mut self.read
        };
        expiration.as_mut().poll(context)
    }
}

impl<IO> Drop for AuthenticatedPublicApiStream<IO> {
    fn drop(&mut self) {
        self.peer.close();
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for AuthenticatedPublicApiStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.poll_current(context, false) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let capacity = buffer.remaining();
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Err(_)))
            || (matches!(result, Poll::Ready(Ok(())))
                && capacity != 0
                && buffer.filled().len() == before)
        {
            self.peer.close();
        }
        result
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AuthenticatedPublicApiStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.poll_current(context, true) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.stream).poll_write(context, bytes);
        if matches!(result, Poll::Ready(Err(_))) {
            self.peer.close();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.poll_current(context, true) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.stream).poll_flush(context);
        if matches!(result, Poll::Ready(Err(_))) {
            self.peer.close();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.peer.close();
        // TLS close-notify can itself wait for socket writability. Closing peer
        // authority immediately must not remove the shutdown deadline wake-up.
        if let Err(error) = self.poll_deadline(context, true) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeFlag(AtomicBool);

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn expiration_wakes_both_idle_transport_halves() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let reader = Arc::new(WakeFlag::default());
            let writer = Arc::new(WakeFlag::default());
            let read_waker = Waker::from(Arc::clone(&reader));
            let write_waker = Waker::from(Arc::clone(&writer));
            let mut read_context = Context::from_waker(&read_waker);
            let mut write_context = Context::from_waker(&write_waker);
            let mut expiration = StreamExpiration::new(Duration::from_millis(50));

            assert!(expiration.poll(&mut read_context, false).is_pending());
            assert!(expiration.poll(&mut write_context, true).is_pending());
            tokio::time::sleep(Duration::from_millis(100)).await;

            assert!(reader.0.load(Ordering::Acquire));
            assert!(writer.0.load(Ordering::Acquire));
            assert!(expiration.poll(&mut read_context, false).is_ready());
            assert!(expiration.poll(&mut write_context, true).is_ready());
        });
    }
}

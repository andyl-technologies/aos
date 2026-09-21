//! Keeps public peer evidence tied to the lifetime of its authenticated TLS stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

use super::PublicApiPeer;

/// Owns authenticated HTTP/2 transport without exposing mutable TLS identity state.
pub struct AuthenticatedPublicApiStream<IO> {
    stream: TlsStream<IO>,
    peer: PublicApiPeer,
}

impl<IO> AuthenticatedPublicApiStream<IO> {
    pub(super) fn new(stream: TlsStream<IO>, peer: PublicApiPeer) -> Self {
        Self { stream, peer }
    }

    /// Borrows peer evidence that becomes stale when this stream closes or drops.
    #[must_use]
    pub fn peer(&self) -> &PublicApiPeer {
        &self.peer
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
        let result = Pin::new(&mut self.stream).poll_write(context, bytes);
        if matches!(result, Poll::Ready(Err(_))) {
            self.peer.close();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_flush(context);
        if matches!(result, Poll::Ready(Err(_))) {
            self.peer.close();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.peer.close();
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

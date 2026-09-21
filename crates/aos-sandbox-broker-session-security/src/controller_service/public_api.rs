//! Serves registered mutual-TLS discovery on the fixed public Unix endpoint.
//!
//! Socket access is not identity evidence. Only a completed protected TLS
//! handshake creates connection metadata; request headers cannot replace it.
//! Connection and concurrent-handshake bounds include clients that send nothing.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aos_sandbox::public_api_session::{
    AuthenticatedPublicApiStream, PublicApiPeer, PublicApiSessionAcceptor,
};
use axum::extract::{ConnectInfo, Request, connect_info::Connected};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse as _, Response};
use axum::serve::{IncomingStream, Listener};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream, unix::SocketAddr};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use super::ControllerRuntimeError;

const SOCKET: &str = "/run/aos/sandboxd/public.sock";
const MAXIMUM_CONNECTIONS: usize = 32;
const MAXIMUM_HANDSHAKES: usize = 8;

/// Loads protected TLS custody and binds the fixed controller-owned endpoint.
///
/// # Errors
///
/// Rejects invalid credentials, unsafe socket custody, or reactor registration failure.
pub(super) async fn bind(uid: u32) -> Result<PublicListener, ControllerRuntimeError> {
    // Validate custody before making a socket available to clients.
    let acceptor = Arc::new(PublicApiSessionAcceptor::from_systemd_credentials()?);
    let socket = super::bind_controller_socket(std::path::Path::new(SOCKET), uid, 0o666)?;
    let listener = UnixListener::from_std(socket).map_err(ControllerRuntimeError::PublicServer)?;
    Ok(PublicListener {
        listener,
        acceptor,
        capacity: Arc::new(Semaphore::new(MAXIMUM_CONNECTIONS)),
        handshakes: JoinSet::new(),
    })
}

/// Serves authenticated discovery, or remains pending when explicitly disabled.
///
/// # Errors
///
/// Reports termination of the public HTTP server.
pub(super) async fn serve(
    listener: Option<PublicListener>,
    application: axum::Router,
) -> Result<(), ControllerRuntimeError> {
    let Some(listener) = listener else {
        return std::future::pending().await;
    };
    axum::serve(
        listener,
        application
            .layer(from_fn(require_current_peer))
            .into_make_service_with_connect_info::<RegisteredPeer>(),
    )
    .await
    .map_err(ControllerRuntimeError::PublicServer)
}

#[derive(Clone)]
struct RegisteredPeer(PublicApiPeer);

impl Connected<IncomingStream<'_, PublicListener>> for RegisteredPeer {
    fn connect_info(stream: IncomingStream<'_, PublicListener>) -> Self {
        Self(stream.io().stream.peer().clone())
    }
}

async fn require_current_peer(mut request: Request, next: Next) -> Response {
    let Some(ConnectInfo(RegisteredPeer(peer))) = request
        .extensions()
        .get::<ConnectInfo<RegisteredPeer>>()
        .cloned()
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if peer.recheck().is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    request.extensions_mut().insert(peer.clone());
    let response = next.run(request).await;
    if peer.recheck().is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    response
}

/// Admits only registered TLS streams within fixed connection and handshake limits.
pub(super) struct PublicListener {
    listener: UnixListener,
    acceptor: Arc<PublicApiSessionAcceptor>,
    capacity: Arc<Semaphore>,
    handshakes: JoinSet<Option<(PublicConnection, SocketAddr)>>,
}

impl Listener for PublicListener {
    type Io = PublicConnection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let capacity = Arc::clone(&self.capacity);
            tokio::select! {
                completed = self.handshakes.join_next(), if !self.handshakes.is_empty() => {
                    if let Some(Ok(Some(connection))) = completed {
                        return connection;
                    }
                }
                accepted = async {
                    let permit = capacity.acquire_owned().await.map_err(io::Error::other)?;
                    let (stream, address) = self.listener.accept().await?;
                    Ok::<_, io::Error>((stream, address, permit))
                }, if self.handshakes.len() < MAXIMUM_HANDSHAKES => {
                    match accepted {
                        Ok((stream, address, permit)) => {
                            let acceptor = Arc::clone(&self.acceptor);
                            self.handshakes.spawn(async move {
                                let stream = acceptor.accept(stream).await.ok()?;
                                Some((PublicConnection { stream, _permit: permit }, address))
                            });
                        }
                        Err(error) => {
                            eprintln!("aos-sandboxd: public socket accept failed: {error}");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Holds a connection slot through HTTP/2 serving, not just its handshake.
pub(super) struct PublicConnection {
    stream: AuthenticatedPublicApiStream<UnixStream>,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for PublicConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for PublicConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[test]
    fn identity_headers_cannot_replace_registered_connection_metadata() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("middleware.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let application = axum::Router::new()
                .route("/", axum::routing::get(|| async { "must not run" }))
                .layer(from_fn(require_current_peer));
            let server = tokio::spawn(async move { axum::serve(listener, application).await });

            let mut client = UnixStream::connect(&path).await.unwrap();
            client.write_all(b"GET / HTTP/1.1\r\nHost: fixture\r\nX-Aos-Principal: administrator\r\nX-Aos-Project: any\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(std::time::Duration::from_secs(2), client.read_to_end(&mut response))
                .await.unwrap().unwrap();

            assert!(response.starts_with(b"HTTP/1.1 401"));
            assert!(!String::from_utf8_lossy(&response).contains("must not run"));
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        });
    }
}

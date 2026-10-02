//! Serves registered mutual-TLS discovery and authorized operation reads.
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
    bind_at(uid, std::path::Path::new(SOCKET)).await
}

async fn bind_at(
    uid: u32,
    path: &std::path::Path,
) -> Result<PublicListener, ControllerRuntimeError> {
    // Validate custody before making a socket available to clients.
    let acceptor = Arc::new(PublicApiSessionAcceptor::from_systemd_credentials()?);
    let socket = super::bind_controller_socket(path, uid, 0o666)?;
    let listener = UnixListener::from_std(socket).map_err(ControllerRuntimeError::PublicServer)?;
    Ok(PublicListener {
        listener,
        acceptor,
        capacity: Arc::new(Semaphore::new(MAXIMUM_CONNECTIONS)),
        handshakes: JoinSet::new(),
    })
}

/// Holds partial public-listener returns as fields of the existing parent.
///
/// Empty construction is not admission. This component has no terminal state
/// or independent owner graph; the parent's original terminal handles failure.
pub(super) struct PublicListenerStartupV1 {
    acceptor: Option<Arc<PublicApiSessionAcceptor>>,
    registration: Option<tokio::net::UnixListenerRegistrationAttempt>,
    listener: Option<UnixListener>,
    capacity: Option<Arc<Semaphore>>,
    handshakes: Option<JoinSet<Option<(PublicConnection, SocketAddr)>>>,
}

impl PublicListenerStartupV1 {
    /// Creates empty ownership slots without loading credentials or doing I/O.
    pub(super) const fn new() -> Self {
        Self {
            acceptor: None,
            registration: None,
            listener: None,
            capacity: None,
            handshakes: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.acceptor.is_none()
            && self.registration.is_none()
            && self.listener.is_none()
            && self.capacity.is_none()
            && self.handshakes.is_none()
    }
}

/// Forms the fixed public listener directly in the selected parent's slots.
///
/// Called inside that parent's existing runtime. Actual errors enter its
/// terminal before the runtime returns; this helper never returns a failure.
/// Lower credential/bind prefixes and accepted TLS tasks remain separate
/// functional custody obligations.
///
/// # Panics
///
/// Borrowed Tokio registration can panic without an I/O-enabled runtime.
/// The existing parent unwind fence remains responsible for termination.
pub(super) fn bind_retained(
    uid: u32,
    partial: &mut PublicListenerStartupV1,
    destination: &mut Option<Option<PublicListener>>,
    terminal: &super::ControllerWorkerCustodyV1,
) {
    if !partial.is_empty() || destination.is_some() {
        terminal.terminate(super::ControllerResidentCauseV1::Closed(
            "Controller public startup destination occupied",
        ));
    }

    let acceptor = match PublicApiSessionAcceptor::from_systemd_credentials() {
        Ok(acceptor) => acceptor,
        Err(cause) => terminal.terminate(super::ControllerResidentCauseV1::Runtime(
            ControllerRuntimeError::PublicSession(cause),
        )),
    };
    partial.acceptor = Some(Arc::new(acceptor));

    let socket = match super::bind_controller_socket(std::path::Path::new(SOCKET), uid, 0o666) {
        Ok(socket) => socket,
        Err(cause) => terminal.terminate(super::ControllerResidentCauseV1::Runtime(cause)),
    };
    partial.registration = Some(tokio::net::UnixListenerRegistrationAttempt::new(socket));

    let Some(attempt) = partial.registration.as_mut() else {
        terminal.terminate(super::ControllerResidentCauseV1::Closed(
            "Controller public registration unavailable",
        ));
    };
    partial.listener = Some(match attempt.register() {
        Ok(listener) => listener,
        Err(cause) => terminal.terminate(super::ControllerResidentCauseV1::Runtime(
            ControllerRuntimeError::PublicServer(cause),
        )),
    });
    partial.capacity = Some(Arc::new(Semaphore::new(MAXIMUM_CONNECTIONS)));
    partial.handshakes = Some(JoinSet::new());

    if partial.listener.is_none()
        || partial.acceptor.is_none()
        || partial.capacity.is_none()
        || partial.handshakes.is_none()
        || destination.is_some()
    {
        terminal.terminate(super::ControllerResidentCauseV1::Closed(
            "Controller public startup incomplete",
        ));
    }

    // All four slots are occupied under this exclusive loan. Only infallible
    // moves follow validation; no user code, checks or allocation can intervene
    // before the final listener is parked in the same parent.
    *destination = partial
        .listener
        .take()
        .zip(partial.acceptor.take())
        .zip(partial.capacity.take())
        .zip(partial.handshakes.take())
        .map(|(((listener, acceptor), capacity), handshakes)| {
            Some(PublicListener {
                listener,
                acceptor,
                capacity,
                handshakes,
            })
        });
}

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_tests;

/// Serves authenticated public APIs, or remains pending when explicitly disabled.
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

impl PublicListener {
    // Shares only the already loaded fixed acceptor; no second credential open.
    pub(super) fn git_read_acceptor(&self) -> Arc<PublicApiSessionAcceptor> {
        Arc::clone(&self.acceptor)
    }
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

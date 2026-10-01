//! Parks completed TLS admission and the real retained TCP handshake.
//!
//! The generic admission slot is shared with legacy Unix/non-Linux accepts.
//! Linux TCP custody retains the provider's actual state, never reconstructed
//! IO or authentication evidence. Dropping a whole owner still drops transport.

use tokio_rustls::server::TlsStream;

use super::{AuthenticatedPublicApiStream, PublicApiPeer, PublicApiSessionError};

#[cfg(target_os = "linux")]
type OriginalV1 = Option<super::socket::OriginalPublicSocketV1>;
#[cfg(not(target_os = "linux"))]
type OriginalV1 = Option<()>;

pub(super) enum CompletedAdmissionStateV1<IO> {
    Pending {
        // Legacy peer.recheck rejection dropped the later local peer first.
        peer: Option<PublicApiPeer>,
        stream: TlsStream<IO>,
        original: OriginalV1,
    },
    Authenticated(AuthenticatedPublicApiStream<IO>),
    Transferred,
}

pub(super) struct CompletedAdmissionV1<IO> {
    pub(super) state: CompletedAdmissionStateV1<IO>,
}

impl<IO> CompletedAdmissionV1<IO> {
    pub(super) fn new(stream: TlsStream<IO>, original: OriginalV1) -> Self {
        Self {
            state: CompletedAdmissionStateV1::Pending {
                peer: None,
                stream,
                original,
            },
        }
    }

    // Exclusive states prevent retaining a second copy of the TLS stream.
    pub(super) fn authenticate(&mut self) -> Result<(), PublicApiSessionError> {
        let state = std::mem::replace(&mut self.state, CompletedAdmissionStateV1::Transferred);
        match state {
            CompletedAdmissionStateV1::Pending {
                peer: Some(peer),
                stream,
                original: _,
            } => {
                self.state = CompletedAdmissionStateV1::Authenticated(
                    AuthenticatedPublicApiStream::new(stream, peer),
                );
                Ok(())
            }
            state => {
                self.state = state;
                Err(PublicApiSessionError::Authentication)
            }
        }
    }

    pub(super) fn into_authenticated(
        self,
    ) -> Result<AuthenticatedPublicApiStream<IO>, PublicApiSessionError> {
        match self.state {
            CompletedAdmissionStateV1::Authenticated(stream) => Ok(stream),
            _ => Err(PublicApiSessionError::Authentication),
        }
    }
}

#[cfg(target_os = "linux")]
mod tcp {
    //! Retains the actual fixed acceptor and one original TCP/TLS flight.

    use std::future::poll_fn;
    use std::os::fd::AsFd as _;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::net::TcpStream;
    use tokio::time::{Instant, error::Elapsed};
    use tokio_rustls::server::RetainedAccept;

    use super::{CompletedAdmissionStateV1, CompletedAdmissionV1};
    use crate::public_api_session::socket::OriginalPublicSocketErrorV1;
    use crate::public_api_session::{
        AuthenticatedPublicApiStream, GitPublicTransportShutdownErrorV1,
        PublicApiOriginalSocketErrorV1, PublicApiPeer, PublicApiSessionAcceptor,
        PublicApiSessionError, HANDSHAKE_TIMEOUT,
        socket::OriginalPublicSocketV1,
    };

    /// Names a terminal interruption without allocating a replacement error.
    #[derive(Clone, Copy)]
    pub(crate) enum HandshakeInterruptionV1 {
        Cancelled,
        Unwound,
        Abandoned,
    }

    /// Borrows the original terminal cause without replacing provider errors.
    pub(crate) enum RetainedPublicTcpCauseV1<'a> {
        Socket(&'a OriginalPublicSocketErrorV1),
        OriginalSocket(&'a PublicApiOriginalSocketErrorV1),
        Session(&'a PublicApiSessionError),
        Tls(&'a std::io::Error),
        Timeout(&'a Elapsed),
        Interrupted(HandshakeInterruptionV1),
    }

    enum FailureV1 {
        Socket(OriginalPublicSocketErrorV1),
        OriginalSocket(PublicApiOriginalSocketErrorV1),
        Session(PublicApiSessionError),
        Tls,
        Timeout(Elapsed),
        Interrupted(HandshakeInterruptionV1),
    }

    enum PhaseV1 {
        Raw(Option<TcpStream>),
        Tls(RetainedAccept<TcpStream>),
        Admission(CompletedAdmissionV1<TcpStream>),
        Transferred,
    }

    /// Retains one actual raw/TLS/admission owner, including failed state.
    pub(crate) struct RetainedPublicTcpHandshakeV1 {
        acceptor: Arc<PublicApiSessionAcceptor>,
        phase: PhaseV1,
        original: Option<OriginalPublicSocketV1>,
        deadline: Option<Instant>,
        failure: Option<FailureV1>,
        ended: bool,
        shutdown_debt: Option<GitPublicTransportShutdownErrorV1>,
    }

    impl RetainedPublicTcpHandshakeV1 {
        /// Parks the actual TCP owner before any fallible protected observation.
        pub(crate) fn begin(socket: TcpStream, acceptor: Arc<PublicApiSessionAcceptor>) -> Self {
            // Park the original before capture, credentials or session construction.
            let mut owner = Self {
                acceptor,
                phase: PhaseV1::Raw(Some(socket)),
                original: None,
                deadline: None,
                failure: None,
                ended: false,
                shutdown_debt: None,
            };
            owner.initialize();
            owner
        }

        fn initialize(&mut self) {
            let PhaseV1::Raw(Some(socket)) = &self.phase else {
                return;
            };
            match OriginalPublicSocketV1::capture(socket.as_fd()) {
                Ok(original) => self.original = Some(original),
                Err(cause) => {
                    self.failure = Some(FailureV1::Socket(cause));
                    self.end_transport();
                    return;
                }
            }
            if let Err(cause) = self.acceptor.credentials.recheck() {
                self.failure = Some(FailureV1::Session(cause));
                self.end_transport();
                return;
            }

            if let PhaseV1::Raw(socket) = &mut self.phase {
                if let Some(socket) = socket.take() {
                    self.phase = PhaseV1::Tls(self.acceptor.acceptor.accept_retained(socket));
                    // Legacy timeout captures its cut after session construction.
                    self.deadline = Some(Instant::now() + HANDSHAKE_TIMEOUT);
                }
            }
        }

        /// Loans the actual stage to the original fixed timeout, never its IO.
        ///
        /// # Errors
        /// Returns a marker while the actual first cause remains borrowed.
        ///
        /// # Panics
        /// Tokio requires a time-enabled runtime; provider panics are not recovered.
        pub(crate) async fn admit(&mut self) -> Result<(), ()> {
            if self.failure.is_some() || self.ended {
                return Err(());
            }
            let Some(deadline) = self.deadline else {
                return Err(());
            };
            let result = tokio::time::timeout_at(
                deadline,
                poll_fn(|context| self.poll_tls(context)),
            )
            .await;
            match result {
                Ok(result) => result,
                Err(cause) => {
                    if self.failure.is_none() {
                        self.failure = Some(FailureV1::Timeout(cause));
                    }
                    self.end_transport();
                    Err(())
                }
            }
        }

        fn poll_tls(&mut self, context: &mut Context<'_>) -> Poll<Result<(), ()>> {
            if self.failure.is_some() || self.ended {
                return Poll::Ready(Err(()));
            }
            let PhaseV1::Tls(tls) = &mut self.phase else {
                return Poll::Ready(Err(()));
            };
            match Pin::new(tls).poll_accept(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_marker)) => {
                    // The actual error stays inside the resident provider owner.
                    self.failure = Some(FailureV1::Tls);
                    self.end_transport();
                    return Poll::Ready(Err(()));
                }
                Poll::Ready(Ok(stream)) => {
                    self.phase = PhaseV1::Admission(
                        CompletedAdmissionV1::new(stream, self.original.take()),
                    );
                }
            }

            let PhaseV1::Admission(admission) = &mut self.phase else {
                return Poll::Ready(Err(()));
            };
            if let Err(cause) = self.acceptor.admit_completed(admission) {
                self.failure = Some(FailureV1::Session(cause));
                self.end_transport();
                return Poll::Ready(Err(()));
            }
            Poll::Ready(Ok(()))
        }

        /// Moves only the genuinely admitted stream after its original-socket check.
        ///
        /// # Errors
        /// Rejects ended/unadmitted state or the actual original-socket failure,
        /// retaining the stream and cause in this owner on rejection.
        pub(crate) fn take_authenticated(
            &mut self,
        ) -> Result<AuthenticatedPublicApiStream<TcpStream>, ()> {
            if self.failure.is_some() || self.ended {
                return Err(());
            }
            let PhaseV1::Admission(admission) = &self.phase else {
                return Err(());
            };
            let CompletedAdmissionStateV1::Authenticated(stream) = &admission.state else {
                return Err(());
            };
            if let Err(cause) = stream.peer().recheck_original_socket() {
                self.failure = Some(FailureV1::OriginalSocket(cause));
                self.end_transport();
                return Err(());
            }
            let state = std::mem::replace(&mut self.phase, PhaseV1::Transferred);
            match state {
                PhaseV1::Admission(admission) => admission.into_authenticated().map_err(|_| ()),
                state => {
                    self.phase = state;
                    Err(())
                }
            }
        }

        /// Borrows its first actual cause without moving the failed provider.
        pub(crate) fn failure(&self) -> Option<RetainedPublicTcpCauseV1<'_>> {
            match self.failure.as_ref()? {
                FailureV1::Socket(cause) => Some(RetainedPublicTcpCauseV1::Socket(cause)),
                FailureV1::OriginalSocket(cause) => {
                    Some(RetainedPublicTcpCauseV1::OriginalSocket(cause))
                }
                FailureV1::Session(cause) => Some(RetainedPublicTcpCauseV1::Session(cause)),
                FailureV1::Timeout(cause) => Some(RetainedPublicTcpCauseV1::Timeout(cause)),
                FailureV1::Interrupted(kind) => Some(RetainedPublicTcpCauseV1::Interrupted(*kind)),
                FailureV1::Tls => match &self.phase {
                    PhaseV1::Tls(tls) => tls.error().map(RetainedPublicTcpCauseV1::Tls),
                    _ => None,
                },
            }
        }

        /// Ends once without overwriting an earlier actual first cause.
        pub(crate) fn interrupt(&mut self, kind: HandshakeInterruptionV1) {
            if self.failure.is_none() {
                self.failure = Some(FailureV1::Interrupted(kind));
            }
            self.end_transport();
        }

        fn peer(&self) -> Option<&PublicApiPeer> {
            match &self.phase {
                PhaseV1::Admission(admission) => match &admission.state {
                    CompletedAdmissionStateV1::Pending { peer, .. } => peer.as_ref(),
                    CompletedAdmissionStateV1::Authenticated(stream) => Some(stream.peer()),
                    CompletedAdmissionStateV1::Transferred => None,
                },
                _ => None,
            }
        }

        fn end_transport(&mut self) {
            if self.ended {
                return;
            }
            self.ended = true;
            // Completed TLS parks the original in admission before creating a peer.
            let original = self.original.as_ref().or_else(|| match &self.phase {
                PhaseV1::Admission(admission) => match &admission.state {
                    CompletedAdmissionStateV1::Pending { original, .. } => original.as_ref(),
                    _ => None,
                },
                _ => None,
            });
            self.shutdown_debt = if let Some(peer) = self.peer() {
                peer.end_original_git_transport().err()
            } else if let Some(original) = original {
                original.end_original().err()
                    .map(GitPublicTransportShutdownErrorV1::Shutdown)
            } else {
                // Even failed capture must not dispose the genuine raw stream.
                let descriptor = match &self.phase {
                    PhaseV1::Raw(Some(socket)) => Some(socket.as_fd()),
                    PhaseV1::Tls(tls) => tls.get_ref().map(|socket| socket.as_fd()),
                    PhaseV1::Admission(admission) => match &admission.state {
                        CompletedAdmissionStateV1::Pending { stream, .. } => {
                            Some(stream.get_ref().0.as_fd())
                        }
                        _ => None,
                    },
                    _ => None,
                };
                descriptor.and_then(|descriptor| {
                    rustix::net::shutdown(descriptor, rustix::net::Shutdown::Both)
                        .err()
                        .map(GitPublicTransportShutdownErrorV1::Shutdown)
                })
            };
        }

        /// Borrows separate shutdown debt, which grants no drain acknowledgement.
        pub(crate) fn shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
            self.shutdown_debt.as_ref()
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use tcp::{
    HandshakeInterruptionV1, RetainedPublicTcpCauseV1, RetainedPublicTcpHandshakeV1,
};

#[cfg(test)]
mod tests;

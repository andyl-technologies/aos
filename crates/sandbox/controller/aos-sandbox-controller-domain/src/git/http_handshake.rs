//! Keeps the actual pre-H2 TLS owner and H2 future across borrowed-driver loss.
//!
//! This dormant path has no owning Gateway registry, listener, funding or drain
//! authority. Failed/pending state must remain in caller custody. Discarded
//! provider bytes and universal unwind recovery are not promised.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::public_api_session::{
    AuthenticatedPublicApiStream, GitPublicTransportShutdownErrorV1,
    HandshakeInterruptionV1, PublicApiPeer, PublicApiSessionAcceptor,
    RetainedPublicTcpCauseV1, RetainedPublicTcpHandshakeV1,
};

use super::http_owner::{GitHttpConnectionV1, GitHttpErrorV1, fixed_handshake};

type OriginalHandshakeV1 =
    h2::server::Handshake<AuthenticatedPublicApiStream<TcpStream>, Bytes>;

enum FirstFailureV1 {
    Tls,
    Actual(GitHttpErrorV1),
    Formed,
    Interrupted(HandshakeInterruptionV1),
}

enum PhaseV1 {
    Tls,
    H2 {
        handshake: Pin<Box<OriginalHandshakeV1>>,
        peer: PublicApiPeer,
        deadline: Instant,
    },
    Formed(GitHttpConnectionV1),
    Transferred,
}

/// Marks terminal rejection while the actual cause stays in the owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GitHttpHandshakeFailedV1;

/// Borrows the original terminal cause, never a reconstructed IO error.
pub(crate) enum GitHttpHandshakeCauseV1<'a> {
    Tls(RetainedPublicTcpCauseV1<'a>),
    Actual(&'a GitHttpErrorV1),
    Interrupted(HandshakeInterruptionV1),
}

/// Owns one concrete TCP/TLS/H2 flight, not a future that moves its transport.
pub(crate) struct GitHttpHandshakeOwnerV1 {
    tls: RetainedPublicTcpHandshakeV1,
    phase: PhaseV1,
    failure: Option<FirstFailureV1>,
    ended: bool,
    transferred: bool,
    shutdown_debt: Option<GitPublicTransportShutdownErrorV1>,
}

impl GitHttpHandshakeOwnerV1 {
    pub(super) fn begin(socket: TcpStream, acceptor: Arc<PublicApiSessionAcceptor>) -> Self {
        Self {
            tls: RetainedPublicTcpHandshakeV1::begin(socket, acceptor),
            phase: PhaseV1::Tls,
            failure: None,
            ended: false,
            transferred: false,
            shutdown_debt: None,
        }
    }

    /// Returns an already armed loan; dropping it never drops resident IO.
    ///
    /// # Errors
    ///
    /// Returns a marker for actual TLS/session/socket/H2/timeout failure or an
    /// already ended owner. Inspect the separate borrowed first-cause view.
    ///
    /// # Panics
    ///
    /// Tokio timers require a time-enabled runtime. Provider panics are not
    /// recovered; fields still resident are ended, not certified resumable.
    pub(crate) fn drive(
        &mut self,
    ) -> impl Future<Output = Result<(), GitHttpHandshakeFailedV1>> + '_ {
        // This guard exists before the async value is returned, even unpolled.
        let mut attempt = HandshakeAttemptV1 { owner: self, armed: true };
        // The method receiver captures the whole Drop guard, not individual fields.
        async move { attempt.run().await }
    }

    async fn drive_original(&mut self) -> Result<(), GitHttpHandshakeFailedV1> {
        if self.ended || self.failure.is_some() {
            return Err(GitHttpHandshakeFailedV1);
        }
        if matches!(self.phase, PhaseV1::Formed(_)) {
            return Ok(());
        }

        if matches!(self.phase, PhaseV1::Tls) {
            if self.tls.admit().await.is_err() {
                self.failure = Some(FirstFailureV1::Tls);
                self.end(HandshakeInterruptionV1::Abandoned);
                return Err(GitHttpHandshakeFailedV1);
            }
            let transport = match self.tls.take_authenticated() {
                Ok(transport) => transport,
                Err(()) => {
                    self.failure = Some(FirstFailureV1::Tls);
                    self.end(HandshakeInterruptionV1::Abandoned);
                    return Err(GitHttpHandshakeFailedV1);
                }
            };
            let peer = transport.peer().clone();
            let handshake = Box::pin(fixed_handshake(transport));
            self.phase = PhaseV1::H2 {
                handshake,
                peer,
                deadline: Instant::now() + Duration::from_secs(10),
            };
        }

        let PhaseV1::H2 { deadline, .. } = &self.phase else {
            self.end(HandshakeInterruptionV1::Abandoned);
            return Err(GitHttpHandshakeFailedV1);
        };
        let deadline = *deadline;
        match tokio::time::timeout_at(deadline, poll_fn(|context| self.poll_h2(context))).await {
            Ok(result) => result,
            Err(cause) => {
                if self.failure.is_none() {
                    self.failure = Some(FirstFailureV1::Actual(GitHttpErrorV1::Timeout(cause)));
                }
                self.end(HandshakeInterruptionV1::Abandoned);
                Err(GitHttpHandshakeFailedV1)
            }
        }
    }

    fn poll_h2(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), GitHttpHandshakeFailedV1>> {
        let PhaseV1::H2 { handshake, peer, .. } = &mut self.phase else {
            return Poll::Ready(Err(GitHttpHandshakeFailedV1));
        };
        let connection = match handshake.as_mut().poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(cause)) => {
                // Never repoll a failed engine or discard its actual codec/IO.
                self.failure = Some(FirstFailureV1::Actual(GitHttpErrorV1::Transport(cause)));
                self.end(HandshakeInterruptionV1::Abandoned);
                return Poll::Ready(Err(GitHttpHandshakeFailedV1));
            }
            Poll::Ready(Ok(connection)) => connection,
        };

        // The clone shares the actual active marker, not authentication state.
        let formed = GitHttpConnectionV1::from_handshake(connection, peer.clone());
        let rejected = formed.handshake_rejected();
        self.phase = PhaseV1::Formed(formed);
        if rejected {
            self.failure = Some(FirstFailureV1::Formed);
            self.end(HandshakeInterruptionV1::Abandoned);
            return Poll::Ready(Err(GitHttpHandshakeFailedV1));
        }
        Poll::Ready(Ok(()))
    }

    /// Borrows the first actual cause after the drive loan has been released.
    pub(crate) fn failure(&self) -> Option<GitHttpHandshakeCauseV1<'_>> {
        match self.failure.as_ref()? {
            FirstFailureV1::Tls => self.tls.failure().map(GitHttpHandshakeCauseV1::Tls),
            FirstFailureV1::Actual(cause) => Some(GitHttpHandshakeCauseV1::Actual(cause)),
            FirstFailureV1::Formed => match &self.phase {
                PhaseV1::Formed(formed) => formed
                    .handshake_cause()
                    .map(GitHttpHandshakeCauseV1::Actual),
                _ => None,
            },
            FirstFailureV1::Interrupted(kind) => Some(GitHttpHandshakeCauseV1::Interrupted(*kind)),
        }
    }

    /// Borrows separate shutdown debt without treating it as transport drain.
    pub(crate) fn shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
        self.shutdown_debt
            .as_ref()
            .or_else(|| match &self.phase {
                PhaseV1::Formed(formed) => formed.handshake_shutdown_debt(),
                _ => None,
            })
            .or_else(|| self.tls.shutdown_debt())
    }

    /// Moves the sole successfully formed owner, or retains the entire ended flight.
    ///
    /// # Errors
    ///
    /// Returns intact ended custody if the original handshake is incomplete or
    /// rejected. No failed IO/session extraction, retry or authority is provided.
    pub(crate) fn try_into_formed(
        mut self,
    ) -> Result<GitHttpConnectionV1, RetainedGitHttpHandshakeCustodyV1> {
        if !self.ended && self.failure.is_none() {
            if let PhaseV1::Formed(formed) = &mut self.phase {
                formed.recheck_handshake();
                if formed.handshake_rejected() {
                    self.failure = Some(FirstFailureV1::Formed);
                    self.end(HandshakeInterruptionV1::Abandoned);
                }
            }
        }
        if !self.ended
            && self.failure.is_none()
            && matches!(self.phase, PhaseV1::Formed(_))
        {
            let phase = std::mem::replace(&mut self.phase, PhaseV1::Transferred);
            if let PhaseV1::Formed(formed) = phase {
                self.transferred = true;
                return Ok(formed);
            }
        }
        self.end(HandshakeInterruptionV1::Abandoned);
        Err(RetainedGitHttpHandshakeCustodyV1 { owner: self })
    }

    fn end(&mut self, kind: HandshakeInterruptionV1) {
        if self.ended || self.transferred {
            return;
        }
        self.ended = true;
        if let PhaseV1::Formed(formed) = &mut self.phase {
            if self.failure.is_none() {
                self.failure = Some(FirstFailureV1::Interrupted(kind));
            }
            formed.interrupt_handshake(kind);
        } else if let PhaseV1::H2 { peer, .. } = &self.phase {
            if self.failure.is_none() {
                self.failure = Some(FirstFailureV1::Interrupted(kind));
            }
            self.shutdown_debt = peer.end_original_git_transport().err();
        } else {
            self.tls.interrupt(kind);
            if self.failure.is_none() {
                self.failure = Some(FirstFailureV1::Tls);
            }
        }
    }
}

impl Drop for GitHttpHandshakeOwnerV1 {
    fn drop(&mut self) {
        self.end(HandshakeInterruptionV1::Abandoned);
    }
}

struct HandshakeAttemptV1<'a> {
    owner: &'a mut GitHttpHandshakeOwnerV1,
    armed: bool,
}

impl HandshakeAttemptV1<'_> {
    async fn run(&mut self) -> Result<(), GitHttpHandshakeFailedV1> {
        let result = self.owner.drive_original().await;
        self.armed = false;
        result
    }
}

impl Drop for HandshakeAttemptV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            let kind = if std::thread::panicking() {
                HandshakeInterruptionV1::Unwound
            } else {
                HandshakeInterruptionV1::Cancelled
            };
            self.owner.end(kind);
        }
    }
}

/// Retains a whole ended flight; dropping it still drops the original IO.
pub(crate) struct RetainedGitHttpHandshakeCustodyV1 {
    owner: GitHttpHandshakeOwnerV1,
}

impl RetainedGitHttpHandshakeCustodyV1 {
    /// Borrows its original first cause without exposing transport extraction.
    pub(crate) fn failure(&self) -> Option<GitHttpHandshakeCauseV1<'_>> {
        self.owner.failure()
    }

    /// Borrows shutdown debt, which is not an all-owner drain acknowledgement.
    pub(crate) fn shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
        self.owner.shutdown_debt()
    }
}

#[cfg(test)]
mod tests;

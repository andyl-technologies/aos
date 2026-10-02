//! Owns one actual, funded pre-effect TCP/TLS/H2 request flight.
//!
//! This dormant registry loads the fixed acceptor and borrows a genuine listener.
//! It does not validate deployment ingress, run Git, expose effect handles, or
//! issue remote/child/ODB drain receipts. Explicit local disposal destroys the
//! actual transport graph before local funding is released. It intentionally
//! ends in-memory cause/byte retention, not durable recovery custody.

use std::future::Future;
use std::io;
use std::sync::Arc;

use aos_sandbox_core::{PrincipalId, ProjectId};
use tokio::net::TcpListener;

use crate::public_api_session::{
    GitPublicTransportShutdownErrorV1, PublicApiSessionAcceptor, PublicApiSessionError,
};

use super::gateway_funding::{GatewayFundingErrorV1, GatewayFundingV1};
use super::http_handshake::{
    GitHttpHandshakeCauseV1, GitHttpHandshakeOwnerV1, RetainedGitHttpHandshakeCustodyV1,
};
use super::http_owner::{
    GitHttpConnectionV1, GitHttpErrorV1, GitHttpRequestV1, RetainedGitHttpConnectionCustodyV1,
};
use super::{GitChannelBindingDigestV1, GitSmartRequestV1};
use super::delegated_read::{GitDelegatedClientV1, NegativeGitResponseV1};

enum EntryV1 {
    Handshake(GitHttpHandshakeOwnerV1),
    Formed(GitHttpConnectionV1),
    EndedHandshake(RetainedGitHttpHandshakeCustodyV1),
    EndedConnection(RetainedGitHttpConnectionCustodyV1),
}

enum LocalFailureV1 {
    Funding(GatewayFundingErrorV1),
    Accept(io::Error),
}

/// Marks failure without moving its actual cause or transport out of registry.
#[derive(Clone, Copy, Debug)]
pub(super) struct GatewayTransportFailedV1;

/// Borrows resident causes without exposing peer, IO, FD or response owners.
pub(super) enum GatewayTransportCauseV1<'a> {
    Funding(&'a GatewayFundingErrorV1),
    Accept(&'a io::Error),
    Handshake(GitHttpHandshakeCauseV1<'a>),
    Formed(Option<&'a GitHttpErrorV1>),
    NegativeDelivery(&'a (dyn std::error::Error + 'static)),
}

/// Describes explicit local disposal, never a peer or protected Drain ACK.
pub(super) struct LocalTransportDisposedV1 {
    shutdown_debt_observed: bool,
}

impl LocalTransportDisposedV1 {
    pub(super) const fn shutdown_debt_observed(&self) -> bool {
        self.shutdown_debt_observed
    }
}

/// Retains every original and its local funding across failed driving loans.
pub(super) struct GatewayTransportRegistryV1 {
    acceptor: Arc<PublicApiSessionAcceptor>,
    entry: Option<EntryV1>,
    funding: GatewayFundingV1,
    failure: Option<LocalFailureV1>,
    retirement_debt: Option<GatewayFundingErrorV1>,
    delegated_read: bool,
    delegation: Option<GitDelegatedClientV1>,
}

impl GatewayTransportRegistryV1 {
    /// Loads the genuine fixed credentials, without a caller configuration.
    ///
    /// # Errors
    /// Preserves fixed credential, certificate and registration rejection.
    pub(super) fn from_systemd_credentials() -> Result<Self, PublicApiSessionError> {
        Ok(Self::from_fixed_acceptor(Arc::new(
            PublicApiSessionAcceptor::from_systemd_credentials()?,
        )))
    }

    // Only the fixed constructor and genuine service owner share this acceptor.
    // This private seam neither admits caller trust nor duplicates originals.
    pub(super) fn from_fixed_acceptor(acceptor: Arc<PublicApiSessionAcceptor>) -> Self {
        Self {
            acceptor,
            entry: None,
            funding: GatewayFundingV1::new(),
            failure: None,
            retirement_debt: None,
            delegated_read: false,
            delegation: None,
        }
    }

    pub(super) fn select_delegated_read(&mut self) {
        if self.entry.is_none() && self.funding.is_vacant() {
            self.delegated_read = true;
        }
    }

    /// Funds actual backing before polling the original listener acceptance.
    ///
    /// This accepts transport only. A borrowed listener is not PID1, endpoint,
    /// role or service-envelope authority. Returned failures retain funding.
    ///
    /// # Errors
    /// Returns a marker for occupancy, actual funding/allocation or accept error.
    ///
    /// # Panics
    /// Tokio networking requires a reactor; provider panics are not recovered.
    pub(super) fn accept_original<'a>(
        &'a mut self,
        listener: &'a TcpListener,
    ) -> impl Future<Output = Result<(), GatewayTransportFailedV1>> + 'a {
        let prepared = self.entry.is_none()
            && self.failure.is_none()
            && self.retirement_debt.is_none()
            && self.funding.is_vacant();
        let armed = if prepared {
            match self.funding.prepare() {
                Ok(()) => true,
                Err(cause) => {
                    self.failure = Some(LocalFailureV1::Funding(cause));
                    false
                }
            }
        } else {
            false
        };
        let attempt = AcceptAttemptV1 { registry: self, armed };
        async move { attempt.run(listener).await }
    }

    /// Loans the one resident retained handshake; cancellation retains it.
    ///
    /// # Errors
    /// Rejects non-handshake state or the actual first handshake failure.
    ///
    /// # Panics
    /// Tokio requires a time-enabled runtime; provider panics are not recovered.
    pub(super) fn drive_handshake(
        &mut self,
    ) -> impl Future<Output = Result<(), GatewayTransportFailedV1>> + '_ {
        let armed = matches!(self.entry, Some(EntryV1::Handshake(_)));
        let attempt = HandshakeAttemptV1 { registry: self, armed };
        async move { attempt.run().await }
    }

    /// Parks the funded allocation synchronously and loans the one receive engine.
    ///
    /// # Errors
    /// Rejects wrong state, reused backing or actual original receive failure.
    /// The READY loan never exposes a cloneable peer or a response/effect handle.
    ///
    /// # Panics
    /// Tokio requires a time-enabled runtime; an h2 internal lock may panic.
    pub(super) fn receive_original(
        &mut self,
    ) -> impl Future<Output = Result<GatewayReadyLoanV1<'_>, GatewayTransportFailedV1>> + '_ {
        let armed = matches!(self.entry, Some(EntryV1::Formed(_)));
        let prepared = if let Some(EntryV1::Formed(owner)) = &mut self.entry {
            match self.funding.take_backing() {
                Ok(backing) => match owner.park_funded_body(backing) {
                    Ok(()) => true,
                    Err(backing) => {
                        self.funding.restore_backing(backing);
                        false
                    }
                },
                Err(cause) => {
                    if self.failure.is_none() {
                        self.failure = Some(LocalFailureV1::Funding(cause));
                    }
                    false
                }
            }
        } else {
            false
        };
        let attempt = ReceiveAttemptV1 { registry: Some(self), armed, prepared };
        async move { attempt.run().await }
    }

    /// Borrows the actual terminal cause while the whole graph remains resident.
    pub(super) fn failure(&self) -> Option<GatewayTransportCauseV1<'_>> {
        match &self.entry {
            Some(EntryV1::Handshake(owner)) => {
                if let Some(cause) = owner.failure() {
                    return Some(GatewayTransportCauseV1::Handshake(cause));
                }
            }
            Some(EntryV1::EndedHandshake(owner)) => {
                if let Some(cause) = owner.failure() {
                    return Some(GatewayTransportCauseV1::Handshake(cause));
                }
            }
            Some(EntryV1::Formed(owner)) if owner.handshake_rejected() => {
                return Some(GatewayTransportCauseV1::Formed(owner.handshake_cause()));
            }
            Some(EntryV1::EndedConnection(owner)) => {
                if let Some(cause) = owner.negative_delivery_failure() {
                    return Some(GatewayTransportCauseV1::NegativeDelivery(cause));
                }
                return Some(GatewayTransportCauseV1::Formed(owner.actual_cause()));
            }
            _ => {}
        }
        match self.failure.as_ref()? {
            LocalFailureV1::Funding(cause) => Some(GatewayTransportCauseV1::Funding(cause)),
            LocalFailureV1::Accept(cause) => Some(GatewayTransportCauseV1::Accept(cause)),
        }
    }

    /// Borrows separate shutdown debt, which never releases funding by itself.
    pub(super) fn shutdown_debt(&self) -> Option<&GitPublicTransportShutdownErrorV1> {
        match &self.entry {
            Some(EntryV1::Handshake(owner)) => owner.shutdown_debt(),
            Some(EntryV1::Formed(owner)) => owner.handshake_shutdown_debt(),
            Some(EntryV1::EndedHandshake(owner)) => owner.shutdown_debt(),
            Some(EntryV1::EndedConnection(owner)) => owner.shutdown_debt(),
            None => None,
        }
    }

    /// Borrows a failed accounting release; it permanently closes this registry.
    pub(super) fn retirement_debt(&self) -> Option<&GatewayFundingErrorV1> {
        self.retirement_debt.as_ref()
    }

    /// Explicitly destroys the known transport-only graph before capacity reuse.
    ///
    /// All driving/request loans must have ended. No peer/FD/IO escapes this
    /// interface, and no child/effect/export enters this registry. This consumes
    /// in-memory diagnostics and bytes; the result is local DATA, not Drain.
    ///
    /// # Errors
    /// Retains accounting-release failure and refuses later acceptance.
    pub(super) fn dispose_local(
        &mut self,
    ) -> Result<LocalTransportDisposedV1, GatewayTransportFailedV1> {
        self.end_handshake();
        self.end_connection();
        let shutdown_debt_observed = self.shutdown_debt().is_some()
            || self.delegation.as_ref().is_some_and(|owner| owner.shutdown_debt_observed());

        // Destruction precedes release, including all internal peer/FD clones.
        drop(self.entry.take());
        drop(self.failure.take());
        drop(self.delegation.take());
        match self.funding.release_destroyed() {
            Ok(()) => Ok(LocalTransportDisposedV1 { shutdown_debt_observed }),
            Err(cause) => {
                if self.retirement_debt.is_none() {
                    self.retirement_debt = Some(cause);
                }
                Err(GatewayTransportFailedV1)
            }
        }
    }

    fn end_handshake(&mut self) {
        if let Some(EntryV1::Handshake(owner)) = &mut self.entry {
            // Construct/drop the accepted unpolled guard to preserve its real
            // cancellation cause; never invent a replacement io::Error.
            drop(owner.drive());
        } else {
            return;
        }
        if let Some(EntryV1::Handshake(owner)) = self.entry.take() {
            self.entry = Some(match owner.try_into_formed() {
                Ok(owner) => EntryV1::EndedConnection(owner.into_retained_custody()),
                Err(owner) => EntryV1::EndedHandshake(owner),
            });
        }
    }

    fn end_connection(&mut self) {
        if matches!(self.entry, Some(EntryV1::Formed(_))) {
            if let Some(EntryV1::Formed(owner)) = self.entry.take() {
                self.entry = Some(EntryV1::EndedConnection(owner.into_retained_custody()));
            }
        }
    }
}

struct AcceptAttemptV1<'a> {
    registry: &'a mut GatewayTransportRegistryV1,
    armed: bool,
}

impl AcceptAttemptV1<'_> {
    async fn run(mut self, listener: &TcpListener) -> Result<(), GatewayTransportFailedV1> {
        if !self.armed {
            return Err(GatewayTransportFailedV1);
        }
        match listener.accept().await {
            Ok((socket, _address)) => {
                // No fallible funding transition or await precedes parking.
                self.registry.entry = Some(EntryV1::Handshake(
                    GitHttpConnectionV1::begin_retained_handshake(
                        socket, Arc::clone(&self.registry.acceptor),
                    ),
                ));
                if let Err(cause) = self.registry.funding.commit() {
                    self.registry.failure = Some(LocalFailureV1::Funding(cause));
                    self.registry.end_handshake();
                    self.armed = false;
                    return Err(GatewayTransportFailedV1);
                }
            }
            Err(cause) => {
                self.registry.failure = Some(LocalFailureV1::Accept(cause));
                self.armed = false;
                return Err(GatewayTransportFailedV1);
            }
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for AcceptAttemptV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            if self.registry.entry.is_none() {
                // Cancel-before-accept has no original transport to retain.
                if let Err(cause) = self.registry.funding.release_destroyed() {
                    self.registry.retirement_debt = Some(cause);
                }
            } else {
                self.registry.end_handshake();
            }
        }
    }
}

struct HandshakeAttemptV1<'a> {
    registry: &'a mut GatewayTransportRegistryV1,
    armed: bool,
}

impl HandshakeAttemptV1<'_> {
    async fn run(mut self) -> Result<(), GatewayTransportFailedV1> {
        if !self.armed {
            return Err(GatewayTransportFailedV1);
        }
        if let Some(EntryV1::Handshake(owner)) = &mut self.registry.entry {
            let _result = owner.drive().await;
        }
        // Only a finished loan is followed by the success/failure ownership move.
        let result = match self.registry.entry.take() {
            Some(EntryV1::Handshake(owner)) => match owner.try_into_formed() {
                Ok(owner) => {
                    self.registry.entry = Some(EntryV1::Formed(owner));
                    Ok(())
                }
                Err(owner) => {
                    self.registry.entry = Some(EntryV1::EndedHandshake(owner));
                    Err(GatewayTransportFailedV1)
                }
            },
            entry => {
                self.registry.entry = entry;
                Err(GatewayTransportFailedV1)
            }
        };
        self.armed = false;
        result
    }
}

impl Drop for HandshakeAttemptV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.registry.end_handshake();
        }
    }
}

struct ReceiveAttemptV1<'a> {
    registry: Option<&'a mut GatewayTransportRegistryV1>,
    armed: bool,
    prepared: bool,
}

impl<'a> ReceiveAttemptV1<'a> {
    async fn run(mut self) -> Result<GatewayReadyLoanV1<'a>, GatewayTransportFailedV1> {
        if !self.prepared {
            return Err(GatewayTransportFailedV1);
        }
        let facts = match self.registry.as_mut() {
            Some(registry) => match &mut registry.entry {
                Some(EntryV1::Formed(owner)) => {
                    if registry.delegated_read { owner.select_delegated_read(); }
                    owner.receive_ready_facts().await
                }
                _ => return Err(GatewayTransportFailedV1),
            },
            None => return Err(GatewayTransportFailedV1),
        };
        // The Copy facts end the driving loan before the actual READY borrow.
        let registry = self.registry.take().ok_or(GatewayTransportFailedV1)?;
        self.armed = false;
        match &mut registry.entry {
            Some(EntryV1::Formed(owner)) => owner.ready_view(facts)
                .map(|request| GatewayReadyLoanV1 { request, delegation: &mut registry.delegation })
                .map_err(|_failure| GatewayTransportFailedV1),
            _ => Err(GatewayTransportFailedV1),
        }
    }
}

impl Drop for ReceiveAttemptV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Some(registry) = &mut self.registry {
                registry.end_connection();
            }
        }
    }
}

/// Loans only actual original request DATA and its existing bookend engine.
pub(super) struct GatewayReadyLoanV1<'a> {
    request: GitHttpRequestV1<'a>,
    delegation: &'a mut Option<GitDelegatedClientV1>,
}

impl GatewayReadyLoanV1<'_> {
    pub(super) async fn inspect_delegated(
        &mut self,
        admission: &super::gateway_service::startup::GatewayAdmissionV1,
    ) -> Result<(), super::gateway_service::GitGatewayServiceErrorV1> {
        use super::gateway_service::GitGatewayServiceErrorV1 as Error;

        let (_, basic) = self.request.delegated_input().ok_or(Error::Runtime)?;
        let negative = if basic.handle().is_none() {
            basic.negative()
        } else {
            let (uid, gid) = admission.delegation_controller_ids().ok_or(Error::Configuration)?;
            if self.delegation.is_some() { return Err(Error::Runtime); }
            *self.delegation = Some(GitDelegatedClientV1::new(uid, gid));
            let client = self.delegation.as_mut().ok_or(Error::Runtime)?;
            match client.inspect(&mut self.request, admission).await {
                Ok(negative) => negative,
                Err(_) => {
                    let _queued = self.request.send_negative(NegativeGitResponseV1::Unavailable).await;
                    return Err(Error::Runtime);
                }
            }
        };
        self.request.send_negative(negative).await.map_err(|_| Error::Runtime)
    }
    pub(super) fn principal(&self) -> PrincipalId {
        self.request.peer().principal()
    }

    pub(super) fn project(&self) -> ProjectId {
        self.request.peer().project()
    }

    pub(super) fn request(&self) -> GitSmartRequestV1 {
        self.request.request()
    }

    pub(super) fn binding(&self) -> GitChannelBindingDigestV1 {
        self.request.binding()
    }

    pub(super) fn body(&self) -> &[u8] {
        self.request.body()
    }

    /// Reuses the same request/socket/session/clock/reset comparisons.
    ///
    /// # Errors
    /// Preserves existing actual first cause and ends the same original.
    ///
    /// # Panics
    /// An h2 internal lock may panic; universal recovery is not promised.
    pub(super) async fn recheck(&mut self) -> Result<(), GitHttpErrorV1> {
        self.request.recheck().await
    }

    /// Loans the same current original checks without an immediately ready loop.
    pub(super) fn poll_while_child_parked(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<std::convert::Infallible, GitHttpErrorV1>> {
        self.request.poll_while_child_parked(context)
    }

    /// Projects the original immutable endpoint, not a newly selected cut.
    pub(super) fn original_deadline_boottime(&self) -> u64 {
        self.request.original_deadline_boottime()
    }
}

#[cfg(test)]
mod tests;

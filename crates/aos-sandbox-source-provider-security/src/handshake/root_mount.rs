//! Root Mount hello preparation, send, and provider authentication states.

use std::num::NonZeroU64;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    CatalogCurrentnessQueryV1, ProviderCatalogFloorV1, RecoveryCurrentnessQueryV1,
    SignedCatalogCurrentnessV1, SignedRecoveryUnavailableV1, SignedSourceProviderHelloV1,
    SourceProviderHelloV1, SourceProviderKeyTrustStateV1, SourceProviderMessageV1,
    SourceProviderPeerRole, SourceProviderSessionV1, decode_message, encode_message, sign_hello,
};

use super::{HandshakeTransitionV1, current_unix_seconds, process_identity};
use crate::SourceProviderSecurityError;
use crate::carrier::{CarrierFailureV1, InertSourceProviderCarrierV1};
use crate::custody::ProtectedRootMountCustodyV1;
use crate::execution::ProcessExecutionEvidenceV1;

const FIXED_ROOT_MOUNT_SOURCE_PROVIDER_CUSTODY: &str =
    "/var/lib/aos/sandbox-mount/source-provider-authority";

pub(super) struct RootMountHelloPreparedV1 {
    custody: ProtectedRootMountCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    nonce: [u8; 32],
    signed_hello: SignedSourceProviderHelloV1,
    packet: Vec<u8>,
}

pub(super) struct RootMountHelloSentV1 {
    custody: ProtectedRootMountCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    nonce: [u8; 32],
    signed_hello: SignedSourceProviderHelloV1,
}

/// Owns the current authenticated Root Mount view of one provider session.
///
/// No public constructor or carrier/session extractor exists.
pub struct CurrentRootMountSourceProviderSessionV1 {
    pub(super) custody: ProtectedRootMountCustodyV1,
    pub(super) carrier: InertSourceProviderCarrierV1,
    pub(super) session: SourceProviderSessionV1,
    pub(super) provider_execution: ProcessExecutionEvidenceV1,
    catalog_exchange: Option<RootCatalogExchangeV1>,
    catalog_sequence: u64,
    catalog_floor: Option<(u64, ObjectDigest)>,
    recovery_exchange: Option<RootRecoveryExchangeV1>,
    recovery_sequence: u64,
}

struct RootCatalogExchangeV1 {
    query: CatalogCurrentnessQueryV1,
    sent: bool,
}

struct RootRecoveryExchangeV1 {
    query: RecoveryCurrentnessQueryV1,
    sent: bool,
}

/// Records only a signed, descriptor-free observation of a pending attempt.
///
/// The protected Mount row remains PendingQuery and this value grants no
/// terminal disposition, successor attempt, source root, or mount authority.
#[must_use = "Unavailable does not settle the protected pending attempt"]
pub struct AuthenticatedRootMountRecoveryUnavailableV1 {
    signed_plan_digest: ObjectDigest,
}

impl AuthenticatedRootMountRecoveryUnavailableV1 {
    /// Returns the exact Storage plan digest that Provider read back.
    #[must_use]
    pub const fn signed_plan_digest(&self) -> ObjectDigest {
        self.signed_plan_digest
    }
}

/// Proves a fresh provider-signed head on the current authenticated channel.
///
/// This value has no public constructor. It grants no catalog-row selection,
/// source effect, or descriptor authority.
#[must_use = "a currentness proof must be consumed with a protected Mount floor"]
pub struct AuthenticatedRootMountCatalogCurrentnessV1 {
    signed: SignedCatalogCurrentnessV1,
}

impl AuthenticatedRootMountCatalogCurrentnessV1 {
    /// Returns the exact provider-verified current catalog head.
    #[must_use]
    pub const fn head(&self) -> (u64, ObjectDigest) {
        self.signed.head()
    }

    /// Returns the protected non-GCable provider catalog floor.
    #[must_use]
    pub const fn floor(&self) -> (u64, ObjectDigest) {
        self.signed.floor()
    }

    /// Returns the provider-journal current-head commitment.
    #[must_use]
    pub const fn head_commitment(&self) -> ObjectDigest {
        self.signed.head_commitment()
    }

    /// Returns the exact signed-publication artifact digest.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.signed.publication_digest()
    }
}

enum RootMountSourceProviderOwnerStateV1 {
    Prepared(RootMountHelloPreparedV1),
    Sent(RootMountHelloSentV1),
    Current(CurrentRootMountSourceProviderSessionV1),
}

/// Owns the fixed Root-Mount SourceProvider custody and one adopted channel.
///
/// This dormant owner opens only the compiled-in protected custody directory
/// and accepts an already-connected descriptor-subject socket. It creates no
/// listener, socket path, route advertisement, backend, or service loop. All
/// retryable send and receive states remain inside the owner, and a current
/// session is available only as a lifetime-bound mutable borrow.
pub struct RootMountSourceProviderOwnerV1 {
    state: Option<RootMountSourceProviderOwnerStateV1>,
}

/// Reports whether the fixed owner still needs handshake I/O or is current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootMountSourceProviderHandshakeStatusV1 {
    /// The nonblocking channel must be advanced again when ready.
    Pending,
    /// The authenticated provider session is current and borrowable.
    Current,
}

impl core::fmt::Debug for CurrentRootMountSourceProviderSessionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentRootMountSourceProviderSessionV1([redacted])")
    }
}

impl core::fmt::Debug for RootMountSourceProviderOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RootMountSourceProviderOwnerV1([protected owner])")
    }
}

impl RootMountSourceProviderOwnerV1 {
    /// Reuses the protected connected carrier for a fresh successor transcript.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the current session and
    /// fixed custody remain live immediately before rotation.
    #[doc(hidden)]
    pub fn begin_successor_handshake(&mut self) -> Result<(), SourceProviderSecurityError> {
        let state = self
            .state
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let RootMountSourceProviderOwnerStateV1::Current(mut current) = state else {
            self.state = Some(state);
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        current.revalidate()?;
        let CurrentRootMountSourceProviderSessionV1 {
            custody,
            carrier,
            session: _,
            provider_execution: _,
            catalog_exchange: _,
            catalog_sequence: _,
            catalog_floor: _,
            recovery_exchange: _,
            recovery_sequence: _,
        } = current;
        let prepared = RootMountHelloPreparedV1::prepare_carrier(custody, carrier)?;
        self.state = Some(RootMountSourceProviderOwnerStateV1::Prepared(prepared));
        Ok(())
    }

    /// Opens the fixed Root-Mount custody and adopts one connected socket.
    ///
    /// `socket` must already be the caller's sole configured
    /// descriptor-subject channel. The owner revalidates its pinned kernel peer
    /// before every handshake action and again before exposing a current
    /// session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when fixed protected custody,
    /// process identity, channel configuration, or initial hello preparation
    /// cannot be authenticated.
    pub fn open_fixed(
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        let custody = ProtectedRootMountCustodyV1::load(std::path::Path::new(
            FIXED_ROOT_MOUNT_SOURCE_PROVIDER_CUSTODY,
        ))?;
        let prepared = RootMountHelloPreparedV1::prepare(custody, socket)?;
        Ok(Self {
            state: Some(RootMountSourceProviderOwnerStateV1::Prepared(prepared)),
        })
    }

    /// Advances exactly one nonblocking handshake state transition.
    ///
    /// Retryable I/O leaves the exact prepared or sent state inside this owner.
    /// Fatal transport, custody, peer, or transcript failure closes the channel
    /// and permanently consumes the state.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for fatal currentness,
    /// transport, peer-execution, or authenticated-transcript failure.
    pub fn advance_handshake(
        &mut self,
    ) -> Result<RootMountSourceProviderHandshakeStatusV1, SourceProviderSecurityError> {
        let state = self
            .state
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        match state {
            RootMountSourceProviderOwnerStateV1::Prepared(prepared) => match prepared.send() {
                HandshakeTransitionV1::Complete(sent) => {
                    self.state = Some(RootMountSourceProviderOwnerStateV1::Sent(sent));
                    Ok(RootMountSourceProviderHandshakeStatusV1::Pending)
                }
                HandshakeTransitionV1::Retry(prepared) => {
                    self.state = Some(RootMountSourceProviderOwnerStateV1::Prepared(prepared));
                    Ok(RootMountSourceProviderHandshakeStatusV1::Pending)
                }
                HandshakeTransitionV1::Fatal(error) => Err(error),
            },
            RootMountSourceProviderOwnerStateV1::Sent(sent) => match sent.receive_provider() {
                HandshakeTransitionV1::Complete(current) => {
                    self.state = Some(RootMountSourceProviderOwnerStateV1::Current(current));
                    Ok(RootMountSourceProviderHandshakeStatusV1::Current)
                }
                HandshakeTransitionV1::Retry(sent) => {
                    self.state = Some(RootMountSourceProviderOwnerStateV1::Sent(sent));
                    Ok(RootMountSourceProviderHandshakeStatusV1::Pending)
                }
                HandshakeTransitionV1::Fatal(error) => Err(error),
            },
            RootMountSourceProviderOwnerStateV1::Current(mut current) => {
                current.revalidate()?;
                self.state = Some(RootMountSourceProviderOwnerStateV1::Current(current));
                Ok(RootMountSourceProviderHandshakeStatusV1::Current)
            }
        }
    }

    /// Runs one operation with the current fixed-owner session.
    ///
    /// `Ok(None)` means the owner still retains a retryable handshake state.
    /// The closure cannot retain or detach the session from this fixed owner.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when a previously current
    /// custody, provider execution, or connected peer is no longer current.
    pub fn with_current_session<R>(
        &mut self,
        operation: impl for<'session> FnOnce(&'session mut CurrentRootMountSourceProviderSessionV1) -> R,
    ) -> Result<Option<R>, SourceProviderSecurityError> {
        let Some(RootMountSourceProviderOwnerStateV1::Current(current)) = self.state.as_mut()
        else {
            return Ok(None);
        };
        current.revalidate()?;
        Ok(Some(operation(current)))
    }
}

impl RootMountHelloPreparedV1 {
    pub(super) fn prepare(
        custody: ProtectedRootMountCustodyV1,
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::prepare_carrier(custody, InertSourceProviderCarrierV1::adopt(socket)?)
    }

    fn prepare_carrier(
        mut custody: ProtectedRootMountCustodyV1,
        mut carrier: InertSourceProviderCarrierV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => return Err(poison_and_close(&mut custody, &mut carrier, error)),
        };
        if let Err(error) = custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        let nonce = match custody.draw_nonce_at(now) {
            Ok(nonce) => nonce,
            Err(error) => return Err(poison_and_close(&mut custody, &mut carrier, error)),
        };
        let hello = {
            let inner = custody.inner();
            SourceProviderHelloV1::new(
                SourceProviderPeerRole::RootMount,
                nonce,
                inner.process_instance(),
                inner.execution().boot_id(),
                inner.root_authority().traffic_signer().clone(),
                inner.provider_authority().traffic_signer().clone(),
                inner.route().route_id(),
                inner.route().route_generation(),
                inner.route().route_digest(),
                None,
                inner.manifest().proof_capabilities(),
                inner.manifest().allow_recursive(),
                inner.manifest().allow_kernel_coupled(),
            )
        };
        let hello = match hello {
            Ok(hello) => hello,
            Err(_) => {
                return Err(poison_and_close(
                    &mut custody,
                    &mut carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let before_signature =
            current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = before_signature {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        let signed_hello = {
            let inner = custody.inner();
            sign_hello(
                hello,
                inner.root_authority().hello_signer().clone(),
                inner.hello_key().signing_key(),
            )
        };
        let signed_hello = match signed_hello {
            Ok(signed) => signed,
            Err(_) => {
                return Err(poison_and_close(
                    &mut custody,
                    &mut carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let after_signature =
            current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = after_signature {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        let packet =
            match encode_message(&SourceProviderMessageV1::HelloRequest(signed_hello.clone())) {
                Ok(packet) => packet,
                Err(_) => {
                    return Err(poison_and_close(
                        &mut custody,
                        &mut carrier,
                        SourceProviderSecurityError::SessionContinuity,
                    ));
                }
            };
        if packet.len() != aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES {
            return Err(poison_and_close(
                &mut custody,
                &mut carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => return Err(poison_and_close(&mut custody, &mut carrier, error)),
        };
        if let Err(error) = custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        Ok(Self {
            custody,
            carrier,
            nonce,
            signed_hello,
            packet,
        })
    }

    pub(super) fn send(
        mut self,
    ) -> HandshakeTransitionV1<RootMountHelloPreparedV1, RootMountHelloSentV1> {
        if let Err(error) = self.revalidate_before_action() {
            return HandshakeTransitionV1::Fatal(error);
        }
        match self.carrier.send(&self.packet) {
            Err(CarrierFailureV1::Retryable) => HandshakeTransitionV1::Retry(self),
            Err(CarrierFailureV1::Fatal(error)) => HandshakeTransitionV1::Fatal(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
            Ok(()) => {
                if let Err(error) = self.revalidate_before_action() {
                    return HandshakeTransitionV1::Fatal(error);
                }
                HandshakeTransitionV1::Complete(RootMountHelloSentV1 {
                    custody: self.custody,
                    carrier: self.carrier,
                    nonce: self.nonce,
                    signed_hello: self.signed_hello,
                })
            }
        }
    }

    fn revalidate_before_action(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result =
            current_unix_seconds().and_then(|now| self.custody.inner_mut().revalidate_at(now));
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }
}

impl RootMountHelloSentV1 {
    pub(super) fn receive_provider(
        mut self,
    ) -> HandshakeTransitionV1<RootMountHelloSentV1, CurrentRootMountSourceProviderSessionV1> {
        if let Err(error) = self.revalidate_before_action() {
            return HandshakeTransitionV1::Fatal(error);
        }
        let received = match self.carrier.receive_zero_descriptors(
            aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES,
        ) {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return HandshakeTransitionV1::Retry(self),
            Err(CarrierFailureV1::Fatal(error)) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let provider_hello = match decode_message(&received.payload) {
            Ok(SourceProviderMessageV1::HelloResponse(hello)) => hello,
            _ => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let identity = match process_identity(&received.execution) {
            Ok(identity) => identity,
            Err(error) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        if let Err(error) = self.custody.inner_mut().revalidate_at(now) {
            return HandshakeTransitionV1::Fatal(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let inner = self.custody.inner();
        let session = SourceProviderSessionV1::authenticate(
            self.nonce,
            now,
            self.signed_hello.clone(),
            provider_hello,
            inner.trust(),
            inner.root_authority(),
            inner.provider_authority(),
            identity.clone(),
            identity,
            inner.route(),
        );
        let session = match session {
            Ok(session) => session,
            Err(_) => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        if received.execution.boot_id() != inner.execution().boot_id()
            || received
                .execution
                .revalidate(self.carrier.socket().peer())
                .is_err()
        {
            return HandshakeTransitionV1::Fatal(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        if let Err(error) = self.revalidate_before_action() {
            return HandshakeTransitionV1::Fatal(error);
        }
        HandshakeTransitionV1::Complete(CurrentRootMountSourceProviderSessionV1 {
            custody: self.custody,
            carrier: self.carrier,
            session,
            provider_execution: received.execution,
            catalog_exchange: None,
            catalog_sequence: 0,
            catalog_floor: None,
            recovery_exchange: None,
            recovery_sequence: 0,
        })
    }

    fn revalidate_before_action(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result =
            current_unix_seconds().and_then(|now| self.custody.inner_mut().revalidate_at(now));
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
        }
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    pub(super) fn advance_recovery_identity(
        &mut self,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        acquisition_id: ObjectDigest,
        signed_request_digest: ObjectDigest,
        mount_attempt_record_digest: ObjectDigest,
    ) -> Result<Option<AuthenticatedRootMountRecoveryUnavailableV1>, SourceProviderSecurityError>
    {
        self.revalidate()?;
        if self.catalog_exchange.is_some()
            || provider_id
                != self
                    .custody
                    .inner()
                    .provider_authority()
                    .authority()
                    .authority_id()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if let Some(exchange) = &self.recovery_exchange {
            if exchange.query.authorities() != (provider_id, holder_id)
                || exchange.query.acquisition_id() != acquisition_id
                || exchange.query.original_signed_request_digest() != signed_request_digest
                || exchange.query.original_attempt_digest() != mount_attempt_record_digest
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        } else {
            let nonce = self.custody.draw_nonce_at(current_unix_seconds()?)?;
            let sequence = self
                .recovery_sequence
                .checked_add(1)
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let query = RecoveryCurrentnessQueryV1::new(
                self.session.binding(),
                nonce,
                sequence,
                provider_id,
                holder_id,
                acquisition_id,
                signed_request_digest,
                mount_attempt_record_digest,
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            self.recovery_exchange = Some(RootRecoveryExchangeV1 { query, sent: false });
        }

        let exchange = self
            .recovery_exchange
            .as_mut()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        if !exchange.sent {
            match self.carrier.send(&exchange.query.to_canonical_bytes()) {
                Ok(()) => exchange.sent = true,
                Err(CarrierFailureV1::Retryable) => return Ok(None),
                Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
            }
        }
        let received = match self
            .carrier
            .receive_zero_descriptors(aos_sandbox_source_provider_protocol::MAXIMUM_FRAME_BYTES)
        {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return Ok(None),
            Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
        };
        if !received.descriptors.is_empty()
            || !received
                .execution
                .has_same_execution(&self.provider_execution)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        let exchange = self
            .recovery_exchange
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let signed = SignedRecoveryUnavailableV1::from_canonical_bytes(&received.payload)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let (signer, trusted_key) = {
            let inner = self.custody.inner();
            let signer = inner.provider_authority().traffic_signer().clone();
            let trusted_key = inner
                .trust()
                .keys()
                .iter()
                .find(|entry| {
                    entry.signer() == &signer
                        && entry.state() == SourceProviderKeyTrustStateV1::Eligible
                })
                .map(|entry| *entry.public_key());
            (signer, trusted_key)
        };
        let trusted_key = trusted_key
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        signed
            .verify_for_query(&exchange.query, &signer, &trusted_key)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.recovery_sequence = exchange.query.sequence();
        Ok(Some(AuthenticatedRootMountRecoveryUnavailableV1 {
            signed_plan_digest: signed.signed_storage_plan_digest(),
        }))
    }

    /// Advances one nonblocking catalog-currentness challenge and response.
    ///
    /// The caller supplies its protected minimum floor. The session refuses a
    /// lower floor after any verified response and binds every answer to its
    /// fresh nonce, strictly increasing sequence, live provider process, and
    /// configured outcome signer. `Ok(None)` retains exact retryable I/O.
    ///
    /// # Errors
    ///
    /// Closes the session for a foreign provider, lowered floor, changed
    /// in-flight query, malformed response, stale custody, or carrier failure.
    pub fn advance_catalog_currentness(
        &mut self,
        minimum: &ProviderCatalogFloorV1,
    ) -> Result<Option<AuthenticatedRootMountCatalogCurrentnessV1>, SourceProviderSecurityError>
    {
        self.revalidate()?;
        if self.recovery_exchange.is_some() {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let inner = self.custody.inner();
        if minimum.provider_authority_id() != inner.provider_authority().authority().authority_id()
            || minimum.resource_namespace_digest() != inner.route().resource_namespace_digest()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let requested = (
            minimum.minimum_catalog_generation(),
            minimum.minimum_catalog_digest(),
        );
        if self.catalog_floor.is_some_and(|previous| {
            requested.0 < previous.0 || (requested.0 == previous.0 && requested.1 != previous.1)
        }) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        if let Some(exchange) = &self.catalog_exchange {
            if exchange.query.minimum() != requested {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        } else {
            let now = current_unix_seconds()?;
            let nonce = self.custody.draw_nonce_at(now)?;
            let sequence = self
                .catalog_sequence
                .checked_add(1)
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let query = CatalogCurrentnessQueryV1::new(
                self.session.binding(),
                nonce,
                sequence,
                requested.0,
                requested.1,
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            self.catalog_exchange = Some(RootCatalogExchangeV1 { query, sent: false });
        }

        let exchange = self
            .catalog_exchange
            .as_mut()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        if !exchange.sent {
            match self.carrier.send(&exchange.query.to_canonical_bytes()) {
                Ok(()) => exchange.sent = true,
                Err(CarrierFailureV1::Retryable) => return Ok(None),
                Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
            }
        }
        let received = match self
            .carrier
            .receive_zero_descriptors(aos_sandbox_source_provider_protocol::MAXIMUM_FRAME_BYTES)
        {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return Ok(None),
            Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
        };
        if !received.descriptors.is_empty()
            || !received
                .execution
                .has_same_execution(&self.provider_execution)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        let exchange = self
            .catalog_exchange
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let signed = SignedCatalogCurrentnessV1::from_canonical_bytes(&received.payload)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let (signer, trusted_key) = {
            let inner = self.custody.inner();
            let signer = inner.provider_authority().traffic_signer().clone();
            let trusted_key = inner
                .trust()
                .keys()
                .iter()
                .find(|entry| {
                    entry.signer() == &signer
                        && entry.state() == SourceProviderKeyTrustStateV1::Eligible
                })
                .map(|entry| *entry.public_key());
            (signer, trusted_key)
        };
        let trusted_key = trusted_key
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        signed
            .verify_for_query(&exchange.query, &signer, &trusted_key)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.catalog_sequence = exchange.query.sequence();
        self.catalog_floor = Some(signed.floor());
        Ok(Some(AuthenticatedRootMountCatalogCurrentnessV1 { signed }))
    }

    pub(crate) fn poison(
        &mut self,
        error: SourceProviderSecurityError,
    ) -> SourceProviderSecurityError {
        poison_and_close(&mut self.custody, &mut self.carrier, error)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.provider_execution
                    .revalidate(self.carrier.socket().peer())
            })
            .and_then(|_| {
                (self.session.provider_hello().kernel_boot_id()
                    == self.custody.inner().execution().boot_id())
                .then_some(())
                .ok_or(SourceProviderSecurityError::SessionContinuity)
            });
        if let Err(error) = result {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        Ok(())
    }

    pub(crate) fn require_complete_acquire_association(
        &mut self,
        session_binding: ObjectDigest,
        socket_cookie: NonZeroU64,
        execution: &ProcessExecutionEvidenceV1,
    ) -> Result<(), SourceProviderSecurityError> {
        let result = self.revalidate().and_then(|_| {
            (session_binding == self.session.binding()
                && socket_cookie == self.carrier.socket().peer().socket_cookie()
                && execution.has_same_execution(&self.provider_execution))
            .then_some(())
            .ok_or(SourceProviderSecurityError::SessionContinuity)
        });
        if let Err(error) = result {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        execution
            .revalidate(self.carrier.socket().peer())
            .map_err(|error| poison_and_close(&mut self.custody, &mut self.carrier, error))
    }
}

fn poison_and_close(
    custody: &mut ProtectedRootMountCustodyV1,
    carrier: &mut InertSourceProviderCarrierV1,
    error: SourceProviderSecurityError,
) -> SourceProviderSecurityError {
    custody.inner_mut().poison();
    carrier.close();
    error
}

//! Root Mount hello preparation, send, and provider authentication states.

use std::num::NonZeroU64;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    CatalogCurrentnessQueryV1, InventoryReadbackQueryV1, MAXIMUM_INVENTORY_READBACK_PACKET_BYTES,
    NativeRecoveryTerminalDigestsV1, ProviderCatalogFloorV1, RecoveryCurrentnessQueryV1,
    SignedCatalogCurrentnessV1, SignedInventoryReadbackV1, SignedNativeRecoveryUnavailableV1,
    SignedRecoveryUnavailableV1, SignedSourceProviderHelloV1, SourceProviderHelloV1,
    SourceProviderKeyTrustStateV1, SourceProviderMessageV1, SourceProviderPeerRole,
    SourceProviderSessionV1, decode_message, encode_message, sign_hello,
};

use super::{
    HandshakeReceiveModeV1, HandshakeTransitionV1, SelectedHandshakeOpeningV1,
    SelectedSourceProviderFailureRefV1, current_unix_seconds, process_identity,
    receive_hello_record,
};
use crate::SourceProviderSecurityError;
use crate::carrier::{
    CarrierFailureV1, InertSourceProviderCarrierV1, ReceivedSourceProviderRecordV1,
    RetainedSourceProviderRecordV5,
};
use crate::custody::{FIXED_ROOT_MOUNT_SOURCE_PROVIDER_CUSTODY, ProtectedRootMountCustodyV1};
use crate::execution::ProcessExecutionEvidenceV1;

mod catalog_retained;

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
    pub(super) catalog_exchange: Option<RootCatalogExchangeV1>,
    pub(super) catalog_sequence: u64,
    catalog_floor: Option<(u64, ObjectDigest)>,
    recovery_exchange: Option<RootRecoveryExchangeV1>,
    inventory_readback_exchange: Option<RootInventoryReadbackExchangeV1>,
    recovery_sequence: u64,
}

pub(super) struct RootCatalogExchangeV1 {
    pub(super) query: CatalogCurrentnessQueryV1,
    sent: bool,
    received: Option<RetainedSourceProviderRecordV5>,
    signed: Option<SignedCatalogCurrentnessV1>,
    failed: bool,
}

struct RootRecoveryExchangeV1 {
    query: RecoveryCurrentnessQueryV1,
    sent: bool,
}

struct RootInventoryReadbackExchangeV1 {
    query: InventoryReadbackQueryV1,
    sent: bool,
}

/// Reports one authenticated non-effect historical Inventory readback step.
#[must_use = "an unavailable readback does not settle Mount's Reserved attempt"]
pub enum InventoryReadbackProgressV1 {
    /// The exact challenge or answer remains pending on the carrier.
    Pending,
    /// Provider did not prove a completed historical response.
    Unavailable,
    /// Provider attested a completed response for Mount's historical verifier.
    Completed(super::CapturedMountProviderRecoveryOutcomeV2),
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

/// Records exact Provider native no-dispatch terminalization, pending Mount settlement.
#[must_use = "Provider terminalization does not settle the protected Mount attempt"]
pub struct AuthenticatedRootMountNativeRecoveryUnavailableV1 {
    terminal_digests: NativeRecoveryTerminalDigestsV1,
    canonical_query: Vec<u8>,
    signed_settlement: Vec<u8>,
}

impl AuthenticatedRootMountNativeRecoveryUnavailableV1 {
    /// Returns the exact pre/post Provider records named by the signer.
    #[must_use]
    pub const fn terminal_digests(&self) -> NativeRecoveryTerminalDigestsV1 {
        self.terminal_digests
    }

    /// Consumes the authenticated proof for one protected Mount settlement.
    #[doc(hidden)]
    pub fn into_protected_records(self) -> (Vec<u8>, Vec<u8>) {
        (self.canonical_query, self.signed_settlement)
    }
}

/// Separates LocalLive Storage readback from native no-dispatch evidence.
///
/// Neither variant mutates Mount's protected graph or authorizes a successor.
#[must_use = "recovery observations do not settle the protected pending attempt"]
pub enum AuthenticatedRootMountRecoveryObservationV2 {
    /// Provider checked the original signed LocalLive Storage plan.
    LocalLive(AuthenticatedRootMountRecoveryUnavailableV1),
    /// Provider terminalized one protected native no-dispatch reservation.
    NativeNoDispatch(AuthenticatedRootMountNativeRecoveryUnavailableV1),
}

/// Proves a fresh provider-signed head on the current authenticated channel.
///
/// This value has no public constructor. It grants no catalog-row selection,
/// source effect, or descriptor authority.
#[must_use = "a currentness proof must be consumed with a protected Mount floor"]
pub struct AuthenticatedRootMountCatalogCurrentnessV1 {
    pub(super) signed: SignedCatalogCurrentnessV1,
    pub(super) query: CatalogCurrentnessQueryV1,
    pub(super) socket_cookie: NonZeroU64,
    received: ReceivedSourceProviderRecordV1,
}

impl AuthenticatedRootMountCatalogCurrentnessV1 {
    pub(super) const fn execution(&self) -> &ProcessExecutionEvidenceV1 {
        &self.received.execution
    }

    /// Rejoins the signed proof with the original descriptor-free packet.
    pub(super) fn require_packet_consistency(&self) -> Result<(), SourceProviderSecurityError> {
        if !self.received.descriptors.is_empty()
            || self.signed.to_canonical_bytes() != self.received.payload
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        Ok(())
    }

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

/// Retains one selected RootMount opening and mutually authenticated HELLO.
///
/// Only the fixed selected entry point constructs this owner. Every returned
/// custody, carrier, raw HELLO and signed prefix remains resident before the
/// next observation. A terminal failure lends its original typed cause and
/// permanently shuts the same carrier. This owner supplies neither the missing
/// initial-table/PID1 image bridge nor independent source-effect admission.
#[must_use = "retain the original selected RootMount flight"]
pub struct SelectedRootMountSourceProviderOwnerV1 {
    opening: SelectedHandshakeOpeningV1,
    custody: Option<ProtectedRootMountCustodyV1>,
    carrier: Option<InertSourceProviderCarrierV1>,
    nonce: Option<[u8; 32]>,
    signed_hello: Option<SignedSourceProviderHelloV1>,
    packet: Option<Vec<u8>>,
    state: Option<RootMountSourceProviderOwnerStateV1>,
    received: Option<RetainedSourceProviderRecordV5>,
    provider_hello: Option<SignedSourceProviderHelloV1>,
    session: Option<SourceProviderSessionV1>,
    received_payload: Option<Vec<u8>>,
    received_descriptors: Option<Vec<std::os::fd::OwnedFd>>,
    first_failure: Option<SourceProviderSecurityError>,
    attempted: bool,
    ended: bool,
}

struct SelectedRootMountBoundaryV1<'owner> {
    owner: &'owner mut SelectedRootMountSourceProviderOwnerV1,
    completed: bool,
}

impl Drop for SelectedRootMountBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.close();
        }
    }
}

impl core::fmt::Debug for SelectedRootMountSourceProviderOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SelectedRootMountSourceProviderOwnerV1([original flight])")
    }
}

impl SelectedRootMountSourceProviderOwnerV1 {
    fn new(socket: DescriptorSubjectSocket) -> Self {
        Self {
            opening: SelectedHandshakeOpeningV1::root_mount(socket),
            custody: None,
            carrier: None,
            nonce: None,
            signed_hello: None,
            packet: None,
            state: None,
            received: None,
            provider_hello: None,
            session: None,
            received_payload: None,
            received_descriptors: None,
            first_failure: None,
            attempted: false,
            ended: false,
        }
    }

    /// Opens the fixed selected role once without releasing returned prefixes.
    ///
    /// # Errors
    ///
    /// Lends the original terminal custody or HELLO preparation failure. A
    /// second opening is refused without reopening files or renewing a nonce.
    pub fn open_once(&mut self) -> Result<(), SelectedSourceProviderFailureRefV1<'_>> {
        if self.failure().is_some() || self.ended {
            self.close();
            return Err(self.failure_or_poison());
        }
        if self.attempted {
            if self.failure().is_none() {
                self.first_failure = Some(SourceProviderSecurityError::Poisoned);
            }
        } else {
            self.attempted = true;
            let mut boundary = SelectedRootMountBoundaryV1 {
                owner: self,
                completed: false,
            };
            if boundary.owner.opening.open_once().is_ok() {
                if let Err(error) = boundary.owner.prepare_inner() {
                    boundary.owner.first_failure = Some(error);
                }
            }
            boundary.completed = boundary.owner.failure().is_none() && !boundary.owner.ended;
        }

        if self.failure().is_some() || self.ended {
            self.close();
            return Err(self.failure_or_poison());
        }
        Ok(())
    }

    /// Lends the first actual failure without rechecking or changing it.
    pub fn failure(&self) -> Option<SelectedSourceProviderFailureRefV1<'_>> {
        let carrier = self.carrier.as_ref().or_else(|| match self.state.as_ref() {
            Some(RootMountSourceProviderOwnerStateV1::Prepared(state)) => Some(&state.carrier),
            Some(RootMountSourceProviderOwnerStateV1::Sent(state)) => Some(&state.carrier),
            Some(RootMountSourceProviderOwnerStateV1::Current(state)) => Some(&state.carrier),
            None => None,
        });
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::socket_failure) {
            return Some(SelectedSourceProviderFailureRefV1::Socket(error));
        }
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::binding_failure) {
            return Some(SelectedSourceProviderFailureRefV1::Binding(error));
        }
        self.first_failure
            .as_ref()
            .map(SelectedSourceProviderFailureRefV1::Source)
            .or_else(|| self.opening.failure())
    }

    /// Reports an actual original-queue shutdown attempt, not peer termination.
    pub fn shutdown_attempted(&self) -> bool {
        self.opening.shutdown_attempted()
    }

    /// Lends shutdown debt separately from the original first failure.
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.opening.shutdown_failure()
    }

    /// Reports missing original endpoint custody for a shutdown attempt.
    ///
    /// This is a negative debt class, never proof of queue or physical drain.
    pub fn shutdown_unavailable(&self) -> bool {
        self.opening.shutdown_unavailable()
    }

    /// Borrows the same resident current session after its actual revalidation.
    ///
    /// `Ok(None)` retains a pending HELLO. No session may be detached from this
    /// selected owner. A caller must retain the owner and fence its own effect
    /// interval; this borrow does not manufacture independent Mount authority.
    ///
    /// # Errors
    ///
    /// Lends the first terminal failure and closes the original queue before
    /// returning it. Failed calls never recheck or revive a later session.
    pub fn borrow_current_session(
        &mut self,
    ) -> Result<Option<&mut CurrentRootMountSourceProviderSessionV1>, SelectedSourceProviderFailureRefV1<'_>> {
        if self.failure().is_none() && !self.ended {
            let mut boundary = SelectedRootMountBoundaryV1 {
                owner: self,
                completed: false,
            };
            let result = match boundary.owner.state.as_mut() {
                Some(RootMountSourceProviderOwnerStateV1::Current(current)) => current.revalidate(),
                _ => Ok(()),
            };
            if let Err(cause) = result {
                boundary.owner.first_failure = Some(cause);
            } else {
                boundary.completed = true;
            }
        }
        if self.failure().is_some() || self.ended {
            self.close();
            return Err(self.failure_or_poison());
        }

        match self.state.as_mut() {
            Some(RootMountSourceProviderOwnerStateV1::Current(current)) => Ok(Some(current)),
            _ => Ok(None),
        }
    }

    /// Ends the original queue while retaining custody and every HELLO prefix.
    pub fn end(&mut self) {
        self.close();
    }

    fn prepare_inner(&mut self) -> Result<(), SourceProviderSecurityError> {
        let (custody, carrier) = self
            .opening
            .take_root_mount_parts()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        self.custody = Some(custody);
        self.carrier = Some(carrier);

        let custody = self
            .custody
            .as_mut()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let carrier = self
            .carrier
            .as_mut()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        RootMountHelloPreparedV1::prepare_step(
            custody,
            carrier,
            &mut self.nonce,
            &mut self.signed_hello,
            &mut self.packet,
        )?;

        if self.custody.is_none()
            || self.carrier.is_none()
            || self.nonce.is_none()
            || self.signed_hello.is_none()
            || self.packet.is_none()
            || self.state.is_some()
        {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        match (
            self.custody.take(),
            self.carrier.take(),
            self.nonce.take(),
            self.signed_hello.take(),
            self.packet.take(),
        ) {
            (Some(custody), Some(carrier), Some(nonce), Some(signed_hello), Some(packet)) => {
                self.state = Some(RootMountSourceProviderOwnerStateV1::Prepared(
                    RootMountHelloPreparedV1 {
                        custody,
                        carrier,
                        nonce,
                        signed_hello,
                        packet,
                    },
                ));
                Ok(())
            }
            (custody, carrier, nonce, signed_hello, packet) => {
                self.custody = custody;
                self.carrier = carrier;
                self.nonce = nonce;
                self.signed_hello = signed_hello;
                self.packet = packet;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }
    }

    /// Advances one resident selected HELLO stage through the shared recipe.
    ///
    /// # Errors
    ///
    /// Lends the first terminal transport, execution, custody or transcript
    /// cause. Failed stages and raw records stay resident; later calls perform
    /// no observation and cannot revive or redispatch the original flight.
    pub fn advance_handshake(
        &mut self,
    ) -> Result<RootMountSourceProviderHandshakeStatusV1, SelectedSourceProviderFailureRefV1<'_>> {
        if self.failure().is_none() && !self.ended {
            let progress = {
                let mut boundary = SelectedRootMountBoundaryV1 {
                    owner: self,
                    completed: false,
                };
                match boundary.owner.advance_inner() {
                    Ok(status) => {
                        boundary.completed = true;
                        Some(status)
                    }
                    Err(error) => {
                        boundary.owner.first_failure = Some(error);
                        None
                    }
                }
            };
            if let Some(status) = progress {
                return Ok(status);
            }
        }
        self.close();
        Err(self.failure_or_poison())
    }

    fn failure_or_poison(&mut self) -> SelectedSourceProviderFailureRefV1<'_> {
        let carrier = self.carrier.as_ref().or_else(|| match self.state.as_ref() {
            Some(RootMountSourceProviderOwnerStateV1::Prepared(state)) => Some(&state.carrier),
            Some(RootMountSourceProviderOwnerStateV1::Sent(state)) => Some(&state.carrier),
            Some(RootMountSourceProviderOwnerStateV1::Current(state)) => Some(&state.carrier),
            None => None,
        });
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::socket_failure) {
            return SelectedSourceProviderFailureRefV1::Socket(error);
        }
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::binding_failure) {
            return SelectedSourceProviderFailureRefV1::Binding(error);
        }
        match &mut self.first_failure {
            Some(error) => SelectedSourceProviderFailureRefV1::Source(error),
            slot => match self.opening.failure() {
                Some(error) => error,
                None => SelectedSourceProviderFailureRefV1::Source(
                    slot.insert(SourceProviderSecurityError::Poisoned),
                ),
            },
        }
    }

    fn advance_inner(
        &mut self,
    ) -> Result<RootMountSourceProviderHandshakeStatusV1, SourceProviderSecurityError> {
        match self.state.as_mut() {
            Some(RootMountSourceProviderOwnerStateV1::Prepared(prepared)) => {
                if !prepared.send_step()? {
                    return Ok(RootMountSourceProviderHandshakeStatusV1::Pending);
                }
            }
            Some(RootMountSourceProviderOwnerStateV1::Sent(sent)) => {
                if !sent.receive_step(
                    &mut self.received,
                    &mut self.provider_hello,
                    &mut self.session,
                    HandshakeReceiveModeV1::Selected,
                )? {
                    return Ok(RootMountSourceProviderHandshakeStatusV1::Pending);
                }
                return self.complete_received();
            }
            Some(RootMountSourceProviderOwnerStateV1::Current(current)) => {
                current.revalidate()?;
                return Ok(RootMountSourceProviderHandshakeStatusV1::Current);
            }
            None => return Err(SourceProviderSecurityError::Poisoned),
        }

        match self.state.take() {
            Some(RootMountSourceProviderOwnerStateV1::Prepared(prepared)) => {
                // Retain the actual sent bytes after the move-only state
                // transition, without cloning or allocating another packet.
                self.packet = Some(prepared.packet);
                self.state = Some(RootMountSourceProviderOwnerStateV1::Sent(
                    RootMountHelloSentV1 {
                        custody: prepared.custody,
                        carrier: prepared.carrier,
                        nonce: prepared.nonce,
                        signed_hello: prepared.signed_hello,
                    },
                ));
                Ok(RootMountSourceProviderHandshakeStatusV1::Pending)
            }
            state => {
                self.state = state;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }
    }

    fn complete_received(
        &mut self,
    ) -> Result<RootMountSourceProviderHandshakeStatusV1, SourceProviderSecurityError> {
        if !matches!(self.state, Some(RootMountSourceProviderOwnerStateV1::Sent(_)))
            || !matches!(self.received, Some(RetainedSourceProviderRecordV5::Bound(_)))
            || self.session.is_none()
            || self.signed_hello.is_some()
            || self.received_payload.is_some()
            || self.received_descriptors.is_some()
        {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        match (self.state.take(), self.received.take(), self.session.take()) {
            (
                Some(RootMountSourceProviderOwnerStateV1::Sent(sent)),
                Some(RetainedSourceProviderRecordV5::Bound(received)),
                Some(session),
            ) => {
                self.nonce = Some(sent.nonce);
                self.signed_hello = Some(sent.signed_hello);
                self.received_payload = Some(received.payload);
                self.received_descriptors = Some(received.descriptors);
                self.state = Some(RootMountSourceProviderOwnerStateV1::Current(
                    CurrentRootMountSourceProviderSessionV1 {
                        custody: sent.custody,
                        carrier: sent.carrier,
                        session,
                        provider_execution: received.execution,
                        catalog_exchange: None,
                        catalog_sequence: 0,
                        catalog_floor: None,
                        recovery_exchange: None,
                        inventory_readback_exchange: None,
                        recovery_sequence: 0,
                    },
                ));
                Ok(RootMountSourceProviderHandshakeStatusV1::Current)
            }
            (state, received, session) => {
                self.state = state;
                self.received = received;
                self.session = session;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }
    }

    fn close(&mut self) {
        self.ended = true;
        self.opening.close();
        if let Some(carrier) = self.carrier.as_mut() {
            carrier.close();
        }
        if let Some(custody) = self.custody.as_mut() {
            custody.inner_mut().poison();
        }
        match self.state.as_mut() {
            Some(RootMountSourceProviderOwnerStateV1::Prepared(stage)) => {
                stage.carrier.close();
                stage.custody.inner_mut().poison();
            }
            Some(RootMountSourceProviderOwnerStateV1::Sent(stage)) => {
                stage.carrier.close();
                stage.custody.inner_mut().poison();
            }
            Some(RootMountSourceProviderOwnerStateV1::Current(stage)) => {
                stage.carrier.close();
                stage.custody.inner_mut().poison();
            }
            None => {}
        }
    }
}

impl Drop for SelectedRootMountSourceProviderOwnerV1 {
    fn drop(&mut self) {
        self.close();
    }
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
    /// Parks the original socket before opening fixed selected RootMount custody.
    ///
    /// This infallible empty owner performs no observation. Its selected
    /// opening and HELLO methods retain failures on the same original carrier;
    /// the ordinary fixed owner and its consuming APIs remain unchanged.
    pub fn begin_fixed_selected_mount_source(
        socket: DescriptorSubjectSocket,
    ) -> SelectedRootMountSourceProviderOwnerV1 {
        SelectedRootMountSourceProviderOwnerV1::new(socket)
    }

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
            inventory_readback_exchange: _,
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
        // Legacy locals retain the original packet -> signed hello -> carrier
        // -> custody release order. The same recipe can instead lend resident
        // selected slots without moving an original across its checks.
        let mut nonce = None;
        let mut signed_hello = None;
        let mut packet = None;
        Self::prepare_step(
            &mut custody,
            &mut carrier,
            &mut nonce,
            &mut signed_hello,
            &mut packet,
        )?;

        if nonce.is_none() || signed_hello.is_none() || packet.is_none() {
            return Err(poison_and_close(
                &mut custody,
                &mut carrier,
                SourceProviderSecurityError::Poisoned,
            ));
        }
        match (nonce.take(), signed_hello.take(), packet.take()) {
            (Some(nonce), Some(signed_hello), Some(packet)) => Ok(Self {
                custody,
                carrier,
                nonce,
                signed_hello,
                packet,
            }),
            (old_nonce, old_signed_hello, old_packet) => {
                nonce = old_nonce;
                signed_hello = old_signed_hello;
                packet = old_packet;
                Err(poison_and_close(
                    &mut custody,
                    &mut carrier,
                    SourceProviderSecurityError::Poisoned,
                ))
            }
        }
    }

    fn prepare_step(
        custody: &mut ProtectedRootMountCustodyV1,
        carrier: &mut InertSourceProviderCarrierV1,
        nonce_slot: &mut Option<[u8; 32]>,
        signed_hello_slot: &mut Option<SignedSourceProviderHelloV1>,
        packet_slot: &mut Option<Vec<u8>>,
    ) -> Result<(), SourceProviderSecurityError> {
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => return Err(poison_and_close(custody, carrier, error)),
        };
        if let Err(error) = custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(custody, carrier, error));
        }
        let nonce = match custody.draw_nonce_at(now) {
            Ok(nonce) => nonce,
            Err(error) => return Err(poison_and_close(custody, carrier, error)),
        };
        *nonce_slot = Some(nonce);
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
                    custody,
                    carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let before_signature =
            current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = before_signature {
            return Err(poison_and_close(custody, carrier, error));
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
                    custody,
                    carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        *signed_hello_slot = Some(signed_hello);
        let after_signature =
            current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = after_signature {
            return Err(poison_and_close(custody, carrier, error));
        }
        let signed_hello = match signed_hello_slot.as_ref() {
            Some(signed_hello) => signed_hello,
            None => {
                return Err(poison_and_close(
                    custody,
                    carrier,
                    SourceProviderSecurityError::Poisoned,
                ));
            }
        };
        let packet =
            match encode_message(&SourceProviderMessageV1::HelloRequest(signed_hello.clone())) {
                Ok(packet) => packet,
                Err(_) => {
                    return Err(poison_and_close(
                        custody,
                        carrier,
                        SourceProviderSecurityError::SessionContinuity,
                    ));
                }
            };
        *packet_slot = Some(packet);
        let packet = match packet_slot.as_ref() {
            Some(packet) => packet,
            None => {
                return Err(poison_and_close(
                    custody,
                    carrier,
                    SourceProviderSecurityError::Poisoned,
                ));
            }
        };
        if packet.len() != aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES {
            return Err(poison_and_close(
                custody,
                carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => return Err(poison_and_close(custody, carrier, error)),
        };
        if let Err(error) = custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(custody, carrier, error));
        }
        Ok(())
    }

    pub(super) fn send(
        mut self,
    ) -> HandshakeTransitionV1<RootMountHelloPreparedV1, RootMountHelloSentV1> {
        match self.send_step() {
            Ok(false) => HandshakeTransitionV1::Retry(self),
            Err(error) => HandshakeTransitionV1::Fatal(error),
            Ok(true) => {
                HandshakeTransitionV1::Complete(RootMountHelloSentV1 {
                    custody: self.custody,
                    carrier: self.carrier,
                    nonce: self.nonce,
                    signed_hello: self.signed_hello,
                })
            }
        }
    }

    // Both adapters borrow the same original stage through every observation
    // and send. Only completed next-state assembly moves the originals.
    fn send_step(&mut self) -> Result<bool, SourceProviderSecurityError> {
        self.revalidate_before_action()?;
        match self.carrier.send(&self.packet) {
            Err(CarrierFailureV1::Retryable) => Ok(false),
            Err(CarrierFailureV1::Fatal(error)) => Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            )),
            Ok(()) => {
                self.revalidate_before_action()?;
                Ok(true)
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
        // Keep Legacy's session-before-received release order. Selected callers
        // lend the same slots from their whole original-flight owner instead.
        let mut received = None;
        let mut provider_hello = None;
        let mut session = None;
        match self.receive_step(
            &mut received,
            &mut provider_hello,
            &mut session,
            HandshakeReceiveModeV1::Legacy,
        ) {
            Ok(false) => HandshakeTransitionV1::Retry(self),
            Err(error) => HandshakeTransitionV1::Fatal(error),
            Ok(true) => {
                if !matches!(received, Some(RetainedSourceProviderRecordV5::Bound(_)))
                    || session.is_none()
                {
                    return HandshakeTransitionV1::Fatal(poison_and_close(
                        &mut self.custody,
                        &mut self.carrier,
                        SourceProviderSecurityError::Poisoned,
                    ));
                }
                match (received.take(), session.take()) {
                    (Some(RetainedSourceProviderRecordV5::Bound(received)), Some(session)) => {
                        HandshakeTransitionV1::Complete(CurrentRootMountSourceProviderSessionV1 {
                            custody: self.custody,
                            carrier: self.carrier,
                            session,
                            provider_execution: received.execution,
                            catalog_exchange: None,
                            catalog_sequence: 0,
                            catalog_floor: None,
                            recovery_exchange: None,
                            inventory_readback_exchange: None,
                            recovery_sequence: 0,
                        })
                    }
                    (old_received, old_session) => {
                        received = old_received;
                        session = old_session;
                        HandshakeTransitionV1::Fatal(poison_and_close(
                            &mut self.custody,
                            &mut self.carrier,
                            SourceProviderSecurityError::Poisoned,
                        ))
                    }
                }
            }
        }
    }

    fn receive_step(
        &mut self,
        received_slot: &mut Option<RetainedSourceProviderRecordV5>,
        provider_hello_slot: &mut Option<SignedSourceProviderHelloV1>,
        session_slot: &mut Option<SourceProviderSessionV1>,
        mode: HandshakeReceiveModeV1,
    ) -> Result<bool, SourceProviderSecurityError> {
        if let Err(error) = self.revalidate_before_action() {
            return Err(error);
        }
        let receiving = receive_hello_record(&mut self.carrier, received_slot, mode);
        match receiving {
            Ok(()) => {}
            Err(CarrierFailureV1::Retryable) => return Ok(false),
            Err(CarrierFailureV1::Fatal(error)) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        }
        let received = match received_slot
            .as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
        {
            Some(received) => received,
            None => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::Poisoned,
                ));
            }
        };
        let provider_hello = match decode_message(&received.payload) {
            Ok(SourceProviderMessageV1::HelloResponse(hello)) => hello,
            _ => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        *provider_hello_slot = Some(provider_hello);
        let identity = match process_identity(&received.execution) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let now = match current_unix_seconds() {
            Ok(now) => now,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        if let Err(error) = self.custody.inner_mut().revalidate_at(now) {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let provider_hello = match mode {
            HandshakeReceiveModeV1::Legacy => provider_hello_slot.take(),
            HandshakeReceiveModeV1::Selected => provider_hello_slot.as_ref().cloned(),
        };
        let provider_hello = match provider_hello {
            Some(provider_hello) => provider_hello,
            None => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::Poisoned,
                ));
            }
        };
        let inner = self.custody.inner();
        let session = match mode {
            HandshakeReceiveModeV1::Legacy => SourceProviderSessionV1::authenticate(
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
            ),
            HandshakeReceiveModeV1::Selected => {
                let pid1 = received
                    .execution
                    .pid1_establishment_identity(self.carrier.socket().peer())?
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                SourceProviderSessionV1::authenticate_activated_provider(
                    self.nonce,
                    now,
                    self.signed_hello.clone(),
                    provider_hello,
                    inner.trust(),
                    inner.root_authority(),
                    inner.provider_authority(),
                    pid1,
                    identity,
                    inner.route(),
                )
            }
        };
        let session = match session {
            Ok(session) => session,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        *session_slot = Some(session);
        if received.execution.boot_id() != inner.execution().boot_id()
            || received
                .execution
                .revalidate(self.carrier.socket().peer())
                .is_err()
        {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        if let Err(error) = self.revalidate_before_action() {
            return Err(error);
        }
        Ok(true)
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
    pub(super) fn has_pending_control_exchange(&self) -> bool {
        self.catalog_exchange.is_some()
            || self.recovery_exchange.is_some()
            || self.inventory_readback_exchange.is_some()
    }

    pub(super) fn advance_recovery_identity(
        &mut self,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        acquisition_id: ObjectDigest,
        signed_request_digest: ObjectDigest,
        mount_attempt_record_digest: ObjectDigest,
    ) -> Result<Option<AuthenticatedRootMountRecoveryObservationV2>, SourceProviderSecurityError>
    {
        self.revalidate()?;
        if self.catalog_exchange.is_some()
            || self.inventory_readback_exchange.is_some()
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
        let observation = if let Ok(signed) =
            SignedRecoveryUnavailableV1::from_canonical_bytes(&received.payload)
        {
            signed
                .verify_for_query(&exchange.query, &signer, &trusted_key)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            AuthenticatedRootMountRecoveryObservationV2::LocalLive(
                AuthenticatedRootMountRecoveryUnavailableV1 {
                    signed_plan_digest: signed.signed_storage_plan_digest(),
                },
            )
        } else {
            let signed = SignedNativeRecoveryUnavailableV1::from_canonical_bytes(&received.payload)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            signed
                .verify_for_query(&exchange.query, &signer, &trusted_key)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            AuthenticatedRootMountRecoveryObservationV2::NativeNoDispatch(
                AuthenticatedRootMountNativeRecoveryUnavailableV1 {
                    terminal_digests: signed
                        .terminal_digests()
                        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
                    canonical_query: exchange.query.to_canonical_bytes().to_vec(),
                    signed_settlement: received.payload,
                },
            )
        };
        self.recovery_sequence = exchange.query.sequence();
        Ok(Some(observation))
    }

    /// Challenges Provider about one old protected Inventory without resending it.
    ///
    /// Only a current-session, nonce-bound, descriptor-free signed answer is
    /// accepted. Completed evidence remains nonauthorizing until the existing
    /// historical Mount receipt verifier consumes the opaque captured value.
    ///
    /// # Errors
    ///
    /// Closes this session for query drift, changed peer or signer, malformed
    /// answer, transferred descriptor, or stale protected custody.
    pub fn advance_inventory_readback(
        &mut self,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        signed_request_digest: ObjectDigest,
        mount_attempt_record_digest: ObjectDigest,
    ) -> Result<InventoryReadbackProgressV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let (current_holder, current_provider, _) = self.current_authority_scope_v2()?;
        if self.catalog_exchange.is_some()
            || self.recovery_exchange.is_some()
            || provider_id != current_provider
            || holder_id != current_holder
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if let Some(exchange) = &self.inventory_readback_exchange {
            if exchange.query.authorities() != (provider_id, holder_id)
                || exchange.query.signed_request_digest() != signed_request_digest
                || exchange.query.mount_attempt_record_digest() != mount_attempt_record_digest
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        } else {
            let nonce = self.custody.draw_nonce_at(current_unix_seconds()?)?;
            let sequence = self
                .recovery_sequence
                .checked_add(1)
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let query = InventoryReadbackQueryV1::new(
                self.session.binding(),
                nonce,
                sequence,
                provider_id,
                holder_id,
                signed_request_digest,
                mount_attempt_record_digest,
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            self.inventory_readback_exchange =
                Some(RootInventoryReadbackExchangeV1 { query, sent: false });
        }

        let exchange = self
            .inventory_readback_exchange
            .as_mut()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        if !exchange.sent {
            match self.carrier.send(&exchange.query.to_canonical_bytes()) {
                Ok(()) => exchange.sent = true,
                Err(CarrierFailureV1::Retryable) => {
                    return Ok(InventoryReadbackProgressV1::Pending);
                }
                Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
            }
        }
        let received = match self
            .carrier
            .receive_zero_descriptors(MAXIMUM_INVENTORY_READBACK_PACKET_BYTES)
        {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return Ok(InventoryReadbackProgressV1::Pending),
            Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
        };
        if !received
            .execution
            .has_same_execution(&self.provider_execution)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        let exchange = self
            .inventory_readback_exchange
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let answer = SignedInventoryReadbackV1::from_canonical_bytes(&received.payload)
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
        answer
            .verify_for_query(&exchange.query, &signer, &trusted_key)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.recovery_sequence = exchange.query.sequence();
        let Some((response, completed_at_seconds, deadline_seconds)) = answer.completed() else {
            return Ok(InventoryReadbackProgressV1::Unavailable);
        };
        let persisted = super::PersistedProviderOutcomeV1 {
            method: aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory,
            signed_request_digest: *signed_request_digest.as_bytes(),
            response_digest:
                *aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                    aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory,
                    response,
                )
                .as_bytes(),
            completed_at_seconds,
            deadline_seconds,
        };
        let captured = self.capture_persisted_mount_provider_outcome_v2(
            aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory,
            response.to_vec(),
            None,
            persisted,
        )?;
        Ok(InventoryReadbackProgressV1::Completed(captured))
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
        self.advance_catalog_currentness_checked(minimum, || Ok(()))
    }

    // Native preparation supplies its same original paired deadline. The
    // legacy control API retains its existing behavior and no external caller
    // can substitute this private per-I/O check for native signer custody.
    pub(super) fn advance_catalog_currentness_checked(
        &mut self,
        minimum: &ProviderCatalogFloorV1,
        require_current: impl FnMut() -> Result<(), SourceProviderSecurityError>,
    ) -> Result<Option<AuthenticatedRootMountCatalogCurrentnessV1>, SourceProviderSecurityError>
    {
        let mut retained = None;
        self.advance_catalog_currentness_retaining_v5(minimum, require_current, &mut retained)?;
        Ok(retained)
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

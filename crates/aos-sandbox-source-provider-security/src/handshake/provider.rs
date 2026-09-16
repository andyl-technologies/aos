//! Provider-side Root Mount authentication and hello-response states.

use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_FRAME_BYTES, ProviderRequestSequenceExpectationV1,
    ProviderRequestVerificationContextV1, SignedSourceExportLeaseV1, SignedSourceProviderHelloV1,
    SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1,
    SignedSourceProviderStatusV1, SignedSourceReleaseReceiptV1, SourceExportLeaseV1,
    SourceProviderAuthorityV1, SourceProviderDescriptorRole, SourceProviderHelloV1,
    SourceProviderIngressSessionV1, SourceProviderInventoryV1, SourceProviderMessageV1,
    SourceProviderMethod, SourceProviderPeerRole, SourceProviderReceiptV1,
    SourceProviderResponseStatusV1, SourceProviderStatus, SourceReleaseReceiptV1,
    decode_acquire_response, decode_inventory_response, decode_message, decode_release_response,
    digest_signed_export_lease, digest_signed_hello, empty_descriptor_set_commitment_v1,
    encode_acquire_response, encode_inventory_response, encode_message, encode_release_response,
    response_result_digest_v1, sign_export_lease, sign_hello, sign_inventory,
    sign_provider_receipt, sign_release_receipt, sign_response_status, verify_hello,
    verify_provider_request,
};

use super::{HandshakeTransitionV1, current_unix_seconds, process_identity};
use crate::SourceProviderSecurityError;
use crate::carrier::{CarrierFailureV1, InertSourceProviderCarrierV1};
use crate::custody::ProtectedProviderCustodyV1;
use crate::execution::ProcessExecutionEvidenceV1;

const MAXIMUM_CURRENT_REQUEST_LIFETIME_SECONDS: i64 = 300;
const FIXED_PROVIDER_SOURCE_PROVIDER_CUSTODY: &str = "/var/lib/aos/source-provider/authority";

#[path = "provider/completion.rs"]
mod completion;
#[path = "provider/session.rs"]
mod session;

pub(super) struct AwaitingRootMountHelloV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
}

pub(super) struct VerifiedRootMountHelloV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    root_mount_hello: SignedSourceProviderHelloV1,
    root_mount_execution: ProcessExecutionEvidenceV1,
}

pub(super) struct ProviderHelloPreparedV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    session: SourceProviderIngressSessionV1,
    root_mount_execution: ProcessExecutionEvidenceV1,
    packet: Vec<u8>,
}

/// Owns the current authenticated provider-ingress session.
///
/// No public constructor, generic signer, raw key, or carrier extractor exists.
/// Its narrow request-verification and typed-signing methods revalidate both
/// protected custody and peer-process continuity before every operation.
pub struct CurrentProviderIngressSessionV1 {
    custody: ProtectedProviderCustodyV1,
    carrier: InertSourceProviderCarrierV1,
    session: SourceProviderIngressSessionV1,
    root_mount_execution: ProcessExecutionEvidenceV1,
}

enum ProviderSourceProviderOwnerStateV1 {
    Awaiting(AwaitingRootMountHelloV1),
    Verified(VerifiedRootMountHelloV1),
    Prepared(ProviderHelloPreparedV1),
    Current(CurrentProviderIngressSessionV1),
}

/// Owns fixed provider custody and one adopted Root-Mount channel.
///
/// The dormant owner opens only the compiled-in provider authority directory,
/// adopts an already-connected descriptor-subject socket, and retains every
/// retryable handshake state. It creates no listener, socket path, backend,
/// route advertisement, or service loop.
pub struct ProviderSourceProviderOwnerV1 {
    state: Option<ProviderSourceProviderOwnerStateV1>,
    predecessor: Option<CurrentProviderSessionProjectionV1>,
}

/// Reports whether provider-side authenticated hello exchange is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSourceProviderHandshakeStatusV1 {
    /// The nonblocking channel must be advanced again when ready.
    Pending,
    /// The authenticated provider ingress session is current.
    Current,
}

/// Restricts signing to one exact protected-journal request reservation.
///
/// The facade has no public constructor. It borrows the current live custody
/// and a move-only authorization minted from the exact materialized AOSSPL
/// attempt. Each artifact purpose may be used at most once.
pub struct ProviderOwnerSecurityFacadeV1<'session, 'journal, 'authority, 'authorization> {
    session: &'session mut CurrentProviderIngressSessionV1,
    journal: &'journal aos_sandbox::ProtectedJournalAuthority<'authority>,
    authorization: &'authorization super::ProviderOutcomeAuthorizationV1,
}

/// Carries physical receipt facts without descriptor or signing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquireReceiptFactsV1 {
    acquisition_id: aos_sandbox_core::ObjectDigest,
    kernel_boot_id: [u8; 16],
    device: u64,
    inode: u64,
    unique_mount_id: u64,
    observed_proof_digest: aos_sandbox_core::ObjectDigest,
    descriptor_commitment: aos_sandbox_core::ObjectDigest,
}

impl AcquireReceiptFactsV1 {
    /// Constructs nonauthorizing facts for one physically revalidated source root.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for a sentinel identity or digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        acquisition_id: aos_sandbox_core::ObjectDigest,
        kernel_boot_id: [u8; 16],
        device: u64,
        inode: u64,
        unique_mount_id: u64,
        observed_proof_digest: aos_sandbox_core::ObjectDigest,
        descriptor_commitment: aos_sandbox_core::ObjectDigest,
    ) -> Result<Self, SourceProviderSecurityError> {
        if acquisition_id.as_bytes() == &[0; 32]
            || kernel_boot_id == [0; 16]
            || device == 0
            || inode == 0
            || unique_mount_id == 0
            || observed_proof_digest.as_bytes() == &[0; 32]
            || descriptor_commitment.as_bytes() == &[0; 32]
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(Self {
            acquisition_id,
            kernel_boot_id,
            device,
            inode,
            unique_mount_id,
            observed_proof_digest,
            descriptor_commitment,
        })
    }
}

/// Retains signed completion artifacts through exact protected commit.
///
/// No artifact or response accessor exists. The only public transition
/// consumes the builder into an opaque committed outcome after exact
/// preflight, protected commit, and postcommit currentness validation.
pub struct ProviderCompletionBuilderV1 {
    transaction: aos_sandbox::JournalTransaction,
    preflight: aos_sandbox::ProtectedJournalPreflight,
    transaction_commitment: aos_sandbox_core::ObjectDigest,
    artifact_commitment: aos_sandbox_core::ObjectDigest,
    reservation_commitment: aos_sandbox_core::ObjectDigest,
    response_sequence: u64,
    method: SourceProviderMethod,
    session_binding: aos_sandbox_core::ObjectDigest,
    response: Option<Vec<u8>>,
}

/// Carries one exact recovered response authorized for a single carrier handoff.
pub struct RevalidatedProviderReplayV1 {
    snapshot: aos_sandbox::ProtectedJournalSnapshot,
    method: SourceProviderMethod,
    response_sequence: u64,
    session_binding: aos_sandbox_core::ObjectDigest,
    response: Vec<u8>,
    has_source_root: bool,
}

impl core::fmt::Debug for RevalidatedProviderReplayV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RevalidatedProviderReplayV1([redacted])")
    }
}

impl core::fmt::Debug for ProviderCompletionBuilderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderCompletionBuilderV1([redacted])")
    }
}

/// Projects non-secret identity from one freshly revalidated ingress session.
///
/// The private-construction, non-cloneable value authenticates only the call
/// during which it was produced. It grants no journal, effect, signing, or send
/// authority.
pub struct CurrentProviderSessionProjectionV1 {
    provider: SourceProviderAuthorityV1,
    holder: SourceProviderAuthorityV1,
    session_binding: aos_sandbox_core::ObjectDigest,
    root_process_instance: [u8; 16],
    provider_process_instance: [u8; 16],
}

/// Retains a pre-receive predecessor identity for explicit ingress reopen.
///
/// The value is move-only and has no scalar projection. It can only seed a
/// fresh fixed Provider handshake after the prior carrier was fatally closed.
pub struct ProviderIngressReopenCheckpointV1 {
    predecessor: CurrentProviderSessionProjectionV1,
}

impl core::fmt::Debug for ProviderIngressReopenCheckpointV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderIngressReopenCheckpointV1([protected predecessor])")
    }
}

/// Proves that security custody consumed and closed a prior live session.
///
/// The evidence is move-only and can be persisted only by the provider owner
/// as the cause for advancing a holder's current-session head.
pub struct ProviderSessionSupersessionEvidenceV1 {
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    prior_session_binding: aos_sandbox_core::ObjectDigest,
    replacement_session_binding: aos_sandbox_core::ObjectDigest,
    prior_root_process_instance: [u8; 16],
}

impl core::fmt::Debug for CurrentProviderSessionProjectionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentProviderSessionProjectionV1([redacted])")
    }
}

impl core::fmt::Debug for ProviderSessionSupersessionEvidenceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderSessionSupersessionEvidenceV1([redacted])")
    }
}

impl CurrentProviderSessionProjectionV1 {
    /// Returns the current provider authority.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the authenticated holder authority.
    #[must_use]
    pub const fn holder(&self) -> &SourceProviderAuthorityV1 {
        &self.holder
    }

    /// Returns the authenticated transcript binding.
    #[must_use]
    pub const fn session_binding(&self) -> aos_sandbox_core::ObjectDigest {
        self.session_binding
    }

    /// Returns the authenticated Root Mount process instance.
    #[must_use]
    pub const fn root_process_instance(&self) -> [u8; 16] {
        self.root_process_instance
    }

    /// Returns the authenticated provider process instance.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }
}

impl ProviderSessionSupersessionEvidenceV1 {
    /// Returns the provider authority identity.
    #[must_use]
    pub const fn provider_id(&self) -> [u8; 16] {
        self.provider_id
    }

    /// Returns the holder authority identity.
    #[must_use]
    pub const fn holder_id(&self) -> [u8; 16] {
        self.holder_id
    }

    /// Returns the consumed prior transcript binding.
    #[must_use]
    pub const fn prior_session_binding(&self) -> aos_sandbox_core::ObjectDigest {
        self.prior_session_binding
    }

    /// Returns the replacement transcript binding.
    #[must_use]
    pub const fn replacement_session_binding(&self) -> aos_sandbox_core::ObjectDigest {
        self.replacement_session_binding
    }

    /// Returns the prior Root Mount process instance.
    #[must_use]
    pub const fn prior_root_process_instance(&self) -> [u8; 16] {
        self.prior_root_process_instance
    }
}

impl core::fmt::Debug for CurrentProviderIngressSessionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentProviderIngressSessionV1([redacted])")
    }
}

impl core::fmt::Debug for ProviderSourceProviderOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderSourceProviderOwnerV1([protected owner])")
    }
}

impl ProviderSourceProviderOwnerV1 {
    /// Opens fixed provider custody and adopts one connected socket.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when fixed protected custody,
    /// process identity, or channel configuration cannot be authenticated.
    pub fn open_fixed(
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        let custody = ProtectedProviderCustodyV1::load(std::path::Path::new(
            FIXED_PROVIDER_SOURCE_PROVIDER_CUSTODY,
        ))?;
        let awaiting = AwaitingRootMountHelloV1::accept(custody, socket)?;
        Ok(Self {
            state: Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting)),
            predecessor: None,
        })
    }

    /// Opens a fresh carrier as the successor of a fatally closed ingress.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when fixed protected custody,
    /// process identity, or the replacement channel cannot be authenticated.
    #[doc(hidden)]
    pub fn open_fixed_recovery(
        socket: DescriptorSubjectSocket,
        checkpoint: ProviderIngressReopenCheckpointV1,
    ) -> Result<
        Self,
        (
            SourceProviderSecurityError,
            ProviderIngressReopenCheckpointV1,
        ),
    > {
        let custody = match ProtectedProviderCustodyV1::load(std::path::Path::new(
            FIXED_PROVIDER_SOURCE_PROVIDER_CUSTODY,
        )) {
            Ok(custody) => custody,
            Err(error) => return Err((error, checkpoint)),
        };
        let awaiting = match AwaitingRootMountHelloV1::accept(custody, socket) {
            Ok(awaiting) => awaiting,
            Err(error) => return Err((error, checkpoint)),
        };
        Ok(Self {
            state: Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting)),
            predecessor: Some(checkpoint.predecessor),
        })
    }

    /// Advances exactly one nonblocking authenticated hello transition.
    ///
    /// Retryable I/O remains owner-held. Fatal failure closes the carrier and
    /// consumes the state so it cannot be reused as a second session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for fatal custody, transport,
    /// peer-execution, or transcript failure.
    pub fn advance_handshake(
        &mut self,
    ) -> Result<ProviderSourceProviderHandshakeStatusV1, SourceProviderSecurityError> {
        let state = self
            .state
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        match state {
            ProviderSourceProviderOwnerStateV1::Awaiting(awaiting) => {
                match awaiting.receive_root_mount() {
                    HandshakeTransitionV1::Complete(verified) => {
                        self.state = Some(ProviderSourceProviderOwnerStateV1::Verified(verified));
                        Ok(ProviderSourceProviderHandshakeStatusV1::Pending)
                    }
                    HandshakeTransitionV1::Retry(awaiting) => {
                        self.state = Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting));
                        Ok(ProviderSourceProviderHandshakeStatusV1::Pending)
                    }
                    HandshakeTransitionV1::Fatal(error) => Err(error),
                }
            }
            ProviderSourceProviderOwnerStateV1::Verified(verified) => {
                let prepared = verified.prepare_provider_hello()?;
                self.state = Some(ProviderSourceProviderOwnerStateV1::Prepared(prepared));
                Ok(ProviderSourceProviderHandshakeStatusV1::Pending)
            }
            ProviderSourceProviderOwnerStateV1::Prepared(prepared) => match prepared.send() {
                HandshakeTransitionV1::Complete(current) => {
                    self.state = Some(ProviderSourceProviderOwnerStateV1::Current(current));
                    Ok(ProviderSourceProviderHandshakeStatusV1::Current)
                }
                HandshakeTransitionV1::Retry(prepared) => {
                    self.state = Some(ProviderSourceProviderOwnerStateV1::Prepared(prepared));
                    Ok(ProviderSourceProviderHandshakeStatusV1::Pending)
                }
                HandshakeTransitionV1::Fatal(error) => Err(error),
            },
            ProviderSourceProviderOwnerStateV1::Current(mut current) => {
                current.revalidate()?;
                self.state = Some(ProviderSourceProviderOwnerStateV1::Current(current));
                Ok(ProviderSourceProviderHandshakeStatusV1::Current)
            }
        }
    }

    /// Consumes the fixed owner into its fixed-ledger ingress session.
    ///
    /// This is a purpose-limited handoff for the fixed provider-ledger owner;
    /// pending and poisoned owners cannot mint a session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the complete handshake is
    /// current immediately before the handoff.
    #[doc(hidden)]
    pub fn into_fixed_ledger_session(
        mut self,
        journal: aos_sandbox::FixedSourceProviderJournalHandoffV1<'_, '_>,
    ) -> Result<CurrentProviderIngressSessionV1, SourceProviderSecurityError> {
        journal
            .validate_current()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let state = self
            .state
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let ProviderSourceProviderOwnerStateV1::Current(mut current) = state else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        current.revalidate()?;
        if self.predecessor.is_some() {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(current)
    }

    /// Consumes a completed same-carrier successor into session and supersession evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the prior and successor
    /// projections name the same fixed authorities and Root-Mount execution.
    #[doc(hidden)]
    pub fn into_fixed_recovery_ledger_session(
        mut self,
        journal: aos_sandbox::FixedSourceProviderJournalHandoffV1<'_, '_>,
    ) -> Result<
        (
            CurrentProviderIngressSessionV1,
            ProviderSessionSupersessionEvidenceV1,
        ),
        SourceProviderSecurityError,
    > {
        journal
            .validate_current()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let predecessor = self
            .predecessor
            .take()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let state = self
            .state
            .take()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let ProviderSourceProviderOwnerStateV1::Current(mut current) = state else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        let successor = current.current_projection()?;
        if predecessor.provider != successor.provider
            || predecessor.holder != successor.holder
            || predecessor.root_process_instance != successor.root_process_instance
            || predecessor.session_binding == successor.session_binding
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let evidence = ProviderSessionSupersessionEvidenceV1 {
            provider_id: predecessor.provider.authority_id(),
            holder_id: predecessor.holder.authority_id(),
            prior_session_binding: predecessor.session_binding,
            replacement_session_binding: successor.session_binding,
            prior_root_process_instance: predecessor.root_process_instance,
        };
        Ok((current, evidence))
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Reuses the protected connected carrier for a fresh successor transcript.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the current provider
    /// custody and peer execution remain live immediately before rotation.
    #[doc(hidden)]
    pub fn into_successor_owner(
        mut self,
    ) -> Result<ProviderSourceProviderOwnerV1, SourceProviderSecurityError> {
        let predecessor = self.current_projection()?;
        let Self {
            custody,
            carrier,
            session: _,
            root_mount_execution: _,
        } = self;
        let awaiting = AwaitingRootMountHelloV1::accept_carrier(custody, carrier)?;
        Ok(ProviderSourceProviderOwnerV1 {
            state: Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting)),
            predecessor: Some(predecessor),
        })
    }
}

impl core::fmt::Debug for ProviderOwnerSecurityFacadeV1<'_, '_, '_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderOwnerSecurityFacadeV1([redacted])")
    }
}

impl AwaitingRootMountHelloV1 {
    pub(super) fn accept(
        custody: ProtectedProviderCustodyV1,
        socket: DescriptorSubjectSocket,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::accept_carrier(custody, InertSourceProviderCarrierV1::adopt(socket)?)
    }

    fn accept_carrier(
        mut custody: ProtectedProviderCustodyV1,
        mut carrier: InertSourceProviderCarrierV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        let result = current_unix_seconds().and_then(|now| custody.inner_mut().revalidate_at(now));
        if let Err(error) = result {
            return Err(poison_and_close(&mut custody, &mut carrier, error));
        }
        Ok(Self { custody, carrier })
    }

    pub(super) fn receive_root_mount(
        mut self,
    ) -> HandshakeTransitionV1<AwaitingRootMountHelloV1, VerifiedRootMountHelloV1> {
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
        let root_mount_hello = match decode_message(&received.payload) {
            Ok(SourceProviderMessageV1::HelloRequest(hello)) => hello,
            _ => {
                return HandshakeTransitionV1::Fatal(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
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
        if verify_root_hello_preflight(&self.custody, &root_mount_hello, &received.execution, now)
            .is_err()
            || received.execution.boot_id() != self.custody.inner().execution().boot_id()
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
        HandshakeTransitionV1::Complete(VerifiedRootMountHelloV1 {
            custody: self.custody,
            carrier: self.carrier,
            root_mount_hello,
            root_mount_execution: received.execution,
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

impl VerifiedRootMountHelloV1 {
    pub(super) fn prepare_provider_hello(
        mut self,
    ) -> Result<ProviderHelloPreparedV1, SourceProviderSecurityError> {
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
        let initial = self.custody.inner_mut().revalidate_at(now).and_then(|_| {
            self.root_mount_execution
                .revalidate(self.carrier.socket().peer())
        });
        if let Err(error) = initial {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let nonce = match self.custody.draw_nonce_at(now) {
            Ok(nonce) => nonce,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let (client_nonce, client_digest, capabilities, recursive, kernel_coupled) = {
            let inner = self.custody.inner();
            let client = self.root_mount_hello.subject();
            (
                client.nonce(),
                digest_signed_hello(&self.root_mount_hello),
                client.proof_class_capabilities() & inner.manifest().proof_capabilities(),
                client.supports_recursive() && inner.manifest().allow_recursive(),
                client.supports_kernel_coupled() && inner.manifest().allow_kernel_coupled(),
            )
        };
        if capabilities == 0 {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let hello = {
            let inner = self.custody.inner();
            SourceProviderHelloV1::new(
                SourceProviderPeerRole::Provider,
                nonce,
                inner.process_instance(),
                inner.execution().boot_id(),
                inner.provider_authority().traffic_signer().clone(),
                inner.root_authority().traffic_signer().clone(),
                inner.route().route_id(),
                inner.route().route_generation(),
                inner.route().route_digest(),
                Some(client_digest),
                capabilities,
                recursive,
                kernel_coupled,
            )
        };
        let hello = match hello {
            Ok(hello) => hello,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let before_signature = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
        if let Err(error) = before_signature {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let provider_hello = {
            let inner = self.custody.inner();
            sign_hello(
                hello,
                inner.provider_authority().hello_signer().clone(),
                inner.hello_key().signing_key(),
            )
        };
        let provider_hello = match provider_hello {
            Ok(hello) => hello,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        let after_signature = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
        if let Err(error) = after_signature {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        let root_identity = match process_identity(&self.root_mount_execution) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    error,
                ));
            }
        };
        let session = {
            let inner = self.custody.inner();
            SourceProviderIngressSessionV1::authenticate(
                client_nonce,
                now,
                self.root_mount_hello,
                provider_hello.clone(),
                inner.trust(),
                inner.root_authority(),
                inner.provider_authority(),
                root_identity.clone(),
                root_identity,
                inner.root_peer(),
                inner.route(),
            )
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
        let packet = match encode_message(&SourceProviderMessageV1::HelloResponse(provider_hello)) {
            Ok(packet) => packet,
            Err(_) => {
                return Err(poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                ));
            }
        };
        if packet.len() != aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let final_check = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
        if let Err(error) = final_check {
            return Err(poison_and_close(
                &mut self.custody,
                &mut self.carrier,
                error,
            ));
        }
        Ok(ProviderHelloPreparedV1 {
            custody: self.custody,
            carrier: self.carrier,
            session,
            root_mount_execution: self.root_mount_execution,
            packet,
        })
    }
}

impl ProviderHelloPreparedV1 {
    pub(super) fn send(
        mut self,
    ) -> HandshakeTransitionV1<ProviderHelloPreparedV1, CurrentProviderIngressSessionV1> {
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
                HandshakeTransitionV1::Complete(CurrentProviderIngressSessionV1 {
                    custody: self.custody,
                    carrier: self.carrier,
                    session: self.session,
                    root_mount_execution: self.root_mount_execution,
                })
            }
        }
    }

    fn revalidate_before_action(&mut self) -> Result<(), SourceProviderSecurityError> {
        let result = current_unix_seconds()
            .and_then(|now| self.custody.inner_mut().revalidate_at(now))
            .and_then(|_| {
                self.root_mount_execution
                    .revalidate(self.carrier.socket().peer())
            });
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

fn validate_prospective_completion(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    transaction: &aos_sandbox::JournalTransaction,
) -> Result<(), SourceProviderSecurityError> {
    journal
        .validate_source_provider_authority()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let current = aos_sandbox_source_provider_ledger::collect_bounded_records(
        journal
            .records()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let mut prospective = current.clone();
    for record in transaction.records() {
        if record.namespace() != aos_sandbox::RecordNamespace::SourceProviderAuthority {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        match record.value() {
            Some(value) => {
                prospective.insert(record.key().to_vec(), value.to_vec());
            }
            None => {
                prospective.remove(record.key());
            }
        }
    }
    aos_sandbox_source_provider_ledger::validate_prospective_transition(
        current
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    Ok(())
}

fn attempt_key_commitment(key: &[u8]) -> aos_sandbox_core::ObjectDigest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.protected-attempt-key.v1\0");
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key);
    aos_sandbox_core::ObjectDigest::from_bytes(hasher.finalize().into())
}

fn classify_send_response(
    bytes: &[u8],
    has_source_root: bool,
) -> Result<
    (SourceProviderMethod, (aos_sandbox_core::ObjectDigest, u64)),
    SourceProviderSecurityError,
> {
    let mut matched = None;
    for method in [
        SourceProviderMethod::Acquire,
        SourceProviderMethod::Release,
        SourceProviderMethod::Inventory,
    ] {
        if let Ok(identity) = validate_send_response(method, bytes, has_source_root) {
            if matched.replace((method, identity)).is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        }
    }
    matched.ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn validate_send_response(
    method: SourceProviderMethod,
    bytes: &[u8],
    has_source_root: bool,
) -> Result<(aos_sandbox_core::ObjectDigest, u64), SourceProviderSecurityError> {
    let (status, descriptor_is_required, canonical) = match method {
        SourceProviderMethod::Acquire => {
            let response = decode_acquire_response(bytes)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            let descriptor_is_required = match response.signed_receipt() {
                Some(receipt) => {
                    let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(receipt)
                        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                    receipt.subject().descriptor_role() == SourceProviderDescriptorRole::SourceRoot
                }
                None => false,
            };
            (
                response.signed_status().clone(),
                descriptor_is_required,
                encode_acquire_response(&response),
            )
        }
        SourceProviderMethod::Release => {
            let response = decode_release_response(bytes)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            (
                response.signed_status().clone(),
                false,
                encode_release_response(&response),
            )
        }
        SourceProviderMethod::Inventory => {
            let response = decode_inventory_response(bytes)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            (
                response.signed_status().clone(),
                false,
                encode_inventory_response(&response),
            )
        }
        SourceProviderMethod::Hello => {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
    };
    if canonical != bytes
        || status.subject().method() != method
        || descriptor_is_required != has_source_root
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok((
        status.subject().session_binding(),
        status.subject().response_sequence(),
    ))
}

fn validate_send_response_with_source_root(
    method: SourceProviderMethod,
    bytes: &[u8],
    source_root: Option<&crate::ProviderSourceRootHandoffV1>,
) -> Result<(aos_sandbox_core::ObjectDigest, u64), SourceProviderSecurityError> {
    let identity = validate_send_response(method, bytes, source_root.is_some())?;
    let Some(source_root) = source_root else {
        return Ok(identity);
    };
    if method != SourceProviderMethod::Acquire {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let response = decode_acquire_response(bytes)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let receipt = response
        .signed_receipt()
        .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok())
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let observation = source_root.observation();
    if receipt.subject().kernel_boot_id() != observation.kernel_boot_id()
        || receipt.subject().device() != observation.device()
        || receipt.subject().inode() != observation.inode()
        || receipt.subject().unique_mount_id() != observation.unique_mount_id()
        || response.signed_status().subject().descriptor_commitment()
            != aos_sandbox_source_provider_protocol::source_root_descriptor_commitment_v1(
                observation,
            )
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(identity)
}

fn completion_response_matches(
    authorization: &super::ProviderOutcomeAuthorizationV1,
    bytes: &[u8],
) -> bool {
    use aos_sandbox_source_provider_protocol::SourceProviderMethod;
    let signed_status = match authorization.method {
        SourceProviderMethod::Acquire => decode_acquire_response(bytes)
            .ok()
            .filter(|value| encode_acquire_response(value) == bytes)
            .map(|value| value.signed_status().clone()),
        SourceProviderMethod::Release => decode_release_response(bytes)
            .ok()
            .filter(|value| encode_release_response(value) == bytes)
            .map(|value| value.signed_status().clone()),
        SourceProviderMethod::Inventory => decode_inventory_response(bytes)
            .ok()
            .filter(|value| encode_inventory_response(value) == bytes)
            .map(|value| value.signed_status().clone()),
        SourceProviderMethod::Hello => None,
    };
    signed_status.is_some_and(|signed| {
        let status = signed.subject();
        status.method() == authorization.method
            && status.request_id() == authorization.request_id
            && status.signed_request_digest() == authorization.signed_request_digest
            && status.session_binding() == authorization.session_binding
            && status.provider_process_instance() == authorization.provider_process_instance
            && status.response_sequence() == authorization.response_sequence
            && signed.signer().authority_id() == authorization.provider.authority_id()
            && signed.signer().authority_generation()
                == authorization.provider.authority_generation()
            && signed.signer().authority_digest() == authorization.provider.authority_digest()
    })
}

fn authorization_authority_is_current(
    authorization: &super::ProviderOutcomeAuthorizationV1,
    now_seconds: i64,
) -> bool {
    now_seconds >= 0 && now_seconds < authorization.current_valid_until_seconds
}

fn validate_authorization_journal(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    authorization: &super::ProviderOutcomeAuthorizationV1,
) -> Result<(), SourceProviderSecurityError> {
    if authorization.reservation_commitment.as_bytes() == &[0; 32] {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    journal
        .validate_source_provider_authority_snapshot(&authorization.journal_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn verify_root_hello_preflight(
    custody: &ProtectedProviderCustodyV1,
    signed: &SignedSourceProviderHelloV1,
    execution: &ProcessExecutionEvidenceV1,
    now_seconds: i64,
) -> Result<(), SourceProviderSecurityError> {
    let inner = custody.inner();
    let signer = signed.signer();
    let subject = signed.subject();
    if signer != inner.root_authority().hello_signer()
        || subject.role() != SourceProviderPeerRole::RootMount
        || subject.kernel_boot_id() != inner.execution().boot_id()
        || subject.expected_peer_traffic_signer() != inner.provider_authority().traffic_signer()
        || subject.traffic_signer() != inner.root_authority().traffic_signer()
        || subject.route_id() != inner.route().route_id()
        || subject.route_generation() != inner.route().route_generation()
        || subject.route_digest() != inner.route().route_digest()
        || subject.proof_class_capabilities() & !inner.manifest().proof_capabilities() != 0
        || (subject.supports_recursive() && !inner.manifest().allow_recursive())
        || (subject.supports_kernel_coupled() && !inner.manifest().allow_kernel_coupled())
        || execution.credentials().effective_user_id() != inner.route_file().root_mount_uid()
        || execution.credentials().effective_group_id() != inner.route_file().root_mount_gid()
        || crate::execution::cgroup_object_digest(execution.cgroup_path_digest())
            != inner.route_file().root_mount_cgroup_digest()
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    inner
        .root_authority()
        .validate_at(now_seconds)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let key = inner
        .trust()
        .keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    verify_hello(signed, key.public_key())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn poison_and_close(
    custody: &mut ProtectedProviderCustodyV1,
    carrier: &mut InertSourceProviderCarrierV1,
    error: SourceProviderSecurityError,
) -> SourceProviderSecurityError {
    custody.inner_mut().poison();
    carrier.close();
    error
}

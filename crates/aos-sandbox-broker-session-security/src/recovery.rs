//! Protected journal authority and recovery for authenticated broker traffic.
//!
//! This module is sealed inside the security crate. It accepts history only
//! through a protected current-head reader, sandwiches every derivation or
//! reopen with a second protected read, replays every retained signature into
//! the protocol traffic machine, and alone mints move-only resend authority.
//! The dormant protected-journal owner below is the only reader implementation.
//!
//! The private reader, recovery states, and public opaque tokens remain
//! co-located so their constructors can stay module-private; splitting them
//! would broaden precisely the authority boundary this module is sealing.

use aos_sandbox_broker_session_protocol::{
    BrokerOutcomeAdmissionV1, BrokerRequestAdmissionV1, BrokerSessionDurableEndpointV1,
    BrokerSessionDurableError, BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1,
    BrokerSessionDurableRecordV1, BrokerSessionPeerBindingV1, BrokerSessionProtectedBindingsV1,
    BrokerSessionProtocolV1, BrokerSessionReplayEvidenceV1, BrokerSessionTrafficStateV1,
    CanonicalBrokerResponseEnvelopeV1, ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1, complete_signed_outcome_digest_v1,
    complete_signed_request_digest_v1, decode_canonical_request_v1, decode_canonical_response_v1,
    hello_message::BrokerMethod, mount_qualification_outcome_projection_v1,
};
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::authenticated_session::all_methods::checkpoint::{
    derive_pending_request_record_v1, derive_successor_request_record_v1, derive_terminal_record_v1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerRequestDirectionV1,
    AuthenticatedBrokerSemanticBindingsV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    admit_server_received_authenticated_broker_method_request_v1,
    prepare_client_sent_authenticated_broker_method_request_v1,
    prepare_server_sent_authenticated_broker_method_outcome_v1,
};
use sha2::{Digest as _, Sha256};

use crate::BrokerSessionSecurityError;

mod journal;

pub(crate) use journal::{FixedEndpointCustodyV1, ProtectedBrokerSessionJournalV1};
pub use journal::{
    ProtectedBrokerOutcomeCommitRecoveryV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerRequestCommitResultV1,
    ProtectedBrokerSessionFixedCustodyV1, ProtectedBrokerSessionFixedEndpointV1,
    ProtectedBrokerSessionInitializationRecoveryV1, ProtectedBrokerSessionInitializationResultV1,
};
pub(crate) use journal::{
    ProtectedBrokerReceivedRequestAdmissionV1, ProtectedBrokerSessionOwnerV1,
    ProtectedPriorTerminalExchangeV1,
};

const PEER_BINDING_DOMAIN: &[u8] = b"aos-sandbox-broker-session-peer-binding-v1\0";

/// Exact kernel-observed peer execution supplied by the protected socket owner.
pub(crate) struct ObservedBrokerPeerExecutionV1 {
    uid: u32,
    gid: u32,
    pid: u32,
    process_execution_id: [u8; 16],
}

impl ObservedBrokerPeerExecutionV1 {
    /// Captures the still-live connection establisher and binds its process ID
    /// to the already verified session transcript.
    fn from_connection(
        peer: &ConnectionPeerIdentity,
        process_execution_id: [u8; 16],
    ) -> Result<Self, BrokerSessionSecurityError> {
        let credentials = peer.credentials();
        if !peer
            .is_alive()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            || peer.initial_info().pid() != credentials.pid().get()
            || process_execution_id.iter().all(|byte| *byte == 0)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: credentials.pid().get(),
            process_execution_id,
        })
    }

    fn binding(
        &self,
        endpoint: BrokerSessionDurableEndpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError> {
        let expected_process = match endpoint {
            BrokerSessionDurableEndpointV1::Client => context.broker_process(),
            BrokerSessionDurableEndpointV1::Broker => context.client_process(),
        };
        if self.process_execution_id != expected_process {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut digest = Sha256::new();
        digest.update(PEER_BINDING_DOMAIN);
        digest.update(context.node_id());
        digest.update(context.boot_id());
        digest.update([context.protocol() as u8]);
        digest.update(context.protocol_major().to_be_bytes());
        digest.update(context.protocol_minor().to_be_bytes());
        digest.update((context.audience() as i32).to_be_bytes());
        digest.update(context.client_process());
        digest.update(context.broker_process());
        digest.update(transcript.session_binding());
        digest.update([endpoint as u8]);
        digest.update(self.uid.to_be_bytes());
        digest.update(self.gid.to_be_bytes());
        digest.update(self.pid.to_be_bytes());
        digest.update(self.process_execution_id);
        BrokerSessionPeerBindingV1::new(digest.finalize().into()).map_err(map_durable)
    }

    fn matches_request_for_endpoint(
        &self,
        endpoint: BrokerSessionDurableEndpointV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> bool {
        if endpoint == BrokerSessionDurableEndpointV1::Client {
            return self.process_execution_id == context.broker_process();
        }
        let admitted = request.peer();
        let policy = request.peer_policy();
        admitted.uid == self.uid
            && admitted.gid == self.gid
            && admitted.pid == Some(self.pid)
            && policy.uid == self.uid
            && policy.gid.is_none_or(|gid| gid == self.gid)
            && policy.audience == context.audience()
            && self.process_execution_id == context.client_process()
    }
}

/// Captures one protected read of the journal head and its surrounding state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedBrokerSessionJournalSnapshotV1 {
    generation: u64,
    endpoint_publication: [u8; 32],
    current_catalog: [u8; 32],
    current_head: [u8; 32],
    history: Option<Vec<u8>>,
}

impl ProtectedBrokerSessionJournalSnapshotV1 {
    /// Constructs a snapshot only for the concrete protected journal owner.
    fn new(
        generation: u64,
        endpoint_publication: [u8; 32],
        current_catalog: [u8; 32],
        current_head: [u8; 32],
        history: Option<Vec<u8>>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let has_history = history.is_some();
        if endpoint_publication.iter().all(|byte| *byte == 0)
            || current_catalog.iter().all(|byte| *byte == 0)
            || has_history == current_head.iter().all(|byte| *byte == 0)
            || (has_history && generation == 0)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            generation,
            endpoint_publication,
            current_catalog,
            current_head,
            history,
        })
    }

    fn protected_bindings(
        &self,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<BrokerSessionProtectedBindingsV1, BrokerSessionSecurityError> {
        BrokerSessionProtectedBindingsV1::new(
            context.protected_context_digest(),
            self.endpoint_publication,
            self.current_catalog,
        )
        .map_err(map_durable)
    }

    fn decode_history(&self) -> Result<BrokerSessionDurableHistoryV1, BrokerSessionSecurityError> {
        let bytes = self
            .history
            .as_deref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = BrokerSessionDurableHistoryV1::decode(bytes).map_err(map_durable)?;
        if history.head_commitment() != self.current_head {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(history)
    }
}

/// Reads one protected, current journal generation and its authority bindings.
trait ProtectedBrokerSessionJournalAuthorityV1: journal::SealedJournalAuthority {
    /// Reads the current journal head through already pinned protected objects.
    fn read_current(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError>;
}

/// Move-only full history awaiting a caller-owned atomic compare-and-swap.
#[must_use = "dropping a prepared request history abandons authenticated progress"]
pub(crate) struct ProtectedBrokerRequestWriteV1 {
    history: BrokerSessionDurableHistoryV1,
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_revision: u64,
}

impl ProtectedBrokerRequestWriteV1 {
    fn prepare_initial_from_snapshot(
        request: &AuthenticatedBrokerMethodRequestV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ObservedBrokerPeerExecutionV1,
        before: &ProtectedBrokerSessionJournalSnapshotV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        require_current_session(transcript, context)?;
        let endpoint = endpoint_for_request(request);
        if before.history.is_some()
            || !peer.matches_request_for_endpoint(endpoint, request, context)
            || request.session_binding() != transcript.session_binding()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let protected_bindings = before.protected_bindings(context)?;
        require_request_catalog(request, protected_bindings)?;
        let peer_binding = peer.binding(endpoint, transcript, context)?;
        let record =
            derive_pending_request_record_v1(request, 1, [0; 32], peer_binding, protected_bindings)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let history =
            BrokerSessionDurableHistoryV1::from_records(vec![record]).map_err(map_durable)?;
        Ok(Self {
            history,
            expected_generation: before.generation,
            expected_head: before.current_head,
            expected_revision: 0,
        })
    }

    /// Derives the first history under one stable protected-state sandwich.
    pub(crate) fn prepare_initial(
        authority: &mut ProtectedBrokerSessionJournalV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ObservedBrokerPeerExecutionV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let before = authority.read_current(transcript.protocol())?;
        let write =
            Self::prepare_initial_from_snapshot(request, context, transcript, peer, &before)?;
        require_unchanged(authority, transcript.protocol(), &before)?;
        Ok(write)
    }

    /// Appends a successor request only to the protected authoritative head.
    pub(crate) fn prepare_successor(
        authority: &mut ProtectedBrokerSessionJournalV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ObservedBrokerPeerExecutionV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        require_current_session(transcript, context)?;
        let before = authority.read_current(transcript.protocol())?;
        let history = before.decode_history()?;
        let traffic = reconstruct_traffic(&history, transcript, context)?;
        let terminal = history.head().map_err(map_durable)?.clone();
        let current_bindings = before.protected_bindings(context)?;
        let request_catalog = request
            .catalog_binding()
            .unwrap_or_else(|| current_bindings.current_catalog());
        let successor_bindings = BrokerSessionProtectedBindingsV1::new(
            current_bindings.protected_context(),
            current_bindings.endpoint_publication(),
            request_catalog,
        )
        .map_err(map_durable)?;
        require_request_catalog(request, successor_bindings)?;
        let peer_binding = peer.binding(terminal.endpoint(), transcript, context)?;
        if terminal.phase() != BrokerSessionDurablePhaseV1::Terminal
            || terminal.protected_bindings().protected_context()
                != current_bindings.protected_context()
            || terminal.protected_bindings().endpoint_publication()
                != current_bindings.endpoint_publication()
            || terminal.peer_binding() != peer_binding
            || traffic.has_outstanding_request()
            || !peer.matches_request_for_endpoint(terminal.endpoint(), request, context)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let record = derive_successor_request_record_v1(
            &terminal,
            request,
            peer_binding,
            successor_bindings,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut records = history.records().to_vec();
        records.push(record);
        let history = BrokerSessionDurableHistoryV1::from_records(records).map_err(map_durable)?;
        require_unchanged(authority, transcript.protocol(), &before)?;
        Ok(Self {
            history,
            expected_generation: before.generation,
            expected_head: before.current_head,
            expected_revision: terminal.revision(),
        })
    }

    /// Returns the canonical full-history replacement bytes.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.history.encode().map_err(map_durable)
    }

    /// Returns the protected catalog head retained by this exact successor.
    pub(crate) fn current_catalog(&self) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.history
            .head()
            .map(|record| record.protected_bindings().current_catalog())
            .map_err(map_durable)
    }

    /// Returns the exact protected journal generation expected by the write.
    pub(crate) const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    /// Returns the exact current-head commitment expected by the write.
    pub(crate) const fn expected_head(&self) -> [u8; 32] {
        self.expected_head
    }

    /// Returns the exact durable record revision expected by the write.
    pub(crate) const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
}

/// Binds one broker-side outcome gate to an exact protected current head.
struct ProtectedBrokerOutcomeCurrentnessV1 {
    generation: u64,
    head: [u8; 32],
    durable_revision: u64,
    durable_commitment: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
}

/// Opaque move-only authority to admit one exact protected broker outcome.
///
/// This gate has no public constructor. The security owner mints it only after
/// re-reading the authoritative full history, re-verifying every retained
/// signature, recomputing the peer binding, and completing a protected-state
/// currentness sandwich. Mount qualification adds a narrower method-specific
/// admission on top of this all-method broker-owned gate.
#[must_use = "the protected broker request still requires an outcome decision"]
pub struct ProtectedBrokerOutcomeAdmissionGateV1 {
    history: BrokerSessionDurableHistoryV1,
    traffic: BrokerSessionTrafficStateV1,
    request: AuthenticatedBrokerMethodRequestV1,
    retained_outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    context: ProtectedBrokerSessionVerificationContextV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    currentness: ProtectedBrokerOutcomeCurrentnessV1,
}

/// Classifies a protected broker outcome as new progress or an exact replay.
#[must_use = "the caller must retain new durable progress or honor replay no-write evidence"]
pub enum ProtectedBrokerOutcomeAdmissionV1 {
    /// The outcome is new and owns its uncommitted durable advancement.
    New {
        /// Move-only pre-CAS traffic state and prepared journal replacement.
        advancement: ProtectedBrokerOutcomePendingAdvancementV1,
    },
    /// The current terminal outcome was repeated byte for byte.
    ExactReplay {
        /// Move-only evidence that the replay permits no journal write.
        replay: ProtectedBrokerOutcomeReplayV1,
    },
}

/// Move-only compare-and-swap target for one prepared terminal history.
#[must_use = "the protected owner must atomically compare and install the prepared history"]
pub struct ProtectedBrokerOutcomeDurableCasV1 {
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_revision: u64,
    expected_commitment: [u8; 32],
    replacement_head: [u8; 32],
}

impl ProtectedBrokerOutcomeDurableCasV1 {
    /// Returns the protected journal generation observed by recovery.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    /// Returns the protected history-head binding observed by recovery.
    #[must_use]
    pub const fn expected_head(&self) -> [u8; 32] {
        self.expected_head
    }

    /// Returns the exact durable-record revision expected at the head.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Returns the exact canonical durable-record commitment expected at the head.
    #[must_use]
    pub const fn expected_commitment(&self) -> [u8; 32] {
        self.expected_commitment
    }

    /// Returns the canonical commitment of the prepared replacement head.
    #[must_use]
    pub const fn replacement_head(&self) -> [u8; 32] {
        self.replacement_head
    }
}

/// Owns one uncommitted outcome and its prepared durable replacement.
///
/// The exact response and next traffic state remain private until a
/// security-minted confirmed-CAS readback is consumed.
#[must_use = "dropping a pending advancement abandons authenticated broker progress"]
pub struct ProtectedBrokerOutcomePendingAdvancementV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    client_sequence: u64,
    broker_sequence: u64,
    session_binding: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
    next_traffic: BrokerSessionTrafficStateV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    replacement_history: Vec<u8>,
    durable_cas: ProtectedBrokerOutcomeDurableCasV1,
    context: ProtectedBrokerSessionVerificationContextV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    admission_commitment: [u8; 32],
    qualification_record_commitment: Option<[u8; 32]>,
}

impl ProtectedBrokerOutcomePendingAdvancementV1 {
    fn confirm_committed_preserving(
        self,
        readback: ProtectedBrokerOutcomeCommitReadbackV1,
    ) -> Result<ProtectedBrokerOutcomeCommittedAdvancementV1, (BrokerSessionSecurityError, Self)>
    {
        if readback.admission_commitment != self.admission_commitment
            || readback.confirmed_generation
                != match self.durable_cas.expected_generation.checked_add(1) {
                    Some(generation) => generation,
                    None => return Err((BrokerSessionSecurityError::Currentness, self)),
                }
            || readback.confirmed_head != self.durable_cas.replacement_head
        {
            return Err((BrokerSessionSecurityError::Currentness, self));
        }
        let signed_outcome_digest =
            match decode_canonical_response_v1(self.outcome.canonical_packet()) {
                Ok(outcome) => complete_signed_outcome_digest_v1(outcome.signed_artifact()),
                Err(_) => return Err((BrokerSessionSecurityError::Currentness, self)),
            };
        let currentness_owner = ProtectedBrokerOutcomeCurrentnessOwnerV1 {
            request: self.outcome.request().clone(),
            outcome: self.outcome.clone(),
            context: self.context,
            transcript: self.transcript,
            protected_generation: readback.confirmed_generation,
            protected_head: readback.confirmed_head,
            peer_binding: self.peer_binding,
            protected_bindings: self.protected_bindings,
            qualification_record_commitment: self.qualification_record_commitment,
        };
        Ok(ProtectedBrokerOutcomeCommittedAdvancementV1 {
            method: self.method,
            request_id: self.request_id,
            signed_request_digest: self.signed_request_digest,
            client_sequence: self.client_sequence,
            broker_sequence: self.broker_sequence,
            session_binding: self.session_binding,
            peer_binding: self.peer_binding,
            protected_bindings: self.protected_bindings,
            next_traffic: self.next_traffic,
            expected_generation: self.durable_cas.expected_generation,
            expected_head: self.durable_cas.expected_head,
            expected_revision: self.durable_cas.expected_revision,
            expected_commitment: self.durable_cas.expected_commitment,
            replacement_head: self.durable_cas.replacement_head,
            admission_commitment: self.admission_commitment,
            qualification_record_commitment: self.qualification_record_commitment,
            signed_outcome_digest,
            exact_packet: self.outcome.canonical_packet().to_vec(),
            currentness_owner,
        })
    }

    /// Returns the canonical full-history bytes prepared for atomic replacement.
    #[must_use]
    pub fn replacement_history(&self) -> &[u8] {
        &self.replacement_history
    }

    /// Returns the move-only token's exact durable compare-and-swap facts.
    #[must_use]
    pub const fn durable_cas(&self) -> &ProtectedBrokerOutcomeDurableCasV1 {
        &self.durable_cas
    }

    /// Returns the exact binding shared with its post-CAS committed advancement.
    #[must_use]
    pub const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }

    /// Returns the qualification record committed by the signed Mount outcome.
    #[must_use]
    pub const fn qualification_record_commitment(&self) -> Option<[u8; 32]> {
        self.qualification_record_commitment
    }

    /// Consumes this pending state after a security-minted CAS readback.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError::Currentness`] unless the readback
    /// proves this exact replacement history was atomically installed.
    pub fn confirm_committed(
        self,
        readback: ProtectedBrokerOutcomeCommitReadbackV1,
    ) -> Result<ProtectedBrokerOutcomeCommittedAdvancementV1, BrokerSessionSecurityError> {
        self.confirm_committed_preserving(readback)
            .map_err(|(error, _)| error)
    }
}

/// Opaque proof that protected CAS readback selected one exact replacement.
///
/// This value has no public constructor. The security-owned protected journal
/// recovery path alone mints it after full-history and traffic reconstruction.
#[must_use = "the matching pending advancement still requires confirmation"]
pub struct ProtectedBrokerOutcomeCommitReadbackV1 {
    admission_commitment: [u8; 32],
    confirmed_generation: u64,
    confirmed_head: [u8; 32],
}

impl ProtectedBrokerOutcomeCommitReadbackV1 {
    /// Reopens protected state and proves one exact CAS replacement current.
    pub(crate) fn confirm_after_cas(
        authority: &mut ProtectedBrokerSessionJournalV1,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        peer: &ObservedBrokerPeerExecutionV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let expected_generation = pending
            .durable_cas
            .expected_generation
            .checked_add(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (history, traffic, current) =
            reopen_current(authority, &pending.transcript, &pending.context, peer)?;
        let encoded = history.encode().map_err(map_durable)?;
        let head = history.head().map_err(map_durable)?;
        let recomputed_admission = pending_outcome_admission_commitment(
            pending.outcome.request(),
            &pending.outcome,
            pending.peer_binding,
            pending.protected_bindings,
            &pending.durable_cas,
            &pending.replacement_history,
        )?;
        if current.generation != expected_generation
            || current.current_head != pending.durable_cas.replacement_head
            || current.protected_bindings(&pending.context)? != pending.protected_bindings
            || encoded != pending.replacement_history
            || traffic != pending.next_traffic
            || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.outcome_packet() != Some(pending.outcome.canonical_packet())
            || recomputed_admission != pending.admission_commitment
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            admission_commitment: pending.admission_commitment,
            confirmed_generation: current.generation,
            confirmed_head: current.current_head,
        })
    }
}

/// Exposes usable traffic only after protected CAS and exact readback succeed.
#[must_use = "the committed advancement carries the only usable advanced traffic state"]
pub struct ProtectedBrokerOutcomeCommittedAdvancementV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    client_sequence: u64,
    broker_sequence: u64,
    session_binding: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
    next_traffic: BrokerSessionTrafficStateV1,
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_revision: u64,
    expected_commitment: [u8; 32],
    replacement_head: [u8; 32],
    admission_commitment: [u8; 32],
    qualification_record_commitment: Option<[u8; 32]>,
    signed_outcome_digest: [u8; 32],
    exact_packet: Vec<u8>,
    currentness_owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn response_descriptor_roles(
        &self,
    ) -> Result<
        &'static [aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole],
        BrokerSessionSecurityError,
    > {
        let profile = aos_sandbox_broker_session_protocol::authenticated_broker_method_profile_v1(
            self.method,
        )
        .ok_or(BrokerSessionSecurityError::Currentness)?;
        Ok(match self.currentness_owner.outcome.result() {
            AuthenticatedBrokerMethodResultV1::Success { .. } => {
                profile.success_response_descriptor_roles()
            }
            AuthenticatedBrokerMethodResultV1::Error(_) => {
                profile.error_response_descriptor_roles()
            }
        })
    }

    /// Returns the exact admitted method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the exact completed request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the complete signed-request digest cross-linked by the outcome.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }

    /// Returns the admitted client-to-broker request sequence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the admitted broker-to-client outcome sequence.
    #[must_use]
    pub const fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    /// Returns the exact authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the exact protected-peer binding rechecked after CAS.
    #[must_use]
    pub const fn peer_binding(&self) -> BrokerSessionPeerBindingV1 {
        self.peer_binding
    }

    /// Returns the protected context, endpoint publication, and catalog bindings.
    #[must_use]
    pub const fn protected_bindings(&self) -> BrokerSessionProtectedBindingsV1 {
        self.protected_bindings
    }

    /// Returns usable stop-and-wait state after durable confirmation.
    #[must_use]
    pub const fn next_traffic(&self) -> &BrokerSessionTrafficStateV1 {
        &self.next_traffic
    }

    /// Returns the original protected generation used by the successful CAS.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    /// Returns the original protected history head used by the successful CAS.
    #[must_use]
    pub const fn expected_head(&self) -> [u8; 32] {
        self.expected_head
    }

    /// Returns the original durable-record revision used by the successful CAS.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Returns the original durable-record commitment used by the successful CAS.
    #[must_use]
    pub const fn expected_commitment(&self) -> [u8; 32] {
        self.expected_commitment
    }

    /// Returns the protected replacement head confirmed by readback.
    #[must_use]
    pub const fn replacement_head(&self) -> [u8; 32] {
        self.replacement_head
    }

    /// Returns the exact binding shared with the pre-CAS pending advancement.
    #[must_use]
    pub const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }

    /// Returns the qualification record committed by the signed Mount outcome.
    #[must_use]
    pub const fn qualification_record_commitment(&self) -> Option<[u8; 32]> {
        self.qualification_record_commitment
    }

    /// Returns the exact domain-separated digest of the signed outcome artifact.
    #[must_use]
    pub const fn signed_outcome_digest(&self) -> [u8; 32] {
        self.signed_outcome_digest
    }

    /// Returns the exact signed terminal packet confirmed by protected readback.
    #[must_use]
    pub fn exact_packet(&self) -> &[u8] {
        &self.exact_packet
    }

    /// Consumes the advancement into exact terminal-head currentness authority.
    #[must_use]
    pub fn into_currentness_owner(self) -> ProtectedBrokerOutcomeCurrentnessOwnerV1 {
        self.currentness_owner
    }

    /// Consumes the advancement into its authenticated outcome and currentness owner.
    #[must_use]
    pub fn into_outcome_and_currentness(
        self,
    ) -> (
        AuthenticatedBrokerMethodOutcomeV1,
        ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) {
        let outcome = self.currentness_owner.outcome.clone();
        (outcome, self.currentness_owner)
    }
}

/// Proves that one protected terminal outcome is a byte-exact no-write replay.
#[must_use = "an exact replay must never mint a second effect or durable write"]
pub struct ProtectedBrokerOutcomeReplayV1 {
    method: BrokerMethod,
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    client_sequence: u64,
    broker_sequence: u64,
    signed_outcome_digest: [u8; 32],
    session_binding: [u8; 32],
    peer_binding: BrokerSessionPeerBindingV1,
    protected_generation: u64,
    protected_head: [u8; 32],
    protected_bindings: BrokerSessionProtectedBindingsV1,
    exact_packet: Vec<u8>,
    qualification_record_commitment: Option<[u8; 32]>,
    currentness_owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
}

impl ProtectedBrokerOutcomeReplayV1 {
    pub(crate) fn request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        &self.currentness_owner.request
    }

    pub(crate) fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.currentness_owner.outcome
    }

    pub(crate) fn verification_context(&self) -> &ProtectedBrokerSessionVerificationContextV1 {
        &self.currentness_owner.context
    }

    pub(crate) fn response_descriptor_roles(
        &self,
    ) -> Result<
        &'static [aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole],
        BrokerSessionSecurityError,
    > {
        let profile = aos_sandbox_broker_session_protocol::authenticated_broker_method_profile_v1(
            self.method,
        )
        .ok_or(BrokerSessionSecurityError::Currentness)?;
        Ok(match self.currentness_owner.outcome.result() {
            AuthenticatedBrokerMethodResultV1::Success { .. } => {
                profile.success_response_descriptor_roles()
            }
            AuthenticatedBrokerMethodResultV1::Error(_) => {
                profile.error_response_descriptor_roles()
            }
        })
    }

    /// Returns the exact replayed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the exact completed request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the complete signed-request digest cross-linked by the replay.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }

    /// Returns the exact admitted client-to-broker request sequence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the replayed broker-to-client sequence.
    #[must_use]
    pub const fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    /// Returns the digest of the byte-identical signed outcome artifact.
    #[must_use]
    pub const fn signed_outcome_digest(&self) -> [u8; 32] {
        self.signed_outcome_digest
    }

    /// Returns the exact authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the exact protected-peer binding rechecked by recovery.
    #[must_use]
    pub const fn peer_binding(&self) -> BrokerSessionPeerBindingV1 {
        self.peer_binding
    }

    /// Returns the protected journal generation that retained the replay.
    #[must_use]
    pub const fn protected_generation(&self) -> u64 {
        self.protected_generation
    }

    /// Returns the protected current history-head binding that retained the replay.
    #[must_use]
    pub const fn protected_head(&self) -> [u8; 32] {
        self.protected_head
    }

    /// Returns the protected context, endpoint publication, and catalog bindings.
    #[must_use]
    pub const fn protected_bindings(&self) -> BrokerSessionProtectedBindingsV1 {
        self.protected_bindings
    }

    /// Returns the byte-exact canonical outcome packet classified as replay.
    #[must_use]
    pub fn exact_packet(&self) -> &[u8] {
        &self.exact_packet
    }

    /// Returns the qualification record committed by the replayed Mount outcome.
    #[must_use]
    pub const fn qualification_record_commitment(&self) -> Option<[u8; 32]> {
        self.qualification_record_commitment
    }

    /// Consumes replay evidence into exact terminal-head currentness authority.
    #[must_use]
    pub fn into_currentness_owner(self) -> ProtectedBrokerOutcomeCurrentnessOwnerV1 {
        self.currentness_owner
    }

    /// Consumes replay evidence into its authenticated outcome and currentness owner.
    #[must_use]
    pub fn into_outcome_and_currentness(
        self,
    ) -> (
        AuthenticatedBrokerMethodOutcomeV1,
        ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) {
        let outcome = self.currentness_owner.outcome.clone();
        (outcome, self.currentness_owner)
    }
}

/// Owns the protected artifacts needed to revalidate one terminal broker head.
///
/// This move-only value has no public constructor. New and exact-replay
/// admissions mint it only from fully authenticated protected journal state.
#[must_use = "revalidate protected terminal currentness immediately before the effect handoff"]
pub struct ProtectedBrokerOutcomeCurrentnessOwnerV1 {
    pub(super) request: AuthenticatedBrokerMethodRequestV1,
    pub(super) outcome: AuthenticatedBrokerMethodOutcomeV1,
    pub(super) context: ProtectedBrokerSessionVerificationContextV1,
    pub(super) transcript: VerifiedBrokerSessionTranscriptV1,
    pub(super) protected_generation: u64,
    pub(super) protected_head: [u8; 32],
    pub(super) peer_binding: BrokerSessionPeerBindingV1,
    pub(super) protected_bindings: BrokerSessionProtectedBindingsV1,
    pub(super) qualification_record_commitment: Option<[u8; 32]>,
}

/// Borrows the sole protected journal owner after an exact currentness sandwich.
///
/// Keeping this token alive keeps the mutable journal-owner borrow live through
/// the associated effect-authority construction.
#[must_use = "retain protected currentness through the effect-authority handoff"]
pub struct ProtectedBrokerOutcomeCurrentV1<'authority> {
    pub(super) authority: &'authority mut ProtectedBrokerSessionJournalV1,
    pub(super) connection_peer: &'authority ConnectionPeerIdentity,
    pub(super) owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
}

impl ProtectedBrokerOutcomeCurrentV1<'_> {
    pub(crate) const fn authenticated_outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.owner.outcome
    }

    pub(crate) fn into_currentness_owner(self) -> ProtectedBrokerOutcomeCurrentnessOwnerV1 {
        self.owner
    }

    /// Revalidates the retained terminal head and live kernel peer in place.
    ///
    /// # Errors
    ///
    /// Returns an error unless the protected journal, endpoint context,
    /// transcript, terminal packet, and pidfd-backed peer remain exact.
    pub(crate) fn revalidate(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.authority
            .validate_broker_outcome(&self.owner, self.connection_peer)
    }
}

/// Move-only protected recovery of one broker-side outcome gate.
#[must_use = "the recovered broker request still requires an outcome decision"]
pub(crate) struct ProtectedBrokerOutcomeGateRecoveryV1 {
    history: BrokerSessionDurableHistoryV1,
    gate: ProtectedBrokerOutcomeAdmissionGateV1,
}

impl ProtectedBrokerOutcomeGateRecoveryV1 {
    /// Reopens a broker head and reconstructs its new-or-replay outcome gate.
    pub(crate) fn reopen_broker_outcome(
        authority: &mut ProtectedBrokerSessionJournalV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        peer: &ObservedBrokerPeerExecutionV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let (history, traffic, current) = reopen_current(authority, transcript, context, peer)?;
        let head = history.head().map_err(map_durable)?;
        if head.endpoint() != BrokerSessionDurableEndpointV1::Broker
            || !request_matches_head(
                request,
                head,
                AuthenticatedBrokerRequestDirectionV1::ServerReceive,
            )
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let retained_outcome = match head.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared if traffic.has_outstanding_request() => {
                None
            }
            BrokerSessionDurablePhaseV1::Terminal if !traffic.has_outstanding_request() => Some(
                reconstruct_terminal_semantics(&history, request, transcript, context, &traffic)?,
            ),
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let durable_commitment = head.commitment().map_err(map_durable)?;
        if durable_commitment != current.current_head {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let currentness = ProtectedBrokerOutcomeCurrentnessV1 {
            generation: current.generation,
            head: current.current_head,
            durable_revision: head.revision(),
            durable_commitment,
            peer_binding: head.peer_binding(),
            protected_bindings: current.protected_bindings(context)?,
        };
        Ok(Self {
            history: history.clone(),
            gate: ProtectedBrokerOutcomeAdmissionGateV1 {
                history,
                traffic,
                request: request.clone(),
                retained_outcome,
                context: context.clone(),
                transcript: transcript.clone(),
                currentness,
            },
        })
    }

    /// Returns the fully verified protected history.
    #[must_use]
    pub(crate) const fn history(&self) -> &BrokerSessionDurableHistoryV1 {
        &self.history
    }

    /// Consumes recovery into the reconstructed outcome gate.
    #[must_use]
    pub(crate) fn into_gate(self) -> ProtectedBrokerOutcomeAdmissionGateV1 {
        self.gate
    }
}

impl ProtectedBrokerOutcomeAdmissionGateV1 {
    pub(crate) fn verification_context(&self) -> ProtectedBrokerSessionVerificationContextV1 {
        self.context.clone()
    }

    /// Returns the exact pending or completed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.request.method()
    }

    /// Returns the exact request identifier bound to outcome admission.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request.request_id()
    }

    /// Returns the client-to-broker sequence bound to outcome admission.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.request.client_sequence()
    }

    /// Returns the complete signed-request digest bound to the outcome.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.request.signed_request_digest()
    }

    /// Returns the exact authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.request.session_binding()
    }

    /// Returns the exact protected-peer binding rechecked by recovery.
    #[must_use]
    pub const fn peer_binding(&self) -> BrokerSessionPeerBindingV1 {
        self.currentness.peer_binding
    }

    /// Returns the protected journal generation observed by recovery.
    #[must_use]
    pub const fn protected_generation(&self) -> u64 {
        self.currentness.generation
    }

    /// Returns the protected current history-head binding observed by recovery.
    #[must_use]
    pub const fn protected_head(&self) -> [u8; 32] {
        self.currentness.head
    }

    /// Returns the exact current durable-record revision.
    #[must_use]
    pub const fn durable_revision(&self) -> u64 {
        self.currentness.durable_revision
    }

    /// Returns the exact current durable-record commitment.
    #[must_use]
    pub const fn durable_commitment(&self) -> [u8; 32] {
        self.currentness.durable_commitment
    }

    /// Returns the protected context, endpoint publication, and catalog bindings.
    #[must_use]
    pub const fn protected_bindings(&self) -> BrokerSessionProtectedBindingsV1 {
        self.currentness.protected_bindings
    }

    /// Authenticates and semantically admits one exact broker-authored outcome.
    ///
    /// A new outcome returns the advanced stop-and-wait state together with a
    /// canonical full-history replacement and its exact protected compare-and-
    /// swap target. A byte-identical terminal replay returns no-write evidence
    /// that cannot be converted into an advancement.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError`] for a changed context, malformed
    /// or mismatched signature, method/body/profile failure, replay
    /// equivocation, or an inconsistent protected current head.
    pub fn admit_outcome(
        self,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        self.admit_outcome_inner(outcome, None)
    }

    pub(crate) fn admit_outcome_with_descriptor_count(
        self,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
        descriptor_count: usize,
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        self.admit_outcome_inner_with_descriptor_count(outcome, None, descriptor_count)
    }

    /// Authenticates a Mount outcome that commits one complete qualification record.
    ///
    /// The expected commitment must occur in the signed, canonically validated
    /// Mount result before that result can enter protected terminal history.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionSecurityError::Currentness`] when the outcome is
    /// not a successful Mount Apply carrying the exact expected commitment, or
    /// when ordinary protected outcome admission fails.
    pub fn admit_qualified_mount_outcome(
        self,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
        qualification_record_commitment: [u8; 32],
        qualification_outcome_projection: [u8; 32],
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        if qualification_record_commitment
            .iter()
            .all(|byte| *byte == 0)
            || qualification_outcome_projection
                .iter()
                .all(|byte| *byte == 0)
            || mount_qualification_outcome_projection_v1(outcome)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                != qualification_outcome_projection
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.admit_outcome_inner(outcome, Some(qualification_record_commitment))
    }

    fn admit_outcome_inner(
        self,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
        qualification_record_commitment: Option<[u8; 32]>,
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        self.admit_outcome_inner_with_descriptor_count(outcome, qualification_record_commitment, 0)
    }

    fn admit_outcome_inner_with_descriptor_count(
        self,
        outcome: &CanonicalBrokerResponseEnvelopeV1,
        qualification_record_commitment: Option<[u8; 32]>,
        descriptor_count: usize,
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        let packet = outcome.encoded_bytes();
        let admission = match self.request.direction() {
            AuthenticatedBrokerRequestDirectionV1::ClientSend => {
                admit_client_received_authenticated_broker_method_outcome_v1(
                    &self.traffic,
                    &self.request,
                    packet,
                    self.retained_outcome.as_ref(),
                    descriptor_count,
                    &self.context,
                )
            }
            AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
                prepare_server_sent_authenticated_broker_method_outcome_v1(
                    &self.traffic,
                    &self.request,
                    packet,
                    self.retained_outcome.as_ref(),
                    descriptor_count,
                    &self.context,
                )
            }
        }
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;

        match admission {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New {
                outcome,
                next_traffic,
            } if self.retained_outcome.is_none()
                && outcome.filesystem_worker_qualification_commitment()
                    == qualification_record_commitment =>
            {
                self.advance_new_outcome(outcome, *next_traffic)
            }
            AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(replay)
                if self.retained_outcome.as_ref().is_some_and(|retained| {
                    retained.filesystem_worker_qualification_commitment()
                        == qualification_record_commitment
                }) =>
            {
                self.prove_exact_replay(replay, packet)
            }
            _ => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn advance_new_outcome(
        self,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        next_traffic: BrokerSessionTrafficStateV1,
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        Ok(ProtectedBrokerOutcomeAdmissionV1::New {
            advancement: prepare_pending_outcome_advancement(
                self.history,
                self.request,
                outcome,
                next_traffic,
                self.context,
                self.transcript,
                self.currentness,
            )?,
        })
    }

    fn prove_exact_replay(
        self,
        replay: BrokerSessionReplayEvidenceV1,
        packet: &[u8],
    ) -> Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError> {
        let retained = self
            .retained_outcome
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if replay.request_id() != self.request.request_id()
            || replay.sequence() != retained.broker_sequence()
            || packet != retained.canonical_packet()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let peer_binding = self.history.head().map_err(map_durable)?.peer_binding();
        let currentness_owner = ProtectedBrokerOutcomeCurrentnessOwnerV1 {
            request: self.request.clone(),
            outcome: retained.clone(),
            context: self.context,
            transcript: self.transcript,
            protected_generation: self.currentness.generation,
            protected_head: self.currentness.head,
            peer_binding,
            protected_bindings: self.currentness.protected_bindings,
            qualification_record_commitment: retained.filesystem_worker_qualification_commitment(),
        };
        Ok(ProtectedBrokerOutcomeAdmissionV1::ExactReplay {
            replay: ProtectedBrokerOutcomeReplayV1 {
                method: self.request.method(),
                request_id: self.request.request_id(),
                signed_request_digest: self.request.signed_request_digest(),
                client_sequence: self.request.client_sequence(),
                broker_sequence: retained.broker_sequence(),
                signed_outcome_digest: replay.signed_artifact_digest(),
                session_binding: self.request.session_binding(),
                peer_binding,
                protected_generation: self.currentness.generation,
                protected_head: self.currentness.head,
                protected_bindings: self.currentness.protected_bindings,
                exact_packet: packet.to_vec(),
                qualification_record_commitment: retained
                    .filesystem_worker_qualification_commitment(),
                currentness_owner,
            },
        })
    }
}

fn prepare_pending_outcome_advancement(
    history: BrokerSessionDurableHistoryV1,
    request: AuthenticatedBrokerMethodRequestV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    next_traffic: BrokerSessionTrafficStateV1,
    context: ProtectedBrokerSessionVerificationContextV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    currentness: ProtectedBrokerOutcomeCurrentnessV1,
) -> Result<ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
    let pending = history.head().map_err(map_durable)?;
    if pending.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || pending.request_id() != request.request_id()
        || pending.method() != request.method()
        || pending.session_binding() != request.session_binding()
        || currentness.durable_revision != pending.revision()
        || currentness.durable_commitment != pending.commitment().map_err(map_durable)?
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let terminal_catalog = match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { .. } => request
            .published_catalog_binding()
            .unwrap_or_else(|| currentness.protected_bindings.current_catalog()),
        AuthenticatedBrokerMethodResultV1::Error(_) => {
            currentness.protected_bindings.current_catalog()
        }
    };
    let terminal_bindings = BrokerSessionProtectedBindingsV1::new(
        currentness.protected_bindings.protected_context(),
        currentness.protected_bindings.endpoint_publication(),
        terminal_catalog,
    )
    .map_err(map_durable)?;
    let revision = pending
        .revision()
        .checked_add(1)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let predecessor = pending.commitment().map_err(map_durable)?;
    let terminal =
        derive_terminal_record_v1(pending, &outcome, revision, predecessor, terminal_bindings)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let mut records = history.records().to_vec();
    records.push(terminal);
    let replacement = BrokerSessionDurableHistoryV1::from_records(records).map_err(map_durable)?;
    let replacement_head = replacement.head_commitment();
    let replacement_history = replacement.encode().map_err(map_durable)?;
    let durable_cas = ProtectedBrokerOutcomeDurableCasV1 {
        expected_generation: currentness.generation,
        expected_head: currentness.head,
        expected_revision: currentness.durable_revision,
        expected_commitment: currentness.durable_commitment,
        replacement_head,
    };
    let admission_commitment = pending_outcome_admission_commitment(
        &request,
        &outcome,
        currentness.peer_binding,
        terminal_bindings,
        &durable_cas,
        &replacement_history,
    )?;
    let qualification_record_commitment = outcome.filesystem_worker_qualification_commitment();
    Ok(ProtectedBrokerOutcomePendingAdvancementV1 {
        method: request.method(),
        request_id: request.request_id(),
        signed_request_digest: request.signed_request_digest(),
        client_sequence: request.client_sequence(),
        broker_sequence: outcome.broker_sequence(),
        session_binding: request.session_binding(),
        peer_binding: currentness.peer_binding,
        protected_bindings: terminal_bindings,
        next_traffic,
        outcome,
        replacement_history,
        durable_cas,
        context,
        transcript,
        admission_commitment,
        qualification_record_commitment,
    })
}

fn pending_outcome_admission_commitment(
    request: &AuthenticatedBrokerMethodRequestV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    peer_binding: BrokerSessionPeerBindingV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
    durable_cas: &ProtectedBrokerOutcomeDurableCasV1,
    replacement_history: &[u8],
) -> Result<[u8; 32], BrokerSessionSecurityError> {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-protected-broker-outcome-admission-v1\0");
    digest.update((request.method() as i32).to_be_bytes());
    digest.update(request.request_id());
    digest.update(request.signed_request_digest());
    digest.update(request.client_sequence().to_be_bytes());
    digest.update(outcome.broker_sequence().to_be_bytes());
    digest.update(request.session_binding());
    digest.update(peer_binding.digest());
    digest.update(protected_bindings.protected_context());
    digest.update(protected_bindings.endpoint_publication());
    digest.update(protected_bindings.current_catalog());
    digest.update(durable_cas.expected_generation.to_be_bytes());
    digest.update(durable_cas.expected_head);
    digest.update(durable_cas.expected_revision.to_be_bytes());
    digest.update(durable_cas.expected_commitment);
    digest.update(durable_cas.replacement_head);
    digest.update(
        u64::try_from(outcome.canonical_packet().len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .to_be_bytes(),
    );
    digest.update(outcome.canonical_packet());
    digest.update(
        u64::try_from(replacement_history.len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .to_be_bytes(),
    );
    digest.update(replacement_history);
    Ok(digest.finalize().into())
}

fn reopen_current(
    authority: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
) -> Result<
    (
        BrokerSessionDurableHistoryV1,
        BrokerSessionTrafficStateV1,
        ProtectedBrokerSessionJournalSnapshotV1,
    ),
    BrokerSessionSecurityError,
> {
    require_current_session(transcript, context)?;
    let before = authority.read_current(transcript.protocol())?;
    let history = before.decode_history()?;
    let head = history.head().map_err(map_durable)?;
    let protected_bindings = before.protected_bindings(context)?;
    let peer_binding = peer.binding(head.endpoint(), transcript, context)?;
    if head.protocol() != transcript.protocol()
        || head.session_binding() != transcript.session_binding()
        || head.protected_bindings() != protected_bindings
        || head.peer_binding() != peer_binding
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let traffic = reconstruct_traffic(&history, transcript, context)?;
    require_unchanged(authority, transcript.protocol(), &before)?;
    Ok((history, traffic, before))
}

fn reconstruct_traffic(
    history: &BrokerSessionDurableHistoryV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<BrokerSessionTrafficStateV1, BrokerSessionSecurityError> {
    reconstruct_traffic_records(history.records(), transcript, context)
}

fn reconstruct_traffic_records(
    records: &[BrokerSessionDurableRecordV1],
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<BrokerSessionTrafficStateV1, BrokerSessionSecurityError> {
    let mut traffic = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    for record in records {
        match record.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => {
                let request = decode_canonical_request_v1(record.request_packet())
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                traffic = match traffic
                    .admit_request(
                        &request,
                        record.request_id(),
                        record.maximum_response_bytes(),
                        context,
                    )
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?
                {
                    BrokerRequestAdmissionV1::New { next_state, .. } => *next_state,
                    BrokerRequestAdmissionV1::ExactReplay(_) => {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                };
            }
            BrokerSessionDurablePhaseV1::Terminal => {
                let packet = record
                    .outcome_packet()
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let outcome = decode_canonical_response_v1(packet)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                traffic = match traffic
                    .admit_outcome(&outcome, context)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?
                {
                    BrokerOutcomeAdmissionV1::New { next_state, .. } => *next_state,
                    BrokerOutcomeAdmissionV1::ExactReplay(_) => {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                };
            }
        }
    }
    Ok(traffic)
}

fn request_matches_head(
    request: &AuthenticatedBrokerMethodRequestV1,
    head: &BrokerSessionDurableRecordV1,
    expected_direction: AuthenticatedBrokerRequestDirectionV1,
) -> bool {
    let signed = head.request_companion().signed_request();
    request.direction() == expected_direction
        && request.method() == head.method()
        && request.session_binding() == head.session_binding()
        && request.request_id() == head.request_id()
        && request.client_sequence() == head.client_sequence()
        && request.maximum_response_bytes() == head.maximum_response_bytes()
        && request.semantic_commitment() == head.request_semantic_binding()
        && request.signed_request_digest() == complete_signed_request_digest_v1(signed)
        && request.canonical_packet() == head.request_packet()
}

fn reconstruct_terminal_semantics(
    history: &BrokerSessionDurableHistoryV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    final_traffic: &BrokerSessionTrafficStateV1,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
    let head_index = history
        .records()
        .len()
        .checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let prior_traffic =
        reconstruct_traffic_records(&history.records()[..head_index], transcript, context)?;
    let packet = history
        .head()
        .map_err(map_durable)?
        .outcome_packet()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let declared_descriptor_count = decode_canonical_response_v1(packet)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?
        .message()
        .descriptors
        .len();
    let admission = match request.direction() {
        AuthenticatedBrokerRequestDirectionV1::ClientSend => {
            admit_client_received_authenticated_broker_method_outcome_v1(
                &prior_traffic,
                request,
                packet,
                None,
                0,
                context,
            )
        }
        AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
            prepare_server_sent_authenticated_broker_method_outcome_v1(
                &prior_traffic,
                request,
                packet,
                None,
                declared_descriptor_count,
                context,
            )
        }
    }
    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    match admission {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New {
            outcome,
            next_traffic,
        } if next_traffic.as_ref() == final_traffic => Ok(outcome),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn require_unchanged(
    authority: &mut ProtectedBrokerSessionJournalV1,
    protocol: BrokerSessionProtocolV1,
    before: &ProtectedBrokerSessionJournalSnapshotV1,
) -> Result<(), BrokerSessionSecurityError> {
    if authority.read_current(protocol)? != *before {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(())
}

fn endpoint_for_request(
    request: &AuthenticatedBrokerMethodRequestV1,
) -> BrokerSessionDurableEndpointV1 {
    match request.direction() {
        AuthenticatedBrokerRequestDirectionV1::ClientSend => BrokerSessionDurableEndpointV1::Client,
        AuthenticatedBrokerRequestDirectionV1::ServerReceive => {
            BrokerSessionDurableEndpointV1::Broker
        }
    }
}

fn require_request_catalog(
    request: &AuthenticatedBrokerMethodRequestV1,
    protected_bindings: BrokerSessionProtectedBindingsV1,
) -> Result<(), BrokerSessionSecurityError> {
    if request
        .catalog_binding()
        .is_some_and(|catalog| catalog != protected_bindings.current_catalog())
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(())
}

fn require_current_session(
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<(), BrokerSessionSecurityError> {
    if transcript.protected_context_digest() != context.protected_context_digest()
        || transcript.protocol() != context.protocol()
        || transcript.protocol_version() != (context.protocol_major(), context.protocol_minor())
        || transcript.audience() != context.audience()
        || transcript.client_process() != context.client_process()
        || transcript.broker_process() != context.broker_process()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(())
}

fn map_durable(_: BrokerSessionDurableError) -> BrokerSessionSecurityError {
    BrokerSessionSecurityError::Currentness
}

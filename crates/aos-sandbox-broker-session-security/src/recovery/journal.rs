//! Concrete protected storage for authenticated broker-session histories.
//!
//! Each namespace-47 value is one canonical, bounded full history. Namespace
//! 55 retains an immutable original Storage group history across rollover. The owner
//! consumes the protected endpoint that defines its stable role/manifest
//! identity and its process-specific publication. Reopen accepts an earlier
//! process publication only as an authenticated terminal rollover predecessor;
//! current-session authority still requires the live endpoint before and after
//! every read.

mod historical_checkpoint;
mod owner;
mod storage_inventory_abandonment;
mod storage_inventory_archive;
pub(crate) use storage_inventory_archive::ArchivedStorageInventoryHeadV1;

pub(crate) use historical_checkpoint::HistoricalSessionCheckpointV1;
use owner::JournalOwnerV1;

use std::path::{Path, PathBuf};

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, RecoverStorageInventoryRequestV1, RecoverStorageInventoryResponseV1,
    StorageInventoryRecoveryDispositionV1,
};
use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES, BrokerSessionDurableEndpointV1,
    BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1,
    BrokerSessionTrafficStateV1, ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1, decode_canonical_request_v1, decode_canonical_response_v1,
};
use aos_sandbox_core::ProtocolVersion;
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerRequestDirectionV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    authenticated_semantic_bindings_from_envelope_v1,
};
use aos_sandbox_protocol::{
    ValidatedStorageInventoryRecoveryResponseV1, decode_storage_inventory_recovery_response_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::handoff::{ProtectedBrokerEffectHandoffV1, effect_evidence};
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1,
};

use super::{
    ObservedBrokerPeerExecutionV1, ProtectedBrokerOutcomeCommitReadbackV1,
    ProtectedBrokerOutcomeCommittedAdvancementV1, ProtectedBrokerOutcomeCurrentV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, ProtectedBrokerOutcomeGateRecoveryV1,
    ProtectedBrokerOutcomePendingAdvancementV1, ProtectedBrokerOutcomeReplayV1,
    ProtectedBrokerRequestWriteV1, ProtectedBrokerSessionJournalAuthorityV1,
    ProtectedBrokerSessionJournalSnapshotV1,
    admit_server_received_authenticated_broker_method_request_v1,
    prepare_client_sent_authenticated_broker_method_request_v1, reconstruct_terminal_semantics,
    reconstruct_traffic, reconstruct_traffic_records, reopen_current, request_matches_head,
};

const KEY_MAGIC: &[u8; 8] = b"AOSBSJ01";
const VALUE_MAGIC: &[u8; 8] = b"AOSBSJ01";
const VALUE_VERSION_V2: u16 = 2;
const VALUE_VERSION_V3: u16 = 3;
const VALUE_FIXED_BYTES_V2: usize = 184;
const VALUE_FIXED_BYTES_V3: usize = 188;
const VALUE_DIGEST_BYTES: usize = 32;
const VALUE_DOMAIN_V2: &[u8] = b"aos.sandbox.broker-session.protected-history.v2\0";
const VALUE_DOMAIN_V3: &[u8] = b"aos.sandbox.broker-session.protected-history.v3\0";
const ENDPOINT_PUBLICATION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.endpoint-publication.v1\0";
const STABLE_ENDPOINT_IDENTITY_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.stable-endpoint-identity.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.journal-transaction.v2\0";
const STORAGE_GROUP_ARCHIVE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-group-archive.v1\0";
const STORAGE_GROUP_ARCHIVE_RETIRE_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-group-archive-retire.v1\0";
const STORAGE_INVENTORY_RETIRE_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-inventory-retire.v1\0";
const STORAGE_GROUP_ARCHIVE_MAGIC: &[u8; 8] = b"AOSASAH1";
const STORAGE_GROUP_ARCHIVE_VALUE_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-group-archive-value.v1\0";
const STORAGE_GROUP_ARCHIVE_HEADER_BYTES: usize = 8 + 2 + 16 + 4;
const STORAGE_GROUP_ARCHIVE_TRAILER_BYTES: usize = 32;
const MAXIMUM_PROTOCOL_RECORDS: usize = 4;
const MAXIMUM_STORAGE_GROUP_ARCHIVES: usize = 16;
const MAXIMUM_STORAGE_INVENTORY_ARCHIVES: usize = 16;
const MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS: usize = 16;
const PROTECTED_SESSION_JOURNAL: &str = "session.journal";

fn exact_storage_inventory_abandonment_marker(
    marker: Option<&storage_inventory_abandonment::StorageInventoryAbandonmentV1>,
    endpoint: BrokerSessionDurableEndpointV1,
    group_id: [u8; 16],
    group_digest: [u8; 32],
    inventory_digest: [u8; 32],
    client_head: [u8; 32],
) -> bool {
    marker.is_some_and(|record| {
        record.endpoint == endpoint
            && record.group_request_id == group_id
            && record.group_request_digest == group_digest
            && record.inventory_request_digest == inventory_digest
            && record.client_original_head == client_head
    })
}

/// Carries one terminal client exchange recovered from protected history.
pub(crate) struct ProtectedPriorTerminalExchangeV1 {
    pub(crate) method: BrokerMethod,
    pub(crate) request_id: [u8; 16],
    pub(crate) request_body: Vec<u8>,
    pub(crate) result: Result<Vec<u8>, String>,
}

/// Classifies the exact prior-session Storage group without sending another request.
pub(crate) enum ProtectedPriorAtomicStorageHistoryV1 {
    /// No request with the reserved ID and packet was journaled.
    Absent,
    /// The request or its adjacent signed successor is not terminal.
    Incomplete,
    /// The original group succeeded, but no adjacent successor was journaled.
    GroupCommitted {
        predecessor_request: Vec<u8>,
        predecessor_outcome: Vec<u8>,
        group_request: Vec<u8>,
        group_outcome: Vec<u8>,
    },
    /// The protected history retains all three adjacent successful exchanges.
    Complete {
        predecessor_request: Vec<u8>,
        predecessor_outcome: Vec<u8>,
        group_request: Vec<u8>,
        group_outcome: Vec<u8>,
        successor_request: Vec<u8>,
        successor_outcome: Vec<u8>,
    },
}

/// Contains only fully reauthenticated historical outcomes, never a send token.
pub(crate) enum ProtectedVerifiedAtomicStorageHistoryV1 {
    Absent,
    Incomplete,
    GroupCommitted {
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
    },
    Complete {
        predecessor: AuthenticatedBrokerMethodOutcomeV1,
        group: AuthenticatedBrokerMethodOutcomeV1,
        successor: AuthenticatedBrokerMethodOutcomeV1,
    },
}

fn historical_terminal_outcome(
    records: &[aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1],
    terminal_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
    let request_index = terminal_index
        .checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let prepared = records
        .get(request_index)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let terminal = records
        .get(terminal_index)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    if prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || terminal.phase() != BrokerSessionDurablePhaseV1::Terminal
        || prepared.request_packet() != terminal.request_packet()
        || prepared.request_id() != terminal.request_id()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }

    let prior =
        reconstruct_traffic_records(&records[..request_index], transcript, checkpoint.context())?;
    let canonical = decode_canonical_request_v1(terminal.request_packet())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let method = canonical.signed_artifact().method();
    let bindings = authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let peer = checkpoint.peer();
    let policy = aos_sandbox_protocol::PeerPolicy {
        uid: peer.uid,
        gid: Some(peer.gid),
        audience: checkpoint.context().audience(),
    };
    let retained_time = terminal
        .request_companion()
        .deadline_boottime_nanoseconds()
        .checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let (request, pending_traffic) =
        match prepare_client_sent_authenticated_broker_method_request_v1(
            &prior,
            terminal.request_packet(),
            None,
            canonical.message().descriptors.len(),
            peer,
            policy,
            retained_time,
            bindings,
            checkpoint.context(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?
        {
            AuthenticatedBrokerMethodRequestAdmissionV1::New {
                request,
                next_traffic,
            } => (request, next_traffic),
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
    if !request_matches_head(
        &request,
        terminal,
        AuthenticatedBrokerRequestDirectionV1::ClientSend,
    ) || request.semantic_commitment() != terminal.request_semantic_binding()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let packet = terminal
        .outcome_packet()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let canonical_outcome = decode_canonical_response_v1(packet)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(
        &pending_traffic,
        &request,
        packet,
        None,
        canonical_outcome.message().descriptors.len(),
        checkpoint.context(),
    )
    .map_err(|_| BrokerSessionSecurityError::Currentness)?
    {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => outcome,
        AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => {
            return Err(BrokerSessionSecurityError::Currentness);
        }
    };
    if outcome.semantic_commitment() != terminal.outcome_semantic_binding()
        || !matches!(
            outcome.result(),
            AuthenticatedBrokerMethodResultV1::Success { .. }
        )
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(outcome)
}

fn successful_terminal(
    record: &aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1,
) -> Result<bool, BrokerSessionSecurityError> {
    let packet = record
        .outcome_packet()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let outcome = decode_canonical_response_v1(packet)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    Ok(outcome.message().error.as_option().is_none())
}

// The source reservation commits the unsigned authority envelope before
// session custody adds semantic bindings and its signed ClientRecord.
fn authority_envelope_digest(packet: &[u8]) -> Result<[u8; 32], BrokerSessionSecurityError> {
    let mut envelope = decode_canonical_request_v1(packet)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?
        .message()
        .clone();
    envelope.semantic_bindings = Default::default();
    Ok(Sha256::digest(envelope.encode_to_vec()).into())
}

/// Classifies a broker-side packet before request installation or effect dispatch.
pub(crate) enum ProtectedBrokerReceivedRequestAdmissionV1 {
    /// A new authenticated request that still requires its protected request CAS.
    New {
        request: AuthenticatedBrokerMethodRequestV1,
        requires_initialization: bool,
    },
    /// The exact request is already durable but has no terminal response yet.
    InFlightReplay {
        request: AuthenticatedBrokerMethodRequestV1,
    },
    /// The exact request already has a protected terminal response.
    TerminalReplay {
        replay: ProtectedBrokerOutcomeReplayV1,
    },
}

fn protected_session_journal_limits() -> JournalLimits {
    let maximum_record_bytes = BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
        + VALUE_FIXED_BYTES_V3
        + historical_checkpoint::MAXIMUM_BYTES
        + 1024;
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes,
        maximum_key_bytes: 16,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: maximum_record_bytes + 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: (MAXIMUM_PROTOCOL_RECORDS
            + MAXIMUM_STORAGE_GROUP_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS)
            * maximum_record_bytes,
        maximum_materialized_records: MAXIMUM_PROTOCOL_RECORDS
            + MAXIMUM_STORAGE_GROUP_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS,
    }
}

/// Seals the recovery reader implementation to this module.
pub(super) trait SealedJournalAuthority {}

enum ProtectedEndpointV1 {
    Client(ProtectedBrokerSessionClientV1),
    Broker(ProtectedBrokerSessionBrokerV1),
}

impl ProtectedEndpointV1 {
    fn broker_outcome_verifier(
        &mut self,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitVerifierV1, BrokerSessionSecurityError>
    {
        match self {
            Self::Broker(endpoint) => endpoint.broker_outcome_verifier(),
            Self::Client(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn sign_terminal_commit_receipt(
        &mut self,
        binding: aos_sandbox_protocol::BrokerTerminalCommitBindingV1,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitReceiptV1, BrokerSessionSecurityError>
    {
        match self {
            Self::Broker(endpoint) => endpoint.sign_terminal_commit_receipt(binding),
            Self::Client(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn sign_lifecycle_bootstrap_attestation(
        &mut self,
        message: &[u8; 32],
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.sign_lifecycle_bootstrap_attestation(message),
            Self::Broker(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn fresh_client_request_id(&mut self) -> Result<[u8; 16], BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.fresh_method_request_id(),
            Self::Broker(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_client_request(
        &mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        sequence: u64,
        request_id: [u8; 16],
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.finalize_method_request(
                message,
                method,
                transcript.session_binding(),
                transcript.client_process(),
                sequence,
                request_id,
            ),
            Self::Broker(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_broker_outcome(
        &mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        sequence: u64,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        match self {
            Self::Broker(endpoint) => endpoint.finalize_method_outcome(
                message,
                request.method(),
                transcript.session_binding(),
                transcript.broker_process(),
                sequence,
                request.request_id(),
                request.signed_request_digest(),
            ),
            Self::Client(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn role(&self) -> BrokerSessionDurableEndpointV1 {
        match self {
            Self::Client(_) => BrokerSessionDurableEndpointV1::Client,
            Self::Broker(_) => BrokerSessionDurableEndpointV1::Broker,
        }
    }

    fn revalidate(&mut self) -> Result<(), BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.revalidate_handshake_custody(),
            Self::Broker(endpoint) => endpoint.revalidate_handshake_custody(),
        }
    }

    fn process_execution_id(&self) -> [u8; 16] {
        match self {
            Self::Client(endpoint) => endpoint.process_execution_id_bytes(),
            Self::Broker(endpoint) => endpoint.process_execution_id_bytes(),
        }
    }

    fn manifest_binding(&mut self) -> Result<[u8; 32], BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.manifest_binding().map(|value| *value.as_bytes()),
            Self::Broker(endpoint) => endpoint.manifest_binding().map(|value| *value.as_bytes()),
        }
    }

    fn context(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.context_for_handshake(transcript.broker_process()),
            Self::Broker(endpoint) => endpoint.context_for_handshake(transcript.client_process()),
        }
    }

    fn historical_context(
        &mut self,
        archived: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.context_for_history(archived),
            Self::Broker(endpoint) => endpoint.context_for_history(archived),
        }
    }
}

/// Owns one protected broker-session journal and its exact local endpoint.
///
/// Construction is dormant: it opens storage and retains authority, but starts
/// no listener, route, dispatcher, or background task.
#[must_use = "dropping the owner releases the sole protected journal lock"]
pub(crate) struct ProtectedBrokerSessionJournalV1 {
    journal: Option<Journal>,
    directory: PathBuf,
    name: String,
    limits: JournalLimits,
    owner: JournalOwnerV1,
    endpoint: ProtectedEndpointV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionJournalV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionJournalV1([redacted])")
    }
}

/// Selects one fixed all-method broker-session endpoint role.
///
/// Each variant maps to a compile-time endpoint directory. It cannot select a
/// path, journal basename, ownership policy, or replay bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedBrokerSessionFixedEndpointV1 {
    /// Uses the controller-side Host client custody root.
    ControllerHostClient,
    /// Uses the Host-service broker custody root.
    HostBroker,
    /// Uses the RootMount-side Host client custody root.
    RootMountHostClient,
    /// Uses the Host-service broker custody root dedicated to RootMount.
    RootMountHostBroker,
    /// Uses the controller-side Storage client custody root.
    ControllerStorageClient,
    /// Uses the Storage-service broker custody root.
    StorageBroker,
    /// Uses the controller-side Mount client custody root.
    ControllerMountClient,
    /// Uses the Mount-service broker custody root.
    MountBroker,
    /// Uses the controller-side Network client custody root.
    ControllerNetworkClient,
    /// Uses the Network-service broker custody root.
    NetworkBroker,
}

impl ProtectedBrokerSessionFixedEndpointV1 {
    pub(crate) fn production_socket_path(self) -> &'static str {
        fixed_endpoint(self).socket_path
    }
}

pub(crate) enum FixedEndpointCustodyV1 {
    Client(ProtectedBrokerSessionClientV1),
    Broker(ProtectedBrokerSessionBrokerV1),
}

/// Owns fixed endpoint custody for the dormant protected handshake.
///
/// This is the public all-role construction boundary for protected manifest,
/// key, process, and kernel-incarnation custody. It exposes neither raw keys nor
/// a path-selected endpoint and performs no socket I/O.
#[must_use = "consume fixed custody into an adopted-socket handshake"]
pub struct ProtectedBrokerSessionFixedCustodyV1 {
    journal_root: &'static str,
    protocol: aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1,
    audience: aos_proto::aos::sandbox::local::v1::Audience,
    socket_path: &'static str,
    custody: FixedEndpointCustodyV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionFixedCustodyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionFixedCustodyV1([redacted])")
    }
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    /// Loads one compile-time endpoint root for dormant protected handshaking.
    ///
    /// # Errors
    ///
    /// Returns an error unless the selected fixed endpoint's protected files,
    /// role keys, process incarnation, and kernel observations remain exact.
    pub fn open_fixed_protected(
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let configuration = fixed_endpoint(endpoint);
        let custody = match configuration.role {
            FixedEndpointRole::Client => FixedEndpointCustodyV1::Client(
                ProtectedBrokerSessionClientV1::load(Path::new(configuration.custody_root))?,
            ),
            FixedEndpointRole::Broker => FixedEndpointCustodyV1::Broker(
                ProtectedBrokerSessionBrokerV1::load(Path::new(configuration.custody_root))?,
            ),
        };
        Ok(Self {
            journal_root: configuration.journal_root,
            protocol: configuration.protocol,
            audience: configuration.audience,
            socket_path: configuration.socket_path,
            custody,
        })
    }

    pub(crate) const fn production_protocol(
        &self,
    ) -> aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1 {
        self.protocol
    }

    pub(crate) const fn production_audience(&self) -> aos_proto::aos::sandbox::local::v1::Audience {
        self.audience
    }

    pub(crate) const fn production_socket_path(&self) -> &'static str {
        self.socket_path
    }

    pub(crate) fn into_handshake_parts(
        self,
    ) -> (
        &'static str,
        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1,
        aos_proto::aos::sandbox::local::v1::Audience,
        &'static str,
        FixedEndpointCustodyV1,
    ) {
        (
            self.journal_root,
            self.protocol,
            self.audience,
            self.socket_path,
            self.custody,
        )
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    /// Reauthenticates the original post-group Storage inventory head.
    ///
    /// This is read-only historical evidence, not authority to send or roll
    /// over a pending request.
    pub(crate) fn original_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<Option<ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let before = self
            .journal
            .read_current(BrokerSessionProtocolV1::Storage)?;
        let head = self
            .journal
            .original_storage_inventory_coordinates(group_request_id, group_request_digest)?;
        if self
            .journal
            .read_current(BrokerSessionProtocolV1::Storage)?
            != before
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(head)
    }

    /// Reauthenticates the fresh status selected by the current Storage history.
    pub(crate) fn fresh_storage_inventory_coordinates(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<Option<ArchivedStorageInventoryHeadV1>, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let before = self
            .journal
            .read_current(BrokerSessionProtocolV1::Storage)?;
        let head = self
            .journal
            .fresh_storage_inventory_coordinates(group_request_id, group_request_digest)?;
        if self
            .journal
            .read_current(BrokerSessionProtocolV1::Storage)?
            != before
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(head)
    }

    /// Retains the exact old signed inventory across a recovery-only rollover.
    ///
    /// The archive is immutable and its write does not mark the request
    /// abandoned or authorize a fresh inventory query.
    pub(crate) fn archive_original_storage_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<storage_inventory_archive::ArchivedStorageInventoryHeadV1, BrokerSessionSecurityError>
    {
        self.revalidate_transport(transcript, connection_peer)?;
        let head = self.journal.archive_original_storage_inventory(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
        )?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(head)
    }

    pub(crate) fn client_storage_inventory_abandonment_committed(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        client_original_head: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<bool, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let committed = self
            .journal
            .client_storage_inventory_abandonment_committed(
                group_request_id,
                group_request_digest,
                inventory_request_id,
                inventory_request_digest,
                client_original_head,
            )?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(committed)
    }

    pub(crate) fn verify_original_storage_inventory_terminal(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        packet: &[u8],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let outcome = self.journal.verify_original_storage_inventory_terminal(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            packet,
        )?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(outcome)
    }

    /// Commits only the broker's exact nonterminal read-only abandonment.
    ///
    /// The caller must sign a recovery-control response only after this
    /// protected marker has been read back; no terminal outcome is fabricated.
    pub(crate) fn broker_abandon_original_storage_inventory(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        client_original_head: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let result = self.journal.broker_abandon_original_storage_inventory(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
            client_original_head,
        )?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(result)
    }

    /// Produces only an old signed terminal or a committed broker abandonment.
    ///
    /// This method never calls Storage inventory or a physical Storage effect.
    pub(crate) fn broker_storage_inventory_recovery_response(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)?;
        let coordinates = RecoverStorageInventoryRequestV1::decode_from_slice(request.exact_body())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let group_id: [u8; 16] = coordinates
            .group_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let group_digest: [u8; 32] = coordinates
            .group_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let inventory_id: [u8; 16] = coordinates
            .inventory_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let inventory_digest: [u8; 32] = coordinates
            .inventory_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let client_head: [u8; 32] = coordinates
            .client_original_head
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let archived = self.journal.archived_storage_inventory_head(
            group_id,
            group_digest,
            inventory_id,
            inventory_digest,
        )?;
        let response = if let Some(packet) = archived.terminal_packet {
            RecoverStorageInventoryResponseV1 {
                disposition: StorageInventoryRecoveryDispositionV1::STORAGE_INVENTORY_RECOVERY_DISPOSITION_ORIGINAL_TERMINAL.into(),
                original_terminal_packet: packet,
                broker_original_head: archived.original_head.to_vec(),
                broker_archive_digest: archived.archive_digest.to_vec(),
                ..Default::default()
            }
        } else {
            let (broker_head, archive_digest, abandonment_digest) =
                self.journal.broker_abandon_original_storage_inventory(
                    group_id,
                    group_digest,
                    inventory_id,
                    inventory_digest,
                    client_head,
                )?;
            RecoverStorageInventoryResponseV1 {
                disposition: StorageInventoryRecoveryDispositionV1::STORAGE_INVENTORY_RECOVERY_DISPOSITION_ABANDONED_READ_ONLY.into(),
                broker_original_head: broker_head.to_vec(),
                broker_archive_digest: archive_digest.to_vec(),
                broker_abandonment_digest: abandonment_digest.to_vec(),
                ..Default::default()
            }
        };
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(response.encode_to_vec())
    }

    /// Commits the client's exact signed broker-abandonment attestation.
    ///
    /// The old signed inventory and successful recovery-control response are
    /// both reauthenticated before this marker can authorize a fresh query.
    pub(crate) fn client_confirm_storage_inventory_abandonment(
        &mut self,
        group_request_id: [u8; 16],
        group_request_digest: [u8; 32],
        inventory_request_id: [u8; 16],
        inventory_request_digest: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        self.journal.client_confirm_storage_inventory_abandonment(
            group_request_id,
            group_request_digest,
            inventory_request_id,
            inventory_request_digest,
        )?;
        self.revalidate_transport(transcript, connection_peer)
    }

    /// Retires an archived group only after its protected source is complete.
    pub(crate) fn retire_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        self.journal.retire_atomic_storage_archive(request_id)?;
        self.revalidate_transport(transcript, connection_peer)
    }

    /// Retains the already verified original signed session before rollover.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn archive_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        self.journal.archive_verified_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint_digest,
        )?;
        self.revalidate_transport(transcript, connection_peer)
    }

    /// Reauthenticates the old Storage trio without granting live traffic authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prior_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedVerifiedAtomicStorageHistoryV1, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let before = self
            .journal
            .read_current(BrokerSessionProtocolV1::Storage)?;
        let history = self.journal.prior_verified_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            checkpoint_digest,
        )?;
        if self
            .journal
            .read_current(BrokerSessionProtocolV1::Storage)?
            != before
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(history)
    }

    /// Reads the exact protected Storage group and adjacent signed inventories.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prior_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedPriorAtomicStorageHistoryV1, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let history = self.journal.prior_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            transcript.protocol(),
        )?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(history)
    }

    /// Recovers an exact completed client exchange before session rollover.
    pub(crate) fn prior_terminal_exchange(
        &mut self,
        method: BrokerMethod,
        request_id: [u8; 16],
        request_body: &[u8],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<Option<ProtectedPriorTerminalExchangeV1>, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let exchange = self.journal.prior_terminal_exchange(
            method,
            request_id,
            request_body,
            transcript.protocol(),
        )?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(exchange)
    }

    pub(crate) fn require_current_node(
        &mut self,
        expected_node: [u8; 16],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let context = self.journal.current_context(transcript)?;
        if expected_node == [0; 16] || context.node_id() != expected_node {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)
    }

    pub(crate) fn broker_outcome_verifier(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitVerifierV1, BrokerSessionSecurityError>
    {
        self.revalidate_transport(transcript, connection_peer)?;
        let verifier = self.journal.endpoint.broker_outcome_verifier()?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(verifier)
    }

    pub(crate) fn sign_terminal_commit_receipt(
        &mut self,
        binding: aos_sandbox_protocol::BrokerTerminalCommitBindingV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<aos_sandbox_protocol::BrokerTerminalCommitReceiptV1, BrokerSessionSecurityError>
    {
        self.revalidate_transport(transcript, connection_peer)?;
        let receipt = self
            .journal
            .endpoint
            .sign_terminal_commit_receipt(binding)?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(receipt)
    }

    pub(crate) fn sign_lifecycle_bootstrap_attestation(
        &mut self,
        message: &[u8; 32],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let signature = self
            .journal
            .endpoint
            .sign_lifecycle_bootstrap_attestation(message)?;
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(signature)
    }

    pub(crate) fn prepare_broker_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        message: aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
        let descriptor_count = message.descriptors.len();
        let packet = self
            .journal
            .sign_broker_outcome(request, message, transcript)?;
        let outcome = aos_sandbox_broker_session_protocol::decode_canonical_response_v1(&packet)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let gate = self
            .journal
            .reopen_broker_outcome(request, transcript, connection_peer)?;
        match gate.admit_outcome_with_descriptor_count(&outcome, descriptor_count)? {
            super::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => Ok(advancement),
            super::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    pub(crate) fn revalidate_transport(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.journal.current_context(transcript)?;
        let peer = self.journal.observe_peer(transcript, connection_peer)?;
        peer.binding(self.journal.endpoint.role(), transcript, &context)?;
        self.journal.endpoint.revalidate()
    }

    pub(crate) fn client_request_coordinates(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        now_boottime_nanoseconds: u64,
    ) -> Result<
        (
            [u8; 16],
            u64,
            u32,
            ProtocolVersion,
            aos_proto::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        self.journal
            .client_request_coordinates(transcript, now_boottime_nanoseconds)
    }

    pub(crate) fn client_request_limits(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        now_boottime_nanoseconds: u64,
    ) -> Result<
        (
            u64,
            u32,
            ProtocolVersion,
            aos_proto::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        self.journal
            .client_request_limits(transcript, now_boottime_nanoseconds)
    }

    pub(crate) fn prepare_client_request(
        &mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
        actual_descriptor_count: usize,
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
    ) -> Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError> {
        self.journal.prepare_client_request(
            message,
            method,
            actual_descriptor_count,
            request_id,
            deadline_boottime_nanoseconds,
            maximum_response_bytes,
            transcript,
            connection_peer,
            now_boottime_nanoseconds,
        )
    }

    pub(crate) fn admit_received_request(
        &mut self,
        packet: &[u8],
        descriptor_count: usize,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        self.journal.admit_received_request(
            packet,
            descriptor_count,
            transcript,
            connection_peer,
            now_boottime_nanoseconds,
        )
    }

    pub(crate) fn from_fixed_custody(
        root: &'static str,
        custody: FixedEndpointCustodyV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let root = Path::new(root);
        let journal = match custody {
            FixedEndpointCustodyV1::Client(endpoint) => {
                ProtectedBrokerSessionJournalV1::open_client(
                    endpoint,
                    root,
                    PROTECTED_SESSION_JOURNAL,
                    protected_session_journal_limits(),
                )?
            }
            FixedEndpointCustodyV1::Broker(endpoint) => {
                ProtectedBrokerSessionJournalV1::open_broker(
                    endpoint,
                    root,
                    PROTECTED_SESSION_JOURNAL,
                    protected_session_journal_limits(),
                )?
            }
        };
        Ok(ProtectedBrokerSessionOwnerV1 { journal })
    }
}

/// Owns one fixed-root protected broker-session endpoint and journal.
///
/// Opening this dormant owner retains endpoint custody and the sole journal
/// lock. It creates no socket, listener, route, dispatcher, or background task;
/// all peer checks use an already-connected socket supplied to an operation.
#[must_use = "dropping the owner releases fixed endpoint custody and its journal lock"]
pub(crate) struct ProtectedBrokerSessionOwnerV1 {
    journal: ProtectedBrokerSessionJournalV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionOwnerV1([redacted])")
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    /// Installs the first authenticated request under an exact absence CAS.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request, transcript, adopted peer, endpoint,
    /// and empty or authenticated terminal rollover predecessor are current.
    pub(crate) fn initialize_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        checkpoint: &HistoricalSessionCheckpointV1,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        self.journal.initialize_authenticated_request(
            request,
            transcript,
            connection_peer,
            checkpoint,
        )
    }

    /// Reopens the exact protected broker-side outcome gate.
    ///
    /// # Errors
    ///
    /// Returns an error unless complete replay and current endpoint, peer,
    /// transcript, request, and journal-head evidence agree.
    pub(crate) fn reopen_broker_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError> {
        self.journal
            .reopen_broker_outcome(request, transcript, connection_peer)
    }

    /// Appends one successor request after a protected terminal head.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request is the exact current successor and
    /// the fixed owner remains current before mutation.
    pub(crate) fn append_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.journal
            .append_authenticated_request(request, transcript, connection_peer)
    }

    /// Commits one pending broker outcome with ambiguity-safe exact readback.
    #[must_use]
    pub(crate) fn commit_broker_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.journal.commit_broker_outcome(pending, connection_peer)
    }

    /// Reopens storage and recovers an interrupted broker outcome commit.
    #[must_use]
    pub(crate) fn recover_broker_outcome_commit(
        &mut self,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        if let Err(error) = self.journal.reopen_storage() {
            return ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery };
        }
        self.journal
            .recover_broker_outcome_commit(recovery, connection_peer)
    }

    /// Reopens storage and recovers an interrupted request installation.
    #[must_use]
    pub(crate) fn recover_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        if let Err(error) = self.journal.reopen_storage() {
            return ProtectedBrokerSessionInitializationResultV1::RecoveryRequired {
                error,
                recovery,
            };
        }
        self.journal
            .recover_initialization(recovery, connection_peer)
    }

    /// Reopens storage and recovers an interrupted successor-request append.
    #[must_use]
    pub(crate) fn recover_request_commit(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        if let Err(error) = self.journal.reopen_storage() {
            return ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery };
        }
        self.journal
            .recover_request_commit(recovery, connection_peer)
    }

    /// Revalidates an exact terminal broker head for immediate effect handoff.
    ///
    /// The returned token retains this fixed owner's unique mutable borrow.
    ///
    /// # Errors
    ///
    /// Returns an error unless every protected terminal binding remains exact.
    pub(crate) fn revalidate_broker_outcome<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>, BrokerSessionSecurityError> {
        self.journal
            .revalidate_broker_outcome(owner, connection_peer)
    }

    pub(crate) fn revalidate_broker_replay(
        &mut self,
        replay: ProtectedBrokerOutcomeReplayV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeReplayV1,
        (BrokerSessionSecurityError, ProtectedBrokerOutcomeReplayV1),
    > {
        self.journal
            .revalidate_broker_replay(replay, connection_peer)
    }

    pub(crate) fn revalidate_broker_committed(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeCommittedAdvancementV1,
        (
            BrokerSessionSecurityError,
            ProtectedBrokerOutcomeCommittedAdvancementV1,
        ),
    > {
        self.journal
            .revalidate_broker_committed(committed, connection_peer)
    }

    /// Revalidates and packages one terminal outcome for a broker-specific adapter.
    ///
    /// # Errors
    ///
    /// Returns an error unless the exact protected terminal head, endpoint,
    /// transcript, peer, and semantic commitments remain current and the typed
    /// terminal result is a method-validated `Success`. Signed errors never
    /// produce effect authority.
    pub(crate) fn prepare_effect_handoff<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerEffectHandoffV1<'authority>, BrokerSessionSecurityError> {
        let request_packet = owner.request.canonical_packet().to_vec();
        let request_body = owner.request.exact_body().to_vec();
        let signed_request_digest = owner.request.signed_request_digest();
        let request_semantic_commitment = owner.request.semantic_commitment();
        let evidence = effect_evidence(
            owner.request.method(),
            owner.request.direction(),
            owner.request.request_id(),
            owner.request.client_sequence(),
            owner.request.exact_body(),
            owner.request.canonical_packet(),
            owner.request.peer(),
            owner.request.peer_policy(),
            owner.context.node_id(),
            owner.context.boot_id(),
            owner.context.protocol(),
            ProtocolVersion::new(
                owner.context.protocol_major(),
                owner.context.protocol_minor(),
            ),
            owner.context.audience(),
            owner.context.client_process(),
            owner.context.broker_process(),
            owner.request.session_binding(),
            owner.peer_binding.digest(),
            owner.protected_generation,
            owner.protected_head,
            &owner.outcome,
        )?;
        let current = self
            .journal
            .revalidate_broker_outcome(owner, connection_peer)?;
        ProtectedBrokerEffectHandoffV1::new(
            current,
            evidence,
            request_packet,
            request_body,
            signed_request_digest,
            request_semantic_commitment,
        )
    }
}

#[derive(Clone, Copy)]
enum FixedEndpointRole {
    Client,
    Broker,
}

struct FixedEndpointConfiguration {
    journal_root: &'static str,
    custody_root: &'static str,
    role: FixedEndpointRole,
    protocol: aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1,
    audience: aos_proto::aos::sandbox::local::v1::Audience,
    socket_path: &'static str,
}

fn fixed_endpoint(endpoint: ProtectedBrokerSessionFixedEndpointV1) -> FixedEndpointConfiguration {
    use ProtectedBrokerSessionFixedEndpointV1 as Endpoint;
    use aos_proto::aos::sandbox::local::v1::Audience;
    use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1 as Protocol;

    match endpoint {
        Endpoint::ControllerHostClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandboxd/broker-session/host",
            custody_root: "/var/lib/aos/sandboxd/broker-session/host/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::Host,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-host/control.sock",
        },
        Endpoint::HostBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-host/broker-session/controller",
            custody_root: "/var/lib/aos/sandbox-host/broker-session/controller/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::Host,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-host/control.sock",
        },
        Endpoint::RootMountHostClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-mount/broker-session/host",
            custody_root: "/var/lib/aos/sandbox-mount/broker-session/host/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::Host,
            audience: Audience::AUDIENCE_ROOT_MOUNT,
            socket_path: "/run/aos/sandbox-host/root-mount.sock",
        },
        Endpoint::RootMountHostBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-host/broker-session/root-mount",
            custody_root: "/var/lib/aos/sandbox-host/broker-session/root-mount/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::Host,
            audience: Audience::AUDIENCE_ROOT_MOUNT,
            socket_path: "/run/aos/sandbox-host/root-mount.sock",
        },
        Endpoint::ControllerStorageClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandboxd/broker-session/storage",
            custody_root: "/var/lib/aos/sandboxd/broker-session/storage/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::Storage,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-storage/control.sock",
        },
        Endpoint::StorageBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-storage/broker-session",
            custody_root: "/var/lib/aos/sandbox-storage/broker-session/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::Storage,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-storage/control.sock",
        },
        Endpoint::ControllerMountClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandboxd/broker-session/mount",
            custody_root: "/var/lib/aos/sandboxd/broker-session/mount/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::Mount,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-mount/control.sock",
        },
        Endpoint::MountBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-mount/broker-session",
            custody_root: "/var/lib/aos/sandbox-mount/broker-session/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::Mount,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-mount/control.sock",
        },
        Endpoint::ControllerNetworkClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandboxd/broker-session/network",
            custody_root: "/var/lib/aos/sandboxd/broker-session/network/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::Network,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-network/control.sock",
        },
        Endpoint::NetworkBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-network/broker-session",
            custody_root: "/var/lib/aos/sandbox-network/broker-session/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::Network,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-network/control.sock",
        },
    }
}

fn reconstruct_retained_server_request(
    history: &BrokerSessionDurableHistoryV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: aos_sandbox_protocol::PeerCredentials,
    policy: aos_sandbox_protocol::PeerPolicy,
) -> Result<AuthenticatedBrokerMethodRequestV1, BrokerSessionSecurityError> {
    let head_index = history
        .records()
        .len()
        .checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let head = history
        .records()
        .get(head_index)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let request_index = match head.phase() {
        BrokerSessionDurablePhaseV1::RequestPrepared => head_index,
        BrokerSessionDurablePhaseV1::Terminal => head_index
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?,
    };
    let request_record = history
        .records()
        .get(request_index)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    if request_record.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || request_record.request_packet() != head.request_packet()
        || request_record.request_companion() != head.request_companion()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }

    let prior_traffic =
        reconstruct_traffic_records(&history.records()[..request_index], transcript, context)?;
    let canonical = decode_canonical_request_v1(head.request_packet())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let method = canonical.signed_artifact().method();
    let bindings = authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let descriptor_count = canonical.message().descriptors.len();
    let retained_verification_time = head
        .request_companion()
        .deadline_boottime_nanoseconds()
        .checked_sub(1)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let request = match admit_server_received_authenticated_broker_method_request_v1(
        &prior_traffic,
        head.request_packet(),
        None,
        descriptor_count,
        peer,
        policy,
        retained_verification_time,
        bindings,
        context,
    )
    .map_err(|_| BrokerSessionSecurityError::Currentness)?
    {
        AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => request,
        AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
            return Err(BrokerSessionSecurityError::Currentness);
        }
    };
    if !request_matches_head(
        &request,
        head,
        aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive,
    ) {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(request)
}

impl ProtectedBrokerSessionJournalV1 {
    fn bounded_storage_records(
        &mut self,
        namespace: RecordNamespace,
        maximum: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError> {
        let authority = self
            .journal_mut()?
            .claim_protected_authority(namespace)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut entries = Vec::new();
        for (key, value) in authority
            .records()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
        {
            if entries.len() == maximum {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            entries.push((key.to_vec(), value.to_vec()));
        }
        Ok(entries)
    }

    fn validate_storage_group_archives(&mut self) -> Result<usize, BrokerSessionSecurityError> {
        let keys = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionStorageGroupArchive)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut keys = Vec::new();
            for (key, _) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                if keys.len() == MAXIMUM_STORAGE_GROUP_ARCHIVES {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                let request_id: [u8; 16] = key
                    .try_into()
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                keys.push(request_id);
            }
            keys
        };
        for request_id in &keys {
            self.read_atomic_storage_archive(*request_id)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
        }
        Ok(keys.len())
    }

    fn read_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let value = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionStorageGroupArchive)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .get(&request_id)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let stored_bytes = open_atomic_storage_archive_frame(request_id, &value)?;
        let stored = StoredProtocolHistoryV1::decode(
            &protocol_key(BrokerSessionProtocolV1::Storage),
            stored_bytes,
        )?;
        if stored.endpoint != self.endpoint.role()
            || stored.checkpoint.is_none()
            || stored.stable_endpoint_identity
                != self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?
            || !stored.history_model()?.records().iter().any(|record| {
                record.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                    && record.request_id() == request_id
            })
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Some(stored))
    }

    fn atomic_storage_history_for_request(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        if let Some(archive) = self.read_atomic_storage_archive(request_id)? {
            Ok(Some(archive))
        } else {
            self.read_optional(BrokerSessionProtocolV1::Storage)
        }
    }

    fn archive_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
    ) -> Result<(), BrokerSessionSecurityError> {
        if !matches!(
            self.prior_verified_atomic_storage_history(
                request_id,
                request_packet,
                predecessor_packet,
                session_binding,
                checkpoint_digest,
            )?,
            ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted { .. }
                | ProtectedVerifiedAtomicStorageHistoryV1::Complete { .. }
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if self.read_atomic_storage_archive(request_id)?.is_some() {
            return Ok(());
        }
        let current = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.commit_atomic_storage_archive(request_id, &current)
    }

    // Broker custody is installed before the first post-group status rolls
    // over the old session, so generation adjacency remains provable later.
    fn archive_terminal_storage_group_for_status(
        &mut self,
        current: &StoredProtocolHistoryV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let history = current.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            || !successful_terminal(head)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let checkpoint = current
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        if self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || current.endpoint_publication
                != self.historical_endpoint_publication(
                    BrokerSessionProtocolV1::Storage,
                    &transcript,
                )?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        reconstruct_traffic(&history, &transcript, checkpoint.context())?;
        let request_id = head.request_id();
        if let Some(archive) = self.read_atomic_storage_archive(request_id)? {
            return if archive == *current {
                Ok(())
            } else {
                Err(BrokerSessionSecurityError::Currentness)
            };
        }
        self.commit_atomic_storage_archive(request_id, current)
    }

    fn commit_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
        current: &StoredProtocolHistoryV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.validate_storage_group_archives()? == MAXIMUM_STORAGE_GROUP_ARCHIVES {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let value = encode_atomic_storage_archive_frame(request_id, &current.encode()?)?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(STORAGE_GROUP_ARCHIVE_TRANSACTION_DOMAIN)
            .chain_update(request_id)
            .chain_update(Sha256::digest(&value))
            .finalize()
            .into();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if transaction_id == [0; 16] {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionStorageGroupArchive,
                request_id.to_vec(),
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionStorageGroupArchive)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&request_id)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .commit(&transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let retained = self
            .read_atomic_storage_archive(request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if retained != *current {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn retire_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.endpoint.role() != BrokerSessionDurableEndpointV1::Client {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let current = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if current
            .history_model()?
            .records()
            .first()
            .is_some_and(|first| {
                first.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            })
        {
            // The next request still needs this signed marker chain to prove
            // the abandoned read-only request was settled.
            return Ok(());
        }
        self.retire_storage_inventory_for_group(request_id)?;
        let Some(stored) = self.read_atomic_storage_archive(request_id)? else {
            return Ok(());
        };
        let value = encode_atomic_storage_archive_frame(request_id, &stored.encode()?)?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(STORAGE_GROUP_ARCHIVE_RETIRE_DOMAIN)
            .chain_update(request_id)
            .chain_update(Sha256::digest(&value))
            .finalize()
            .into();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if transaction_id == [0; 16] {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::delete(
                RecordNamespace::BrokerSessionStorageGroupArchive,
                request_id.to_vec(),
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionStorageGroupArchive)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&request_id)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            != Some(value.as_slice())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .commit(&transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.read_atomic_storage_archive(request_id)?.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn retire_exact_storage_inventory_record(
        &mut self,
        namespace: RecordNamespace,
        request_id: [u8; 16],
        expected: &[u8],
    ) -> Result<(), BrokerSessionSecurityError> {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(STORAGE_INVENTORY_RETIRE_DOMAIN)
            .chain_update([namespace as u8])
            .chain_update(request_id)
            .chain_update(Sha256::digest(expected))
            .finalize()
            .into();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::delete(namespace, request_id.to_vec())],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(namespace)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&request_id)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            != Some(expected)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .commit(&transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&request_id)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn prior_verified_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        checkpoint_digest: [u8; 32],
    ) -> Result<ProtectedVerifiedAtomicStorageHistoryV1, BrokerSessionSecurityError> {
        let raw = self.prior_atomic_storage_history(
            request_id,
            request_packet,
            predecessor_packet,
            session_binding,
            BrokerSessionProtocolV1::Storage,
        )?;
        let (
            predecessor_request,
            predecessor_outcome,
            group_request,
            group_outcome,
            successor_bytes,
        ) = match raw {
            ProtectedPriorAtomicStorageHistoryV1::Absent => {
                return Ok(ProtectedVerifiedAtomicStorageHistoryV1::Absent);
            }
            ProtectedPriorAtomicStorageHistoryV1::Incomplete => {
                return Ok(ProtectedVerifiedAtomicStorageHistoryV1::Incomplete);
            }
            ProtectedPriorAtomicStorageHistoryV1::GroupCommitted {
                predecessor_request,
                predecessor_outcome,
                group_request,
                group_outcome,
            } => (
                predecessor_request,
                predecessor_outcome,
                group_request,
                group_outcome,
                None,
            ),
            ProtectedPriorAtomicStorageHistoryV1::Complete {
                predecessor_request,
                predecessor_outcome,
                group_request,
                group_outcome,
                successor_request,
                successor_outcome,
            } => (
                predecessor_request,
                predecessor_outcome,
                group_request,
                group_outcome,
                Some((successor_request, successor_outcome)),
            ),
        };
        let stored = self
            .atomic_storage_history_for_request(request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if checkpoint.digest()? != checkpoint_digest
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let transcript = checkpoint.verify()?;
        if transcript.session_binding() != session_binding
            || stored.endpoint_publication
                != self.historical_endpoint_publication(
                    BrokerSessionProtocolV1::Storage,
                    &transcript,
                )?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history = stored.history_model()?;
        reconstruct_traffic(&history, &transcript, checkpoint.context())?;
        let records = history.records();
        let (index, _) = records
            .iter()
            .enumerate()
            .find(|(_, record)| {
                record.phase() == BrokerSessionDurablePhaseV1::Terminal
                    && record.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                    && record.request_id() == request_id
            })
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if authority_envelope_digest(records[index].request_packet())? != request_packet {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let predecessor_index = index
            .checked_sub(2)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let predecessor =
            historical_terminal_outcome(records, predecessor_index, checkpoint, &transcript)?;
        let group = historical_terminal_outcome(records, index, checkpoint, &transcript)?;
        if predecessor.request().canonical_packet() != predecessor_request
            || predecessor.canonical_packet() != predecessor_outcome
            || group.request().canonical_packet() != group_request
            || group.canonical_packet() != group_outcome
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let Some((successor_request, successor_outcome)) = successor_bytes else {
            return Ok(ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted {
                predecessor,
                group,
            });
        };
        let successor_index = index
            .checked_add(2)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let successor =
            historical_terminal_outcome(records, successor_index, checkpoint, &transcript)?;
        if successor.request().canonical_packet() != successor_request
            || successor.canonical_packet() != successor_outcome
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(ProtectedVerifiedAtomicStorageHistoryV1::Complete {
            predecessor,
            group,
            successor,
        })
    }

    fn prior_atomic_storage_history(
        &mut self,
        request_id: [u8; 16],
        request_packet: [u8; 32],
        predecessor_packet: [u8; 32],
        session_binding: [u8; 32],
        protocol: BrokerSessionProtocolV1,
    ) -> Result<ProtectedPriorAtomicStorageHistoryV1, BrokerSessionSecurityError> {
        let Some(stored) = (if protocol == BrokerSessionProtocolV1::Storage {
            self.atomic_storage_history_for_request(request_id)?
        } else {
            self.read_optional(protocol)?
        }) else {
            return Ok(ProtectedPriorAtomicStorageHistoryV1::Absent);
        };
        let history = stored.history_model()?;
        let records = history.records();
        let matching = records.iter().enumerate().filter(|(_, record)| {
            record.endpoint() == BrokerSessionDurableEndpointV1::Client
                && record.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                && record.request_id() == request_id
        });
        let mut matching = matching.peekable();
        let Some((index, group)) = matching.next() else {
            return Ok(ProtectedPriorAtomicStorageHistoryV1::Absent);
        };
        if authority_envelope_digest(group.request_packet())? != request_packet {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let (group_index, group) = if group.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
        {
            let Some((terminal_index, terminal)) = matching.next() else {
                return Ok(ProtectedPriorAtomicStorageHistoryV1::Incomplete);
            };
            if terminal_index != index + 1
                || terminal.phase() != BrokerSessionDurablePhaseV1::Terminal
                || matching.next().is_some()
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            (terminal_index, terminal)
        } else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let predecessor = group_index
            .checked_sub(2)
            .and_then(|index| records.get(index))
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let successor = records.get(group_index + 2);
        if predecessor.phase() != BrokerSessionDurablePhaseV1::Terminal
            || predecessor.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || Sha256::digest(
                predecessor
                    .outcome_packet()
                    .ok_or(BrokerSessionSecurityError::Currentness)?,
            )
            .as_slice()
                != predecessor_packet
            || predecessor.session_binding() != session_binding
            || group.session_binding() != session_binding
            || predecessor.client_sequence().checked_add(1) != Some(group.client_sequence())
            || predecessor.broker_sequence().checked_add(1) != Some(group.broker_sequence())
            || !successful_terminal(predecessor)?
            || !successful_terminal(group)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let predecessor_request = predecessor.request_packet().to_vec();
        let predecessor_outcome = predecessor
            .outcome_packet()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .to_vec();
        let group_request = group.request_packet().to_vec();
        let group_outcome = group
            .outcome_packet()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .to_vec();
        let Some(successor) = successor else {
            return Ok(ProtectedPriorAtomicStorageHistoryV1::GroupCommitted {
                predecessor_request,
                predecessor_outcome,
                group_request,
                group_outcome,
            });
        };
        if successor.phase() != BrokerSessionDurablePhaseV1::Terminal
            || successor.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || successor.session_binding() != session_binding
            || group.client_sequence().checked_add(1) != Some(successor.client_sequence())
            || group.broker_sequence().checked_add(1) != Some(successor.broker_sequence())
            || !successful_terminal(successor)?
        {
            return Ok(ProtectedPriorAtomicStorageHistoryV1::GroupCommitted {
                predecessor_request,
                predecessor_outcome,
                group_request,
                group_outcome,
            });
        }
        Ok(ProtectedPriorAtomicStorageHistoryV1::Complete {
            predecessor_request,
            predecessor_outcome,
            group_request,
            group_outcome,
            successor_request: successor.request_packet().to_vec(),
            successor_outcome: successor
                .outcome_packet()
                .ok_or(BrokerSessionSecurityError::Currentness)?
                .to_vec(),
        })
    }

    fn prior_terminal_exchange(
        &mut self,
        method: BrokerMethod,
        request_id: [u8; 16],
        request_body: &[u8],
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<ProtectedPriorTerminalExchangeV1>, BrokerSessionSecurityError> {
        let Some(stored) = self.read_optional(protocol)? else {
            return Ok(None);
        };
        let history = stored.history_model()?;
        for record in history.records().iter().rev() {
            if record.endpoint() != BrokerSessionDurableEndpointV1::Client
                || record.phase() != BrokerSessionDurablePhaseV1::Terminal
                || record.method() != method
                || record.request_id() != request_id
            {
                continue;
            }
            let request = decode_canonical_request_v1(record.request_packet())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if request.message().body.as_slice() != request_body {
                continue;
            }
            let outcome_packet = record
                .outcome_packet()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let outcome = decode_canonical_response_v1(outcome_packet)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let message = outcome.message();
            if message.request_id.as_slice() != request_id
                || message.method.as_known() != Some(method)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let result = match message.error.as_option() {
                None => Ok(message.body.clone()),
                Some(error) => Err(error.safe_message.clone()),
            };
            return Ok(Some(ProtectedPriorTerminalExchangeV1 {
                method,
                request_id,
                request_body: request.message().body.clone(),
                result,
            }));
        }
        Ok(None)
    }

    pub(crate) fn sign_broker_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        message: aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let current = self
            .read_optional(transcript.protocol())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = current.history_model()?;
        let traffic = reconstruct_traffic(&history, transcript, &context)?;
        if !traffic.has_outstanding_request()
            || request.direction()
                != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.endpoint.finalize_broker_outcome(
            message,
            request,
            transcript,
            traffic.next_broker_sequence(),
        )
    }

    pub(crate) fn client_request_coordinates(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        now_boottime_nanoseconds: u64,
    ) -> Result<
        (
            [u8; 16],
            u64,
            u32,
            ProtocolVersion,
            aos_proto::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        let (deadline, maximum_response_bytes, protocol_version, audience) =
            self.client_request_limits(transcript, now_boottime_nanoseconds)?;
        let request_id = self.endpoint.fresh_client_request_id()?;

        Ok((
            request_id,
            deadline,
            maximum_response_bytes,
            protocol_version,
            audience,
        ))
    }

    pub(crate) fn client_request_limits(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        now_boottime_nanoseconds: u64,
    ) -> Result<
        (
            u64,
            u32,
            ProtocolVersion,
            aos_proto::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        let context = self.current_context(transcript)?;
        let deadline = now_boottime_nanoseconds
            .checked_add(10_000_000_000)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let maximum_response_bytes = transcript.negotiated_maximum_response_bytes();
        Ok((
            deadline,
            maximum_response_bytes,
            ProtocolVersion::new(context.protocol_major(), context.protocol_minor()),
            context.audience(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_client_request(
        &mut self,
        message: aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_proto::aos::sandbox::local::v1::BrokerMethod,
        actual_descriptor_count: usize,
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
    ) -> Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let first_peer = self.observe_peer(transcript, connection_peer)?;
        let current = self.read_optional(transcript.protocol())?;
        let current_publication = self.endpoint_publication(transcript.protocol())?;
        let requires_initialization = current
            .as_ref()
            .is_none_or(|value| value.endpoint_publication != current_publication);
        let traffic = match current.as_ref() {
            Some(current) if !requires_initialization => {
                reconstruct_traffic(&current.history_model()?, transcript, &context)?
            }
            _ => BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?,
        };
        let sequence = traffic.next_client_sequence();
        let packet = self
            .endpoint
            .finalize_client_request(message, method, transcript, sequence, request_id)?;
        let canonical = decode_canonical_request_v1(&packet)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let semantic_bindings =
            authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let credentials = connection_peer.credentials();
        let peer = aos_sandbox_protocol::PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        };
        let policy = aos_sandbox_protocol::PeerPolicy {
            uid: credentials.uid(),
            gid: Some(credentials.gid()),
            audience: context.audience(),
        };
        let admission = prepare_client_sent_authenticated_broker_method_request_v1(
            &traffic,
            &packet,
            None,
            actual_descriptor_count,
            peer,
            policy,
            now_boottime_nanoseconds,
            semantic_bindings,
            &context,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let request = match admission {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => request,
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        if request.method() != method
            || request.request_id() != request_id
            || request.client_sequence() != sequence
            || request.deadline_boottime_nanoseconds() != deadline_boottime_nanoseconds
            || request.maximum_response_bytes() != maximum_response_bytes
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let second_peer = self.observe_peer(transcript, connection_peer)?;
        if first_peer.binding(self.endpoint.role(), transcript, &context)?
            != second_peer.binding(self.endpoint.role(), transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((request, requires_initialization))
    }

    pub(crate) fn admit_received_request(
        &mut self,
        packet: &[u8],
        descriptor_count: usize,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let first_peer = self.observe_peer(transcript, connection_peer)?;
        let credentials = connection_peer.credentials();
        let peer = aos_sandbox_protocol::PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        };
        let policy = aos_sandbox_protocol::PeerPolicy {
            uid: credentials.uid(),
            gid: Some(credentials.gid()),
            audience: context.audience(),
        };
        let canonical = decode_canonical_request_v1(packet)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let method = canonical.signed_artifact().method();
        let semantic_bindings =
            authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let current = self.read_optional(transcript.protocol())?;
        let current_publication = self.endpoint_publication(transcript.protocol())?;
        let requires_initialization = current
            .as_ref()
            .is_none_or(|value| value.endpoint_publication != current_publication);
        let history = current
            .as_ref()
            .map(StoredProtocolHistoryV1::history_model)
            .transpose()?;
        let traffic = match history.as_ref() {
            Some(history) if !requires_initialization => {
                reconstruct_traffic(history, transcript, &context)?
            }
            _ => BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?,
        };
        let retained_request = history
            .as_ref()
            .filter(|_| !requires_initialization)
            .map(|history| {
                reconstruct_retained_server_request(history, transcript, &context, peer, policy)
            })
            .transpose()?;
        let admission = admit_server_received_authenticated_broker_method_request_v1(
            &traffic,
            packet,
            retained_request.as_ref(),
            descriptor_count,
            peer,
            policy,
            now_boottime_nanoseconds,
            semantic_bindings,
            &context,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let second_peer = self.observe_peer(transcript, connection_peer)?;
        if first_peer.binding(self.endpoint.role(), transcript, &context)?
            != second_peer.binding(self.endpoint.role(), transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        match admission {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => {
                Ok(ProtectedBrokerReceivedRequestAdmissionV1::New {
                    request,
                    requires_initialization,
                })
            }
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                let request = retained_request.ok_or(BrokerSessionSecurityError::Currentness)?;
                let history = history.ok_or(BrokerSessionSecurityError::Currentness)?;
                let head = history
                    .head()
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                match head.phase() {
                    BrokerSessionDurablePhaseV1::RequestPrepared => {
                        Ok(ProtectedBrokerReceivedRequestAdmissionV1::InFlightReplay { request })
                    }
                    BrokerSessionDurablePhaseV1::Terminal => {
                        let packet = head
                            .outcome_packet()
                            .ok_or(BrokerSessionSecurityError::Currentness)?;
                        let canonical = decode_canonical_response_v1(packet)
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        let descriptor_count = canonical.message().descriptors.len();
                        let gate = ProtectedBrokerOutcomeGateRecoveryV1::reopen_broker_outcome(
                            self,
                            &request,
                            transcript,
                            &context,
                            &second_peer,
                        )?
                        .into_gate();
                        match gate
                            .admit_outcome_with_descriptor_count(&canonical, descriptor_count)?
                        {
                            super::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { replay } => {
                                Ok(ProtectedBrokerReceivedRequestAdmissionV1::TerminalReplay {
                                    replay,
                                })
                            }
                            super::ProtectedBrokerOutcomeAdmissionV1::New { .. } => {
                                Err(BrokerSessionSecurityError::Currentness)
                            }
                        }
                    }
                }
            }
        }
    }

    /// Opens a service-owned journal for one protected client endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error unless the journal has protected-open provenance, its
    /// complete namespace-47 materialized state is canonical and bounded, and
    /// every retained record matches the current protected client endpoint.
    pub(crate) fn open_client(
        endpoint: ProtectedBrokerSessionClientV1,
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<Self, BrokerSessionSecurityError> {
        Self::open(
            ProtectedEndpointV1::Client(endpoint),
            directory,
            name,
            limits,
        )
    }

    /// Opens a root-owned journal for one protected broker endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error unless the journal has protected-open provenance, its
    /// complete namespace-47 materialized state is canonical and bounded, and
    /// every retained record matches the current protected broker endpoint.
    pub(crate) fn open_broker(
        endpoint: ProtectedBrokerSessionBrokerV1,
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<Self, BrokerSessionSecurityError> {
        Self::open(
            ProtectedEndpointV1::Broker(endpoint),
            directory,
            name,
            limits,
        )
    }

    fn open(
        mut endpoint: ProtectedEndpointV1,
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let directory = directory.as_ref().to_path_buf();
        endpoint.revalidate()?;
        let owner = JournalOwnerV1::capture(endpoint.role());
        let (journal, _) = owner
            .open(&directory, name, limits)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        endpoint.revalidate()?;
        let mut authority = Self {
            journal: Some(journal),
            directory,
            name: name.to_owned(),
            limits,
            owner,
            endpoint,
        };
        authority.validate_all()?;
        Ok(authority)
    }

    fn reopen_storage(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        drop(self.journal.take());
        let (journal, _) = self
            .owner
            .open(&self.directory, &self.name, self.limits)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.journal = Some(journal);
        self.validate_all()?;
        self.endpoint.revalidate()?;
        Ok(())
    }

    fn journal_mut(&mut self) -> Result<&mut Journal, BrokerSessionSecurityError> {
        self.journal
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    /// Installs the first authenticated request under an exact absence CAS.
    ///
    /// A method-specific current-catalog binding is retained when the signed
    /// request carries one. Other valid first methods use their nonzero signed
    /// semantic commitment as a type-separated placeholder. A publication's
    /// successor catalog is installed only with its successful terminal result.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation for a wrong endpoint, stale peer,
    /// mismatched transcript, invalid semantic binding, a current-process history,
    /// or a nonterminal old-process head. A terminal old-process history may be
    /// replaced only by this new signed initial request under an exact monotone
    /// predecessor CAS. Durability or readback failure retains recovery.
    pub fn initialize_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        checkpoint: &HistoricalSessionCheckpointV1,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        if super::endpoint_for_request(request) != self.endpoint.role() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let before = self.read_optional(transcript.protocol())?;
        if before.is_none()
            && request.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let current_catalog = request
            .catalog_binding()
            .unwrap_or_else(|| request.semantic_commitment());
        if current_catalog.iter().all(|byte| *byte == 0) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let endpoint_publication = self.endpoint_publication(transcript.protocol())?;
        let stable_endpoint_identity = self.stable_endpoint_identity(transcript.protocol())?;
        let (expected_generation, expected_head, expected_publication) = match before.as_ref() {
            None => (0, [0; 32], [0; 32]),
            Some(current) => {
                let history = current.history_model()?;
                let head = history
                    .head()
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                if current.endpoint_publication == endpoint_publication
                    || current.stable_endpoint_identity != stable_endpoint_identity
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                if request.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
                    let coordinates =
                        RecoverStorageInventoryRequestV1::decode_from_slice(request.exact_body())
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let group_id: [u8; 16] = coordinates
                        .group_request_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let group_digest: [u8; 32] = coordinates
                        .group_request_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let inventory_id: [u8; 16] = coordinates
                        .inventory_request_id
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let inventory_digest: [u8; 32] = coordinates
                        .inventory_request_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let client_head: [u8; 32] = coordinates
                        .client_original_head
                        .as_slice()
                        .try_into()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let archived = if head.method()
                        == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                    {
                        self.archive_original_storage_inventory(
                            group_id,
                            group_digest,
                            inventory_id,
                            inventory_digest,
                        )?
                    } else if head.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
                    {
                        // A recovery control request has no physical effect. It may be
                        // retried across a crash, but only for the exact old status.
                        let records = history.records();
                        if records.len() > 2
                            || records.first().is_none_or(|first| {
                                first.method()
                                    != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
                                    || first.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
                            })
                        {
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                        let first = records
                            .first()
                            .ok_or(BrokerSessionSecurityError::Currentness)?;
                        let original = decode_canonical_request_v1(first.request_packet())
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        let previous = RecoverStorageInventoryRequestV1::decode_from_slice(
                            &original.message().body,
                        )
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        if previous.group_request_id != coordinates.group_request_id
                            || previous.group_request_digest != coordinates.group_request_digest
                            || previous.inventory_request_id != coordinates.inventory_request_id
                            || previous.inventory_request_digest
                                != coordinates.inventory_request_digest
                            || previous.client_original_head != coordinates.client_original_head
                        {
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                        self.archived_storage_inventory_head(
                            group_id,
                            group_digest,
                            inventory_id,
                            inventory_digest,
                        )?
                    } else {
                        return Err(BrokerSessionSecurityError::Currentness);
                    };
                    if self.endpoint.role() == BrokerSessionDurableEndpointV1::Client
                        && client_head != archived.original_head
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    if (head.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                        && archived.original_head != current.current_head)
                        || self.read_optional(BrokerSessionProtocolV1::Storage)? != before
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                } else {
                    if head.phase() != BrokerSessionDurablePhaseV1::Terminal {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    if request.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                        && head.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                    {
                        match self.endpoint.role() {
                            BrokerSessionDurableEndpointV1::Broker => {
                                self.archive_terminal_storage_group_for_status(current)?;
                            }
                            BrokerSessionDurableEndpointV1::Client => {
                                if self.read_atomic_storage_archive(head.request_id())?
                                    != Some(current.clone())
                                {
                                    return Err(BrokerSessionSecurityError::Currentness);
                                }
                            }
                        }
                    }
                    if let Some(first) = history.records().first() {
                        if first.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY {
                            self.require_storage_inventory_abandonment_successor(
                                &history,
                                request.method(),
                            )?;
                        }
                    }
                }
                (
                    current.generation,
                    current.current_head,
                    current.endpoint_publication,
                )
            }
        };
        let empty = ProtectedBrokerSessionJournalSnapshotV1::new(
            expected_generation,
            endpoint_publication,
            current_catalog,
            [0; 32],
            None,
        )?;
        let write = ProtectedBrokerRequestWriteV1::prepare_initial_from_snapshot(
            request, &context, transcript, &peer, &empty,
        )?;
        let target = StoredProtocolHistoryV1::from_request_write(
            transcript.protocol(),
            self.endpoint.role(),
            stable_endpoint_identity,
            endpoint_publication,
            current_catalog,
            write,
            Some(checkpoint.clone()),
        )?;
        let recovery = ProtectedBrokerSessionInitializationRecoveryV1 {
            expected_generation,
            expected_head,
            expected_publication,
            target,
            transcript: transcript.clone(),
        };
        Ok(self.install_initial(recovery, connection_peer))
    }

    /// Reopens the exact protected broker-side outcome gate.
    ///
    /// # Errors
    ///
    /// Returns an error unless full canonical replay, endpoint custody, peer
    /// identity, catalog binding, transcript, request, and current head agree.
    pub fn reopen_broker_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        let recovery = ProtectedBrokerOutcomeGateRecoveryV1::reopen_broker_outcome(
            self, request, transcript, &context, &peer,
        )?;
        let after_peer = self.observe_peer(transcript, connection_peer)?;
        if recovery.gate.currentness.peer_binding
            != after_peer.binding(self.endpoint.role(), transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(recovery.into_gate())
    }

    /// Revalidates one exact protected terminal broker outcome for immediate use.
    ///
    /// The returned token holds this journal's unique mutable borrow, preventing
    /// another in-process recovery or advancement from superseding the checked
    /// head during the associated effect-authority handoff.
    ///
    /// # Errors
    ///
    /// Returns an error unless endpoint custody, peer identity, transcript,
    /// protected bindings, generation, head, request, and outcome packet still
    /// match the authority captured by protected admission.
    pub fn revalidate_broker_outcome<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>, BrokerSessionSecurityError> {
        self.validate_broker_outcome(&owner, connection_peer)?;
        Ok(ProtectedBrokerOutcomeCurrentV1 {
            authority: self,
            connection_peer,
            owner,
        })
    }

    fn revalidate_broker_replay(
        &mut self,
        replay: ProtectedBrokerOutcomeReplayV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeReplayV1,
        (BrokerSessionSecurityError, ProtectedBrokerOutcomeReplayV1),
    > {
        match self.validate_broker_outcome(&replay.currentness_owner, connection_peer) {
            Ok(()) => Ok(replay),
            Err(error) => Err((error, replay)),
        }
    }

    fn revalidate_broker_committed(
        &mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeCommittedAdvancementV1,
        (
            BrokerSessionSecurityError,
            ProtectedBrokerOutcomeCommittedAdvancementV1,
        ),
    > {
        match self.validate_broker_outcome(&committed.currentness_owner, connection_peer) {
            Ok(()) => Ok(committed),
            Err(error) => Err((error, committed)),
        }
    }

    pub(super) fn validate_broker_outcome(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.current_context(&owner.transcript)?;
        if context.protected_context_digest() != owner.context.protected_context_digest() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let peer = self.observe_peer(&owner.transcript, connection_peer)?;
        let peer_binding = peer.binding(self.endpoint.role(), &owner.transcript, &owner.context)?;
        let (history, traffic, current) =
            reopen_current(self, &owner.transcript, &owner.context, &peer)?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if current.generation != owner.protected_generation
            || current.current_head != owner.protected_head
            || current.protected_bindings(&owner.context)? != owner.protected_bindings
            || peer_binding != owner.peer_binding
            || head.endpoint() != BrokerSessionDurableEndpointV1::Broker
            || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || !request_matches_head(
                &owner.request,
                head,
                aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ServerReceive,
            )
            || traffic.has_outstanding_request()
            || head.outcome_packet() != Some(owner.outcome.canonical_packet())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let reconstructed = reconstruct_terminal_semantics(
            &history,
            &owner.request,
            &owner.transcript,
            &owner.context,
            &traffic,
        )?;
        if reconstructed != owner.outcome
            || reconstructed.filesystem_worker_qualification_commitment()
                != owner.qualification_record_commitment
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let after_peer = self.observe_peer(&owner.transcript, connection_peer)?;
        if after_peer.binding(self.endpoint.role(), &owner.transcript, &owner.context)?
            != owner.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    // The signed original terminal or two durable abandonment markers must
    // settle the old request before another inventory can be sent.
    fn require_storage_inventory_abandonment_successor(
        &mut self,
        history: &BrokerSessionDurableHistoryV1,
        method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        let records = history.records();
        let first = records
            .first()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if method != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || records.len() != 2
            || first.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || first.method() != BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
            || records[1].phase() != BrokerSessionDurablePhaseV1::Terminal
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let canonical = decode_canonical_request_v1(first.request_packet())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let coordinates =
            RecoverStorageInventoryRequestV1::decode_from_slice(&canonical.message().body)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let inventory_id: [u8; 16] = coordinates
            .inventory_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let group_id: [u8; 16] = coordinates
            .group_request_id
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let group_digest: [u8; 32] = coordinates
            .group_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let inventory_digest: [u8; 32] = coordinates
            .inventory_request_digest
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let client_head: [u8; 32] = coordinates
            .client_original_head
            .as_slice()
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let stored = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let verified_history = stored.history_model()?;
        if verified_history != *history {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        reconstruct_traffic(&verified_history, &transcript, checkpoint.context())?;
        let response = decode_canonical_response_v1(
            records[1]
                .outcome_packet()
                .ok_or(BrokerSessionSecurityError::Currentness)?,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if response.message().error.as_option().is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let decision = decode_storage_inventory_recovery_response_v1(
            &response.message().body,
            first.maximum_response_bytes(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if let ValidatedStorageInventoryRecoveryResponseV1::OriginalTerminal {
            packet,
            broker_head,
            archive_digest,
        } = decision
        {
            let archived = self.archived_storage_inventory_head(
                group_id,
                group_digest,
                inventory_id,
                inventory_digest,
            )?;
            if archived.original_head != client_head
                && self.endpoint.role() == BrokerSessionDurableEndpointV1::Client
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            match self.endpoint.role() {
                BrokerSessionDurableEndpointV1::Broker
                    if archived.terminal_packet.as_deref() == Some(packet.as_slice())
                        && archived.original_head == broker_head
                        && archived.archive_digest == archive_digest
                        && decode_canonical_response_v1(&packet)
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?
                            .message()
                            .error
                            .as_option()
                            .is_none() => {}
                BrokerSessionDurableEndpointV1::Client => {
                    self.verify_original_storage_inventory_terminal(
                        group_id,
                        group_digest,
                        inventory_id,
                        inventory_digest,
                        &packet,
                    )?;
                }
                _ => return Err(BrokerSessionSecurityError::Currentness),
            }
            return Ok(());
        }
        let marker = self.read_storage_inventory_abandonment(inventory_id)?;
        if !exact_storage_inventory_abandonment_marker(
            marker.as_ref(),
            self.endpoint.role(),
            group_id,
            group_digest,
            inventory_digest,
            client_head,
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.validate_storage_inventory_abandonments()?;
        Ok(())
    }

    /// Appends one authenticated successor request after a terminal head.
    ///
    /// # Errors
    ///
    /// Returns an error before mutation unless canonical full replay selects
    /// the exact terminal predecessor and the protected endpoint, peer,
    /// transcript, catalog, generation, head, and revision all remain current.
    pub fn append_authenticated_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        let write = ProtectedBrokerRequestWriteV1::prepare_successor(
            self, request, &context, transcript, &peer,
        )?;
        let current = self
            .read_optional(transcript.protocol())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = current.history_model()?;
        if history.records().first().is_some_and(|first| {
            first.method() == BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY
        }) {
            self.require_storage_inventory_abandonment_successor(&history, request.method())?;
        }
        if current.generation != write.expected_generation()
            || current.current_head != write.expected_head()
            || current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .revision()
                != write.expected_revision()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let recovery = ProtectedBrokerRequestCommitRecoveryV1 {
            expected_generation: write.expected_generation(),
            expected_head: write.expected_head(),
            expected_revision: write.expected_revision(),
            target: StoredProtocolHistoryV1::from_request_write(
                transcript.protocol(),
                current.endpoint,
                current.stable_endpoint_identity,
                current.endpoint_publication,
                write.current_catalog()?,
                write,
                current.checkpoint.clone(),
            )?,
            transcript: transcript.clone(),
        };
        Ok(self.install_successor(recovery, connection_peer))
    }

    /// Commits one exact pending outcome and confirms canonical readback.
    ///
    /// Every post-preflight failure retains the pending advancement inside an
    /// explicit recovery token. The co-owned authenticated session reopens this
    /// fixed storage before classifying the exact predecessor or replacement.
    #[must_use]
    pub(crate) fn commit_broker_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        match self.try_commit_outcome(&pending, connection_peer) {
            Ok(readback) => match pending.confirm_committed_preserving(readback) {
                Ok(committed) => ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                Err((error, pending)) => ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                    error,
                    recovery: ProtectedBrokerOutcomeCommitRecoveryV1 { pending },
                },
            },
            Err(error) => ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                error,
                recovery: ProtectedBrokerOutcomeCommitRecoveryV1 { pending },
            },
        }
    }

    /// Resolves an interrupted outcome commit against a freshly opened owner.
    #[must_use]
    pub(crate) fn recover_broker_outcome_commit(
        &mut self,
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.commit_broker_outcome(recovery.pending, connection_peer)
    }

    /// Resolves an interrupted initial install by exact target or absence.
    #[must_use]
    pub fn recover_initialization(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        self.install_initial(recovery, connection_peer)
    }

    /// Resolves an interrupted successor-request append.
    #[must_use]
    pub fn recover_request_commit(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        self.install_successor(recovery, connection_peer)
    }

    fn install_initial(
        &mut self,
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerSessionInitializationResultV1 {
        let target = &recovery.target;
        let result = (|| {
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            match self.read_optional(target.protocol)? {
                Some(current) if current == *target => return Ok(()),
                Some(current)
                    if current.generation == recovery.expected_generation
                        && current.current_head == recovery.expected_head
                        && current.endpoint_publication == recovery.expected_publication
                        && current.stable_endpoint_identity == target.stable_endpoint_identity => {}
                None if recovery.expected_generation == 0
                    && recovery.expected_head == [0; 32]
                    && recovery.expected_publication == [0; 32] => {}
                _ => return Err(BrokerSessionSecurityError::Currentness),
            }
            self.commit_stored(target)?;
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            if !matches!(self.read_optional(target.protocol)?, Some(current) if current == *target)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        match result {
            Ok(()) => ProtectedBrokerSessionInitializationResultV1::Initialized,
            Err(error) => {
                ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { error, recovery }
            }
        }
    }

    fn install_successor(
        &mut self,
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> ProtectedBrokerRequestCommitResultV1 {
        let target = &recovery.target;
        let result = (|| {
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            let current = self
                .read_optional(target.protocol)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            if current == *target {
                return Ok(());
            }
            let head = current
                .history_model()?
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .clone();
            if current.generation != recovery.expected_generation
                || current.current_head != recovery.expected_head
                || head.revision() != recovery.expected_revision
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            self.commit_stored(target)?;
            self.validate_recovery_peer(target, &recovery.transcript, connection_peer)?;
            if !matches!(self.read_optional(target.protocol)?, Some(current) if current == *target)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })();
        match result {
            Ok(()) => ProtectedBrokerRequestCommitResultV1::Committed,
            Err(error) => {
                ProtectedBrokerRequestCommitResultV1::RecoveryRequired { error, recovery }
            }
        }
    }

    fn try_commit_outcome(
        &mut self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCommitReadbackV1, BrokerSessionSecurityError> {
        let context = self.current_context(&pending.transcript)?;
        let before_peer = self.observe_peer(&pending.transcript, connection_peer)?;
        if before_peer.binding(self.endpoint.role(), &pending.transcript, &context)?
            != pending.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let protocol = pending.transcript.protocol();
        let current = self
            .read_optional(protocol)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let replacement = StoredProtocolHistoryV1::from_pending_outcome(&current, pending)?;
        if current.generation == replacement.generation
            && current.current_head == replacement.current_head
            && current.history == replacement.history
        {
            return self.confirm_pending(pending, connection_peer);
        }
        let current_history = current.history_model()?;
        let current_record = current_history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if current.generation != pending.durable_cas.expected_generation
            || current.current_head != pending.durable_cas.expected_head
            || current.endpoint_publication != pending.protected_bindings.endpoint_publication()
            || current.current_catalog != current_record.protected_bindings().current_catalog()
            || current_record.revision() != pending.durable_cas.expected_revision
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.commit_stored(&replacement)?;
        self.confirm_pending(pending, connection_peer)
    }

    fn confirm_pending(
        &mut self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomeCommitReadbackV1, BrokerSessionSecurityError> {
        let peer = self.observe_peer(&pending.transcript, connection_peer)?;
        let readback =
            ProtectedBrokerOutcomeCommitReadbackV1::confirm_after_cas(self, pending, &peer)?;
        let context = self.current_context(&pending.transcript)?;
        let after_peer = self.observe_peer(&pending.transcript, connection_peer)?;
        if after_peer.binding(self.endpoint.role(), &pending.transcript, &context)?
            != pending.peer_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(readback)
    }

    fn current_context(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let context = self.endpoint.context(transcript)?;
        self.endpoint.revalidate()?;
        if context.protected_context_digest() != transcript.protected_context_digest()
            || context.protocol() != transcript.protocol()
            || context.client_process() != transcript.client_process()
            || context.broker_process() != transcript.broker_process()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(context)
    }

    fn validate_recovery_peer(
        &mut self,
        target: &StoredProtocolHistoryV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.current_context(transcript)?;
        let peer = self.observe_peer(transcript, connection_peer)?;
        let head = target
            .history_model()?
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .clone();
        if target.protocol != transcript.protocol()
            || target.endpoint != self.endpoint.role()
            || target.stable_endpoint_identity != self.stable_endpoint_identity(target.protocol)?
            || target.endpoint_publication != self.endpoint_publication(target.protocol)?
            || head.session_binding() != transcript.session_binding()
            || head.peer_binding() != peer.binding(target.endpoint, transcript, &context)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn observe_peer(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ObservedBrokerPeerExecutionV1, BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let process_execution_id = match self.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => transcript.broker_process(),
            BrokerSessionDurableEndpointV1::Broker => transcript.client_process(),
        };
        let peer =
            ObservedBrokerPeerExecutionV1::from_connection(connection_peer, process_execution_id)?;
        self.endpoint.revalidate()?;
        Ok(peer)
    }

    fn endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let manifest = self.endpoint.manifest_binding()?;
        let process = self.endpoint.process_execution_id();
        let role = endpoint_code(self.endpoint.role());
        self.endpoint.revalidate()?;

        let mut digest = Sha256::new();
        digest.update(ENDPOINT_PUBLICATION_DOMAIN);
        digest.update([protocol_code(protocol), role]);
        digest.update(manifest);
        digest.update(process);
        Ok(digest.finalize().into())
    }

    fn historical_endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let manifest = self.endpoint.manifest_binding()?;
        let process = match self.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => transcript.client_process(),
            BrokerSessionDurableEndpointV1::Broker => transcript.broker_process(),
        };
        let role = endpoint_code(self.endpoint.role());
        self.endpoint.revalidate()?;

        Ok(Sha256::new()
            .chain_update(ENDPOINT_PUBLICATION_DOMAIN)
            .chain_update([protocol_code(protocol), role])
            .chain_update(manifest)
            .chain_update(process)
            .finalize()
            .into())
    }

    fn stable_endpoint_identity(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.endpoint.revalidate()?;
        let manifest = self.endpoint.manifest_binding()?;
        let role = endpoint_code(self.endpoint.role());
        self.endpoint.revalidate()?;

        let mut digest = Sha256::new();
        digest.update(STABLE_ENDPOINT_IDENTITY_DOMAIN);
        digest.update([protocol_code(protocol), role]);
        digest.update(manifest);
        Ok(digest.finalize().into())
    }

    fn read_optional(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let before_identity = self.stable_endpoint_identity(protocol)?;
        let records = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut decoded = Vec::new();
            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                if decoded.len() == MAXIMUM_PROTOCOL_RECORDS {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                decoded.push(StoredProtocolHistoryV1::decode(key, value)?);
            }
            decoded
        };
        let after_identity = self.stable_endpoint_identity(protocol)?;
        if before_identity != after_identity
            || records
                .iter()
                .any(|record| record.endpoint != self.endpoint.role())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut selected = None;
        for record in records {
            if record.stable_endpoint_identity != self.stable_endpoint_identity(record.protocol)? {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            if record.protocol == protocol {
                if selected.replace(record).is_some() {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            }
        }
        Ok(selected)
    }

    fn validate_all(&mut self) -> Result<(), BrokerSessionSecurityError> {
        for protocol in [
            BrokerSessionProtocolV1::Host,
            BrokerSessionProtocolV1::Storage,
            BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network,
        ] {
            let _ = self.read_optional(protocol)?;
        }
        self.validate_storage_group_archives()?;
        self.validate_storage_inventory_archives()?;
        self.validate_storage_inventory_abandonments()?;
        Ok(())
    }

    fn commit_stored(
        &mut self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let key = protocol_key(stored.protocol);
        let value = stored.encode()?;
        let transaction = JournalTransaction::new(
            transaction_id(stored)?,
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                key,
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        authority
            .commit(&transaction)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(())
    }
}

impl SealedJournalAuthority for ProtectedBrokerSessionJournalV1 {}

impl ProtectedBrokerSessionJournalAuthorityV1 for ProtectedBrokerSessionJournalV1 {
    fn read_current(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
        let current = self
            .read_optional(protocol)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        current.snapshot()
    }
}

/// Classifies an initial protected-history install.
#[must_use = "an interrupted install must retain its recovery token"]
pub enum ProtectedBrokerSessionInitializationResultV1 {
    /// The exact first history is current and durably readable.
    Initialized,
    /// Durable state may contain the target and must be reopened through the session.
    RecoveryRequired {
        /// Redacted reason that the install could not be confirmed.
        error: BrokerSessionSecurityError,
        /// Move-only exact target used for reopen classification.
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
    },
}

/// Retains the exact canonical initial target across an ambiguous commit.
#[must_use = "resolve the initialization target through the authenticated session"]
pub struct ProtectedBrokerSessionInitializationRecoveryV1 {
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_publication: [u8; 32],
    target: StoredProtocolHistoryV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
}

/// Classifies a successor-request commit without discarding its exact target.
#[must_use = "an interrupted request commit must retain its recovery token"]
pub enum ProtectedBrokerRequestCommitResultV1 {
    /// The exact successor history is current and durably readable.
    Committed,
    /// Durable state may contain the target and must be reopened explicitly.
    RecoveryRequired {
        /// Redacted reason that exact readback did not complete.
        error: BrokerSessionSecurityError,
        /// Move-only predecessor and target retained for exact classification.
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
    },
}

/// Retains one exact predecessor CAS and successor target across interruption.
#[must_use = "the successor target must be resolved against a reopened journal"]
pub struct ProtectedBrokerRequestCommitRecoveryV1 {
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_revision: u64,
    target: StoredProtocolHistoryV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
}

/// Classifies an outcome commit without discarding authenticated progress.
#[must_use = "an interrupted outcome commit must retain its recovery token"]
pub enum ProtectedBrokerOutcomeCommitResultV1 {
    /// The replacement was committed, fully replayed, and read back exactly.
    Committed(ProtectedBrokerOutcomeCommittedAdvancementV1),
    /// Durable state is unconfirmed and requires an explicit reopen.
    RecoveryRequired {
        /// Redacted reason that exact readback did not complete.
        error: BrokerSessionSecurityError,
        /// Move-only pending advancement retained for exact classification.
        recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    },
}

/// Retains an exact pending outcome across ambiguous durable mutation.
#[must_use = "the pending outcome must be resolved against a reopened journal"]
pub struct ProtectedBrokerOutcomeCommitRecoveryV1 {
    pending: ProtectedBrokerOutcomePendingAdvancementV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredProtocolHistoryV1 {
    protocol: BrokerSessionProtocolV1,
    endpoint: BrokerSessionDurableEndpointV1,
    generation: u64,
    stable_endpoint_identity: [u8; 32],
    endpoint_publication: [u8; 32],
    current_catalog: [u8; 32],
    current_head: [u8; 32],
    history: Vec<u8>,
    checkpoint: Option<HistoricalSessionCheckpointV1>,
}

impl StoredProtocolHistoryV1 {
    fn from_request_write(
        protocol: BrokerSessionProtocolV1,
        endpoint: BrokerSessionDurableEndpointV1,
        stable_endpoint_identity: [u8; 32],
        endpoint_publication: [u8; 32],
        current_catalog: [u8; 32],
        write: ProtectedBrokerRequestWriteV1,
        checkpoint: Option<HistoricalSessionCheckpointV1>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let history = write.encode()?;
        let model = BrokerSessionDurableHistoryV1::decode(&history)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(Self {
            protocol,
            endpoint,
            generation: write
                .expected_generation()
                .checked_add(1)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
            stable_endpoint_identity,
            endpoint_publication,
            current_catalog,
            current_head: model.head_commitment(),
            history,
            checkpoint,
        })
    }

    fn from_pending_outcome(
        current: &Self,
        pending: &ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let history = pending.replacement_history.clone();
        let model = BrokerSessionDurableHistoryV1::decode(&history)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if model.head_commitment() != pending.durable_cas.replacement_head {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            protocol: current.protocol,
            endpoint: current.endpoint,
            generation: pending
                .durable_cas
                .expected_generation
                .checked_add(1)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
            stable_endpoint_identity: current.stable_endpoint_identity,
            endpoint_publication: current.endpoint_publication,
            current_catalog: pending.protected_bindings.current_catalog(),
            current_head: pending.durable_cas.replacement_head,
            history,
            checkpoint: current.checkpoint.clone(),
        })
    }

    fn history_model(&self) -> Result<BrokerSessionDurableHistoryV1, BrokerSessionSecurityError> {
        BrokerSessionDurableHistoryV1::decode(&self.history)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    fn snapshot(
        &self,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
        ProtectedBrokerSessionJournalSnapshotV1::new(
            self.generation,
            self.endpoint_publication,
            self.current_catalog,
            self.current_head,
            Some(self.history.clone()),
        )
    }

    fn encode(&self) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        let model = self.history_model()?;
        let head = model
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if let Some(checkpoint) = &self.checkpoint {
            let transcript = checkpoint.verify()?;
            if transcript.protocol() != self.protocol
                || model.records().iter().any(|record| {
                    record.session_binding() != transcript.session_binding()
                        || record.protected_bindings().protected_context()
                            != checkpoint.context().protected_context_digest()
                        || record.protected_bindings().endpoint_publication()
                            != self.endpoint_publication
                })
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        if self.generation == 0
            || self.endpoint_publication.iter().all(|byte| *byte == 0)
            || self.stable_endpoint_identity.iter().all(|byte| *byte == 0)
            || self.current_catalog.iter().all(|byte| *byte == 0)
            || model.head_commitment() != self.current_head
            || head.protocol() != self.protocol
            || head.endpoint() != self.endpoint
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history_length = u32::try_from(self.history.len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(HistoricalSessionCheckpointV1::encode)
            .transpose()?;
        let checkpoint_length = checkpoint.as_ref().map_or(0, Vec::len);
        let version = if checkpoint.is_some() {
            VALUE_VERSION_V3
        } else {
            VALUE_VERSION_V2
        };
        let capacity = VALUE_FIXED_BYTES_V3
            .checked_add(self.history.len())
            .and_then(|size| size.checked_add(checkpoint_length))
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if self.history.len() > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
            || checkpoint_length > historical_checkpoint::MAXIMUM_BYTES
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut value = Vec::with_capacity(capacity);
        value.extend_from_slice(VALUE_MAGIC);
        value.extend_from_slice(&version.to_be_bytes());
        value.push(protocol_code(self.protocol));
        value.push(endpoint_code(self.endpoint));
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&self.stable_endpoint_identity);
        value.extend_from_slice(&self.endpoint_publication);
        value.extend_from_slice(&self.current_catalog);
        value.extend_from_slice(&self.current_head);
        value.extend_from_slice(&history_length.to_be_bytes());
        value.extend_from_slice(&self.history);
        if let Some(checkpoint) = checkpoint {
            let length = u32::try_from(checkpoint.len())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            value.extend_from_slice(&length.to_be_bytes());
            value.extend_from_slice(&checkpoint);
        }
        let digest = value_digest(&value, version);
        value.extend_from_slice(&digest);
        Ok(value)
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        if value.len() < VALUE_FIXED_BYTES_V2
            || value.len()
                > VALUE_FIXED_BYTES_V3
                    .checked_add(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)
                    .and_then(|size| size.checked_add(historical_checkpoint::MAXIMUM_BYTES))
                    .ok_or(BrokerSessionSecurityError::Currentness)?
            || value.get(..8) != Some(VALUE_MAGIC.as_slice())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let version = read_u16(value, 8)?;
        if !matches!(version, VALUE_VERSION_V2 | VALUE_VERSION_V3) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let protocol = decode_protocol(read_u8(value, 10)?)?;
        let endpoint = decode_endpoint(read_u8(value, 11)?)?;
        if key != protocol_key(protocol) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let generation = read_u64(value, 12)?;
        let stable_endpoint_identity = read_array(value, 20)?;
        let endpoint_publication = read_array(value, 52)?;
        let current_catalog = read_array(value, 84)?;
        let current_head = read_array(value, 116)?;
        let history_length = usize::try_from(read_u32(value, 148)?)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let history_end = 152usize
            .checked_add(history_length)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (checkpoint, digest_start) = if version == VALUE_VERSION_V3 {
            let length = usize::try_from(read_u32(value, history_end)?)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if length == 0 || length > historical_checkpoint::MAXIMUM_BYTES {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let start = history_end
                .checked_add(4)
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let end = start
                .checked_add(length)
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let checkpoint = HistoricalSessionCheckpointV1::decode(
                value
                    .get(start..end)
                    .ok_or(BrokerSessionSecurityError::Currentness)?,
            )?;
            (Some(checkpoint), end)
        } else {
            (None, history_end)
        };
        let digest_end = digest_start
            .checked_add(VALUE_DIGEST_BYTES)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if history_length == 0
            || history_length > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
            || digest_end != value.len()
            || read_array::<32>(value, digest_start)?
                != value_digest(&value[..digest_start], version)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history = value
            .get(152..history_end)
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .to_vec();
        let stored = Self {
            protocol,
            endpoint,
            generation,
            stable_endpoint_identity,
            endpoint_publication,
            current_catalog,
            current_head,
            history,
            checkpoint,
        };
        if stored.encode()? != value {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(stored)
    }
}

fn protocol_key(protocol: BrokerSessionProtocolV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(9);
    key.extend_from_slice(KEY_MAGIC);
    key.push(protocol_code(protocol));
    key
}

fn protocol_code(protocol: BrokerSessionProtocolV1) -> u8 {
    match protocol {
        BrokerSessionProtocolV1::Host => 1,
        BrokerSessionProtocolV1::Storage => 2,
        BrokerSessionProtocolV1::Mount => 3,
        BrokerSessionProtocolV1::Network => 4,
    }
}

fn decode_protocol(code: u8) -> Result<BrokerSessionProtocolV1, BrokerSessionSecurityError> {
    match code {
        1 => Ok(BrokerSessionProtocolV1::Host),
        2 => Ok(BrokerSessionProtocolV1::Storage),
        3 => Ok(BrokerSessionProtocolV1::Mount),
        4 => Ok(BrokerSessionProtocolV1::Network),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn endpoint_code(endpoint: BrokerSessionDurableEndpointV1) -> u8 {
    match endpoint {
        BrokerSessionDurableEndpointV1::Client => 1,
        BrokerSessionDurableEndpointV1::Broker => 2,
    }
}

fn decode_endpoint(code: u8) -> Result<BrokerSessionDurableEndpointV1, BrokerSessionSecurityError> {
    match code {
        1 => Ok(BrokerSessionDurableEndpointV1::Client),
        2 => Ok(BrokerSessionDurableEndpointV1::Broker),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn encode_atomic_storage_archive_frame(
    request_id: [u8; 16],
    stored_history: &[u8],
) -> Result<Vec<u8>, BrokerSessionSecurityError> {
    let stored_length =
        u32::try_from(stored_history.len()).map_err(|_| BrokerSessionSecurityError::Currentness)?;
    if request_id == [0; 16] || stored_history.is_empty() {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let mut value = Vec::with_capacity(
        STORAGE_GROUP_ARCHIVE_HEADER_BYTES
            + stored_history.len()
            + STORAGE_GROUP_ARCHIVE_TRAILER_BYTES,
    );
    value.extend_from_slice(STORAGE_GROUP_ARCHIVE_MAGIC);
    value.extend_from_slice(&1_u16.to_be_bytes());
    value.extend_from_slice(&request_id);
    value.extend_from_slice(&stored_length.to_be_bytes());
    value.extend_from_slice(stored_history);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(STORAGE_GROUP_ARCHIVE_VALUE_DOMAIN)
        .chain_update(&value)
        .finalize()
        .into();
    value.extend_from_slice(&digest);
    Ok(value)
}

fn open_atomic_storage_archive_frame<'a>(
    request_id: [u8; 16],
    value: &'a [u8],
) -> Result<&'a [u8], BrokerSessionSecurityError> {
    if request_id == [0; 16]
        || value.len() <= STORAGE_GROUP_ARCHIVE_HEADER_BYTES + STORAGE_GROUP_ARCHIVE_TRAILER_BYTES
        || value.get(..8) != Some(STORAGE_GROUP_ARCHIVE_MAGIC.as_slice())
        || read_u16(value, 8)? != 1
        || read_array::<16>(value, 10)? != request_id
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let stored_length = usize::try_from(read_u32(value, 26)?)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let stored_end = STORAGE_GROUP_ARCHIVE_HEADER_BYTES
        .checked_add(stored_length)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    if stored_length == 0
        || stored_end.checked_add(STORAGE_GROUP_ARCHIVE_TRAILER_BYTES) != Some(value.len())
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let actual: [u8; 32] = Sha256::new()
        .chain_update(STORAGE_GROUP_ARCHIVE_VALUE_DOMAIN)
        .chain_update(&value[..stored_end])
        .finalize()
        .into();
    if read_array::<32>(value, stored_end)? != actual {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    value
        .get(STORAGE_GROUP_ARCHIVE_HEADER_BYTES..stored_end)
        .ok_or(BrokerSessionSecurityError::Currentness)
}

fn value_digest(value_without_digest: &[u8], version: u16) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(if version == VALUE_VERSION_V3 {
        VALUE_DOMAIN_V3
    } else {
        VALUE_DOMAIN_V2
    });
    digest.update(value_without_digest);
    digest.finalize().into()
}

fn transaction_id(
    stored: &StoredProtocolHistoryV1,
) -> Result<[u8; 16], BrokerSessionSecurityError> {
    let value = stored.encode()?;
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update([
        protocol_code(stored.protocol),
        endpoint_code(stored.endpoint),
    ]);
    digest.update(stored.generation.to_be_bytes());
    digest.update(stored.current_head);
    digest.update(value_digest(
        &value,
        if stored.checkpoint.is_some() {
            VALUE_VERSION_V3
        } else {
            VALUE_VERSION_V2
        },
    ));
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[..16]);
    if id == [0; 16] {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(id)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, BrokerSessionSecurityError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(BrokerSessionSecurityError::Currentness)
}

#[cfg(test)]
mod storage_group_archive_tests {
    use super::*;

    #[test]
    fn archive_frame_binds_request_and_rejects_tampering() {
        let request_id = [7; 16];
        let frame =
            encode_atomic_storage_archive_frame(request_id, b"original-signed-history").unwrap();
        assert_eq!(
            open_atomic_storage_archive_frame(request_id, &frame).unwrap(),
            b"original-signed-history"
        );
        assert!(open_atomic_storage_archive_frame([8; 16], &frame).is_err());

        let mut tampered = frame.clone();
        tampered[STORAGE_GROUP_ARCHIVE_HEADER_BYTES] ^= 1;
        assert!(open_atomic_storage_archive_frame(request_id, &tampered).is_err());
        assert!(open_atomic_storage_archive_frame(request_id, &frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn archived_original_survives_current_session_rollover_and_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let journal_path = temporary.path().join("session.journal");
        let request_id = [9; 16];
        let archive =
            encode_atomic_storage_archive_frame(request_id, b"original-signed-history").unwrap();
        let (mut journal, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        let current_key = protocol_key(BrokerSessionProtocolV1::Storage);
        for (id, namespace, key, value) in [
            (
                1,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"original-session".to_vec(),
            ),
            (
                2,
                RecordNamespace::BrokerSessionStorageGroupArchive,
                request_id.to_vec(),
                archive.clone(),
            ),
            (
                3,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"new-session".to_vec(),
            ),
        ] {
            let transaction =
                JournalTransaction::new([id; 16], vec![JournalRecord::put(namespace, key, value)])
                    .unwrap();
            journal.commit(&transaction).unwrap();
        }
        drop(journal);

        let (journal, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::BrokerSessionTraffic, &current_key),
            Some(b"new-session".as_slice())
        );
        let retained = journal
            .get(
                RecordNamespace::BrokerSessionStorageGroupArchive,
                &request_id,
            )
            .unwrap();
        assert_eq!(
            open_atomic_storage_archive_frame(request_id, retained).unwrap(),
            b"original-signed-history"
        );
    }

    #[test]
    fn crash_after_archive_before_rollover_retains_the_old_group() {
        let temporary = tempfile::tempdir().unwrap();
        let journal_path = temporary.path().join("session.journal");
        let request_id = [19; 16];
        let archive =
            encode_atomic_storage_archive_frame(request_id, b"signed-group-history").unwrap();
        let current_key = protocol_key(BrokerSessionProtocolV1::Storage);
        let (mut journal, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        for (id, namespace, key, value) in [
            (
                1,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"old-group".to_vec(),
            ),
            (
                2,
                RecordNamespace::BrokerSessionStorageGroupArchive,
                request_id.to_vec(),
                archive,
            ),
        ] {
            journal
                .commit(
                    &JournalTransaction::new(
                        [id; 16],
                        vec![JournalRecord::put(namespace, key, value)],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        drop(journal);

        let (journal, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::BrokerSessionTraffic, &current_key),
            Some(b"old-group".as_slice())
        );
        let retained = journal
            .get(
                RecordNamespace::BrokerSessionStorageGroupArchive,
                &request_id,
            )
            .unwrap();
        assert_eq!(
            open_atomic_storage_archive_frame(request_id, retained).unwrap(),
            b"signed-group-history"
        );
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BrokerSessionSecurityError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BrokerSessionSecurityError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, BrokerSessionSecurityError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], BrokerSessionSecurityError> {
    bytes
        .get(offset..offset + N)
        .ok_or(BrokerSessionSecurityError::Currentness)?
        .try_into()
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

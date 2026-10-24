//! Concrete protected storage for authenticated broker-session histories.
//!
//! Namespace 47 holds disjoint typed keys for canonical current histories,
//! immutable Storage archives, and original Controller Host requests. The owner
//! consumes the protected endpoint that defines its stable role/manifest
//! identity and its process-specific publication. Reopen accepts an earlier
//! process publication only as an authenticated terminal rollover predecessor;
//! current-session authority still requires the live endpoint before and after
//! every read.

/// Retains either the original protected-owner refusal or raw journal geometry error.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FixedServiceReceivingExtentErrorV4 {
    #[error(transparent)]
    Security(BrokerSessionSecurityError),
    #[error(transparent)]
    Journal(aos_sandbox_controller_domain::journal::JournalError),
}

mod client_request;
pub(crate) use client_request::ClientRequestOriginalsV1;
mod current_context;
mod current_session;
mod operator_recover_inventory;
#[cfg(test)]
mod recover_slot_tests;
pub(in crate::recovery) use current_context::CurrentContextOriginalsV1;
mod outcome_current;
pub(crate) use outcome_current::OutcomeCurrentOriginalsV1;
mod peer_current;
pub(in crate::recovery) use peer_current::CurrentPeerOriginalsV1;
mod stored_readback;
pub(crate) use stored_readback::StoredReadOriginalsV1;
mod storage_floor_schema;
pub(crate) use storage_floor_schema::StorageFloorSchemaOriginalV3;
mod storage_session_continuation;
mod delete_inventory;
mod retired_storage_transcript;
use retired_storage_transcript::RetiredStorageTranscriptPhaseV1;
mod client_session_continuation;
pub(crate) use client_session_continuation::{FixedServiceSessionPostOriginalV4, FixedServiceTerminalCurrentOriginalV4};
mod request_current;
pub use client_session_continuation::ExecutionClientPostOriginalV1;
pub(crate) use client_session_continuation::{RetainedStorageClientTerminalOriginalV1, RetainedStorageClientOwnerPostV1};
pub(crate) use storage_session_continuation::RetainedStorageOwnerPostV1;
mod storage_receiving_demand;
mod host_execution_receiving;
pub use host_execution_receiving::HostExecutionSessionReceivingOriginalV1;
mod storage_session_schema_demand;
mod storage_host;
pub(crate) use storage_host::StorageHostClientReceivingV1;

mod controller_initial;
use controller_initial::ControllerInitialSessionMainOpenV1;
pub(crate) use controller_initial::controller_initial_fixed_endpoint_v1;
#[cfg(test)]
mod lifecycle_test_fixture;
#[cfg(test)]
pub(crate) use lifecycle_test_fixture::LifecycleTerminalFixture;
mod host_terminal_archive;
mod owner;
pub(crate) mod floor_revalidation;
mod operator_repair_history;
mod original_create_failure;
mod pending_request;
mod storage_inventory_abandonment;
mod storage_inventory_archive;
#[allow(
    dead_code,
    reason = "TPM floor attachment and live transport remain unqualified"
)]
mod tpm_floor;
pub(crate) use tpm_floor::storage_receiving::StorageFloorFinancialSourceV2;
pub(crate) use tpm_floor::BrokerSidecarCustodyV1;
pub(crate) use tpm_floor::{
    AuthenticatedNvObservationV1, BrokerPhysicalOpenV1, OwnerConfinementOriginalV1, FloorErrorV1, FloorProfileV1,
    HelperExecutedImageOriginalV1, HelperImageAcquisitionOriginalV1, HelperImageRevalidationOriginalV1, HelperObservationV1, HelperOperationV1, LOCK_ACK_BYTES, MeasuredHelperImageV1,
    NV_ATTRIBUTES_WRITTEN, RESPONSE_BYTES, FloorServiceAcquisitionOriginalV1, FloorServiceCurrentnessOriginalV1, FloorServicePolicyReadbackV1, RetainedFloorServicePolicyV1, decode_response_v2,
    encode_auth_v2, encode_hello_v2, encode_request_v2, require_broker_floor_helper_v1,
    require_broker_floor_owner_v1, require_lock_ack_v2,
};
pub(crate) use tpm_floor::{
    InitialModeOriginalV1, ModePinV1, ModePresenceOriginalV1, ModeRevalidationOriginalV1,
    mode_initial_receiving_demand_v1, mode_presence_receiving_demand_v1,
    mode_revalidation_receiving_demand_v1,
};
pub use storage_inventory_archive::ArchivedStorageInventoryHeadV1;

use owner::JournalOwnerV1;
pub(crate) use pending_request::ProtectedPendingBrokerRequestCutV1;
pub use original_create_failure::RetainedFailedCreateOriginalsDataV3;

use std::path::{Path, PathBuf};

use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyStorageRequest, BrokerMethod, ObserveHostExecutionArgumentRequestV1,
    AcceptHostExecutionArgumentRequestV2, RecoverStorageInventoryRequestV1,
    RecoverStorageInventoryResponseV1, StorageInventoryRecoveryDispositionV1,
};
use aos_sandbox_controller_domain::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_controller_domain::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES, BrokerSessionDurableEndpointV1,
    BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1, BrokerSessionProtectedBindingsV1,
    BrokerSessionProtocolV1,
    BrokerSessionTrafficStateV1, ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1, decode_canonical_request_v1, decode_canonical_response_v1,
};
use aos_sandbox_model::ProtocolVersion;
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerRequestDirectionV1,
    AuthenticatedHostNoApplyReadbackV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    authenticated_semantic_bindings_from_envelope_v1,
};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalSessionCheckpointV1, MAXIMUM_BYTES as MAXIMUM_HISTORICAL_CHECKPOINT_BYTES,
};
use aos_sandbox_protocol::authenticated_session::stored_history::{
    StoredBrokerSessionPurposeDataV2 as SessionPurpose,
    classify_protocol_key_v2, canonical_operator_recover_inventory_key_v1,
    canonical_host_stop_cleanup_key_v1, canonical_host_no_apply_cleanup_key_v1,
};
use aos_sandbox_protocol::authenticated_session::stored_history::{
    KEY_MAGIC, VALUE_FIXED_BYTES_V3, VALUE_VERSION_V2, VALUE_VERSION_V3,
    StoredBrokerSessionHistoryV1 as CanonicalStoredHistoryV1,
    StoredBrokerSessionHistoryViewV1 as CanonicalStoredHistoryViewV1, canonical_protocol_key_v1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordFieldsV1, HostExecutionNoApplyRecordV1,
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
    ObservedBrokerPeerExecutionV1, ObservedBrokerPeerOriginalV1,
    ProtectedBrokerOutcomeCommitReadbackV1,
    ProtectedBrokerOutcomeCommittedAdvancementV1, ProtectedBrokerOutcomeCurrentV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, ProtectedBrokerOutcomeGateRecoveryV1,
    ProtectedBrokerOutcomePendingAdvancementV1, ProtectedBrokerOutcomeReplayV1,
    ProtectedBrokerRequestWriteV1, ProtectedBrokerSessionJournalAuthorityV1,
    ProtectedBrokerSessionJournalSnapshotV1,
    admit_server_received_authenticated_broker_method_request_v1,
    map_durable, prepare_client_sent_authenticated_broker_method_request_v1,
    reconstruct_terminal_semantics,
    reconstruct_traffic, reconstruct_traffic_records, reopen_current,
    request_direction_for_endpoint, request_matches_head,
};

use crate::endpoint::RetainedOriginalBrokerOutcomeV1;

const STORAGE_GROUP_KEY_MAGIC: &[u8; 8] = b"AOSBSG01";
const STORAGE_INVENTORY_KEY_MAGIC: &[u8; 8] = b"AOSBSI01";
const STORAGE_ABANDONMENT_KEY_MAGIC: &[u8; 8] = b"AOSBSA01";
const HOST_ORIGINAL_SESSION_KEY_MAGIC: &[u8; 8] = aos_sandbox_protocol::authenticated_session::history_archive::HOST_ORIGINAL_SESSION_KEY_MAGIC_V1;
const HOST_TERMINAL_SESSION_KEY_MAGIC: &[u8; 8] = aos_sandbox_protocol::authenticated_session::history_archive::HOST_TERMINAL_SESSION_KEY_MAGIC_V1;
const VALUE_DOMAIN_V2: &[u8] = b"aos.sandbox.broker-session.protected-history.v2\0";
const VALUE_DOMAIN_V3: &[u8] = b"aos.sandbox.broker-session.protected-history.v3\0";
const ENDPOINT_PUBLICATION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.endpoint-publication.v1\0";
const STABLE_ENDPOINT_IDENTITY_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.stable-endpoint-identity.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.journal-transaction.v2\0";
const STORAGE_GROUP_ARCHIVE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-group-archive.v1\0";
const STORAGE_INVENTORY_ARCHIVE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-inventory-archive-transaction.v1\0";
const STORAGE_GROUP_ARCHIVE_RETIRE_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-group-archive-retire.v1\0";
const STORAGE_INVENTORY_RETIRE_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-inventory-retire.v1\0";
const STORAGE_GROUP_ARCHIVE_MAGIC: &[u8; 8] = b"AOSASAH1";
const STORAGE_GROUP_ARCHIVE_VALUE_DOMAIN: &[u8] =
    b"aos.sandbox.broker-session.storage-group-archive-value.v1\0";
const STORAGE_GROUP_ARCHIVE_HEADER_BYTES: usize = 8 + 2 + 16 + 4;
const STORAGE_GROUP_ARCHIVE_TRAILER_BYTES: usize = 32;
const HOST_ARGUMENT_ARCHIVE_MAGIC: &[u8; 8] = aos_sandbox_protocol::authenticated_session::history_archive::HOST_ARGUMENT_ARCHIVE_MAGIC_V1;
const HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN: &[u8] = aos_sandbox_protocol::authenticated_session::history_archive::HOST_ARGUMENT_ARCHIVE_DOMAIN_V1;
use aos_sandbox_controller_domain::journal::broker_session_receiving::{
    CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1,
    PROTECTED_SESSION_JOURNAL_V1 as PROTECTED_SESSION_JOURNAL,
    MAXIMUM_HOST_ARGUMENT_ARCHIVES, MAXIMUM_HOST_TERMINAL_ARCHIVES,
    MAXIMUM_PROTOCOL_RECORDS, MAXIMUM_STORAGE_GROUP_ARCHIVES,
    MAXIMUM_STORAGE_INVENTORY_ARCHIVES, MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS,
    protected_session_journal_limits_v1 as protected_session_journal_limits,
};

pub(crate) fn require_launch_image_presence(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    supplied: bool,
) -> Result<(), BrokerSessionSecurityError> {
    tpm_floor::runtime::require_launch_image_presence(endpoint, supplied)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn request_id_unused(request_id: [u8; 16], prior: impl IntoIterator<Item = [u8; 16]>) -> bool {
    request_id != [0; 16] && prior.into_iter().all(|previous| previous != request_id)
}

enum StorageArchiveKind {
    Group,
    Inventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerSessionJournalKeyKind {
    Traffic,
    StorageGroupArchive,
    StorageInventoryArchive,
    StorageInventoryAbandonment,
    HostOriginalSessionArchive,
    HostTerminalSessionArchive,
    OperatorRepairInventoryArchive,
}

impl BrokerSessionJournalKeyKind {
    fn from_storage_namespace(
        namespace: RecordNamespace,
    ) -> Result<Self, BrokerSessionSecurityError> {
        match namespace {
            RecordNamespace::BrokerSessionStorageGroupArchive => Ok(Self::StorageGroupArchive),
            RecordNamespace::BrokerSessionStorageInventoryArchive => {
                Ok(Self::StorageInventoryArchive)
            }
            RecordNamespace::BrokerSessionStorageInventoryAbandonment => {
                Ok(Self::StorageInventoryAbandonment)
            }
            _ => Err(BrokerSessionSecurityError::Currentness),
        }
    }
}

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

// Names the DATA returned by fully reauthenticated protected history reads.
pub(crate) use crate::controller_composition::HistoricalAtomicStorageHistoryDataV1 as ProtectedVerifiedAtomicStorageHistoryV1;

/// Retains one reauthenticated original method-37 request from protected H custody.
///
/// This historical readback cannot send, reobserve Guest arguments, or settle
/// Controller Create. Its signed identity must still be joined to a fresh
/// authenticated method-39/40 Host marker under both owners' currentness.
pub struct AuthenticatedOriginalHostArgumentArchiveV1 {
    source: ControllerExecutionArgumentAttemptV1,
    request: AuthenticatedBrokerMethodRequestV1,
    archive_head: [u8; 32],
}

impl AuthenticatedOriginalHostArgumentArchiveV1 {
    /// Borrows the original reauthenticated Host argument source.
    pub const fn source(&self) -> &ControllerExecutionArgumentAttemptV1 {
        &self.source
    }

    /// Borrows the original authenticated request without releasing its flight.
    pub const fn request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        &self.request
    }

    /// Observes the original protected archive head as comparison DATA.
    pub const fn archive_head(&self) -> [u8; 32] {
        self.archive_head
    }

    /// Joins original signed identity to one signed Host no-Apply readback.
    ///
    /// The result is historical evidence only. It does not prove current Host
    /// marker custody, Controller rollback resistance, or FAILED settlement.
    pub(crate) fn join_no_apply(
        self,
        readback: &AuthenticatedHostNoApplyReadbackV1<'_>,
    ) -> Result<AuthenticatedOriginalHostNoApplyJoinV1, BrokerSessionSecurityError> {
        if !OriginalHostArgumentIdentityV1::from_archive(&self).matches(readback.record().fields())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        Ok(AuthenticatedOriginalHostNoApplyJoinV1 {
            original: self,
            no_apply_outcome: readback.outcome().clone(),
            no_apply_record: *readback.record(),
        })
    }
}

/// Retains the typed identity-only join, without Controller settlement authority.
pub struct AuthenticatedOriginalHostNoApplyJoinV1 {
    original: AuthenticatedOriginalHostArgumentArchiveV1,
    no_apply_outcome: AuthenticatedBrokerMethodOutcomeV1,
    no_apply_record: HostExecutionNoApplyRecordV1,
}

impl AuthenticatedOriginalHostNoApplyJoinV1 {
    /// Borrows the original authenticated Host argument archive.
    pub const fn original(&self) -> &AuthenticatedOriginalHostArgumentArchiveV1 {
        &self.original
    }

    /// Borrows the original authenticated Host no-apply outcome.
    pub const fn no_apply_outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.no_apply_outcome
    }

    /// Observes the original checked no-apply record as comparison DATA.
    pub const fn no_apply_record(&self) -> HostExecutionNoApplyRecordV1 {
        self.no_apply_record
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OriginalHostArgumentIdentityV1 {
    execution_id: [u8; 16],
    create_operation_id: [u8; 16],
    original_request_id: [u8; 16],
    host_boot_id: [u8; 16],
    assignment_digest: [u8; 32],
    source_record_digest: [u8; 32],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
}

impl OriginalHostArgumentIdentityV1 {
    fn from_archive(archive: &AuthenticatedOriginalHostArgumentArchiveV1) -> Self {
        Self {
            execution_id: *archive.source.execution().as_bytes(),
            create_operation_id: *archive.source.create_operation().as_bytes(),
            original_request_id: archive.source.request_id(),
            host_boot_id: archive.source.host_boot_id(),
            assignment_digest: *archive.source.assignment_digest().as_bytes(),
            source_record_digest: *archive.source.record_digest().as_bytes(),
            original_session_binding: archive.request.session_binding(),
            original_signed_request_digest: archive.request.signed_request_digest(),
        }
    }

    fn matches(self, marker: HostExecutionNoApplyRecordFieldsV1) -> bool {
        self.execution_id == marker.execution_id
            && self.create_operation_id == marker.create_operation_id
            && self.original_request_id == marker.original_request_id
            && self.host_boot_id == marker.host_boot_id
            && self.assignment_digest == marker.assignment_digest
            && self.source_record_digest == marker.source_record_digest
            && self.original_session_binding == marker.original_session_binding
            && self.original_signed_request_digest == marker.original_signed_request_digest
    }
}

fn historical_terminal_outcome(
    records: &[aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1],
    terminal_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
    aos_sandbox_protocol::authenticated_session::historical_method::historical_terminal_outcome(records, terminal_index, checkpoint, transcript)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn historical_client_request(
    records: &[aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1],
    request_index: usize,
    checkpoint: &HistoricalSessionCheckpointV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<
    (
        AuthenticatedBrokerMethodRequestV1,
        Box<BrokerSessionTrafficStateV1>,
    ),
    BrokerSessionSecurityError,
> {
    aos_sandbox_protocol::authenticated_session::historical_method::historical_client_request(records, request_index, checkpoint, transcript)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
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

/// Seals the recovery reader implementation to this module.
pub(super) trait SealedJournalAuthority {}

enum ProtectedEndpointV1 {
    Client(ProtectedBrokerSessionClientV1),
    Broker(ProtectedBrokerSessionBrokerV1),
}

impl ProtectedEndpointV1 {
    fn launch_image(&self) -> Option<crate::production_startup::Pid1LaunchImageV1> {
        match self {
            Self::Client(endpoint) => endpoint.launch_image(),
            Self::Broker(endpoint) => endpoint.launch_image(),
        }
    }

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

    fn sign_stop_inventory_retaining_v5(&mut self, message: &[u8; 32],
        original: &mut crate::host_stop_inventory::StopAttestationSignatureV5,
    ) -> Result<[u8; 64], BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.sign_stop_inventory_retaining_v5(message, original),
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
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
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
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
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

    fn revalidate_into_v1(&mut self,
        original: &mut crate::endpoint::RetainedEndpointRevalidationOriginalV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.revalidate_handshake_custody_into_v1(original),
            Self::Broker(endpoint) => endpoint.revalidate_handshake_custody_into_v1(original),
        }
    }

    fn revalidate(&mut self) -> Result<(), BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint.revalidate_handshake_custody(),
            Self::Broker(endpoint) => endpoint.revalidate_handshake_custody(),
        }
    }

    fn protected_protocol_and_node(&self) -> (BrokerSessionProtocolV1, [u8; 16]) {
        match self {
            Self::Client(endpoint) => endpoint.protected_protocol_and_node(),
            Self::Broker(endpoint) => endpoint.protected_protocol_and_node(),
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

    fn context_retaining_v1(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        originals: &mut aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestContextOriginalsV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        match self {
            Self::Client(endpoint) => endpoint
                .context_for_handshake_retaining_v1(transcript.broker_process(), originals),
            Self::Broker(endpoint) => endpoint
                .context_for_handshake_retaining_v1(transcript.client_process(), originals),
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
    purpose: SessionPurpose,
    // Child/sidecar custody drops before the main writer. An unavailable
    // replacement during reconciliation grants no reentrant public read.
    floor_preparation: Option<Box<tpm_floor::runtime::InitialFloorConfigurationOriginalV1>>,
    floor_currentness: Option<floor_revalidation::FloorCurrentnessSharedV1>,
    floor_currentness_admission: Option<floor_revalidation::FloorCurrentnessAdmissionV1>,
    floor_currentness_binding: Option<Result<(), tpm_floor::FloorErrorV1>>,
    floor: tpm_floor::runtime::BrokerFloorV1,
    journal: Option<Journal>,
    captured_native_failure: Option<([u8; 16], aos_sandbox_controller_domain::JournalError)>,
    floor_main: tpm_floor::StorageFloorMainArchiveV3,
    session_replays: super::current_replay::StorageSessionReplayArchiveV3,
    schema_original: Option<StorageFloorSchemaOriginalV3>,
    storage_receiving_open: Option<StoragePrepareSessionOpenV1>,
    controller_initial_open: Option<ControllerInitialSessionMainOpenV1>,
    storage_host_open: Option<aos_sandbox_controller_domain::journal::StorageHostSessionCapturedJournalOpenV1>,
    client_retired_transcript: Option<retired_storage_transcript::RetiredStorageTranscriptV1>,
    directory: PathBuf,
    name: String,
    limits: JournalLimits,
    owner: JournalOwnerV1,
    endpoint: ProtectedEndpointV1,
    #[cfg(feature = "online-nix")]
    online_schema: Option<OnlineJournalSchemaV1>,
}

#[cfg(feature = "online-nix")]
struct OnlineJournalSchemaV1 {
    profile: crate::tpm_nv_custody::OnlineFloorProfileV1,
    key: [u8; 24],
    seed: [u8; 640],
    authority: aos_sandbox_broker::BrokerAuthority,
    prepared: Option<OnlinePreparedAuthorizationV1>,
    completed_preparations: [Option<OnlinePreparedAuthorizationV1>; 2],
    next_method: BrokerMethod,
    original_deadline: Option<u64>,
    phase_failed: bool,
    native_transaction: Option<std::sync::Arc<JournalTransaction>>,
    first_failure: Option<aos_sandbox_broker::BrokerAdmissionError>,
    clock_failure: Option<aos_sandbox_model::OwnershipClockObservationError>,
}

#[cfg(feature = "online-nix")]
struct OnlinePreparedAuthorizationV1 {
    request_id: [u8; 16],
    admission: Option<aos_sandbox_broker::VerifiedBrokerAdmission>,
    fence: Option<Vec<u8>>,
    effect: Option<Vec<u8>>,
}

/// Maps only the three canonical online methods to their existing verbs.
#[cfg(feature = "online-nix")]
pub(crate) fn online_nix_verb(method: BrokerMethod) -> Option<aos_sandbox_model::BrokerVerb> {
    match method {
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 =>
            Some(aos_sandbox_model::BrokerVerb::NixResolveProtectedRecipe),
        BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 =>
            Some(aos_sandbox_model::BrokerVerb::NixRealizeAuthorizedDerivation),
        BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 =>
            Some(aos_sandbox_model::BrokerVerb::NixQueryAuthorizedPathInfo),
        _ => None,
    }
}

#[cfg(feature = "online-nix")]
fn retain_online_authority_result<T>(
    first_failure: &mut Option<aos_sandbox_broker::BrokerAdmissionError>,
    result: Result<T, aos_sandbox_broker::BrokerAdmissionError>,
) -> Result<T, BrokerSessionSecurityError> {
    match result {
        Ok(value) => Ok(value),
        Err(cause) => {
            first_failure.get_or_insert(cause);
            Err(BrokerSessionSecurityError::Currentness)
        }
    }
}

#[cfg(feature = "online-nix")]
fn is_online_nix_authorization_key(key: &[u8]) -> bool {
    key.len() == 24 && (&key[..8] == b"AOSNXF01" || &key[..8] == b"AOSNXE01")
}

#[cfg(feature = "online-nix")]
fn require_online_effect_fields(
    schema: &OnlineJournalSchemaV1,
    effect: &aos_sandbox_broker::BrokerEffectIntentV1,
) -> Result<(), BrokerSessionSecurityError> {
    let target = aos_sandbox_model::BrokerResourceHandle::from_bytes(schema.profile.domain_commitment())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    if !matches!(effect.verb(), aos_sandbox_model::BrokerVerb::NixResolveProtectedRecipe
        | aos_sandbox_model::BrokerVerb::NixRealizeAuthorizedDerivation
        | aos_sandbox_model::BrokerVerb::NixQueryAuthorizedPathInfo)
        || effect.target() != aos_sandbox_model::BrokerGrantTarget::Resource(target)
        || effect.maximum_descriptors() != 0
        || effect.maximum_request_bytes() > aos_sandbox_protocol::nix_build::NIX_REQUEST_MAXIMUM_BYTES_V2 as u32
        || effect.local_lease_record().node().as_bytes() != &schema.profile.node()
        || (effect.status() == aos_sandbox_broker::BrokerEffectStatusV1::Complete
            && effect.receipt().len() != 32)
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(())
}

#[cfg(feature = "online-nix")]
fn require_online_history_effect(
    schema: &OnlineJournalSchemaV1,
    record: &aos_sandbox_broker_session_protocol::BrokerSessionDurableRecordV1,
    effect: &aos_sandbox_broker::BrokerEffectIntentV1,
) -> Result<(), BrokerSessionSecurityError> {
    require_online_effect_fields(schema, effect)?;
    let request = decode_canonical_request_v1(record.request_packet())
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let body_digest: [u8; 32] = Sha256::digest(&request.message().body).into();
    if online_nix_verb(record.method()) != Some(effect.verb())
        || record.request_id() != *effect.request_id()
        || effect.transport_request_digest().as_bytes() != &body_digest
        || effect.request_digest().as_bytes() != &record.request_semantic_binding()
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    if record.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
        && effect.status() != aos_sandbox_broker::BrokerEffectStatusV1::Pending
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    if record.phase() == BrokerSessionDurablePhaseV1::Terminal {
        let receipt: [u8; 32] = Sha256::digest(record.outcome_packet()
            .ok_or(BrokerSessionSecurityError::Currentness)?).into();
        if effect.status() != aos_sandbox_broker::BrokerEffectStatusV1::Complete
            || effect.receipt() != receipt
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
    }
    Ok(())
}

impl core::fmt::Debug for ProtectedBrokerSessionJournalV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionJournalV1([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerMainOpenPhaseV1 {
    Fresh,
    Checking,
    Ready,
    Failed,
}

enum BrokerMainOpenFailureV1 {
    Endpoint(BrokerSessionSecurityError),
    Floor(tpm_floor::FloorErrorV1),
    Deadline(crate::DormantBrokerSessionHandshakeErrorV1),
}

impl BrokerMainOpenFailureV1 {
    fn projection(&self) -> BrokerSessionSecurityError {
        match self {
            // These errors contain only static labels, not owning descriptors
            // or provider errors. The actual Required native cause stays on
            // the resident floor, rather than being cloned into this result.
            Self::Endpoint(error) => error.clone(),
            Self::Floor(_) | Self::Deadline(_) => BrokerSessionSecurityError::Currentness,
        }
    }
}

impl From<BrokerSessionSecurityError> for BrokerMainOpenFailureV1 {
    fn from(error: BrokerSessionSecurityError) -> Self {
        Self::Endpoint(error)
    }
}

/// Stages actual endpoint, configured floor and returned main without a shell
/// that can manufacture endpoint custody or bypass its admission.
pub(crate) struct BrokerMainOpenV1 {
    floor_preparation: Option<Box<tpm_floor::runtime::InitialFloorConfigurationOriginalV1>>,
    authority: Option<ProtectedBrokerSessionJournalV1>,
    floor: Option<tpm_floor::runtime::BrokerFloorV1>,
    endpoint: Option<ProtectedEndpointV1>,
    directory: PathBuf,
    name: String,
    limits: JournalLimits,
    phase: BrokerMainOpenPhaseV1,
    first_failure: Option<BrokerMainOpenFailureV1>,
    cold_deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    #[cfg(feature = "online-nix")]
    online_schema: Option<OnlineJournalSchemaV1>,
}

// One native open recipe serves the original consuming boundary and the
// Required progress slots. The literal arms change storage, not replay policy.
macro_rules! broker_main_open_step {
    (Legacy, deadline $place:ident) => {};
    (Retained, deadline $place:ident) => { $place.check_cold_deadline()?; };
    (Legacy, directory $place:ident, $directory:ident) => { &$directory };
    (Retained, directory $place:ident, $directory:ident) => { &$place.owner.directory };
    (Legacy, name $place:ident, $name:ident) => { $name };
    (Retained, name $place:ident, $name:ident) => { &$place.owner.name };
    (Legacy, limits $place:ident, $limits:ident) => { $limits };
    (Retained, limits $place:ident, $limits:ident) => { $place.owner.limits };
    (Legacy, owner $place:ident, $owner:ident) => { $owner };
    (Retained, owner $place:ident, $owner:ident) => { $place.owner.owner };
    (Legacy, requires_existing $place:ident, $floor:ident) => { $floor.requires_existing() };
    (Retained, requires_existing $place:ident, $floor:ident) => {
        $place.floor.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.requires_existing()
    };
    (Legacy, stage $place:ident, $opened:ident, $journal:ident) => {
        let ($journal, _) = $opened.map_err(|_| BrokerSessionSecurityError::Currentness)?;
    };
    (Retained, stage $place:ident, $opened:ident, $journal:ident) => {
        let ($journal, _) = $place.retain_native_result($opened)?;
        $place.owner.journal = Some($journal);
    };
    (Legacy, endpoint $place:ident, $endpoint:ident) => { $endpoint.revalidate()?; };
    (Retained, endpoint $place:ident, $endpoint:ident) => { $place.owner.endpoint.revalidate()?; };
    (Legacy, construct $place:ident, $endpoint:ident, $directory:ident, $name:ident,
        $limits:ident, $owner:ident, $journal:ident) => {
        let mut $place = Self {
            purpose: SessionPurpose::Ordinary,
            floor_preparation: None,
            floor_currentness: None,
            floor_currentness_admission: None,
            floor_currentness_binding: None,
            floor: tpm_floor::runtime::BrokerFloorV1::unavailable(),
            journal: Some($journal),
            captured_native_failure: None,
            floor_main: tpm_floor::StorageFloorMainArchiveV3::new(),
            session_replays: Default::default(),
            schema_original: None,
            storage_receiving_open: None,
            controller_initial_open: None,
            storage_host_open: None,
            client_retired_transcript: None,
            directory: $directory,
            name: $name.to_owned(),
            limits: $limits,
            owner: $owner,
            endpoint: $endpoint,
            #[cfg(feature = "online-nix")]
            online_schema: None,
        };
    };
    (Retained, construct $place:ident, $endpoint:ident, $directory:ident, $name:ident,
        $limits:ident, $owner:ident, $journal:ident) => {};
    (Legacy, finish $place:ident, $floor:ident) => {{
        $place.validate_schema_only()?;
        $place.floor = $floor;
        $place.attach_floor()?;
        $place.validate_all()?;
        Ok($place)
    }};
    (Retained, finish $place:ident, $floor:ident) => {{
        $place.owner.validate_schema_only()?;
        $place.attach()
    }};
}

macro_rules! broker_main_open_recipe {
    ($mode:ident, $place:ident, $protocol:ident, $endpoint:ident, $directory:ident,
        $name:ident, $limits:ident, $floor:ident, $owner:ident) => {{
        broker_main_open_step!($mode, deadline $place);
        let existing = match std::fs::symlink_metadata(
            broker_main_open_step!($mode, directory $place, $directory).join(
                broker_main_open_step!($mode, name $place, $name),
            ),
        ) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(BrokerSessionSecurityError::Currentness),
        };
        broker_main_open_step!($mode, deadline $place);
        let opened = if broker_main_open_step!($mode, requires_existing $place, $floor)
            || $protocol == BrokerSessionProtocolV1::Storage && existing
        {
            broker_main_open_step!($mode, owner $place, $owner).open_existing(
                broker_main_open_step!($mode, directory $place, $directory),
                broker_main_open_step!($mode, name $place, $name),
                broker_main_open_step!($mode, limits $place, $limits),
            )
        } else {
            broker_main_open_step!($mode, owner $place, $owner).open(
                broker_main_open_step!($mode, directory $place, $directory),
                broker_main_open_step!($mode, name $place, $name),
                broker_main_open_step!($mode, limits $place, $limits),
            )
        };
        broker_main_open_step!($mode, stage $place, opened, journal);
        broker_main_open_step!($mode, deadline $place);
        broker_main_open_step!($mode, endpoint $place, $endpoint);
        broker_main_open_step!($mode, construct $place, $endpoint, $directory, $name,
            $limits, $owner, journal);
        broker_main_open_step!($mode, finish $place, $floor)
    }};
}

// The actual opening stays with the Session authority after the Journal
// moves out. Its failed native stage and independent posts therefore survive
// both cold-open failure and successful receipt of the contacted request.
struct StoragePrepareSessionOpenV1 {
    existing: Option<Result<std::fs::Metadata, std::io::Error>>,
    native: aos_sandbox_controller_domain::journal::StorageBrokerCapturedJournalOpenV1,
    original_extent: Option<aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1>,
    schema_demand: Option<Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError>>,
    initialization_demand: Option<Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError>>,
    native_settlement: Option<Result<(), BrokerSessionSecurityError>>,
    retired_transcript: Option<retired_storage_transcript::RetiredStorageTranscriptV1>,
}

impl StoragePrepareSessionOpenV1 {
    const fn new() -> Self {
        Self {
            existing: None,
            native: aos_sandbox_controller_domain::journal::StorageBrokerCapturedJournalOpenV1::new(),
            original_extent: None,
            schema_demand: None,
            initialization_demand: None,
            native_settlement: None,
            retired_transcript: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.existing.as_ref()
            .and_then(|result| result.as_ref().err())
            .filter(|cause| cause.kind() != std::io::ErrorKind::NotFound)
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.native.failure())
            .or_else(|| self.schema_demand.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.initialization_demand.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

/// Describes only the actual closed initial floor capture representation.
pub(crate) fn floor_initial_capture_shape_v1(
    role: aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1,
) -> Option<aos_sandbox_controller_domain::ControllerInitialBrokerSessionCaptureShapeV1> {
    tpm_floor::runtime::InitialFloorConfigurationOriginalV1::fixed_shape_v1(role)
}

impl BrokerMainOpenV1 {
    pub(crate) fn storage_hello_flight_demand_v1() -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        storage_receiving_demand::handshake_flight_demand()
    }

    /// Reserves the actual fixed endpoint/hello stage before custody is loaded.
    ///
    /// # Errors
    /// Rejects checked demand overflow, a repeated stage, insufficient original
    /// Storage capacity, or failed same-original receiving currentness. Native
    /// debit and currentness causes remain on that actual receiving owner.
    pub(crate) fn reserve_storage_prepare_fixed_v1(
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let demand = storage_receiving_demand::fixed_security_demand()?;
        receiving.reserve_session_fixed_once_v1(demand)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn prepare_online(
        custody: &mut Option<FixedEndpointCustodyV1>,
        provision: &mut Option<crate::nix_service::floor::OnlineProvisionV1>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        // The delivered original manifest and fixed key custody must describe
        // the same signed context. Protocol/node equality alone is too weak.
        // Both actual owning options remain parked across these observations.
        let expected_binding = provision.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .manifest_binding().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let observed_binding = match custody.as_mut() {
            Some(FixedEndpointCustodyV1::Client(endpoint)) => endpoint.manifest_binding()?,
            Some(FixedEndpointCustodyV1::Broker(endpoint)) => endpoint.manifest_binding()?,
            None => return Err(BrokerSessionSecurityError::Currentness),
        };
        if observed_binding.as_bytes() != &expected_binding {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        provision.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .revalidate().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        deadline.check().map_err(|_| BrokerSessionSecurityError::Currentness)?;

        let supplied = provision.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let profile = supplied.profile().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let key = supplied.seed_key().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let seed: [u8; 640] = supplied.seed().map_err(|_| BrokerSessionSecurityError::Currentness)?
            .try_into().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let expected_role = match profile.role() {
            crate::tpm_nv_custody::OnlineFloorRoleV1::Controller => BrokerSessionDurableEndpointV1::Client,
            crate::tpm_nv_custody::OnlineFloorRoleV1::Owner => BrokerSessionDurableEndpointV1::Broker,
        };
        let observed_role = match custody.as_ref() {
            Some(FixedEndpointCustodyV1::Client(endpoint))
                if endpoint.protected_protocol_and_node()
                    == (BrokerSessionProtocolV1::Nix, profile.node()) =>
                BrokerSessionDurableEndpointV1::Client,
            Some(FixedEndpointCustodyV1::Broker(endpoint))
                if endpoint.protected_protocol_and_node()
                    == (BrokerSessionProtocolV1::Nix, profile.node()) =>
                BrokerSessionDurableEndpointV1::Broker,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if expected_role != observed_role {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let limits = profile.main_limits().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let directory = PathBuf::from(profile.role().directory());
        let name = PROTECTED_SESSION_JOURNAL.to_owned();
        // Both originals remain in caller slots through all checks/allocation.
        // These final moves contain no effect or subsequent fallible gate.
        if !supplied.has_original_authority() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        match (custody.take(), provision.take()) {
            (Some(custody_original), Some(mut provision_original)) => {
                let authority = match provision_original.take_original_authority() {
                    Some(authority) => authority,
                    None => {
                        *custody = Some(custody_original);
                        *provision = Some(provision_original);
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                };
                let endpoint = match custody_original {
                    FixedEndpointCustodyV1::Client(endpoint) => ProtectedEndpointV1::Client(endpoint),
                    FixedEndpointCustodyV1::Broker(endpoint) => ProtectedEndpointV1::Broker(endpoint),
                };
                Ok(Self {
                    floor_preparation: None,
                    authority: None,
                    floor: Some(tpm_floor::runtime::BrokerFloorV1::online(provision_original)),
                    endpoint: Some(endpoint), directory, name, limits,
                    phase: BrokerMainOpenPhaseV1::Fresh,
                    first_failure: None,
                    cold_deadline: Some(deadline),
                    online_schema: Some(OnlineJournalSchemaV1 {
                        profile, key, seed, authority, prepared: None,
                        completed_preparations: [None, None],
                        next_method: BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2,
                        original_deadline: None, phase_failed: false,
                        native_transaction: None, first_failure: None, clock_failure: None,
                    }),
                })
            }
            (custody_original, provision_original) => {
                *custody = custody_original;
                *provision = provision_original;
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    /// Prepares only the actual fixed Storage endpoint without moving custody
    /// across an allocation or validation gate. The caller keeps its slot
    /// until the prepared shell is complete.
    ///
    /// # Errors
    /// Rejects absent custody or a role/protocol/root other than fixed Storage.
    pub(crate) fn prepare_storage(
        root: &'static str,
        custody: &mut Option<FixedEndpointCustodyV1>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let expected_root = match custody.as_ref() {
            Some(FixedEndpointCustodyV1::Client(endpoint))
                if endpoint.protected_protocol_and_node().0 == BrokerSessionProtocolV1::Storage =>
            {
                "/var/lib/aos/sandboxd/broker-session/storage"
            }
            Some(FixedEndpointCustodyV1::Broker(endpoint))
                if endpoint.protected_protocol_and_node().0 == BrokerSessionProtocolV1::Storage =>
            {
                "/var/lib/aos/sandbox-storage/broker-session"
            }
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if root != expected_root {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let directory = PathBuf::from(root);
        let name = PROTECTED_SESSION_JOURNAL.to_owned();
        let endpoint = match custody.take() {
            Some(FixedEndpointCustodyV1::Client(endpoint)) => ProtectedEndpointV1::Client(endpoint),
            Some(FixedEndpointCustodyV1::Broker(endpoint)) => ProtectedEndpointV1::Broker(endpoint),
            None => return Err(BrokerSessionSecurityError::Currentness),
        };
        Ok(Self {
            floor_preparation: None,
            authority: None,
            floor: None,
            endpoint: Some(endpoint),
            directory,
            name,
            limits: protected_session_journal_limits(),
            phase: BrokerMainOpenPhaseV1::Fresh,
            first_failure: None,
            cold_deadline: Some(deadline),
            #[cfg(feature = "online-nix")]
            online_schema: None,
        })
    }

    pub(crate) fn finish_into(&mut self, destination: &mut Option<ProtectedBrokerSessionOwnerV1>) {
        // All shape and currentness gates run before this infallible move.
        if self.phase == BrokerMainOpenPhaseV1::Ready && destination.is_none() {
            if let Some(journal) = self.authority.take() {
                *destination = Some(ProtectedBrokerSessionOwnerV1 { journal });
            }
        }
    }

    pub(crate) fn completed_transfer_shell_v1(&self) -> bool {
        self.phase == BrokerMainOpenPhaseV1::Ready && self.first_failure.is_none()
            && self.authority.is_none() && self.endpoint.is_none() && self.floor.is_none()
    }

    fn prepare(
        endpoint: ProtectedEndpointV1,
        directory: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Self {
        Self {
            floor_preparation: None,
            authority: None,
            floor: None,
            endpoint: Some(endpoint),
            directory: directory.to_path_buf(),
            name: name.to_owned(),
            limits,
            phase: BrokerMainOpenPhaseV1::Fresh,
            first_failure: None,
            cold_deadline: None,
            #[cfg(feature = "online-nix")]
            online_schema: None,
        }
    }

    /// Opens only this prepared actual endpoint; failed or unfinished phases
    /// cannot be repeated.
    ///
    /// # Errors
    /// Preserves endpoint rejection and the old currentness projection while
    /// native, physical and cutoff causes remain on their resident owners.
    pub(crate) fn open(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.open_with_storage_receiving(None)
    }

    /// Opens the fixed Storage main through its genuine receiving subdivision.
    ///
    /// The actual loan admits and resumes this same captured Native opening;
    /// a caller-supplied byte ceiling cannot substitute for that continuation.
    pub(crate) fn open_storage_prepare_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.open_with_storage_receiving(Some(receiving))
    }

    pub(crate) fn observe_storage_initial_failure_post_v2(&mut self)
        -> Result<(), BrokerSessionSecurityError>
    {
        let Some(owner) = self.authority.as_mut() else { return Ok(()); };
        finish_storage_failure_post_v2(owner)
    }

    pub(crate) fn storage_prepare_native_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.floor_preparation.as_ref().and_then(|original| original.failure())
            .or_else(|| self.authority.as_ref().and_then(|owner| {
                owner.floor_preparation.as_ref().and_then(|original| original.failure())
            }))
            .or_else(|| self.authority.as_ref()?.storage_receiving_open.as_ref()?.failure())
            .or_else(|| self.authority.as_ref()?.floor_main.failure())
            .or_else(|| self.authority.as_ref()?.session_replays.failure())
            .or_else(|| self.authority.as_ref()?.floor.storage_sidecar_failure_v2())
            .or_else(|| self.authority.as_ref()?.floor.storage_physical_failure_v2())
    }

    pub(crate) fn storage_prepare_cold_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.authority.as_ref().and_then(|owner| owner.floor.ordinary_cold_failure())
            .or_else(|| self.floor.as_ref().and_then(|floor| floor.ordinary_cold_failure()))
    }

    fn open_with_storage_receiving(
        &mut self,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.open_with_original_receiving_v1(receiving, None, None)
    }

    fn open_with_original_receiving_v1(
        &mut self,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        initial: Option<&mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        host: Option<&mut StorageHostClientReceivingV1<'_, '_, '_>>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.open_with_fixed_service_receiving_v4(receiving, initial, host, None)
    }

    fn open_with_fixed_service_receiving_v4(
        &mut self,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        initial: Option<&mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        host: Option<&mut StorageHostClientReceivingV1<'_, '_, '_>>,
        fixed: Option<&mut dyn FixedServiceColdJournalReceivingV4>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.phase != BrokerMainOpenPhaseV1::Fresh {
            self.phase = BrokerMainOpenPhaseV1::Failed;
            return Err(self.first_failure.as_ref().map_or(
                BrokerSessionSecurityError::Currentness,
                BrokerMainOpenFailureV1::projection,
            ));
        }
        if (receiving.is_some() && initial.is_some())
            || (host.is_some() && (receiving.is_some() || initial.is_some()))
            || (fixed.is_some() && (receiving.is_some() || initial.is_some() || host.is_some())) {
            self.phase = BrokerMainOpenPhaseV1::Failed;
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // An abandoned or caught-unwind admission stays Checking and cannot
        // start again. Returned owners remain in these same original slots.
        self.phase = BrokerMainOpenPhaseV1::Checking;
        let result = self.open_inner(receiving, initial, host, fixed);
        match result {
            Ok(()) => {
                self.phase = BrokerMainOpenPhaseV1::Ready;
                Ok(())
            }
            Err(cause) => {
                let projected = cause.projection();
                self.first_failure = Some(cause);
                self.phase = BrokerMainOpenPhaseV1::Failed;
                if let Some(owner) = self.authority.as_mut() {
                    // The primary and each actual Mode/provision/main/
                    // sidecar/physical post remain on their real owners.
                    // Completing this negative cannot restore readiness.
                    let _ = finish_storage_failure_post_v2(owner);
                }
                Err(projected)
            }
        }
    }

    fn open_inner(
        &mut self,
        mut receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        mut initial: Option<&mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>>,
        mut host: Option<&mut StorageHostClientReceivingV1<'_, '_, '_>>,
        mut fixed: Option<&mut dyn FixedServiceColdJournalReceivingV4>,
    ) -> Result<(), BrokerMainOpenFailureV1> {
        if let Some(deadline) = self.cold_deadline {
            deadline.check().map_err(BrokerMainOpenFailureV1::Deadline)?;
        }
        if let Some(original) = receiving.as_deref_mut() {
            original.require_session_fixed_current_v1()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if let Some(original) = initial.as_deref_mut() {
            original.require_fixed_capture_current_v1(original.role_v1())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if let Some(original) = host.as_deref_mut() { original.require_current_v1()?; }
        if let Some(original) = fixed.as_deref_mut() { original.require_current_v4()?; }
        let endpoint = self.endpoint
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        endpoint.revalidate()?;
        let protocol = endpoint.protected_protocol_and_node().0;
        if protocol == BrokerSessionProtocolV1::Storage && self.name != PROTECTED_SESSION_JOURNAL {
            return Err(BrokerSessionSecurityError::Currentness.into());
        }
        if let Some(deadline) = self.cold_deadline {
            deadline.check().map_err(BrokerMainOpenFailureV1::Deadline)?;
        }
        if self.floor.is_none() {
            if receiving.is_some() || initial.is_some() || host.is_some() || fixed.is_some() {
                // Genuine fixed payment preceded this allocation. Park the
                // owner before any mode path construction or native access.
                self.floor_preparation = Some(Box::new(
                    tpm_floor::runtime::InitialFloorConfigurationOriginalV1::new(),
                ));
                let original = self.floor_preparation.as_mut()
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                original.configure_once(
                    &self.directory, protocol, endpoint.role(), endpoint.launch_image(),
                ).map_err(BrokerMainOpenFailureV1::Floor)?;
                self.floor = Some(original.take_floor_once()
                    .ok_or(BrokerMainOpenFailureV1::Floor(tpm_floor::FloorErrorV1::Unavailable))?);
            } else {
                self.floor = Some(tpm_floor::runtime::BrokerFloorV1::configure(
                    &self.directory, protocol, endpoint.role(), endpoint.launch_image(),
                ).map_err(BrokerMainOpenFailureV1::Floor)?);
            }
        }
        let floor = self.floor.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if host.is_some() {
            floor.bind_storage_host_cold_v1(self.cold_deadline
                .ok_or(BrokerSessionSecurityError::Currentness)?)
                .map_err(BrokerMainOpenFailureV1::Floor)?;
        } else if initial.is_some() || fixed.is_some() {
            // Genuine selected binding happens after the actual main take.
            // Required's distinct sidecar and persistent physical phases debit
            // the same original before their own native frontiers below.
        } else if floor.has_resident_required_attempt() {
            if let Some(deadline) = self.cold_deadline {
                floor.bind_cold_deadline(deadline)
                    .map_err(BrokerMainOpenFailureV1::Floor)?;
            }
        } else {
            // Only the actual receiving-loan entry may retain ordinary Storage
            // cold custody. A resource image never selects a physical floor.
            let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
            if protocol != BrokerSessionProtocolV1::Storage
                || endpoint.role() != BrokerSessionDurableEndpointV1::Broker
                || self.directory != Path::new(fixed.journal_root)
                || self.name != PROTECTED_SESSION_JOURNAL
            {
                return Err(BrokerSessionSecurityError::Currentness.into());
            }
            let receiving = receiving.as_deref_mut()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let deadline = self.cold_deadline
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            floor.bind_storage_receiving_cold(receiving, deadline)
                .map_err(BrokerMainOpenFailureV1::Floor)?;
        }
        let owner = JournalOwnerV1::capture(endpoint.role());

        // All names were prepared before effects. The moves below perform no
        // validation between the returned floor and its whole-owner slot.
        match (self.endpoint.take(), self.floor.take()) {
            (Some(endpoint), Some(floor)) => {
                self.authority = Some(ProtectedBrokerSessionJournalV1 {
                    purpose: SessionPurpose::Ordinary,
                    floor_preparation: self.floor_preparation.take(),
                    floor_currentness: None,
                    floor_currentness_admission: None,
                    floor_currentness_binding: None,
                    floor,
                    journal: None,
                    captured_native_failure: None,
                    floor_main: tpm_floor::StorageFloorMainArchiveV3::new(),
                    session_replays: Default::default(),
                    schema_original: None,
                    storage_receiving_open: None,
                    controller_initial_open: None,
            storage_host_open: None,
            client_retired_transcript: None,
                    directory: std::mem::take(&mut self.directory),
                    name: std::mem::take(&mut self.name),
                    limits: self.limits,
                    owner,
                    endpoint,
                    #[cfg(feature = "online-nix")]
                    online_schema: self.online_schema.take(),
                });
            }
            (endpoint, floor) => {
                self.endpoint = endpoint;
                self.floor = floor;
                return Err(BrokerSessionSecurityError::Currentness.into());
            }
        }
        let authority = self.authority
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let mut operation = BrokerFloorOperationV1::begin(authority);
        let result = if let Some(original) = fixed {
            operation.open_fixed_service_main_v4(protocol, original,
                self.cold_deadline.ok_or(BrokerSessionSecurityError::Currentness)?)
        } else {
            match (initial, host) {
            (Some(original), None) => operation.open_controller_initial_main_v1(
                protocol, original, self.cold_deadline.ok_or(BrokerSessionSecurityError::Currentness)?,
            ),
            (None, Some(original)) => operation.open_storage_host_main_v1(protocol, original),
            (None, None) => operation.open_main(protocol, receiving.as_deref_mut()),
            _ => Err(BrokerSessionSecurityError::Currentness),
            }
        };
        operation.finish(result)?;
        authority.validate_all()?;
        Ok(())
    }

    fn into_owner(
        mut self,
    ) -> Result<ProtectedBrokerSessionJournalV1, BrokerSessionSecurityError> {
        if self.phase != BrokerMainOpenPhaseV1::Ready {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.authority.take().ok_or(BrokerSessionSecurityError::Currentness)
    }
}

#[cfg(test)]
mod broker_cold_adapter_tests {
    use super::{BrokerMainOpenFailureV1, BrokerMainOpenV1, BrokerSessionSecurityError};
    use crate::handshake::OriginalBrokerColdDeadlineV1;

    #[test]
    fn missing_actual_custody_refuses_before_name_or_journal_work() {
        let mut custody = None;
        let deadline = OriginalBrokerColdDeadlineV1::storage_accept(1);

        let result = BrokerMainOpenV1::prepare_storage(
            "/var/lib/aos/sandboxd/broker-session/storage",
            &mut custody,
            deadline,
        );

        assert!(matches!(result, Err(BrokerSessionSecurityError::Currentness)));
        assert!(custody.is_none());
    }

    #[test]
    fn cutoff_cause_keeps_existing_currentness_facade() {
        let cause = BrokerMainOpenFailureV1::Deadline(
            crate::DormantBrokerSessionHandshakeErrorV1::Deadline,
        );

        assert!(matches!(cause.projection(), BrokerSessionSecurityError::Currentness));
        assert!(matches!(cause, BrokerMainOpenFailureV1::Deadline(_)));
    }
}

/// Owns the moved floor and a separate borrow of the whole original Journal.
/// Its Drop restores only the same fenced Required floor. Ordinary unwind
/// retains the original local-disposal inverse. Forgetting leaves the owner
/// unavailable, never ready.
struct BrokerFloorOperationV1<'operation> {
    floor: Option<tpm_floor::runtime::BrokerFloorV1>,
    owner: &'operation mut ProtectedBrokerSessionJournalV1,
    complete: bool,
}

impl<'operation> BrokerFloorOperationV1<'operation> {
    fn check_cold_deadline(&mut self) -> Result<(), BrokerSessionSecurityError> {
        Self::check_floor_cold_deadline(&mut self.floor)
    }

    fn check_floor_cold_deadline(
        floor: &mut Option<tpm_floor::runtime::BrokerFloorV1>,
    ) -> Result<(), BrokerSessionSecurityError> {
        floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .check_cold_deadline().map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    fn begin(owner: &'operation mut ProtectedBrokerSessionJournalV1) -> Self {
        let floor = std::mem::replace(
            &mut owner.floor,
            tpm_floor::runtime::BrokerFloorV1::unavailable(),
        );
        Self {
            floor: Some(floor),
            owner,
            complete: false,
        }
    }

    fn open_main(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if let Some(receiving) = receiving {
            return self.open_storage_prepare_main(protocol, receiving);
        }
        broker_main_open_recipe!(Retained, self, protocol, endpoint, directory,
            name, limits, floor, owner)
    }

    fn open_storage_prepare_main(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        use aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1;

        self.check_cold_deadline()?;
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        if protocol != BrokerSessionProtocolV1::Storage
            || self.owner.owner != JournalOwnerV1::RootBroker
            || self.owner.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || self.owner.directory != Path::new(fixed.journal_root)
            || self.owner.name != PROTECTED_SESSION_JOURNAL
            || self.owner.journal.is_some()
            || self.owner.storage_receiving_open.is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let floor_requires_existing = self.floor.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .requires_existing();
        self.owner.storage_receiving_open = Some(StoragePrepareSessionOpenV1::new());
        let staged = self.owner.storage_receiving_open.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        staged.existing = Some(std::fs::symlink_metadata(
            self.owner.directory.join(&self.owner.name),
        ));
        let existing = match staged.existing.as_ref() {
            Some(Ok(_)) => true,
            Some(Err(cause)) if cause.kind() == std::io::ErrorKind::NotFound => false,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        Self::check_floor_cold_deadline(&mut self.floor)?;
        let mode = if floor_requires_existing || existing {
            CapturedJournalOpenModeV1::ExistingOnly
        } else {
            CapturedJournalOpenModeV1::CreateAndRepair
        };
        staged.native.prepare_once(self.owner.limits, mode);
        Self::check_floor_cold_deadline(&mut self.floor)?;
        // Preserve full historical geometry before the Native replay entrance
        // closes its pre-replay getter. This DATA cannot authorize another open.
        staged.original_extent = staged.native.captured_extent().copied();

        // Price upper Session schema materialization from this same captured
        // prefix. The whole supplier Result remains in the original opening.
        staged.schema_demand = Some(staged.original_extent.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)
            .and_then(|extent| storage_session_schema_demand::schema_demand(extent)
                .map_err(BrokerSessionSecurityError::from)));
        let demand = match staged.schema_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };

        // The guard borrows both originals across upper-schema and Native
        // admission, so another staged opener cannot replace the paid prefix.
        {
            let mut replay = receiving.reserve_session_schema_once_v1(&mut staged.native, demand)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            replay.reserve_session_prefix_once_v1()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            Self::check_floor_cold_deadline(&mut self.floor)?;
            // Native V3 binds the existing Journal Arc to its active pool
            // before this guard releases either actual original borrow.
            replay.replay_session_once_v1()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        // Initialization and later checkpoint growth are distinct from replay.
        // Refusal leaves the actual opened Journal in its original staging slot.
        staged.initialization_demand = Some(staged.original_extent.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)
            .and_then(|extent| storage_session_schema_demand::initialization_demand(extent)
                .map_err(BrokerSessionSecurityError::from)));
        let demand = match staged.initialization_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        receiving.reserve_session_initialization_once_v1(demand)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Self::check_floor_cold_deadline(&mut self.floor)?;

        let (journal, _) = staged.native.take_opened()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.owner.journal = Some(journal);

        // The original floor attachment and full schema/currentness checks
        // retain their order after the actual same-file opening completes.
        self.check_cold_deadline()?;
        self.owner.endpoint.revalidate()?;
        self.owner.validate_schema_only()?;
        let floor = self.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        self.owner.arm_storage_receiving_floor_revalidation_v2(floor, receiving)?;
        floor.attach_storage_initial_v2(self.owner, receiving)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    fn reopen(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.floor
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .suspend_for_reopen();
        drop(self.owner.journal.take());
        // Healthy reopen preserves the explicit sidecar-before-main release
        // and original opener selection; failure cannot enable another reopen.
        let floor = self.floor
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let opened = if floor.requires_existing()
            || self.owner.endpoint.protected_protocol_and_node().0 == BrokerSessionProtocolV1::Storage
        {
            self.owner.owner.open_existing(
                &self.owner.directory,
                &self.owner.name,
                self.owner.limits,
            )
        } else {
            self.owner.owner.open(
                &self.owner.directory,
                &self.owner.name,
                self.owner.limits,
            )
        };
        let (journal, _) = self.retain_native_result(opened)?;
        self.owner.journal = Some(journal);
        self.owner.validate_schema_only()?;
        self.attach()?;
        self.owner.endpoint.revalidate()
    }

    fn retain_native_result<T>(
        &mut self,
        result: Result<T, aos_sandbox_controller_domain::JournalError>,
    ) -> Result<T, BrokerSessionSecurityError> {
        if !self.floor.as_ref().is_some_and(
            tpm_floor::runtime::BrokerFloorV1::has_resident_required_attempt,
        ) {
            // Legacy redacts and disposes the provider error immediately at
            // the original native-return boundary, without debt retention.
            return result.map_err(|_| BrokerSessionSecurityError::Currentness);
        }
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                if let Some(floor) = &mut self.floor {
                    floor.record_native_failure(cause);
                }
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    fn attach(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.floor
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .attach(self.owner)
            .map_err(floor_revalidation::security_error)
    }

    fn check(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.floor
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .check(self.owner)
            .map_err(floor_revalidation::security_error)
    }

    fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.commit_with_storage_receiving_v2(transaction, None)
    }

    fn commit_with_storage_receiving_v2(&mut self, transaction: &JournalTransaction,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let before = self.owner.captured_native_failure.is_some();
        let result = self.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .commit_with_storage_receiving_v2(self.owner, transaction, receiving).map_err(floor_revalidation::security_error);
        if result.is_err() && !before {
            if self.owner.captured_native_failure.as_ref().is_some_and(|(id, _)| id == transaction.id()) {
                return Err(BrokerSessionSecurityError::CapturedJournalMutation { transaction: *transaction.id() });
            }
        }
        result
    }

    fn finish<T, E>(mut self, result: Result<T, E>) -> Result<T, E> {
        if result.is_err() {
            if let Some(floor) = &mut self.floor {
                floor.fence_retained_cold();
            }
        }
        if let Some(floor) = self.floor.take() {
            self.owner.floor = floor;
        }
        self.complete = true;
        result
    }
}

impl Drop for BrokerFloorOperationV1<'_> {
    fn drop(&mut self) {
        if !self.complete {
            if let Some(mut floor) = self.floor.take() {
                if floor.has_resident_cold_attempt() {
                    floor.fence_retained_cold();
                    self.owner.floor = floor;
                }
                // Unselected ordinary unwind keeps the original consuming
                // inverse: the moved local drops and the sentinel remains.
            }
        }
    }
}

#[cfg(test)]
mod main_open_projection_tests {
    use super::*;

    #[test]
    fn static_endpoint_labels_and_floor_projection_preserve_old_errors() {
        for error in [
            BrokerSessionSecurityError::Currentness,
            BrokerSessionSecurityError::ExecutionChanged,
            BrokerSessionSecurityError::Manifest { field: "protocol" },
        ] {
            let failure = BrokerMainOpenFailureV1::Endpoint(error.clone());
            assert_eq!(failure.projection(), error);
        }

        let failure = BrokerMainOpenFailureV1::Floor(tpm_floor::FloorErrorV1::Provisioning);
        assert_eq!(failure.projection(), BrokerSessionSecurityError::Currentness);
        assert!(matches!(failure, BrokerMainOpenFailureV1::Floor(tpm_floor::FloorErrorV1::Provisioning)));
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
    /// Uses the Storage-side Host client custody root.
    StorageHostClient,
    /// Uses the Host-service broker custody root dedicated to Storage.
    StorageHostBroker,
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
    /// Uses separate FUSE-3 client history with the existing Mount role keys.
    ControllerMountFuseClient,
    /// Uses separate FUSE-3 broker history on the existing Mount socket.
    MountFuseBroker,
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

impl FixedEndpointCustodyV1 {
    pub(crate) fn retained_revalidation_failure_for(
        &self,
        returned: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(endpoint) => endpoint.retained_revalidation_failure_for(returned),
            Self::Broker(endpoint) => endpoint.retained_revalidation_failure_for(returned),
        }
    }
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
    audience: aos_sandbox_api::aos::sandbox::local::v1::Audience,
    socket_path: &'static str,
    custody: FixedEndpointCustodyV1,
}

impl core::fmt::Debug for ProtectedBrokerSessionFixedCustodyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedBrokerSessionFixedCustodyV1([redacted])")
    }
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    /// Selects only the two genuine fixed Client roots used by Output.
    pub(crate) fn require_output_client_endpoint(&self) -> Result<(), BrokerSessionSecurityError> {
        for endpoint in [
            ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            ProtectedBrokerSessionFixedEndpointV1::StorageHostClient,
        ] {
            let fixed = fixed_endpoint(endpoint);
            if matches!(&self.custody, FixedEndpointCustodyV1::Client(_))
                && self.journal_root == fixed.journal_root
                && self.protocol == fixed.protocol
                && self.audience == fixed.audience
                && self.socket_path == fixed.socket_path
            {
                return Ok(());
            }
        }
        Err(BrokerSessionSecurityError::Currentness)
    }

    /// Carries only the actual startup observation into its exact Storage role.
    ///
    /// # Errors
    /// Rejects a non-Storage endpoint or a launch observation that does not match its exact fixed role.
    pub fn retain_launch_image(
        mut self,
        image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        self.attach_launch_image_retaining_v1(image)?;
        Ok(self)
    }

    // Selected callers keep their actual acquired endpoint in its reservoir
    // while this SAME existing comparison/attachment may refuse.
    pub(crate) fn attach_launch_image_retaining_v1(
        &mut self,
        image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if let Some(image) = image {
            let endpoint = match (&self.custody, self.protocol) {
                (FixedEndpointCustodyV1::Client(_), BrokerSessionProtocolV1::Storage) => {
                    ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
                }
                (FixedEndpointCustodyV1::Broker(_), BrokerSessionProtocolV1::Storage) => {
                    ProtectedBrokerSessionFixedEndpointV1::StorageBroker
                }
                _ => return Err(BrokerSessionSecurityError::Currentness),
            };
            image.require_endpoint(endpoint)?;
            match &mut self.custody {
                FixedEndpointCustodyV1::Client(custody) => custody.retain_launch_image(image),
                FixedEndpointCustodyV1::Broker(custody) => custody.retain_launch_image(image),
            }
        }
        Ok(())
    }

    /// Loads only the fixed broker while its actual lower partial stays owned.
    pub(crate) fn open_storage_broker_retaining_v1(
        opening: &mut crate::endpoint::ProtectedBrokerSessionBrokerOpeningV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let configuration = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        opening.load_once(Path::new(configuration.custody_root));
        opening.arm_original_once(receiving)?;
        let custody = opening.take_completed().ok_or_else(|| opening.classified_failure()
            .unwrap_or(BrokerSessionSecurityError::Currentness))?;
        Ok(Self {
            journal_root: configuration.journal_root,
            protocol: configuration.protocol,
            audience: configuration.audience,
            socket_path: configuration.socket_path,
            custody: FixedEndpointCustodyV1::Broker(custody),
        })
    }

    pub(crate) fn retained_revalidation_failure_for(
        &self,
        returned: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.custody.retained_revalidation_failure_for(returned)
    }

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
        let mut custody = match configuration.role {
            FixedEndpointRole::Client => FixedEndpointCustodyV1::Client(
                ProtectedBrokerSessionClientV1::load(Path::new(configuration.custody_root))?,
            ),
            FixedEndpointRole::Broker => FixedEndpointCustodyV1::Broker(
                ProtectedBrokerSessionBrokerV1::load(Path::new(configuration.custody_root))?,
            ),
        };
        if configuration.protocol == BrokerSessionProtocolV1::MountFuse {
            // A native-2 manifest must never be reinterpreted as FUSE-3, even
            // when both contexts intentionally reuse the same role keys.
            match &mut custody {
                FixedEndpointCustodyV1::Client(endpoint) => endpoint.require_fuse_context()?,
                FixedEndpointCustodyV1::Broker(endpoint) => endpoint.require_fuse_context()?,
            }
        }
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

    pub(crate) const fn production_audience(&self) -> aos_sandbox_api::aos::sandbox::local::v1::Audience {
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
        aos_sandbox_api::aos::sandbox::local::v1::Audience,
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
    /// Identifies the actual opened Client endpoint, not a caller nomination.
    pub(crate) fn is_output_client_endpoint(&self) -> bool {
        self.journal.endpoint.role() == BrokerSessionDurableEndpointV1::Client
            && [
                ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
                ProtectedBrokerSessionFixedEndpointV1::StorageHostClient,
            ].into_iter().any(|endpoint| {
                self.journal.directory == Path::new(fixed_endpoint(endpoint).journal_root)
            })
    }

    pub(crate) fn require_fixed_service_server_v4(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.fixed_service_server_recipe_v4(transcript)?;
        self.revalidate_transport(transcript, peer)
    }

    pub(crate) fn fixed_service_request_demand_v4(
        &self,
        extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        fixed_service_request_demand_v4(extent)
    }

    pub(crate) fn fixed_service_receiving_extent_v4(
        &self,
        metadata: &mut Option<std::io::Result<std::fs::Metadata>>,
    ) -> Result<aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1, FixedServiceReceivingExtentErrorV4> {
        self.journal.journal.as_ref().ok_or(FixedServiceReceivingExtentErrorV4::Security(
            BrokerSessionSecurityError::Currentness))?
            .held_session_receiving_extent_v1(metadata).map_err(FixedServiceReceivingExtentErrorV4::Journal)
    }

    pub(crate) fn require_original_storage_output_server(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_storage_server_engine_v2(transcript, peer, None)
    }

    pub(crate) fn require_storage_prepare_server_v2(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_storage_server_engine_v2(transcript, peer, Some(receiving))
    }

    pub(crate) fn require_storage_lifecycle_server_v2(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_storage_server_engine_v2(transcript, peer, Some(receiving))
    }

    pub(crate) fn require_storage_server_receiving_v3(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_storage_server_engine_v2(transcript, peer, receiving)
    }

    fn require_storage_server_engine_v2(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        if self.journal.directory != Path::new(fixed.journal_root)
            || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || transcript.protocol() != BrokerSessionProtocolV1::Storage
            || transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport_engine_v2(transcript, peer, receiving)
    }

    pub(crate) fn require_original_capture_candidate_client(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if self.journal.directory != Path::new(fixed.journal_root)
            || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || transcript.protocol() != BrokerSessionProtocolV1::Storage
            || transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || !transcript.negotiated_methods().contains(
                &BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE,
            )
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, peer)
    }

    pub(crate) fn compare_original_capture_candidate_outcome(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.compare_original_capture_candidate_outcome(owner, peer)
    }

    pub(crate) fn compare_storage_output_server_terminal_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.compare_storage_output_server_terminal_v1(owner, peer)
    }

    pub(crate) fn compare_atomic_snapshot_predecessor_v3(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.compare_atomic_snapshot_predecessor_v3(owner, peer)
    }

    pub(crate) fn compare_atomic_snapshot_predecessor_retaining_v1(
        &mut self,
        owner: &super::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_inventory_once(&mut self.journal, owner, connection_peer)
    }


    pub(crate) fn compare_host_storage_output_outcome_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.compare_host_storage_output_outcome_v1(owner, peer)
    }

    pub(crate) fn compare_original_storage_output_outcome_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.compare_original_storage_output_outcome_v1(owner, peer)
    }

    /// Stages common signed-plan admission before the first ONLINE mutation.
    #[cfg(feature = "online-nix")]
    pub(crate) fn retain_online_resolve_admission(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        checked: &aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2,
        sample: &aos_sandbox_model::RawPairedClockSample,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let schema = self.journal.online_schema.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if schema.prepared.is_some() || schema.native_transaction.is_some()
            || schema.first_failure.is_some() || schema.clock_failure.is_some()
            || schema.phase_failed || request.method() != schema.next_method
            || schema.original_deadline.is_some_and(|original|
                request.deadline_boottime_nanoseconds() != original)
            || online_nix_verb(request.method()).is_none()
            || checked.method() != request.method()
            || *checked.header().request_id() != request.request_id()
            || checked.commitment() != request.semantic_commitment()
            || checked.wire().domain_digest.as_slice() != schema.profile.domain_commitment()
            || checked.wire().disclosure_digest.as_slice() != schema.profile.disclosure()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // Occupy the one-shot slot before signature verification. A partial
        // result or interrupted preparation cannot be replaced and retried.
        schema.original_deadline.get_or_insert(request.deadline_boottime_nanoseconds());
        schema.prepared = Some(OnlinePreparedAuthorizationV1 {
            request_id: request.request_id(), admission: None, fence: None, effect: None,
        });
        let artifacts = request.authorization().ok_or(BrokerSessionSecurityError::Currentness)?;
        let fence = checked.fence();
        let assignment = fence.broker_assignment()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let target = aos_sandbox_model::BrokerResourceHandle::from_bytes(schema.profile.domain_commitment())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let commitment = aos_sandbox_model::BrokerArgumentCommitment::from_digest(
            aos_sandbox_model::ObjectDigest::from_bytes(checked.commitment()),
        ).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let key = aos_sandbox_broker::BrokerAuthority::online_nix_fence_key(assignment.sandbox().as_bytes());
        let prior = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?
            .get(RecordNamespace::BrokerSessionTraffic, &key);
        let result = schema.authority.admit(
            artifacts,
            aos_sandbox_broker::AdmissionRequest {
                audience: aos_sandbox_model::BrokerAudience::Nix,
                protocol: aos_sandbox_model::ProtocolId::NixBuildBroker,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment,
                request_id: request.request_id(),
                request_body: request.exact_body(),
                descriptor_count: 0,
                verb: online_nix_verb(request.method()).ok_or(BrokerSessionSecurityError::Currentness)?,
                target: aos_sandbox_model::BrokerGrantTarget::Resource(target),
                argument_commitment: commitment,
                request_deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds(),
            },
            sample,
            prior,
        );
        let prepared = schema.prepared.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        match result {
            Ok(admission) => prepared.admission = Some(admission),
            Err(cause) => {
                schema.first_failure.get_or_insert(cause);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        let admission = prepared.admission.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let result = schema.authority.seal_online_nix_fence(
            assignment.sandbox().as_bytes(), &admission.fence,
        );
        match result {
            Ok(bytes) => prepared.fence = Some(bytes),
            Err(cause) => {
                schema.first_failure.get_or_insert(cause);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        let result = schema.authority.seal_online_nix_effect(&request.request_id(), &admission.effect);
        match result {
            Ok(bytes) => prepared.effect = Some(bytes),
            Err(cause) => {
                schema.first_failure.get_or_insert(cause);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        self.revalidate_transport(transcript, connection_peer)
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn check_online_resolve_effect(
        &mut self,
        request_id: [u8; 16],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let schema = self.journal.online_schema.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if schema.first_failure.is_some() || schema.clock_failure.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let prepared = schema.prepared.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let admission = prepared.admission.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        if prepared.request_id != request_id || prepared.fence.is_none() || prepared.effect.is_none() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let effect_key = aos_sandbox_broker::BrokerAuthority::online_nix_effect_key(&request_id);
        let journal = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let effect_bytes = journal.get(RecordNamespace::BrokerSessionTraffic, &effect_key)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let effect = match schema.authority.open_online_nix_effect(&request_id, effect_bytes) {
            Ok(effect) => effect,
            Err(cause) => {
                schema.first_failure.get_or_insert(cause);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        if effect.plan_digest() != admission.effect.plan_digest()
            || effect.lease_digest() != admission.effect.lease_digest()
            || effect.local_lease_record() != admission.effect.local_lease_record()
            || effect.effect_deadline_boottime_nanoseconds()
                != admission.effect.effect_deadline_boottime_nanoseconds()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        require_online_effect_fields(schema, &effect)?;
        let history_key = protocol_key(BrokerSessionProtocolV1::Nix);
        let history = StoredProtocolHistoryV1::decode(
            &history_key,
            journal.get(RecordNamespace::BrokerSessionTraffic, &history_key)
                .ok_or(BrokerSessionSecurityError::Currentness)?,
        )?.history_model()?;
        let head = history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if head.request_id() != request_id {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        require_online_history_effect(schema, head, &effect)?;

        // The physical/floor observations may be slow. The paired clock below
        // is sampled only after their final bookend, never supplied by a caller.
        self.revalidate_transport(transcript, connection_peer)?;
        self.check_online_admitted_clock()
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn check_online_admitted_clock(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.journal.check_online_admitted_clock()
    }

    /// Independently compares available originals without entering a floor effect.
    #[cfg(feature = "online-nix")]
    pub(crate) fn observe_online_postflight(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        report: &mut crate::handshake::OnlinePostflightV1,
    ) {
        report.endpoint_before = Some(self.journal.endpoint.revalidate());
        let process_execution_id = match self.journal.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => transcript.broker_process(),
            BrokerSessionDurableEndpointV1::Broker => transcript.client_process(),
        };
        report.peer = Some(ObservedBrokerPeerExecutionV1::from_connection(
            connection_peer, process_execution_id,
        ).map(|_| ()));
        report.endpoint_after = Some(self.journal.endpoint.revalidate());
        report.named = Some(match self.journal.journal.as_ref() {
            Some(journal) => self.journal.owner.validate_held(
                journal, &self.journal.directory, &self.journal.name,
            ),
            None => Err(aos_sandbox_controller_domain::JournalError::ProtectedBoundary),
        });

        let mut operation = BrokerFloorOperationV1::begin(&mut self.journal);
        let result = match operation.floor.as_mut() {
            Some(floor) => floor.observe_online_postflight(operation.owner),
            None => Err(tpm_floor::FloorErrorV1::Unavailable),
        };
        // Restore the SAME floor without clearing its existing failed state.
        // finish's normal failure fencing remains unchanged and is not used
        // to manufacture a fresh current-floor observation here.
        report.floor = Some(result);
        if let Some(floor) = operation.floor.take() {
            operation.owner.floor = floor;
        }
        operation.complete = true;
    }

    /// Samples even a poisoned schema, then checks only the original effect/D.
    #[cfg(feature = "online-nix")]
    pub(crate) fn observe_online_postflight_clock(
        &mut self,
    ) -> Result<(), crate::handshake::OnlinePostflightClockErrorV1> {
        use crate::handshake::OnlinePostflightClockErrorV1;

        let sample = aos_sandbox_broker::ownership_clock::sample_ownership_clock()?;
        let schema = self.journal.online_schema.as_ref()
            .ok_or(OnlinePostflightClockErrorV1::Unavailable)?;
        let prepared = schema.prepared.as_ref().or_else(|| {
            schema.completed_preparations.iter().rev().find_map(Option::as_ref)
        }).ok_or(OnlinePostflightClockErrorV1::Unavailable)?;
        let admission = prepared.admission.as_ref()
            .ok_or(OnlinePostflightClockErrorV1::Unavailable)?;
        schema.authority.validate_effect_clock(&admission.effect, &sample)?;
        if schema.first_failure.is_some() || schema.clock_failure.is_some() {
            return Err(OnlinePostflightClockErrorV1::Unavailable);
        }
        Ok(())
    }

    /// Reacquires remaining suffix sizing at the actual pending Realize cut.
    #[cfg(feature = "online-nix")]
    pub(crate) fn require_online_existing_output_suffix(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        if request.method() != BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.check_online_resolve_effect(request.request_id(), transcript, connection_peer)?;

        // The whole owner is unavailable from BEFORE geometry through the last
        // original clock observation. Its Drop restores only the same fence.
        let mut operation = BrokerFloorOperationV1::begin(&mut self.journal);
        let result = (|| {
            operation.check_cold_deadline()?;
            operation.owner.endpoint.revalidate()?;
            operation.owner.validate_schema_only()?;
            let schema = operation.owner.online_schema.as_ref()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let prepared = schema.prepared.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            let admission = prepared.admission.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            if schema.phase_failed || schema.first_failure.is_some() || schema.clock_failure.is_some()
                || schema.next_method != request.method()
                || prepared.request_id != request.request_id()
                || schema.native_transaction.is_some()
                || schema.original_deadline != Some(request.deadline_boottime_nanoseconds())
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let traffic_key = protocol_key(BrokerSessionProtocolV1::Nix);
            let fence_key = aos_sandbox_broker::BrokerAuthority::online_nix_fence_key(
                admission.fence.assignment().sandbox().as_bytes(),
            );
            let effect_key = aos_sandbox_broker::BrokerAuthority::online_nix_effect_key(&prepared.request_id);
            let old = schema.completed_preparations[0].as_ref()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let completed_key = aos_sandbox_broker::BrokerAuthority::online_nix_effect_key(&old.request_id);
            let journal = operation.owner.journal.as_ref()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let stored = StoredProtocolHistoryV1::decode(
                &traffic_key, journal.get(RecordNamespace::BrokerSessionTraffic, &traffic_key)
                    .ok_or(BrokerSessionSecurityError::Currentness)?,
            )?;
            let history = stored.history_model()?;
            let head = history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
                || head.request_packet() != request.canonical_packet()
                || head.method() != request.method() || head.request_id() != request.request_id()
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            // These widths come from actual canonical retained rows, not from
            // fabricated future signatures, effects, or transaction IDs.
            let fence_bytes = prepared.fence.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.len();
            let pending_bytes = prepared.effect.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.len();
            let complete_bytes = journal.get(RecordNamespace::BrokerSessionTraffic, &completed_key)
                .ok_or(BrokerSessionSecurityError::Currentness)?.len();
            let compared = journal.compare_online_nix_main_suffix_capacity_v1(
                &traffic_key, &fence_key, &effect_key, fence_bytes, pending_bytes, complete_bytes,
            );
            let widths = operation.retain_native_result(compared)?;
            operation.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
                .check_online_existing_output_suffix(operation.owner, widths)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            operation.owner.endpoint.revalidate()?;
            operation.owner.check_online_admitted_clock()?;
            operation.check_cold_deadline()
        })();
        operation.finish(result)
    }

    /// Releases only a completed native preparation after caller bookends.
    #[cfg(feature = "online-nix")]
    pub(crate) fn release_online_native_step(&mut self) {
        if let Some(schema) = self.journal.online_schema.as_mut() {
            schema.native_transaction = None;
        }
    }

    /// Advances only the same Session's authentic successful native terminal.
    ///
    /// The two fixed slots retain prior admissions and original sealed bytes.
    /// A failure before the infallible move permanently closes phase admission;
    /// it does not clear a pending request or authorize a new deadline/retry.
    #[cfg(feature = "online-nix")]
    pub(crate) fn advance_online_nix_terminal(
        &mut self,
        previous: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let (index, next) = match previous.method() {
            BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 =>
                (0, BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2),
            BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 =>
                (1, BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2),
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let schema = self.journal.online_schema.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if schema.phase_failed || schema.next_method != previous.method()
            || schema.native_transaction.is_some()
            || schema.completed_preparations[index].is_some()
            || schema.completed_preparations[..index].iter().any(Option::is_none)
            || schema.original_deadline != Some(previous.deadline_boottime_nanoseconds())
            || schema.prepared.as_ref().is_none_or(|prepared|
                prepared.request_id != previous.request_id())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        schema.phase_failed = true;

        self.check_online_resolve_effect(previous.request_id(), transcript, connection_peer)?;
        let retained = self.journal.read_optional(BrokerSessionProtocolV1::Nix)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = retained.history_model()?;
        let head = history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.method() != previous.method()
            || head.request_id() != previous.request_id()
            || head.request_packet() != previous.canonical_packet()
            || head.request_semantic_binding() != previous.semantic_commitment()
            || !successful_terminal(head)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)?;
        self.check_online_admitted_clock()?;

        // No fallible work follows the move. The actual fixed destination was
        // checked while every old admission and sealed byte remained resident.
        let schema = self.journal.online_schema.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        schema.completed_preparations[index] = schema.prepared.take();
        schema.next_method = next;
        schema.phase_failed = false;
        Ok(())
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn online_admission_failure(&self) -> Option<&aos_sandbox_broker::BrokerAdmissionError> {
        self.journal.online_schema.as_ref().and_then(|schema| schema.first_failure.as_ref())
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn online_clock_failure(
        &self,
    ) -> Option<&aos_sandbox_model::OwnershipClockObservationError> {
        self.journal.online_schema.as_ref().and_then(|schema| schema.clock_failure.as_ref())
    }

    /// Selects receive direction from this genuine fixed online endpoint.
    #[cfg(feature = "online-nix")]
    pub(crate) fn online_endpoint_role(
        &self,
    ) -> Result<BrokerSessionDurableEndpointV1, BrokerSessionSecurityError> {
        if self.journal.online_schema.is_none()
            || self.journal.endpoint.protected_protocol_and_node().0
                != BrokerSessionProtocolV1::Nix
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        Ok(self.journal.endpoint.role())
    }

    #[cfg(feature = "online-nix")]
    pub(crate) fn bind_online_request_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.floor.bind_online_request_deadline(deadline)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    /// Removes temporary comparison DATA from the same fully checked owner.
    ///
    /// # Errors
    /// Retains/fences the owner on an unfinished, changed or expired cold cut.
    pub(crate) fn retire_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.floor.retire_cold_deadline(deadline)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn storage_prepare_cold_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.journal.floor.ordinary_cold_failure()
    }

    /// Retains pending Host49 custody without enabling ordinary client captures.
    pub(crate) fn hold_host_worker_comparison<'owner>(
        &'owner mut self,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        connection_peer: &'owner ConnectionPeerIdentity,
    ) -> Result<ProtectedPendingBrokerRequestCutV1<'owner>, BrokerSessionSecurityError> {
        ProtectedPendingBrokerRequestCutV1::capture_host_worker_comparison(
            &mut self.journal,
            request,
            transcript,
            connection_peer,
        )
    }

    pub(crate) fn hold_fuse_intent_request<'owner>(
        &'owner mut self,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        connection_peer: &'owner ConnectionPeerIdentity,
    ) -> Result<ProtectedPendingBrokerRequestCutV1<'owner>, BrokerSessionSecurityError> {
        ProtectedPendingBrokerRequestCutV1::capture_fuse_intent(
            &mut self.journal,
            request,
            transcript,
            connection_peer,
        )
    }

    pub(crate) fn hold_output_registration_request<'owner>(
        &'owner mut self,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        connection_peer: &'owner ConnectionPeerIdentity,
    ) -> Result<ProtectedPendingBrokerRequestCutV1<'owner>, BrokerSessionSecurityError> {
        ProtectedPendingBrokerRequestCutV1::capture_output_registration(
            &mut self.journal, request, transcript, connection_peer,
        )
    }

    pub(crate) fn hold_capture_candidate_client_request<'owner>(
        &'owner mut self,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        peer: &'owner ConnectionPeerIdentity,
    ) -> Result<ProtectedPendingBrokerRequestCutV1<'owner>, BrokerSessionSecurityError> {
        ProtectedPendingBrokerRequestCutV1::capture_execution_capture_candidate(
            &mut self.journal, request, transcript, peer,
        )
    }

    pub(crate) fn hold_storage_output_host_readback<'owner>(
        &'owner mut self,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        connection_peer: &'owner ConnectionPeerIdentity,
    ) -> Result<ProtectedPendingBrokerRequestCutV1<'owner>, BrokerSessionSecurityError> {
        ProtectedPendingBrokerRequestCutV1::capture_storage_output_host_readback(
            &mut self.journal, request, transcript, connection_peer,
        )
    }

    /// Borrows the actual broker writer while an exact admitted request is pending.
    ///
    /// This is transport/history custody, not signed-plan or consumer authority.
    /// No terminal handoff can substitute for the current pending request.
    pub(crate) fn hold_pending_request<'owner>(
        &'owner mut self,
        request: &'owner AuthenticatedBrokerMethodRequestV1,
        transcript: &'owner VerifiedBrokerSessionTranscriptV1,
        connection_peer: &'owner ConnectionPeerIdentity,
    ) -> Result<ProtectedPendingBrokerRequestCutV1<'owner>, BrokerSessionSecurityError> {
        ProtectedPendingBrokerRequestCutV1::capture(
            &mut self.journal,
            request,
            transcript,
            connection_peer,
        )
    }

    /// Confirms exact protected archive custody before a method-37 socket send.
    pub(crate) fn confirm_original_host_argument_archive(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let current = self
            .journal
            .read_optional(BrokerSessionProtocolV1::Host)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let history = current.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if transcript.protocol() != BrokerSessionProtocolV1::Host
            || !original_host_argument_method_v2(request.method())
            || current.endpoint_publication
                != self
                    .journal
                    .endpoint_publication(BrokerSessionProtocolV1::Host)?
            || head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || head.request_id() != request.request_id()
            || head.request_packet() != request.canonical_packet()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)
    }

    /// Reauthenticates one protected original method-37 request after rollover.
    ///
    /// A missing archive is indeterminate, never evidence that no socket send
    /// occurred. The caller supplies the separately protected Controller source
    /// and must recheck that source after this historical readback. This
    /// read-only bridge does not establish a cross-owner rollback floor.
    pub(crate) fn authenticated_original_host_argument_archive(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<AuthenticatedOriginalHostArgumentArchiveV1, BrokerSessionSecurityError> {
        let before = self.journal.read_current(BrokerSessionProtocolV1::Host)?;
        let stored = self
            .journal
            .read_host_argument_archive(source.request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let history = stored.history_model()?;
        let request_index = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (request, _) =
            historical_client_request(history.records(), request_index, checkpoint, &transcript)?;
        let body_source = original_host_argument_source_v2(request.method(), request.exact_body())?;
        if !original_host_argument_method_v2(request.method())
            || request.request_id() != source.request_id()
            || body_source != *source
            || self.journal.read_current(BrokerSessionProtocolV1::Host)? != before
            || self
                .journal
                .read_host_argument_archive(source.request_id())?
                .as_ref()
                != Some(&stored)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(AuthenticatedOriginalHostArgumentArchiveV1 {
            source: source.clone(),
            request,
            archive_head: stored.current_head,
        })
    }

    /// Reauthenticates a retained signed method-39 terminal after rollover.
    ///
    /// This returns only historical identity evidence joined to the original
    /// method-37 H archive. It cannot prove that Host still holds the marker
    /// or authorize Controller FAILED settlement.
    pub(crate) fn historical_host_terminal_no_apply_archive(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<AuthenticatedOriginalHostNoApplyJoinV1, BrokerSessionSecurityError> {
        let before = self.journal.read_current(BrokerSessionProtocolV1::Host)?;
        let joined = self
            .journal
            .read_host_terminal_archive(source.request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if joined.original().source().canonical_bytes() != source.canonical_bytes() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let after = self
            .journal
            .read_host_terminal_archive(source.request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if self.journal.read_current(BrokerSessionProtocolV1::Host)? != before
            || joined.original().archive_head() != after.original().archive_head()
            || joined.no_apply_record() != after.no_apply_record()
            || joined.no_apply_outcome().canonical_packet()
                != after.no_apply_outcome().canonical_packet()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(joined)
    }

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
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
        self.prepare_broker_outcome_with_storage_receiving_v3(request, message, transcript, connection_peer, None)
    }

    pub(crate) fn prepare_broker_outcome_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError> {
        let descriptor_count = message.descriptors.len();
        let packet = self
            .journal
            .sign_broker_outcome_with_storage_receiving_v3(request, message, transcript, receiving.as_mut()
                .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        let outcome = aos_sandbox_broker_session_protocol::decode_canonical_response_v1(&packet)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let gate = self
            .journal
            .reopen_broker_outcome_with_storage_receiving_v3(request, transcript, connection_peer, receiving)?;
        match gate.admit_outcome_with_descriptor_count(&outcome, descriptor_count)? {
            super::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => Ok(advancement),
            super::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    pub(crate) fn prepare_original_nonadmitting_outcome(
        &mut self,
        retained: &mut RetainedOriginalBrokerOutcomeV1,
        purpose: crate::endpoint::OriginalBrokerOutcomePurposeV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> bool {
        if retained.setup.is_some() || retained.gate.is_some() || retained.signed
            || retained.endpoint.message.is_some()
        {
            return false;
        }
        retained.endpoint.message = Some(message);
        retained.gate = Some(self.journal.reopen_broker_outcome(request, transcript, connection_peer));
        retained.setup = Some((|| {
            let gate = match retained.gate.as_ref() {
                Some(Ok(gate)) => gate,
                _ => return Err(BrokerSessionSecurityError::Currentness),
            };
            if !gate.traffic.has_outstanding_request()
                || request.method() != purpose.method()
                || request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let endpoint = match &mut self.journal.endpoint {
                ProtectedEndpointV1::Broker(endpoint) => endpoint,
                ProtectedEndpointV1::Client(_) => return Err(BrokerSessionSecurityError::Currentness),
            };
            if !endpoint.prepare_original_outcome(
                &mut retained.endpoint, request.method(), transcript.session_binding(),
                transcript.broker_process(), gate.traffic.next_broker_sequence(),
                request.request_id(), request.signed_request_digest(), request.maximum_response_bytes(),
            ) {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })());
        retained.failure().is_none()
    }

    pub(crate) fn sign_original_nonadmitting_outcome(
        &mut self,
        retained: &mut RetainedOriginalBrokerOutcomeV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> bool {
        if retained.signed || retained.failure().is_some() || !matches!(retained.setup, Some(Ok(()))) {
            return false;
        }
        retained.signed = true;
        let endpoint = match &mut self.journal.endpoint {
            ProtectedEndpointV1::Broker(endpoint) => endpoint,
            ProtectedEndpointV1::Client(_) => return false,
        };
        if !endpoint.sign_original_outcome(&mut retained.endpoint) {
            return false;
        }
        // The signed packet remains in endpoint custody before all decoder and
        // protected admission crossings. The ordinary gate/parser is reused.
        retained.admission = Some((|| {
            let packet = retained.endpoint.packet().ok_or(BrokerSessionSecurityError::Currentness)?;
            let outcome = decode_canonical_response_v1(packet)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let gate = self.journal.reopen_broker_outcome(request, transcript, connection_peer)?;
            match gate.admit_outcome_with_descriptor_count(&outcome, 0)? {
                super::ProtectedBrokerOutcomeAdmissionV1::New { advancement } => Ok(advancement),
                super::ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                    Err(BrokerSessionSecurityError::Currentness)
                }
            }
        })());
        retained.failure().is_none() && matches!(retained.admission, Some(Ok(_)))
    }

    pub(crate) fn revalidate_transport(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport_engine_v2(transcript, connection_peer, None)
    }

    pub(crate) fn revalidate_storage_lifecycle_transport_v2(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport_engine_v2(transcript, connection_peer, Some(receiving))
    }

    fn revalidate_transport_engine_v2(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.journal.current_context_with_storage_receiving_v2(transcript, None,
            receiving.as_mut().map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?
            .into_ordinary();
        let peer = self.journal.observe_peer_with_storage_receiving_v3(transcript, connection_peer, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        peer.binding(self.journal.endpoint.role(), transcript, &context)?;
        self.journal.endpoint.revalidate()?;
        self.journal.require_floor_current_with_storage_receiving_v2(receiving)
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
            aos_sandbox_api::aos::sandbox::local::v1::Audience,
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
            aos_sandbox_api::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        self.journal
            .client_request_limits(transcript, now_boottime_nanoseconds)
    }

    pub(crate) fn prepare_client_request(
        &mut self,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
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

    pub(crate) fn admit_storage_prepare_replay_received_request_v1(
        &mut self,
        packet: &[u8],
        descriptor_count: usize,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        self.journal.admit_received_request_with_storage_receiving_v1(
            packet, descriptor_count, transcript, connection_peer,
            now_boottime_nanoseconds, Some(receiving), Some(terminal), None,
        )
    }

    pub(crate) fn admit_retained_storage_request_v1(
        &mut self,
        packet: &[u8],
        transcript: &VerifiedBrokerSessionTranscriptV1,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        now_boottime_nanoseconds: u64,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        request_bound: aos_sandbox_model::ResourceVector,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        self.journal.admit_received_request_with_storage_receiving_v1(
            packet, 0, transcript, socket.peer(), now_boottime_nanoseconds,
            None, None, Some((receiving, socket, request_bound)),
        )
    }

    pub(crate) fn admit_storage_prepare_received_request_v1(
        &mut self,
        packet: &[u8],
        descriptor_count: usize,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        self.journal.admit_received_request_with_storage_receiving_v1(
            packet, descriptor_count, transcript, connection_peer,
            now_boottime_nanoseconds, Some(receiving), None, None,
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

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    /// Borrows the genuine Controller Storage Inventory terminal and its owner.
    ///
    /// This projection creates no Host execution authority and does not replace
    /// the same live Session's exact Inventory predecessor comparison.
    ///
    /// # Errors
    /// Refuses another direction, method, protocol, audience or signed profile.
    pub fn storage_inventory_client_originals_v1(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError>
    {
        self.storage_preparation_client_originals_engine_v1(BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES, false)
    }

    /// Borrows the genuine same-profile Controller Prepare terminal and owner.
    ///
    /// This historical projection creates no Apply or Create completion grant.
    ///
    /// # Errors
    /// Refuses another direction, method, protocol, audience or signed profile.
    #[doc(hidden)]
    pub fn storage_prepare_client_originals_v1(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.storage_preparation_client_originals_engine_v1(BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG, false)
    }

    pub(crate) fn storage_provisioning_client_originals_v1(&self, inventory: bool)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let method = if inventory { BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES }
            else { BrokerMethod::BROKER_METHOD_STORAGE_APPLY };
        self.storage_preparation_client_originals_engine_v1(method, true)
    }

    fn storage_preparation_client_originals_engine_v1(&self, method: BrokerMethod, provisioning: bool)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.provisioning_client_originals_engine_v4(method, provisioning, false)
    }

    pub(crate) fn start_resource_provisioning_client_originals_v2(&self, inventory: bool)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let method = match (self.currentness_owner.transcript.protocol(), inventory) {
            (BrokerSessionProtocolV1::Network, false) => BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2,
            (BrokerSessionProtocolV1::Network, true) => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            (BrokerSessionProtocolV1::Storage, false) => BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT,
            (BrokerSessionProtocolV1::Storage, true) => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            (BrokerSessionProtocolV1::Mount, false) => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            (BrokerSessionProtocolV1::Mount, true) => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            (BrokerSessionProtocolV1::Host, false) => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            (BrokerSessionProtocolV1::Host, true) => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        self.provisioning_client_originals_engine_v4(method, true, true)
    }

    pub(crate) fn start_host_catalog_client_originals_v2(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        if !aos_sandbox_broker_session_protocol::profile::is_start_host_catalog_launch_transcript_v2(
            &self.currentness_owner.transcript) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.provisioning_client_originals_engine_v4(BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG, true, true)
    }

    fn provisioning_client_originals_engine_v4(&self, method: BrokerMethod, provisioning: bool, network: bool)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.provisioning_client_originals_selected_v4(method, provisioning, network, false)
    }

    pub(crate) fn catalog_maintenance_client_originals_v2(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.provisioning_client_originals_selected_v4(BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG, false, false, true)
    }

    fn provisioning_client_originals_selected_v4(&self, method: BrokerMethod, provisioning: bool, network: bool, maintenance: bool)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let owner = &self.currentness_owner;
        if owner.request.method() != method
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.method() != owner.request.method()
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || (!network && !maintenance && owner.transcript.protocol() != BrokerSessionProtocolV1::Storage)
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || !(if maintenance {
                owner.transcript.protocol() == BrokerSessionProtocolV1::Host
                    && owner.transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG)
            } else if network {
                aos_sandbox_broker_session_protocol::profile::is_start_resource_transcript_v2(&owner.transcript)
            } else if provisioning {
                aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&owner.transcript)
            } else { aos_sandbox_broker_session_protocol::profile::is_storage_preparation_transcript_v1(&owner.transcript) }) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((&owner.outcome, owner))
    }

    /// Borrows the actual completed Controller-client method-41 terminal.
    ///
    /// This projection does not replace the session's currentness comparison.
    ///
    /// # Errors
    /// Rejects a mismatched method, direction, Storage protocol, Controller
    /// audience, or negotiated method with a currentness error.
    pub fn capture_candidate_client_originals(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let owner = &self.currentness_owner;
        if owner.request.method() != BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.method() != owner.request.method()
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || !owner.transcript.negotiated_methods().contains(&owner.request.method())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((&owner.outcome, owner))
    }

    pub(crate) fn original_nonadmitting_request_context(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodRequestV1, &ProtectedBrokerSessionVerificationContextV1), BrokerSessionSecurityError> {
        if !matches!(self.method, BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS)
            || self.currentness_owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((&self.currentness_owner.request, &self.currentness_owner.context))
    }

    pub(crate) fn storage_output_server_originals_v1(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let owner = &self.currentness_owner;
        if !matches!(owner.request.method(),
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT)
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ServerSend
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((&owner.outcome, owner))
    }

    /// Borrows only the completed original Controller-client Storage46 result.
    ///
    /// This projection does not replace the session's currentness comparison.
    ///
    /// # Errors
    /// Rejects a mismatched method, direction, Storage protocol, or Controller
    /// audience with a currentness error.
    pub fn output_registration_originals_v1(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let owner = &self.currentness_owner;
        if owner.request.method() != BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((&owner.outcome, owner))
    }

    /// Borrows only a genuine committed Storage-client Host48 result and owner.
    /// This projection is not a currentness check; the actual Session performs it.
    pub(crate) fn host_storage_output_originals_v1(
        &self,
    ) -> Result<(
        &AuthenticatedBrokerMethodOutcomeV1,
        &ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ), BrokerSessionSecurityError> {
        let owner = &self.currentness_owner;
        if owner.request.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || owner.transcript.protocol() != BrokerSessionProtocolV1::Host
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_STORAGE_BROKER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok((&owner.outcome, owner))
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
    /// Prices the closed receiving cycle from this same retained journal opening.
    ///
    /// # Errors
    /// Refuses unavailable original geometry or unrepresentable demand.
    pub(crate) fn storage_prepare_request_demand_v1(
        &self,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.journal.storage_prepare_request_demand_v1()
    }

    pub(crate) fn retained_storage_request_demand_v1(
        &self,
        extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        storage_session_schema_demand::retained_request_demand(extent)
    }

    pub(crate) fn retained_storage_operation_demand_v1(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        storage_session_schema_demand::operation_flight_demand(transcript)
            .map_err(BrokerSessionSecurityError::from)
    }

    /// Prices upper growth from the actual retained domain response.
    ///
    /// # Errors
    /// Refuses unavailable original geometry/history or unrepresentable demand.
    pub(crate) fn storage_prepare_outcome_demand_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation: &crate::dormant_handshake::ProtectedBrokerDomainResponseV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.journal.storage_prepare_outcome_demand_v1(request, observation)
    }

    pub(crate) fn retained_storage_terminal_demand_v1(
        &self,
        extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
        terminal: &super::RetainedStorageTerminalV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        storage_session_schema_demand::replay_demand(
            extent, self.journal.storage_prepare_current_stored()?,
            terminal.canonical_request(), terminal.exact_packet(),
        ).map_err(Into::into)
    }

    pub(crate) fn retained_storage_replay_outcome_demand_v1(
        &self,
        extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
        replay: &super::ProtectedBrokerOutcomeReplayV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        storage_session_schema_demand::replay_demand(
            extent, self.journal.storage_prepare_current_stored()?,
            replay.request().canonical_packet(), replay.exact_packet(),
        ).map_err(Into::into)
    }

    pub(crate) fn retained_storage_outcome_demand_v1(
        &self,
        extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation: &crate::dormant_handshake::ProtectedBrokerDomainResponseV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        storage_session_schema_demand::outcome_demand(
            extent, self.journal.storage_prepare_current_stored()?,
            request.canonical_packet(), observation.body(),
        ).map_err(Into::into)
    }

    /// Prices replay from the original committed pair and actual stored history.
    ///
    /// # Errors
    /// Refuses unavailable original geometry/history or unrepresentable demand.
    pub(crate) fn storage_prepare_replay_demand_v1(
        &self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.journal.storage_prepare_replay_demand_v1(terminal)
    }

    /// Borrows the actual initial Session facade and returned Journal together.
    ///
    /// The cold caller has already completed its protected/floor/endpoint and
    /// original-cutoff posts. It keeps its actual HELLO controls resident until
    /// the genuine Native loan prepares their joint infallible disposition.
    pub(crate) fn storage_prepare_hello_cleanup_parts_v1(
        &mut self,
    ) -> Result<(
        &Journal,
        &mut aos_sandbox_controller_domain::journal::StorageBrokerCapturedJournalOpenV1,
        &mut Option<Result<(), BrokerSessionSecurityError>>,
    ), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        let owner = &mut self.journal;
        if owner.owner != JournalOwnerV1::RootBroker
            || owner.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Storage
            || owner.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || owner.directory != Path::new(fixed.journal_root)
            || owner.name != PROTECTED_SESSION_JOURNAL
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let journal = owner.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let staged = owner.storage_receiving_open.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        if staged.native_settlement.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // An unfinished preparation never rearms this actual facade.
        staged.native_settlement = Some(Err(BrokerSessionSecurityError::Currentness));
        Ok((journal, &mut staged.native, &mut staged.native_settlement))
    }

    pub(crate) fn finish_storage_initial_physical_program_v2(
        &mut self, receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let owner = &mut self.journal;
        let main = owner.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        owner.floor.finish_storage_initial_program_v2(main, receiving)
            .map_err(floor_revalidation::security_error)
    }

    pub(crate) fn observe_storage_initial_failure_post_v2(&mut self)
        -> Result<(), BrokerSessionSecurityError>
    {
        finish_storage_failure_post_v2(&mut self.journal)
    }

    pub(crate) fn storage_prepare_native_failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.journal.storage_receiving_open.as_ref().and_then(|original| original.failure())
            .or_else(|| self.journal.floor_main.failure())
            .or_else(|| self.journal.session_replays.failure())
            .or_else(|| self.journal.floor.storage_sidecar_failure_v2())
            .or_else(|| self.journal.floor.storage_physical_failure_v2())
    }

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

    pub(crate) fn initialize_storage_request_receiving_v2(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1, transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity, checkpoint: &HistoricalSessionCheckpointV1,
        receiving: &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2,
    ) -> Result<ProtectedBrokerSessionInitializationResultV1, BrokerSessionSecurityError> {
        self.journal.initialize_request_with_storage_receiving_v2(
            request, transcript, connection_peer, checkpoint, Some(receiving),
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

    pub(crate) fn reopen_broker_outcome_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<super::ProtectedBrokerOutcomeAdmissionGateV1, BrokerSessionSecurityError> {
        self.journal.reopen_broker_outcome_with_storage_receiving_v3(request, transcript, connection_peer, receiving)
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

    pub(crate) fn append_request_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerRequestCommitResultV1, BrokerSessionSecurityError> {
        self.journal.append_request_with_storage_receiving_v3(request, transcript, connection_peer, receiving)
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

    pub(crate) fn commit_outcome_with_storage_receiving_v3(&mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.journal.commit_outcome_with_storage_receiving_v3(pending, connection_peer, receiving)
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

    /// Loans execution terminal currentness without discarding failed custody.
    ///
    /// # Errors
    ///
    /// Returns the original owner with a failed fixed terminal validation.
    pub(crate) fn retain_execution_outcome_current_with_post_v1<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &'authority ConnectionPeerIdentity,
        original: &mut ExecutionClientPostOriginalV1,
        socket: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<ProtectedBrokerOutcomeCurrentV1<'authority>,
        (ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError)>
    {
        use std::os::fd::AsRawFd;

        // Closed Session custody still reaches the independently owed post.
        let socket = socket.map(|socket| socket.as_raw_fd()).unwrap_or(-1);
        self.journal.retain_execution_outcome_current_with_post_v1(owner, peer, original, socket)
    }

    pub(crate) fn retain_execution_outcome_current<'authority>(
        &'authority mut self,
        owner: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &'authority ConnectionPeerIdentity,
    ) -> Result<
        ProtectedBrokerOutcomeCurrentV1<'authority>,
        (ProtectedBrokerOutcomeCurrentnessOwnerV1, BrokerSessionSecurityError),
    > {
        self.journal
            .retain_execution_outcome_current(owner, connection_peer)
    }

    // Comparison borrows the original terminal owner so an error cannot drop
    // its signed packets or currentness before the selected caller parks it.
    pub(crate) fn compare_git_coverage_outcome_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        if !matches!(
            owner.request.method(),
            BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
                | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
                | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
                | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1
        ) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.journal.validate_broker_outcome(owner, connection_peer)
    }

    // Only the original V3 checkpoint can supply the signed hello bytes. Its
    // historical DATA is independently checked against the still-resident
    // outcome/currentness; the caller parks encoding before later postchecks.
    pub(crate) fn capture_git_coverage_checkpoint_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        connection_peer: &ConnectionPeerIdentity,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        if maximum_bytes == 0 || maximum_bytes > 16_384 {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.compare_git_coverage_outcome_v1(owner, connection_peer)?;
        let stored = self.journal.read_optional(owner.context.protocol())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored.checkpoint.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if checkpoint.context() != &owner.context
            || checkpoint.verify()? != owner.transcript
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        checkpoint
            .encode_bounded(maximum_bytes)
            .map_err(BrokerSessionSecurityError::from)
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

    pub(crate) fn revalidate_storage_replay_receiving_v3(&mut self,
        replay: ProtectedBrokerOutcomeReplayV1, peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerOutcomeReplayV1, (BrokerSessionSecurityError, ProtectedBrokerOutcomeReplayV1)> {
        let Some(source) = receiving else { return self.revalidate_broker_replay(replay, peer); };
        match self.compare_storage_replay_receiving_v3(&replay, peer, source) {
            Ok(()) => Ok(replay),
            Err(cause) => Err((cause, replay)),
        }
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

    pub(crate) fn revalidate_storage_committed_receiving_v3(&mut self,
        committed: ProtectedBrokerOutcomeCommittedAdvancementV1, peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerOutcomeCommittedAdvancementV1,
        (BrokerSessionSecurityError, ProtectedBrokerOutcomeCommittedAdvancementV1)> {
        let Some(source) = receiving else { return self.revalidate_broker_committed(committed, peer); };
        match self.compare_storage_terminal_receiving_v3(&committed, peer, source) {
            Ok(()) => Ok(committed),
            Err(cause) => Err((cause, committed)),
        }
    }

    pub(crate) fn revalidate_transport_with_storage_receiving_v3(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.revalidate_transport_engine_v2(transcript, peer, receiving)
    }

    pub(crate) fn compare_original_nonadmitting_outcome(
        &mut self,
        committed: &ProtectedBrokerOutcomeCommittedAdvancementV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let owner = &committed.currentness_owner;
        let exact_result = match owner.request.method() {
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => matches!(owner.outcome.result(), AuthenticatedBrokerMethodResultV1::Error(error)
                if error.code() == aos_sandbox_api::aos::sandbox::local::v1::BrokerErrorCode::BROKER_ERROR_CODE_CONFLICT
                    && error.retryable() && error.safe_message() == "broker operation conflicts"
                    && error.missing_feature().is_none()),
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
                owner.request.authorization().is_none()
                    && matches!(owner.outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. })
            }
            _ => false,
        };
        if owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || !exact_result
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.journal.validate_broker_outcome(owner, connection_peer)
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
        self.journal.require_floor_method(owner.request.method())?;

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
    audience: aos_sandbox_api::aos::sandbox::local::v1::Audience,
    socket_path: &'static str,
}

fn fixed_endpoint(endpoint: ProtectedBrokerSessionFixedEndpointV1) -> FixedEndpointConfiguration {
    use ProtectedBrokerSessionFixedEndpointV1 as Endpoint;
    use aos_sandbox_api::aos::sandbox::local::v1::Audience;
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
        Endpoint::StorageHostClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-storage/broker-session/host",
            custody_root: "/var/lib/aos/sandbox-storage/broker-session/host/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::Host,
            audience: Audience::AUDIENCE_STORAGE_BROKER,
            socket_path: "/run/aos/sandbox-host/storage.sock",
        },
        Endpoint::StorageHostBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-host/broker-session/storage",
            custody_root: "/var/lib/aos/sandbox-host/broker-session/storage/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::Host,
            audience: Audience::AUDIENCE_STORAGE_BROKER,
            socket_path: "/run/aos/sandbox-host/storage.sock",
        },
        Endpoint::ControllerStorageClient => FixedEndpointConfiguration {
            journal_root: CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1,
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
        Endpoint::ControllerMountFuseClient => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandboxd/broker-session/mount-fuse",
            custody_root: "/var/lib/aos/sandboxd/broker-session/mount-fuse/custody",
            role: FixedEndpointRole::Client,
            protocol: Protocol::MountFuse,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-mount/control.sock",
        },
        Endpoint::MountFuseBroker => FixedEndpointConfiguration {
            journal_root: "/var/lib/aos/sandbox-mount/broker-session/fuse",
            custody_root: "/var/lib/aos/sandbox-mount/broker-session/fuse/custody",
            role: FixedEndpointRole::Broker,
            protocol: Protocol::MountFuse,
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
            socket_path: "/run/aos/sandbox-mount/control.sock",
        },
    }
}

pub(crate) fn fixed_service_request_demand_v4(
    extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
    storage_session_schema_demand::schema_demand(extent)?
        .checked_add(storage_session_schema_demand::request_demand(extent)?)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn reconstruct_retained_request(
    history: &BrokerSessionDurableHistoryV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: aos_sandbox_protocol::PeerCredentials,
    policy: aos_sandbox_protocol::PeerPolicy,
    direction: AuthenticatedBrokerRequestDirectionV1,
) -> Result<AuthenticatedBrokerMethodRequestV1, BrokerSessionSecurityError> {
    request_current::reconstruct_retained_request_engine(history, transcript, context, peer, policy, direction, None)
        .map(crate::recovery::current_replay::ReplayValue::into_ordinary)
}

impl ProtectedBrokerSessionJournalV1 {
    // Historical geometry remains DATA after replay. Actual Journal custody,
    // current terminal checks and the genuine receiving loan remain separate.
    fn storage_prepare_original_extent(
        &self,
    ) -> Result<&aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1, BrokerSessionSecurityError> {
        self.storage_receiving_open.as_ref()
            .and_then(|opening| opening.original_extent.as_ref())
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    fn storage_prepare_current_stored(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        let key = protocol_key(BrokerSessionProtocolV1::Storage);
        self.journal.as_ref()
            .and_then(|journal| journal.get(RecordNamespace::BrokerSessionTraffic, &key))
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    fn storage_prepare_request_demand_v1(
        &self,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        storage_session_schema_demand::request_demand(self.storage_prepare_original_extent()?)
    }

    fn storage_prepare_outcome_demand_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        observation: &crate::dormant_handshake::ProtectedBrokerDomainResponseV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        storage_session_schema_demand::outcome_demand(
            self.storage_prepare_original_extent()?,
            self.storage_prepare_current_stored()?,
            request.canonical_packet(),
            observation.body(),
        )
        .map_err(BrokerSessionSecurityError::from)
    }

    fn storage_prepare_replay_demand_v1(
        &self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        storage_session_schema_demand::replay_demand(
            self.storage_prepare_original_extent()?,
            self.storage_prepare_current_stored()?,
            terminal.currentness_owner.request.canonical_packet(),
            terminal.exact_packet(),
        )
        .map_err(BrokerSessionSecurityError::from)
    }

    pub(super) fn endpoint_role(&self) -> BrokerSessionDurableEndpointV1 {
        self.endpoint.role()
    }

    fn read_host_argument_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let value = {
            let mut authority = self.schema_authority_v3()?;
            authority
                .get(&host_argument_archive_key(request_id))
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        // Absence is OutcomeUnknown, never proof that the original request
        // was unsent: an earlier journal snapshot could have been restored.
        let Some(value) = self.schema_retain_value_v3(value)? else {
            return Ok(None);
        };
        let bytes = open_history_archive_frame(
            request_id,
            &value,
            HOST_ARGUMENT_ARCHIVE_MAGIC,
            HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
        )?;
        let stored = self.schema_decode_stored_v3(&protocol_key(BrokerSessionProtocolV1::Host), bytes)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let history = stored.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if stored.endpoint != BrokerSessionDurableEndpointV1::Client
            || stored.stable_endpoint_identity
                != self.stable_endpoint_identity(BrokerSessionProtocolV1::Host)?
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || stored.endpoint_publication
                != self
                    .historical_endpoint_publication(BrokerSessionProtocolV1::Host, &transcript)?
            || head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
            || (!original_host_argument_method_v2(head.method())
                && self.closed_host_prepared_request_id_v2(&stored)? != Some(request_id))
            || head.request_id() != request_id
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if original_host_argument_method_v2(head.method()) {
            validate_host_argument_source(head.request_packet(), request_id)?;
        }
        reconstruct_traffic(&history, &transcript, checkpoint.context())?;
        Ok(Some(stored))
    }

    fn validate_host_argument_archives(&mut self) -> Result<usize, BrokerSessionSecurityError> {
        let keys = self.bounded_host_archive_request_ids(
            BrokerSessionJournalKeyKind::HostOriginalSessionArchive,
            MAXIMUM_HOST_ARGUMENT_ARCHIVES,
        )?;
        for request_id in &keys {
            let scope = self.schema_scope_v3();
            let result = self.read_host_argument_archive(*request_id)
                .and_then(|archive| archive.ok_or(BrokerSessionSecurityError::Currentness));
            self.schema_complete_scope_v3(scope, &result);
            result?;
        }
        Ok(keys.len())
    }

    fn bounded_host_archive_request_ids(
        &mut self,
        expected_kind: BrokerSessionJournalKeyKind,
        maximum: usize,
    ) -> Result<Vec<[u8; 16]>, BrokerSessionSecurityError> {
        let mut keys = Vec::new();
        let result = (|| {
            let mut authority = self.schema_authority_v3()?;
            for (key, _) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                let (kind, logical_key) = classified_broker_session_key(key)?;
                if kind == expected_kind {
                    if keys.len() == maximum {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    keys.push(
                        logical_key
                            .try_into()
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?,
                    );
                }
            }
            Ok(())
        })();
        self.schema_retain_ids_v3(keys, result)
    }

    fn bounded_storage_records(
        &mut self,
        namespace: RecordNamespace,
        maximum: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError> {
        let expected_kind = BrokerSessionJournalKeyKind::from_storage_namespace(namespace)?;
        let mut entries = Vec::new();
        let result = (|| {
            let mut authority = self.schema_authority_v3()?;
            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                let (kind, logical_key) = classified_broker_session_key(key)?;
                if kind != expected_kind {
                    continue;
                }
                if entries.len() == maximum {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                entries.push((logical_key.to_vec(), value.to_vec()));
            }
            Ok(())
        })();
        self.schema_retain_entries_v3(entries, result)
    }

    fn validate_storage_group_archives(&mut self) -> Result<usize, BrokerSessionSecurityError> {
        let entries = self.bounded_storage_records(
            RecordNamespace::BrokerSessionStorageGroupArchive,
            MAXIMUM_STORAGE_GROUP_ARCHIVES,
        )?;
        for (key, _) in &entries {
            let request_id: [u8; 16] = key
                .as_slice()
                .try_into()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let scope = self.schema_scope_v3();
            let result = self.read_atomic_storage_archive(request_id)
                .and_then(|archive| archive.ok_or(BrokerSessionSecurityError::Currentness));
            self.schema_complete_scope_v3(scope, &result);
            result?;
        }
        Ok(entries.len())
    }

    fn read_atomic_storage_archive(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageGroupArchive,
            request_id,
        )?;
        let value = {
            let mut authority = self.schema_authority_v3()?;
            authority
                .get(&key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        let Some(value) = self.schema_retain_value_v3(value)? else {
            return Ok(None);
        };
        let stored_bytes = open_atomic_storage_archive_frame(request_id, &value)?;
        let stored = self.schema_decode_stored_v3(
            &protocol_key(BrokerSessionProtocolV1::Storage),
            stored_bytes,
        )?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let history = stored.history_model()?;
        // A group archive may outlive or precede its inventory archive, so
        // cold replay must authenticate it independently of inventory links.
        if stored.endpoint != self.endpoint.role()
            || stored.stable_endpoint_identity
                != self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || stored.endpoint_publication
                != self.historical_endpoint_publication(
                    BrokerSessionProtocolV1::Storage,
                    &transcript,
                )?
            || !history.records().iter().any(|record| {
                record.method() == BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
                    && record.request_id() == request_id
            })
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        reconstruct_traffic(&history, &transcript, checkpoint.context())?;
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
        self.commit_absent_storage_archive(StorageArchiveKind::Group, request_id, value)?;
        let retained = self
            .read_atomic_storage_archive(request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if retained != *current {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn commit_absent_storage_archive(
        &mut self,
        kind: StorageArchiveKind,
        request_id: [u8; 16],
        value: Vec<u8>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let (namespace, transaction_domain) = match kind {
            StorageArchiveKind::Group => (
                RecordNamespace::BrokerSessionStorageGroupArchive,
                STORAGE_GROUP_ARCHIVE_TRANSACTION_DOMAIN,
            ),
            StorageArchiveKind::Inventory => (
                RecordNamespace::BrokerSessionStorageInventoryArchive,
                STORAGE_INVENTORY_ARCHIVE_TRANSACTION_DOMAIN,
            ),
        };
        let digest: [u8; 32] = Sha256::new()
            .chain_update(transaction_domain)
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
        let key = storage_archive_key(namespace, request_id)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                key.clone(),
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&key)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        drop(authority);
        self.commit_floor_checked_transaction(&transaction)
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
        let key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageGroupArchive,
            request_id,
        )?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::delete(
                RecordNamespace::BrokerSessionTraffic,
                key.clone(),
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&key)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            != Some(value.as_slice())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        drop(authority);
        self.commit_floor_checked_transaction(&transaction)?;
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
        let key = storage_archive_key(namespace, request_id)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::delete(
                RecordNamespace::BrokerSessionTraffic,
                key.clone(),
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let mut authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&key)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            != Some(expected)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        drop(authority);
        self.commit_floor_checked_transaction(&transaction)?;
        let authority = self
            .journal_mut()?
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if authority
            .get(&key)
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
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.sign_broker_outcome_with_storage_receiving_v3(request, message, transcript, None)
    }

    fn sign_broker_outcome_with_storage_receiving_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerResponseEnvelope,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<Vec<u8>, BrokerSessionSecurityError> {
        self.require_floor_method_with_storage_receiving_v2(request.method(), receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
        let context = self.current_context_with_storage_receiving_v2(transcript, None, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?.into_ordinary();
        let current = self
            .read_optional_with_storage_receiving_v2(transcript.protocol(), receiving)?
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
            aos_sandbox_api::aos::sandbox::local::v1::Audience,
        ),
        BrokerSessionSecurityError,
    > {
        let (deadline, maximum_response_bytes, protocol_version, audience) =
            self.client_request_limits(transcript, now_boottime_nanoseconds)?;
        let request_id = self.endpoint.fresh_client_request_id()?;
        // Prevent a current-session ID collision before a one-shot domain
        // owner can reserve it. This is not a global historical ID ledger;
        // Host still checks its own original-attempt key on method admission.
        let request_id_available = self
            .read_optional(transcript.protocol())?
            .map(|stored| {
                stored.history_model().map(|history| {
                    request_id_unused(
                        request_id,
                        history.records().iter().map(|record| record.request_id()),
                    )
                })
            })
            .transpose()?
            .unwrap_or_else(|| request_id_unused(request_id, std::iter::empty()));
        if !request_id_available {
            return Err(BrokerSessionSecurityError::Currentness);
        }

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
            aos_sandbox_api::aos::sandbox::local::v1::Audience,
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
        message: aos_sandbox_api::aos::sandbox::local::v1::BrokerRequestEnvelope,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
        actual_descriptor_count: usize,
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
        maximum_response_bytes: u32,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
    ) -> Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError> {
        self.prepare_client_request_engine_v1(message, method, actual_descriptor_count, request_id,
            deadline_boottime_nanoseconds, maximum_response_bytes, transcript, connection_peer,
            now_boottime_nanoseconds, None)
    }

    pub(crate) fn admit_received_request(
        &mut self,
        packet: &[u8],
        descriptor_count: usize,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        self.admit_received_request_with_storage_receiving_v1(
            packet, descriptor_count, transcript, connection_peer,
            now_boottime_nanoseconds, None, None, None,
        )
    }

    fn admit_received_request_with_storage_receiving_v1(
        &mut self,
        packet: &[u8],
        descriptor_count: usize,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        now_boottime_nanoseconds: u64,
        mut receiving: Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
        replay_terminal: Option<&ProtectedBrokerOutcomeCommittedAdvancementV1>,
        mut lifecycle_receiving: Option<(
            &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
            &aos_sandbox_linux::seqpacket::SeqpacketSocket,
            aos_sandbox_model::ResourceVector,
        )>,
    ) -> Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError> {
        if (replay_terminal.is_some() && receiving.is_none())
            || (receiving.is_some() && lifecycle_receiving.is_some())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if let Some((guard, socket, _)) = lifecycle_receiving.as_mut() {
            let journal = self.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            guard.require_request_current_v1(journal, socket)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        let context = self.current_context_with_storage_receiving_v2(transcript, None,
            borrow_storage_floor_source_v2(&mut receiving, &mut lifecycle_receiving))?.into_ordinary();
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
        if receiving.is_some() || lifecycle_receiving.is_some() {
            if let Some(receiving) = receiving.as_deref_mut() {
                match replay_terminal {
                    Some(_) => receiving.require_prepare_replay_lane_current_v1(),
                    None => receiving.require_prepare_retention_v1(),
                }.map_err(|_| BrokerSessionSecurityError::Currentness)?;
            }
            // Authenticate the same canonical outer carrier before any reached
            // body schema. This provisional state grants no sequence or CAS.
            let carrier = BrokerSessionTrafficStateV1::from_provisional_transcript(
                transcript.clone(),
            ).map_err(|_| BrokerSessionSecurityError::Currentness)?;
            carrier.authenticate_request_carrier_v1(&canonical, &context)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if lifecycle_receiving.is_none() && !matches!(method,
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                    | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        if let Some((guard, socket, baseline)) = lifecycle_receiving.as_mut() {
            // Buffa's outer/body decoder lane is already paid. Only Apply can
            // reach portable workspace metadata; price its actual embedded
            // lengths before the existing canonical-semantic decoder grows it.
            let extra = if method == BrokerMethod::BROKER_METHOD_STORAGE_APPLY {
                let body = ApplyStorageRequest::decode_from_slice(&canonical.message().body)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                let (memory, cells) = aos_sandbox_protocol::semantics::storage::workspace_metadata_receiving_obligations_v1(
                    body.assignment_manifest.len(), body.sandbox_spec.len(),
                ).ok_or(BrokerSessionSecurityError::Currentness)?;
                aos_sandbox_model::ResourceVector::ZERO
                    .with(aos_sandbox_model::ResourceDimension::MemoryBytes,
                        u64::try_from(memory).map_err(|_| BrokerSessionSecurityError::Currentness)?)
                    .with(aos_sandbox_model::ResourceDimension::MetadataEntries,
                        u64::try_from(cells).map_err(|_| BrokerSessionSecurityError::Currentness)?)
            } else {
                aos_sandbox_model::ResourceVector::ZERO
            };
            let complete = baseline.checked_add(extra)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let journal = self.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            guard.extend_request_semantics_v1(journal, socket, complete)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if let Some(terminal) = replay_terminal {
            let owner = &terminal.currentness_owner;
            if terminal.method() != BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                || owner.request.method() != terminal.method()
                || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
                || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ServerSend
                || !matches!(owner.outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. })
                || packet != owner.request.canonical_packet()
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            // The real retained committed terminal, not a detached digest,
            // qualifies this exact replay before any semantic or append path.
            self.validate_broker_outcome(owner, connection_peer)?;
        }
        self.require_floor_method_with_storage_receiving_v2(method,
            borrow_storage_floor_source_v2(&mut receiving, &mut lifecycle_receiving))?;
        let semantic_bindings =
            authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let current = self.read_optional_with_storage_receiving_v2(transcript.protocol(),
            borrow_storage_floor_source_v2(&mut receiving, &mut lifecycle_receiving))?;
        let current_publication = self.endpoint_publication(transcript.protocol())?;
        let history = current
            .as_ref()
            .map(StoredProtocolHistoryV1::history_model)
            .transpose()?;
        let retired_rollover = match (current.as_ref(), history.as_ref()) {
            (Some(current), Some(history)) if current.endpoint_publication == current_publication
                && lifecycle_receiving.is_some() =>
                self.require_retired_storage_rollover_v1(current, history, transcript)?,
            _ => false,
        };
        let requires_initialization = retired_rollover || current
            .as_ref()
            .is_none_or(|value| value.endpoint_publication != current_publication);
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
                reconstruct_retained_request(history, transcript, &context, peer, policy,
                    AuthenticatedBrokerRequestDirectionV1::ServerReceive)
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
        if replay_terminal.is_some()
            && !matches!(&admission, AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        match admission {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => {
                if retired_rollover {
                    // Only this actual funded request admission may bind the
                    // first replacement request. HELLO alone cannot arm CAS.
                    self.bind_retired_storage_request_v1(&request)?;
                }
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
        let protocol = endpoint.protected_protocol_and_node().0;
        if protocol == BrokerSessionProtocolV1::Storage && name != PROTECTED_SESSION_JOURNAL {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let floor = tpm_floor::runtime::BrokerFloorV1::configure(
            &directory,
            protocol,
            endpoint.role(),
            endpoint.launch_image(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let owner = JournalOwnerV1::capture(endpoint.role());
        broker_main_open_recipe!(Legacy, authority, protocol, endpoint, directory,
            name, limits, floor, owner)
    }

    fn reopen_storage(&mut self) -> Result<(), BrokerSessionSecurityError> {
        // This refusal precedes even endpoint revalidation, sidecar suspension
        // and main.take. A failed Required owner keeps all original custody.
        self.floor.require_reopen_allowed()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        // The first endpoint read still precedes extraction on Legacy. Only
        // Required pre-arms its actual resident attempt across this same read.
        self.floor.revalidate_endpoint_for_reopen(&mut self.endpoint)?;
        let mut operation = BrokerFloorOperationV1::begin(self);
        let result = operation.reopen();
        operation.finish(result)?;
        self.validate_all()
    }

    fn attach_floor(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let mut operation = BrokerFloorOperationV1::begin(self);
        let result = operation.attach();
        operation.finish(result)
    }

    fn require_floor_current(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.require_floor_current_with_storage_receiving_v2(None)
    }

    fn require_floor_current_with_storage_receiving_v2(&mut self,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let mut operation = BrokerFloorOperationV1::begin(self);
        let result = operation.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .check_with_storage_receiving_v2(operation.owner, receiving)
            .map_err(floor_revalidation::security_error);
        operation.finish(result)
    }

    fn require_floor_method(
        &mut self,
        method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_floor_method_with_storage_receiving_v2(method, None)
    }

    fn require_floor_method_with_storage_receiving_v2(&mut self, method: BrokerMethod,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_floor_current_with_storage_receiving_v2(receiving)?;
        self.floor.require_method(method).map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    /// Routes every actual namespace-47 mutation through the retained floor.
    fn commit_floor_checked_transaction(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.commit_floor_checked_transaction_with_storage_v2(transaction, None)
    }

    fn commit_floor_checked_transaction_with_storage_v2(&mut self, transaction: &JournalTransaction,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let mut operation = BrokerFloorOperationV1::begin(self);
        let result = operation.commit_with_storage_receiving_v2(transaction, receiving);
        operation.finish(result)
    }

    fn journal_mut(&mut self) -> Result<&mut Journal, BrokerSessionSecurityError> {
        self.journal
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    // The ordinary owner and the selected whole-Journal guard borrow this one
    // clock recipe. Neither accepts a sample or creates a renewed deadline.
    #[cfg(feature = "online-nix")]
    fn check_online_admitted_clock(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let schema = self.online_schema.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if schema.first_failure.is_some() || schema.clock_failure.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let Some(prepared) = schema.prepared.as_ref().or_else(|| {
            schema.completed_preparations.iter().rev().find_map(Option::as_ref)
        }) else {
            return Ok(());
        };
        let admission = prepared.admission.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let sample = match aos_sandbox_broker::ownership_clock::sample_ownership_clock() {
            Ok(sample) => sample,
            Err(cause) => {
                schema.clock_failure = Some(cause);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        if let Err(cause) = schema.authority.validate_effect_clock(&admission.effect, &sample) {
            schema.first_failure.get_or_insert(cause);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn current_context(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.current_context_with_originals(transcript, None)
            .map(|value| value.into_ordinary())
    }

    fn validate_recovery_peer(
        &mut self,
        target: &StoredProtocolHistoryV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.validate_recovery_peer_with_storage_receiving_v2(target, transcript, connection_peer, None)
    }

    fn validate_recovery_peer_with_storage_receiving_v2(&mut self,
        target: &StoredProtocolHistoryV1, transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        mut receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let context = self.current_context_with_storage_receiving_v2(transcript, None, receiving.as_mut()
            .map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?.into_ordinary();
        let peer = self.observe_peer_with_storage_receiving_v3(transcript, connection_peer, receiving)?;
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
        self.observe_peer_current_engine(transcript, connection_peer, None, None)
            .map(|value| value.into_ordinary())
    }

    fn observe_peer_with_storage_receiving_v3(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<ObservedBrokerPeerExecutionV1, BrokerSessionSecurityError> {
        let Some(source) = receiving else { return self.observe_peer(transcript, peer); };
        let mut archive = std::mem::take(&mut self.session_replays);
        let result = archive.peer(self, transcript, peer, source);
        self.session_replays = archive;
        result
    }

    fn observe_peer_retaining_v1(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        originals: &mut super::peer_liveness::ObservedBrokerPeerOriginalV1,
    ) -> Result<ObservedBrokerPeerExecutionV1, BrokerSessionSecurityError> {
        self.observe_peer_current_engine(transcript, connection_peer, Some(originals), None)
            .map(|value| value.into_ordinary())
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
        self.read_optional_with_storage_receiving_v2(protocol, None)
    }

    pub(in crate::recovery) fn read_current_with_storage_receiving_v3(&mut self,
        protocol: BrokerSessionProtocolV1,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
        self.read_optional_with_storage_receiving_v2(protocol, receiving)?
            .ok_or(BrokerSessionSecurityError::Currentness)?.snapshot()
    }

    pub(in crate::recovery) fn read_current_in_storage_validation_v3(&mut self,
        protocol: BrokerSessionProtocolV1, receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<ProtectedBrokerSessionJournalSnapshotV1, BrokerSessionSecurityError> {
        self.read_optional_in_storage_validation_v3(protocol, receiving)?
            .ok_or(BrokerSessionSecurityError::Currentness)?.snapshot()
    }

    pub(in crate::recovery) fn read_optional_in_storage_validation_v3(&mut self,
        protocol: BrokerSessionProtocolV1, receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        // The closed validation caller has prepaid this exact held-prefix
        // model. This direct shared recipe avoids nesting another owner/quote.
        self.read_optional_engine_v3(protocol, Some(receiving))
    }

    pub(in crate::recovery) fn retained_storage_main_v3(&self)
        -> Result<&Journal, BrokerSessionSecurityError>
    {
        self.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(in crate::recovery) fn reopen_current_with_storage_archive_v3(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        peer: &ObservedBrokerPeerExecutionV1,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1,
        ProtectedBrokerSessionJournalSnapshotV1), BrokerSessionSecurityError> {
        // A serial, non-awaiting loan lends this SAME held writer to the
        // canonical replay. Restore the whole archive on every returned path.
        let mut archive = std::mem::take(&mut self.session_replays);
        let result = archive.observe(self, transcript, context, peer, receiving);
        self.session_replays = archive;
        result
    }

    fn current_context_with_storage_archive_v3(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        let mut archive = std::mem::take(&mut self.session_replays);
        let result = archive.context(self, transcript, receiving);
        self.session_replays = archive;
        result
    }

    fn validate_storage_outcome_receiving_v3(&mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        let mut archive = std::mem::take(&mut self.session_replays);
        let result = archive.outcome(self, owner, peer, receiving);
        self.session_replays = archive;
        result
    }

    fn read_optional_with_storage_receiving_v2(&mut self, protocol: BrokerSessionProtocolV1,
        receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        if let Some(source) = receiving {
            let mut archive = std::mem::take(&mut self.session_replays);
            let result = archive.observe_optional(self, protocol, source);
            self.session_replays = archive;
            return result;
        }
        self.read_optional_engine_v3(protocol, None)
    }

    fn read_optional_engine_v3(&mut self, protocol: BrokerSessionProtocolV1,
        mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        self.require_floor_current_with_storage_receiving_v2(receiving.as_mut()
            .map(|source| &mut **source as &mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2))?;
        let observed = self.read_optional_schema(protocol);
        if receiving.is_none() {
            let current = observed?;
            self.require_floor_current()?;
            return Ok(current);
        }
        // The funded native floor post remains independent of pure schema
        // refusal. Exclusive parser/model scratch may drop without a refund.
        let post = self.require_floor_current_with_storage_receiving_v2(receiving);
        let current = observed?;
        post?;
        Ok(current)
    }

    /// Parses protected schema only; it never grants currentness or replay.
    fn read_optional_schema(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        if self.schema_original.is_some() {
            return self.read_optional_schema_retaining_v3(protocol);
        }
        let mut work = StoredReadOriginalsV1::new();
        self.read_optional_schema_captured(protocol, &mut work, false)?;
        Ok(work.take_ordinary())
    }

    fn validate_all(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.require_floor_current()?;
        self.validate_schema_only()?;
        self.require_floor_current()
    }

    /// Checks schema/role under the actual held writer, without a floor token.
    fn validate_schema_only(&mut self) -> Result<(), BrokerSessionSecurityError> {
        #[cfg(feature = "online-nix")]
        if self.online_schema.is_some() {
            self.validate_online_rows()?;
            let _ = self.read_optional_schema(BrokerSessionProtocolV1::Nix)?;
            return Ok(());
        }
        for protocol in [
            BrokerSessionProtocolV1::Host,
            BrokerSessionProtocolV1::Storage,
            BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network,
            BrokerSessionProtocolV1::MountFuse,
            BrokerSessionProtocolV1::Nix,
        ] {
            let _ = self.read_optional_schema(protocol)?;
        }
        self.validate_host_argument_archives()?;
        self.validate_host_terminal_archives()?;
        self.validate_storage_group_archives()?;
        self.validate_storage_inventory_archives()?;
        self.validate_storage_inventory_abandonments()?;
        self.validate_operator_repair_inventory_archives()?;
        Ok(())
    }

    #[cfg(feature = "online-nix")]
    fn validate_online_rows(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let schema = self.online_schema.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        if schema.first_failure.is_some() || schema.clock_failure.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let journal = self.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let mut seeds = 0_usize;
        let mut traffic = 0_usize;
        let traffic_key = protocol_key(BrokerSessionProtocolV1::Nix);
        let stored = journal.get(RecordNamespace::BrokerSessionTraffic, &traffic_key)
            .map(|bytes| StoredProtocolHistoryV1::decode(&traffic_key, bytes)).transpose()?;
        let history = stored.as_ref().map(StoredProtocolHistoryV1::history_model).transpose()?;
        for (namespace, key, value) in journal.all_records() {
            if namespace != RecordNamespace::BrokerSessionTraffic {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            if key == schema.key && value == schema.seed {
                seeds += 1;
            } else if key == traffic_key && !value.is_empty() {
                traffic += 1;
            } else if key.len() == 24 && &key[..8] == b"AOSNXF01" {
                let sandbox = key[8..].try_into().map_err(|_| BrokerSessionSecurityError::Currentness)?;
                let result = schema.authority.open_online_nix_fence(&sandbox, value);
                let fence = retain_online_authority_result(&mut schema.first_failure, result)?;
                let result = schema.authority.check_current_fence(&fence);
                retain_online_authority_result(&mut schema.first_failure, result)?;
            } else if key.len() == 24 && &key[..8] == b"AOSNXE01" {
                let request_id = key[8..].try_into().map_err(|_| BrokerSessionSecurityError::Currentness)?;
                let result = schema.authority.open_online_nix_effect(&request_id, value);
                let effect = retain_online_authority_result(&mut schema.first_failure, result)?;
                require_online_effect_fields(schema, &effect)?;
                // Completed older-session receipts remain authenticated DATA.
                // An orphan pending effect, however, cannot be reinterpreted
                // as a new request or as permission to repeat the reader.
                if effect.status() == aos_sandbox_broker::BrokerEffectStatusV1::Pending {
                    let head = history.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?
                        .head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    if head.request_id() != request_id
                        || head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
                    {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                }
            } else {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        if seeds != 1 || traffic > 1 {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if let Some(history) = &history {
            for record in history.records() {
                let key = aos_sandbox_broker::BrokerAuthority::online_nix_effect_key(&record.request_id());
                let bytes = journal.get(RecordNamespace::BrokerSessionTraffic, &key)
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let result = schema.authority.open_online_nix_effect(&record.request_id(), bytes);
                let effect = retain_online_authority_result(&mut schema.first_failure, result)?;
                require_online_history_effect(schema, record, &effect)?;
                let assignment = effect.local_lease_record().assignment();
                let fence_key = aos_sandbox_broker::BrokerAuthority::online_nix_fence_key(
                    assignment.sandbox().as_bytes(),
                );
                let bytes = journal.get(RecordNamespace::BrokerSessionTraffic, &fence_key)
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let result = schema.authority.open_online_nix_fence(assignment.sandbox().as_bytes(), bytes);
                let fence = retain_online_authority_result(&mut schema.first_failure, result)?;
                if record == history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?
                    && (fence.assignment().sandbox() != assignment.sandbox()
                        || fence.assignment().incarnation() != assignment.incarnation()
                        || fence.assignment().epoch() != assignment.epoch()
                        || fence.assignment().digest() != assignment.digest()
                        || fence.plan_digest() != effect.plan_digest())
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "online-nix")]
    fn require_online_transaction(&mut self, transaction: &JournalTransaction)
        -> Result<(), BrokerSessionSecurityError>
    {
        let schema = self.online_schema.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        let prepared = schema.prepared.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let admission = prepared.admission.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        if schema.first_failure.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let records = transaction.records();
        let record = records.first().ok_or(BrokerSessionSecurityError::Currentness)?;
        let key = protocol_key(BrokerSessionProtocolV1::Nix);
        if record.namespace() != RecordNamespace::BrokerSessionTraffic
            || record.key() != key || record.value().is_none()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let stored = StoredProtocolHistoryV1::decode(&key, record.value().ok_or(BrokerSessionSecurityError::Currentness)?)?;
        if stored.protocol != BrokerSessionProtocolV1::Nix || stored.endpoint != self.endpoint.role() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history = stored.history_model()?;
        let head = history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let effect_key = aos_sandbox_broker::BrokerAuthority::online_nix_effect_key(&prepared.request_id);
        let effect_record = match head.phase() {
            BrokerSessionDurablePhaseV1::RequestPrepared => {
                if records.len() != 3 {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                let fence_key = aos_sandbox_broker::BrokerAuthority::online_nix_fence_key(
                    admission.fence.assignment().sandbox().as_bytes(),
                );
                if records[1].namespace() != RecordNamespace::BrokerSessionTraffic
                    || records[1].key() != fence_key
                    || records[1].value() != prepared.fence.as_deref()
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                &records[2]
            }
            BrokerSessionDurablePhaseV1::Terminal => {
                if records.len() != 2 {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                &records[1]
            }
        };
        if head.request_id() != prepared.request_id
            || effect_record.namespace() != RecordNamespace::BrokerSessionTraffic
            || effect_record.key() != effect_key
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let result = schema.authority.open_online_nix_effect(
            &prepared.request_id,
            effect_record.value().ok_or(BrokerSessionSecurityError::Currentness)?,
        );
        let effect = retain_online_authority_result(&mut schema.first_failure, result)?;
        require_online_history_effect(schema, head, &effect)?;
        if effect.plan_digest() != admission.effect.plan_digest()
            || effect.lease_digest() != admission.effect.lease_digest()
            || effect.local_lease_record() != admission.effect.local_lease_record()
            || effect.effect_deadline_boottime_nanoseconds()
                != admission.effect.effect_deadline_boottime_nanoseconds()
            || (head.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
                && effect_record.value() != prepared.effect.as_deref())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn commit_stored(
        &mut self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.commit_stored_with_storage_receiving_v2(stored, None)
    }

    fn commit_stored_with_storage_receiving_v2(&mut self, stored: &StoredProtocolHistoryV1,
        mut receiving: Option<&mut dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if stored.purpose != self.purpose { return Err(BrokerSessionSecurityError::Currentness); }
        let key = session_protocol_key_v2(stored.protocol, stored.purpose)?;
        let value = stored.encode()?;
        let history = stored.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let original_request_id = (stored.protocol == BrokerSessionProtocolV1::Host
            && stored.endpoint == BrokerSessionDurableEndpointV1::Client
            && head.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
            && original_host_argument_method_v2(head.method()))
            .then(|| head.request_id())
            .or(self.closed_host_prepared_request_id_v2(stored)?);
        let mut records = vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            key,
            value.clone(),
        )];
        #[cfg(feature = "online-nix")]
        if let Some(schema) = self.online_schema.as_mut() {
            if schema.native_transaction.is_some() || schema.first_failure.is_some() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let prepared = schema.prepared.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            let admission = prepared.admission.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            if stored.protocol != BrokerSessionProtocolV1::Nix || head.request_id() != prepared.request_id {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let effect_key = aos_sandbox_broker::BrokerAuthority::online_nix_effect_key(&prepared.request_id);
            match head.phase() {
                BrokerSessionDurablePhaseV1::RequestPrepared => {
                    records.push(JournalRecord::put(
                        RecordNamespace::BrokerSessionTraffic,
                        aos_sandbox_broker::BrokerAuthority::online_nix_fence_key(
                            admission.fence.assignment().sandbox().as_bytes(),
                        )
                        .to_vec(),
                        prepared.fence.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone(),
                    ));
                    records.push(JournalRecord::put(
                        RecordNamespace::BrokerSessionTraffic,
                        effect_key.to_vec(),
                        prepared.effect.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?.clone(),
                    ));
                }
                BrokerSessionDurablePhaseV1::Terminal => {
                    let receipt = Sha256::digest(head.outcome_packet()
                        .ok_or(BrokerSessionSecurityError::Currentness)?).to_vec();
                    let completed = admission.effect.clone().complete(receipt)
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    let result = schema.authority.seal_online_nix_effect(&prepared.request_id, &completed);
                    let value = match result {
                        Ok(value) => value,
                        Err(cause) => {
                            schema.first_failure.get_or_insert(cause);
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                    };
                    records.push(JournalRecord::put(
                        RecordNamespace::BrokerSessionTraffic,
                        effect_key.to_vec(),
                        value,
                    ));
                }
            }
            let transaction = JournalTransaction::new(transaction_id(stored)?, records)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            // One selected-only Arc holds the actual immutable full native
            // transaction across the existing mutable floor coordinator. No
            // record or byte payload is reconstructed for the borrowed commit.
            schema.native_transaction = Some(std::sync::Arc::new(transaction));
            let transaction = std::sync::Arc::clone(schema.native_transaction.as_ref()
                .ok_or(BrokerSessionSecurityError::Currentness)?);
            return self.commit_floor_checked_transaction_with_storage_v2(&transaction, receiving);
        }
        if let Some(request_id) = original_request_id {
            if original_host_argument_method_v2(head.method()) {
                validate_host_argument_source(head.request_packet(), request_id)?;
            }
            if stored.checkpoint.is_none()
                || self.validate_host_argument_archives()? == MAXIMUM_HOST_ARGUMENT_ARCHIVES
                || self.read_host_argument_archive(request_id)?.is_some()
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let archive = encode_history_archive_frame(
                request_id,
                &value,
                HOST_ARGUMENT_ARCHIVE_MAGIC,
                HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )?;
            records.push(JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                host_argument_archive_key(request_id),
                archive,
            ));
        }
        if let Some(archive) = self.prepare_host_terminal_archive(stored)? {
            records.push(archive);
        }
        // Each selected Host preparation and terminal shares its native
        // transaction with an immutable full-prefix archive. New closed
        // methods use their own request IDs; legacy37/59 keys stay literal.
        let transaction = JournalTransaction::new(transaction_id(stored)?, records)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.commit_floor_checked_transaction_with_storage_v2(&transaction, receiving)
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
pub(in crate::recovery) struct StoredProtocolHistoryV1 {
    purpose: SessionPurpose,
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

    fn from_request_write(
        protocol: BrokerSessionProtocolV1,
        endpoint: BrokerSessionDurableEndpointV1,
        stable_endpoint_identity: [u8; 32],
        endpoint_publication: [u8; 32],
        current_catalog: [u8; 32],
        write: ProtectedBrokerRequestWriteV1,
        checkpoint: Option<HistoricalSessionCheckpointV1>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        Self::from_request_write_for_purpose_v2(SessionPurpose::Ordinary, protocol,
            endpoint, stable_endpoint_identity, endpoint_publication, current_catalog, write, checkpoint)
    }

    fn from_request_write_for_purpose_v2(
        purpose: SessionPurpose,
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
            purpose,
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
            purpose: current.purpose,
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
        // The lower carrier is historical DATA. This wrapper retains the
        // protected producers and snapshot admission in their original owner.
        let view = CanonicalStoredHistoryViewV1 {
            protocol: self.protocol,
            endpoint: self.endpoint,
            generation: self.generation,
            stable_endpoint_identity: self.stable_endpoint_identity,
            endpoint_publication: self.endpoint_publication,
            current_catalog: self.current_catalog,
            current_head: self.current_head,
            history: &self.history,
            checkpoint: self.checkpoint.as_ref(),
        };
        match self.purpose {
            SessionPurpose::Ordinary => view.encode(),
            SessionPurpose::OperatorRecoverInventory => view.encode_operator_recover_inventory_v1(),
            SessionPurpose::HostStopCleanup => view.encode_host_stop_cleanup_v1(),
            SessionPurpose::HostNoApplyCleanup => view.encode_host_no_apply_cleanup_v1(),
        }.map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self, BrokerSessionSecurityError> {
        let stored = CanonicalStoredHistoryV1::decode(key, value)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;

        Self::from_canonical_for_key_v2(stored, key)
    }

    fn from_canonical_for_key_v2(stored: CanonicalStoredHistoryV1, key: &[u8])
        -> Result<Self, BrokerSessionSecurityError>
    {
        let (purpose, protocol) = classify_protocol_key_v2(key)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if protocol != stored.protocol { return Err(BrokerSessionSecurityError::Currentness); }
        let mut row = Self::from_canonical(stored);
        row.purpose = purpose;
        Ok(row)
    }

    fn from_canonical(stored: CanonicalStoredHistoryV1) -> Self {
        Self {
            purpose: SessionPurpose::Ordinary,
            protocol: stored.protocol,
            endpoint: stored.endpoint,
            generation: stored.generation,
            stable_endpoint_identity: stored.stable_endpoint_identity,
            endpoint_publication: stored.endpoint_publication,
            current_catalog: stored.current_catalog,
            current_head: stored.current_head,
            history: stored.history,
            checkpoint: stored.checkpoint,
        }
    }
}

fn session_protocol_key_v2(protocol: BrokerSessionProtocolV1, purpose: SessionPurpose)
    -> Result<Vec<u8>, BrokerSessionSecurityError>
{
    match purpose {
        SessionPurpose::Ordinary => Ok(protocol_key(protocol)),
        SessionPurpose::OperatorRecoverInventory if protocol == BrokerSessionProtocolV1::Storage =>
            Ok(canonical_operator_recover_inventory_key_v1()),
        SessionPurpose::HostStopCleanup if protocol == BrokerSessionProtocolV1::Host =>
            Ok(canonical_host_stop_cleanup_key_v1()),
        SessionPurpose::HostNoApplyCleanup if protocol == BrokerSessionProtocolV1::Host =>
            Ok(canonical_host_no_apply_cleanup_key_v1()),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn protocol_key(protocol: BrokerSessionProtocolV1) -> Vec<u8> {
    canonical_protocol_key_v1(protocol)
}

fn storage_archive_key(
    namespace: RecordNamespace,
    request_id: [u8; 16],
) -> Result<Vec<u8>, BrokerSessionSecurityError> {
    let magic = match namespace {
        RecordNamespace::BrokerSessionStorageGroupArchive => STORAGE_GROUP_KEY_MAGIC,
        RecordNamespace::BrokerSessionStorageInventoryArchive => STORAGE_INVENTORY_KEY_MAGIC,
        RecordNamespace::BrokerSessionStorageInventoryAbandonment => STORAGE_ABANDONMENT_KEY_MAGIC,
        _ => return Err(BrokerSessionSecurityError::Currentness),
    };
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(magic);
    key.extend_from_slice(&request_id);
    Ok(key)
}

fn classified_broker_session_key(
    key: &[u8],
) -> Result<(BrokerSessionJournalKeyKind, &[u8]), BrokerSessionSecurityError> {
    if key.len() == 9 && classify_protocol_key_v2(key).is_ok() {
        return Ok((BrokerSessionJournalKeyKind::Traffic, key));
    }
    if key.len() == 24 {
        for (magic, kind) in [
            (
                STORAGE_GROUP_KEY_MAGIC,
                BrokerSessionJournalKeyKind::StorageGroupArchive,
            ),
            (
                STORAGE_INVENTORY_KEY_MAGIC,
                BrokerSessionJournalKeyKind::StorageInventoryArchive,
            ),
            (
                STORAGE_ABANDONMENT_KEY_MAGIC,
                BrokerSessionJournalKeyKind::StorageInventoryAbandonment,
            ),
            (
                HOST_ORIGINAL_SESSION_KEY_MAGIC,
                BrokerSessionJournalKeyKind::HostOriginalSessionArchive,
            ),
            (
                HOST_TERMINAL_SESSION_KEY_MAGIC,
                BrokerSessionJournalKeyKind::HostTerminalSessionArchive,
            ),
            (
                operator_repair_history::KEY_MAGIC,
                BrokerSessionJournalKeyKind::OperatorRepairInventoryArchive,
            ),
        ] {
            if key.starts_with(magic) {
                return Ok((kind, &key[8..]));
            }
        }
    }
    Err(BrokerSessionSecurityError::Currentness)
}

fn host_argument_archive_key(request_id: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(HOST_ORIGINAL_SESSION_KEY_MAGIC);
    key.extend_from_slice(&request_id);
    key
}

fn host_terminal_archive_key(original_request_id: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(HOST_TERMINAL_SESSION_KEY_MAGIC);
    key.extend_from_slice(&original_request_id);
    key
}

fn protocol_code(protocol: BrokerSessionProtocolV1) -> u8 {
    protocol.code()
}

fn decode_protocol(code: u8) -> Result<BrokerSessionProtocolV1, BrokerSessionSecurityError> {
    BrokerSessionProtocolV1::from_code(code)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn endpoint_code(endpoint: BrokerSessionDurableEndpointV1) -> u8 {
    match endpoint {
        BrokerSessionDurableEndpointV1::Client => 1,
        BrokerSessionDurableEndpointV1::Broker => 2,
    }
}

fn encode_atomic_storage_archive_frame(
    request_id: [u8; 16],
    stored_history: &[u8],
) -> Result<Vec<u8>, BrokerSessionSecurityError> {
    encode_history_archive_frame(
        request_id,
        stored_history,
        STORAGE_GROUP_ARCHIVE_MAGIC,
        STORAGE_GROUP_ARCHIVE_VALUE_DOMAIN,
    )
}

fn encode_history_archive_frame(
    request_id: [u8; 16],
    stored_history: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Result<Vec<u8>, BrokerSessionSecurityError> {
    aos_sandbox_protocol::authenticated_session::history_archive::
        encode_history_archive_frame_data_v1(request_id, stored_history, magic, domain)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn open_atomic_storage_archive_frame<'a>(
    request_id: [u8; 16],
    value: &'a [u8],
) -> Result<&'a [u8], BrokerSessionSecurityError> {
    open_history_archive_frame(
        request_id,
        value,
        STORAGE_GROUP_ARCHIVE_MAGIC,
        STORAGE_GROUP_ARCHIVE_VALUE_DOMAIN,
    )
}

fn open_history_archive_frame<'a>(
    request_id: [u8; 16],
    value: &'a [u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Result<&'a [u8], BrokerSessionSecurityError> {
    aos_sandbox_protocol::authenticated_session::history_archive::
        open_history_archive_frame_data_v1(request_id, value, magic, domain)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

// Old37 remains decode-only historical input. The new live one-shot archive
// is exact59, including the completed preparation bytes in its signed body.
fn original_host_argument_method_v2(method: BrokerMethod) -> bool {
    matches!(method, BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
        | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
}

fn original_host_argument_source_v2(
    method: BrokerMethod,
    bytes: &[u8],
) -> Result<ControllerExecutionArgumentAttemptV1, BrokerSessionSecurityError> {
    let source = match method {
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            let body = ObserveHostExecutionArgumentRequestV1::decode_from_slice(bytes)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if body.encode_to_vec() != bytes { return Err(BrokerSessionSecurityError::Currentness); }
            body.canonical_attempt
        }
        BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => {
            let body = AcceptHostExecutionArgumentRequestV2::decode_from_slice(bytes)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if body.encode_to_vec() != bytes { return Err(BrokerSessionSecurityError::Currentness); }
            let preparation = aos_sandbox_protocol::host_execution_argument::preparation::HostArgumentPreparationV2::decode(
                &body.canonical_preparation,
            ).map_err(|_| BrokerSessionSecurityError::Currentness)?;
            preparation.require_accept_source(&body.canonical_attempt)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            body.canonical_attempt
        }
        _ => return Err(BrokerSessionSecurityError::Currentness),
    };
    ControllerExecutionArgumentAttemptV1::decode_canonical(&source)
        .map_err(|_| BrokerSessionSecurityError::Currentness)
}

fn validate_host_argument_source(
    packet: &[u8],
    request_id: [u8; 16],
) -> Result<(), BrokerSessionSecurityError> {
    let signed = decode_canonical_request_v1(packet)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let method = signed.message().method.as_known()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let source = original_host_argument_source_v2(method, &signed.message().body)?;
    if source.request_id() != request_id { return Err(BrokerSessionSecurityError::Currentness); }
    Ok(())
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

#[cfg(test)]
mod protocol_code_tests {
    use super::*;

    #[test]
    fn protocol_adapter_preserves_currentness_errors_for_unknown_codes() {
        assert_eq!(protocol_code(BrokerSessionProtocolV1::Nix), 6);
        assert_eq!(decode_protocol(6).unwrap(), BrokerSessionProtocolV1::Nix);

        for code in std::iter::once(0).chain(7..=u8::MAX) {
            assert!(matches!(
                decode_protocol(code),
                Err(BrokerSessionSecurityError::Currentness)
            ));
        }
    }
}

#[cfg(test)]
mod request_id_tests {
    use super::request_id_unused;

    #[test]
    fn selected_request_id_must_not_reuse_prior_method_identity() {
        assert!(!request_id_unused([0; 16], std::iter::empty()));
        assert!(request_id_unused([3; 16], [[1; 16], [2; 16]]));
        assert!(!request_id_unused([3; 16], [[1; 16], [3; 16]]));
    }
}

#[cfg(test)]
mod storage_host_endpoint_tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::Audience;

    #[test]
    fn storage_host_endpoint_has_distinct_signed_role_and_journal_custody() {
        let client = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostClient);
        let broker = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostBroker);
        let controller = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::HostBroker);
        let mount = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::RootMountHostBroker);

        assert_eq!(client.audience, Audience::AUDIENCE_STORAGE_BROKER);
        assert_eq!(broker.audience, Audience::AUDIENCE_STORAGE_BROKER);
        assert!(matches!(client.role, FixedEndpointRole::Client));
        assert!(matches!(broker.role, FixedEndpointRole::Broker));
        assert_eq!(client.socket_path, broker.socket_path);
        assert_eq!(broker.socket_path, "/run/aos/sandbox-host/storage.sock");
        assert_ne!(broker.socket_path, controller.socket_path);
        assert_ne!(broker.socket_path, mount.socket_path);
        assert_ne!(client.journal_root, broker.journal_root);
        assert_ne!(broker.journal_root, controller.journal_root);
        assert_ne!(broker.journal_root, mount.journal_root);
        assert_ne!(broker.custody_root, controller.custody_root);
    }
}

#[cfg(test)]
mod fuse_endpoint_tests {
    use super::*;

    #[test]
    fn fuse_contexts_share_only_the_existing_mount_transport_and_role() {
        for (native, fuse) in [
            (
                ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
                ProtectedBrokerSessionFixedEndpointV1::ControllerMountFuseClient,
            ),
            (
                ProtectedBrokerSessionFixedEndpointV1::MountBroker,
                ProtectedBrokerSessionFixedEndpointV1::MountFuseBroker,
            ),
        ] {
            let native = fixed_endpoint(native);
            let fuse = fixed_endpoint(fuse);
            assert_eq!(native.protocol, BrokerSessionProtocolV1::Mount);
            assert_eq!(fuse.protocol, BrokerSessionProtocolV1::MountFuse);
            assert_eq!(native.socket_path, fuse.socket_path);
            assert_eq!(native.audience, fuse.audience);
            assert_ne!(native.journal_root, fuse.journal_root);
            assert_ne!(native.custody_root, fuse.custody_root);
        }
        assert!(
            aos_sandbox_broker_session_protocol::production_broker_client_hello_v1(
                BrokerSessionProtocolV1::MountFuse,
                aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
                4096,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod storage_group_archive_tests {
    use super::*;
    #[cfg(debug_assertions)]
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

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

    #[cfg(debug_assertions)]
    #[test]
    fn nonempty_traffic_and_archive_share_one_protected_claim_after_cold_reopen() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let limits = protected_session_journal_limits();
        let traffic_key = protocol_key(BrokerSessionProtocolV1::Storage);
        let archive_key =
            storage_archive_key(RecordNamespace::BrokerSessionStorageGroupArchive, [9; 16])
                .unwrap();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SESSION_JOURNAL,
            limits,
            uid,
        )
        .unwrap();

        for (id, key, value) in [
            (1, traffic_key.clone(), b"current-traffic".to_vec()),
            (2, archive_key.clone(), b"old-session-archive".to_vec()),
        ] {
            let transaction = JournalTransaction::new(
                [id; 16],
                vec![JournalRecord::put(
                    RecordNamespace::BrokerSessionTraffic,
                    key,
                    value,
                )],
            )
            .unwrap();
            journal
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .unwrap()
                .commit(&transaction)
                .unwrap();
        }
        drop(journal);

        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SESSION_JOURNAL,
            limits,
            uid,
        )
        .unwrap();
        let authority = reopened
            .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .unwrap();
        assert_eq!(
            authority.get(&traffic_key).unwrap(),
            Some(b"current-traffic".as_slice())
        );
        assert_eq!(
            authority.get(&archive_key).unwrap(),
            Some(b"old-session-archive".as_slice())
        );
        assert_eq!(
            classified_broker_session_key(&archive_key).unwrap().0,
            BrokerSessionJournalKeyKind::StorageGroupArchive
        );
        let mut host_key = HOST_ORIGINAL_SESSION_KEY_MAGIC.to_vec();
        host_key.extend_from_slice(&[7; 16]);
        assert_eq!(
            classified_broker_session_key(&host_key).unwrap().0,
            BrokerSessionJournalKeyKind::HostOriginalSessionArchive
        );
        assert!(classified_broker_session_key(b"unknown-record-key").is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn old_cross_namespace_archive_blocks_protected_cold_reopen() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let limits = protected_session_journal_limits();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SESSION_JOURNAL,
            limits,
            uid,
        )
        .unwrap();
        for (id, namespace, key) in [
            (
                1,
                RecordNamespace::BrokerSessionTraffic,
                protocol_key(BrokerSessionProtocolV1::Storage),
            ),
            (
                2,
                RecordNamespace::BrokerSessionStorageGroupArchive,
                [9; 16].to_vec(),
            ),
        ] {
            journal
                .commit(
                    &JournalTransaction::new(
                        [id; 16],
                        vec![JournalRecord::put(namespace, key, b"nonempty".to_vec())],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        drop(journal);

        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SESSION_JOURNAL,
            limits,
            uid,
        )
        .unwrap();
        assert!(matches!(
            reopened.claim_protected_authority(RecordNamespace::BrokerSessionTraffic),
            Err(aos_sandbox_controller_domain::JournalError::ForeignAuthorityNamespace)
        ));
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
        let archive_key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageGroupArchive,
            request_id,
        )
        .unwrap();
        for (id, namespace, key, value) in [
            (
                1,
                RecordNamespace::BrokerSessionTraffic,
                current_key.clone(),
                b"original-session".to_vec(),
            ),
            (
                2,
                RecordNamespace::BrokerSessionTraffic,
                archive_key.clone(),
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
            .get(RecordNamespace::BrokerSessionTraffic, &archive_key)
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
        let archive_key = storage_archive_key(
            RecordNamespace::BrokerSessionStorageGroupArchive,
            request_id,
        )
        .unwrap();
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
                RecordNamespace::BrokerSessionTraffic,
                archive_key.clone(),
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
            .get(RecordNamespace::BrokerSessionTraffic, &archive_key)
            .unwrap();
        assert_eq!(
            open_atomic_storage_archive_frame(request_id, retained).unwrap(),
            b"signed-group-history"
        );
    }
}

#[cfg(test)]
mod host_argument_archive_tests {
    use super::*;

    #[test]
    fn no_apply_identity_rejects_every_foreign_original_coordinate() {
        let original = OriginalHostArgumentIdentityV1 {
            execution_id: [1; 16],
            create_operation_id: [2; 16],
            original_request_id: [3; 16],
            host_boot_id: [4; 16],
            assignment_digest: [5; 32],
            source_record_digest: [6; 32],
            original_session_binding: [7; 32],
            original_signed_request_digest: [8; 32],
        };
        let marker = HostExecutionNoApplyRecordFieldsV1 {
            execution_id: original.execution_id,
            create_operation_id: original.create_operation_id,
            original_request_id: original.original_request_id,
            terminal_request_id: [9; 16],
            host_boot_id: original.host_boot_id,
            assignment_digest: original.assignment_digest,
            source_record_digest: original.source_record_digest,
            original_session_binding: original.original_session_binding,
            original_signed_request_digest: original.original_signed_request_digest,
            terminal_session_binding: [10; 32],
            terminal_signed_request_digest: [11; 32],
            runtime_handle: [12; 32],
            execution_store_binding: [13; 32],
            commit_sequence: 1,
        };
        assert!(HostExecutionNoApplyRecordV1::new(marker).is_ok());
        assert!(original.matches(marker));

        for foreign in [
            HostExecutionNoApplyRecordFieldsV1 {
                execution_id: [16; 16],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                create_operation_id: [16; 16],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                original_request_id: [16; 16],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                host_boot_id: [16; 16],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                assignment_digest: [16; 32],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                source_record_digest: [16; 32],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                original_session_binding: [16; 32],
                ..marker
            },
            HostExecutionNoApplyRecordFieldsV1 {
                original_signed_request_digest: [16; 32],
                ..marker
            },
        ] {
            assert!(!original.matches(foreign));
        }
    }

    #[test]
    fn original_request_frame_is_separate_from_storage_and_bound_to_its_id() {
        let request_id = [37; 16];
        let key = host_argument_archive_key(request_id);
        assert_eq!(key.len(), 24);
        assert_eq!(
            classified_broker_session_key(&key).unwrap().0,
            BrokerSessionJournalKeyKind::HostOriginalSessionArchive
        );
        assert_ne!(key, protocol_key(BrokerSessionProtocolV1::Host));

        let frame = encode_history_archive_frame(
            request_id,
            b"exact-signed-request-and-checkpoint",
            HOST_ARGUMENT_ARCHIVE_MAGIC,
            HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
        )
        .unwrap();

        assert_eq!(
            open_history_archive_frame(
                request_id,
                &frame,
                HOST_ARGUMENT_ARCHIVE_MAGIC,
                HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )
            .unwrap(),
            b"exact-signed-request-and-checkpoint"
        );
        assert!(open_atomic_storage_archive_frame(request_id, &frame).is_err());
        assert!(
            open_history_archive_frame(
                [38; 16],
                &frame,
                HOST_ARGUMENT_ARCHIVE_MAGIC,
                HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )
            .is_err()
        );

        let mut changed = frame;
        changed[STORAGE_GROUP_ARCHIVE_HEADER_BYTES] ^= 1;
        assert!(
            open_history_archive_frame(
                request_id,
                &changed,
                HOST_ARGUMENT_ARCHIVE_MAGIC,
                HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )
            .is_err()
        );
    }

    #[test]
    fn original_request_archive_survives_reopen_and_session_rollover() {
        let temporary = tempfile::tempdir().unwrap();
        let journal_path = temporary.path().join("session.journal");
        let request_id = [37; 16];
        let current_key = protocol_key(BrokerSessionProtocolV1::Host);
        let archive_key = host_argument_archive_key(request_id);
        let archive = encode_history_archive_frame(
            request_id,
            b"original-signed-request-and-checkpoint",
            HOST_ARGUMENT_ARCHIVE_MAGIC,
            HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
        )
        .unwrap();

        let (mut journal, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::BrokerSessionTraffic,
                            current_key.clone(),
                            b"original-session".to_vec(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::BrokerSessionTraffic,
                            archive_key.clone(),
                            archive.clone(),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        let (mut reopened, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        assert_eq!(
            reopened.get(RecordNamespace::BrokerSessionTraffic, &archive_key),
            Some(archive.as_slice())
        );
        reopened
            .commit(
                &JournalTransaction::new(
                    [2; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::BrokerSessionTraffic,
                        current_key.clone(),
                        b"successor-session".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(reopened);

        let (reopened, _) =
            Journal::open(&journal_path, protected_session_journal_limits()).unwrap();
        assert_eq!(
            reopened.get(RecordNamespace::BrokerSessionTraffic, &current_key),
            Some(b"successor-session".as_slice())
        );
        let retained = reopened
            .get(RecordNamespace::BrokerSessionTraffic, &archive_key)
            .unwrap();
        assert_eq!(
            open_history_archive_frame(
                request_id,
                retained,
                HOST_ARGUMENT_ARCHIVE_MAGIC,
                HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )
            .unwrap(),
            b"original-signed-request-and-checkpoint"
        );
        assert!(
            reopened
                .get(
                    RecordNamespace::BrokerSessionTraffic,
                    &host_argument_archive_key([38; 16]),
                )
                .is_none()
        );
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BrokerSessionSecurityError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BrokerSessionSecurityError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
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

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn require_original_storage_revalidation_healthy(&self)
        -> Result<(), BrokerSessionSecurityError>
    {
        match &self.journal.endpoint {
            ProtectedEndpointV1::Client(client) => client.require_original_storage_revalidation_healthy(),
            ProtectedEndpointV1::Broker(_) => Err(BrokerSessionSecurityError::Currentness),
        }
    }
}

// Only the exact returned indexed observation can name an archive cause.
// Unrelated canonical/history errors never select a later endpoint failure.
impl ProtectedEndpointV1 {
    pub(crate) fn retained_revalidation_failure_for(
        &self, error: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(endpoint) => endpoint.retained_revalidation_failure_for(error),
            Self::Broker(endpoint) => endpoint.retained_revalidation_failure_for(error),
        }
    }
}

impl ProtectedBrokerSessionJournalV1 {
    // Only this actual native return's transaction selects its parked cause.
    fn captured_mutation_failure_for_v1(&self, transaction: &[u8; 16])
        -> Option<&(dyn std::error::Error + 'static)>
    {
        let (actual, cause) = self.captured_native_failure.as_ref()?;
        if actual != transaction {
            return None;
        }
        self.journal.as_ref().and_then(Journal::retained_native_append_failure_v1)
            .or(Some(cause as &(dyn std::error::Error + 'static)))
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn retained_revalidation_failure_for(
        &self, error: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        if let BrokerSessionSecurityError::CapturedJournalMutation { transaction } = error {
            return self.journal.captured_mutation_failure_for_v1(transaction);
        }
        self.journal.endpoint.retained_revalidation_failure_for(error)
    }
}

impl BrokerMainOpenV1 {
    pub(crate) fn retained_revalidation_failure_for(
        &self, error: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        // Main opening moves the same endpoint into authority; it never opens
        // another endpoint or falls back to a globally remembered failure.
        self.authority.as_ref().map(|authority| &authority.endpoint)
            .or(self.endpoint.as_ref())?
            .retained_revalidation_failure_for(error)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn select_verified_storage_recover_slot_v1(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        genuine_recover_client: bool,
        genuine_storage_broker: bool,
        genuine_execution_cleanup_client: bool,
        genuine_stop_cleanup_client: bool,
        host_cleanup: Option<aos_sandbox_host::HostControlColdSessionPurposeV1>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let recover = aos_sandbox_broker_session_protocol::profile::
            is_storage_operator_recover_transcript_v1(transcript);
        if recover && !((genuine_recover_client && self.journal.endpoint.role()
                == BrokerSessionDurableEndpointV1::Client)
            || (genuine_storage_broker && self.journal.endpoint.role()
                == BrokerSessionDurableEndpointV1::Broker))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if genuine_recover_client && !recover {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let host_purpose = if aos_sandbox_broker_session_protocol::profile::is_host_stop_cleanup_transcript_v1(transcript) {
            Some(SessionPurpose::HostStopCleanup)
        } else if aos_sandbox_broker_session_protocol::profile::is_host_no_apply_cleanup_transcript_v1(transcript) {
            Some(SessionPurpose::HostNoApplyCleanup)
        } else { None };
        let execution_client = genuine_execution_cleanup_client
            && self.journal.endpoint.role() == BrokerSessionDurableEndpointV1::Client
            && host_purpose == Some(SessionPurpose::HostNoApplyCleanup)
            && transcript.protocol() == BrokerSessionProtocolV1::Host;
        if genuine_execution_cleanup_client && !execution_client {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let stop_client = genuine_stop_cleanup_client
            && self.journal.endpoint.role() == BrokerSessionDurableEndpointV1::Client
            && host_purpose == Some(SessionPurpose::HostStopCleanup)
            && transcript.protocol() == BrokerSessionProtocolV1::Host;
        if genuine_stop_cleanup_client && !stop_client {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if host_cleanup.is_none() && host_purpose.is_some() && !execution_client && !stop_client {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if let Some(financial) = host_cleanup {
            if financial != aos_sandbox_host::HostControlColdSessionPurposeV1::Bootstrap
                || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
                || transcript.protocol() != BrokerSessionProtocolV1::Host
            { return Err(BrokerSessionSecurityError::Currentness); }
            if host_purpose.is_none() {
                let ordinary = aos_sandbox_broker_session_protocol::profile::authenticated_broker_methods_for_role_v1(
                    BrokerSessionProtocolV1::Host,
                    aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER);
                if transcript.negotiated_methods() != ordinary { return Err(BrokerSessionSecurityError::Currentness); }
            }
        }
        self.journal.purpose = if let Some(purpose) = host_purpose {
            if !execution_client && !stop_client && (host_cleanup != Some(aos_sandbox_host::HostControlColdSessionPurposeV1::Bootstrap)
                || self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
                || transcript.protocol() != BrokerSessionProtocolV1::Host)
            { return Err(BrokerSessionSecurityError::Currentness); }
            purpose
        } else if recover {
            SessionPurpose::OperatorRecoverInventory
        } else {
            SessionPurpose::Ordinary
        };
        Ok(())
    }

    pub(crate) fn completed_initial_native_borrow_for_maintenance_v2<'held>(
        &'held self, receiving: &'held aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1,
    ) -> Result<aos_sandbox_controller_domain::ControllerInitialSessionCompletedNativeBorrowV1<'held>, BrokerSessionSecurityError> {
        let ProtectedEndpointV1::Client(endpoint) = &self.journal.endpoint else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let endpoint = endpoint.completed_initial_native_custody_v1()?;
        let main = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        receiving.borrow_completed_native_v1(main, endpoint).map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    /// Rejoins the actual completed receiver/main/endpoint to all four new roles.
    pub(crate) fn require_completed_recovered_initial_native_v2(
        &self,
        receiving: &aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1,
        context: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &aos_sandbox_controller_domain::Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let ProtectedEndpointV1::Client(endpoint) = &self.journal.endpoint else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let endpoint = endpoint.completed_initial_native_custody_v1()?;
        let main = self.journal.journal.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let completed = receiving.borrow_completed_native_v1(main, endpoint)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        completed.require_completed_recovered_ordinary_context_v2(
            context, bank, controller, profile)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn retire_completed_initial_native_v1(
        &mut self,
        receiving: &aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let ProtectedEndpointV1::Client(endpoint) = &self.journal.endpoint else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let endpoint = endpoint.completed_initial_native_custody_v1()?;
        let main = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let completed = receiving.borrow_completed_native_v1(main, endpoint)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.journal.floor.retire_completed_initial_native_v1(&completed, main)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn fixed_service_server_recipe_v4(
        &self, transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let endpoint = match transcript.protocol() {
            BrokerSessionProtocolV1::Network if aos_sandbox_broker_session_protocol::profile::is_network_service_transcript_v5(transcript)
                || aos_sandbox_broker_session_protocol::profile::is_network_inventory_transcript_v5(transcript) => ProtectedBrokerSessionFixedEndpointV1::NetworkBroker,
            BrokerSessionProtocolV1::Mount if aos_sandbox_broker_session_protocol::profile::is_mount_attachment_anchor_transcript_v4(transcript) => ProtectedBrokerSessionFixedEndpointV1::MountBroker,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if self.owner != JournalOwnerV1::RootBroker
            || self.directory != Path::new(fixed_endpoint(endpoint).journal_root)
            || self.name != PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || self.endpoint.protected_protocol_and_node().0 != transcript.protocol()
            || self.limits != protected_session_journal_limits()
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }
}


/// Private closed adapter implemented only by the actual fixed cold original.
///
/// The lender takes from a named protected captured-journal owner. There is no
/// public raw Journal, supplied-path or successful-marker implementation.
pub(crate) trait FixedServiceColdJournalReceivingV4 {
    fn fixed_endpoint_v4(&self) -> ProtectedBrokerSessionFixedEndpointV1;
    fn durable_endpoint_v4(&self) -> BrokerSessionDurableEndpointV1 { BrokerSessionDurableEndpointV1::Broker }
    fn host_cleanup_purpose_v1(&self) -> Option<aos_sandbox_host::HostControlColdSessionPurposeV1> { None }
    fn require_current_v4(&mut self) -> Result<(), BrokerSessionSecurityError>;
    fn take_captured_journal_v4(&mut self) -> Result<Journal, BrokerSessionSecurityError>;
}

impl BrokerMainOpenV1 {
    pub(crate) fn prepare_fixed_service_v4(
        root: &'static str, custody: &mut Option<FixedEndpointCustodyV1>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
        receiving: &mut dyn FixedServiceColdJournalReceivingV4,
    ) -> Result<Self, BrokerSessionSecurityError> {
        receiving.require_current_v4()?;
        let fixed = fixed_endpoint(receiving.fixed_endpoint_v4());
        let endpoint = match custody.as_ref() {
            Some(FixedEndpointCustodyV1::Broker(endpoint)) if receiving.durable_endpoint_v4() == BrokerSessionDurableEndpointV1::Broker => endpoint.protected_protocol_and_node(),
            Some(FixedEndpointCustodyV1::Client(endpoint)) if receiving.durable_endpoint_v4() == BrokerSessionDurableEndpointV1::Client => endpoint.protected_protocol_and_node(),
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if root != fixed.journal_root || endpoint.0 != fixed.protocol
            || !matches!(fixed.protocol, BrokerSessionProtocolV1::Mount | BrokerSessionProtocolV1::Network | BrokerSessionProtocolV1::Host)
        { return Err(BrokerSessionSecurityError::Currentness); }
        let directory = PathBuf::from(fixed.journal_root);
        let name = PROTECTED_SESSION_JOURNAL.to_owned();
        let endpoint = match custody.take() {
            Some(FixedEndpointCustodyV1::Broker(endpoint)) => ProtectedEndpointV1::Broker(endpoint),
            Some(FixedEndpointCustodyV1::Client(endpoint)) => ProtectedEndpointV1::Client(endpoint),
            _ => std::process::abort(),
        };
        Ok(Self { floor_preparation: None, authority: None, floor: None,
            endpoint: Some(endpoint), directory, name,
            limits: protected_session_journal_limits(), phase: BrokerMainOpenPhaseV1::Fresh,
            first_failure: None, cold_deadline: Some(deadline),
            #[cfg(feature = "online-nix")] online_schema: None })
    }

    pub(crate) fn open_fixed_service_v4(&mut self, receiving: &mut dyn FixedServiceColdJournalReceivingV4)
        -> Result<(), BrokerSessionSecurityError> {
        self.open_with_fixed_service_receiving_v4(None, None, None, Some(receiving))
    }
}

impl BrokerFloorOperationV1<'_> {
    fn open_fixed_service_main_v4(&mut self, protocol: BrokerSessionProtocolV1,
        receiving: &mut dyn FixedServiceColdJournalReceivingV4,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.check_cold_deadline()?;
        receiving.require_current_v4()?;
        let fixed = fixed_endpoint(receiving.fixed_endpoint_v4());
        if protocol != fixed.protocol || self.owner.owner != JournalOwnerV1::capture(receiving.durable_endpoint_v4())
            || self.owner.endpoint.role() != receiving.durable_endpoint_v4()
            || self.owner.directory != Path::new(fixed.journal_root)
            || self.owner.name != PROTECTED_SESSION_JOURNAL || self.owner.journal.is_some()
        { return Err(BrokerSessionSecurityError::Currentness); }
        // The same real captured native original performs this sole take;
        // park the returned writer before endpoint/schema/floor comparisons.
        self.owner.journal = Some(receiving.take_captured_journal_v4()?);
        self.owner.endpoint.revalidate()?;
        let floor = self.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        floor.bind_fixed_service_cold_v4(deadline).map_err(floor_revalidation::security_error)?;
        self.owner.validate_schema_only()?;
        self.attach()
    }
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    pub(crate) fn open_start_resource_retaining_v4(
        opening: &mut crate::endpoint::ProtectedBrokerSessionControllerClientOpeningV1,
        receiving: &mut aos_sandbox_controller_domain::StartResourceSessionOpeningLoanV2<'_>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let target = match receiving.actual_role_v2() {
            aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Network => ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
            aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Mount => ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
            aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Storage => ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let fixed = fixed_endpoint(target);
        opening.load_start_network_once_v2(receiving);
        let client = opening.completed_ref_v1().ok_or(BrokerSessionSecurityError::Currentness)?;
        let node = receiving.expected_node_v2().map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if client.protected_protocol_and_node() != (fixed.protocol, node) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let custody = opening.take_completed().ok_or(BrokerSessionSecurityError::Currentness)?;
        Ok(Self { journal_root: fixed.journal_root, protocol: fixed.protocol,
            audience: fixed.audience, socket_path: fixed.socket_path,
            custody: FixedEndpointCustodyV1::Client(custody) })
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn start_resource_journal_v4(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        let target = match self.journal.endpoint.protected_protocol_and_node().0 {
            BrokerSessionProtocolV1::Network => ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
            BrokerSessionProtocolV1::Mount => ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
            BrokerSessionProtocolV1::Storage => ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let fixed = fixed_endpoint(target);
        if self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.journal.endpoint.protected_protocol_and_node().0 != fixed.protocol
            || self.journal.directory != Path::new(fixed.journal_root)
            || self.journal.name != PROTECTED_SESSION_JOURNAL {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn start_resource_stored_v4(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        let journal = self.start_resource_journal_v4()?;
        journal.get(RecordNamespace::BrokerSessionTraffic,
            &protocol_key(self.journal.endpoint.protected_protocol_and_node().0))
            .ok_or(BrokerSessionSecurityError::Currentness)
    }
}

mod reconciliation_inventory;

// The primary is already parked on its Cold/MainOpen owner. The actual
// attachment alone decides whether its finite independent post remains owed.
fn finish_storage_failure_post_v2(owner: &mut ProtectedBrokerSessionJournalV1)
    -> Result<(), BrokerSessionSecurityError>
{
    if !owner.floor.storage_initial_failure_post_is_owed_v2() {
        return Ok(());
    }
    let mut operation = BrokerFloorOperationV1::begin(owner);
    let result = operation.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
        .observe_storage_initial_failure_post_v2(operation.owner)
        .map_err(floor_revalidation::security_error);
    operation.finish(result)
}

// Reborrows only the existing two mutually exclusive genuine F entries. This
// financial selection has no native constructor and cannot qualify a request.
fn borrow_storage_floor_source_v2<'borrow>(
    initial: &'borrow mut Option<&mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>>,
    lifecycle: &'borrow mut Option<(
        &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        aos_sandbox_model::ResourceVector,
    )>,
) -> Option<&'borrow mut (dyn tpm_floor::storage_receiving::StorageFloorFinancialSourceV2 + 'borrow)> {
    match (initial.as_deref_mut(), lifecycle.as_mut()) {
        (Some(source), None) => Some(source),
        (None, Some((source, _, _))) => Some(&mut **source),
        _ => None,
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    // This reuses the actual fixed ordinary Host Client recipe. It checks
    // location/custody only; the genuine maintenance loan supplies purpose,
    // current funding and the completed initial/recovered receiver association.
    pub(crate) fn catalog_maintenance_client_journal_v2(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        if self.journal.delete_inventory_client_method_v1()? != BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn catalog_maintenance_client_stored_v2(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.catalog_maintenance_client_journal_v2()?
            .get(RecordNamespace::BrokerSessionTraffic, &protocol_key(BrokerSessionProtocolV1::Host))
            .ok_or(BrokerSessionSecurityError::Currentness)
    }
}

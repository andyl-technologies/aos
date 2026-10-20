//! Shares the actual protected Session schema and receiving geometry.
//!
//! These fixed recipes and reached-history footprints are passive DATA. They
//! perform no IO, replay, payment or authority construction. Actual role owners
//! retain their native prefix and use their own genuine ledger before growth.

mod network_client;
pub use network_client::{
    network_prepare_client_request_additional_demand_v2,
    network_inventory_client_response_decode_demand_v2,
};

mod create_storage_use;
mod host_execution_argument;
pub use host_execution_argument::{
    host_execution_argument_client_demand_v1,
    execution_output_client_demand_v1,
    host_execution_authorize_observe_client_demand_v2,
    host_stop_client_demand_v4, host_stop_inventory_client_demand_v5,
};
pub use create_storage_use::{StorageCreateUseSecurityShapeDataV1,
    storage_create_use_prefix_receiving_demand_v1, storage_create_use_receiving_demand_v1, storage_create_use_signing_receiving_demand_v1};

use std::mem::size_of;

use aos_sandbox_broker_session_protocol::receiving_geometry::{
    ReceivingGeometryRefusalV1,
    protobuf_carriers_v1 as protobuf_carriers,
    schema_protobuf_carriers_v1 as schema_protobuf_carriers,
    inventory_repeated_width_v1 as inventory_repeated_width,
};

use aos_sandbox_broker_session_protocol::manifest::BROKER_SESSION_MANIFEST_BYTES;
use aos_sandbox_broker_session_protocol::{BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, SERVER_HELLO_MAXIMUM_BYTES};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

use aos_sandbox_api::aos::sandbox::local::v1::{
    AssignmentFence, BrokerAuthorizationArtifactsV1,
    BrokerDescriptorEntry, BrokerMethod,
    BrokerRequestEnvelope, BrokerResponseEnvelope, BrokerSemanticBindingsV1, Descriptor, Feature,
    RequestHeader,
};
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES,
    AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
    BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES, BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_RECORDS,
    BROKER_SESSION_OUTCOME_COMPANION_BYTES, BROKER_SESSION_REQUEST_COMPANION_BYTES,
    BrokerSessionDurableRecordV1, BrokerSessionTrafficStateV1, CLIENT_HELLO_MAXIMUM_BYTES,
    VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_model::{FeatureRef, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalSessionCheckpointV1, MAXIMUM_BYTES as CHECKPOINT_BYTES,
};
use aos_sandbox_protocol::authenticated_session::stored_history::VALUE_FIXED_BYTES_V3;
use aos_sandbox_protocol::{
    MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS, ValidatedStorageWorkspace,
};

use aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryV1;

use aos_sandbox_broker_session_protocol::artifact::BrokerSessionArtifactVerifyCaptureV1;
use aos_sandbox_broker_session_protocol::context::BrokerSessionContextCheckpointDecodeCaptureV1;
use aos_sandbox_broker_session_protocol::{
    BROKER_REQUEST_SUBJECT_BYTES, BROKER_OUTCOME_SUBJECT_BYTES,
    SIGNED_BROKER_REQUEST_BYTES, SIGNED_BROKER_OUTCOME_BYTES,
};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
    HistoricalSessionCheckpointDecodeCaptureV1, HistoricalSessionCheckpointVerifyCaptureV1,
};

use super::{JournalLimits, ProtectedJournalPreopenReplayExtentV1};

// The fixed durable header precedes its mandatory request companion. Ignoring
// the nonempty packet and per-history length prefix gives a safe row lower bound.
const DURABLE_FIXED_HEADER_BYTES: u64 = 8 + 2 + 4 + 8 + 5 * 32 + 16 + 2 * 8 + 4 + 4 * 32 + 2 * 4;
const RECEIPT_TURNS: u64 = 2;
const DURABLE_SUCCESSORS: u64 = 2 * RECEIPT_TURNS;

/// Names the existing fixed Controller Storage Client journal root.
pub const CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1: &str = "/var/lib/aos/sandboxd/broker-session/storage";

/// Names the existing fixed protected Session journal basename.
pub const PROTECTED_SESSION_JOURNAL_V1: &str = "session.journal";

/// Bounds the existing current protocol rows in one protected Session writer.
pub const MAXIMUM_PROTOCOL_RECORDS: usize = 4;

/// Bounds the existing retained Storage group archives.
pub const MAXIMUM_STORAGE_GROUP_ARCHIVES: usize = 16;

/// Bounds the existing retained Storage Inventory archives.
pub const MAXIMUM_STORAGE_INVENTORY_ARCHIVES: usize = 16;

/// Bounds the existing retained Storage Inventory abandonment rows.
pub const MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS: usize = 16;

/// Bounds the existing retained Host argument archives.
pub const MAXIMUM_HOST_ARGUMENT_ARCHIVES: usize = 16;

/// Bounds the existing retained Host terminal archives.
pub const MAXIMUM_HOST_TERMINAL_ARCHIVES: usize = MAXIMUM_HOST_ARGUMENT_ARCHIVES;

/// Reports checked passive representation geometry refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("protected Session representation geometry is invalid or overflows")]
pub struct StorageSessionGeometryRefusalV1;

impl From<ReceivingGeometryRefusalV1> for StorageSessionGeometryRefusalV1 {
    fn from(_: ReceivingGeometryRefusalV1) -> Self {
        Self
    }
}

/// Returns the existing compiled protected Session writer and reader limits.
#[must_use]
pub fn protected_session_journal_limits_v1() -> JournalLimits {
    let maximum_record_bytes = BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
        + VALUE_FIXED_BYTES_V3
        + CHECKPOINT_BYTES
        + 1024;
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes,
        maximum_key_bytes: 24,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 2 * maximum_record_bytes + 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: (MAXIMUM_PROTOCOL_RECORDS
            + MAXIMUM_STORAGE_GROUP_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS
            + MAXIMUM_HOST_ARGUMENT_ARCHIVES
            + MAXIMUM_HOST_TERMINAL_ARCHIVES)
            * maximum_record_bytes,
        maximum_materialized_records: MAXIMUM_PROTOCOL_RECORDS
            + MAXIMUM_STORAGE_GROUP_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ARCHIVES
            + MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS
            + MAXIMUM_HOST_ARGUMENT_ARCHIVES
            + MAXIMUM_HOST_TERMINAL_ARCHIVES,
    }
}

/// Prices upper schema objects before the existing schema validator runs.
///
/// # Errors
///
/// Refuses inconsistent prefix bounds or unrepresentable checked demand.
pub fn schema_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    schema_demand_for_prefix_bytes_v3(checked_prefix(extent)?)
}

/// Prices the same signed-history model within a protected historical carrier.
///
/// The actual containing row bounds the embedded prefix before its sole full
/// decoder runs. This passive bound opens no Session or receiving interval.
///
/// # Errors
/// Rejects unrepresentable checked model or archive geometry.
pub fn historical_signed_session_model_demand_v4(encoded_bound: usize)
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1>
{
    schema_demand_for_prefix_bytes_v3(as_u64(encoded_bound)?)
}

// One mechanical supplier describes the same stored/history/checkpoint and
// authenticated method models whether borrowed from a native Session prefix
// or the exact immutable copy of that prefix in a Controller Capture anchor.
fn schema_demand_for_prefix_bytes_v3(prefix: u64)
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1>
{
    let depth = add(as_u64(MAXIMUM_STORAGE_INVENTORY_ARCHIVES)?, 4)?;
    let rows = reached_history_rows(prefix)?;
    let carrier_slots = history_carriers(rows, depth)?;

    // Each recursive archive can retain stored bytes, a decoded history and
    // canonical encodings. The extra transient lanes cover bounded archive
    // lists, readback copies, current history, traffic and authenticated joins.
    let copies = add(mul(depth, 6)?, 16)?;
    let encoded = mul(prefix, copies)?;
    let inline = mul(depth, inline_context_bytes()?)?;
    let checkpoint_copies = mul(4, prefix.min(mul(depth, as_u64(CHECKPOINT_BYTES)?)?))?;
    let proto = if prefix == 0 {
        0
    } else {
        schema_protobuf_carriers(prefix, depth)?
    };
    let inventory = inventory_validation_carriers(prefix)?;
    let memory = sum(&[carrier_slots, encoded, inline, checkpoint_copies, proto, inventory])?;

    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
}

/// Prices the sole complete Source944 anchor and its historical signed model.
///
/// # Errors
/// Refuses invalid canonical payload widths or checked representation overflow.
pub fn controller_capture_anchor_model_demand_ongoing_v4(response_bytes: usize, history_bytes: usize)
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1>
{
    let encoded = aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1::encoded_len_ongoing_v4(
        response_bytes, history_bytes).ok_or_else(invalid)?;
    let model = schema_demand_for_prefix_bytes_v3(as_u64(encoded)?)?;
    let encoding = encoded.checked_mul(3)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
            aos_sandbox_protocol::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1>()
            .checked_mul(2)?)).ok_or_else(invalid)?;
    model.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, as_u64(encoding)?))
        .map_err(|_| invalid())
}

/// Prices the longer resident selected readbacks and their active partial codec.
///
/// Two complete Stored-row sets remain beside the original History/Traffic;
/// one additional Snapshot also remains. Each encoded lane uses the actual held
/// prefix, including malformed raw Record lengths before semantic packet caps.
/// Failed pure leaves stop primary growth; complete scratch physically drops
/// before another leaf enters, so no lifetime-row multiplier is introduced.
///
/// # Errors
/// Refuses an invalid captured prefix or checked geometry overflow.
fn storage_retained_partial_replay_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let prefix = checked_prefix(extent)?;
    // Before+after whole Stored rows and the additional retained Snapshot.
    // Three widths cover each Vec's live/growing/reallocation backing.
    let retained_wire = mul(prefix, 3 * (2 + 1))?;
    let hello = prefix.min(as_u64(CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)
        .ok_or_else(invalid)?)?);
    let hello = usize::try_from(hello).map_err(|_| invalid())?;
    let checkpoint = as_u64(HistoricalSessionCheckpointDecodeCaptureV1::receiving_nonprojection_heap_bytes_v1(hello)
        .ok_or_else(invalid)?)?;
    // Two Hello models and one active split encoder coexist at verification.
    // The same narrow schema recipe also covers the active malformed child
    // representation; it does not multiply whole models by Native row count.
    let hello_models = if hello == 0 { 0 } else { mul(3, schema_protobuf_carriers(as_u64(hello)?, 1)?)? };
    let partial_child = if prefix == 0 { 0 } else { schema_protobuf_carriers(prefix, 1)? };
    let crypto = as_u64(BrokerSessionArtifactVerifyCaptureV1::receiving_heap_bytes_v1().ok_or_else(invalid)?)?;
    let companion = codec_companion_transient_bytes()?;
    // At most one parent Stored row per key in each actual read. Context keys
    // are fixed four-entry DATA; the raw HELLO/history Vecs are above.
    let contexts = mul(mul(2, as_u64(MAXIMUM_PROTOCOL_RECORDS)?)?,
        as_u64(BrokerSessionContextCheckpointDecodeCaptureV1::receiving_heap_bytes_v1())?)?;
    let memory = sum(&[retained_wire, checkpoint, hello_models, partial_child, crypto,
        companion, contexts, 512, 9])?;
    let table_cells = as_u64(HistoricalSessionCheckpointDecodeCaptureV1::receiving_table_metadata_cells_v1(hello)
        .ok_or_else(invalid)?)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        // Companion2, parser Strings2, canonical key1, added Snapshot backing1
        // and two genuine Native geometry Results are distinct retained cells.
        .with(D::MetadataEntries, add(table_cells, 8)?))
}

/// Prices the complete retained current-replay dynamic frontier.
///
/// The genuine operation owner supplies the SAME held Journal's captured
/// extent before growth. Fixed Security owner layouts and an old HELLO whose
/// traffic history is absent are admitted separately by their actual suppliers.
///
/// # Errors
/// Refuses an invalid actual extent or checked geometry overflow.
pub fn storage_retained_current_replay_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    schema_demand(extent)?
        .checked_add(storage_retained_partial_replay_demand_v1(extent)?)
        .map_err(|_| invalid())
}

/// Prices one additional retained prior-traffic reconstruction.
///
/// The actual terminal comparison replays the borrowed preceding records while
/// the completed full replay remains resident. No Stored read or History Vec
/// is duplicated here. Complete descriptor-count scratch drops before method
/// admission; failed scratch remains in this same exclusive active frontier.
///
/// # Errors
/// Refuses an inconsistent actual extent or checked geometry overflow.
pub fn storage_retained_traffic_reconstruction_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let prefix = checked_prefix(extent)?;
    if prefix == 0 { return Ok(ResourceVector::ZERO); }
    let maximum_hello = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)
        .ok_or_else(invalid)?;
    let hello = usize::try_from(prefix.min(as_u64(maximum_hello)?)).map_err(|_| invalid())?;
    // The old completed packet, its candidate-state clone, the new response
    // before replacement, and the canonical signed admission bytes coexist.
    let encoded = mul(prefix, 4 * 3)?;
    // One reached decoded packet plus the v1 encoder's one split clone.
    let projection = mul(2, schema_protobuf_carriers(prefix, 1)?)?;
    // The first request's key-proof update can hold the evolving transcript,
    // its candidate-state clone and the replacement proved transcript at once.
    let transcript = mul(3, as_u64(
        HistoricalSessionCheckpointVerifyCaptureV1::receiving_nonprojection_heap_bytes_v1(hello)
            .ok_or_else(invalid)?)?)?;
    let transcript_cells = mul(3, as_u64(
        HistoricalSessionCheckpointVerifyCaptureV1::receiving_table_metadata_cells_v1(hello)
            .ok_or_else(invalid)?)?)?;
    let state = mul(3, as_u64(size_of::<BrokerSessionTrafficStateV1>())?)?;
    let crypto = as_u64(BrokerSessionArtifactVerifyCaptureV1::receiving_heap_bytes_v1()
        .ok_or_else(invalid)?)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, sum(&[encoded, projection, transcript, state, crypto, 512])?)
        // Four byte-owner controls, three boxed/state carriers, two parser
        // diagnostics and this actual Native demand Result are separate cells.
        .with(D::MetadataEntries, add(transcript_cells, 10)?))
}

/// Prices old HELLO verification independently of an empty Native history.
///
/// The closed Security producer obtains this extent from the SAME retained
/// checkpoint before any clone, encode or native work. It is passive DATA;
/// only the genuine original J derives and admits this demand.
///
/// # Errors
/// Refuses an empty/excessive extent or checked geometry overflow.
pub fn storage_client_checkpoint_verification_demand_v1(
    actual_hello_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    client_checkpoint_verification_demand_v4(actual_hello_bytes, CheckpointReceivingPurposeV4::Storage)
}

/// Prices the new Network opening's pure checkpoint verifier before any IO.
///
/// The fixed maximum comes from the same two canonical HELLO codecs. These
/// decoding models and parser tables have byte backing, not named namespaces.
///
/// # Errors
/// Refuses arithmetic overflow in the actual shared decoder/model recipe.
pub(crate) fn start_network_checkpoint_verification_demand_v4()
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let maximum = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)
        .ok_or_else(invalid)?;
    client_checkpoint_verification_demand_v4(maximum, CheckpointReceivingPurposeV4::StartNetwork)
}

#[derive(Clone, Copy)]
enum CheckpointReceivingPurposeV4 {
    Storage,
    StartNetwork,
}

fn client_checkpoint_verification_demand_v4(
    actual_hello_bytes: usize,
    purpose: CheckpointReceivingPurposeV4,
)
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let maximum = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)
        .ok_or_else(invalid)?;
    if actual_hello_bytes == 0 || actual_hello_bytes > maximum { return Err(invalid()); }
    let bytes = as_u64(actual_hello_bytes)?;
    let nonprojection = as_u64(HistoricalSessionCheckpointVerifyCaptureV1::receiving_nonprojection_heap_bytes_v1(actual_hello_bytes)
        .ok_or_else(invalid)?)?;
    let models = mul(3, schema_protobuf_carriers(bytes, 1)?)?;
    let cells = as_u64(HistoricalSessionCheckpointVerifyCaptureV1::receiving_table_metadata_cells_v1(actual_hello_bytes)
        .ok_or_else(invalid)?)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, sum(&[nonprojection, models, 512])?)
        .with(D::MetadataEntries, match purpose {
            CheckpointReceivingPurposeV4::Storage => add(cells, 2)?,
            CheckpointReceivingPurposeV4::StartNetwork => 0,
        }))
}

fn codec_companion_transient_bytes() -> Result<u64, StorageSessionGeometryRefusalV1> {
    let request = BROKER_REQUEST_SUBJECT_BYTES.checked_add(SIGNED_BROKER_REQUEST_BYTES)
        .ok_or_else(invalid)?;
    let outcome = BROKER_OUTCOME_SUBJECT_BYTES.checked_add(SIGNED_BROKER_OUTCOME_BYTES)
        .ok_or_else(invalid)?;
    as_u64(request.max(outcome))
}

/// Prices hostile Inventory response decoding before typed allocation.
///
/// The caller supplies the length of the actual retained authenticated response
/// packet. The signed outer envelope and its inner Inventory model may coexist,
/// so both use the shared reached-schema carrier bound. This deliberately keeps
/// the pre-validation singular-child allowance: a malformed response has not
/// passed the Domain producer's workspace-count restriction.
///
/// Existing raw receive storage, fixed native owners and protected history
/// replay remain separate. This passive bound supplies neither authentication
/// nor a receiving payer; the genuine Client original must admit it before the
/// corresponding decoder grows any typed representation.
///
/// # Errors
///
/// Refuses a packet beyond the existing authenticated response ceiling or
/// unrepresentable checked demand.
pub fn storage_inventory_client_response_decode_demand_v1(
    retained_packet_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if retained_packet_bytes > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
        return Err(invalid());
    }
    let bytes = as_u64(retained_packet_bytes)?;
    let schemas = mul(2, schema_protobuf_carriers(bytes, 1)?)?;
    let validated = inventory_validation_carriers(bytes)?;

    Ok(ResourceVector::ZERO.with(D::MemoryBytes, add(schemas, validated)?))
}

/// Prices post-replay checkpoint and Session initialization before packet receipt.
///
/// Initial request installation belongs to request_demand, not this stage.
/// Existing loaded credentials, HELLO frames and fixed raw FD pool are separate.
///
/// # Errors
///
/// Refuses an invalid captured extent or arithmetic overflow.
pub fn initialization_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    checked_prefix(extent)?;
    fixed_initialization_demand_v1()
}

/// Prices the existing fixed HELLO checkpoint and initialization carriers.
///
/// The actual constant models do not depend on a historical prefix. A closed
/// initial Client recipe uses this DATA before its pre-main checkpoint grows;
/// no synthetic replay extent or caller maximum is needed.
///
/// # Errors
/// Refuses unrepresentable checked model geometry.
pub fn fixed_initialization_demand_v1()
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1>
{
    let checkpoint = mul(6, as_u64(CHECKPOINT_BYTES)?)?;
    let inline = mul(4, inline_context_bytes()?)?;
    let hello_verification = protobuf_carriers(
        as_u64(CLIENT_HELLO_MAXIMUM_BYTES)?,
        as_u64(size_of::<Feature>())?,
    )?;

    Ok(ResourceVector::ZERO.with(D::MemoryBytes, sum(&[checkpoint, inline, hello_verification])?))
}

/// Prices both retained Inventory/Prepare requests before their first receipt.
///
/// Requires the private selected-method gate before semantic body decoding.
/// Actual Inventory production and each observed outcome are separate stages.
/// The caller supplies only its actual private sender-layout sizes as DATA;
/// these amounts neither admit work nor construct a role payer.
/// The schema reservation stays held for captured baseline histories. One shared
/// transient decoder lane serves later outcomes: accepted request owners retain
/// opaque/canonical bytes, not hostile Buffa models. Ambiguity retains owners
/// and closes the cycle instead of reusing that lane.
///
/// # Errors
///
/// Refuses a changed extent shape or unrepresentable checked demand.
pub fn request_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    send_bytes: usize,
    send_cells: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    request_representation_demand_v1(extent, send_bytes, send_cells,
        AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, RECEIPT_TURNS, DURABLE_SUCCESSORS)
}

/// Prices the selected header-only Inventory request before signing.
///
/// Prepare has a separate actual original and is not provisioned or authorized
/// by this single Inventory operation. The closed Security constructor checks
/// its actual encoded request against the same format-owner derived bound.
///
/// # Errors
/// Refuses invalid actual prefix geometry or checked arithmetic overflow.
pub fn storage_inventory_client_request_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    request_representation_demand_v1(extent, 0, 0,
        aos_sandbox_protocol::fixed_storage_inventory_request_packet_bound_v1(), 1, 2)
}

/// Prices the actual closed Create Prepare request before signing and CAS.
///
/// The caller supplies only the common format-derived encoded shape width;
/// its genuine U issuer must independently compare the actual private caller
/// and authenticated Root original. This passive supplier creates no grant.
///
/// # Errors
/// Rejects an empty/over-ceiling width, invalid prefix or checked overflow.
pub fn storage_create_prepare_client_request_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    encoded_request_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if encoded_request_bytes == 0
        || encoded_request_bytes > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(invalid());
    }
    request_representation_demand_v1(extent, 0, 0, encoded_request_bytes, 1, 2)
}

/// Prices the unchanged canonical producer's successful Prepare outcome.
///
/// The stored-row bound comes from the actual held native prefix. A genuine
/// caller separately retains and pays the full raw15MiB receive profile, then
/// recomputes actual response/decode demand before any further allocation. A
/// larger hostile model may exhaust U without changing any wire/semantic cap.
///
/// # Errors
/// Rejects invalid actual prefix/width or checked shared representation overflow.
pub fn storage_create_prepare_client_positive_outcome_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    encoded_request_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if encoded_request_bytes == 0
        || encoded_request_bytes > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(invalid());
    }
    let stored = usize::try_from(checked_prefix(extent)?).map_err(|_| invalid())?;
    outcome_representation_demand_v1(extent, stored, encoded_request_bytes,
        aos_sandbox_protocol::semantics::storage_prepare::
            storage_catalog_preparation_response_body_bound_v1())
}

fn request_representation_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1, send_bytes: usize, send_cells: usize,
    request_bytes: usize, turns: u64, successors: u64,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let prefix = checked_prefix(extent)?;
    let request = as_u64(request_bytes)?;
    let packet_copies = mul(turns, mul(16, request)?)?;
    let rows = history_carriers(successors, 8)?;
    let proto = protobuf_carriers(request, as_u64(size_of::<BrokerDescriptorEntry>())?)?;
    let memory = sum(&[packet_copies, rows, proto, mul(8, inline_context_bytes()?)?, as_u64(send_bytes)?])?;

    // Baseline copies remain covered by the held schema lane. New request
    // payloads/slots are bounded here; the Inventory outcome stage later pays
    // its actual terminal and the following request's enlarged append width.
    let baseline = prefix.min(as_u64(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)?);
    let new_requests = mul(turns, sum(&[
        request,
        DURABLE_FIXED_HEADER_BYTES,
        as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
        4,
    ])?)?;
    let storage = append_bytes(extent, add(baseline, new_requests)?, turns)?;

    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(D::MetadataEntries, as_u64(send_cells)?)
        .with(D::StorageBytes, storage))
}

/// Prices one actual parked observed response before envelope/sign/history growth.
///
/// Inputs are borrowed by the parent from the same admitted map, authenticated
/// request and retained observation. The original Domain response Vec is already
/// paid by its producer; only additional representations are charged here.
/// Refusal must leave that original response and Session in their owning slots.
///
/// # Errors
///
/// Refuses over-ceiling actual bodies or arithmetic/Native width overflow.
pub fn outcome_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    current_stored: &[u8],
    request: &[u8],
    observed_body: &[u8],
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    outcome_representation_demand_v1(extent, current_stored.len(), request.len(), observed_body.len())
}

fn outcome_representation_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    current_stored_bytes: usize,
    encoded_request_bytes: usize,
    observed_body_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    checked_prefix(extent)?;
    let request_bytes = as_u64(encoded_request_bytes)?;
    let body_bytes = as_u64(observed_body_bytes)?;
    if encoded_request_bytes > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
        || observed_body_bytes > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
        return Err(invalid());
    }

    let packet = response_packet_bytes(body_bytes)?;
    let terminal = sum(&[
        DURABLE_FIXED_HEADER_BYTES,
        as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
        request_bytes,
        as_u64(BROKER_SESSION_OUTCOME_COMPANION_BYTES)?,
        packet,
        4,
    ])?;
    let history = add(as_u64(current_stored_bytes)?, terminal)?;
    let rows = add(reached_history_rows(as_u64(current_stored_bytes)?)?, 2)?;
    let memory = sum(&[
        mul(16, history)?,
        mul(12, add(packet, request_bytes)?)?,
        history_carriers(rows, 6)?,
        inventory_model_carriers(body_bytes)?,
        inventory_validation_carriers(body_bytes)?,
        mul(8, inline_context_bytes()?)?,
    ])?;

    // This terminal and the possible next request are funded before either
    // enlarged history is appended. No budget or effect grant is refunded.
    let next_request = sum(&[
        as_u64(AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES)?,
        DURABLE_FIXED_HEADER_BYTES,
        as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
        4,
    ])?;
    let storage = append_bytes(extent, add(history, next_request)?, 2)?;

    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(D::StorageBytes, storage))
}

/// Prices a reusable exact terminal replay lane, with no new CAS or effect.
///
/// The parent borrows the actual current carrier and original committed pair.
/// Reuse requires exact resend plus positive original Session/native/deadline
/// closure. Failure retains the lane and closes receiving without a refund.
///
/// # Errors
///
/// Refuses invalid extent or unrepresentable checked representation demand.
pub fn replay_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    current_stored: &[u8],
    committed_request: &[u8],
    committed_outcome: &[u8],
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    checked_prefix(extent)?;
    let stored = as_u64(current_stored.len())?;
    let packets = add(as_u64(committed_request.len())?, as_u64(committed_outcome.len())?)?;
    let memory = sum(&[
        mul(8, stored)?,
        mul(8, packets)?,
        as_u64(AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES)?,
        history_carriers(reached_history_rows(stored)?, 4)?,
        mul(4, inline_context_bytes()?)?,
    ])?;

    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
}

// Linux bounds each successfully resolved pathname. This provision covers
// simultaneous protected-file, immutable-mode and procfs path/error carriers;
// it does not reinterpret their strings as authority.
const PATH_BYTES: usize = 4096;
const PATH_CARRIERS: usize = 32;
const CONTROL_BYTES: usize = 64 * 1024;
const SECRET_BYTES: usize = 48;

// The flight retains both original packets, their cleared/canonical encodings,
// verification copies and historical checkpoint copies. Four complete pairs
// also cover the corresponding decoded/cleared models and partial failures.
const MODEL_PAIRS: usize = 4;
const RAW_COPIES: usize = 8;

/// Describes actual private fixed HELLO representation layouts as passive DATA.
///
/// Each owning Security producer derives these named sizes from its actual
/// retained types/heap suppliers. This DATA has no account, caller identity,
/// resource ceiling, endpoint, constructor or admission effect.
#[derive(Clone, Copy)]
pub struct StorageHandshakePrivateFootprintV1 {
    /// Actual sum of private inline owner layouts; heap payloads are separate.
    pub actual_inline_bytes: usize,
    /// Actual retained error/reducer heap bytes supplied by their owning types.
    pub actual_failure_bytes: usize,
    /// Actual retained failure control cells supplied by their owning types.
    pub actual_failure_cells: usize,
}

/// Prices the shared fixed HELLO model/raw/native representation recipe.
///
/// Private actual owner layout remains with each producer. Raw receive demand
/// comes from the same Linux strict selected receiver; no second parser or
/// generic role payer is introduced. A genuine operation original must admit
/// the result before any actual allocation, endpoint load or raw flight.
///
/// # Errors
/// Refuses checked geometry overflow. This supplier authorizes no work.
pub fn fixed_handshake_receiving_demand(private: StorageHandshakePrivateFootprintV1)
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1>
{
    fixed_handshake_receiving_demand_for_purpose(private, HandshakeGeometryPurposeV2::Legacy)
}

// Only the old public recipe preserves its historical control-cell invoice.
// A genuine new Start lender uses the same Memory/FD/staging calculation;
// pure HELLO/protobuf/carrier fields are not a protected namespace entry.
#[derive(Clone, Copy)]
enum HandshakeGeometryPurposeV2 { Legacy, StartNetwork }

fn fixed_handshake_receiving_demand_for_purpose(
    private: StorageHandshakePrivateFootprintV1, purpose: HandshakeGeometryPurposeV2,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let refused = || StorageSessionGeometryRefusalV1;
    let hello_bytes = CLIENT_HELLO_MAXIMUM_BYTES
        .checked_add(SERVER_HELLO_MAXIMUM_BYTES)
        .ok_or_else(refused)?;
    let carrier_cell = size_of::<buffa::UnknownField>()
        .checked_add(size_of::<i32>())
        .ok_or_else(refused)?;
    let model_bytes = hello_bytes
        .checked_mul(carrier_cell)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_mul(MODEL_PAIRS))
        .ok_or_else(refused)?;
    let raw_bytes = hello_bytes
        .checked_mul(RAW_COPIES)
        .and_then(|bytes| bytes.checked_add(4 * BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES))
        .and_then(|bytes| bytes.checked_add(4 * BROKER_SESSION_MANIFEST_BYTES))
        .and_then(|bytes| bytes.checked_add(8 * SECRET_BYTES))
        .ok_or_else(refused)?;

    // These actual layouts include the retained floor/ordinary-cold state,
    // partial handshake, endpoint owners, descriptor slots and Result fields.
    // Heap payloads are charged separately above and below, not inferred from
    // the size of an owning Vec, Box, or Arc header.
    let inline_bytes = private.actual_inline_bytes;
    // The selected HELLO and request paths use the same strict 80-byte
    // ancillary profile. Pay its complete retaining receive footprint before
    // the first sample, including malformed rights received before rejection.
    // Endpoint and cold-opening originals remain resident alongside that peak.
    let maximum_hello_bytes = CLIENT_HELLO_MAXIMUM_BYTES.max(SERVER_HELLO_MAXIMUM_BYTES);
    let (receive_bytes, receive_slots) =
        SeqpacketSocket::storage_preparation_receive_obligations_v1(maximum_hello_bytes)
            .ok_or_else(refused)?;
    // The selected reducer forwards the same owning failure reservoir
    // through both public error layers. Its actual boxed payloads are priced
    // independently from the lower raw receive and inline activation state.
    let (failure_bytes, failure_cells) = (private.actual_failure_bytes, private.actual_failure_cells);
    let open_files = receive_slots.checked_add(32).ok_or_else(refused)?;
    let descriptor_inspection = receive_slots
        .checked_mul(2 * PATH_BYTES + CONTROL_BYTES)
        .ok_or_else(refused)?;
    let path_bytes = PATH_BYTES
        .checked_mul(PATH_CARRIERS)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(refused)?;
    let memory = model_bytes
        .checked_add(raw_bytes)
        .and_then(|bytes| bytes.checked_add(inline_bytes))
        .and_then(|bytes| bytes.checked_add(path_bytes))
        .and_then(|bytes| bytes.checked_add(CONTROL_BYTES))
        .and_then(|bytes| bytes.checked_add(descriptor_inspection))
        .and_then(|bytes| bytes.checked_add(receive_bytes))
        .and_then(|bytes| bytes.checked_add(failure_bytes))
        .ok_or_else(refused)?;
    let cells = match purpose {
        HandshakeGeometryPurposeV2::Legacy => hello_bytes
            .checked_mul(2 * MODEL_PAIRS)
            .and_then(|cells| cells.checked_add(PATH_CARRIERS + receive_slots))
            .and_then(|cells| cells.checked_add(failure_cells))
            .ok_or_else(refused)?,
        // No protected Session/schema/index row exists in this fixed pure
        // HELLO representation. The genuine caller separately admits actual
        // endpoint/native and captured Journal/schema/initialization entries.
        HandshakeGeometryPurposeV2::StartNetwork => 0,
    };

    let memory = u64::try_from(memory).map_err(|_| refused())?;
    let cells = u64::try_from(cells).map_err(|_| refused())?;
    let staging = u64::try_from(raw_bytes).map_err(|_| refused())?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(
            D::OpenFiles,
            u64::try_from(open_files).map_err(|_| refused())?,
        )
        .with(D::MetadataEntries, cells)
        .with(D::PublicationStagingBytes, staging))
}

/// Prices the closed initial Controller Client's three-flight HELLO geometry.
///
/// This uses the same model, buffer and native receiver recipe. The Client
/// connects once, receives Publication, sends ClientHello without descriptors,
/// then receives ServerHello. The prior publication subject remains held during
/// the second receive and both subjects survive into Cold. The bound covers
/// hostile rights installed before ancillary refusal; expected-zero grammar
/// supplies no zero-FD credit. Broker/ordinary users retain their old bound.
///
/// # Errors
/// Refuses checked native geometry conversion or arithmetic overflow.
pub fn fixed_controller_client_handshake_receiving_demand(
    private: StorageHandshakePrivateFootprintV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    fixed_controller_client_handshake_for_purpose_v2(private, HandshakeGeometryPurposeV2::Legacy)
}

/// Prices the same finite HELLO representation for a genuine new Start Network client.
///
/// Memory, staging and reached native descriptor geometry are shared with the
/// existing Controller Client helper. Rust/protobuf/control fields add no
/// namespace entry. Actual fixed endpoint, floor, protected Journal, schema and
/// publication rows must be separately invoiced by that owning Start lender.
/// This is passive cost DATA and can mint no receiving/native/HELLO permission.
///
/// # Errors
/// Refuses checked compiled-layout, native width or arithmetic overflow.
pub fn fixed_start_network_client_handshake_receiving_demand_v2(
    private: StorageHandshakePrivateFootprintV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    fixed_controller_client_handshake_for_purpose_v2(private, HandshakeGeometryPurposeV2::StartNetwork)
}

fn fixed_controller_client_handshake_for_purpose_v2(
    private: StorageHandshakePrivateFootprintV1, purpose: HandshakeGeometryPurposeV2,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    let refused = || StorageSessionGeometryRefusalV1;
    let demand = fixed_handshake_receiving_demand_for_purpose(private, purpose)?;
    let maximum = CLIENT_HELLO_MAXIMUM_BYTES.max(SERVER_HELLO_MAXIMUM_BYTES);
    let (_, receive_files) = SeqpacketSocket::storage_preparation_receive_obligations_v1(maximum)
        .ok_or_else(refused)?;
    let (_, connection_files) = SeqpacketSocket::retained_connect_obligations_v1();
    // A fatal no-descriptor send moves the SAME socket into its original;
    // it never duplicates another socket or grants new descriptor capacity.
    let retained_publication_subject = 1usize;
    let files = receive_files.checked_add(connection_files)
        .and_then(|files| files.checked_add(retained_publication_subject)).ok_or_else(refused)?;
    Ok(demand.with(D::OpenFiles, u64::try_from(files).map_err(|_| refused())?))
}

/// Bounds the completed closed Client HELLO carrier entering Cold.
///
/// Both authenticated zero-rights receives have completed. Their successful
/// native staging, preview subjects and endpoint duplicates have actually
/// dropped; only socket/peer and the two accepted record subjects remain.
/// Failed receives retain their full native bound and never enter Cold/main.
/// This DATA grants no successful handshake or native disposition.
///
/// # Errors
/// Refuses checked native geometry conversion or arithmetic overflow.
pub fn controller_client_completed_handshake_open_file_bound_v1()
    -> Result<u64, StorageSessionGeometryRefusalV1>
{
    let (_, connected) = SeqpacketSocket::retained_connect_obligations_v1();
    let files = connected.checked_add(2).ok_or(StorageSessionGeometryRefusalV1)?;
    u64::try_from(files).map_err(|_| StorageSessionGeometryRefusalV1)
}

/// Selects the passive output direction of the fixed three-record HELLO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageHandshakeEndpointV1 {
    /// The Controller sends the client HELLO and receives the other two records.
    Client,
    /// Storage sends the publication and broker HELLO.
    Broker,
}

/// Prices the three actual HELLO records as one finite operation.
///
/// Genuine Controller J or Storage F derives this shape for its own endpoint
/// before actual connect/HELLO work. Resident Native/model/FD debt is separate.
/// This DATA admits no Session and cannot reset a cutoff or protected history.
///
/// # Errors
/// Refuses unrepresentable checked wire geometry.
pub fn handshake_flight_demand(endpoint: StorageHandshakeEndpointV1)
    -> Result<ResourceVector, StorageSessionGeometryRefusalV1>
{
    let broker = aos_sandbox_broker_session_protocol::SERVER_HELLO_MAXIMUM_BYTES
        .checked_add(aos_sandbox_broker_session_protocol::BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES)
        .ok_or_else(invalid)?;
    let client = CLIENT_HELLO_MAXIMUM_BYTES;
    let network = client.checked_add(broker).ok_or_else(invalid)?;
    let output = match endpoint {
        StorageHandshakeEndpointV1::Client => client,
        StorageHandshakeEndpointV1::Broker => broker,
    };
    Ok(ResourceVector::ZERO
        .with(D::NetworkBytes, as_u64(network)?)
        .with(D::OutputBytes, as_u64(output)?)
        .with(D::ConcurrentOperations, 1))
}

/// Prices one finite request/reply operation from its verified HELLO ceilings.
///
/// This is a separate all-dimension operation shape, never a lifetime traffic
/// highwater. The genuine same-original lane consumes it once before receive.
/// Resident models, file growth and domain effects have separate debits. CPU
/// remains under the same installed aggregate cgroup rate; no new task, mount,
/// writable object, fetch, descriptor or execution is created by this framing.
///
/// # Errors
/// Refuses an invalid Storage transcript or unrepresentable byte ceilings.
pub fn operation_flight_demand(
    transcript: &VerifiedBrokerSessionTranscriptV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if transcript.protocol() != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage {
        return Err(invalid());
    }
    // The shared raw receiver retains this protocol ceiling before rejecting
    // a smaller negotiated limit. Pay hostile received bytes at that actual
    // frontier, rather than underpricing them from the later live header.
    let request = aos_sandbox_broker_session_protocol::maximum_broker_session_request_bytes_v1(
        transcript.protocol(),
    );
    let response = u64::from(transcript.negotiated_maximum_response_bytes())
        .min(as_u64(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)?);
    Ok(ResourceVector::ZERO
        .with(D::NetworkBytes, add(as_u64(request)?, response)?)
        .with(D::OutputBytes, response)
        .with(D::ConcurrentOperations, 1))
}

/// Bounds both actual native appends of one fixed Controller Inventory turn.
///
/// The same protected history recipe supplies request and terminal row framing.
/// This is encoded-byte DATA, not a native append owner, capacity or permission
/// to use a Session. A genuine caller pays the reached representation and both
/// append/post obligations before installing its finite retained interval.
///
/// # Errors
/// Rejects invalid held-prefix geometry or checked width/append overflow.
pub fn controller_inventory_append_encoded_bound_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    controller_session_two_append_bound_v3(extent,
        aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1())
}

/// Bounds the same two native Session appends for an actual signed Delete26.
///
/// The request ceiling is derived from the held Root-signed26 quartet. This
/// passive geometry does not authorize a request or create a native window.
///
/// # Errors
/// Refuses empty/over-protocol request bounds, invalid extents or checked overflow.
pub fn delete_storage_preparation_append_encoded_bound_v3(
    extent: &ProtectedJournalPreopenReplayExtentV1, request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    delete_storage_two_append_bound_v3(extent, request_bytes)
}

/// Bounds the same two native Session appends for an actual signed DeleteApply7.
///
/// This passive width admits no plan, Session, native window or budget.
///
/// # Errors
/// Refuses invalid held extents, zero/oversized requests or checked overflow.
pub fn delete_storage_apply_append_encoded_bound_v3(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    delete_storage_two_append_bound_v3(extent, request_bytes)
}

/// Bounds the same exact request/terminal native appends for signed Delete9.
///
/// This width supplies no worker, Session, native loan or lifecycle authority.
///
/// # Errors
/// Refuses zero/oversized requests, invalid held extents or checked overflow.
pub fn delete_network_apply_append_encoded_bound_v4(
    extent: &ProtectedJournalPreopenReplayExtentV1, request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    delete_storage_two_append_bound_v3(extent, request_bytes)
}

/// Bounds the actual signed Reap62 request and terminal native appends.
///
/// This passive width grants no cleanup, Session, or append authority.
///
/// # Errors
/// Refuses zero or oversized requests, invalid held extents, or checked overflow.
pub fn delete_mount_reap_append_encoded_bound_v4(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    delete_storage_two_append_bound_v3(extent, request_bytes)
}

fn delete_storage_two_append_bound_v3(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    if request_bytes == 0 || request_bytes > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(invalid());
    }
    controller_session_two_append_bound_v3(extent, request_bytes)
}

fn controller_session_two_append_bound_v3(extent: &ProtectedJournalPreopenReplayExtentV1,
    request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    let prefix = checked_prefix(extent)?;
    let request = as_u64(request_bytes)?;
    let request_row = sum(&[
        DURABLE_FIXED_HEADER_BYTES,
        as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
        request,
        4,
    ])?;
    let terminal_row = sum(&[
        DURABLE_FIXED_HEADER_BYTES,
        as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
        request,
        as_u64(BROKER_SESSION_OUTCOME_COMPANION_BYTES)?,
        response_packet_bytes(as_u64(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)?)?,
        4,
    ])?;
    // The legal history cap and exact two-record native envelope remain in
    // append_bytes. A smaller damaged File cannot reduce its held-state lane.
    let history = sum(&[
        prefix.min(as_u64(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)?),
        request_row,
        terminal_row,
    ])?;
    append_bytes(extent, history, 2)
}

/// Bounds current-head plus immutable-archive writes for one Host NoApply turn.
///
/// The same supplier prices two full StoredHistory rows per transaction and
/// both request/terminal transactions. It preserves the actual retained map,
/// checkpoint, archive and history-cap bounds; it grants no Session authority.
///
/// # Errors
/// Refuses zero/oversized requests, invalid held extents or checked overflow.
pub fn host_execution_no_apply_append_encoded_bound_v2(
    extent: &ProtectedJournalPreopenReplayExtentV1, request_bytes: usize,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    if request_bytes == 0 || request_bytes > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(invalid());
    }
    controller_session_two_append_bound_v3(extent, request_bytes)
}

fn append_bytes(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    history_bytes: u64,
    transactions: u64,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    // Inventory archive framing is header110 plus digest32.
    let archive = 8 + 2 + 2 * 16 + 2 * 32 + 4 + 32;
    let stored = sum(&[
        history_bytes.min(as_u64(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES)?),
        as_u64(VALUE_FIXED_BYTES_V3)?,
        as_u64(CHECKPOINT_BYTES)?,
        archive,
    ])?;
    let value_bytes = usize::try_from(stored).map_err(|_| invalid())?;
    let shapes = [
        RecordShape {
            key_bytes: extent.limits.maximum_key_bytes,
            value_bytes: Some(value_bytes),
        },
        RecordShape {
            key_bytes: extent.limits.maximum_key_bytes,
            value_bytes: Some(value_bytes),
        },
    ];
    let append = encoded_transaction_append_bytes(shapes.into_iter()).map_err(|_| invalid())?;
    mul(transactions, append)
}

fn response_packet_bytes(body_bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    // The selected success has only request ID, method, body and authentication.
    // Projection owns the exact auth-field contribution. Each other field has
    // a one-byte tag and at most a full u64 varint; ID payload is exactly16.
    let authentication = AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
        .checked_sub(AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES)
        .ok_or_else(invalid)?;
    let varint = add(mul(as_u64(size_of::<u64>())?, 8)? / 7, 1)?;
    let fields = add(mul(3, add(1, varint)?)?, 16)?;
    sum(&[body_bytes, as_u64(authentication)?, fields])
}

fn checked_prefix(
    extent: &ProtectedJournalPreopenReplayExtentV1,
) -> Result<u64, StorageSessionGeometryRefusalV1> {
    if extent.native_bytes > extent.limits.maximum_journal_bytes {
        return Err(invalid());
    }
    Ok(extent.native_bytes)
}

fn reached_history_rows(bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    let minimum = add(
        DURABLE_FIXED_HEADER_BYTES,
        as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
    )?;
    Ok((bytes / minimum).min(as_u64(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_RECORDS)?))
}

fn history_carriers(rows: u64, copies: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    // Requires the shared decoder's grow-after-complete-record cut. A doubling
    // Vec may retain old+new allocations during growth; 3*n+4 covers that peak
    // and the initial typed capacity floor. It does not charge absent8192 rows.
    let cells = add(mul(rows, 3)?, 4)?;
    let record = as_u64(size_of::<BrokerSessionDurableRecordV1>())?;
    let encoded_row = as_u64(size_of::<Vec<u8>>())?;
    mul(copies, mul(cells, add(record, encoded_row)?)?)
}

fn inline_context_bytes() -> Result<u64, StorageSessionGeometryRefusalV1> {
    // These are the actual validated HELLO ceilings, not new parser limits.
    // FeatureRef::new bounds each accepted namespace to 255 bytes.
    let features = mul(2 * 64, add(as_u64(size_of::<FeatureRef>())?, 255)?)?;
    let methods = mul(2 * 23, as_u64(size_of::<BrokerMethod>())?)?;
    sum(&[
        as_u64(size_of::<StoredBrokerSessionHistoryV1>())?,
        as_u64(size_of::<HistoricalSessionCheckpointV1>())?,
        as_u64(size_of::<VerifiedBrokerSessionTranscriptV1>())?,
        as_u64(size_of::<BrokerSessionTrafficStateV1>())?,
        as_u64(size_of::<AuthenticatedBrokerMethodRequestV1>())?,
        as_u64(size_of::<AuthenticatedBrokerMethodOutcomeV1>())?,
        as_u64(size_of::<BrokerRequestEnvelope>())?,
        as_u64(size_of::<BrokerResponseEnvelope>())?,
        as_u64(size_of::<BrokerAuthorizationArtifactsV1>())?,
        as_u64(size_of::<BrokerSemanticBindingsV1>())?,
        as_u64(size_of::<RequestHeader>())?,
        as_u64(size_of::<AssignmentFence>())?,
        as_u64(size_of::<Descriptor>())?,
        mul(as_u64(MAXIMUM_PROTOCOL_RECORDS)?, as_u64(size_of::<StoredBrokerSessionHistoryV1>())?)?,
        mul(4, add(features, methods)?)?,
    ])
}



fn inventory_model_carriers(bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    // These five item types are the actual Inventory response tree. Its Domain
    // producer already passed the canonical Inventory validator before parking.
    let width = inventory_repeated_width()?;
    let rows = bytes / 2;
    let elements = mul(rows, width)?.min(as_u64(buffa::DEFAULT_ELEMENT_MEMORY_LIMIT)?);
    // Workspace rows additionally own these singular nested models. They are
    // not repeated-element charges in Buffa. Each of the five Vecs has a floor.
    let children = add(as_u64(size_of::<AssignmentFence>())?, as_u64(size_of::<Descriptor>())?)?;
    let nested = mul(rows.min(as_u64(MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS)?), children)?;
    sum(&[mul(3, add(elements, nested)?)?, mul(5 * 4, width)?, mul(4, children)?])
}

fn inventory_validation_carriers(bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    // A repeated nested protobuf item needs at least tag+length bytes. Only
    // these matching validated rows and uniqueness/range entries are priced;
    // the protobuf model itself is in the independent Buffa footprint budget.
    let rows = (bytes / 2).min(as_u64(MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS)?);
    let per_row = sum(&[
        as_u64(size_of::<ValidatedStorageWorkspace>())?,
        as_u64(size_of::<([u8; 16], [u8; 32], [u8; 32], [u8; 32])>())?,
        as_u64(size_of::<(u64, u64)>())?,
        as_u64(size_of::<u64>())?,
        as_u64(size_of::<(u32, u32)>())?,
        as_u64(size_of::<&Vec<u8>>())?,
    ])?;
    mul(add(mul(rows, 3)?, 4)?, per_row)
}

fn as_u64(value: usize) -> Result<u64, StorageSessionGeometryRefusalV1> {
    u64::try_from(value).map_err(|_| invalid())
}

fn add(left: u64, right: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    left.checked_add(right).ok_or_else(invalid)
}

fn mul(left: u64, right: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
    left.checked_mul(right).ok_or_else(invalid)
}

fn sum(values: &[u64]) -> Result<u64, StorageSessionGeometryRefusalV1> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

fn invalid() -> StorageSessionGeometryRefusalV1 {
    StorageSessionGeometryRefusalV1
}

#[cfg(test)]
mod start_network_fixed_geometry_tests {
    use super::*;

    #[test]
    fn start_hello_conserves_actual_memory_files_and_staging_without_control_entries() {
        fn footprint(cells: usize) -> StorageHandshakePrivateFootprintV1 {
            StorageHandshakePrivateFootprintV1 {
                actual_inline_bytes: 512, actual_failure_bytes: 1024, actual_failure_cells: cells,
            }
        }
        let old = fixed_controller_client_handshake_receiving_demand(footprint(77)).unwrap();
        let start = fixed_start_network_client_handshake_receiving_demand_v2(footprint(usize::MAX)).unwrap();
        for dimension in [D::MemoryBytes, D::OpenFiles, D::PublicationStagingBytes] {
            assert_eq!(start.get(dimension), old.get(dimension));
            assert!(start.get(dimension) > 0);
        }
        assert_eq!(start.get(D::MetadataEntries), 0);
        assert!(old.get(D::MetadataEntries) > 77);
        assert!(fixed_controller_client_handshake_receiving_demand(footprint(usize::MAX)).is_err());
    }
}


/// Prices the existing broker-side HELLO representation for a fixed-role opener.
///
/// The genuine role, captured Journal/schema and native endpoint supplies are
/// admitted separately. This passive helper shares the canonical HELLO Memory,
/// FD and staging arithmetic; it creates no role or financial permission.
///
/// # Errors
/// Refuses the same checked geometry overflow as the original HELLO supplier.
pub fn fixed_service_broker_handshake_receiving_demand_v4(
    private: StorageHandshakePrivateFootprintV1,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    fixed_handshake_receiving_demand_for_purpose(private, HandshakeGeometryPurposeV2::StartNetwork)
}

#[cfg(test)]
mod delete_preparation_append_shape_tests {
    use super::*;

    #[test]
    fn signed26_width_uses_the_same_two_append_framing_as_inventory() {
        let extent = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
            protected_session_journal_limits_v1(), 0).unwrap();
        let inventory_width = aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1();
        let old = controller_inventory_append_encoded_bound_v1(&extent).unwrap();
        let same = delete_storage_preparation_append_encoded_bound_v3(&extent, inventory_width).unwrap();
        let larger = delete_storage_preparation_append_encoded_bound_v3(&extent,
            inventory_width.checked_add(4096).unwrap()).unwrap();

        assert_eq!(same, old);
        assert!(larger > same);
        assert!(delete_storage_preparation_append_encoded_bound_v3(&extent, 0).is_err());
        assert!(delete_storage_preparation_append_encoded_bound_v3(&extent,
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES + 1).is_err());
    }
}

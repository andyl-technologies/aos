//! Prices the closed future report grammar before Prepare or native birth.
//!
//! Only the actual selected two-event Producer format is accepted. Future
//! native IDs, coordinates, full references and birth rows are represented by
//! their immutable grammar maxima, not a fabricated live checkpoint. The exact
//! report serializer and this projection share the complete field roster.

use super::report::{REPORT_FIELDS, REPORT_SCHEMA};
use super::*;
use crate::reference_packet::service::connected::PacketConnectedSourceProgram;
use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, actual_serialization_storage_data,
};
use std::mem::size_of;

/// Reports independent future report ownership without issuing publication rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredProducerReportStorageData {
    maximum_encoded: usize,
    retained_value: usize,
    retained_canonical: usize,
    transient: usize,
    scratch: usize,
}
impl PacketRestoredProducerReportStorageData {
    /// Bounds the defining report serializer's complete canonical output.
    pub const fn maximum_report_encoded_bytes_data(&self) -> usize {
        self.maximum_encoded
    }
    /// Returns one independently retained Source Value tree, including empty roots.
    pub const fn retained_value_requested_bytes_data(&self) -> usize {
        self.retained_value
    }
    /// Returns the independent Source canonical output bank's cumulative requests.
    pub const fn retained_canonical_requested_bytes_data(&self) -> usize {
        self.retained_canonical
    }
    /// Returns simultaneous serializer, parser, sorting, escaping and canonical work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }
    /// Returns the borrowed report root and explicit defining projection/result views.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
}

/// Projects the same finite report grammar without requiring a future checkpoint.
///
/// The caller independently authenticates the actual launch and its Source
/// declaration, then prices its own durable copies/placement separately. This
/// returns no envelope, live proof, common outcome, grant or publication permit.
///
/// # Errors
/// Refuses another program shape or payload extent, overflow, or complete
/// construction geometry above the caller's unchanged finite ceiling.
pub fn original_restored_producer_report_storage_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<PacketRestoredProducerReportStorageData, ProviderError> {
    let PacketConnectedSourceProgram::Producer { program } = &launch.program else {
        return Err(invalid());
    };
    let [private, output] = program.events.as_slice() else {
        return Err(invalid());
    };
    if private.payload.is_some()
        || output
            .payload
            .as_ref()
            .is_none_or(|bytes| bytes.as_slice().len() > 32)
        || launch.selection.realization.owners.len() != 1
        || launch.selection.realization.owners[0].participant_ids.len() != 1
    {
        return Err(invalid());
    }
    let report = projection(maximum)?;
    Ok(PacketRestoredProducerReportStorageData {
        maximum_encoded: report.maximum_encoded_bytes,
        retained_value: report.retained_value_backing_bytes,
        retained_canonical: report.canonical_output_requested_bytes,
        transient: report.requested_total()?,
        scratch: original_restored_producer_report_counter_scratch_data(),
    })
}

pub(crate) fn wire_projection(
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    actual_serialization_storage_data(&ENVELOPE, Default::default(), maximum)
}

pub(crate) fn projection(
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    // The static field view does not invoke Bytes::Serialize. Its eight maximum
    // payload/context byte fields still require independent base64 temporaries
    // when the actual borrowed report is encoded after admission.
    actual_serialization_storage_data(
        &REPORT,
        crate::retained_metadata::RetainedProtocolMetadataFacts {
            vector_capacity_bytes: 8 * 32,
            vector_banks: 8,
            ..Default::default()
        },
        maximum,
    )
}

/// Names the complete borrowed report and independent projection result headers.
pub fn original_restored_producer_report_counter_scratch_data() -> usize {
    size_of::<PacketRestoredProducerOperationReportData<'static>>()
        + size_of::<&PacketRestoredProducerOperationReportData<'static>>()
        + size_of::<PacketRestoredProducerReportStorageData>()
        + size_of::<Result<PacketRestoredProducerReportStorageData, ProviderError>>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<&PacketNative5SourceLaunch>() + size_of::<&V<'static>>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

const ID: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const DOMAIN: &str = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const DECIMAL: &str = "18446744073709551615";
const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HASH: V<'static> = V::Object(&[
    ("algorithm", V::Text("blake3-256")),
    ("domain", V::Text(DOMAIN)),
    ("digest", V::Text(DIGEST)),
]);
const CONTENT: V<'static> = V::Object(&[
    ("hash", HASH),
    ("length", V::Text(DECIMAL)),
    ("media_type", V::Text(DOMAIN)),
]);
const EMPTY: V<'static> = V::Object(&[]);
const POSITION: V<'static> = V::Object(&[
    ("time_ps", V::Text(DECIMAL)),
    ("microstep", V::Text(DECIMAL)),
    ("phase", V::Text("3")),
]);
const ARGUMENTS: V<'static> = V::Object(&[
    ("grant_id", V::Text(ID)),
    ("participant_ids", V::Array(&[V::Text(ID)])),
    ("realization_id", V::Text(ID)),
    ("activation_id", V::Text(ID)),
    ("world_generation", V::Text(DECIMAL)),
    ("owner_generation", V::Text(DECIMAL)),
    ("input_epoch", V::Text(ID)),
    ("mode", V::Text("exact")),
    ("ordering_profile", V::Text("superdense-v1")),
    ("start", POSITION),
    ("limit", POSITION),
    ("boundary_policy", V::Text("ordinary_stop")),
    ("input_authorization", CONTENT),
    ("input_watermark", V::Text(DECIMAL)),
]);
const BEGIN_RESULT: V<'static> = V::Object(&[
    ("grant_id", V::Text(ID)),
    ("reached", POSITION),
    ("stop_reason", V::Text("attention")),
    ("stop_receipt", CONTENT),
    ("observation_batch", CONTENT),
    ("pending_inventory", CONTENT),
    (
        "next_attention",
        V::Object(&[
            ("kind", V::Text("at")),
            ("position", POSITION),
            ("evidence", CONTENT),
        ]),
    ),
]);
const BEGIN_TERMINAL: V<'static> = V::Object(&[
    ("status", V::Text("completed")),
    ("operation_state", V::Text("completed")),
    ("result", BEGIN_RESULT),
    ("extensions", EMPTY),
]);
// This field superset independently dominates either Begin request or Poll
// request/terminal, including the Poll's entire cached original Begin body.
const BODY: V<'static> = V::Object(&[
    ("kind", V::Text("boundary_settle")),
    ("binding_hash", HASH),
    ("owner_generation", V::Text(DECIMAL)),
    ("activation_id", V::Text(ID)),
    ("world_generation", V::Text(DECIMAL)),
    ("arguments", ARGUMENTS),
    ("after_observation_sequence", V::Text(DECIMAL)),
    ("status", V::Text("completed")),
    ("operation_state", V::Text("completed")),
    (
        "result",
        V::Object(&[
            ("operation_id", V::Text(ID)),
            ("operation_state", V::Text("completed")),
            ("grant_id", V::Text(ID)),
            ("reached", POSITION),
            ("stop_reason", V::Text("attention")),
            ("stop_receipt", CONTENT),
            ("observation_batch", CONTENT),
            ("pending_inventory", CONTENT),
            (
                "next_attention",
                V::Object(&[
                    ("kind", V::Text("at")),
                    ("position", POSITION),
                    ("evidence", CONTENT),
                ]),
            ),
            ("outcome", BEGIN_TERMINAL),
            ("observations", V::Array(&[])),
            ("next_observation_sequence", V::Text(DECIMAL)),
        ]),
    ),
    ("extensions", EMPTY),
]);
const ENVELOPE: V<'static> = V::Object(&[
    ("protocol", V::Text("CNP/1")),
    ("message", V::Text("response")),
    ("session_id", V::Text(ID)),
    ("incarnation_id", V::Text(ID)),
    ("node_id", V::Text(ID)),
    ("execution_owner_id", V::Text(ID)),
    ("capture_owner_id", V::Text(ID)),
    ("request_id", V::Text(ID)),
    ("operation_id", V::Text(ID)),
    ("sequence", V::Text(DECIMAL)),
    ("method", V::Text("begin")),
    ("body", BODY),
    ("extensions", EMPTY),
]);
const EVENT: V<'static> = V::Object(&[
    ("id", V::Text(ID)),
    ("evaluation", POSITION),
    ("completion", POSITION),
    ("payload", V::Text(BASE64)),
]);
const PUBLICATION: V<'static> = V::Object(&[
    ("event", V::Text(ID)),
    ("operation", V::Text(ID)),
    ("sequence", V::Text(DECIMAL)),
    ("evaluation", POSITION),
    ("publication", POSITION),
    ("payload", V::Text(BASE64)),
]);
const INVENTORY: V<'static> = V::Object(&[
    ("reached", POSITION),
    ("gate_closed", V::Text("false")),
    ("pending", V::Array(&[EVENT, EVENT])),
    ("retained_outputs", V::Array(&[PUBLICATION])),
    ("private_mutations", V::Text(DECIMAL)),
    ("packet_effects", V::Text(DECIMAL)),
]);
const GRANT: V<'static> = V::Object(&[
    ("operation", V::Text(ID)),
    ("start", POSITION),
    ("limit", POSITION),
    ("inventory", INVENTORY),
    ("newborn", V::Array(&[PUBLICATION])),
    ("complete", V::Text("true")),
]);
const PRODUCER: V<'static> = V::Object(&[
    ("schema", V::Text("source-owned.packet-native/2")),
    ("native_pid", V::Text(DECIMAL)),
    ("original", ENVELOPE),
    ("inventory", INVENTORY),
    ("grant", GRANT),
]);
const BANK: V<'static> = V::Object(&[
    ("selected_rows", V::Text(DECIMAL)),
    ("record_capacity", V::Text(DECIMAL)),
    ("record_bytes", V::Text(DECIMAL)),
    ("alias_row_capacity", V::Text(DECIMAL)),
    ("alias_lookup_capacity", V::Text(DECIMAL)),
    ("alias_row_bytes", V::Text(DECIMAL)),
    ("alias_lookup_bytes", V::Text(DECIMAL)),
]);
const RECEIPT: V<'static> = V::Object(&[
    ("schema", V::Text("source-owned.packet-restored-native/12")),
    (
        "native_receipt",
        V::Object(&[
            ("schema", V::Text("source-owned.packet-receipt/5")),
            ("native_pid", V::Text(DECIMAL)),
            ("original", ENVELOPE),
            ("binding_hash", HASH),
            ("session", V::Text(ID)),
            ("incarnation", V::Text(ID)),
            ("node", V::Text(ID)),
            ("owner", V::Text(ID)),
            ("owner_generation", V::Text(DECIMAL)),
            ("input_epoch", V::Text(ID)),
            ("world", HASH),
            ("native_record", CONTENT),
            (
                "storage_selection",
                V::Object(&[
                    (
                        "storage",
                        V::Object(&[
                            ("snapshot_bytes", V::Text(DECIMAL)),
                            ("control_snapshot_bytes", V::Text(DECIMAL)),
                            ("protocol_snapshot_bytes", V::Text(DECIMAL)),
                            ("frame_bank_bytes", V::Text(DECIMAL)),
                            ("frames_per_direction", V::Text(DECIMAL)),
                            ("hello_bytes", V::Text(DECIMAL)),
                            ("settlement_bytes", V::Text(DECIMAL)),
                        ]),
                    ),
                    (
                        "limits",
                        V::Object(&[
                            ("frame_bytes", V::Text(DECIMAL)),
                            ("nesting", V::Text(DECIMAL)),
                            ("requests", V::Text(DECIMAL)),
                            ("journal_entries", V::Text(DECIMAL)),
                            ("blob_chunk_bytes", V::Text(DECIMAL)),
                        ]),
                    ),
                ]),
            ),
            (
                "capture_profile",
                V::Object(&[(
                    "OwnedProtocol11",
                    V::Object(&[
                        ("native_before_protocol_bytes", V::Text(DECIMAL)),
                        ("native_after_protocol_bytes", V::Text(DECIMAL)),
                        ("host_protocol_bytes", V::Text(DECIMAL)),
                    ]),
                )]),
            ),
            ("confirmation_selection", V::Text(ID)),
            ("ack_emitter_selection", V::Text(ID)),
            ("complete_restore_selection", V::Text(ID)),
            (
                "protocol_metadata_limits",
                V::Object(&[
                    ("native_before_rows", V::Text(DECIMAL)),
                    ("native_after_rows", V::Text(DECIMAL)),
                ]),
            ),
            (
                "protocol_metadata_birth_facts",
                V::Object(&[("before", BANK), ("after", BANK)]),
            ),
            ("restore_input_emitter_selection", V::Text(ID)),
        ]),
    ),
    ("captured_owner_state", CONTENT),
    ("captured_journal", CONTENT),
    ("mapping", CONTENT),
    ("restore_commit", CONTENT),
    ("restore_response", CONTENT),
    ("context_digest", V::Text(BASE64)),
    ("physical_gate_held", V::Text("false")),
]);

const REPORT: V<'static> = V::Object(&[
    (REPORT_FIELDS[0], V::Text(REPORT_SCHEMA)),
    (REPORT_FIELDS[1], V::Text(ID)),
    (REPORT_FIELDS[2], ENVELOPE),
    (REPORT_FIELDS[3], ENVELOPE),
    (REPORT_FIELDS[4], ENVELOPE),
    (REPORT_FIELDS[5], ENVELOPE),
    (REPORT_FIELDS[6], CONTENT),
    (REPORT_FIELDS[7], RECEIPT),
    (REPORT_FIELDS[8], PRODUCER),
    (REPORT_FIELDS[9], CONTENT),
]);

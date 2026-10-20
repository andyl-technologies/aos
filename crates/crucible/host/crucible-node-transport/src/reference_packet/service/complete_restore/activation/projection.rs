//! Counts the closed activation field roster without future owned DTOs.
//!
//! Static borrowed maxima cover the contract's finite identifiers, full refs,
//! decimal widths and exact digest representation. The unchanged artifact and
//! full-frame guards independently refuse an actual value that cannot fit. No
//! hypothetical identifier, proof, receipt or envelope is constructed here.

use super::*;
use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, actual_serialization_storage_data,
};

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
pub(super) const CONTENT: V<'static> = V::Object(&[
    (
        "hash",
        V::Object(&[
            ("algorithm", V::Text("blake3-256")),
            ("domain", V::Text("cnp.blob.v1")),
            ("digest", V::Text(DIGEST)),
        ]),
    ),
    ("length", V::Text(DECIMAL)),
    ("media_type", V::Text(DOMAIN)),
]);
const EMPTY: V<'static> = V::Object(&[]);
pub(super) const ROW: V<'static> = V::Object(&[
    ("retained_requested_bytes", V::Text(DECIMAL)),
    ("maximum_simultaneous_transient_bytes", V::Text(DECIMAL)),
    ("declared_counter_scratch_bytes", V::Text(DECIMAL)),
]);
const TARGET: V<'static> = V::Object(&[
    ("native_pid", V::Text(DECIMAL)),
    ("session", V::Text(ID)),
    ("incarnation", V::Text(ID)),
    ("node", V::Text(ID)),
    ("owner", V::Text(ID)),
    ("owner_generation", V::Text(DECIMAL)),
    ("binding_hash", HASH),
    ("world", HASH),
    ("activation", V::Text(ID)),
    ("generation", V::Text(DECIMAL)),
    ("prepared_token", V::Text(ID)),
    ("gate", V::Text(ID)),
    ("admission", V::Text(ID)),
    ("transaction", V::Text(ID)),
]);
const ORIGINALS: V<'static> = V::Object(&[
    ("captured_owner_state", CONTENT),
    ("captured_control", CONTENT),
    ("captured_journal", CONTENT),
    ("mapping", CONTENT),
    ("commit_request", CONTENT),
    ("commit_response", CONTENT),
    ("context_digest", V::Text(BASE64)),
]);
pub(super) const SCOPE: V<'static> = V::Object(&[
    ("source_birth", CONTENT),
    ("source_runtime", CONTENT),
    ("scope_proof", CONTENT),
    ("target", TARGET),
    ("restoration", ORIGINALS),
]);
const REQUEST: V<'static> = V::Object(&[
    ("schema", V::Text(PACKET_RESTORATION_ACTIVATION_FEATURE)),
    ("phase", V::Text("world_activate")),
    ("scope", SCOPE),
    ("native_allocation", ROW),
]);
const ARTIFACT: V<'static> = V::Object(&[
    ("request", REQUEST),
    (
        "proof",
        V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-restoration-activation-proof/1"),
            ),
            ("algorithm", V::Text("blake3-256-mac")),
            ("context_digest", V::Text(BASE64)),
            ("mac", V::Text(BASE64)),
        ]),
    ),
]);
const ORIGINAL: V<'static> = V::Object(&[
    ("protocol", V::Text("CNP/1")),
    ("message", V::Text("request")),
    ("session_id", V::Text(ID)),
    ("incarnation_id", V::Text(ID)),
    ("node_id", V::Text(ID)),
    ("execution_owner_id", V::Text(ID)),
    // These null fields are represented with larger string nodes for a
    // conservative counter only; actual envelopes still require null.
    ("capture_owner_id", V::Text(ID)),
    ("operation_id", V::Text(ID)),
    ("request_id", V::Text(ID)),
    ("sequence", V::Text(DECIMAL)),
    ("method", V::Text("world_activate")),
    (
        "body",
        V::Object(&[
            ("transaction_id", V::Text(ID)),
            ("activation_id", V::Text(ID)),
            ("world_generation", V::Text(DECIMAL)),
            ("prepared_token", V::Text(ID)),
            ("world_binding_hash", HASH),
            ("gate_id", V::Text(ID)),
            ("activation_manifest", CONTENT),
            ("extensions", EMPTY),
        ]),
    ),
    (
        "extensions",
        V::Object(&[(PACKET_RESTORATION_ACTIVATION_FEATURE, ARTIFACT)]),
    ),
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
            ("original", ORIGINAL),
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
const TERMINAL: V<'static> = V::Object(&[
    ("protocol", V::Text("CNP/1")),
    ("message", V::Text("response")),
    ("session_id", V::Text(ID)),
    ("incarnation_id", V::Text(ID)),
    ("node_id", V::Text(ID)),
    ("execution_owner_id", V::Text(ID)),
    ("capture_owner_id", V::Text(ID)),
    ("operation_id", V::Text(ID)),
    ("request_id", V::Text(ID)),
    ("sequence", V::Text(DECIMAL)),
    ("method", V::Text("world_activate")),
    (
        "body",
        V::Object(&[
            ("status", V::Text("completed")),
            ("operation_state", V::Text("completed")),
            (
                "result",
                V::Object(&[
                    ("staged_owner_ids", V::Array(&[V::Text(ID)])),
                    ("gate_id", V::Text(ID)),
                    ("activation_receipt", CONTENT),
                ]),
            ),
            ("extensions", EMPTY),
        ]),
    ),
    ("extensions", EMPTY),
]);

pub(super) fn wire_projection_data(
    maximum: usize,
) -> Result<[OriginalSerializationStorageData; 3], ProviderError> {
    let mut result = [
        actual_serialization_storage_data(&ORIGINAL, Default::default(), maximum)?,
        actual_serialization_storage_data(&TERMINAL, Default::default(), maximum)?,
        actual_serialization_storage_data(&RECEIPT, Default::default(), maximum)?,
    ];
    // U64's actual formatter owns a separate twenty-byte string. Bytes owns a
    // separate exact base64 formatter; the borrowed views above use its output
    // width without constructing it, so include that actual temporary bank.
    for row in &mut result {
        row.serializer_temporary_requested_bytes = row
            .serializer_temporary_requested_bytes
            .checked_add(20 + 43)
            .ok_or(ProviderError::ResourceExhausted(
                "activation formatter views",
            ))?;
    }
    Ok(result)
}

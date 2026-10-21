//! Owns the shared protected Session representation calculations.
//!
//! The lexical recipe binds only the caller's concrete passive extent type.
//! It performs checked arithmetic over existing format/model owners; it opens
//! no native journal, admits no resources and constructs no role authority.

use aos_sandbox_broker_session_protocol::receiving_geometry::ReceivingGeometryRefusalV1;

/// Reports checked passive representation geometry refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("protected Session representation geometry is invalid or overflows")]
pub struct StorageSessionGeometryRefusalV1;

impl From<ReceivingGeometryRefusalV1> for StorageSessionGeometryRefusalV1 {
    fn from(_: ReceivingGeometryRefusalV1) -> Self {
        Self
    }
}

/// Expands the existing Session quote closure for a concrete extent.
///
/// The extent must expose the original `native_bytes` and `limits` DATA fields.
/// The generated private module preserves the exact function argument, result,
/// arithmetic and error bodies. The caller retains every real native gate and
/// admission before its original growth frontier.
#[macro_export]
macro_rules! define_storage_session_geometry_v1 {
    (module = $module:ident, extent = $extent:ty $(,)?) => {
        mod $module {
            use std::mem::size_of;

            use aos_sandbox_broker_session_protocol::receiving_geometry::{
                protobuf_carriers_v1 as protobuf_carriers,
                schema_protobuf_carriers_v1 as schema_protobuf_carriers,
                inventory_repeated_width_v1 as inventory_repeated_width,
            };
            use aos_sandbox_api::aos::sandbox::local::v1::{
                AssignmentFence, BrokerAuthorizationArtifactsV1, BrokerDescriptorEntry,
                BrokerMethod, BrokerRequestEnvelope, BrokerResponseEnvelope,
                BrokerSemanticBindingsV1, Descriptor, RequestHeader,
            };
            use aos_sandbox_broker_session_protocol::{
                AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,
                AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES,
                AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
                BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES,
                BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_RECORDS,
                BROKER_SESSION_OUTCOME_COMPANION_BYTES,
                BROKER_SESSION_REQUEST_COMPANION_BYTES,
                BrokerSessionDurableRecordV1, BrokerSessionTrafficStateV1,
                CLIENT_HELLO_MAXIMUM_BYTES, SERVER_HELLO_MAXIMUM_BYTES,
                VerifiedBrokerSessionTranscriptV1,
                BROKER_REQUEST_SUBJECT_BYTES, BROKER_OUTCOME_SUBJECT_BYTES,
                SIGNED_BROKER_REQUEST_BYTES, SIGNED_BROKER_OUTCOME_BYTES,
            };
            use aos_sandbox_broker_session_protocol::artifact::BrokerSessionArtifactVerifyCaptureV1;
            use aos_sandbox_broker_session_protocol::context::BrokerSessionContextCheckpointDecodeCaptureV1;
            use aos_sandbox_model::{FeatureRef, ResourceDimension as D, ResourceVector};
            use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
            use aos_sandbox_protocol::authenticated_session::all_methods::{
                AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
            };
            use aos_sandbox_protocol::authenticated_session::historical_checkpoint::{
                HistoricalSessionCheckpointV1, MAXIMUM_BYTES as CHECKPOINT_BYTES,
                HistoricalSessionCheckpointDecodeCaptureV1,
                HistoricalSessionCheckpointVerifyCaptureV1,
            };
            use aos_sandbox_protocol::authenticated_session::stored_history::{
                StoredBrokerSessionHistoryV1, VALUE_FIXED_BYTES_V3,
            };
            use aos_sandbox_protocol::{
                MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS, ValidatedStorageWorkspace,
            };

            // The fixed durable header precedes its mandatory request companion. Ignoring
            // the nonempty packet and per-history length prefix gives a safe row lower bound.
            pub(super) const DURABLE_FIXED_HEADER_BYTES: u64 = 8 + 2 + 4 + 8 + 5 * 32 + 16 + 2 * 8 + 4 + 4 * 32 + 2 * 4;

            pub use aos_sandbox_protocol::authenticated_session::fixed_journal::{
                MAXIMUM_PROTOCOL_RECORDS,
                MAXIMUM_STORAGE_GROUP_ARCHIVES,
                MAXIMUM_STORAGE_INVENTORY_ARCHIVES,
                MAXIMUM_STORAGE_INVENTORY_ABANDONMENTS,
                MAXIMUM_HOST_ARGUMENT_ARCHIVES,
                MAXIMUM_HOST_TERMINAL_ARCHIVES,
            };

            pub use $crate::storage_session_geometry_data::StorageSessionGeometryRefusalV1;

            /// Prices upper schema objects before the existing schema validator runs.
            ///
            /// # Errors
            ///
            /// Refuses inconsistent prefix bounds or unrepresentable checked demand.
            pub fn schema_demand(
                extent: &$extent,
            ) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
                schema_demand_for_prefix_bytes_v3(checked_prefix(extent)?)
            }

            // One mechanical supplier describes the same stored/history/checkpoint and
            // authenticated method models whether borrowed from a native Session prefix
            // or the exact immutable copy of that prefix in a Controller Capture anchor.
            pub(super) fn schema_demand_for_prefix_bytes_v3(prefix: u64)
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
            pub(super) fn storage_retained_partial_replay_demand_v1(
                extent: &$extent,
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
                extent: &$extent,
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
                extent: &$extent,
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

            pub(super) fn codec_companion_transient_bytes() -> Result<u64, StorageSessionGeometryRefusalV1> {
                let request = BROKER_REQUEST_SUBJECT_BYTES.checked_add(SIGNED_BROKER_REQUEST_BYTES)
                    .ok_or_else(invalid)?;
                let outcome = BROKER_OUTCOME_SUBJECT_BYTES.checked_add(SIGNED_BROKER_OUTCOME_BYTES)
                    .ok_or_else(invalid)?;
                as_u64(request.max(outcome))
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
                extent: &$extent,
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
                extent: &$extent,
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

            pub(super) fn request_representation_demand_v1(
                extent: &$extent, send_bytes: usize, send_cells: usize,
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

            pub(super) fn outcome_representation_demand_v1(
                extent: &$extent,
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

            pub(super) fn append_bytes(
                extent: &$extent,
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

            pub(super) fn response_packet_bytes(body_bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
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

            pub(super) fn checked_prefix(
                extent: &$extent,
            ) -> Result<u64, StorageSessionGeometryRefusalV1> {
                if extent.native_bytes > extent.limits.maximum_journal_bytes {
                    return Err(invalid());
                }
                Ok(extent.native_bytes)
            }

            pub(super) fn reached_history_rows(bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
                let minimum = add(
                    DURABLE_FIXED_HEADER_BYTES,
                    as_u64(BROKER_SESSION_REQUEST_COMPANION_BYTES)?,
                )?;
                Ok((bytes / minimum).min(as_u64(BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_RECORDS)?))
            }

            pub(super) fn history_carriers(rows: u64, copies: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
                // Requires the shared decoder's grow-after-complete-record cut. A doubling
                // Vec may retain old+new allocations during growth; 3*n+4 covers that peak
                // and the initial typed capacity floor. It does not charge absent8192 rows.
                let cells = add(mul(rows, 3)?, 4)?;
                let record = as_u64(size_of::<BrokerSessionDurableRecordV1>())?;
                let encoded_row = as_u64(size_of::<Vec<u8>>())?;
                mul(copies, mul(cells, add(record, encoded_row)?)?)
            }

            pub(super) fn inline_context_bytes() -> Result<u64, StorageSessionGeometryRefusalV1> {
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

            pub(super) fn inventory_model_carriers(bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
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

            pub(super) fn inventory_validation_carriers(bytes: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
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

            pub(super) fn as_u64(value: usize) -> Result<u64, StorageSessionGeometryRefusalV1> {
                u64::try_from(value).map_err(|_| invalid())
            }

            pub(super) fn add(left: u64, right: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
                left.checked_add(right).ok_or_else(invalid)
            }

            pub(super) fn mul(left: u64, right: u64) -> Result<u64, StorageSessionGeometryRefusalV1> {
                left.checked_mul(right).ok_or_else(invalid)
            }

            pub(super) fn sum(values: &[u64]) -> Result<u64, StorageSessionGeometryRefusalV1> {
                values.iter().try_fold(0, |total, value| add(total, *value))
            }

            pub(super) fn invalid() -> StorageSessionGeometryRefusalV1 {
                StorageSessionGeometryRefusalV1
            }
        }
    };
}

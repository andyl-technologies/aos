//! Defines the unchanged closed capture allocation selector data.

use serde::{Deserialize, Serialize};

/// Selects the separately source-installed native original-Observe quote producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNative5CaptureAllocationSelection {
    /// Reports the same original active native model before its first Capture.
    OriginalObserve12,
}

use crate::profile::ProviderError;
use crucible_node_format::{Id, SchemaRef, canonical};

/// Names the explicitly selected original native allocation-report family.
pub const PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE: &str =
    "source-owned.packet-native-capture-allocation/12";

/// Names the report's closed schema discriminator.
pub const PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT: &str =
    "source-owned.packet-native-capture-allocation/12";

/// Names the selected Observe proof wrapper, separately from receipt5.
pub const PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD: &str =
    "source-owned.packet-native-capture-record/12";

/// Names the report's exact content media type.
pub const PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA: &str =
    "application/vnd.source-owned.packet-native-capture-allocation.v12+json";

/// Bounds a report's wire encoding, independently of its requested-storage sum.
pub const MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES: usize = 16 * 1024;

/// Separates the actual original Observe request commitment from other hashes.
pub const NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN: &str =
    "source-owned.packet-native-capture-allocation-observe/12";

/// Encodes the complete selected report/record and producer obligations.
///
/// # Errors
/// Reports failure to canonicalize the fixed source-owned definition.
pub fn capture_allocation_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(CaptureAllocationContractValue)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
}

/// Binds the complete original-Observe report schema definition.
///
/// # Errors
/// Reports invalid fixed identity or canonical definition encoding failure.
pub fn capture_allocation_schema() -> Result<SchemaRef, ProviderError> {
    schema(PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT)
}

/// Binds the distinct selected Observe record wrapper to the same full definition.
///
/// # Errors
/// Reports invalid fixed identity or canonical definition encoding failure.
pub fn capture_allocation_record_schema() -> Result<SchemaRef, ProviderError> {
    schema(PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD)
}

fn schema(id: &str) -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(id)?,
        version: 12,
        definition: canonical::content_ref(&capture_allocation_contract()?, "application/json")?,
        extensions: Default::default(),
    })
}

/// Serializes the original borrowed immutable contract roster without authority.
pub struct CaptureAllocationContractValue;

impl serde::Serialize for CaptureAllocationContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::profile::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-native-capture-allocation-contract/12"),
            ),
            ("feature", V::Text(PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)),
            ("selection", V::Text("original_observe12")),
            ("report", V::Text(PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT)),
            (
                "report_media",
                V::Text(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA),
            ),
            (
                "report_maximum_encoded_bytes",
                V::Number(MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES as u64),
            ),
            (
                "report_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("scope"),
                    V::Text("before"),
                    V::Text("after"),
                    V::Text("metadata_banks"),
                    V::Text("retained_requested_bytes"),
                    V::Text("shared_edges"),
                    V::Text("unique_roots"),
                    V::Text("growth"),
                    V::Text("transients"),
                ]),
            ),
            (
                "scope_fields",
                V::Array(&[
                    V::Text("native_pid"),
                    V::Text("observe_request"),
                    V::Text("observe_sequence"),
                    V::Text("observe_hash"),
                    V::Text("session"),
                    V::Text("incarnation"),
                    V::Text("node"),
                    V::Text("owner"),
                    V::Text("binding_hash"),
                    V::Text("world"),
                    V::Text("activation"),
                    V::Text("world_generation"),
                    V::Text("owner_generation"),
                    V::Text("model_cursor"),
                    V::Text("control_originals_before"),
                    V::Text("endpoint_records_before"),
                    V::Text("provider_next_sequence_before"),
                ]),
            ),
            (
                "reservation_fields",
                V::Array(&[
                    V::Text("encoded_capacity"),
                    V::Text("literal_and_descriptor_bytes"),
                    V::Text("current_encoded_bytes"),
                ]),
            ),
            (
                "growth_fields",
                V::Array(&[
                    V::Text("observe_publication_bytes"),
                    V::Text("capture_request_bytes"),
                    V::Text("capture_publication_bytes"),
                    V::Text("after_confirmation_bytes"),
                ]),
            ),
            (
                "transient_fields",
                V::Array(&[
                    V::Text("observe_encoding_bytes"),
                    V::Text("model_control_encoding_bytes"),
                    V::Text("native_before_encoding_bytes"),
                    V::Text("native_after_encoding_bytes"),
                    V::Text("quote_scratch_bytes"),
                ]),
            ),
            (
                "metadata_banks",
                V::Text(
                    "exact independently allocated before/after protocol metadata bank facts, including spare record and alias capacities; never a substitute for whole native storage",
                ),
            ),
            (
                "record",
                V::Object(&[
                    ("schema", V::Text(PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD)),
                    (
                        "fields",
                        V::Array(&[V::Text("schema"), V::Text("native"), V::Text("allocation")]),
                    ),
                    (
                        "native",
                        V::Text(
                            "complete unmodified PacketNative5Record receipt5 with its exact original Observe and underlying producer2/reactive4 reference",
                        ),
                    ),
                ]),
            ),
            (
                "producer",
                V::Text(
                    "same actual active original native Control/model, endpoint, Connection, BlobReceiver, registrar, bootstrap, supervisor, immutable policy, original operational cut and both actual precharged reservations; all erased or incomplete fields refuse",
                ),
            ),
            (
                "identity",
                V::Text(
                    "process-local typed alias roster counts every strong edge and walks each actual payload once, including independently cloned authority fields; no pointers, Rust layouts or roster identities are serialized",
                ),
            ),
            (
                "currency",
                V::Text(
                    "report owner retained by SAME endpoint before fallible publication; actual completed Observe/current model cursor/Control identity and originals/endpoint-record sequence boundary reauthenticated before first Capture; no intervening semantic operation or alternate connection",
                ),
            ),
            (
                "requested_storage",
                V::Text(
                    "actual current retained requested backing and inline roots plus all independent future retained components, maximum complete transient phase and known quote scratch; physical allocator/compiler/whole Source admission remain separate",
                ),
            ),
            (
                "capture_input",
                V::Text(
                    "after successful selected Observe, restrict next receive to exact scoped Begin/Capture before arbitrary typed-body allocation; ordinary full negotiated raw and JSON parsing still apply",
                ),
            ),
            (
                "codec",
                V::Text(
                    "selection requires explicit policy17, Control6, endpoint15 and nativeSnapshot12 full owning coverage and matching cold decoder before Capture; old None policy16/Control5/endpoint14/snapshot11 and ordinary receipt5 remain exact",
                ),
            ),
            (
                "source",
                V::Text(
                    "same source-bound selected contract before birth; Source authenticates actual original Observe terminal/raw report, current kernel/controller/runtime and whole four-owner requested allocation before any Capture request; readonly preflight issues no RPC",
                ),
            ),
            (
                "authority",
                V::Text(
                    "data only; numeric peak, portable record, report hash, metadata facts or decoded selector grant no Source acceptance, Core ticket, allocation permission, Arm, Ready, Capture or restoration",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

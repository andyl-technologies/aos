//! Defines the original immutable schema DATA without live protocol owners.

use crate::profile::ProviderError;
use crucible_node_format::{Id, SchemaRef, canonical};

/// Names the separately registered restored native proof feature and schema.
pub const PACKET_NATIVE_RESTORED_RECORD_FEATURE: &str = "source-owned.packet-restored-native/12";

/// Encodes the complete distinct restored proof and physical gate contract.
///
/// # Errors
/// Reports canonical specification encoding failure.
pub fn native_restored_record_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(NativeRestoredRecordContractValue)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
}

/// Names the full immutable restored native evidence definition.
///
/// # Errors
/// Reports invalid static identifiers or canonical specification encoding failure.
pub fn native_restored_record_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_NATIVE_RESTORED_RECORD_FEATURE)?,
        version: 12,
        definition: canonical::content_ref(
            &native_restored_record_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Serializes the original borrowed immutable contract roster without authority.
pub struct NativeRestoredRecordContractValue;

impl serde::Serialize for NativeRestoredRecordContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::profile::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-restored-native-contract/12"),
            ),
            ("feature", V::Text(PACKET_NATIVE_RESTORED_RECORD_FEATURE)),
            (
                "selection",
                V::Text(
                    "SourceSignedTransfer12 with actual installed same fresh boot/source/controller/Core restoration; portable value never creates an installed gate",
                ),
            ),
            (
                "commit_held",
                V::Object(&[
                    (
                        "schema",
                        V::Text("source-owned.packet-restored-commit-held/12"),
                    ),
                    (
                        "fields",
                        V::Array(&[
                            V::Text("schema"),
                            V::Text("native_pid"),
                            V::Text("target_world"),
                            V::Text("target_owner"),
                            V::Text("target_owner_binding"),
                            V::Text("target_activation"),
                            V::Text("target_generation"),
                            V::Text("captured_owner_state"),
                            V::Text("captured_control"),
                            V::Text("captured_journal"),
                            V::Text("mapping"),
                            V::Text("restore_commit"),
                            V::Text("context_digest"),
                            V::Text("local_cursor"),
                            V::Text("inventory_hash"),
                            V::Text("physical_gate_held"),
                        ]),
                    ),
                    (
                        "meaning",
                        V::Text(
                            "nonrecursive actual installed same-socket model and fresh physical hold; body exported before actual assigned Commit response; original logical inventory/cursor/hash unchanged; no response reference or portable permit",
                        ),
                    ),
                    (
                        "maximum",
                        V::Text(
                            "allocation-free shared producer field-view count of max128 IDs, six-byte escaped max128 hash domains, exact64hex digests, five full ContentRefs with max128 quote media, U64MAX counters/coordinate, exact32-byte digest base64 width; actual producer validates same bound before encoding",
                        ),
                    ),
                ]),
            ),
            (
                "fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("native_receipt"),
                    V::Text("captured_owner_state"),
                    V::Text("captured_journal"),
                    V::Text("mapping"),
                    V::Text("restore_commit"),
                    V::Text("restore_response"),
                    V::Text("context_digest"),
                    V::Text("physical_gate_held"),
                ]),
            ),
            (
                "native_receipt",
                V::Text(
                    "complete unchanged PacketNative5Record receipt/5 and full source-selected tuple; native_record names complete unchanged producer2 or reactive4 record, including actual captured logical inventory without gate/PID/ID rewriting",
                ),
            ),
            (
                "originals",
                V::Text(
                    "restore_commit and restore_response are application/json full ContentRefs of complete canonical actual retained Envelope bodies including assigned sequences, commit proof and completed receipt; original literal headers/bodies remain retained in the same actual native and host banks and independently checked; these refs name a strictly earlier completed pair and do not recurse",
                ),
            ),
            (
                "association",
                V::Text(
                    "owner_state/journal/mapping and context_digest equal the actual installed commit context/request; Source witness verifies actual original committed pair, key MAC receipt, signed source archive/Core target and current child/controller rather than accepting decoded refs or bool",
                ),
            ),
            (
                "physical_gate",
                V::Text(
                    "installed native restoration keeps a distinct physical gate while captured logical gate remains false; Stage reports held=true without changing logical inventory; genuine WorldActivate prepares exact prospective held=false proof before its no-allocation physical release, then publishes only after successful release; no pending/error attempt can certify a completed release",
                ),
            ),
            (
                "later_dispatch",
                V::Text(
                    "later Run/Input/Observe proof records retain the same exact completed commit association and physical=false; original model inventory and all historical stage/grant/PID/ID records stay literal; fresh registrations and immutable policy remain fresh",
                ),
            ),
            (
                "failure",
                V::Text(
                    "proof/preflight/callback failure retains original Unknown, gate/attempt/custody and all bytes; no second Admit, copied reply authority, retries, gate rewriting or live reconstruction from data",
                ),
            ),
            (
                "bounds",
                V::Text(
                    "complete evidence <=65536 canonical bytes with actual count before native effect; model/control, input banks and all retained/prospective proof copies have independent source whole-row admission",
                ),
            ),
            (
                "legacy",
                V::Text(
                    "absent restoration keeps the original receipt5/native2/native4 bytes and gate checks exactly; this separate feature/schema must be selected before hashes/Hello; it is a content proof schema, not an envelope extension",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

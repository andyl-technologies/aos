//! Binds the separate fresh query, report, proof and Prepare association schemas.

use super::*;
use crucible_node_format::{SchemaRef, canonical};

/// Names one closed member of the fresh inactive allocation family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketNativeFreshRestoreAllocationSchema {
    /// Names the startup Observe request extension.
    Query,
    /// Names the authenticated report content.
    Report,
    /// Names the report's separate keyed proof.
    Proof,
    /// Names the completed startup response extension.
    Receipt,
    /// Names the completed exchange bound into the later Prepare.
    PrepareBinding,
}

impl PacketNativeFreshRestoreAllocationSchema {
    /// Returns the exact selected grammar identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Query => PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            Self::Report => PACKET_FRESH_RESTORE_ALLOCATION_REPORT,
            Self::Proof => PACKET_FRESH_RESTORE_ALLOCATION_PROOF,
            Self::Receipt => PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT,
            Self::PrepareBinding => PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
        }
    }
}

/// Encodes the exact fresh inactive allocation grammar and producer obligations.
///
/// This declaration participates in the original source binding before birth.
/// Its data fields never authorize a native allocation or a host transition.
///
/// # Errors
/// Reports failure to encode the fixed canonical definition.
pub fn fresh_restore_allocation_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-fresh-restore-allocation-contract/13",
        "feature":PACKET_FRESH_RESTORE_ALLOCATION_FEATURE,
        "selection":"completed_admit13",
        "schemas":[
            PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            PACKET_FRESH_RESTORE_ALLOCATION_REPORT,
            PACKET_FRESH_RESTORE_ALLOCATION_PROOF,
            PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT,
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING
        ],
        "query":{
            "method":"observe",
            "fields":["schema","nonce","completed_admit_request","completed_admit_response"],
            "body":"same selected owner binding/generation; after_observation_sequence=0; maximum_items=1; body extensions empty",
            "envelope":"sole query13 extension; actual node/execution owner/session/incarnation; no capture owner or operation",
            "maximum_canonical_bytes":MAXIMUM_FRESH_RESTORE_ALLOCATION_QUERY_BYTES,
            "nonce_domain":"source-owned.packet-fresh-restore-allocation-nonce/13"
        },
        "report":{
            "schema":PACKET_FRESH_RESTORE_ALLOCATION_REPORT,
            "fields":["schema","data","proof"],
            "data_fields":["scope","storage"],
            "scope_fields":["native_pid","session","incarnation","node","owner","owner_generation","owner_binding","world","prepared_token","admission","closed_gate_receipt","nonce","assigned_query","completed_admit_request","completed_admit_response","ack_context"],
            "storage_fields":["current_retained_bytes","query_retained_growth_bytes","prepare_retained_growth_bytes","query_transient_bytes","prepare_transient_bytes","declared_counter_scratch_bytes"],
            "media_type":PACKET_FRESH_RESTORE_ALLOCATION_MEDIA,
            "maximum_canonical_bytes":MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES,
            "proof_fields":["schema","algorithm","context_digest","mac"],
            "proof_algorithm":FRESH_RESTORE_ALLOCATION_ALGORITHM,
            "proof_key_domain":"source-owned.packet-fresh-restore-allocation-key/13",
            "proof_input":"complete canonical data object only, without proof or response reference; all scope and storage fields are mandatory",
            "current_retained":"same actual inactive Control/model, endpoint, Connection/reader/blob/Hello, original ACK boot/token, policy, registrar/bootstrap/supervisor/deadline; actual typed local alias roster, each strong edge, each shared child once",
            "prospective":"all independent query report/cache/prefix owners and fixed future Prepare issuer/response owners, largest complete simultaneous query/Prepare transient phase and declared observation scratch; no transport-credit-to-heap conversion",
            "excluded":"input raw banks, archived typed reconstruction and adoption/displacement/model/socket/held-proof growth, host/Source/Core/factory/process owners; the independent whole preparation context must conjoin these before MAC or allocation"
        },
        "receipt":{
            "fields":["schema","allocation"],
            "response":"completed Observe with no ObservationBatch, next_sequence=0, complete=true and actual inactive model inventory hash; sole receipt13 ResponseShape/body.extensions member, response Envelope.extensions empty",
            "validation":"only selectedSome13 accepts this exact completed Observe body extension after closed receipt parsing; generic body-extension refusal remains unchanged",
            "evidence":"one exact report full reference/body through existing ordinary bounded proof prefix; generic raw/window/credit limits remain unchanged"
        },
        "prepare_binding":{
            "fields":["schema","assigned_query","completed_query_response","allocation"],
            "binding":"additional selected envelope extension on the actual Prepare; complete assigned digest retains this extension; existing transfer12 request/proof/receipt data remains exact"
        },
        "digests":"32-byte BLAKE3 derive_key over the complete canonical original Envelope; distinct query, Admit-request, Admit-response and query-response domains; every envelope extension retained",
        "origin":"true source-signed ACK admission on same boot/key/Hello/registration/actor/codec/original bank; actual complete original Admit request and successful correlated response; unique real cached Realize closed-gate proof",
        "fresh":"realized and admitted, gate closed, inactive and unstaged, no current operation or original Begin/terminal, no native effect or restoration attempt; no activation, mutable Prepare or active Observe used to obtain report",
        "retention":"one query attempt retained before parsing/encoding/publication; same report data/raw bytes/full reference and exact query original/terminal survive refusal/unwind; no sequence renewal, bank refund or retry",
        "currency":"query completes before assignment of Prepare; Source retains actual original pair and full report under same native/kernel/source/current controller guards; no intervening Control original except the exact assigned Prepare; native checks same retained query/report before accepting the additional Prepare binding",
        "codec":"new policy18/binding13 and fresh-query owner roots require explicit full class coverage; existing old11 and native-state12 codecs refuse populated unsupported roots until matched owning/cold successor exists",
        "default":"absent fresh selector retains all earlier launch/policy/Hello/Observe/receipt5/transfer12 bytes and refusal behavior",
        "authority":"report/key proof/counts/portable bindings grant no allocation, Core ticket, source whole context, Arm, activation, installation or restoration completion"
    }))?)
}

/// Binds one selected fresh allocation schema to its complete definition.
///
/// # Errors
/// Reports an invalid fixed identifier or definition serialization failure.
pub fn fresh_restore_allocation_schema(
    schema: PacketNativeFreshRestoreAllocationSchema,
) -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(schema.id())?,
        version: 13,
        definition: canonical::content_ref(
            &fresh_restore_allocation_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

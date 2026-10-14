//! Defines the closed confirmation specification independently of installation.

use crate::ProviderError;
use crucible_node_contract::{Id, SchemaRef, canonical};

/// Encodes the immutable source-owned native-after confirmation grammar.
///
/// # Errors
/// Reports canonical encoding failure; this data grants no installation rights.
pub fn native_after_confirmation_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-native-after-confirmation-contract/5",
        "feature":"source-owned.packet-native-after-confirmation/5",
        "selection":"closed optional AfterProtocolPoll5; absent selection preserves ordinary bytes and behavior",
        "request":"correlated Poll body unchanged; exact one envelope extension request/5 binds original Capture request ID/cnp.request.v1 identity/operation, actual terminal canonical-byte hash+sequence and snapshot/control/anchor full typed references",
        "receipt":"PollResult retains original completed Capture outcome; exact one envelope extension receipt/5 additionally names actual opaque native HostSettled body full reference and actual independent encoded Vec capacity",
        "ordering":"after owner issued only after original three-object ACKs and Capture terminal; subsequent Poll transfers that immutable fourth body with all ACKs before Poll response; confirmation cannot certify itself or enter the earlier after snapshot",
        "history":"signed source journal retains complete literal headers/bodies, request IDs, sequences, counters, byte extents, capacities and exact confirmation suffix beyond after boundary; fresh adoption preserves and applies this suffix as historical state, never Stage/Begin replay",
        "admission":"same actual native/controller sealed codec/source selection/negotiated feature and live registrar; all four native objects, raw ACK worst extents or authentic original emitter bounds, lifetime histories, banks/copies and whole four-owner memory peak admitted before effects",
        "authority":"syntax/hash/receipt/capacity alone grants no source settlement, Capture, signed archive, Ready or fresh association; source ticket and full original issuer/target proof remain mandatory"
    }))?)
}

/// Binds the closed confirmation schema to its complete immutable definition.
///
/// # Errors
/// Reports invalid identifier or canonical specification encoding failure.
pub fn native_after_confirmation_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new("source-owned.packet-native-after-confirmation/5")?,
        version: 5,
        definition: canonical::content_ref(
            &native_after_confirmation_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

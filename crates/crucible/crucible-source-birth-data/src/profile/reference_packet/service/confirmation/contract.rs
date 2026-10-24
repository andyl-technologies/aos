//! Defines the original immutable schema DATA without live protocol owners.

use crate::profile::ProviderError;
use crucible_node_format::{Id, SchemaRef, canonical};

/// Encodes the immutable source-owned native-after confirmation grammar.
///
/// # Errors
/// Reports canonical encoding failure; this data grants no installation rights.
pub fn native_after_confirmation_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(NativeAfterConfirmationContractValue)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
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

/// Serializes the original borrowed immutable contract roster without authority.
pub struct NativeAfterConfirmationContractValue;

impl serde::Serialize for NativeAfterConfirmationContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::profile::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-native-after-confirmation-contract/5"),
            ),
            (
                "feature",
                V::Text("source-owned.packet-native-after-confirmation/5"),
            ),
            (
                "selection",
                V::Text(
                    "closed optional AfterProtocolPoll5; absent selection preserves ordinary bytes and behavior",
                ),
            ),
            (
                "request",
                V::Text(
                    "correlated Poll body unchanged; exact one envelope extension request/5 binds original Capture request ID/cnp.request.v1 identity/operation, actual terminal canonical-byte hash+sequence and snapshot/control/anchor full typed references",
                ),
            ),
            (
                "receipt",
                V::Text(
                    "PollResult retains original completed Capture outcome; exact one envelope extension receipt/5 additionally names actual opaque native HostSettled body full reference and actual independent encoded Vec capacity",
                ),
            ),
            (
                "ordering",
                V::Text(
                    "after owner issued only after original three-object ACKs and Capture terminal; subsequent Poll transfers that immutable fourth body with all ACKs before Poll response; confirmation cannot certify itself or enter the earlier after snapshot",
                ),
            ),
            (
                "history",
                V::Text(
                    "signed source journal retains complete literal headers/bodies, request IDs, sequences, counters, byte extents, capacities and exact confirmation suffix beyond after boundary; fresh adoption preserves and applies this suffix as historical state, never Stage/Begin replay",
                ),
            ),
            (
                "admission",
                V::Text(
                    "same actual native/controller sealed codec/source selection/negotiated feature and live registrar; all four native objects, raw ACK worst extents or authentic original emitter bounds, lifetime histories, banks/copies and whole four-owner memory peak admitted before effects",
                ),
            ),
            (
                "authority",
                V::Text(
                    "syntax/hash/receipt/capacity alone grants no source settlement, Capture, signed archive, Ready or fresh association; source ticket and full original issuer/target proof remain mandatory",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

//! Borrows the exact saved World identity without serializing live authority.
//!
//! ```text
//! {generation,activation_id,world_binding_hash,owners,boundary}
//! ```
//!
//! The projection uses the existing saved-activation grammar. Construction
//! borrows live identity only; no clone, deserializer or activation issuer exists.

use crate::node_contract::ActivationRecord;
use serde::{Serialize, Serializer, ser::SerializeStruct};

/// Borrows the five immutable fields in the saved activation wire grammar.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalSourceRestoredWorld17View<
    'a,
>(&'a ActivationRecord);

impl<'a> OriginalSourceRestoredWorld17View<'a> {
    /// Borrows an existing World record as historical identity DATA.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn new_data(
        record: &'a ActivationRecord,
    ) -> Self {
        Self(record)
    }

    /// Counts the fixed projection header without cloning an owner roster.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn counter_scratch_data()
    -> usize {
        std::mem::size_of::<Self>()
    }
}

impl Serialize for OriginalSourceRestoredWorld17View<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let record = self.0;
        let mut fields = serializer.serialize_struct("SavedRuntimeActivation", 5)?;
        fields.serialize_field("generation", &record.generation)?;
        fields.serialize_field("activation_id", &record.activation_id)?;
        fields.serialize_field("world_binding_hash", &record.world_binding_hash)?;
        fields.serialize_field("owners", &record.owners)?;
        fields.serialize_field("boundary", &record.boundary)?;
        fields.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::{OwnerIdentity, SavedRuntimeActivation};
    use crucible_node_contract::{HashRef, Id, Phase, Position, canonical};

    #[test]
    fn borrowed_live_identity_uses_existing_saved_world_grammar() {
        let record = ActivationRecord {
            generation: 9.into(),
            activation_id: Id::new("activation/original").unwrap(),
            world_binding_hash: HashRef {
                algorithm: "blake3-256".into(),
                domain: "cnp.world-binding.v1".into(),
                digest: "7".repeat(64),
            },
            owners: vec![OwnerIdentity {
                owner: Id::new("owner/original").unwrap(),
                incarnation: Id::new("incarnation/original").unwrap(),
                generation: 4.into(),
            }],
            boundary: Position::new(17.into(), 3.into(), Phase::BoundaryControl),
        };
        let original_pointer = record.owners.as_ptr();
        let original_capacity = record.owners.capacity();
        let saved = SavedRuntimeActivation::from(&record);

        let literal = canonical::canonical_json(
            &serde_json::to_value(OriginalSourceRestoredWorld17View::new_data(&record)).unwrap(),
        )
        .unwrap();
        let decoded: SavedRuntimeActivation = serde_json::from_slice(&literal).unwrap();

        assert_eq!(decoded, saved);
        assert_eq!(
            literal,
            canonical::canonical_json(&serde_json::to_value(&saved).unwrap()).unwrap()
        );
        assert_eq!(record.owners.as_ptr(), original_pointer);
        assert_eq!(record.owners.capacity(), original_capacity);
        let mut extra_field = serde_json::to_value(&saved).unwrap();
        extra_field["ready"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<SavedRuntimeActivation>(extra_field).is_err());
    }
}

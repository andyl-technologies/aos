//! Lends the exact untouched producer inventory without cloning payload banks.
//!
//! The field projection matches PacketProgram::inventory. Its authenticating
//! borrow proves the same closed gate and initial cursor before exposing it;
//! serialization remains data and creates no startup or execution permission.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::ser::SerializeStruct;

pub(crate) struct OriginalFreshProducerInventory<'a>(&'a PacketProgram);

impl PacketProgram {
    pub(crate) fn borrow_original_fresh_inventory(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<OriginalFreshProducerInventory<'_>, ProviderError> {
        self.observe_fresh_restore_metadata(observer)?;
        Ok(OriginalFreshProducerInventory(self))
    }
}

impl OriginalFreshProducerInventory<'_> {
    /// Observes actual Bytes fields that this borrowed serializer can format.
    /// Retained model arrays remain in the independent full metadata census.
    pub(crate) fn formatter_fields_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        for event in self
            .0
            .events
            .get(self.0.next_event..)
            .ok_or(ProviderError::Correlation(
                "fresh producer formatter cursor differs",
            ))?
        {
            observer.observe(&event.payload)?;
        }
        Ok(observer.finish())
    }
}

impl Serialize for OriginalFreshProducerInventory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let program = self.0;
        let pending = program
            .events
            .get(program.next_event..)
            .ok_or_else(|| serde::ser::Error::custom("fresh producer cursor differs"))?;
        let mut value = serializer.serialize_struct("PacketInventory", 6)?;
        value.serialize_field("reached", &program.reached)?;
        value.serialize_field("gate_closed", &program.gate_closed)?;
        value.serialize_field("pending", pending)?;
        value.serialize_field("retained_outputs", &program.outputs)?;
        value.serialize_field("private_mutations", &U64::new(program.private_mutations))?;
        value.serialize_field("packet_effects", &U64::new(program.packet_effects))?;
        value.end()
    }
}

// crucible-lint: allow panic-shortcut -- real model construction and projection equality are the observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual native model and canonical serialization are test observations"
)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn actual_pending_payload_inventory_matches_owned_projection_and_hash() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let mut payload = Vec::with_capacity(777);
        payload.extend_from_slice(b"retained original payload");
        let event = PacketEvent {
            id: Id::new("fresh-original-event").unwrap(),
            evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
            payload: Some(Bytes::new(payload)),
        };
        let mut model = PacketProgram::new(vec![event], socket).unwrap();
        let mut observer = MetadataObserver::new();
        let view = model
            .borrow_original_fresh_inventory(&mut observer)
            .unwrap();
        let actual = serde_json::to_value(&view).unwrap();
        let expected = serde_json::to_value(model.inventory()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual["pending"].as_array().unwrap().len(), 1);
        assert_eq!(
            canonical::json_hash("source-owned.packet-inventory.v1", &view).unwrap(),
            canonical::json_hash("source-owned.packet-inventory.v1", &model.inventory()).unwrap()
        );
        assert!(observer.finish().vector_capacity_bytes >= 777);
        model.open_gate().unwrap();
        assert!(
            model
                .borrow_original_fresh_inventory(&mut MetadataObserver::new())
                .is_err()
        );
    }
}

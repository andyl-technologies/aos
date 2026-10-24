//! Lends the actual stopped active inventory without copying payload banks.
//!
//! The field/row projection matches the original inventory serializer exactly.
//! Its live-model guard is distinct from the untouched Fresh inventory guard.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::ser::SerializeStruct;

pub(crate) struct OriginalCaptureProducerInventory<'a>(&'a PacketProgram);

impl PacketProgram {
    pub(crate) fn borrow_original_capture_inventory(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<OriginalCaptureProducerInventory<'_>, ProviderError> {
        self.observe_original_live_capture_metadata(observer)?;
        Ok(OriginalCaptureProducerInventory(self))
    }
}

impl OriginalCaptureProducerInventory<'_> {
    /// Counts only borrowed byte fields whose serializer formats base64.
    pub(crate) fn observe_serialized_formatter_fields(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let pending = self
            .0
            .events
            .get(self.0.next_event..)
            .ok_or(ProviderError::Correlation(
                "original Capture producer cursor differs",
            ))?;
        for event in pending {
            if let Some(payload) = &event.payload {
                observer.observe(payload)?;
            }
        }
        for output in &self.0.outputs {
            observer.observe(&output.payload)?;
        }
        Ok(())
    }
}

impl Serialize for OriginalCaptureProducerInventory<'_> {
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

impl PacketProgram {
    pub(crate) fn authenticate_original_capture_cut(
        &self,
        cut: Position,
    ) -> Result<Position, ProviderError> {
        let cursor = self.observe_original_live_capture_metadata(&mut MetadataObserver::new())?;
        if cut < cursor
            || self
                .events
                .get(self.next_event..)
                .is_none_or(|pending| pending.iter().any(|event| event.completion < cut))
        {
            return Err(ProviderError::Correlation(
                "original producer Capture cut differs",
            ));
        }
        Ok(cursor)
    }
}

// crucible-lint: allow panic-shortcut -- actual native construction and byte equality are the observations.
#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn actual_active_inventory_matches_original_canonical_bytes_and_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let event = PacketEvent {
            id: Id::new("active-capture-event")?,
            evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
            payload: Some(Bytes::new(b"actual pending payload".to_vec())),
        };
        let mut model = PacketProgram::new(vec![event], socket)?;
        assert!(
            model
                .borrow_original_capture_inventory(&mut MetadataObserver::new())
                .is_err()
        );
        model.open_gate()?;
        let original = model.inventory();
        let current = original.reached;
        assert_eq!(model.authenticate_original_capture_cut(current)?, current);
        assert!(
            model
                .authenticate_original_capture_cut(Position::new(
                    U64::new(6),
                    U64::new(0),
                    Phase::BoundaryControl
                ))
                .is_err()
        );
        let mut observer = MetadataObserver::new();
        let actual = model.borrow_original_capture_inventory(&mut observer)?;
        let mut formatter = MetadataObserver::new();
        actual.observe_serialized_formatter_fields(&mut formatter)?;
        let facts = formatter.finish();
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(
            facts.vector_capacity_bytes,
            model.events[0]
                .payload
                .as_ref()
                .ok_or("payload absent")?
                .allocation_capacity()
        );
        let counted =
            crate::reference_packet::serialization_storage::actual_serialization_storage_data(
                &actual,
                facts,
                usize::MAX,
            )?;
        let omitted =
            crate::reference_packet::serialization_storage::actual_serialization_storage_data(
                &actual,
                Default::default(),
                usize::MAX,
            )?;
        assert!(counted.requested_total()? > omitted.requested_total()?);
        assert_eq!(
            canonical::canonical_json(&serde_json::to_value(&actual)?)?,
            canonical::canonical_json(&serde_json::to_value(&original)?)?
        );
        assert_eq!(
            canonical::json_hash("source-owned.packet-inventory.v1", &actual)?,
            canonical::json_hash("source-owned.packet-inventory.v1", &original)?
        );
        Ok(())
    }
}

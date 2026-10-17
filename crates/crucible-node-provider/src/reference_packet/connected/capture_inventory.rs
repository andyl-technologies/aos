//! Lends the actual stopped active inventory without copying payload banks.
//!
//! The field/row projection matches the original inventory serializer exactly.
//! Its live-model guard is distinct from the untouched Fresh inventory guard.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::ser::{SerializeSeq, SerializeStruct};

pub(crate) struct OriginalCaptureReactiveInventory<'a>(&'a PacketConnectedProgram);

impl PacketConnectedProgram {
    pub(crate) fn borrow_original_capture_inventory(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<OriginalCaptureReactiveInventory<'_>, ProviderError> {
        self.observe_original_live_capture_metadata(observer)?;
        Ok(OriginalCaptureReactiveInventory(self))
    }
}

impl OriginalCaptureReactiveInventory<'_> {
    /// Counts serialized byte fields independently of reserved inventory Vecs.
    pub(crate) fn observe_serialized_formatter_fields(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        for reaction in &self.0.reactions {
            observer.observe(&reaction.payload)?;
        }
        for delivered in &self.0.delivered_inputs {
            observer.observe(&delivered.reaction.payload)?;
        }
        for publication in &self.0.publications {
            observer.observe(&publication.reaction.payload)?;
        }
        for output in &self.0.outputs {
            observer.observe(&output.output.payload)?;
            observer.observe(&output.pending.reaction.payload)?;
        }
        // Stage/commit inventory adapters serialize references only. Their raw
        // retained payload banks do not invoke the Bytes formatter in this view.
        Ok(())
    }
}

struct StageReferences<'a>(&'a [OriginalStage]);

impl Serialize for StageReferences<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for stage in self.0 {
            sequence.serialize_element(&stage.record_ref)?;
        }
        sequence.end()
    }
}

struct CommitReferences<'a>(&'a [OriginalStage]);

impl Serialize for CommitReferences<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self.0.iter().filter(|stage| stage.commit.is_some()).count();
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for stage in self.0 {
            if let Some(commit) = &stage.commit {
                sequence.serialize_element(&commit.record_ref)?;
            }
        }
        sequence.end()
    }
}

impl Serialize for OriginalCaptureReactiveInventory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let program = self.0;
        let mut value = serializer.serialize_struct("PacketConnectedInventory", 10)?;
        value.serialize_field("reached", &program.reached)?;
        value.serialize_field("gate_closed", &program.gate_closed)?;
        value.serialize_field("reactions", &program.reactions)?;
        value.serialize_field("delivered_inputs", &program.delivered_inputs)?;
        value.serialize_field("publications", &program.publications)?;
        value.serialize_field("retained_outputs", &program.outputs)?;
        value.serialize_field(
            "reactions_completed",
            &U64::new(program.reactions_completed),
        )?;
        value.serialize_field("packet_effects", &U64::new(program.packet_effects))?;
        value.serialize_field("stages", &StageReferences(&program.stages))?;
        value.serialize_field("commits", &CommitReferences(&program.stages))?;
        value.end()
    }
}

impl PacketConnectedProgram {
    pub(crate) fn authenticate_original_capture_cut(
        &self,
        cut: Position,
    ) -> Result<Position, ProviderError> {
        let cursor = self.observe_original_live_capture_metadata(&mut MetadataObserver::new())?;
        if cut < cursor {
            return Err(ProviderError::Correlation(
                "original reactive Capture cut precedes cursor",
            ));
        }
        // This is the exact completion predicate used by Control's old
        // PacketInventory projection. No generated event Id, payload copy,
        // collected pending Vec or sorting phase is needed for this predicate.
        for reaction in &self.reactions {
            let completion = if self.definition.output.is_some() {
                reaction.evaluation.reaction_publication(U64::new(16))?
            } else {
                reaction.evaluation
            };
            if completion < cut {
                return Err(ProviderError::Correlation(
                    "original reactive Capture precedes pending completion",
                ));
            }
        }
        if self
            .publications
            .iter()
            .any(|publication| publication.publication < cut)
        {
            return Err(ProviderError::Correlation(
                "original reactive Capture precedes publication",
            ));
        }
        Ok(cursor)
    }
}

// crucible-lint: allow panic-shortcut -- actual native construction and byte equality are the observations.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_active_inventory_matches_original_canonical_bytes_and_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let endpoint = |node| -> Result<Endpoint, ContractError> {
            Ok(Endpoint {
                node_id: Id::new(node)?,
                port_id: Id::new("packet")?,
                lane_id: Id::new("lane")?,
            })
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("active-capture-route")?,
                policy: canonical::content_ref(b"actual original policy", "application/json")?,
                producer: endpoint("source")?,
                consumer: endpoint("target")?,
                delay_ps: U64::new(3),
            }],
            output: None,
        };
        let mut model = PacketConnectedProgram::new(definition, socket)?;
        assert!(
            model
                .borrow_original_capture_inventory(&mut MetadataObserver::new())
                .is_err()
        );
        model.open_gate()?;
        let original = model.inventory()?;
        let mut observer = MetadataObserver::new();
        let actual = model.borrow_original_capture_inventory(&mut observer)?;
        let mut formatter = MetadataObserver::new();
        actual.observe_serialized_formatter_fields(&mut formatter)?;
        let facts = formatter.finish();
        assert_eq!(facts.vector_banks, 0);
        assert_eq!(facts.vector_capacity_bytes, 0);
        assert_eq!(
            canonical::canonical_json(&serde_json::to_value(&actual)?)?,
            canonical::canonical_json(&serde_json::to_value(&original)?)?
        );
        assert_eq!(
            canonical::json_hash("source-owned.packet-connected-inventory/4", &actual)?,
            canonical::json_hash("source-owned.packet-connected-inventory/4", &original)?
        );
        Ok(())
    }
}

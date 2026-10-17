//! Lends the exact untouched reactive inventory without collecting references.
//!
//! These borrowed arrays and stage-reference iterators match the existing
//! PacketConnectedProgram::inventory projection. The initial-state guard is
//! checked before the loan; no stage, commit or completion is fabricated.

use super::*;
use crate::retained_metadata::MetadataObserver;
use serde::ser::{SerializeSeq, SerializeStruct};

pub(crate) struct OriginalFreshReactiveInventory<'a>(&'a PacketConnectedProgram);

impl PacketConnectedProgram {
    pub(crate) fn borrow_original_fresh_inventory(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<OriginalFreshReactiveInventory<'_>, ProviderError> {
        self.observe_fresh_restore_metadata(observer)?;
        Ok(OriginalFreshReactiveInventory(self))
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

impl Serialize for OriginalFreshReactiveInventory<'_> {
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

// crucible-lint: allow panic-shortcut -- real reactive construction and projection equality are the observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual native model and canonical serialization are test observations"
)]
mod tests {
    use super::*;

    #[test]
    fn actual_reactive_inventory_matches_owned_projection_and_refuses_open_gate() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let endpoint = |node: &str| Endpoint {
            node_id: Id::new(node).unwrap(),
            port_id: Id::new("packet-port").unwrap(),
            lane_id: Id::new("packet-lane").unwrap(),
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("fresh-route").unwrap(),
                policy: canonical::content_ref(b"original policy", "application/json").unwrap(),
                producer: endpoint("source"),
                consumer: endpoint("target"),
                delay_ps: U64::new(3),
            }],
            output: None,
        };
        let mut model = PacketConnectedProgram::new(definition, socket).unwrap();
        let view = model
            .borrow_original_fresh_inventory(&mut MetadataObserver::new())
            .unwrap();
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::to_value(model.inventory().unwrap()).unwrap()
        );
        assert_eq!(
            canonical::json_hash("source-owned.packet-connected-inventory/4", &view).unwrap(),
            canonical::json_hash(
                "source-owned.packet-connected-inventory/4",
                &model.inventory().unwrap()
            )
            .unwrap()
        );
        model.open_gate().unwrap();
        assert!(
            model
                .borrow_original_fresh_inventory(&mut MetadataObserver::new())
                .is_err()
        );
    }
}

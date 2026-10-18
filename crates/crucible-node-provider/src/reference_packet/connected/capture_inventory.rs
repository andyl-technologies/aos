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

impl PacketConnectedProgram {
    /// Borrows the exact stopped Observe17 inventory, including retained outputs.
    ///
    /// This is a field view only; the real action separately requires owning
    /// checkpoint/currentness, Source MAC and prepaid same-Boot occurrence.
    ///
    /// # Errors
    /// Refuses foreign/failed/unopened models, unfinished grants or counter overflow.
    pub(crate) fn borrow_original_observation17_inventory_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<OriginalCaptureReactiveInventory<'_>, ProviderError> {
        self.observe_original_observation17_metadata_data(observer)?;
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

impl PacketConnectedProgram {
    /// Compares the complete retained inventory with this genuine stopped owner.
    ///
    /// Queue equality includes every nested payload and causal coordinate.
    /// Stage and Commit references follow the exact original inventory order;
    /// no queue, grant, input record or pending publication is consumed here.
    ///
    /// # Errors
    /// Refuses an unavailable live Capture cut or any inventory disagreement.
    pub(crate) fn authenticate_original_settled_inventory_data(
        &self,
        inventory: &PacketConnectedInventory,
    ) -> Result<(), ProviderError> {
        self.observe_original_live_capture_metadata(&mut MetadataObserver::new())?;
        let PacketConnectedInventory {
            reached,
            gate_closed,
            reactions,
            delivered_inputs,
            publications,
            retained_outputs,
            reactions_completed,
            packet_effects,
            stages,
            commits,
        } = inventory;

        if *reached != self.reached
            || *gate_closed != self.gate_closed
            || reactions.as_slice() != self.reactions.as_slice()
            || delivered_inputs.as_slice() != self.delivered_inputs.as_slice()
            || publications.as_slice() != self.publications.as_slice()
            || retained_outputs.as_slice() != self.outputs.as_slice()
            || reactions_completed.get() != self.reactions_completed
            || packet_effects.get() != self.packet_effects
            || stages.len() != self.stages.len()
        {
            return Err(settled_inventory_mismatch());
        }

        for (expected, actual) in stages.iter().zip(&self.stages) {
            if expected != &actual.record_ref {
                return Err(settled_inventory_mismatch());
            }
        }

        let mut expected_commits = commits.iter();
        for stage in &self.stages {
            if let Some(commit) = &stage.commit {
                if expected_commits.next() != Some(&commit.record_ref) {
                    return Err(settled_inventory_mismatch());
                }
            }
        }
        if expected_commits.next().is_some() {
            return Err(settled_inventory_mismatch());
        }
        Ok(())
    }

    /// Quotes the actual borrowed fields, comparison iterators and census views.
    ///
    /// Inventory payloads remain in their existing owners. This fixed counter
    /// supplies no credit for copied vectors, serialization or model effects.
    pub(crate) const fn original_settled_inventory_counter_scratch_data() -> usize {
        use std::mem::size_of;
        use std::{iter::Zip, slice::Iter};

        size_of::<&Self>()
            + size_of::<&PacketConnectedInventory>()
            + size_of::<&Position>()
            + size_of::<&bool>()
            + size_of::<&Vec<PacketReaction>>()
            + size_of::<&Vec<PacketDeliveredInput>>()
            + size_of::<&Vec<PacketPendingPublication>>()
            + size_of::<&Vec<PacketConnectedPublication>>()
            + 2 * size_of::<&U64>()
            + 2 * size_of::<&Vec<ContentRef>>()
            + 2 * size_of::<&[PacketReaction]>()
            + 2 * size_of::<&[PacketDeliveredInput]>()
            + 2 * size_of::<&[PacketPendingPublication]>()
            + 2 * size_of::<&[PacketConnectedPublication]>()
            + size_of::<Zip<Iter<'static, ContentRef>, Iter<'static, OriginalStage>>>()
            + size_of::<Iter<'static, ContentRef>>()
            + size_of::<Iter<'static, OriginalStage>>()
            + size_of::<Option<&OriginalCommit>>()
            + size_of::<Option<&ContentRef>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<Result<Position, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

fn settled_inventory_mismatch() -> ProviderError {
    ProviderError::Correlation("native17 reactive checkpoint differs from live inventory")
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

#[cfg(test)]
mod settled_inventory_tests {
    use super::*;

    #[test]
    fn full_pending_queue_correspondence_refuses_changes_without_consuming_work()
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
                id: Id::new("settled-inventory-route")?,
                policy: canonical::content_ref(b"retained policy", "application/json")?,
                producer: endpoint("source")?,
                consumer: endpoint("target")?,
                delay_ps: U64::new(3),
            }],
            output: None,
        };
        let mut model = PacketConnectedProgram::new(definition, socket)?;
        let inactive = model.inventory()?;
        assert!(
            model
                .authenticate_original_settled_inventory_data(&inactive)
                .is_err()
        );
        model.open_gate()?;
        let reaction = PacketReaction {
            input_event: Id::new("pending-input")?,
            input_producer: Id::new("source")?,
            input_sequence: U64::new(7),
            stage_operation: Id::new("stage")?,
            commit_request: Id::new("commit")?,
            payload: Bytes::new(b"complete retained payload".to_vec()),
            parent: Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl),
            evaluation: Position::new(U64::new(5), U64::new(1), Phase::BoundaryControl),
        };
        model.reactions.push(reaction.clone());
        model.delivered_inputs.push(PacketDeliveredInput {
            reaction: reaction.clone(),
            delivery_operation: Id::new("delivery")?,
        });
        model.publications.push(PacketPendingPublication {
            event: Id::new("pending-publication")?,
            reaction,
            reaction_operation: Id::new("reaction")?,
            publication: Position::new(U64::new(5), U64::new(2), Phase::BoundaryControl),
        });
        let expected = model.inventory()?;
        let capacities = (
            model.reactions.capacity(),
            model.delivered_inputs.capacity(),
            model.publications.capacity(),
        );

        model.authenticate_original_settled_inventory_data(&expected)?;
        let mut changed = expected.clone();
        changed.reactions[0].payload = Bytes::new(b"changed retained payload".to_vec());
        assert!(
            model
                .authenticate_original_settled_inventory_data(&changed)
                .is_err()
        );
        let mut changed = expected.clone();
        changed.delivered_inputs[0].delivery_operation = Id::new("other-delivery")?;
        assert!(
            model
                .authenticate_original_settled_inventory_data(&changed)
                .is_err()
        );
        let mut changed = expected.clone();
        changed.publications[0].reaction.payload = Bytes::new(b"changed nested payload".to_vec());
        assert!(
            model
                .authenticate_original_settled_inventory_data(&changed)
                .is_err()
        );
        let mut changed = expected.clone();
        changed.packet_effects = U64::new(1);
        assert!(
            model
                .authenticate_original_settled_inventory_data(&changed)
                .is_err()
        );
        let mut changed = expected.clone();
        changed
            .stages
            .push(canonical::content_ref(b"extra stage", "application/json")?);
        assert!(
            model
                .authenticate_original_settled_inventory_data(&changed)
                .is_err()
        );
        let mut changed = expected.clone();
        changed
            .commits
            .push(canonical::content_ref(b"extra commit", "application/json")?);
        assert!(
            model
                .authenticate_original_settled_inventory_data(&changed)
                .is_err()
        );

        assert_eq!(model.inventory()?, expected);
        assert_eq!(
            capacities,
            (
                model.reactions.capacity(),
                model.delivered_inputs.capacity(),
                model.publications.capacity()
            )
        );
        model.failed = true;
        assert!(
            model
                .authenticate_original_settled_inventory_data(&expected)
                .is_err()
        );
        Ok(())
    }
}

#[path = "capture_inventory/observation17.rs"]
pub(super) mod observation17;

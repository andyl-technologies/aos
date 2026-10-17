//! Borrows the actual stopped connected inventory without clone intermediates.
//!
//! This view has the identical fields/order/content as inventory(). Its Stage
//! and Commit sequences borrow the same original refs; no new role or authority
//! follows from serialization. The current original model guard runs first.

use super::*;
use serde::ser::SerializeSeq;

#[derive(Serialize)]
pub(crate) struct OriginalStoppedConnectedInventory<'a> {
    reached: Position,
    gate_closed: bool,
    reactions: &'a [PacketReaction],
    delivered_inputs: &'a [PacketDeliveredInput],
    publications: &'a [PacketPendingPublication],
    retained_outputs: &'a [PacketConnectedPublication],
    reactions_completed: U64,
    packet_effects: U64,
    stages: StageReferences<'a>,
    commits: StageReferences<'a>,
}

struct StageReferences<'a> {
    original: &'a [OriginalStage],
    commits: bool,
}

impl Serialize for StageReferences<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = if self.commits {
            self.original
                .iter()
                .filter(|stage| stage.commit.is_some())
                .count()
        } else {
            self.original.len()
        };
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for stage in self.original {
            if self.commits {
                if let Some(commit) = &stage.commit {
                    sequence.serialize_element(&commit.record_ref)?;
                }
            } else {
                sequence.serialize_element(&stage.record_ref)?;
            }
        }
        sequence.end()
    }
}

impl PacketConnectedProgram {
    // These are the actual constructor/transition limits, not selected usage.
    // The pre-child closed Observe projection needs the same finite population
    // bounds without constructing a native model or inventing pending owners.
    pub(crate) fn borrowed_original_stopped_inventory(
        &self,
    ) -> Result<OriginalStoppedConnectedInventory<'_>, ProviderError> {
        self.current()?;
        // The old Observe path constructed project_inventory twice before
        // encoding raw4. Preserve every fallible projection check without its
        // temporary pending Vec/Id/Bytes owners. The immutable definition is
        // already borrowed by the existing implementation.
        for reaction in &self.reactions {
            reaction.input_event.validate()?;
            if "packet-reaction-"
                .len()
                .checked_add(reaction.input_event.as_str().len())
                .is_none_or(|bytes| bytes > 128)
            {
                return Err(ProviderError::Correlation(
                    "native stopped reaction identifier extent",
                ));
            }
            if self.definition.output.is_some() {
                reaction
                    .evaluation
                    .reaction_publication(U64::new(MAXIMUM_MICROSTEPS))?;
            }
        }
        Ok(OriginalStoppedConnectedInventory {
            reached: self.reached,
            gate_closed: self.gate_closed,
            reactions: &self.reactions,
            delivered_inputs: &self.delivered_inputs,
            publications: &self.publications,
            retained_outputs: &self.outputs,
            reactions_completed: U64::new(self.reactions_completed),
            packet_effects: U64::new(self.packet_effects),
            stages: StageReferences {
                original: &self.stages,
                commits: false,
            },
            commits: StageReferences {
                original: &self.stages,
                commits: true,
            },
        })
    }
}

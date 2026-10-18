//! Projects the exact Reactive inventory without running a Bytes formatter.
//!
//! Both the stopped native model and the authenticated Source DTO lend the same
//! closed field view. This visitor allocates no JSON, copied references, stage
//! bank or base64 temporary, and supplies no currentness or effect permission.

use super::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
use std::mem::size_of;

type Projection = OriginalSerializationStorageProjection;

struct InventoryFields<'a> {
    reached: &'a Position,
    gate_closed: bool,
    reactions: &'a [PacketReaction],
    delivered_inputs: &'a [PacketDeliveredInput],
    publications: &'a [PacketPendingPublication],
    outputs: &'a [PacketConnectedPublication],
    reactions_completed: U64,
    packet_effects: U64,
    roots: Roots<'a>,
}

enum Roots<'a> {
    Retained {
        stages: &'a [ContentRef],
        commits: &'a [ContentRef],
    },
    Native(&'a [OriginalStage]),
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("signed Observe17 Reactive inventory projection")
}

fn fields(out: &mut Projection, names: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for name in names {
        out.add_field(name)?;
    }
    Ok(())
}

fn decimal(out: &mut Projection, value: U64) -> Result<(), ProviderError> {
    let digits = value.get().checked_ilog10().unwrap_or(0) as usize + 1;
    out.add_unescaped_ascii_extent(digits)
}

fn position(out: &mut Projection, value: &Position) -> Result<(), ProviderError> {
    fields(out, &["time_ps", "microstep", "phase"])?;
    decimal(out, value.time_ps)?;
    decimal(out, value.microstep)?;
    out.add_value(&value.phase)
}

fn reference(out: &mut Projection, value: &ContentRef) -> Result<(), ProviderError> {
    fields(out, &["hash", "length", "media_type"])?;
    out.add_value(&value.hash)?;
    decimal(out, value.length)?;
    out.add_string(&value.media_type)
}

fn payload(out: &mut Projection, bytes: &Bytes) -> Result<(), ProviderError> {
    let length = bytes.as_slice().len();
    if length > MAXIMUM_BYTES {
        return Err(refused());
    }
    // Bytes uses unpadded base64url. Its alphabet needs no JSON escaping.
    let encoded = length
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .map(|n| n / 3)
        .ok_or_else(refused)?;
    out.add_unescaped_ascii_extent(encoded)
}

fn reaction(out: &mut Projection, value: &PacketReaction) -> Result<(), ProviderError> {
    fields(
        out,
        &[
            "input_event",
            "input_producer",
            "input_sequence",
            "stage_operation",
            "commit_request",
            "payload",
            "parent",
            "evaluation",
        ],
    )?;
    out.add_value(&value.input_event)?;
    out.add_value(&value.input_producer)?;
    decimal(out, value.input_sequence)?;
    out.add_value(&value.stage_operation)?;
    out.add_value(&value.commit_request)?;
    payload(out, &value.payload)?;
    position(out, &value.parent)?;
    position(out, &value.evaluation)
}

fn publication(
    out: &mut Projection,
    value: &PacketPendingPublication,
) -> Result<(), ProviderError> {
    fields(
        out,
        &["event", "reaction", "reaction_operation", "publication"],
    )?;
    out.add_value(&value.event)?;
    reaction(out, &value.reaction)?;
    out.add_value(&value.reaction_operation)?;
    position(out, &value.publication)
}

fn output(out: &mut Projection, value: &PacketPublication) -> Result<(), ProviderError> {
    fields(
        out,
        &[
            "event",
            "operation",
            "sequence",
            "evaluation",
            "publication",
            "payload",
        ],
    )?;
    out.add_value(&value.event)?;
    out.add_value(&value.operation)?;
    decimal(out, value.sequence)?;
    position(out, &value.evaluation)?;
    position(out, &value.publication)?;
    payload(out, &value.payload)
}

impl Roots<'_> {
    fn project(&self, out: &mut Projection) -> Result<(), ProviderError> {
        match self {
            Self::Retained { stages, commits } => {
                if stages.len() > MAXIMUM_BATCHES || commits.len() > MAXIMUM_BATCHES {
                    return Err(refused());
                }
                out.add_array_extent(stages.len())?;
                for stage in *stages {
                    reference(out, stage)?;
                }
                out.add_array_extent(commits.len())?;
                for commit in *commits {
                    reference(out, commit)?;
                }
                Ok(())
            }
            Self::Native(stages) => {
                if stages.len() > MAXIMUM_BATCHES {
                    return Err(refused());
                }
                out.add_array_extent(stages.len())?;
                for stage in *stages {
                    reference(out, &stage.record_ref)?;
                }
                let mut count = 0usize;
                for stage in *stages {
                    if stage.commit.is_some() {
                        count = count.checked_add(1).ok_or_else(refused)?;
                    }
                }
                out.add_array_extent(count)?;
                for stage in *stages {
                    if let Some(commit) = &stage.commit {
                        reference(out, &commit.record_ref)?;
                    }
                }
                Ok(())
            }
        }
    }
}

fn formatter_storage_data(fields: &InventoryFields<'_>) -> Result<usize, ProviderError> {
    let mut total = 20usize;
    let mut add = |payload: &Bytes| {
        let length = payload.as_slice().len();
        if length > MAXIMUM_BYTES {
            return Err(refused());
        }
        // The pinned base64 encoder reserves its encoded extent. Padded width
        // bounds the actual unpadded extent for all three possible tails.
        let encoded = length
            .checked_add(2)
            .map(|length| length / 3)
            .and_then(|groups| groups.checked_mul(4))
            .ok_or_else(refused)?;
        total = total.checked_add(encoded).ok_or_else(refused)?;
        Ok(())
    };
    for value in fields.reactions {
        add(&value.payload)?;
    }
    for value in fields.delivered_inputs {
        add(&value.reaction.payload)?;
    }
    for value in fields.publications {
        add(&value.reaction.payload)?;
    }
    for value in fields.outputs {
        add(&value.output.payload)?;
        add(&value.pending.reaction.payload)?;
    }
    Ok(total)
}

impl InventoryFields<'_> {
    fn project(self, out: &mut Projection) -> Result<(), ProviderError> {
        // Check every finite population before visiting even its first child.
        if [
            self.reactions.len(),
            self.delivered_inputs.len(),
            self.publications.len(),
            self.outputs.len(),
        ]
        .into_iter()
        .any(|length| length > MAXIMUM_EVENTS)
        {
            return Err(refused());
        }
        fields(
            out,
            &[
                "reached",
                "gate_closed",
                "reactions",
                "delivered_inputs",
                "publications",
                "retained_outputs",
                "reactions_completed",
                "packet_effects",
                "stages",
                "commits",
            ],
        )?;
        position(out, self.reached)?;
        out.add_value(&self.gate_closed)?;
        out.add_array_extent(self.reactions.len())?;
        for value in self.reactions {
            reaction(out, value)?;
        }
        out.add_array_extent(self.delivered_inputs.len())?;
        for value in self.delivered_inputs {
            fields(out, &["reaction", "delivery_operation"])?;
            reaction(out, &value.reaction)?;
            out.add_value(&value.delivery_operation)?;
        }
        out.add_array_extent(self.publications.len())?;
        for value in self.publications {
            publication(out, value)?;
        }
        out.add_array_extent(self.outputs.len())?;
        for value in self.outputs {
            fields(out, &["output", "pending"])?;
            output(out, &value.output)?;
            publication(out, &value.pending)?;
        }
        decimal(out, self.reactions_completed)?;
        decimal(out, self.packet_effects)?;
        self.roots.project(out)
    }
}

impl OriginalCaptureReactiveInventory<'_> {
    /// Counts only the actual serialized Bytes lengths, independently of Vec capacities.
    pub(crate) fn observation17_formatter_storage_data(&self) -> Result<usize, ProviderError> {
        let program = self.0;
        formatter_storage_data(&InventoryFields {
            reached: &program.reached,
            gate_closed: program.gate_closed,
            reactions: &program.reactions,
            delivered_inputs: &program.delivered_inputs,
            publications: &program.publications,
            outputs: &program.outputs,
            reactions_completed: U64::new(program.reactions_completed),
            packet_effects: U64::new(program.packet_effects),
            roots: Roots::Native(&program.stages),
        })
    }

    /// Projects the actual stopped native inventory through its borrowed roots.
    pub(crate) fn project_observation17_inventory_data(
        &self,
        out: &mut Projection,
    ) -> Result<(), ProviderError> {
        let program = self.0;
        InventoryFields {
            reached: &program.reached,
            gate_closed: program.gate_closed,
            reactions: &program.reactions,
            delivered_inputs: &program.delivered_inputs,
            publications: &program.publications,
            outputs: &program.outputs,
            reactions_completed: U64::new(program.reactions_completed),
            packet_effects: U64::new(program.packet_effects),
            roots: Roots::Native(&program.stages),
        }
        .project(out)
    }
}

/// Projects an already authenticated Source-owned inventory without cloning it.
pub(crate) fn project_original_observation17_inventory_data(
    value: &PacketConnectedInventory,
    out: &mut Projection,
) -> Result<(), ProviderError> {
    InventoryFields {
        reached: &value.reached,
        gate_closed: value.gate_closed,
        reactions: &value.reactions,
        delivered_inputs: &value.delivered_inputs,
        publications: &value.publications,
        outputs: &value.retained_outputs,
        reactions_completed: value.reactions_completed,
        packet_effects: value.packet_effects,
        roots: Roots::Retained {
            stages: &value.stages,
            commits: &value.commits,
        },
    }
    .project(out)
}

/// Counts the same serialized payload lengths on the Source-held inventory.
pub(crate) fn original_observation17_inventory_formatter_storage_data(
    value: &PacketConnectedInventory,
) -> Result<usize, ProviderError> {
    formatter_storage_data(&InventoryFields {
        reached: &value.reached,
        gate_closed: value.gate_closed,
        reactions: &value.reactions,
        delivered_inputs: &value.delivered_inputs,
        publications: &value.publications,
        outputs: &value.retained_outputs,
        reactions_completed: value.reactions_completed,
        packet_effects: value.packet_effects,
        roots: Roots::Retained {
            stages: &value.stages,
            commits: &value.commits,
        },
    })
}

pub(crate) fn observation17_inventory_counter_scratch_data() -> usize {
    size_of::<InventoryFields<'static>>()
        + size_of::<Roots<'static>>()
        + size_of::<OriginalCaptureReactiveInventory<'static>>()
        + size_of::<std::slice::Iter<'static, PacketReaction>>()
        + size_of::<std::slice::Iter<'static, PacketDeliveredInput>>()
        + size_of::<std::slice::Iter<'static, PacketPendingPublication>>()
        + size_of::<std::slice::Iter<'static, PacketConnectedPublication>>()
        + size_of::<std::slice::Iter<'static, OriginalStage>>()
        + size_of::<std::slice::Iter<'static, ContentRef>>()
        + size_of::<[usize; 4]>()
        + 8 * size_of::<usize>()
        + size_of::<U64>()
        + size_of::<Result<(), ProviderError>>()
}

// crucible-lint: allow panic-shortcut -- compares defining serializers with their closed projection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

    fn inventory(payload: Vec<u8>) -> Result<PacketConnectedInventory, ProviderError> {
        let position = Position {
            time_ps: U64::new(7),
            microstep: U64::new(2),
            phase: Phase::Reaction,
        };
        let reaction = PacketReaction {
            input_event: Id::new("input")?,
            input_producer: Id::new("producer")?,
            input_sequence: U64::new(u64::MAX),
            stage_operation: Id::new("stage")?,
            commit_request: Id::new("commit")?,
            payload: Bytes::new(payload),
            parent: position,
            evaluation: position,
        };
        Ok(PacketConnectedInventory {
            reached: position,
            gate_closed: false,
            reactions: vec![reaction],
            delivered_inputs: Vec::new(),
            publications: Vec::new(),
            retained_outputs: Vec::new(),
            reactions_completed: U64::new(0),
            packet_effects: U64::new(0),
            stages: Vec::new(),
            commits: Vec::new(),
        })
    }

    #[test]
    fn exact_inventory_walk_covers_each_base64_tail_and_maximum_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        for length in [0, 1, 2, 3, 4, MAXIMUM_BYTES] {
            let value = inventory(vec![255; length])?;
            let actual = actual_serialization_storage_data(&value, Default::default(), usize::MAX)?;
            let mut out = Projection::new(usize::MAX)?;
            project_original_observation17_inventory_data(&value, &mut out)?;
            let quoted = out.finish(usize::MAX)?;

            assert_eq!(quoted.maximum_encoded_bytes, actual.maximum_encoded_bytes);
            assert_eq!(quoted.serialized_value_nodes, actual.serialized_value_nodes);
            assert_eq!(
                quoted.serialized_capacity_records,
                actual.serialized_capacity_records
            );
            assert!(quoted.retained_value_backing_bytes >= actual.retained_value_backing_bytes);
            assert!(
                quoted.projected_parser_requested_bytes >= actual.projected_parser_requested_bytes
            );
        }
        Ok(())
    }

    #[test]
    fn oversized_payload_and_population_refuse_before_projection_can_be_used()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = inventory(vec![0; MAXIMUM_BYTES + 1])?;
        let mut out = Projection::new(usize::MAX)?;
        assert!(project_original_observation17_inventory_data(&value, &mut out).is_err());

        value.reactions[0].payload = Bytes::new(Vec::new());
        value
            .reactions
            .resize(MAXIMUM_EVENTS + 1, value.reactions[0].clone());
        let mut out = Projection::new(usize::MAX)?;
        assert!(project_original_observation17_inventory_data(&value, &mut out).is_err());
        Ok(())
    }
}

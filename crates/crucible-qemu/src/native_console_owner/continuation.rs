//! Process-free consumed console custody paired with the original VMState.
//!
//! Only a fully settled ledger can be captured. Neither issued physical AUTHs,
//! wrapped requests nor native revocation floors survive as execution credit.
//! Restored pending bytes keep their original projection and remain observable;
//! another grant requires the separately authenticated native restore owner.

use std::sync::Arc;

use crucible::{NativeConsoleByteOrigin, NativeConsoleMappingLease, NodeCounter, NodeId};
use serde::{Deserialize, Serialize};

use super::observation::{ConsoleProjection, RetainedConsoleByte};
use super::*;
use crate::checkpoint::bounded_cbor::{BoundedVec, HARD_FAT_CHECKPOINT_BYTES, encode_prefixed};

#[cfg(test)]
mod tests;

const MAGIC: &[u8] = b"crucible.native-console-continuation.v1\0";
const BYTE_LIMIT: u64 = crate::native_console_owner::MAX_CONSOLE_OBSERVATION_BYTES as u64;

/// Logical observation custody, with no process identity or runnable receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConsoleOriginContinuation {
    pub(super) node: NodeId,
    pub(super) ready_counter: NodeCounter,
    pub(super) plan: Vec<u8>,
    pub(super) sequence: u64,
    pub(super) ring_end: u64,
    pub(super) stream_sequences: Vec<u64>,
    pub(super) pending: Vec<RetainedConsoleByte>,
    pub(super) projection: ConsoleProjection,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    node: BoundedVec<u8, BYTE_LIMIT>,
    ready_counter: NodeCounter,
    plan: BoundedVec<u8, 1088>,
    sequence: u64,
    ring_end: u64,
    stream_sequences: BoundedVec<u64, 16>,
    pending: BoundedVec<ByteWire, BYTE_LIMIT>,
    projection: ProjectionWire,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ByteWire {
    origin: NativeConsoleByteOrigin,
    projection: ProjectionWire,
}

#[derive(Serialize, Deserialize)]
enum ProjectionWire {
    Boot,
    Run(BoundedVec<u8, BYTE_LIMIT>),
}

fn checkpoint_shape() -> ConsoleOwnerError {
    NativeConsoleError::Binding.into()
}

fn projection_wire(projection: &ConsoleProjection) -> Result<ProjectionWire, ConsoleOwnerError> {
    Ok(match projection {
        ConsoleProjection::Boot => ProjectionWire::Boot,
        ConsoleProjection::Run(map) => ProjectionWire::Run(
            BoundedVec::new(map.to_canonical_bytes()?).map_err(|_| checkpoint_shape())?,
        ),
    })
}

fn projection_from_wire(wire: ProjectionWire) -> Result<ConsoleProjection, ConsoleOwnerError> {
    Ok(match wire {
        ProjectionWire::Boot => ConsoleProjection::Boot,
        ProjectionWire::Run(bytes) => ConsoleProjection::Run(Arc::new(
            NativeConsoleMappingLease::from_canonical_bytes(bytes.as_slice())?,
        )),
    })
}

impl ConsoleOriginContinuation {
    /// Borrows the original logical node without exposing continuation fields.
    pub(crate) fn node(&self) -> &NodeId {
        &self.node
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ConsoleOwnerError> {
        let mut pending = Vec::new();
        pending.try_reserve_exact(self.pending.len())?;
        for byte in &self.pending {
            pending.push(ByteWire {
                origin: byte.origin.clone(),
                projection: projection_wire(&byte.projection)?,
            });
        }
        let mut node = Vec::new();
        node.try_reserve_exact(self.node.name.len())?;
        node.extend_from_slice(self.node.name.as_bytes());
        let wire = Wire {
            node: BoundedVec::new(node).map_err(|_| checkpoint_shape())?,
            ready_counter: self.ready_counter,
            plan: BoundedVec::new(self.plan.clone()).map_err(|_| checkpoint_shape())?,
            sequence: self.sequence,
            ring_end: self.ring_end,
            stream_sequences: BoundedVec::new(self.stream_sequences.clone())
                .map_err(|_| checkpoint_shape())?,
            pending: BoundedVec::new(pending).map_err(|_| checkpoint_shape())?,
            projection: projection_wire(&self.projection)?,
        };
        encode_prefixed(
            &wire,
            MAGIC,
            "native console continuation",
            HARD_FAT_CHECKPOINT_BYTES,
        )
        .map_err(|_| checkpoint_shape())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ConsoleOwnerError> {
        if bytes.len() as u64 > HARD_FAT_CHECKPOINT_BYTES {
            return Err(checkpoint_shape());
        }
        let payload = bytes.strip_prefix(MAGIC).ok_or_else(checkpoint_shape)?;
        let wire: Wire = ciborium::de::from_reader(payload).map_err(|_| checkpoint_shape())?;
        let node = NodeId {
            name: String::from_utf8(wire.node.into_inner()).map_err(|_| checkpoint_shape())?,
        };
        let plan_bytes = wire.plan.into_inner();
        let plan = crucible_protocol::native_console::NativeConsolePlan::decode(&plan_bytes)?;
        if plan.slot != 0
            || wire.sequence < plan.node_sequence_base
            || wire.stream_sequences.as_slice().len() != plan.streams.len()
        {
            return Err(checkpoint_shape());
        }
        let projection = projection_from_wire(wire.projection)?;
        if let ConsoleProjection::Run(map) = &projection {
            map.validate_binding(&node, plan.logical_generation, wire.ready_counter)?;
        }
        let node_delta = wire
            .sequence
            .checked_sub(plan.node_sequence_base)
            .ok_or_else(checkpoint_shape)?;
        let stream_delta = plan
            .streams
            .iter()
            .zip(wire.stream_sequences.as_slice())
            .try_fold(0_u64, |total, (row, sequence)| {
                sequence
                    .checked_sub(row.sequence_base)
                    .and_then(|delta| total.checked_add(delta))
            })
            .ok_or_else(checkpoint_shape)?;
        if stream_delta != node_delta {
            return Err(checkpoint_shape());
        }
        let mut pending = Vec::new();
        pending.try_reserve_exact(wire.pending.as_slice().len())?;
        let mut previous = None;
        let mut previous_streams = Vec::new();
        previous_streams.try_reserve_exact(plan.streams.len())?;
        previous_streams.resize(plan.streams.len(), None::<u64>);
        for byte in wire.pending.into_inner() {
            let projection = projection_from_wire(byte.projection)?;
            let origin = byte.origin;
            origin.validate()?;
            let stream_index = plan
                .streams
                .iter()
                .position(|row| row.stream == origin.stream)
                .ok_or_else(checkpoint_shape)?;
            let row = &plan.streams[stream_index];
            if origin.logical_generation != plan.logical_generation
                || origin.device.bytes != row.device_identity
                || row.owner_mask & (1_u64 << origin.vcpu) == 0
                || origin.node_sequence <= plan.node_sequence_base
                || origin.node_sequence > wire.sequence
                || origin.stream_sequence <= row.sequence_base
                || origin.stream_sequence > wire.stream_sequences.as_slice()[stream_index]
                || previous_streams[stream_index]
                    .is_some_and(|sequence| sequence.checked_add(1) != Some(origin.stream_sequence))
                || previous.is_some_and(|sequence: u64| {
                    sequence.checked_add(1) != Some(origin.node_sequence)
                })
            {
                return Err(checkpoint_shape());
            }
            match &projection {
                ConsoleProjection::Boot if origin.emitted_ps > wire.ready_counter.ticks => {
                    return Err(checkpoint_shape());
                }
                ConsoleProjection::Run(map) => {
                    map.validate_binding(&node, plan.logical_generation, wire.ready_counter)?;
                    map.project_origin(&node, &origin)?;
                }
                ConsoleProjection::Boot => {}
            }
            previous_streams[stream_index] = Some(origin.stream_sequence);
            previous = Some(origin.node_sequence);
            pending.push(RetainedConsoleByte { origin, projection });
        }
        // A retained suffix can begin after observations already handed off,
        // but each represented stream must end at its saved accepted tail.
        if previous.is_some_and(|sequence| sequence != wire.sequence)
            || previous_streams
                .iter()
                .zip(wire.stream_sequences.as_slice())
                .any(|(previous, accepted)| previous.is_some_and(|value| value != *accepted))
        {
            return Err(checkpoint_shape());
        }
        let checkpoint = Self {
            node,
            ready_counter: wire.ready_counter,
            plan: plan_bytes,
            sequence: wire.sequence,
            ring_end: wire.ring_end,
            stream_sequences: wire.stream_sequences.into_inner(),
            pending,
            projection,
        };
        // Canonical re-encoding rejects trailing bytes and alternate CBOR forms.
        if checkpoint.encode()?.as_slice() != bytes {
            return Err(checkpoint_shape());
        }
        Ok(checkpoint)
    }
}

impl ConsoleLaunchCustody {
    pub(crate) fn checkpoint_origins(
        &self,
        node: &NodeId,
        ready_counter: NodeCounter,
    ) -> Result<ConsoleOriginContinuation, ConsoleOwnerError> {
        let owner = self.lock()?;
        if !owner.issued.is_empty() || owner.clamp.is_some() {
            return Err(checkpoint_shape());
        }
        let parts = owner.accepted.checkpoint_parts()?;
        let mut plan = owner.accepted.checkpoint_plan();
        // Slot is physical authentication, not canonical continuation identity.
        plan.slot = 0;
        let checkpoint = ConsoleOriginContinuation {
            node: node.clone(),
            ready_counter,
            plan: plan.encode()?,
            sequence: parts.sequence,
            ring_end: parts.ring_end,
            stream_sequences: parts.stream_sequences,
            pending: parts.pending,
            projection: owner.projection.clone(),
        };
        // Validate the same closed representation restored by the node codec.
        ConsoleOriginContinuation::decode(&checkpoint.encode()?)
    }

    pub(crate) fn restore_origins(
        &self,
        node: &NodeId,
        saved: &ConsoleOriginContinuation,
    ) -> Result<NodeCounter, ConsoleOwnerError> {
        let mut owner = self.lock()?;
        if let Some(pending) = &owner.pending_node_restore {
            if node != &saved.node
                || pending != saved
                || owner.accepted.restored
                || !owner.issued.is_empty()
                || owner.clamp.is_some()
            {
                return Err(checkpoint_shape());
            }
            // The genuine stopped load installed logical custody before its
            // Restore request. Transfer the ready view once, without rewinding
            // the now-accepted native phase or fresh physical ledger.
            owner.pending_node_restore = None;
            return Ok(saved.ready_counter);
        }
        let mut plan = owner.accepted.checkpoint_plan();
        plan.slot = 0;
        if node != &saved.node
            || plan.encode()? != saved.plan
            || !owner.issued.is_empty()
            || owner.clamp.is_some()
        {
            return Err(checkpoint_shape());
        }
        let restored = ConsoleOriginContinuation::decode(&saved.encode()?)?;
        owner.accepted.restore_owned_parts(
            restored.sequence,
            restored.ring_end,
            restored.stream_sequences,
            restored.pending,
        );
        owner.projection = restored.projection;
        Ok(restored.ready_counter)
    }
}

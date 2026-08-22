//! Canonical codec for the complete production fault-runtime continuation.

use std::collections::{BTreeMap, BTreeSet};

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use super::{
    ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    production_checkpoint_identity, validate_pending_qemu_event_sequences,
    validate_production_event_state, validate_qemu_action_ledger,
};
use crate::fault_action_sink::CommittedQemuActionEvidence;
use crucible::model::{
    ContentHash, FaultObservation, FaultRuntimeCheckpoint, FaultSignalPlan, HostFaultActionState,
    ReferencedSignalEvent, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};
use crucible_shmem::DequeuedFaultEvent;

use crate::checkpoint::bounded_cbor::{
    BoundedVec, HARD_FAT_CHECKPOINT_BYTES, admit_input, encode_prefixed, map_decode_error,
};

mod resource;

use resource::*;

const MAGIC: &[u8] = b"crucible.production-fault-runtime.v5\0";
const MAX_BYTES: u64 = HARD_FAT_CHECKPOINT_BYTES;
const MAX_EVENT_RECORDS: u64 = 1_073_741_824;

type CheckpointBytes = BoundedVec<u8, HARD_FAT_CHECKPOINT_BYTES>;
type CheckpointByteRecords = BoundedVec<CheckpointBytes, MAX_EVENT_RECORDS>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointWire {
    runtime: Option<CheckpointBytes>,
    host: CheckpointBytes,
    qemu_fingerprints: BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: BTreeMap<NodeId, u64>,
    qemu_fault_event_sequences: BTreeMap<NodeId, u64>,
    qemu_issued_actions: BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_action_commits: BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    network_state: Option<NetworkWire>,
    emitted_events: BoundedVec<ReferencedSignalEvent, MAX_EVENT_RECORDS>,
    pending_qemu_observations: BoundedVec<FaultObservation, MAX_EVENT_RECORDS>,
    pending_qemu_events: BTreeMap<NodeId, CheckpointByteRecords>,
    identity: ContentHash,
}

#[derive(Serialize)]
struct CheckpointEncodeWire<'a> {
    runtime: Option<CheckpointBytes>,
    host: CheckpointBytes,
    qemu_fingerprints: &'a BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: &'a BTreeMap<NodeId, u64>,
    qemu_fault_event_sequences: &'a BTreeMap<NodeId, u64>,
    qemu_issued_actions: &'a BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_action_commits: &'a BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    qemu_active_rule_ids: &'a BTreeSet<ContentHash>,
    network_state: Option<NetworkEncodeWire<'a>>,
    emitted_events: &'a [ReferencedSignalEvent],
    pending_qemu_observations: &'a [FaultObservation],
    pending_qemu_events: EncodedQemuEventMap<'a>,
    identity: ContentHash,
}

struct EncodedQemuEventMap<'a> {
    entries: Vec<(&'a NodeId, CheckpointByteRecords)>,
}

impl Serialize for EncodedQemuEventMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (node, events) in &self.entries {
            map.serialize_entry(node, events)?;
        }
        map.end()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkWire {
    identity: ContentHash,
    scheduler: CheckpointBytes,
    committed_frontier_ticks: u64,
    pending_outputs: CheckpointByteRecords,
    adapter_state: CheckpointBytes,
}

#[derive(Serialize)]
struct NetworkEncodeWire<'a> {
    identity: ContentHash,
    scheduler: CheckpointBytes,
    committed_frontier_ticks: u64,
    pending_outputs: CheckpointByteRecords,
    adapter_state: &'a [u8],
}

impl ProductionFaultRuntimeCheckpoint {
    /// Encodes every evaluator, host, QEMU, network, and event continuation.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeCheckpointCodecError`] if a nested owner
    /// cannot encode or the aggregate exceeds the hard checkpoint ceiling.
    pub fn to_canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, ProductionFaultRuntimeCheckpointCodecError> {
        self.to_canonical_bytes_with_limit(MAX_BYTES)
    }

    /// Encodes the checkpoint under an authored fat-checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeCheckpointCodecError`] under the same
    /// conditions as [`Self::to_canonical_bytes`], and when the canonical
    /// representation exceeds `fat_checkpoint_bytes`.
    pub fn to_canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, ProductionFaultRuntimeCheckpointCodecError> {
        admit_checkpoint_record_count("emitted fault events", self.emitted_events.len())?;
        admit_checkpoint_record_count(
            "pending QEMU observations",
            self.pending_qemu_observations.len(),
        )?;

        let mut budget = CheckpointConstructionBudget::new(maximum);
        let runtime = self
            .runtime
            .as_ref()
            .map(|runtime| {
                let bytes = checkpoint_runtime_bytes(runtime, budget.remaining())?;
                budget.admit(bytes.len())?;
                bounded_checkpoint_bytes(bytes)
            })
            .transpose()?;
        let host_bytes = self
            .host
            .canonical_bytes_with_limits(host_resource_limits(self, budget.remaining()))
            .map_err(map_host_error)?;
        budget.admit(host_bytes.len())?;
        let host = bounded_checkpoint_bytes(host_bytes)?;
        let network_state = self
            .network_state
            .as_ref()
            .map(|network| encode_network(network, &mut budget))
            .transpose()?;
        let pending_qemu_events = encode_qemu_event_map(&self.pending_qemu_events, &mut budget)?;

        let wire = CheckpointEncodeWire {
            runtime,
            host,
            qemu_fingerprints: &self.qemu_fingerprints,
            qemu_fault_sequences: &self.qemu_fault_sequences,
            qemu_fault_event_sequences: &self.qemu_fault_event_sequences,
            qemu_issued_actions: &self.qemu_issued_actions,
            qemu_action_commits: &self.qemu_action_commits,
            qemu_active_rule_ids: &self.qemu_active_rule_ids,
            network_state,
            emitted_events: &self.emitted_events,
            pending_qemu_observations: &self.pending_qemu_observations,
            pending_qemu_events,
            identity: self.identity,
        };
        encode_prefixed(&wire, MAGIC, "production fault checkpoint", maximum)
            .map_err(map_bounded_cbor_error)
    }

    /// Decodes and authenticates a complete production fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeCheckpointCodecError`] for unsupported,
    /// malformed, over-limit, noncanonical, plan-mismatched, identity-mismatched,
    /// or nested restore-invalid state.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
    ) -> Result<Self, ProductionFaultRuntimeCheckpointCodecError> {
        Self::from_canonical_bytes_with_limit(
            bytes,
            plan,
            scenario_seed,
            plan.resource_limits().fat_checkpoint_bytes,
        )
    }

    /// Decodes a checkpoint under its authored fat-checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeCheckpointCodecError`] under the same
    /// conditions as [`Self::from_canonical_bytes`], and before decoding when
    /// `bytes` exceeds `fat_checkpoint_bytes`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
        fat_checkpoint_bytes: u64,
    ) -> Result<Self, ProductionFaultRuntimeCheckpointCodecError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(ProductionFaultRuntimeCheckpointCodecError::Version)?;
        admit_input(bytes, "production fault checkpoint", fat_checkpoint_bytes)
            .map_err(map_bounded_cbor_error)?;
        let requested = u64::try_from(bytes.len()).map_err(|_| {
            resource_limit(
                "fat_checkpoint_bytes",
                0,
                u64::MAX,
                fat_checkpoint_bytes,
                HARD_FAT_CHECKPOINT_BYTES,
            )
        })?;
        if fat_checkpoint_bytes != plan.resource_limits().fat_checkpoint_bytes {
            return Err(resource_limit(
                "fat_checkpoint_bytes",
                0,
                requested,
                fat_checkpoint_bytes,
                HARD_FAT_CHECKPOINT_BYTES,
            ));
        }
        plan.resource_limits()
            .reserve("fat_checkpoint_bytes", 0, requested)
            .map_err(map_plan_resource_error)?;
        let wire: CheckpointWire = ciborium::de::from_reader(payload)
            .map_err(map_decode_error)
            .map_err(map_bounded_cbor_error)?;
        let runtime = wire
            .runtime
            .map(|encoded| {
                FaultRuntimeCheckpoint::from_canonical_bytes(
                    encoded.as_slice(),
                    plan,
                    scenario_seed,
                )
            })
            .transpose()
            .map_err(map_runtime_error)?;
        if runtime.is_none() && !plan.programs().is_empty() {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Runtime);
        }
        let host = HostFaultActionState::from_canonical_bytes_with_limits(
            wire.host.as_slice(),
            plan.resource_limits(),
        )
        .map_err(map_host_error)?;
        let network_state = wire
            .network_state
            .map(|network| decode_network(network, fat_checkpoint_bytes))
            .transpose()?;
        let mut pending_qemu_events = BTreeMap::new();
        for (node, events) in wire.pending_qemu_events {
            let events = events.into_inner();
            let mut decoded = Vec::new();
            decoded
                .try_reserve_exact(events.len())
                .map_err(|_| record_allocation_limit("pending QEMU event count", events.len()))?;
            for encoded in events {
                decoded.push(
                    DequeuedFaultEvent::from_canonical_bytes(encoded.as_slice())
                        .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::QemuEvent)?,
                );
            }
            pending_qemu_events.insert(node, decoded);
        }
        let checkpoint = Self {
            runtime,
            host,
            qemu_fingerprints: wire.qemu_fingerprints,
            qemu_fault_sequences: wire.qemu_fault_sequences,
            qemu_fault_event_sequences: wire.qemu_fault_event_sequences,
            qemu_issued_actions: wire.qemu_issued_actions,
            qemu_action_commits: wire.qemu_action_commits,
            qemu_active_rule_ids: wire.qemu_active_rule_ids,
            network_state,
            emitted_events: wire.emitted_events.into_inner(),
            pending_qemu_observations: wire.pending_qemu_observations.into_inner(),
            pending_qemu_events,
            identity: wire.identity,
        };
        validate_checkpoint(&checkpoint, plan)?;
        if checkpoint
            .to_canonical_bytes_with_limit(fat_checkpoint_bytes)?
            .as_slice()
            != bytes
        {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Noncanonical);
        }
        Ok(checkpoint)
    }
}

/// Failure to encode or authenticate the production fault continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProductionFaultRuntimeCheckpointCodecError {
    /// The envelope version is unsupported.
    #[error("unsupported production fault-runtime checkpoint version")]
    Version,
    /// The aggregate cannot be serialized or decoded.
    #[error("malformed production fault-runtime checkpoint")]
    Malformed,
    /// The evaluator continuation is invalid.
    #[error("invalid evaluator continuation")]
    Runtime,
    /// The host action ledger is invalid.
    #[error("invalid host action continuation")]
    Host,
    /// The scheduler/network continuation is invalid.
    #[error("invalid network continuation")]
    Network,
    /// A drained QEMU event is invalid.
    #[error("invalid drained QEMU event continuation")]
    QemuEvent,
    /// Cross-owner indexes, ledgers, event state, or identity are inconsistent.
    #[error("invalid production fault-runtime checkpoint state")]
    Invalid,
    /// A bounded envelope allocation cannot be admitted.
    #[error(
        "production fault-runtime resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Resource field that rejected the operation.
        field: &'static str,
        /// Bytes already retained by the operation.
        current: u64,
        /// Additional bytes requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical production fault-runtime checkpoint")]
    Noncanonical,
}

fn encode_network<'a>(
    checkpoint: &'a ProductionNetworkStateCheckpoint,
    budget: &mut CheckpointConstructionBudget,
) -> Result<NetworkEncodeWire<'a>, ProductionFaultRuntimeCheckpointCodecError> {
    let scheduler_bytes = checkpoint
        .scheduler
        .canonical_bytes_with_limit(budget.remaining())
        .map_err(map_scheduler_network_error)?;
    budget.admit(scheduler_bytes.len())?;
    let scheduler = bounded_checkpoint_bytes(scheduler_bytes)?;

    let mut pending_outputs = Vec::new();
    pending_outputs
        .try_reserve_exact(checkpoint.pending_outputs.len())
        .map_err(|_| {
            record_allocation_limit(
                "pending network output count",
                checkpoint.pending_outputs.len(),
            )
        })?;
    for output in &checkpoint.pending_outputs {
        let encoded = output
            .canonical_bytes_with_limit(budget.remaining())
            .map_err(map_backend_network_output_error)?;
        budget.admit(encoded.len())?;
        pending_outputs.push(bounded_checkpoint_bytes(encoded)?);
    }
    let pending_outputs = BoundedVec::new(pending_outputs).map_err(map_bounded_cbor_error)?;
    admit_checkpoint_bytes(
        "network adapter checkpoint bytes",
        checkpoint.adapter_state.len(),
    )?;
    budget.admit(checkpoint.adapter_state.len())?;

    Ok(NetworkEncodeWire {
        identity: checkpoint.identity,
        scheduler,
        committed_frontier_ticks: checkpoint.committed_frontier.ticks,
        pending_outputs,
        adapter_state: &checkpoint.adapter_state,
    })
}

fn decode_network(
    wire: NetworkWire,
    maximum: u64,
) -> Result<ProductionNetworkStateCheckpoint, ProductionFaultRuntimeCheckpointCodecError> {
    let pending_outputs = wire.pending_outputs.into_inner();
    let mut decoded_outputs = Vec::new();
    decoded_outputs
        .try_reserve_exact(pending_outputs.len())
        .map_err(|_| {
            record_allocation_limit("pending network output count", pending_outputs.len())
        })?;
    for encoded in pending_outputs {
        decoded_outputs.push(
            BackendNetworkOutput::from_canonical_bytes_with_limit(encoded.as_slice(), maximum)
                .map_err(map_backend_network_output_error)?,
        );
    }

    Ok(ProductionNetworkStateCheckpoint {
        identity: wire.identity,
        scheduler: SchedulerNetworkCheckpoint::from_canonical_bytes_with_limit(
            wire.scheduler.as_slice(),
            maximum,
        )
        .map_err(map_scheduler_network_error)?,
        committed_frontier: crucible::VirtualTime {
            ticks: wire.committed_frontier_ticks,
        },
        pending_outputs: decoded_outputs,
        adapter_state: wire.adapter_state.into_inner(),
    })
}

fn bounded_checkpoint_bytes(
    bytes: Vec<u8>,
) -> Result<CheckpointBytes, ProductionFaultRuntimeCheckpointCodecError> {
    BoundedVec::new(bytes).map_err(map_bounded_cbor_error)
}

fn encode_qemu_event_map<'a>(
    events_by_node: &'a BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    budget: &mut CheckpointConstructionBudget,
) -> Result<EncodedQemuEventMap<'a>, ProductionFaultRuntimeCheckpointCodecError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(events_by_node.len())
        .map_err(|_| {
            record_allocation_limit("pending QEMU event node count", events_by_node.len())
        })?;

    for (node, events) in events_by_node {
        let mut encoded_events = Vec::new();
        encoded_events
            .try_reserve_exact(events.len())
            .map_err(|_| record_allocation_limit("pending QEMU event count", events.len()))?;
        for event in events {
            let encoded = event
                .canonical_bytes()
                .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::QemuEvent)?;
            budget.admit(encoded.len())?;
            encoded_events.push(bounded_checkpoint_bytes(encoded)?);
        }
        let encoded_events = BoundedVec::new(encoded_events).map_err(map_bounded_cbor_error)?;
        entries.push((node, encoded_events));
    }

    Ok(EncodedQemuEventMap { entries })
}

fn validate_checkpoint(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
    plan: &FaultSignalPlan,
) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
    if checkpoint
        .qemu_fault_sequences
        .keys()
        .ne(checkpoint.qemu_fingerprints.keys())
        || checkpoint
            .qemu_fault_event_sequences
            .keys()
            .ne(checkpoint.qemu_fingerprints.keys())
    {
        return Err(ProductionFaultRuntimeCheckpointCodecError::Invalid);
    }
    validate_qemu_action_ledger(
        &checkpoint.qemu_issued_actions,
        &checkpoint.qemu_action_commits,
        &checkpoint.qemu_active_rule_ids,
    )
    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Invalid)?;
    validate_pending_qemu_event_sequences(
        &checkpoint.pending_qemu_events,
        &checkpoint.qemu_fault_event_sequences,
    )
    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Invalid)?;
    validate_production_event_state(
        &checkpoint.emitted_events,
        &[],
        &checkpoint.pending_qemu_observations,
        &[],
        &checkpoint.pending_qemu_events,
        plan.resource_limits(),
    )
    .map_err(map_identity_error)?;
    let identity = production_checkpoint_identity(
        plan.id(),
        plan.resource_limits(),
        checkpoint.runtime.as_ref(),
        &checkpoint.host,
        &checkpoint.qemu_fingerprints,
        &checkpoint.qemu_fault_sequences,
        &checkpoint.qemu_fault_event_sequences,
        &checkpoint.qemu_issued_actions,
        &checkpoint.qemu_action_commits,
        &checkpoint.qemu_active_rule_ids,
        checkpoint.network_state.as_ref(),
        &checkpoint.emitted_events,
        &checkpoint.pending_qemu_observations,
        &checkpoint.pending_qemu_events,
    )
    .map_err(map_identity_error)?;
    if identity != checkpoint.identity {
        return Err(ProductionFaultRuntimeCheckpointCodecError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

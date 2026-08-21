//! Canonical codec for the complete production fault-runtime continuation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    production_checkpoint_identity, validate_pending_qemu_event_sequences,
    validate_production_event_state, validate_qemu_action_ledger,
};
use crate::fault_action_sink::CommittedQemuActionEvidence;
use crucible::model::{
    ContentHash, FaultObservation, FaultResourceLimitError, FaultRuntimeCheckpoint,
    FaultSignalPlan, HostFaultActionState, ReferencedSignalEvent, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};
use crucible_shmem::DequeuedFaultEvent;

use crate::checkpoint::bounded_cbor::{
    BoundedCborError, BoundedVec, HARD_FAT_CHECKPOINT_BYTES, admit_input, encode_prefixed,
};

const MAGIC: &[u8] = b"crucible.production-fault-runtime.v4\0";
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
    qemu_action_commits: BTreeMap<ContentHash, QemuActionCommitWire>,
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    network_state: Option<NetworkWire>,
    emitted_events: BoundedVec<ReferencedSignalEvent, MAX_EVENT_RECORDS>,
    pending_qemu_observations: BoundedVec<FaultObservation, MAX_EVENT_RECORDS>,
    pending_qemu_events: BTreeMap<NodeId, CheckpointByteRecords>,
    identity: ContentHash,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QemuActionCommitWire {
    command_sequence: u64,
    command_kind: u16,
    before_hash: [u8; 32],
    after_hash: [u8; 32],
}

impl From<CommittedQemuActionEvidence> for QemuActionCommitWire {
    fn from(value: CommittedQemuActionEvidence) -> Self {
        Self {
            command_sequence: value.command_sequence,
            command_kind: value.command_kind,
            before_hash: value.before_hash,
            after_hash: value.after_hash,
        }
    }
}

impl From<QemuActionCommitWire> for CommittedQemuActionEvidence {
    fn from(value: QemuActionCommitWire) -> Self {
        Self {
            command_sequence: value.command_sequence,
            command_kind: value.command_kind,
            before_hash: value.before_hash,
            after_hash: value.after_hash,
        }
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
        let wire = CheckpointWire {
            runtime: self
                .runtime
                .as_ref()
                .map(FaultRuntimeCheckpoint::canonical_bytes)
                .transpose()
                .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Runtime)?
                .map(bounded_checkpoint_bytes)
                .transpose()?,
            host: bounded_checkpoint_bytes(
                self.host
                    .canonical_bytes()
                    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Host)?,
            )?,
            qemu_fingerprints: self.qemu_fingerprints.clone(),
            qemu_fault_sequences: self.qemu_fault_sequences.clone(),
            qemu_fault_event_sequences: self.qemu_fault_event_sequences.clone(),
            qemu_issued_actions: self.qemu_issued_actions.clone(),
            qemu_action_commits: self
                .qemu_action_commits
                .iter()
                .map(|(identity, commit)| (*identity, (*commit).into()))
                .collect(),
            qemu_active_rule_ids: self.qemu_active_rule_ids.clone(),
            network_state: self
                .network_state
                .as_ref()
                .map(encode_network)
                .transpose()?,
            emitted_events: BoundedVec::new(self.emitted_events.clone())
                .map_err(map_bounded_cbor_error)?,
            pending_qemu_observations: BoundedVec::new(self.pending_qemu_observations.clone())
                .map_err(map_bounded_cbor_error)?,
            pending_qemu_events: self
                .pending_qemu_events
                .iter()
                .map(|(node, events)| {
                    let encoded = events
                        .iter()
                        .map(DequeuedFaultEvent::canonical_bytes)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::QemuEvent)?;
                    Ok((node.clone(), bounded_checkpoint_records(encoded)?))
                })
                .collect::<Result<_, ProductionFaultRuntimeCheckpointCodecError>>()?,
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
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
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
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Runtime)?;
        if runtime.is_none() && !plan.programs().is_empty() {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Runtime);
        }
        let host = HostFaultActionState::from_canonical_bytes(wire.host.as_slice())
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Host)?;
        let network_state = wire.network_state.map(decode_network).transpose()?;
        let pending_qemu_events = wire
            .pending_qemu_events
            .into_iter()
            .map(|(node, events)| {
                let decoded = events
                    .into_inner()
                    .into_iter()
                    .map(|encoded| DequeuedFaultEvent::from_canonical_bytes(encoded.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::QemuEvent)?;
                Ok((node, decoded))
            })
            .collect::<Result<_, ProductionFaultRuntimeCheckpointCodecError>>()?;
        let checkpoint = Self {
            runtime,
            host,
            qemu_fingerprints: wire.qemu_fingerprints,
            qemu_fault_sequences: wire.qemu_fault_sequences,
            qemu_fault_event_sequences: wire.qemu_fault_event_sequences,
            qemu_issued_actions: wire.qemu_issued_actions,
            qemu_action_commits: wire
                .qemu_action_commits
                .into_iter()
                .map(|(identity, commit)| (identity, commit.into()))
                .collect(),
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

fn map_bounded_cbor_error(error: BoundedCborError) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        BoundedCborError::Malformed => ProductionFaultRuntimeCheckpointCodecError::Malformed,
        BoundedCborError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource_limit(field, current, requested, configured, hard),
    }
}

fn map_plan_resource_error(
    error: FaultResourceLimitError,
) -> ProductionFaultRuntimeCheckpointCodecError {
    match error {
        FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        }
        | FaultResourceLimitError::UsageOverflow {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource_limit(field, current, requested, configured, hard),
        FaultResourceLimitError::ConfiguredAboveHard {
            field,
            configured,
            hard,
        } => resource_limit(field, 0, configured, configured, hard),
        FaultResourceLimitError::Zero { field } => resource_limit(field, 0, 1, 0, 0),
        FaultResourceLimitError::UnknownField { field } => resource_limit(field, 0, 1, 0, 0),
        FaultResourceLimitError::Representation { field, value } => {
            resource_limit(field, 0, value, value, value)
        }
    }
}

const fn resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> ProductionFaultRuntimeCheckpointCodecError {
    ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    }
}

fn encode_network(
    checkpoint: &ProductionNetworkStateCheckpoint,
) -> Result<NetworkWire, ProductionFaultRuntimeCheckpointCodecError> {
    Ok(NetworkWire {
        identity: checkpoint.identity,
        scheduler: bounded_checkpoint_bytes(
            checkpoint
                .scheduler
                .canonical_bytes()
                .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        )?,
        committed_frontier_ticks: checkpoint.committed_frontier.ticks,
        pending_outputs: bounded_checkpoint_records(
            checkpoint
                .pending_outputs
                .iter()
                .map(BackendNetworkOutput::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        )?,
        adapter_state: bounded_checkpoint_bytes(checkpoint.adapter_state.clone())?,
    })
}

fn decode_network(
    wire: NetworkWire,
) -> Result<ProductionNetworkStateCheckpoint, ProductionFaultRuntimeCheckpointCodecError> {
    Ok(ProductionNetworkStateCheckpoint {
        identity: wire.identity,
        scheduler: SchedulerNetworkCheckpoint::from_canonical_bytes(wire.scheduler.as_slice())
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        committed_frontier: crucible::VirtualTime {
            ticks: wire.committed_frontier_ticks,
        },
        pending_outputs: wire
            .pending_outputs
            .into_inner()
            .into_iter()
            .map(|encoded| BackendNetworkOutput::from_canonical_bytes(encoded.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        adapter_state: wire.adapter_state.into_inner(),
    })
}

fn bounded_checkpoint_bytes(
    bytes: Vec<u8>,
) -> Result<CheckpointBytes, ProductionFaultRuntimeCheckpointCodecError> {
    BoundedVec::new(bytes).map_err(map_bounded_cbor_error)
}

fn bounded_checkpoint_records(
    records: Vec<Vec<u8>>,
) -> Result<CheckpointByteRecords, ProductionFaultRuntimeCheckpointCodecError> {
    let mut bounded = Vec::new();
    bounded.try_reserve_exact(records.len()).map_err(|_| {
        resource_limit(
            "checkpoint record count",
            0,
            records.len() as u64,
            MAX_EVENT_RECORDS,
            MAX_EVENT_RECORDS,
        )
    })?;
    for record in records {
        bounded.push(bounded_checkpoint_bytes(record)?);
    }
    BoundedVec::new(bounded).map_err(map_bounded_cbor_error)
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
    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Invalid)?;
    let identity = production_checkpoint_identity(
        plan.id(),
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
    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Invalid)?;
    if identity != checkpoint.identity {
        return Err(ProductionFaultRuntimeCheckpointCodecError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

//! Canonical codec for the complete production fault-runtime continuation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    production_checkpoint_identity, validate_pending_qemu_event_sequences,
    validate_production_event_state, validate_qemu_action_ledger,
};
use crucible::model::{
    ContentHash, FaultObservation, FaultRuntimeCheckpoint, FaultSignalPlan, HostFaultActionState,
    ReferencedSignalEvent, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutput, NodeId, SchedulerNetworkCheckpoint};
use crucible_shmem::DequeuedFaultEvent;

const MAGIC: &[u8] = b"crucible.production-fault-runtime.v1\0";
const MAX_BYTES: usize = 1_610_612_736;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointWire {
    runtime: Option<Vec<u8>>,
    host: Vec<u8>,
    qemu_fingerprints: BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: BTreeMap<NodeId, u64>,
    qemu_fault_event_sequences: BTreeMap<NodeId, u64>,
    qemu_issued_actions: BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_active_rule_ids: BTreeSet<ContentHash>,
    network_state: Option<NetworkWire>,
    emitted_events: Vec<ReferencedSignalEvent>,
    pending_qemu_observations: Vec<FaultObservation>,
    pending_qemu_events: BTreeMap<NodeId, Vec<Vec<u8>>>,
    identity: ContentHash,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkWire {
    identity: ContentHash,
    scheduler: Vec<u8>,
    pending_outputs: Vec<Vec<u8>>,
    adapter_state: Vec<u8>,
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
        let wire = CheckpointWire {
            runtime: self
                .runtime
                .as_ref()
                .map(FaultRuntimeCheckpoint::canonical_bytes)
                .transpose()
                .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Runtime)?,
            host: self
                .host
                .canonical_bytes()
                .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Host)?,
            qemu_fingerprints: self.qemu_fingerprints.clone(),
            qemu_fault_sequences: self.qemu_fault_sequences.clone(),
            qemu_fault_event_sequences: self.qemu_fault_event_sequences.clone(),
            qemu_issued_actions: self.qemu_issued_actions.clone(),
            qemu_active_rule_ids: self.qemu_active_rule_ids.clone(),
            network_state: self
                .network_state
                .as_ref()
                .map(encode_network)
                .transpose()?,
            emitted_events: self.emitted_events.clone(),
            pending_qemu_observations: self.pending_qemu_observations.clone(),
            pending_qemu_events: self
                .pending_qemu_events
                .iter()
                .map(|(node, events)| {
                    let encoded = events
                        .iter()
                        .map(DequeuedFaultEvent::canonical_bytes)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::QemuEvent)?;
                    Ok((node.clone(), encoded))
                })
                .collect::<Result<_, ProductionFaultRuntimeCheckpointCodecError>>()?,
            identity: self.identity,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&wire, &mut payload)
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
        if payload.len() > MAX_BYTES {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Limit);
        }
        let mut bytes = Vec::with_capacity(MAGIC.len() + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
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
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(ProductionFaultRuntimeCheckpointCodecError::Version)?;
        if payload.len() > MAX_BYTES {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Limit);
        }
        plan.resource_limits()
            .reserve(
                "fat_checkpoint_bytes",
                0,
                u64::try_from(bytes.len())
                    .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Limit)?,
            )
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Limit)?;
        let wire: CheckpointWire = ciborium::de::from_reader(payload)
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
        let runtime = wire
            .runtime
            .map(|encoded| {
                FaultRuntimeCheckpoint::from_canonical_bytes(&encoded, plan, scenario_seed)
            })
            .transpose()
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Runtime)?;
        if runtime.is_none() && !plan.programs().is_empty() {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Runtime);
        }
        let host = HostFaultActionState::from_canonical_bytes(&wire.host)
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Host)?;
        let network_state = wire.network_state.map(decode_network).transpose()?;
        let pending_qemu_events = wire
            .pending_qemu_events
            .into_iter()
            .map(|(node, events)| {
                let decoded = events
                    .into_iter()
                    .map(|encoded| DequeuedFaultEvent::from_canonical_bytes(&encoded))
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
            qemu_active_rule_ids: wire.qemu_active_rule_ids,
            network_state,
            emitted_events: wire.emitted_events,
            pending_qemu_observations: wire.pending_qemu_observations,
            pending_qemu_events,
            identity: wire.identity,
        };
        validate_checkpoint(&checkpoint, plan)?;
        if checkpoint.to_canonical_bytes()?.as_slice() != bytes {
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
    /// The aggregate exceeds a compiled or plan-authored resource ceiling.
    #[error("production fault-runtime checkpoint exceeds its size limit")]
    Limit,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical production fault-runtime checkpoint")]
    Noncanonical,
}

fn encode_network(
    checkpoint: &ProductionNetworkStateCheckpoint,
) -> Result<NetworkWire, ProductionFaultRuntimeCheckpointCodecError> {
    Ok(NetworkWire {
        identity: checkpoint.identity,
        scheduler: checkpoint
            .scheduler
            .canonical_bytes()
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        pending_outputs: checkpoint
            .pending_outputs
            .iter()
            .map(BackendNetworkOutput::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        adapter_state: checkpoint.adapter_state.clone(),
    })
}

fn decode_network(
    wire: NetworkWire,
) -> Result<ProductionNetworkStateCheckpoint, ProductionFaultRuntimeCheckpointCodecError> {
    Ok(ProductionNetworkStateCheckpoint {
        identity: wire.identity,
        scheduler: SchedulerNetworkCheckpoint::from_canonical_bytes(&wire.scheduler)
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        pending_outputs: wire
            .pending_outputs
            .into_iter()
            .map(|encoded| BackendNetworkOutput::from_canonical_bytes(&encoded))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Network)?,
        adapter_state: wire.adapter_state,
    })
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
mod tests {
    use super::*;

    fn empty_checkpoint(
        plan: &FaultSignalPlan,
        network_state: Option<ProductionNetworkStateCheckpoint>,
    ) -> ProductionFaultRuntimeCheckpoint {
        let mut checkpoint = ProductionFaultRuntimeCheckpoint {
            runtime: None,
            host: HostFaultActionState::default(),
            qemu_fingerprints: BTreeMap::new(),
            qemu_fault_sequences: BTreeMap::new(),
            qemu_fault_event_sequences: BTreeMap::new(),
            qemu_issued_actions: BTreeMap::new(),
            qemu_active_rule_ids: BTreeSet::new(),
            network_state,
            emitted_events: Vec::new(),
            pending_qemu_observations: Vec::new(),
            pending_qemu_events: BTreeMap::new(),
            identity: ContentHash::from_bytes(b"uninitialized checkpoint identity"),
        };
        checkpoint.identity = production_checkpoint_identity(
            plan.id(),
            checkpoint.runtime.as_ref(),
            &checkpoint.host,
            &checkpoint.qemu_fingerprints,
            &checkpoint.qemu_fault_sequences,
            &checkpoint.qemu_fault_event_sequences,
            &checkpoint.qemu_issued_actions,
            &checkpoint.qemu_active_rule_ids,
            checkpoint.network_state.as_ref(),
            &checkpoint.emitted_events,
            &checkpoint.pending_qemu_observations,
            &checkpoint.pending_qemu_events,
        )
        .unwrap_or_else(|error| panic!("empty checkpoint identity should encode: {error}"));
        checkpoint
    }

    fn empty_network(adapter_state: Vec<u8>) -> ProductionNetworkStateCheckpoint {
        ProductionNetworkStateCheckpoint::new(
            ContentHash::from_bytes(b"network semantic identity"),
            SchedulerNetworkCheckpoint {
                links: Vec::new(),
                rng_positions: BTreeMap::new(),
                signal_fault_wakeup_nanos: None,
            },
            Vec::new(),
            adapter_state,
        )
    }

    #[test]
    fn complete_production_checkpoint_round_trips_canonically() {
        let plan = FaultSignalPlan::empty();
        let seed = ContentHash::from_bytes(b"empty checkpoint seed");
        let checkpoint = empty_checkpoint(&plan, Some(empty_network(b"adapter-v1".to_vec())));

        let bytes = checkpoint
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("checkpoint should encode: {error}"));
        let restored = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed)
            .unwrap_or_else(|error| panic!("checkpoint should decode: {error}"));

        assert_eq!(restored.id(), checkpoint.id());
        assert_eq!(
            restored
                .to_canonical_bytes()
                .unwrap_or_else(|error| panic!("restored checkpoint should encode: {error}")),
            bytes
        );
    }

    #[test]
    fn aggregate_identity_binds_network_adapter_bytes() {
        let plan = FaultSignalPlan::empty();
        let seed = ContentHash::from_bytes(b"network mutation seed");
        let checkpoint = empty_checkpoint(&plan, Some(empty_network(b"adapter-v1".to_vec())));
        let mut mutated = checkpoint.clone();
        mutated
            .network_state
            .as_mut()
            .unwrap_or_else(|| panic!("test checkpoint should own network state"))
            .adapter_state = b"adapter-v2".to_vec();
        let bytes = mutated
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("mutated fixture should encode: {error}"));

        assert!(matches!(
            ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed),
            Err(ProductionFaultRuntimeCheckpointCodecError::Invalid)
        ));
    }

    #[test]
    fn aggregate_codec_rejects_trailing_bytes() {
        let plan = FaultSignalPlan::empty();
        let seed = ContentHash::from_bytes(b"trailing checkpoint seed");
        let mut bytes = empty_checkpoint(&plan, None)
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("checkpoint should encode: {error}"));
        bytes.push(0);

        assert!(
            ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed).is_err()
        );
    }
}

//! Checkpoint state validation, resource accounting, identity, and manifests.

use super::*;

#[path = "checkpoint_identity_material.rs"]
mod material;
#[path = "checkpoint_identity/record_state.rs"]
mod record_state;

use material::*;
pub(super) use record_state::*;

pub(super) trait NodeSequenceLookup {
    fn sequence(&self, node: &NodeId) -> Option<u64>;
}

#[cfg(test)]
impl NodeSequenceLookup for BTreeMap<NodeId, u64> {
    fn sequence(&self, node: &NodeId) -> Option<u64> {
        self.get(node).copied()
    }
}

impl NodeSequenceLookup for QemuNodeSet {
    fn sequence(&self, node: &NodeId) -> Option<u64> {
        self.fault_event_sequence(node)
    }
}

impl NodeSequenceLookup for QemuNodeMap<u64> {
    fn sequence(&self, node: &NodeId) -> Option<u64> {
        self.get(node).copied()
    }
}

pub(super) fn validate_pending_qemu_event_sequences(
    pending_qemu_events: &PendingQemuEventMap,
    next_sequences: &impl NodeSequenceLookup,
) -> Result<(), ProductionFaultRuntimeError> {
    for (node, events) in pending_qemu_events {
        let Some(first) = events.first() else {
            continue;
        };
        let next_sequence =
            next_sequences
                .sequence(node)
                .ok_or_else(|| BackendError::Rejected {
                    message: format!(
                        "pending QEMU fault events name unknown node `{}`",
                        node.name
                    ),
                })?;
        if first.header.event_sequence == 0 {
            return Err(BackendError::Rejected {
                message: format!(
                    "pending QEMU fault events for `{}` begin with sequence zero",
                    node.name
                ),
            }
            .into());
        }
        for pair in events.windows(2) {
            let expected = pair[0]
                .header
                .event_sequence
                .checked_add(1)
                .ok_or_else(|| BackendError::Rejected {
                    message: format!(
                        "pending QEMU fault-event sequence for `{}` is exhausted",
                        node.name
                    ),
                })?;
            if pair[1].header.event_sequence != expected {
                return Err(BackendError::Rejected {
                    message: format!(
                        "pending QEMU fault events for `{}` are not contiguous: expected {}, observed {}",
                        node.name, expected, pair[1].header.event_sequence
                    ),
                }
                .into());
            }
        }
        let observed_next = events
            .last()
            .and_then(|event| event.header.event_sequence.checked_add(1))
            .ok_or_else(|| BackendError::Rejected {
                message: format!(
                    "pending QEMU fault-event sequence for `{}` is exhausted",
                    node.name
                ),
            })?;
        if observed_next != next_sequence {
            return Err(BackendError::Rejected {
                message: format!(
                    "pending QEMU fault events for `{}` end before sequence {}, but the live continuation requires {}",
                    node.name, observed_next, next_sequence
                ),
            }
            .into());
        }
    }
    Ok(())
}

pub(super) fn extend_referenced_event_usage(
    events: &[ReferencedSignalEvent],
    resource_limits: FaultResourceLimits,
    mut records: u64,
    mut total_bytes: u64,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    for event in events {
        let (evidence, bytes) = event
            .canonical_value_identity()
            .map_err(FaultExecutionError::from)?;
        if evidence != event.evidence {
            return Err(FaultExecutionError::CheckpointPresence.into());
        }
        resource_limits.reserve("event_records", records, 1)?;
        records += 1;
        let value_bytes =
            u64::try_from(bytes).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_inline_payload_bytes",
                value: u64::MAX,
            })?;
        resource_limits.reserve("event_inline_payload_bytes", 0, value_bytes)?;
        let signal_bytes = u64::try_from(event.signal.as_str().len()).map_err(|_| {
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            }
        })?;
        let record_bytes = signal_bytes
            .checked_add(value_bytes)
            .and_then(|value| value.checked_add(81))
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            })?;
        resource_limits.reserve("event_log_bytes", total_bytes, record_bytes)?;
        total_bytes += record_bytes;
    }
    Ok((records, total_bytes))
}

pub(super) fn extend_observation_usage(
    observations: &[FaultObservation],
    resource_limits: FaultResourceLimits,
    mut records: u64,
    mut total_bytes: u64,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    for observation in observations {
        let material = observation_identity_material(observation, resource_limits)?;
        resource_limits.reserve("event_records", records, 1)?;
        records = records
            .checked_add(1)
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            })?;
        let record_bytes =
            u64::try_from(material.len()).map_err(|_| FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            })?;
        resource_limits.reserve("event_log_bytes", total_bytes, record_bytes)?;
        total_bytes = total_bytes.checked_add(record_bytes).ok_or(
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            },
        )?;
    }
    Ok((records, total_bytes))
}

pub(super) fn extend_pending_qemu_event_usage(
    events_by_node: &PendingQemuEventMap,
    resource_limits: FaultResourceLimits,
    mut records: u64,
    mut total_bytes: u64,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    for events in events_by_node.values() {
        for event in events {
            resource_limits.reserve("event_records", records, 1)?;
            records = records
                .checked_add(1)
                .ok_or(FaultResourceLimitError::Representation {
                    field: "event_records",
                    value: u64::MAX,
                })?;
            let payload_bytes = u64::try_from(event.payload.len()).map_err(|_| {
                FaultResourceLimitError::Representation {
                    field: "event_inline_payload_bytes",
                    value: u64::MAX,
                }
            })?;
            resource_limits.reserve("event_inline_payload_bytes", 0, payload_bytes)?;
            let header_bytes =
                u64::try_from(crucible_shmem::FAULT_EVENT_HEADER_V1_BYTES).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "event_log_bytes",
                        value: u64::MAX,
                    }
                })?;
            let record_bytes = payload_bytes.checked_add(header_bytes).ok_or(
                FaultResourceLimitError::Representation {
                    field: "event_log_bytes",
                    value: u64::MAX,
                },
            )?;
            resource_limits.reserve("event_log_bytes", total_bytes, record_bytes)?;
            total_bytes = total_bytes.checked_add(record_bytes).ok_or(
                FaultResourceLimitError::Representation {
                    field: "event_log_bytes",
                    value: u64::MAX,
                },
            )?;
        }
    }
    Ok((records, total_bytes))
}

pub(super) fn observation_identity_material(
    observation: &FaultObservation,
    resource_limits: FaultResourceLimits,
) -> Result<Vec<u8>, ProductionFaultRuntimeError> {
    observation_identity_material_with_checkpoint_offset(observation, resource_limits, None)
}

pub(super) fn observation_identity_material_at_checkpoint_offset(
    observation: &FaultObservation,
    resource_limits: FaultResourceLimits,
    checkpoint_offset: u64,
) -> Result<Vec<u8>, ProductionFaultRuntimeError> {
    observation_identity_material_with_checkpoint_offset(
        observation,
        resource_limits,
        Some(checkpoint_offset),
    )
}

fn observation_identity_material_with_checkpoint_offset(
    observation: &FaultObservation,
    resource_limits: FaultResourceLimits,
    checkpoint_offset: Option<u64>,
) -> Result<Vec<u8>, ProductionFaultRuntimeError> {
    if observation.semantic_version != crucible::model::FAULT_RUNTIME_STATE_VERSION
        || observation.evidence == ContentHash::default()
        || !matches!(
            observation.kind,
            FaultObservationKind::FaultOpportunity
                | FaultObservationKind::EffectCommitted
                | FaultObservationKind::EffectApplied
        )
        || observation.binding.is_none()
        || observation.target.is_none()
        || observation
            .target
            .as_ref()
            .is_some_and(|target| target.validate().is_err())
    {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    let mut material = match checkpoint_offset {
        Some(offset) => {
            BoundedObservationIdentityMaterial::at_checkpoint_offset(resource_limits, offset)
        }
        None => BoundedObservationIdentityMaterial::new(resource_limits),
    };
    material.append(&observation.semantic_version.to_be_bytes())?;
    material.append_length_prefixed(observation.kind.as_str().as_bytes())?;
    material.append(&observation.coordinate.virtual_nanos.to_be_bytes())?;
    match observation.coordinate.retired_instructions {
        Some(retired) => {
            material.push(1)?;
            material.append(&retired.to_be_bytes())?;
        }
        None => material.push(0)?,
    }
    match &observation.binding {
        Some(binding) => {
            material.push(1)?;
            material.append_length_prefixed(binding.as_str().as_bytes())?;
        }
        None => material.push(0)?,
    }
    match &observation.target {
        Some(target) => {
            material.push(1)?;
            material.append_target(target)?;
        }
        None => material.push(0)?,
    }
    match observation.opportunity {
        Some(opportunity) => {
            material.push(1)?;
            material.append(&opportunity.bytes)?;
        }
        None => material.push(0)?,
    }
    material.append(&observation.evidence.bytes)?;
    Ok(material.into_bytes())
}

// crucible-lint: allow rust-allow -- aggregate identity receives every independently owned checkpoint component explicitly.
#[allow(
    clippy::too_many_arguments,
    reason = "the aggregate identity must receive every independently owned checkpoint component explicitly"
)]
pub(super) fn production_checkpoint_identity(
    plan: ContentHash,
    resource_limits: FaultResourceLimits,
    runtime: Option<&FaultRuntimeCheckpoint>,
    host: &HostFaultActionState,
    qemu_fingerprints: &QemuNodeMap<ContentHash>,
    qemu_fault_sequences: &QemuNodeMap<u64>,
    qemu_fault_event_sequences: &QemuNodeMap<u64>,
    qemu_issued_actions: &QemuActionMap<ResolvedBindingAction>,
    qemu_action_commits: &QemuActionMap<CommittedQemuActionEvidence>,
    qemu_active_rule_ids: &QemuActionSet,
    network_state: Option<&ProductionNetworkStateCheckpoint>,
    emitted_events: &[ReferencedSignalEvent],
    pending_qemu_observations: &[FaultObservation],
    pending_qemu_events: &PendingQemuEventMap,
) -> Result<ContentHash, ProductionFaultRuntimeError> {
    let mut material = BoundedCheckpointIdentityMaterial::new(resource_limits);
    material.append(&plan.bytes)?;
    material.append(&host.digest().bytes)?;
    match network_state {
        Some(network_state) => {
            material.push(1)?;
            material.append(&network_state.id().bytes)?;
            let scheduler_maximum = material.remaining_after_length_prefix()?;
            material.append_length_prefixed(
                &network_state
                    .scheduler
                    .canonical_bytes_with_limit(scheduler_maximum)
                    .map_err(map_identity_scheduler_error)?,
            )?;
            material.append(&network_state.committed_frontier.ticks.to_be_bytes())?;
            let pending_output_count =
                u64::try_from(network_state.pending_outputs.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "event_log_bytes",
                        value: u64::MAX,
                    }
                })?;
            material.append(&pending_output_count.to_be_bytes())?;
            for output in &network_state.pending_outputs {
                let output_maximum = material.remaining_after_length_prefix()?;
                material.append_length_prefixed(
                    &output
                        .canonical_bytes_with_limit(output_maximum)
                        .map_err(map_identity_network_output_error)?,
                )?;
            }
            material.append_length_prefixed(&network_state.adapter_state)?;
        }
        None => material.push(0)?,
    }
    if let Some(runtime) = runtime {
        material.append(
            &runtime
                .content_id()
                .map_err(FaultExecutionError::from)?
                .bytes,
        )?;
    }
    for event in emitted_events {
        material.append(event.signal.as_str().as_bytes())?;
        material.push(0)?;
        material.append(&event.coordinate.virtual_nanos.to_be_bytes())?;
        material.append(
            &event
                .coordinate
                .retired_instructions
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        )?;
        material.append(&event.same_coordinate_sequence.to_be_bytes())?;
        material.append(&event.evidence.bytes)?;
    }
    for observation in pending_qemu_observations {
        let checkpoint_offset = material.offset_after_length_prefix()?;
        material.append_length_prefixed(&observation_identity_material_at_checkpoint_offset(
            observation,
            resource_limits,
            checkpoint_offset,
        )?)?;
    }
    for (node, events) in pending_qemu_events {
        material.append(node.name.as_bytes())?;
        material.push(0)?;
        for event in events {
            material.append(&event.header.encode())?;
            material.append(&event.payload)?;
        }
    }
    for (node, fingerprint) in qemu_fingerprints {
        material.append_length_prefixed(node.name.as_bytes())?;
        material.append(&fingerprint.bytes)?;
        let command_sequence = qemu_fault_sequences
            .get(node)
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let event_sequence = qemu_fault_event_sequences
            .get(node)
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        material.append(&command_sequence.to_be_bytes())?;
        material.append(&event_sequence.to_be_bytes())?;
    }
    if qemu_fault_sequences.keys().ne(qemu_fingerprints.keys())
        || qemu_fault_event_sequences
            .keys()
            .ne(qemu_fingerprints.keys())
    {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    for (identity, action) in qemu_issued_actions {
        material.append(&identity.bytes)?;
        material.append(&action.id().bytes)?;
        let commit = qemu_action_commits
            .get(identity)
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        material.append(&commit.command_sequence.to_be_bytes())?;
        material.append(&commit.command_kind.to_be_bytes())?;
        material.append(&commit.before_hash)?;
        material.append(&commit.after_hash)?;
    }
    if qemu_action_commits.keys().ne(qemu_issued_actions.keys()) {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    for identity in qemu_active_rule_ids {
        material.append(&identity.bytes)?;
    }
    Ok(ContentHash::from_canonical_hex_bytes(
        "crucible.production-fault-runtime-checkpoint.v9",
        material.as_slice(),
    ))
}

pub(super) fn validate_qemu_action_ledger(
    actions: &QemuActionMap<ResolvedBindingAction>,
    commits: &QemuActionMap<CommittedQemuActionEvidence>,
    active_rule_ids: &QemuActionSet,
) -> Result<(), ProductionFaultRuntimeError> {
    if commits.keys().ne(actions.keys())
        || commits
            .values()
            .any(|commit| commit.command_sequence == 0 || commit.command_kind == 0)
    {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    if actions.iter().any(|(identity, action)| {
        *identity != action.id()
            || !matches!(
                action.kind,
                BindingActionKind::UpsertPersistent | BindingActionKind::Apply
            )
            || !matches!(action.effect.specification(), EffectSpecification::Node(_))
    }) {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    if active_rule_ids.iter().any(|identity| {
        actions
            .get(identity)
            .is_none_or(|action| action.kind != BindingActionKind::UpsertPersistent)
    }) {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    Ok(())
}

pub(super) fn production_manifests(
    nodes: &QemuNodeSet,
    host: HostFaultAdapterManifests,
) -> Result<FaultAdapterManifests, ProductionFaultRuntimeError> {
    Ok(FaultAdapterManifests {
        network: host.network,
        storage: host.storage,
        node: nodes.fault_capability_manifest()?,
    })
}

pub(super) fn validate_ready_marker_admission(
    plan: &FaultSignalPlan,
    nodes: &QemuNodeSet,
) -> Result<(), ProductionFaultRuntimeError> {
    for binding in plan.bindings() {
        let EffectSpecification::Node(effect) = binding.effect().specification() else {
            continue;
        };
        let marker = match effect {
            NodeEffectSpecification::Lifecycle {
                boot_policy: NodeBootPolicy::RequireReady { ready_marker, .. },
                ..
            }
            | NodeEffectSpecification::Hang {
                watchdog_policy:
                    NodeWatchdogPolicy::TransitionAfter {
                        boot_policy: NodeBootPolicy::RequireReady { ready_marker, .. },
                        ..
                    },
                ..
            } => ready_marker,
            _ => continue,
        };
        for target in binding.selector().resolved().targets() {
            let crucible::model::ResolvedFaultTarget::Node { node } = target else {
                return Err(BackendError::Rejected {
                    message: format!(
                        "ready-marker binding `{}` contains a non-node target",
                        binding.id()
                    ),
                }
                .into());
            };
            if !nodes.admits_ready_marker(node, marker) {
                return Err(BackendError::Rejected {
                    message: format!(
                        "ready marker `{}` is absent from live node `{}` launch manifest",
                        marker.as_str(),
                        node.as_str()
                    ),
                }
                .into());
            }
        }
    }
    Ok(())
}

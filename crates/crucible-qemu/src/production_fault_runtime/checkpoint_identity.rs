//! Checkpoint state validation, resource accounting, identity, and manifests.

use super::*;

pub(super) fn validate_production_event_state(
    emitted_events: &[ReferencedSignalEvent],
    additional_emitted_events: &[ReferencedSignalEvent],
    pending_observations: &[FaultObservation],
    additional_observations: &[FaultObservation],
    pending_qemu_events: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    resource_limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeError> {
    let (records, bytes) = extend_referenced_event_usage(emitted_events, resource_limits, 0, 0)?;
    let (records, bytes) =
        extend_referenced_event_usage(additional_emitted_events, resource_limits, records, bytes)?;
    let (records, bytes) =
        extend_observation_usage(pending_observations, resource_limits, records, bytes)?;
    let (records, bytes) =
        extend_observation_usage(additional_observations, resource_limits, records, bytes)?;
    let _ = extend_pending_qemu_event_usage(pending_qemu_events, resource_limits, records, bytes)?;
    Ok(())
}

pub(super) fn validate_pending_qemu_event_sequences(
    pending_qemu_events: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
    next_sequences: &BTreeMap<NodeId, u64>,
) -> Result<(), ProductionFaultRuntimeError> {
    for (node, events) in pending_qemu_events {
        let Some(first) = events.first() else {
            continue;
        };
        let next_sequence = next_sequences
            .get(node)
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
        if observed_next != *next_sequence {
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
        let material = observation_identity_material(observation)?;
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
    events_by_node: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
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
) -> Result<Vec<u8>, ProductionFaultRuntimeError> {
    if observation.semantic_version != crucible::model::FAULT_RUNTIME_STATE_VERSION
        || observation.evidence == ContentHash::default()
        || !matches!(
            observation.kind,
            FaultObservationKind::FaultOpportunity | FaultObservationKind::EffectApplied
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
    let mut material = Vec::new();
    material.extend_from_slice(&observation.semantic_version.to_be_bytes());
    append_length_prefixed(&mut material, observation.kind.as_str().as_bytes())?;
    material.extend_from_slice(&observation.coordinate.virtual_nanos.to_be_bytes());
    match observation.coordinate.retired_instructions {
        Some(retired) => {
            material.push(1);
            material.extend_from_slice(&retired.to_be_bytes());
        }
        None => material.push(0),
    }
    match &observation.binding {
        Some(binding) => {
            material.push(1);
            append_length_prefixed(&mut material, binding.as_str().as_bytes())?;
        }
        None => material.push(0),
    }
    match &observation.target {
        Some(target) => {
            material.push(1);
            append_length_prefixed(&mut material, target.canonical_material().as_bytes())?;
        }
        None => material.push(0),
    }
    match observation.opportunity {
        Some(opportunity) => {
            material.push(1);
            material.extend_from_slice(&opportunity.bytes);
        }
        None => material.push(0),
    }
    material.extend_from_slice(&observation.evidence.bytes);
    Ok(material)
}

pub(super) fn append_length_prefixed(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), ProductionFaultRuntimeError> {
    let length =
        u64::try_from(value.len()).map_err(|_| FaultResourceLimitError::Representation {
            field: "event_log_bytes",
            value: u64::MAX,
        })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the aggregate identity must receive every independently owned checkpoint component explicitly"
)]
pub(super) fn production_checkpoint_identity(
    plan: ContentHash,
    runtime: Option<&FaultRuntimeCheckpoint>,
    host: &HostFaultActionState,
    qemu_fingerprints: &BTreeMap<NodeId, ContentHash>,
    qemu_fault_sequences: &BTreeMap<NodeId, u64>,
    qemu_fault_event_sequences: &BTreeMap<NodeId, u64>,
    qemu_issued_actions: &BTreeMap<ContentHash, ResolvedBindingAction>,
    qemu_action_commits: &BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    qemu_active_rule_ids: &BTreeSet<ContentHash>,
    network_state: Option<&ProductionNetworkStateCheckpoint>,
    emitted_events: &[ReferencedSignalEvent],
    pending_qemu_observations: &[FaultObservation],
    pending_qemu_events: &BTreeMap<NodeId, Vec<DequeuedFaultEvent>>,
) -> Result<ContentHash, ProductionFaultRuntimeError> {
    let mut material = Vec::new();
    material.extend_from_slice(&plan.bytes);
    material.extend_from_slice(&host.digest().bytes);
    match network_state {
        Some(network_state) => {
            material.push(1);
            material.extend_from_slice(&network_state.id().bytes);
            append_length_prefixed(
                &mut material,
                &network_state.scheduler.canonical_bytes().map_err(|_| {
                    ProductionFaultRuntimeError::CheckpointEncoding {
                        component: "scheduler network",
                    }
                })?,
            )?;
            let pending_output_count =
                u64::try_from(network_state.pending_outputs.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "event_log_bytes",
                        value: u64::MAX,
                    }
                })?;
            material.extend_from_slice(&pending_output_count.to_be_bytes());
            for output in &network_state.pending_outputs {
                append_length_prefixed(
                    &mut material,
                    &output.canonical_bytes().map_err(|_| {
                        ProductionFaultRuntimeError::CheckpointEncoding {
                            component: "pending network output",
                        }
                    })?,
                )?;
            }
            append_length_prefixed(&mut material, &network_state.adapter_state)?;
        }
        None => material.push(0),
    }
    if let Some(runtime) = runtime {
        material.extend_from_slice(
            &runtime
                .content_id()
                .map_err(FaultExecutionError::from)?
                .bytes,
        );
    }
    for event in emitted_events {
        material.extend_from_slice(event.signal.as_str().as_bytes());
        material.push(0);
        material.extend_from_slice(&event.coordinate.virtual_nanos.to_be_bytes());
        material.extend_from_slice(
            &event
                .coordinate
                .retired_instructions
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        material.extend_from_slice(&event.same_coordinate_sequence.to_be_bytes());
        material.extend_from_slice(&event.evidence.bytes);
    }
    for observation in pending_qemu_observations {
        append_length_prefixed(&mut material, &observation_identity_material(observation)?)?;
    }
    for (node, events) in pending_qemu_events {
        material.extend_from_slice(node.name.as_bytes());
        material.push(0);
        for event in events {
            material.extend_from_slice(&event.header.encode());
            material.extend_from_slice(&event.payload);
        }
    }
    for (node, fingerprint) in qemu_fingerprints {
        append_length_prefixed(&mut material, node.name.as_bytes())?;
        material.extend_from_slice(&fingerprint.bytes);
        let command_sequence = qemu_fault_sequences
            .get(node)
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        let event_sequence = qemu_fault_event_sequences
            .get(node)
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        material.extend_from_slice(&command_sequence.to_be_bytes());
        material.extend_from_slice(&event_sequence.to_be_bytes());
    }
    if qemu_fault_sequences.keys().ne(qemu_fingerprints.keys())
        || qemu_fault_event_sequences
            .keys()
            .ne(qemu_fingerprints.keys())
    {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    for (identity, action) in qemu_issued_actions {
        material.extend_from_slice(&identity.bytes);
        material.extend_from_slice(&action.id().bytes);
        let commit = qemu_action_commits
            .get(identity)
            .ok_or(FaultExecutionError::CheckpointPresence)?;
        material.extend_from_slice(&commit.command_sequence.to_be_bytes());
        material.extend_from_slice(&commit.command_kind.to_be_bytes());
        material.extend_from_slice(&commit.before_hash);
        material.extend_from_slice(&commit.after_hash);
    }
    if qemu_action_commits.keys().ne(qemu_issued_actions.keys()) {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    for identity in qemu_active_rule_ids {
        material.extend_from_slice(&identity.bytes);
    }
    Ok(ContentHash::from_canonical_material(
        "crucible.production-fault-runtime-checkpoint.v8",
        &hex_bytes(&material),
    ))
}

pub(super) fn validate_qemu_action_ledger(
    actions: &BTreeMap<ContentHash, ResolvedBindingAction>,
    commits: &BTreeMap<ContentHash, CommittedQemuActionEvidence>,
    active_rule_ids: &BTreeSet<ContentHash>,
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

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

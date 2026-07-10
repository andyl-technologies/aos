// DAG closure persistence, artifact bytes, and local-store helpers.
fn persist_checkpoint_cow_deltas<S>(
    store: &S,
    checkpoint: &Checkpoint,
    cow_deltas: &mut BTreeMap<CowDeltaRef, ContentHash>,
    schedule_deltas: &mut Vec<ContentHash>,
    event_log_segments: &mut Vec<ContentHash>,
) -> Result<(), TemporalGraphStoreError>
where
    S: DagStore + ?Sized,
{
    for cow_ref in checkpoint.cow_delta_refs() {
        if cow_deltas.contains_key(&cow_ref) {
            continue;
        }
        let delta_key = match cow_ref.kind {
            CowDeltaKind::ScheduleDelta => {
                let key = store
                    .put(&schedule_delta_store_bytes(&checkpoint.schedule_delta))
                    .map_err(|source| TemporalGraphStoreError::Store {
                        operation: "put-schedule-delta",
                        source,
                    })?;
                schedule_deltas.push(key);
                key
            }
            CowDeltaKind::EventLogSegment => {
                let exists = store.exists(&cow_ref.content).map_err(|source| {
                    TemporalGraphStoreError::Store {
                        operation: "lookup-event-log-segment",
                        source,
                    }
                })?;
                if !exists {
                    return Err(TemporalGraphStoreError::Store {
                        operation: "lookup-event-log-segment",
                        source: DagStoreError::NotFound {
                            key: cow_ref.content,
                        },
                    });
                }
                event_log_segments.push(cow_ref.content);
                cow_ref.content
            }
            CowDeltaKind::VmMemory | CowDeltaKind::DeviceOverlay => store
                .put(&cow_delta_store_bytes(cow_ref))
                .map_err(|source| TemporalGraphStoreError::Store {
                    operation: "put-cow-delta",
                    source,
                })?,
        };
        cow_deltas.insert(cow_ref, delta_key);
    }
    Ok(())
}

fn insert_checkpoint_store_keys(checkpoint: &Checkpoint, keys: &mut BTreeSet<ContentHash>) {
    keys.insert(ContentHash::from_bytes(&checkpoint_store_bytes(checkpoint)));
    if !checkpoint.schedule_delta.is_empty() {
        keys.insert(ContentHash::from_bytes(&schedule_delta_store_bytes(
            &checkpoint.schedule_delta,
        )));
    }
    for cow_ref in checkpoint.cow_delta_refs() {
        match cow_ref.kind {
            CowDeltaKind::ScheduleDelta => {}
            CowDeltaKind::EventLogSegment => {
                keys.insert(cow_ref.content);
            }
            CowDeltaKind::VmMemory | CowDeltaKind::DeviceOverlay => {
                keys.insert(ContentHash::from_bytes(&cow_delta_store_bytes(cow_ref)));
            }
        }
    }
}

fn delete_collectible_store_keys<S>(
    store: &S,
    report: &mut TemporalGraphGcReport,
) -> Result<(), TemporalGraphStoreError>
where
    S: DagStore + ?Sized,
{
    for key in &report.collectible_store_keys {
        let deleted = store
            .delete(key)
            .map_err(|source| TemporalGraphStoreError::Store {
                operation: "delete-gc-object",
                source,
            })?;
        if deleted {
            report.deleted_store_keys.insert(*key);
        } else {
            report.missing_store_keys.insert(*key);
        }
    }
    Ok(())
}

fn scenario_def_store_bytes(def: &ScenarioDef) -> Vec<u8> {
    format!(
        "crucible.dag-store.scenario-def.v1\nscenario_ref={}\n{}\n{}\n",
        content_hash_hex(def.id),
        seed_material(def.seed),
        app_random_draw_cap_material(def.app_random_draw_cap)
    )
    .into_bytes()
}

fn reproduction_artifact_canonical_bytes(
    scenario: &ScenarioDefForm,
    schedule: &Schedule,
) -> Vec<u8> {
    let magic = if scenario.world.io_nodes().next().is_some() {
        REPRODUCTION_ARTIFACT_BINARY_MAGIC_V2
    } else {
        REPRODUCTION_ARTIFACT_BINARY_MAGIC_V1
    };
    let mut writer = ScenarioBinaryWriter::new(magic);
    writer.write_binary_blob(&scenario.to_compact_binary());
    writer.write_binary_blob(&schedule.to_compact_binary());
    writer.finish()
}

fn reproduction_event_log_artifact_id(
    reproduction_artifact: ContentHash,
    fork_point: EventLogOffset,
    causal_subsequence: ContentHash,
    causal_subsequence_bytes: usize,
    causal_subsequence_events: usize,
    coverage_fingerprint: ContentHash,
    shared_store_segments: &[ContentHash],
) -> ContentHash {
    let mut lines = vec![
        format!(
            "reproduction_artifact={}",
            content_hash_hex(reproduction_artifact)
        ),
        format!("fork.prefix={}", content_hash_hex(fork_point.prefix)),
        format!(
            "fork.appended_segment={}",
            fork_point
                .appended_segment
                .map(content_hash_hex)
                .unwrap_or_else(|| String::from("none"))
        ),
        format!("fork.bytes={}", fork_point.bytes),
        format!("fork.events={}", fork_point.events),
        format!(
            "causal_subsequence={}",
            content_hash_hex(causal_subsequence)
        ),
        format!("causal_subsequence_bytes={causal_subsequence_bytes}"),
        format!("causal_subsequence_events={causal_subsequence_events}"),
        format!(
            "coverage_fingerprint={}",
            content_hash_hex(coverage_fingerprint)
        ),
        format!("shared_store_segments={}", shared_store_segments.len()),
    ];
    for segment in shared_store_segments {
        lines.push(format!(
            "shared_store_segment={}",
            content_hash_hex(*segment)
        ));
    }
    ContentHash::from_canonical_material(
        "crucible.reproduction.event-log-artifact.v1",
        &lines.join("\n"),
    )
}

fn sorted_unique_hashes(mut hashes: Vec<ContentHash>) -> Vec<ContentHash> {
    hashes.sort();
    hashes.dedup();
    hashes
}

fn checkpoint_store_bytes(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut lines = vec![
        String::from("crucible.dag-store.checkpoint-node.v1"),
        format!("id={}", content_hash_hex(checkpoint.id)),
        format!(
            "configuration={}",
            content_hash_hex(checkpoint.configuration)
        ),
        format!("scenario_ref={}", content_hash_hex(checkpoint.scenario_ref)),
        format!(
            "parent={}",
            checkpoint
                .parent
                .map(content_hash_hex)
                .unwrap_or_else(|| String::from("none"))
        ),
        format!(
            "schedule_delta={}",
            content_hash_hex(checkpoint.schedule_delta.content_hash())
        ),
        format!("kind={}", checkpoint_kind_label(checkpoint.kind)),
        format!("virtual_time_ticks={}", checkpoint.virtual_time.ticks),
        format!(
            "coverage_fingerprint={}",
            content_hash_hex(checkpoint.coverage_fingerprint)
        ),
        format!(
            "assertion_proximity_fingerprint={}",
            content_hash_hex(checkpoint.assertion_proximity_fingerprint)
        ),
    ];

    lines.push(format!("node_icounts={}", checkpoint.node_icounts.len()));
    for (node, icount) in &checkpoint.node_icounts {
        lines.push(format!("node_icount.node={}", node.name));
        lines.push(format!("node_icount.retired={}", icount.retired));
    }

    match &checkpoint.state {
        Some(state) => {
            lines.push(format!("state={}", content_hash_hex(state.id)));
            lines.push(format!("state_cow_refs={}", state.cow_delta_refs().len()));
            for cow_ref in state.cow_delta_refs() {
                push_cow_delta_ref_lines("state_cow_ref", cow_ref, &mut lines);
            }
        }
        None => lines.push(String::from("state=none")),
    }

    lines.push(format!("node_blobs={}", checkpoint.node_blobs.len()));
    for (node, blob) in &checkpoint.node_blobs {
        lines.push(format!("node_blob.node={}", node.name));
        push_node_blob_ref_lines("node_blob", blob, &mut lines);
    }

    lines.push(format!(
        "metadata_labels={}",
        checkpoint.metadata.labels.len()
    ));
    for (key, value) in &checkpoint.metadata.labels {
        lines.push(format!("metadata.key_len={}", key.len()));
        lines.push(format!("metadata.key={key}"));
        lines.push(format!("metadata.value_len={}", value.len()));
        lines.push(format!("metadata.value={value}"));
    }

    lines.join("\n").into_bytes()
}

fn schedule_delta_store_bytes(schedule: &Schedule) -> Vec<u8> {
    let mut lines = vec![
        String::from("crucible.dag-store.schedule-delta.v1"),
        format!("id={}", content_hash_hex(schedule.content_hash())),
        format!("decisions={}", schedule.decisions().len()),
    ];
    for (index, decision) in schedule.decisions().iter().enumerate() {
        push_decision_lines(index, decision, &mut lines);
    }
    lines.join("\n").into_bytes()
}

fn cow_delta_store_bytes(cow_ref: CowDeltaRef) -> Vec<u8> {
    let mut lines = vec![String::from("crucible.dag-store.cow-delta-ref.v1")];
    push_cow_delta_ref_lines("cow_delta", cow_ref, &mut lines);
    lines.join("\n").into_bytes()
}

fn push_cow_delta_ref_lines(prefix: &str, cow_ref: CowDeltaRef, lines: &mut Vec<String>) {
    lines.push(format!(
        "{prefix}.kind={}",
        cow_delta_kind_label(cow_ref.kind)
    ));
    lines.push(format!(
        "{prefix}.content={}",
        content_hash_hex(cow_ref.content)
    ));
}

fn push_node_blob_ref_lines(prefix: &str, blob: &NodeBlobRef, lines: &mut Vec<String>) {
    match blob {
        NodeBlobRef::Baked(blob) => {
            lines.push(format!("{prefix}.kind=baked"));
            lines.push(format!("{prefix}.blob={}", content_hash_hex(*blob)));
        }
        NodeBlobRef::CowDelta {
            parent,
            delta,
            resolved,
        } => {
            lines.push(format!("{prefix}.kind=cow-delta"));
            lines.push(format!("{prefix}.parent={}", content_hash_hex(*parent)));
            lines.push(format!("{prefix}.delta={}", content_hash_hex(*delta)));
            lines.push(format!("{prefix}.resolved={}", content_hash_hex(*resolved)));
        }
    }
}

fn push_decision_lines(index: usize, decision: &Decision, lines: &mut Vec<String>) {
    let prefix = format!("decision.{index}");
    match decision {
        Decision::DeliveryOrder(order) => {
            lines.push(format!("{prefix}.kind=delivery-order"));
            lines.push(format!("{prefix}.at_ticks={}", order.at.ticks));
            lines.push(format!("{prefix}.events={}", order.order.len()));
            for event in &order.order {
                lines.push(format!(
                    "{prefix}.event.virtual_time={}",
                    event.virtual_time.ticks
                ));
                lines.push(format!(
                    "{prefix}.event.consumer={}",
                    event.consumer.node.name
                ));
                lines.push(format!(
                    "{prefix}.event.consumer_kind={}",
                    scheduling_node_kind_label(event.consumer.kind)
                ));
                lines.push(format!(
                    "{prefix}.event.producer={}",
                    event.producer.node.name
                ));
                lines.push(format!(
                    "{prefix}.event.producer_kind={}",
                    scheduling_node_kind_label(event.producer.kind)
                ));
                lines.push(format!("{prefix}.event.sequence={}", event.sequence));
            }
        }
        Decision::FaultFires(fault) => {
            lines.push(format!("{prefix}.kind=fault-fires"));
            lines.push(format!("{prefix}.at_ticks={}", fault.at.ticks));
            lines.push(format!("{prefix}.fault_len={}", fault.fault.name.len()));
            lines.push(format!("{prefix}.fault={}", fault.fault.name));
            lines.push(format!("{prefix}.fired={}", fault.fired));
        }
        Decision::RngDraw(draw) => {
            lines.push(format!("{prefix}.kind=rng-draw"));
            push_rng_stream_lines(&prefix, &draw.stream, lines);
            lines.push(format!("{prefix}.value={}", draw.value));
        }
        Decision::Override(override_decision) => {
            lines.push(format!("{prefix}.kind=override"));
            lines.push(format!(
                "{prefix}.point_len={}",
                override_decision.point.key.len()
            ));
            lines.push(format!("{prefix}.point={}", override_decision.point.key));
            lines.push(format!(
                "{prefix}.choice_len={}",
                override_decision.choice.name.len()
            ));
            lines.push(format!("{prefix}.choice={}", override_decision.choice.name));
        }
        Decision::Preemption(preemption) => {
            lines.push(format!("{prefix}.kind=preemption"));
            lines.push(format!("{prefix}.node_len={}", preemption.node.name.len()));
            lines.push(format!("{prefix}.node={}", preemption.node.name));
            lines.push(format!("{prefix}.at_retired={}", preemption.at.retired));
            match &preemption.kind {
                PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                    lines.push(format!("{prefix}.preemption_kind=vcpu-switch"));
                    lines.push(format!("{prefix}.from_vcpu={}", from_vcpu.index));
                    lines.push(format!("{prefix}.to_vcpu={}", to_vcpu.index));
                }
                PreemptionKind::InterruptAt { target_vcpu, irq } => {
                    lines.push(format!("{prefix}.preemption_kind=interrupt-at"));
                    lines.push(format!("{prefix}.target_vcpu={}", target_vcpu.index));
                    lines.push(format!("{prefix}.irq={}", irq.vector));
                }
            }
        }
        Decision::AppRandom(random) => {
            lines.push(format!("{prefix}.kind=app-random"));
            lines.push(format!("{prefix}.node_len={}", random.node.name.len()));
            lines.push(format!("{prefix}.node={}", random.node.name));
            push_rng_stream_lines(&prefix, &random.stream, lines);
            lines.push(format!("{prefix}.request_id={}", random.request_id));
            lines.push(format!("{prefix}.width={}", random.width));
            lines.push(format!("{prefix}.value={}", random.value));
        }
        Decision::ControlFault(control) => {
            lines.push(format!("{prefix}.kind=control-fault"));
            lines.push(format!("{prefix}.at_ticks={}", control.at.ticks));
            lines.push(format!("{prefix}.sequence={}", control.sequence));
            match &control.action {
                ControlFaultAction::Inject { tag, fault } => {
                    lines.push(format!("{prefix}.action=inject-fault"));
                    lines.push(format!("{prefix}.tag_len={}", tag.name.len()));
                    lines.push(format!("{prefix}.tag={}", tag.name));
                    lines.push(fault.canonical_material());
                }
                ControlFaultAction::Heal { tag } => {
                    lines.push(format!("{prefix}.action=heal-fault"));
                    lines.push(format!("{prefix}.tag_len={}", tag.name.len()));
                    lines.push(format!("{prefix}.tag={}", tag.name));
                }
            }
        }
    }
}

fn cow_delta_kind_label(kind: CowDeltaKind) -> &'static str {
    match kind {
        CowDeltaKind::VmMemory => "vm-memory",
        CowDeltaKind::DeviceOverlay => "device-overlay",
        CowDeltaKind::ScheduleDelta => "schedule-delta",
        CowDeltaKind::EventLogSegment => "event-log-segment",
    }
}

fn checkpoint_closure_index_bytes(
    checkpoint: ContentHash,
    reproduction_artifact: ContentHash,
) -> Vec<u8> {
    format!(
        "crucible.local-dag-store.checkpoint-closure-index.v1\ncheckpoint={}\nreproduction_artifact={}\n",
        ContentAddressedBlobRef::from_hash(checkpoint).to_uri(),
        ContentAddressedBlobRef::from_hash(reproduction_artifact).to_uri()
    )
    .into_bytes()
}

fn parse_checkpoint_closure_index_sidecar(
    checkpoint: ContentHash,
    sidecar: &str,
) -> Result<ContentHash, DagStoreError> {
    let trimmed = sidecar.trim();
    if trimmed.is_empty() || trimmed.lines().count() != 1 {
        return Err(corrupt_checkpoint_index(
            checkpoint,
            "sidecar must contain exactly one index reference",
        ));
    }
    ContentAddressedBlobRef::parse("checkpoint closure index", trimmed)
        .map(ContentAddressedBlobRef::hash)
        .map_err(|error| corrupt_checkpoint_index(checkpoint, error.to_string()))
}

fn parse_checkpoint_closure_index_bytes(
    expected_checkpoint: ContentHash,
    bytes: &[u8],
) -> Result<LocalCheckpointClosureIndex, DagStoreError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        corrupt_checkpoint_index(
            expected_checkpoint,
            format!("index bytes are not UTF-8: {error}"),
        )
    })?;
    let mut lines = text.lines();
    match lines.next() {
        Some("crucible.local-dag-store.checkpoint-closure-index.v1") => {}
        Some(other) => {
            return Err(corrupt_checkpoint_index(
                expected_checkpoint,
                format!("unsupported schema `{other}`"),
            ));
        }
        None => {
            return Err(corrupt_checkpoint_index(
                expected_checkpoint,
                "index record is empty",
            ));
        }
    }
    let checkpoint = parse_checkpoint_index_field(expected_checkpoint, lines.next(), "checkpoint")?;
    if checkpoint != expected_checkpoint {
        return Err(corrupt_checkpoint_index(
            expected_checkpoint,
            format!(
                "record names checkpoint {}, expected {}",
                ContentAddressedBlobRef::from_hash(checkpoint).to_uri(),
                ContentAddressedBlobRef::from_hash(expected_checkpoint).to_uri()
            ),
        ));
    }
    let reproduction_artifact =
        parse_checkpoint_index_field(expected_checkpoint, lines.next(), "reproduction_artifact")?;
    if let Some(extra) = lines.next() {
        return Err(corrupt_checkpoint_index(
            expected_checkpoint,
            format!("unexpected extra line `{extra}`"),
        ));
    }
    Ok(LocalCheckpointClosureIndex {
        checkpoint,
        reproduction_artifact,
    })
}

fn parse_checkpoint_index_field(
    checkpoint: ContentHash,
    line: Option<&str>,
    field: &'static str,
) -> Result<ContentHash, DagStoreError> {
    let line = line
        .ok_or_else(|| corrupt_checkpoint_index(checkpoint, format!("missing `{field}` line")))?;
    let expected_prefix = format!("{field}=");
    let Some(value) = line.strip_prefix(&expected_prefix) else {
        return Err(corrupt_checkpoint_index(
            checkpoint,
            format!("expected `{field}` line, got `{line}`"),
        ));
    };
    ContentAddressedBlobRef::parse(field, value)
        .map(ContentAddressedBlobRef::hash)
        .map_err(|error| corrupt_checkpoint_index(checkpoint, error.to_string()))
}

fn corrupt_checkpoint_index(checkpoint: ContentHash, reason: impl Into<String>) -> DagStoreError {
    DagStoreError::CorruptIndex {
        checkpoint,
        reason: reason.into(),
    }
}

fn local_store_temp_path(path: &Path, key: &ContentHash) -> PathBuf {
    let index = LOCAL_DAG_STORE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = format!("{}.tmp.{}.{}", key.to_hex(), std::process::id(), index);
    path.with_file_name(file_name)
}

fn search_replay_oracle_sampling_score(
    seed_tag: &str,
    sequence: u64,
    checkpoint: ContentHash,
) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fold_fnv_bytes(hash, REPLAY_ORACLE_SEARCH_SAMPLING_DOMAIN);
    hash = fold_fnv_bytes(hash, seed_tag.as_bytes());
    hash = fold_fnv_bytes(hash, &sequence.to_le_bytes());
    fold_fnv_bytes(hash, checkpoint.to_hex().as_bytes())
}

fn fold_fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn content_hash_hex(hash: ContentHash) -> String {
    bytes_hex(&hash.bytes)
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[usize::from(*byte >> 4)] as char);
        encoded.push(HEX[usize::from(*byte & 0x0f)] as char);
    }
    encoded
}

//! Canonical binary writer and checkpoint/materialized-state codec.

use super::*;
pub(super) struct ScenarioBinaryWriter {
    pub(super) bytes: Vec<u8>,
}

impl ScenarioBinaryWriter {
    pub(super) fn new(magic: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(magic.len().saturating_add(256));
        bytes.extend_from_slice(magic);
        Self { bytes }
    }

    pub(super) fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn write_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn write_count(&mut self, count: usize) {
        self.write_u64(count as u64);
    }

    pub(super) fn write_string(&mut self, value: &str) {
        self.write_count(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(super) fn write_binary_blob(&mut self, value: &[u8]) {
        self.write_count(value.len());
        self.bytes.extend_from_slice(value);
    }

    pub(super) fn write_hash(&mut self, hash: ContentHash) {
        self.bytes.extend_from_slice(&hash.bytes);
    }

    pub(super) fn write_optional_blob_ref(&mut self, reference: Option<ContentAddressedBlobRef>) {
        match reference {
            Some(reference) => {
                self.write_u8(1);
                self.write_hash(reference.hash());
            }
            None => self.write_u8(0),
        }
    }

    pub(super) fn write_seed(&mut self, seed: Seed) {
        self.bytes.extend_from_slice(&seed.bytes());
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(super) struct ScenarioBinaryReader<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> ScenarioBinaryReader<'a> {
    pub(super) fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, EngineError> {
        if !bytes.starts_with(magic) {
            return Err(scenario_serialization_error("binary magic mismatch"));
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
        })
    }

    pub(super) fn finish(&self) -> Result<(), EngineError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(scenario_serialization_error("trailing binary bytes"))
        }
    }

    pub(super) fn read_exact(&mut self, len: usize) -> Result<&'a [u8], EngineError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| scenario_serialization_error("binary offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| scenario_serialization_error("truncated binary input"))?;
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn read_u8(&mut self) -> Result<u8, EngineError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, EngineError> {
        let bytes = self.read_exact(4)?;
        let mut fixed = [0; 4];
        fixed.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(fixed))
    }

    pub(super) fn read_u64(&mut self) -> Result<u64, EngineError> {
        let bytes = self.read_exact(8)?;
        let mut fixed = [0; 8];
        fixed.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(fixed))
    }

    pub(super) fn read_i64(&mut self) -> Result<i64, EngineError> {
        let bytes = self.read_exact(8)?;
        let mut fixed = [0; 8];
        fixed.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(fixed))
    }

    pub(super) fn read_count(&mut self) -> Result<usize, EngineError> {
        usize::try_from(self.read_u64()?)
            .map_err(|_| scenario_serialization_error("binary count does not fit usize"))
    }

    pub(super) fn read_collection_count(
        &mut self,
        label: &'static str,
    ) -> Result<usize, EngineError> {
        let count = self.read_count()?;
        if count > MAX_SCENARIO_BINARY_COLLECTION_ITEMS {
            Err(scenario_serialization_error(format!(
                "{label} count exceeds serialized collection limit"
            )))
        } else {
            Ok(count)
        }
    }

    pub(super) fn read_string(&mut self) -> Result<String, EngineError> {
        let len = self.read_count()?;
        if len > MAX_SCENARIO_BINARY_STRING_BYTES {
            return Err(scenario_serialization_error(
                "binary string exceeds serialized string limit",
            ));
        }
        let bytes = self.read_exact(len)?.to_vec();
        String::from_utf8(bytes)
            .map_err(|source| scenario_serialization_error(format!("invalid UTF-8: {source}")))
    }

    pub(super) fn read_binary_blob(
        &mut self,
        label: &'static str,
    ) -> Result<&'a [u8], EngineError> {
        self.read_binary_blob_bounded(label, MAX_SCENARIO_BINARY_BLOB_BYTES)
    }

    pub(super) fn read_binary_blob_bounded(
        &mut self,
        label: &'static str,
        maximum_bytes: usize,
    ) -> Result<&'a [u8], EngineError> {
        let len = self.read_count()?;
        if len > maximum_bytes {
            return Err(scenario_serialization_error(format!(
                "{label} exceeds serialized blob limit"
            )));
        }
        self.read_exact(len)
    }

    pub(super) fn read_hash(&mut self) -> Result<ContentHash, EngineError> {
        let bytes = self.read_exact(32)?;
        let mut fixed = [0; 32];
        fixed.copy_from_slice(bytes);
        Ok(ContentHash { bytes: fixed })
    }

    pub(super) fn read_optional_blob_ref(
        &mut self,
    ) -> Result<Option<ContentAddressedBlobRef>, EngineError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(ContentAddressedBlobRef::from_hash(self.read_hash()?))),
            _ => Err(scenario_serialization_error(
                "invalid optional blob-ref tag",
            )),
        }
    }

    pub(super) fn read_seed(&mut self) -> Result<Seed, EngineError> {
        let bytes = self.read_exact(32)?;
        let mut fixed = [0; 32];
        fixed.copy_from_slice(bytes);
        Ok(Seed::from_bytes(fixed))
    }
}

pub(super) fn scenario_binary_reader_for_versions<'a>(
    bytes: &'a [u8],
    v1_magic: &[u8],
    v2_magic: &[u8],
) -> Result<(ScenarioBinaryReader<'a>, bool), EngineError> {
    if bytes.starts_with(v2_magic) {
        return Ok((ScenarioBinaryReader::new(bytes, v2_magic)?, true));
    }
    if bytes.starts_with(v1_magic) {
        return Ok((ScenarioBinaryReader::new(bytes, v1_magic)?, false));
    }
    Err(scenario_serialization_error("binary magic mismatch"))
}

pub(super) fn write_scenario_form_binary(
    form: &ScenarioDefForm,
    writer: &mut ScenarioBinaryWriter,
) {
    let includes_devices = form.world.io_nodes().next().is_some();
    writer.write_u8(u8::from(includes_devices));
    writer.write_hash(form.id());
    write_world_binary(&form.world, writer, includes_devices);
    write_plan_binary(&form.plan, writer);
    write_properties_binary(&form.properties, writer);
    writer.write_seed(form.seed);
    writer.write_u64(form.app_random_draw_cap);
}

pub(super) fn read_scenario_form_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ScenarioDefForm, EngineError> {
    let includes_devices = match reader.read_u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(scenario_serialization_error(
                "invalid scenario world-kind tag",
            ));
        }
    };
    let expected = reader.read_hash()?;
    let world = read_world_binary(reader, includes_devices)?;
    let plan = read_plan_binary_for_scenario(&world, reader)?;
    let properties = read_properties_binary(&world, reader)?;
    let seed = reader.read_seed()?;
    let app_random_draw_cap = reader.read_u64()?;
    let form = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        seed,
        app_random_draw_cap,
    )?;
    validate_serialized_id("scenario", expected, form.id())?;
    Ok(form)
}

pub(super) fn write_schedule_binary(schedule: &Schedule, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(schedule.content_hash());
    writer.write_count(schedule.decisions().len());
    for decision in schedule.decisions() {
        write_decision_binary(decision, writer);
    }
}

pub(super) fn read_schedule_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Schedule, EngineError> {
    let expected = reader.read_hash()?;
    let count = reader.read_collection_count("schedule.decision")?;
    let mut decisions = Vec::with_capacity(count);
    for _ in 0..count {
        decisions.push(read_decision_binary(reader)?);
    }
    let schedule = Schedule { decisions };
    validate_serialized_id("schedule", expected, schedule.content_hash())?;
    Ok(schedule)
}

pub(super) fn write_checkpoint_binary(checkpoint: &Checkpoint, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(checkpoint.id);
    writer.write_hash(checkpoint.configuration);
    writer.write_hash(checkpoint.scenario_ref);
    write_optional_hash_binary(checkpoint.parent, writer);
    write_schedule_binary(&checkpoint.schedule_delta, writer);
    write_checkpoint_kind_binary(checkpoint.kind, writer);
    writer.write_u64(checkpoint.virtual_time.ticks);
    write_node_icounts_binary(&checkpoint.node_icounts, writer);
    write_optional_materialized_state_binary(checkpoint.state.as_ref(), writer);
    writer.write_hash(checkpoint.coverage_fingerprint);
    writer.write_hash(checkpoint.assertion_proximity_fingerprint);
    write_checkpoint_metadata_binary(&checkpoint.metadata, writer);
    write_node_blobs_binary(&checkpoint.node_blobs, writer);
}

pub(super) fn read_checkpoint_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Checkpoint, EngineError> {
    let id = reader.read_hash()?;
    let configuration = reader.read_hash()?;
    let scenario_ref = reader.read_hash()?;
    let parent = read_optional_hash_binary(reader)?;
    let schedule_delta = read_schedule_binary(reader)?;
    let kind = read_checkpoint_kind_binary(reader)?;
    let virtual_time = VirtualTime {
        ticks: reader.read_u64()?,
    };
    let node_icounts = read_node_icounts_binary(reader)?;
    let state = read_optional_materialized_state_binary(reader)?;
    let coverage_fingerprint = reader.read_hash()?;
    let assertion_proximity_fingerprint = reader.read_hash()?;
    let metadata = read_checkpoint_metadata_binary(reader)?;
    let node_blobs = read_node_blobs_binary(reader)?;
    Ok(Checkpoint {
        id,
        configuration,
        scenario_ref,
        parent,
        schedule_delta,
        virtual_time,
        node_icounts,
        state,
        coverage_fingerprint,
        assertion_proximity_fingerprint,
        metadata,
        node_blobs,
        kind,
    })
}

pub(super) fn validate_checkpoint_binary_shape(checkpoint: &Checkpoint) -> Result<(), EngineError> {
    match (checkpoint.kind, checkpoint.state.is_some()) {
        (CheckpointKind::Fat, false) => {
            return Err(scenario_serialization_error(
                "fat checkpoint is missing materialized state",
            ));
        }
        (CheckpointKind::Thin, true) => {
            return Err(scenario_serialization_error(
                "thin checkpoint carries materialized state",
            ));
        }
        (CheckpointKind::Fat, true) | (CheckpointKind::Thin, false) => {}
    }
    if checkpoint.id != checkpoint.configuration {
        return Err(scenario_serialization_error(
            "checkpoint id does not match configuration id",
        ));
    }
    Ok(())
}

pub(super) fn write_checkpoint_kind_binary(
    kind: CheckpointKind,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_u8(match kind {
        CheckpointKind::Fat => 0,
        CheckpointKind::Thin => 1,
    });
}

pub(super) fn read_checkpoint_kind_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<CheckpointKind, EngineError> {
    match reader.read_u8()? {
        0 => Ok(CheckpointKind::Fat),
        1 => Ok(CheckpointKind::Thin),
        _ => Err(scenario_serialization_error("invalid checkpoint-kind tag")),
    }
}

pub(super) fn write_optional_hash_binary(
    hash: Option<ContentHash>,
    writer: &mut ScenarioBinaryWriter,
) {
    match hash {
        Some(hash) => {
            writer.write_u8(1);
            writer.write_hash(hash);
        }
        None => writer.write_u8(0),
    }
}

pub(super) fn read_optional_hash_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Option<ContentHash>, EngineError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.read_hash()?)),
        _ => Err(scenario_serialization_error("invalid optional hash tag")),
    }
}

pub(super) fn write_node_icounts_binary(
    node_icounts: &BTreeMap<NodeId, Icount>,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(node_icounts.len());
    for (node, icount) in node_icounts {
        writer.write_string(&node.name);
        writer.write_u64(icount.retired);
    }
}

pub(super) fn read_node_icounts_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<BTreeMap<NodeId, Icount>, EngineError> {
    let count = reader.read_collection_count("checkpoint.node-icount")?;
    let mut node_icounts = BTreeMap::new();
    for _ in 0..count {
        node_icounts.insert(
            NodeId {
                name: reader.read_string()?,
            },
            Icount {
                retired: reader.read_u64()?,
            },
        );
    }
    Ok(node_icounts)
}

pub(super) fn write_optional_materialized_state_binary(
    state: Option<&MaterializedState>,
    writer: &mut ScenarioBinaryWriter,
) {
    match state {
        Some(state) => {
            writer.write_u8(1);
            write_materialized_state_binary(state, writer);
        }
        None => writer.write_u8(0),
    }
}

pub(super) fn read_optional_materialized_state_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Option<MaterializedState>, EngineError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => read_materialized_state_binary(reader).map(Some),
        _ => Err(scenario_serialization_error(
            "invalid optional materialized-state tag",
        )),
    }
}

pub(super) fn write_materialized_state_binary(
    state: &MaterializedState,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_hash(state.id);
    write_vm_snapshots_binary(&state.vm_snapshots, writer);
    write_device_overlays_binary(&state.device_overlays, writer);
    write_scheduler_state_binary(&state.scheduler, writer);
    write_decision_rng_state_binary(&state.decision_rng, writer);
    write_event_log_offset_binary(state.event_log, writer);
    writer.write_count(state.event_log_segments.len());
    for segment in &state.event_log_segments {
        writer.write_hash(*segment);
    }
}

pub(super) fn read_materialized_state_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<MaterializedState, EngineError> {
    let expected = reader.read_hash()?;
    let vm_snapshots = read_vm_snapshots_binary(reader)?;
    let device_overlays = read_device_overlays_binary(reader)?;
    let scheduler = read_scheduler_state_binary(reader)?;
    let decision_rng = read_decision_rng_state_binary(reader)?;
    let event_log = read_event_log_offset_binary(reader)?;
    let segment_count = reader.read_collection_count("materialized-state.event-log-segment")?;
    let mut event_log_segments = Vec::with_capacity(segment_count);
    for _ in 0..segment_count {
        event_log_segments.push(reader.read_hash()?);
    }
    let state = MaterializedState::from_components_with_event_log_segments(
        vm_snapshots,
        device_overlays,
        scheduler,
        decision_rng,
        event_log,
        event_log_segments,
    );
    validate_serialized_id("materialized-state", expected, state.id)?;
    Ok(state)
}

pub(super) fn write_vm_snapshots_binary(
    snapshots: &BTreeMap<NodeId, VmSnapshotRef>,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(snapshots.len());
    for (node, snapshot) in snapshots {
        writer.write_string(&node.name);
        write_node_blob_ref_binary(&snapshot.blob, writer);
        writer.write_u64(snapshot.icount.retired);
    }
}

pub(super) fn read_vm_snapshots_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<BTreeMap<NodeId, VmSnapshotRef>, EngineError> {
    let count = reader.read_collection_count("materialized-state.vm-snapshot")?;
    let mut snapshots = BTreeMap::new();
    for _ in 0..count {
        let node = NodeId {
            name: reader.read_string()?,
        };
        let blob = read_node_blob_ref_binary(reader)?;
        let icount = Icount {
            retired: reader.read_u64()?,
        };
        snapshots.insert(node, VmSnapshotRef { blob, icount });
    }
    Ok(snapshots)
}

pub(super) fn write_device_overlays_binary(
    overlays: &BTreeMap<DeviceId, DeviceOverlayDelta>,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(overlays.len());
    for (device, overlay) in overlays {
        writer.write_string(&device.name);
        writer.write_hash(overlay.parent);
        writer.write_hash(overlay.delta);
        writer.write_hash(overlay.resolved);
        write_device_rng_state_binary(&overlay.rng, writer);
    }
}

pub(super) fn read_device_overlays_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<BTreeMap<DeviceId, DeviceOverlayDelta>, EngineError> {
    let count = reader.read_collection_count("materialized-state.device-overlay")?;
    let mut overlays = BTreeMap::new();
    for _ in 0..count {
        let device = DeviceId {
            name: reader.read_string()?,
        };
        let parent = reader.read_hash()?;
        let delta = reader.read_hash()?;
        let resolved = reader.read_hash()?;
        let rng = read_device_rng_state_binary(reader)?;
        overlays.insert(
            device,
            DeviceOverlayDelta {
                parent,
                delta,
                resolved,
                rng,
            },
        );
    }
    Ok(overlays)
}

pub(super) fn write_node_blobs_binary(
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(node_blobs.len());
    for (node, blob) in node_blobs {
        writer.write_string(&node.name);
        write_node_blob_ref_binary(blob, writer);
    }
}

pub(super) fn read_node_blobs_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<BTreeMap<NodeId, NodeBlobRef>, EngineError> {
    let count = reader.read_collection_count("checkpoint.node-blob")?;
    let mut node_blobs = BTreeMap::new();
    for _ in 0..count {
        node_blobs.insert(
            NodeId {
                name: reader.read_string()?,
            },
            read_node_blob_ref_binary(reader)?,
        );
    }
    Ok(node_blobs)
}

pub(super) fn write_node_blob_ref_binary(blob: &NodeBlobRef, writer: &mut ScenarioBinaryWriter) {
    match blob {
        NodeBlobRef::Baked(hash) => {
            writer.write_u8(0);
            writer.write_hash(*hash);
        }
        NodeBlobRef::CowDelta {
            parent,
            delta,
            resolved,
        } => {
            writer.write_u8(1);
            writer.write_hash(*parent);
            writer.write_hash(*delta);
            writer.write_hash(*resolved);
        }
    }
}

pub(super) fn read_node_blob_ref_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<NodeBlobRef, EngineError> {
    match reader.read_u8()? {
        0 => Ok(NodeBlobRef::Baked(reader.read_hash()?)),
        1 => Ok(NodeBlobRef::CowDelta {
            parent: reader.read_hash()?,
            delta: reader.read_hash()?,
            resolved: reader.read_hash()?,
        }),
        _ => Err(scenario_serialization_error("invalid node-blob-ref tag")),
    }
}

pub(super) fn write_device_rng_state_binary(
    state: &DeviceRngState,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(state.streams.len());
    for (stream, position) in &state.streams {
        write_rng_stream_binary(stream, writer);
        writer.write_u64(position.draws);
    }
}

pub(super) fn read_device_rng_state_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<DeviceRngState, EngineError> {
    let count = reader.read_collection_count("device-rng-state.stream")?;
    let mut streams = BTreeMap::new();
    for _ in 0..count {
        streams.insert(
            read_rng_stream_binary(reader)?,
            RngStreamPosition {
                draws: reader.read_u64()?,
            },
        );
    }
    Ok(DeviceRngState { streams })
}

pub(super) fn write_decision_rng_state_binary(
    state: &DecisionRngState,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(state.positions.len());
    for (stream, position) in &state.positions {
        write_rng_stream_binary(stream, writer);
        writer.write_u64(position.draws);
    }
}

pub(super) fn read_decision_rng_state_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<DecisionRngState, EngineError> {
    let count = reader.read_collection_count("decision-rng-state.stream")?;
    let mut positions = BTreeMap::new();
    for _ in 0..count {
        positions.insert(
            read_rng_stream_binary(reader)?,
            RngStreamPosition {
                draws: reader.read_u64()?,
            },
        );
    }
    Ok(DecisionRngState { positions })
}

pub(super) fn write_event_log_offset_binary(
    offset: EventLogOffset,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_hash(offset.prefix);
    write_optional_hash_binary(offset.appended_segment, writer);
    writer.write_u64(offset.bytes);
    writer.write_u64(offset.events);
}

pub(super) fn read_event_log_offset_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<EventLogOffset, EngineError> {
    Ok(EventLogOffset {
        prefix: reader.read_hash()?,
        appended_segment: read_optional_hash_binary(reader)?,
        bytes: reader.read_u64()?,
        events: reader.read_u64()?,
    })
}

pub(super) fn write_scheduler_state_binary(
    state: &SchedulerState,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(state.horizons.len());
    for (node, horizon) in &state.horizons {
        writer.write_string(&node.name);
        writer.write_u64(horizon.ticks);
    }
    writer.write_count(state.pending_frames.len());
    for (node, frames) in &state.pending_frames {
        writer.write_string(&node.name);
        writer.write_count(frames.len());
        for frame in frames {
            writer.write_string(&frame.source.name);
            writer.write_u64(frame.sequence);
            writer.write_u64(frame.delivery_icount.retired);
            writer.write_hash(frame.payload);
        }
    }
    writer.write_count(state.network_link_cursors.len());
    for (link, cursor) in &state.network_link_cursors {
        writer.write_string(&link.name);
        writer.write_u64(cursor.current_icount);
        writer.write_u32(cursor.next_sequence);
        writer.write_u64(cursor.rng_position);
        writer.write_count(cursor.inflight.len());
        for pending in &cursor.inflight {
            writer.write_u32(pending.sequence);
            writer.write_u64(pending.delivery_icount.retired);
            writer.write_u32(pending.frame_id);
            writer.write_hash(pending.payload);
        }
    }
    writer.write_count(state.event_sequences.next.len());
    for (key, next) in &state.event_sequences.next {
        write_scheduler_node_id_binary(&key.producer, writer);
        write_scheduler_node_id_binary(&key.consumer, writer);
        writer.write_u64(*next);
    }
    writer.write_u64(state.topology_epoch);
    writer.write_count(state.effective_topology_edges.len());
    for edge in &state.effective_topology_edges {
        write_scheduler_lookahead_edge_binary(edge, writer);
    }
    writer.write_count(state.pending_topology_changes.len());
    for change in &state.pending_topology_changes {
        write_scheduler_topology_change_binary(change, writer);
    }
    writer.write_count(state.timers.timers.len());
    for (id, timer) in &state.timers.timers {
        writer.write_string(&id.name);
        writer.write_string(&timer.owner.name);
        writer.write_u64(timer.armed_at.ticks);
        writer.write_u64(timer.fire_at.ticks);
        writer.write_u64(timer.fire_icount.retired);
    }
    writer.write_count(state.active_faults.len());
    for (fault, state) in &state.active_faults {
        writer.write_string(&fault.name);
        writer.write_u64(state.active_since.ticks);
        write_optional_virtual_time_binary(state.heal_at, writer);
    }
    writer.write_count(state.active_fault_tags.len());
    for (tag, fault) in &state.active_fault_tags {
        writer.write_string(&tag.name);
        write_membership_fault_binary(fault, writer);
    }
    writer.write_count(state.pending_device_decisions.len());
    for decision in &state.pending_device_decisions {
        write_decision_binary(decision, writer);
    }
    write_search_frontier_choices_binary(&state.search_frontier, writer);
}

pub(super) fn read_scheduler_state_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<SchedulerState, EngineError> {
    let horizon_count = reader.read_collection_count("scheduler-state.horizon")?;
    let mut horizons = BTreeMap::new();
    for _ in 0..horizon_count {
        horizons.insert(
            NodeId {
                name: reader.read_string()?,
            },
            VirtualTime {
                ticks: reader.read_u64()?,
            },
        );
    }

    let pending_count = reader.read_collection_count("scheduler-state.pending-frame-node")?;
    let mut pending_frames = BTreeMap::new();
    for _ in 0..pending_count {
        let node = NodeId {
            name: reader.read_string()?,
        };
        let frame_count = reader.read_collection_count("scheduler-state.pending-frame")?;
        let mut frames = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            frames.push(PendingFrame {
                source: NodeId {
                    name: reader.read_string()?,
                },
                sequence: reader.read_u64()?,
                delivery_icount: Icount {
                    retired: reader.read_u64()?,
                },
                payload: reader.read_hash()?,
            });
        }
        pending_frames.insert(node, frames);
    }

    let network_cursor_count =
        reader.read_collection_count("scheduler-state.network-link-cursor")?;
    let mut network_link_cursors = BTreeMap::new();
    for _ in 0..network_cursor_count {
        network_link_cursors.insert(
            DeviceId {
                name: reader.read_string()?,
            },
            NetworkLinkRuntimeCursor {
                current_icount: reader.read_u64()?,
                next_sequence: reader.read_u32()?,
                rng_position: reader.read_u64()?,
                inflight: {
                    let count =
                        reader.read_collection_count("scheduler-state.network-link-inflight")?;
                    let mut inflight = Vec::with_capacity(count);
                    for _ in 0..count {
                        inflight.push(NetworkLinkPendingFrame {
                            sequence: reader.read_u32()?,
                            delivery_icount: Icount {
                                retired: reader.read_u64()?,
                            },
                            frame_id: reader.read_u32()?,
                            payload: reader.read_hash()?,
                        });
                    }
                    inflight
                },
            },
        );
    }

    let sequence_count = reader.read_collection_count("scheduler-state.event-sequence")?;
    let mut event_sequences = EventSequenceState::empty();
    for _ in 0..sequence_count {
        event_sequences.next.insert(
            EventSequenceKey {
                producer: read_scheduler_node_id_binary(reader)?,
                consumer: read_scheduler_node_id_binary(reader)?,
            },
            reader.read_u64()?,
        );
    }
    let topology_epoch = reader.read_u64()?;
    let effective_topology_edge_count =
        reader.read_collection_count("scheduler-state.effective-topology-edge")?;
    let mut effective_topology_edges = Vec::with_capacity(effective_topology_edge_count);
    for _ in 0..effective_topology_edge_count {
        effective_topology_edges.push(read_scheduler_lookahead_edge_binary(reader)?);
    }
    let pending_topology_change_count =
        reader.read_collection_count("scheduler-state.pending-topology-change")?;
    let mut pending_topology_changes = Vec::with_capacity(pending_topology_change_count);
    for _ in 0..pending_topology_change_count {
        pending_topology_changes.push(read_scheduler_topology_change_binary(reader)?);
    }

    let timer_count = reader.read_collection_count("scheduler-state.timer")?;
    let mut timers = TimerRegistry::empty();
    for _ in 0..timer_count {
        timers.timers.insert(
            TimerId {
                name: reader.read_string()?,
            },
            TimerState {
                owner: NodeId {
                    name: reader.read_string()?,
                },
                armed_at: VirtualTime {
                    ticks: reader.read_u64()?,
                },
                fire_at: VirtualTime {
                    ticks: reader.read_u64()?,
                },
                fire_icount: Icount {
                    retired: reader.read_u64()?,
                },
            },
        );
    }

    let active_fault_count = reader.read_collection_count("scheduler-state.active-fault")?;
    let mut active_faults = BTreeMap::new();
    for _ in 0..active_fault_count {
        active_faults.insert(
            FaultId {
                name: reader.read_string()?,
            },
            FaultState {
                active_since: VirtualTime {
                    ticks: reader.read_u64()?,
                },
                heal_at: read_optional_virtual_time_binary(reader)?,
            },
        );
    }

    let active_fault_tag_count =
        reader.read_collection_count("scheduler-state.active-fault-tag")?;
    let mut active_fault_tags = BTreeMap::new();
    for _ in 0..active_fault_tag_count {
        active_fault_tags.insert(
            FaultTag {
                name: reader.read_string()?,
            },
            read_membership_fault_binary(reader)?,
        );
    }
    let active_fault_table = ActiveFaultTable::from_active_faults(&active_fault_tags);
    let pending_device_decision_count =
        reader.read_collection_count("scheduler-state.pending-device-decision")?;
    let mut pending_device_decisions = Vec::with_capacity(pending_device_decision_count);
    for _ in 0..pending_device_decision_count {
        pending_device_decisions.push(read_decision_binary(reader)?);
    }
    let search_frontier = read_search_frontier_choices_binary(reader)?;

    Ok(SchedulerState {
        horizons,
        pending_frames,
        network_link_cursors,
        event_sequences,
        topology_epoch,
        effective_topology_edges,
        pending_topology_changes,
        timers,
        active_faults,
        active_fault_tags,
        active_fault_table,
        pending_device_decisions,
        search_frontier,
    })
}

pub(super) fn write_scheduler_lookahead_edge_binary(
    edge: &crate::scheduler::SchedulerLookaheadEdge,
    writer: &mut ScenarioBinaryWriter,
) {
    write_scheduler_node_id_binary(&edge.from, writer);
    write_scheduler_node_id_binary(&edge.to, writer);
    writer.write_u64(edge.minimum_latency.nanos);
}

pub(super) fn read_scheduler_lookahead_edge_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<crate::scheduler::SchedulerLookaheadEdge, EngineError> {
    Ok(crate::scheduler::SchedulerLookaheadEdge::new(
        read_scheduler_node_id_binary(reader)?,
        read_scheduler_node_id_binary(reader)?,
        SimDuration {
            nanos: reader.read_u64()?,
        },
    ))
}

pub(super) fn write_scheduler_topology_change_binary(
    change: &crate::scheduler::SchedulerTopologyChange,
    writer: &mut ScenarioBinaryWriter,
) {
    use crate::scheduler::{SchedulerTopologyChangeEffect, SchedulerTopologyChangeTrigger};

    writer.write_u64(change.sequence);
    writer.write_u8(match change.trigger {
        SchedulerTopologyChangeTrigger::FaultActivation => 0,
        SchedulerTopologyChangeTrigger::Heal => 1,
        SchedulerTopologyChangeTrigger::LatencyChange => 2,
    });
    match change.activation_time {
        Some(at) => {
            writer.write_u8(1);
            writer.write_u64(at.nanos);
        }
        None => writer.write_u8(0),
    }
    match &change.effect {
        SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(edges) => {
            writer.write_u8(0);
            writer.write_count(edges.len());
            for edge in edges {
                write_scheduler_lookahead_edge_binary(edge, writer);
            }
        }
        SchedulerTopologyChangeEffect::UpdateEffectiveEdges(edges) => {
            writer.write_u8(1);
            writer.write_count(edges.len());
            for edge in edges {
                write_scheduler_lookahead_edge_binary(edge, writer);
            }
        }
        SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
            writer.write_u8(2);
            writer.write_count(endpoints.len());
            for endpoint in endpoints {
                write_scheduler_node_id_binary(&endpoint.from, writer);
                write_scheduler_node_id_binary(&endpoint.to, writer);
            }
        }
        SchedulerTopologyChangeEffect::RestoreEffectiveEdges(edges) => {
            writer.write_u8(3);
            writer.write_count(edges.len());
            for edge in edges {
                write_scheduler_lookahead_edge_binary(edge, writer);
            }
        }
    }
}

pub(super) fn read_scheduler_topology_change_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<crate::scheduler::SchedulerTopologyChange, EngineError> {
    use crate::scheduler::{
        SchedulerLookaheadEdgeEndpoint, SchedulerTopologyChange, SchedulerTopologyChangeEffect,
        SchedulerTopologyChangeTrigger,
    };

    let sequence = reader.read_u64()?;
    let trigger = match reader.read_u8()? {
        0 => SchedulerTopologyChangeTrigger::FaultActivation,
        1 => SchedulerTopologyChangeTrigger::Heal,
        2 => SchedulerTopologyChangeTrigger::LatencyChange,
        _ => {
            return Err(scenario_serialization_error(
                "invalid topology-change trigger tag",
            ));
        }
    };
    let activation_time = match reader.read_u8()? {
        0 => None,
        1 => Some(SimInstant {
            nanos: reader.read_u64()?,
        }),
        _ => {
            return Err(scenario_serialization_error(
                "invalid topology-change time tag",
            ));
        }
    };
    let effect_tag = reader.read_u8()?;
    let count = reader.read_collection_count("scheduler-state.topology-change-effect")?;
    let effect = match effect_tag {
        0 | 1 | 3 => {
            let mut edges = Vec::with_capacity(count);
            for _ in 0..count {
                edges.push(read_scheduler_lookahead_edge_binary(reader)?);
            }
            match effect_tag {
                0 => SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(edges),
                1 => SchedulerTopologyChangeEffect::UpdateEffectiveEdges(edges),
                3 => SchedulerTopologyChangeEffect::RestoreEffectiveEdges(edges),
                _ => {
                    return Err(scenario_serialization_error(
                        "invalid topology-change effect tag",
                    ));
                }
            }
        }
        2 => {
            let mut endpoints = Vec::with_capacity(count);
            for _ in 0..count {
                endpoints.push(SchedulerLookaheadEdgeEndpoint::new(
                    read_scheduler_node_id_binary(reader)?,
                    read_scheduler_node_id_binary(reader)?,
                ));
            }
            SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints)
        }
        _ => {
            return Err(scenario_serialization_error(
                "invalid topology-change effect tag",
            ));
        }
    };
    Ok(SchedulerTopologyChange {
        sequence,
        trigger,
        activation_time,
        effect,
    })
}

pub(super) fn write_optional_virtual_time_binary(
    value: Option<VirtualTime>,
    writer: &mut ScenarioBinaryWriter,
) {
    match value {
        Some(value) => {
            writer.write_u8(1);
            writer.write_u64(value.ticks);
        }
        None => writer.write_u8(0),
    }
}

pub(super) fn read_optional_virtual_time_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Option<VirtualTime>, EngineError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(VirtualTime {
            ticks: reader.read_u64()?,
        })),
        _ => Err(scenario_serialization_error(
            "invalid optional virtual-time tag",
        )),
    }
}

pub(super) fn write_search_frontier_choices_binary(
    frontier: &SearchFrontierChoices,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(frontier.choices.len());
    for choice in &frontier.choices {
        write_decision_binary(&choice.decision, writer);
        writer.write_count(choice.decisions.len());
        for decision in &choice.decisions {
            write_decision_binary(decision, writer);
        }
    }
}

pub(super) fn read_search_frontier_choices_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<SearchFrontierChoices, EngineError> {
    let count = reader.read_collection_count("scheduler-state.search-frontier-choice")?;
    let mut choices = Vec::with_capacity(count);
    for _ in 0..count {
        let decision = read_decision_binary(reader)?;
        let decision_count =
            reader.read_collection_count("scheduler-state.search-frontier-choice.decision")?;
        let mut decisions = Vec::with_capacity(decision_count);
        for _ in 0..decision_count {
            decisions.push(read_decision_binary(reader)?);
        }
        choices.push(SearchFrontierChoice {
            decision,
            decisions,
        });
    }
    let decisions = choices
        .iter()
        .map(|choice| choice.decision.clone())
        .collect();
    Ok(SearchFrontierChoices { choices, decisions })
}

pub(super) fn write_checkpoint_metadata_binary(
    metadata: &CheckpointMeta,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_count(metadata.labels.len());
    for (key, value) in &metadata.labels {
        writer.write_string(key);
        writer.write_string(value);
    }
}

pub(super) fn read_checkpoint_metadata_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<CheckpointMeta, EngineError> {
    let count = reader.read_collection_count("checkpoint.metadata-label")?;
    let mut labels = BTreeMap::new();
    for _ in 0..count {
        labels.insert(reader.read_string()?, reader.read_string()?);
    }
    Ok(CheckpointMeta { labels })
}

pub(super) fn write_decision_binary(decision: &Decision, writer: &mut ScenarioBinaryWriter) {
    match decision {
        Decision::DeliveryOrder(order) => {
            writer.write_u8(0);
            writer.write_u64(order.at.ticks);
            writer.write_count(order.order.len());
            for event in &order.order {
                writer.write_u64(event.virtual_time.ticks);
                write_scheduler_node_id_binary(&event.consumer, writer);
                write_scheduler_node_id_binary(&event.producer, writer);
                writer.write_u64(event.sequence);
            }
        }
        Decision::FaultFires(fault) => {
            writer.write_u8(1);
            writer.write_u64(fault.at.ticks);
            writer.write_string(&fault.fault.name);
            write_binary_bool(writer, fault.fired);
        }
        Decision::RngDraw(draw) => {
            writer.write_u8(2);
            write_rng_stream_binary(&draw.stream, writer);
            writer.write_u64(draw.value);
        }
        Decision::Override(override_decision) => {
            writer.write_u8(3);
            writer.write_string(&override_decision.point.key);
            writer.write_string(&override_decision.choice.name);
        }
        Decision::Preemption(preemption) => {
            writer.write_u8(4);
            writer.write_string(&preemption.node.name);
            writer.write_u64(preemption.at.retired);
            write_preemption_kind_binary(&preemption.kind, writer);
        }
        Decision::AppRandom(random) => {
            writer.write_u8(5);
            writer.write_string(&random.node.name);
            write_rng_stream_binary(&random.stream, writer);
            writer.write_u64(random.request_id);
            writer.write_u8(random.width);
            writer.write_u64(random.value);
        }
        Decision::ControlFault(control) => {
            writer.write_u8(6);
            writer.write_u64(control.at.ticks);
            writer.write_u64(control.sequence);
            write_control_fault_action_binary(&control.action, writer);
        }
    }
}

pub(super) fn read_decision_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Decision, EngineError> {
    match reader.read_u8()? {
        0 => {
            let at = VirtualTime {
                ticks: reader.read_u64()?,
            };
            let count = reader.read_collection_count("decision.delivery-order.event")?;
            let mut order = Vec::with_capacity(count);
            for _ in 0..count {
                order.push(EventKey {
                    virtual_time: VirtualTime {
                        ticks: reader.read_u64()?,
                    },
                    consumer: read_scheduler_node_id_binary(reader)?,
                    producer: read_scheduler_node_id_binary(reader)?,
                    sequence: reader.read_u64()?,
                });
            }
            Ok(Decision::DeliveryOrder(DeliveryOrderDecision { at, order }))
        }
        1 => Ok(Decision::FaultFires(FaultDecision {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            fault: FaultId {
                name: reader.read_string()?,
            },
            fired: read_binary_bool(reader, "fault decision fired")?,
        })),
        2 => Ok(Decision::RngDraw(RngDecision {
            stream: read_rng_stream_binary(reader)?,
            value: reader.read_u64()?,
        })),
        3 => Ok(Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: reader.read_string()?,
            },
            choice: ChoiceTag {
                name: reader.read_string()?,
            },
        })),
        4 => Ok(Decision::Preemption(PreemptionDecision {
            node: NodeId {
                name: reader.read_string()?,
            },
            at: Icount {
                retired: reader.read_u64()?,
            },
            kind: read_preemption_kind_binary(reader)?,
        })),
        5 => Ok(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: reader.read_string()?,
            },
            stream: read_rng_stream_binary(reader)?,
            request_id: reader.read_u64()?,
            width: reader.read_u8()?,
            value: reader.read_u64()?,
        })),
        6 => Ok(Decision::ControlFault(ControlFaultDecision {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            sequence: reader.read_u64()?,
            action: read_control_fault_action_binary(reader)?,
        })),
        _ => Err(scenario_serialization_error("invalid decision tag")),
    }
}

pub(super) fn write_control_fault_action_binary(
    action: &ControlFaultAction,
    writer: &mut ScenarioBinaryWriter,
) {
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            writer.write_u8(0);
            writer.write_string(&tag.name);
            write_fault_binary(fault, writer);
        }
        ControlFaultAction::Heal { tag } => {
            writer.write_u8(1);
            writer.write_string(&tag.name);
        }
    }
}

pub(super) fn read_control_fault_action_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ControlFaultAction, EngineError> {
    match reader.read_u8()? {
        0 => Ok(ControlFaultAction::Inject {
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_fault_binary(reader)?,
        }),
        1 => Ok(ControlFaultAction::Heal {
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        _ => Err(scenario_serialization_error(
            "invalid control-fault action tag",
        )),
    }
}

pub(super) fn write_rng_stream_binary(stream: &RngStreamId, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&stream.domain);
    writer.write_string(&stream.name);
}

pub(super) fn read_rng_stream_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<RngStreamId, EngineError> {
    Ok(RngStreamId::new(
        reader.read_string()?,
        reader.read_string()?,
    ))
}

pub(super) fn write_scheduler_node_id_binary(
    node: &SchedulerNodeId,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_string(&node.node.name);
    write_scheduling_node_kind_binary(node.kind, writer);
}

pub(super) fn read_scheduler_node_id_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<SchedulerNodeId, EngineError> {
    Ok(SchedulerNodeId {
        node: NodeId {
            name: reader.read_string()?,
        },
        kind: read_scheduling_node_kind_binary(reader)?,
    })
}

pub(super) fn write_scheduling_node_kind_binary(
    kind: SchedulingNodeKind,
    writer: &mut ScenarioBinaryWriter,
) {
    let tag = match kind {
        SchedulingNodeKind::Vm => 0,
        SchedulingNodeKind::Disk => 1,
        SchedulingNodeKind::NineP => 2,
        SchedulingNodeKind::Network => 3,
        SchedulingNodeKind::ControlPlane => 4,
    };
    writer.write_u8(tag);
}

pub(super) fn read_scheduling_node_kind_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<SchedulingNodeKind, EngineError> {
    match reader.read_u8()? {
        0 => Ok(SchedulingNodeKind::Vm),
        1 => Ok(SchedulingNodeKind::Disk),
        2 => Ok(SchedulingNodeKind::NineP),
        3 => Ok(SchedulingNodeKind::Network),
        4 => Ok(SchedulingNodeKind::ControlPlane),
        _ => Err(scenario_serialization_error(
            "invalid scheduling-node-kind tag",
        )),
    }
}

pub(super) fn write_preemption_kind_binary(
    kind: &PreemptionKind,
    writer: &mut ScenarioBinaryWriter,
) {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
            writer.write_u8(0);
            writer.write_u32(from_vcpu.index);
            writer.write_u32(to_vcpu.index);
        }
        PreemptionKind::InterruptAt { target_vcpu, irq } => {
            writer.write_u8(1);
            writer.write_u32(target_vcpu.index);
            writer.write_u32(irq.vector);
        }
    }
}

pub(super) fn read_preemption_kind_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<PreemptionKind, EngineError> {
    match reader.read_u8()? {
        0 => Ok(PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId {
                index: reader.read_u32()?,
            },
            to_vcpu: VcpuId {
                index: reader.read_u32()?,
            },
        }),
        1 => Ok(PreemptionKind::InterruptAt {
            target_vcpu: VcpuId {
                index: reader.read_u32()?,
            },
            irq: IrqVector {
                vector: reader.read_u32()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid preemption-kind tag")),
    }
}

pub(super) fn write_binary_bool(writer: &mut ScenarioBinaryWriter, value: bool) {
    writer.write_u8(u8::from(value));
}

pub(super) fn read_binary_bool(
    reader: &mut ScenarioBinaryReader<'_>,
    label: &'static str,
) -> Result<bool, EngineError> {
    match reader.read_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(scenario_serialization_error(format!(
            "invalid binary bool for {label}"
        ))),
    }
}

pub(super) fn write_world_binary(
    world: &World,
    writer: &mut ScenarioBinaryWriter,
    includes_io_nodes: bool,
) {
    writer.write_hash(world.id());
    if includes_io_nodes {
        writer.write_count(world.topology_nodes().len());
        for node in world.topology_nodes() {
            match node {
                WorldNodeDef::Vm(node) => {
                    writer.write_u8(0);
                    write_world_node_binary(node, writer);
                }
                WorldNodeDef::Io(node) => write_world_io_node_binary(node, writer),
            }
        }
    } else {
        writer.write_count(world.vm_nodes().len());
        for node in world.vm_nodes() {
            write_world_node_binary(node, writer);
        }
    }
    writer.write_count(world.links().len());
    for link in world.links() {
        write_link_binary(link, writer);
    }
}

pub(super) fn read_world_binary(
    reader: &mut ScenarioBinaryReader<'_>,
    includes_io_nodes: bool,
) -> Result<World, EngineError> {
    let id = reader.read_hash()?;
    let node_count = reader.read_collection_count("world.node")?;
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(if includes_io_nodes {
            match reader.read_u8()? {
                0 => WorldNodeDef::Vm(read_world_node_binary(reader)?),
                1 => WorldNodeDef::Io(read_world_block_node_binary(reader)?),
                2 => WorldNodeDef::Io(read_world_ninep_node_binary(reader)?),
                _ => return Err(scenario_serialization_error("invalid world node kind tag")),
            }
        } else {
            WorldNodeDef::Vm(read_world_node_binary(reader)?)
        });
    }
    let link_count = reader.read_collection_count("world.link")?;
    let mut links = Vec::with_capacity(link_count);
    for _ in 0..link_count {
        links.push(read_link_binary(reader)?);
    }
    if includes_io_nodes && nodes.iter().all(|node| matches!(node, WorldNodeDef::Vm(_))) {
        return Err(scenario_serialization_error(
            "world v2 encoding contains no I/O node",
        ));
    }
    let world = World::from_recorded_node_defs_and_links(id, nodes, links)?;
    validate_world_serialized_identity(&world)?;
    Ok(world)
}

pub(super) fn write_world_io_node_binary(node: &WorldIoNode, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match &node.kind {
        WorldIoNodeKind::Block { .. } => 1,
        WorldIoNodeKind::NineP { .. } => 2,
    });
    writer.write_string(&node.id.name);
    writer.write_string(&node.owner.name);
    writer.write_u8(node.core.shift_bits);
    match &node.kind {
        WorldIoNodeKind::Block {
            base_image,
            base_length,
            latency,
        } => {
            writer.write_hash(base_image.hash());
            writer.write_u64(*base_length);
            writer.write_u64(latency.read_base_ns);
            writer.write_u64(latency.write_base_ns);
            writer.write_u64(latency.flush_ns);
            writer.write_u64(latency.get_length_ns);
            writer.write_u64(latency.per_byte_ns);
        }
        WorldIoNodeKind::NineP { tree, latency } => {
            writer.write_hash(tree.hash());
            writer.write_u64(latency.control_ns);
            writer.write_u64(latency.data_ns);
            writer.write_u64(latency.per_byte_ns);
        }
    }
}

pub(super) fn read_world_io_node_header(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<(NodeId, NodeId, WorldIoCoreConfig), EngineError> {
    let id = NodeId {
        name: reader.read_string()?,
    };
    let owner = NodeId {
        name: reader.read_string()?,
    };
    let core = WorldIoCoreConfig::new(reader.read_u8()?);
    Ok((id, owner, core))
}

pub(super) fn read_world_block_node_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<WorldIoNode, EngineError> {
    let (id, owner, core) = read_world_io_node_header(reader)?;
    Ok(WorldIoNode::block(
        id,
        owner,
        core,
        ContentAddressedBlobRef::from_hash(reader.read_hash()?),
        reader.read_u64()?,
        WorldBlockLatency::new(
            reader.read_u64()?,
            reader.read_u64()?,
            reader.read_u64()?,
            reader.read_u64()?,
            reader.read_u64()?,
        ),
    ))
}

pub(super) fn read_world_ninep_node_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<WorldIoNode, EngineError> {
    let (id, owner, core) = read_world_io_node_header(reader)?;
    Ok(WorldIoNode::ninep(
        id,
        owner,
        core,
        ContentAddressedBlobRef::from_hash(reader.read_hash()?),
        WorldNinePLatency::new(reader.read_u64()?, reader.read_u64()?, reader.read_u64()?),
    ))
}

pub(super) fn write_world_node_binary(node: &WorldNode, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&node.id.name);
    write_vm_arch_binary(node.arch, writer);
    writer.write_u32(node.memory_mib);
    writer.write_string(&node.cmdline);
    writer.write_u32(u32::from(node.smp_vcpus));
    writer.write_u8(node.icount_shift);
    writer.write_optional_blob_ref(node.kernel);
    writer.write_optional_blob_ref(node.root_image);
    writer.write_optional_blob_ref(node.initrd);
    write_ready_point_binary(&node.ready_point, writer);
    writer.write_u8(match node.white_box {
        WhiteBoxPolicy::Disabled => 0,
        WhiteBoxPolicy::Enabled => 1,
    });
}

pub(super) fn read_world_node_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<WorldNode, EngineError> {
    let id = NodeId {
        name: reader.read_string()?,
    };
    let arch = read_vm_arch_binary(reader)?;
    let memory_mib = reader.read_u32()?;
    let cmdline = reader.read_string()?;
    let smp_vcpus = u16::try_from(reader.read_u32()?)
        .map_err(|_error| scenario_serialization_error("world node vCPU count overflows u16"))?;
    let icount_shift = reader.read_u8()?;
    let kernel = reader.read_optional_blob_ref()?;
    let root_image = reader.read_optional_blob_ref()?;
    let initrd = reader.read_optional_blob_ref()?;
    let ready_point = read_ready_point_binary(reader)?;
    let white_box = match reader.read_u8()? {
        0 => WhiteBoxPolicy::Disabled,
        1 => WhiteBoxPolicy::Enabled,
        _ => return Err(scenario_serialization_error("invalid white-box policy tag")),
    };
    Ok(WorldNode {
        id,
        arch,
        memory_mib,
        cmdline,
        ready_point,
        white_box,
        smp_vcpus,
        icount_shift,
        kernel,
        root_image,
        initrd,
    })
}

pub(super) fn write_vm_arch_binary(arch: VmArchitecture, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match arch {
        VmArchitecture::X86_64 => 0,
        VmArchitecture::Aarch64 => 1,
    });
}

pub(super) fn read_vm_arch_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<VmArchitecture, EngineError> {
    match reader.read_u8()? {
        0 => Ok(VmArchitecture::X86_64),
        1 => Ok(VmArchitecture::Aarch64),
        _ => Err(scenario_serialization_error(
            "invalid virtual-machine architecture tag",
        )),
    }
}

pub(super) fn write_ready_point_binary(
    ready_point: &ReadyPoint,
    writer: &mut ScenarioBinaryWriter,
) {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => {
            writer.write_u8(0);
            writer.write_u64(icount.retired);
        }
        ReadyPoint::NetworkIdle { window } => {
            writer.write_u8(1);
            writer.write_u64(window.nanos);
        }
        ReadyPoint::ConsoleMarker { marker } => {
            writer.write_u8(2);
            writer.write_string(marker);
        }
        ReadyPoint::AgentSignal => {
            writer.write_u8(3);
        }
    }
}

pub(super) fn read_ready_point_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ReadyPoint, EngineError> {
    match reader.read_u8()? {
        0 => Ok(ReadyPoint::FixedIcount {
            icount: Icount {
                retired: reader.read_u64()?,
            },
        }),
        1 => Ok(ReadyPoint::NetworkIdle {
            window: SimDuration {
                nanos: reader.read_u64()?,
            },
        }),
        2 => Ok(ReadyPoint::ConsoleMarker {
            marker: reader.read_string()?,
        }),
        3 => Ok(ReadyPoint::AgentSignal),
        _ => Err(scenario_serialization_error("invalid ready-point tag")),
    }
}

pub(super) fn write_link_binary(link: &LinkDef, writer: &mut ScenarioBinaryWriter) {
    let (endpoint_a, endpoint_b) = link.endpoints();
    writer.write_string(&endpoint_a.name);
    writer.write_string(&endpoint_b.name);
    writer.write_u64(link.latency().nanos);
    writer.write_u64(link.jitter().nanos);
    writer.write_u32(link.loss().millionths());
    match link.bandwidth_bps() {
        Some(bandwidth) => {
            writer.write_u8(1);
            writer.write_u64(bandwidth);
        }
        None => writer.write_u8(0),
    }
}

pub(super) fn read_link_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<LinkDef, EngineError> {
    let endpoint_a = NodeId {
        name: reader.read_string()?,
    };
    let endpoint_b = NodeId {
        name: reader.read_string()?,
    };
    let latency = SimDuration {
        nanos: reader.read_u64()?,
    };
    let jitter = SimDuration {
        nanos: reader.read_u64()?,
    };
    let loss = LinkLossProbability::from_millionths(reader.read_u32()?)?;
    let bandwidth_bps = match reader.read_u8()? {
        0 => None,
        1 => Some(reader.read_u64()?),
        _ => return Err(scenario_serialization_error("invalid bandwidth tag")),
    };
    LinkDef::with_transport(endpoint_a, endpoint_b, latency, jitter, loss, bandwidth_bps)
}

pub(super) fn write_plan_binary(plan: &Plan, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(plan.content_hash());
    match &plan.kind {
        PlanKind::ScheduledEntries { entries } => {
            writer.write_count(entries.len());
            for entry in entries {
                write_plan_entry_binary(entry, writer);
            }
        }
        PlanKind::FaultPlan { plan } => {
            writer.write_u64(FAULT_PLAN_BINARY_SENTINEL);
            writer.write_count(plan.entries().len());
            for entry in plan.entries() {
                write_fault_plan_entry_binary(entry, writer);
            }
        }
        PlanKind::EventGraph { graph } => {
            writer.write_u64(EVENT_GRAPH_PLAN_BINARY_SENTINEL);
            writer.write_count(graph.events().len());
            for event in graph.events() {
                write_event_binary(event, writer);
            }
        }
    }
    writer.write_binary_blob(plan.fault_signals().wire_bytes());
}

pub(super) fn read_plan_binary(
    world: &World,
    assertions: impl IntoIterator<Item = AssertionId>,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Plan, EngineError> {
    read_plan_binary_inner(
        world,
        Some(assertions.into_iter().collect::<Vec<_>>()),
        reader,
    )
}

pub(super) fn read_plan_binary_for_scenario(
    world: &World,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Plan, EngineError> {
    read_plan_binary_inner(world, None, reader)
}

pub(super) fn read_plan_binary_inner(
    world: &World,
    assertions: Option<Vec<AssertionId>>,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Plan, EngineError> {
    let id = reader.read_hash()?;
    let count_or_sentinel = reader.read_u64()?;
    let plan = if count_or_sentinel == EVENT_GRAPH_PLAN_BINARY_SENTINEL {
        let count = reader.read_collection_count("plan.event")?;
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(read_event_binary(reader)?);
        }
        let assertions = assertions.unwrap_or_else(|| event_graph_assertion_references(&events));
        let graph = EventGraph::from_unchecked_events_for_model(events);
        Plan::from_event_graph_with_assertions_for_world(world, assertions, graph)?
    } else if count_or_sentinel == FAULT_PLAN_BINARY_SENTINEL {
        let count = reader.read_collection_count("plan.fault_entry")?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(read_fault_plan_entry_binary(reader)?);
        }
        Plan::from_fault_plan_for_world(world, FaultPlan::from_entries(entries))?
    } else {
        let count = collection_count_from_raw("plan.entry", count_or_sentinel)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(read_plan_entry_binary(reader)?);
        }
        Plan::from_entries_for_world(world, entries)?
    };
    let fault_signals =
        FaultSignalPlan::from_wire_bytes(reader.read_binary_blob("plan.fault_signals")?)
            .map_err(|error| scenario_serialization_error(error.to_string()))?;
    let plan = plan.with_fault_signals(fault_signals);
    validate_serialized_id("plan", id, plan.content_hash())?;
    Ok(plan)
}

//! Canonical hashing for execution-model identities.

use super::{
    Configuration, ContentHash, Decision, DecisionRngState, DeviceOverlayDelta, DeviceRngState,
    EventLogOffset, EventSequenceState, Icount, NodeBlobRef, NodeId, PendingFrame, PreemptionKind,
    RngDrawAddress, RngStreamId, RngStreamPosition, ScenarioDef, Schedule, SchedulerNodeId,
    SchedulerState, SchedulingNodeKind, TimerRegistry, TimerState, VirtualTime, VmSnapshotRef,
};
use std::collections::BTreeMap;

pub(super) fn content_hash_from_canonical_material(domain: &str, material: &str) -> ContentHash {
    content_hash_from_canonical_material_bytes(domain, material.as_bytes())
}

pub(super) fn content_hash_from_canonical_material_bytes(
    domain: &str,
    material: &[u8],
) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(domain.as_bytes());
    hasher.write_bytes(material);
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn content_hash_from_canonical_hex_bytes(domain: &str, bytes: &[u8]) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(domain.as_bytes());
    hasher.write_hex_bytes(bytes);
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn configuration_hash(configuration: &Configuration) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.configuration.v2");
    write_content_hash(&mut hasher, &configuration.def.id());
    write_seed(&mut hasher, configuration.def.seed());
    write_schedule(&mut hasher, &configuration.schedule);
    ContentHash {
        bytes: hasher.finish(),
    }
}

/// Computes [`configuration_hash`] for the first `len` decisions of `schedule`.
///
/// The canonical encoding writes the decision count before the decisions, so
/// one prefix identity cannot be extended into another; each costs one pass
/// over its own decisions. Nothing is copied. Returns `None` when `len`
/// exceeds the schedule.
pub(super) fn configuration_prefix_hash(
    def: &ScenarioDef,
    schedule: &Schedule,
    len: usize,
) -> Option<ContentHash> {
    if len > schedule.len() {
        return None;
    }

    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.configuration.v2");
    write_content_hash(&mut hasher, &def.id());
    write_seed(&mut hasher, def.seed());
    hasher.write_u64(len as u64);
    for decision in schedule.decision_history().iter().take(len) {
        write_decision(&mut hasher, decision);
    }
    Some(ContentHash {
        bytes: hasher.finish(),
    })
}

/// Extends a schedule's running decision chain by one decision.
///
/// The chain commits to every decision in order, so a chain value together
/// with the decision count identifies one exact schedule.
pub(super) fn decision_chain_step(previous: &ContentHash, decision: &Decision) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.schedule.decision-chain.v1");
    write_content_hash(&mut hasher, previous);
    write_decision(&mut hasher, decision);
    ContentHash {
        bytes: hasher.finish(),
    }
}

/// Binds a configuration's definition and exact schedule in constant time.
///
/// Unlike [`configuration_hash`], this reads the schedule's maintained decision
/// chain instead of rehashing every decision.
pub(super) fn configuration_admission_digest(configuration: &Configuration) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.configuration.admission.v1");
    write_content_hash(&mut hasher, &configuration.def.id());
    write_seed(&mut hasher, configuration.def.seed());
    hasher.write_u64(configuration.schedule.len() as u64);
    write_content_hash(&mut hasher, &configuration.schedule.decision_chain());
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn schedule_hash(schedule: &Schedule) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.schedule.v2");
    write_schedule(&mut hasher, schedule);
    ContentHash {
        bytes: hasher.finish(),
    }
}

/// Computes [`schedule_hash`] for decisions supplied by an iterator.
///
/// The canonical encoding writes the decision count before the decisions, so
/// the caller declares it up front. Returns `None` when the iterator yields a
/// different number of decisions, which leaves no partial identity behind.
pub(super) fn schedule_hash_from_decisions<'a>(
    len: usize,
    decisions: impl IntoIterator<Item = &'a Decision>,
) -> Option<ContentHash> {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.schedule.v2");
    hasher.write_u64(len as u64);

    let mut written = 0_usize;
    for decision in decisions {
        write_decision(&mut hasher, decision);
        written = written.saturating_add(1);
    }

    (written == len).then(|| ContentHash {
        bytes: hasher.finish(),
    })
}

/// Incremental form of [`content_hash_from_canonical_material_bytes`].
///
/// The material hash commits to the material length before its bytes, so the
/// stream takes the exact length when it starts. Bytes may then arrive in
/// arbitrarily sized pieces; the result is identical to hashing their
/// concatenation in one call, without ever holding that concatenation.
pub(super) struct CanonicalMaterialStream {
    hasher: MaterialHasher,
    declared_len: u64,
    written_len: u64,
    // Bytes of the next little-endian word that have not been mixed yet.
    pending: [u8; 8],
    pending_len: usize,
}

impl CanonicalMaterialStream {
    /// Starts a material hash in `domain` for exactly `material_len` bytes.
    pub(super) fn new(domain: &str, material_len: u64) -> Self {
        let mut hasher = MaterialHasher::new();
        hasher.write_bytes(b"crucible.content-hash.v1");
        hasher.write_bytes(domain.as_bytes());
        hasher.write_u64(material_len);
        Self {
            hasher,
            declared_len: material_len,
            written_len: 0,
            pending: [0; 8],
            pending_len: 0,
        }
    }

    /// Appends the next piece of material.
    pub(super) fn write(&mut self, mut bytes: &[u8]) {
        self.written_len = self.written_len.wrapping_add(bytes.len() as u64);

        // Complete a partially filled word before mixing whole words.
        if self.pending_len != 0 {
            let take = bytes.len().min(self.pending.len() - self.pending_len);
            let (head, rest) = bytes.split_at(take);
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(head);
            self.pending_len += take;
            bytes = rest;
            if self.pending_len < self.pending.len() {
                return;
            }
            self.hasher.mix_word(u64::from_le_bytes(self.pending));
            self.pending_len = 0;
        }

        let (words, remainder) = bytes.as_chunks::<8>();
        for word in words {
            self.hasher.mix_word(u64::from_le_bytes(*word));
        }
        self.pending[..remainder.len()].copy_from_slice(remainder);
        self.pending_len = remainder.len();
    }

    /// Finishes the hash, or returns `None` when the written length differs
    /// from the declared length.
    pub(super) fn finish(mut self) -> Option<ContentHash> {
        if self.written_len != self.declared_len {
            return None;
        }

        // The one-shot encoding zero-pads the final partial word.
        if self.pending_len != 0 {
            self.pending[self.pending_len..].fill(0);
            self.hasher.mix_word(u64::from_le_bytes(self.pending));
        }
        self.hasher.bytes_written = self.hasher.bytes_written.wrapping_add(self.declared_len);
        Some(ContentHash {
            bytes: self.hasher.finish(),
        })
    }
}

pub(super) fn reduced_state_hash(def: &ScenarioDef, schedule: &Schedule) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.reduce.state.v2");
    write_content_hash(&mut hasher, &def.id());
    write_seed(&mut hasher, def.seed());
    write_schedule(&mut hasher, schedule);
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn materialized_state_hash(
    vm_snapshots: &BTreeMap<NodeId, VmSnapshotRef>,
    device_overlays: &BTreeMap<super::DeviceId, DeviceOverlayDelta>,
    scheduler: &SchedulerState,
    decision_rng: &DecisionRngState,
    event_log: EventLogOffset,
) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.materialized-state.v2");
    write_vm_snapshots(&mut hasher, vm_snapshots);
    write_device_overlays(&mut hasher, device_overlays);
    write_scheduler_state(&mut hasher, scheduler);
    write_decision_rng_state(&mut hasher, decision_rng);
    write_event_log_offset(&mut hasher, event_log);
    ContentHash {
        bytes: hasher.finish(),
    }
}

fn write_schedule(hasher: &mut MaterialHasher, schedule: &Schedule) {
    hasher.write_u64(schedule.decision_history().len() as u64);
    for decision in schedule.decision_history() {
        write_decision(hasher, decision);
    }
}

fn write_decision(hasher: &mut MaterialHasher, decision: &Decision) {
    match decision {
        Decision::DeliveryOrder(order) => {
            hasher.write_u64(0);
            write_virtual_time(hasher, order.at);
            hasher.write_u64(order.order.len() as u64);
            for key in &order.order {
                write_virtual_time(hasher, key.virtual_time);
                write_scheduler_node_id(hasher, &key.consumer);
                write_scheduler_node_id(hasher, &key.producer);
                hasher.write_u64(key.sequence);
            }
        }
        Decision::RngDraw(draw) => {
            hasher.write_u64(1);
            write_rng_stream_id(hasher, &draw.stream);
            write_rng_draw_address(hasher, draw.address);
            hasher.write_u64(draw.value);
        }
        Decision::Override(override_decision) => {
            hasher.write_u64(2);
            hasher.write_bytes(override_decision.point.key.as_bytes());
            hasher.write_bytes(override_decision.choice.name.as_bytes());
        }
        Decision::Preemption(preemption) => {
            hasher.write_u64(3);
            hasher.write_bytes(preemption.node.name.as_bytes());
            hasher.write_u64(preemption.at.ticks);
            write_preemption_kind(hasher, &preemption.kind);
        }
        Decision::Selection(selection) => {
            hasher.write_u64(5);
            hasher.write_bytes(selection.canonical_bytes());
            if let Some(config) = selection.preemption_config() {
                hasher.write_u64(1);
                hasher.write_bytes(config.node.name.as_bytes());
                hasher.write_u64(config.deadline.ticks);
                hasher.write_u64(config.horizon.ticks);
                hasher.write_u64(config.step);
                hasher.write_u64(u64::from(config.switch_from_vcpu.index));
                hasher.write_u64(u64::from(config.switch_to_vcpu.index));
                hasher.write_u64(u64::from(config.target_vcpu.index));
                hasher.write_u64(u64::from(config.irq.vector));
            } else {
                hasher.write_u64(0);
            }
        }
    }
}

fn write_preemption_kind(hasher: &mut MaterialHasher, kind: &PreemptionKind) {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
            hasher.write_u64(0);
            hasher.write_u64(u64::from(from_vcpu.index));
            hasher.write_u64(u64::from(to_vcpu.index));
        }
        PreemptionKind::InterruptAt { target_vcpu, irq } => {
            hasher.write_u64(1);
            hasher.write_u64(u64::from(target_vcpu.index));
            hasher.write_u64(u64::from(irq.vector));
        }
    }
}

fn write_vm_snapshots(hasher: &mut MaterialHasher, snapshots: &BTreeMap<NodeId, VmSnapshotRef>) {
    hasher.write_u64(snapshots.len() as u64);
    for (node, snapshot) in snapshots {
        write_node_id(hasher, node);
        write_node_blob_ref(hasher, &snapshot.blob);
        write_icount(hasher, snapshot.icount);
    }
}

fn write_device_overlays(
    hasher: &mut MaterialHasher,
    overlays: &BTreeMap<super::DeviceId, DeviceOverlayDelta>,
) {
    hasher.write_u64(overlays.len() as u64);
    for (device, overlay) in overlays {
        hasher.write_bytes(device.name.as_bytes());
        write_content_hash(hasher, &overlay.parent);
        write_content_hash(hasher, &overlay.delta);
        write_content_hash(hasher, &overlay.resolved);
        write_device_rng_state(hasher, &overlay.rng);
    }
}

fn write_device_rng_state(hasher: &mut MaterialHasher, state: &DeviceRngState) {
    hasher.write_u64(state.streams.len() as u64);
    for (stream, position) in &state.streams {
        write_rng_stream_id(hasher, stream);
        write_rng_stream_position(hasher, *position);
    }
}

fn write_scheduler_state(hasher: &mut MaterialHasher, state: &SchedulerState) {
    hasher.write_u64(state.horizons.len() as u64);
    for (node, horizon) in &state.horizons {
        write_node_id(hasher, node);
        write_virtual_time(hasher, *horizon);
    }
    hasher.write_u64(state.pending_frames.len() as u64);
    for (node, frames) in &state.pending_frames {
        write_node_id(hasher, node);
        hasher.write_u64(frames.len() as u64);
        for frame in frames {
            write_pending_frame(hasher, frame);
        }
    }
    hasher.write_u64(state.network_link_cursors.len() as u64);
    for (link, cursor) in &state.network_link_cursors {
        hasher.write_bytes(link.name.as_bytes());
        hasher.write_u64(cursor.current_icount);
        hasher.write_u64(u64::from(cursor.next_sequence));
        hasher.write_u64(cursor.rng_position);
        hasher.write_u64(cursor.inflight.len() as u64);
        for pending in &cursor.inflight {
            hasher.write_u64(u64::from(pending.sequence));
            write_icount(hasher, pending.delivery_icount);
            hasher.write_u64(u64::from(pending.frame_id));
            write_content_hash(hasher, &pending.payload);
        }
    }
    write_event_sequence_state(hasher, &state.event_sequences);
    hasher.write_u64(state.topology_epoch);
    hasher.write_u64(state.effective_topology_edges.len() as u64);
    for edge in &state.effective_topology_edges {
        write_scheduler_lookahead_edge(hasher, edge);
    }
    hasher.write_u64(state.pending_topology_changes.len() as u64);
    for change in &state.pending_topology_changes {
        write_scheduler_topology_change(hasher, change);
    }
    write_timer_registry(hasher, &state.timers);
    hasher.write_u64(state.pending_device_decisions.len() as u64);
    for decision in &state.pending_device_decisions {
        write_decision(hasher, decision);
    }
    hasher.write_u64(state.search_frontier.choices().len() as u64);
    for choice in state.search_frontier.choices() {
        hasher.write_u64(choice.decisions().len() as u64);
        for decision in choice.decisions() {
            write_decision(hasher, decision);
        }
    }
}

fn write_scheduler_lookahead_edge(
    hasher: &mut MaterialHasher,
    edge: &crate::scheduler::SchedulerLookaheadEdge,
) {
    write_scheduler_node_id(hasher, &edge.from);
    write_scheduler_node_id(hasher, &edge.to);
    hasher.write_u64(edge.minimum_latency.ticks);
}

fn write_scheduler_topology_change(
    hasher: &mut MaterialHasher,
    change: &crate::scheduler::SchedulerTopologyChange,
) {
    use crate::scheduler::{SchedulerTopologyChangeEffect, SchedulerTopologyChangeTrigger};

    hasher.write_u64(change.sequence);
    hasher.write_u64(match change.trigger {
        SchedulerTopologyChangeTrigger::EdgeRemoval => 0,
        SchedulerTopologyChangeTrigger::EdgeRestore => 1,
        SchedulerTopologyChangeTrigger::LatencyChange => 2,
    });
    match change.activation_time {
        Some(at) => {
            hasher.write_bool(true);
            hasher.write_u64(at.ticks);
        }
        None => hasher.write_bool(false),
    }
    match &change.effect {
        SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(edges) => {
            hasher.write_u64(0);
            hasher.write_u64(edges.len() as u64);
            for edge in edges {
                write_scheduler_lookahead_edge(hasher, edge);
            }
        }
        SchedulerTopologyChangeEffect::UpdateEffectiveEdges(edges) => {
            hasher.write_u64(1);
            hasher.write_u64(edges.len() as u64);
            for edge in edges {
                write_scheduler_lookahead_edge(hasher, edge);
            }
        }
        SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
            hasher.write_u64(2);
            hasher.write_u64(endpoints.len() as u64);
            for endpoint in endpoints {
                write_scheduler_node_id(hasher, &endpoint.from);
                write_scheduler_node_id(hasher, &endpoint.to);
            }
        }
        SchedulerTopologyChangeEffect::RestoreEffectiveEdges(edges) => {
            hasher.write_u64(3);
            hasher.write_u64(edges.len() as u64);
            for edge in edges {
                write_scheduler_lookahead_edge(hasher, edge);
            }
        }
    }
}

fn write_pending_frame(hasher: &mut MaterialHasher, frame: &PendingFrame) {
    write_node_id(hasher, &frame.source);
    hasher.write_u64(frame.sequence);
    write_icount(hasher, frame.delivery_icount);
    write_content_hash(hasher, &frame.payload);
}

fn write_event_sequence_state(hasher: &mut MaterialHasher, state: &EventSequenceState) {
    hasher.write_u64(state.next.len() as u64);
    for (key, next) in &state.next {
        write_scheduler_node_id(hasher, &key.producer);
        write_scheduler_node_id(hasher, &key.consumer);
        hasher.write_u64(*next);
    }
}

fn write_timer_registry(hasher: &mut MaterialHasher, registry: &TimerRegistry) {
    hasher.write_u64(registry.timers.len() as u64);
    for (timer, state) in &registry.timers {
        hasher.write_bytes(timer.name.as_bytes());
        write_timer_state(hasher, state);
    }
}

fn write_timer_state(hasher: &mut MaterialHasher, state: &TimerState) {
    write_node_id(hasher, &state.owner);
    write_virtual_time(hasher, state.armed_at);
    write_virtual_time(hasher, state.fire_at);
    write_icount(hasher, state.fire_icount);
}

fn write_decision_rng_state(hasher: &mut MaterialHasher, state: &DecisionRngState) {
    hasher.write_u64(state.positions.len() as u64);
    for (stream, position) in &state.positions {
        write_rng_stream_id(hasher, stream);
        write_rng_stream_position(hasher, *position);
    }
}

fn write_rng_stream_id(hasher: &mut MaterialHasher, stream: &RngStreamId) {
    hasher.write_bytes(stream.domain.as_bytes());
    hasher.write_bytes(stream.name.as_bytes());
}

fn write_rng_draw_address(hasher: &mut MaterialHasher, address: RngDrawAddress) {
    match address {
        RngDrawAddress::Ordinal { ordinal } => {
            hasher.write_u64(0);
            hasher.write_u64(ordinal);
        }
        RngDrawAddress::LinkFrame {
            direction,
            producer_sequence,
            role,
        } => {
            hasher.write_u64(1);
            hasher.write_u64(u64::from(direction.code()));
            hasher.write_u64(producer_sequence);
            hasher.write_u64(role);
        }
    }
}

fn write_rng_stream_position(hasher: &mut MaterialHasher, position: RngStreamPosition) {
    hasher.write_u64(position.draws);
}

fn write_event_log_offset(hasher: &mut MaterialHasher, offset: EventLogOffset) {
    write_content_hash(hasher, &offset.prefix);
    match offset.appended_segment {
        Some(segment) => {
            hasher.write_bool(true);
            write_content_hash(hasher, &segment);
        }
        None => hasher.write_bool(false),
    }
    hasher.write_u64(offset.bytes);
    hasher.write_u64(offset.events);
}

fn write_node_blob_ref(hasher: &mut MaterialHasher, blob: &NodeBlobRef) {
    match blob {
        NodeBlobRef::Baked(hash) => {
            hasher.write_u64(0);
            write_content_hash(hasher, hash);
        }
        NodeBlobRef::CowDelta {
            parent,
            delta,
            resolved,
        } => {
            hasher.write_u64(1);
            write_content_hash(hasher, parent);
            write_content_hash(hasher, delta);
            write_content_hash(hasher, resolved);
        }
    }
}

fn write_node_id(hasher: &mut MaterialHasher, node: &NodeId) {
    hasher.write_bytes(node.name.as_bytes());
}

fn write_scheduler_node_id(hasher: &mut MaterialHasher, node: &SchedulerNodeId) {
    write_node_id(hasher, &node.node);
    write_scheduling_node_kind(hasher, node.kind);
}

fn write_scheduling_node_kind(hasher: &mut MaterialHasher, kind: SchedulingNodeKind) {
    let tag = match kind {
        SchedulingNodeKind::Vm => 0,
        SchedulingNodeKind::Disk => 1,
        SchedulingNodeKind::NineP => 2,
        SchedulingNodeKind::Network => 3,
        SchedulingNodeKind::ControlPlane => 4,
    };
    hasher.write_u64(tag);
}

fn write_content_hash(hasher: &mut MaterialHasher, hash: &ContentHash) {
    hasher.write_bytes(&hash.bytes);
}

fn write_seed(hasher: &mut MaterialHasher, seed: super::Seed) {
    hasher.write_bytes(&seed.bytes());
}

fn write_icount(hasher: &mut MaterialHasher, icount: Icount) {
    hasher.write_u64(icount.retired);
}

fn write_virtual_time(hasher: &mut MaterialHasher, virtual_time: VirtualTime) {
    hasher.write_u64(virtual_time.ticks);
}

struct MaterialHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl MaterialHasher {
    fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);

        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.mix_word(u64::from_le_bytes(*chunk));
        }

        if !remainder.is_empty() {
            let mut word = [0; 8];
            for (index, byte) in remainder.iter().enumerate() {
                word[index] = *byte;
            }
            self.mix_word(u64::from_le_bytes(word));
        }

        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    fn write_hex_bytes(&mut self, bytes: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let encoded_length = (bytes.len() as u64).wrapping_mul(2);
        self.write_u64(encoded_length);

        let mut word = [0; 8];
        let mut word_length = 0;
        for byte in bytes {
            for nibble in [byte >> 4, byte & 0x0f] {
                word[word_length] = HEX[usize::from(nibble)];
                word_length += 1;
                if word_length == word.len() {
                    self.mix_word(u64::from_le_bytes(word));
                    word = [0; 8];
                    word_length = 0;
                }
            }
        }
        if word_length != 0 {
            self.mix_word(u64::from_le_bytes(word));
        }

        self.bytes_written = self.bytes_written.wrapping_add(encoded_length);
    }

    fn finish(&self) -> [u8; 32] {
        let mut lanes = self.lanes;
        for (index, lane) in lanes.iter_mut().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            *lane = finalize_hash_word(lane.wrapping_add(self.bytes_written).wrapping_add(salt));
        }

        let mut bytes = [0; 32];
        for (index, lane) in lanes.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        bytes
    }

    fn write_u64(&mut self, value: u64) {
        self.mix_word(value);
        self.bytes_written = self.bytes_written.wrapping_add(8);
    }

    fn write_bool(&mut self, value: bool) {
        self.write_u64(u64::from(value));
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }
}

fn finalize_hash_word(mut word: u64) -> u64 {
    word ^= word >> 30;
    word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word ^= word >> 27;
    word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_byte_hash_matches_legacy_material_string() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for bytes in [
            Vec::new(),
            vec![0],
            vec![0xab, 0xcd, 0xef],
            (0_u8..=31).collect(),
        ] {
            let mut encoded = String::with_capacity(bytes.len() * 2);
            for byte in &bytes {
                encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }

            assert_eq!(
                content_hash_from_canonical_hex_bytes("crucible.test.hex-stream.v1", &bytes),
                content_hash_from_canonical_material("crucible.test.hex-stream.v1", &encoded)
            );
        }
    }

    #[test]
    fn streamed_material_hash_matches_one_shot_material_for_every_split() {
        let material = b"seed=00ff\nartifact=abcdef\nkept_schedule=0123\nremoved=1,22,333";
        let expected =
            content_hash_from_canonical_material_bytes("crucible.test.stream.v1", material);

        for piece_len in 1..=material.len() {
            let mut stream =
                CanonicalMaterialStream::new("crucible.test.stream.v1", material.len() as u64);
            for piece in material.chunks(piece_len) {
                stream.write(piece);
            }

            assert_eq!(stream.finish(), Some(expected), "piece length {piece_len}");
        }

        let empty = CanonicalMaterialStream::new("crucible.test.stream.v1", 0);
        assert_eq!(
            empty.finish(),
            Some(content_hash_from_canonical_material(
                "crucible.test.stream.v1",
                ""
            ))
        );
    }

    #[test]
    fn streamed_material_hash_rejects_a_length_other_than_declared() {
        let mut short = CanonicalMaterialStream::new("crucible.test.stream.v1", 4);
        short.write(b"abc");
        assert_eq!(short.finish(), None);

        let mut long = CanonicalMaterialStream::new("crucible.test.stream.v1", 2);
        long.write(b"abc");
        assert_eq!(long.finish(), None);
    }

    #[test]
    fn streamed_schedule_hash_matches_schedule_identity_and_checks_count() {
        let decisions = (0..3)
            .map(|value| {
                Decision::RngDraw(super::super::RngDecision::ordinal(
                    RngStreamId::from_name("canonical-stream-test"),
                    0,
                    value,
                ))
            })
            .collect::<Vec<_>>();
        let schedule = Schedule::from_decisions(decisions.clone());

        assert_eq!(
            schedule_hash_from_decisions(decisions.len(), &decisions),
            Some(schedule_hash(&schedule))
        );
        assert_eq!(schedule_hash_from_decisions(2, &decisions), None);
        assert_eq!(schedule_hash_from_decisions(4, &decisions), None);
    }
}

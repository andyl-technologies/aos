//! Canonical hashing for execution-model identities.

use super::{
    Configuration, ContentHash, Decision, Icount, PreemptionKind, ScenarioDef, Schedule,
    VirtualTime,
};

pub(super) fn content_hash_from_canonical_material(domain: &str, material: &str) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(domain.as_bytes());
    hasher.write_bytes(material.as_bytes());
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn configuration_hash(configuration: &Configuration) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.configuration.v1");
    write_content_hash(&mut hasher, &configuration.def.id);
    write_schedule(&mut hasher, &configuration.schedule);
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn schedule_hash(schedule: &Schedule) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.schedule.v1");
    write_schedule(&mut hasher, schedule);
    ContentHash {
        bytes: hasher.finish(),
    }
}

pub(super) fn reduced_state_hash(def: &ScenarioDef, schedule: &Schedule) -> ContentHash {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.reduce.state.v1");
    write_content_hash(&mut hasher, &def.id);
    write_schedule(&mut hasher, schedule);
    ContentHash {
        bytes: hasher.finish(),
    }
}

fn write_schedule(hasher: &mut MaterialHasher, schedule: &Schedule) {
    hasher.write_u64(schedule.decisions().len() as u64);
    for decision in schedule.decisions() {
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
                hasher.write_u64(key.sequence);
            }
        }
        Decision::FaultFires(fault) => {
            hasher.write_u64(1);
            write_virtual_time(hasher, fault.at);
            hasher.write_bytes(fault.fault.name.as_bytes());
            hasher.write_bool(fault.fired);
        }
        Decision::RngDraw(draw) => {
            hasher.write_u64(2);
            hasher.write_bytes(draw.stream.name.as_bytes());
            hasher.write_u64(draw.value);
        }
        Decision::Override(override_decision) => {
            hasher.write_u64(3);
            hasher.write_bytes(override_decision.point.key.as_bytes());
            hasher.write_bytes(override_decision.choice.name.as_bytes());
        }
        Decision::Preemption(preemption) => {
            hasher.write_u64(4);
            hasher.write_bytes(preemption.node.name.as_bytes());
            write_icount(hasher, preemption.at);
            write_preemption_kind(hasher, &preemption.kind);
        }
        Decision::AppRandom(random) => {
            hasher.write_u64(5);
            hasher.write_bytes(random.node.name.as_bytes());
            hasher.write_bytes(random.stream.name.as_bytes());
            hasher.write_u64(random.request_id);
            hasher.write_u64(u64::from(random.width));
            hasher.write_u64(random.value);
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

fn write_content_hash(hasher: &mut MaterialHasher, hash: &ContentHash) {
    hasher.write_bytes(&hash.bytes);
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

        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            self.mix_word(u64::from_le_bytes(word));
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut word = [0; 8];
            for (index, byte) in remainder.iter().enumerate() {
                word[index] = *byte;
            }
            self.mix_word(u64::from_le_bytes(word));
        }

        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
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

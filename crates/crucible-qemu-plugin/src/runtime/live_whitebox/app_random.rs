//! Synchronous live app-random service and independent decision conjecture.

use std::collections::BTreeMap;

use crucible_protocol::app_random_transport::{
    AppRandomDecisionTransportRecord, WHITEBOX_SHMEM_KIND_APP_RANDOM_DECISION,
    app_random_stream_name,
};
use crucible_protocol::{WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST, WhiteboxDoorbellFrame};
use crucible_shmem::MAX_FRAME_DATA;

use super::*;
use crate::{
    AppRandomDecisionError, AppRandomDecisionRecord, AppRandomDecisionSource,
    AppRandomDoorbellOutcome, WhiteboxGuestInputCapability, WhiteboxGuestInputWriteError,
    WhiteboxGuestInputWriter, handle_whitebox_app_random_callback,
};

pub(super) fn is_request(payload: &[u8]) -> bool {
    WhiteboxDoorbellFrame::decode_bounded(payload, MAX_FRAME_DATA)
        .is_ok_and(|frame| frame.kind() == WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST)
}

impl LiveWhiteboxState {
    pub(super) fn handle_app_random(
        &mut self,
        reader: &mut LiveGuestMemoryReader,
        event: WhiteboxDoorbellTrapEvent,
        current_icount: u64,
        vcpu_index: usize,
    ) -> Result<(), LiveWhiteboxError> {
        let app_random = self
            .app_random
            .as_mut()
            .ok_or(LiveWhiteboxError::AppRandomNotConfigured)?;
        let mut writer = LiveGuestMemoryWriter {
            apis: self.apis,
            current_icount,
        };
        let node_name = app_random.decisions.node_name().to_owned();
        let outcome = handle_whitebox_app_random_callback(
            &self.doorbell,
            &app_random.capability,
            reader,
            &mut app_random.decisions,
            &mut writer,
            &node_name,
            event,
        )
        .map_err(callback_error)?;
        if let AppRandomDoorbellOutcome::Served(service) = outcome {
            let record = AppRandomDecisionTransportRecord::new(
                service.request().guest_request_id(),
                service.request().width_bytes(),
                service.decision().value(),
                service.request().stream_tag(),
            )
            .map_err(callback_error)?;
            self.marker_sink
                .output
                .record_app_random(current_icount, vcpu_index as u32, &record)
                .map_err(callback_error)?;
        }
        Ok(())
    }
}

fn callback_error(source: impl ToString) -> LiveWhiteboxError {
    LiveWhiteboxError::Callback {
        message: source.to_string(),
    }
}

impl LiveWhiteboxMarkerShmemProducer {
    fn record_app_random(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        record: &AppRandomDecisionTransportRecord,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        self.record(
            current_icount,
            vcpu_index,
            WHITEBOX_SHMEM_KIND_APP_RANDOM_DECISION,
            &record.encode(),
        )
    }
}

pub(super) struct LiveGuestMemoryWriter {
    apis: LiveWhiteboxApis,
    current_icount: u64,
}

impl LiveGuestMemoryWriter {
    pub(super) const fn new(apis: LiveWhiteboxApis, current_icount: u64) -> Self {
        Self {
            apis,
            current_icount,
        }
    }
}

impl WhiteboxGuestInputWriter for LiveGuestMemoryWriter {
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), WhiteboxGuestInputWriteError> {
        if delivery_icount != self.current_icount {
            return Err(WhiteboxGuestInputWriteError::new(format!(
                "delivery icount {delivery_icount} differs from callback icount {}",
                self.current_icount
            )));
        }
        if !matches!(range.address_space(), GuestMemoryAddressSpace::Virtual) {
            return Err(WhiteboxGuestInputWriteError::new(
                "live white-box writer requires a virtual reply range",
            ));
        }
        if !(self.apis.write_memory_vaddr)(range.guest_address(), payload.as_ptr(), payload.len()) {
            return Err(WhiteboxGuestInputWriteError::new(
                "qemu_plugin_crucible_write_memory_vaddr failed",
            ));
        }
        Ok(())
    }
}

pub(super) struct LiveAppRandomState {
    capability: WhiteboxGuestInputCapability,
    decisions: LiveAppRandomDecisionSource,
}

impl LiveAppRandomState {
    pub(super) fn new(
        config: &PluginAppRandomConfig,
        capability: WhiteboxGuestInputCapability,
    ) -> Self {
        Self {
            capability,
            decisions: LiveAppRandomDecisionSource::new(config),
        }
    }
}

struct LiveAppRandomDecisionSource {
    root_seed: u64,
    streams: BTreeMap<String, PluginDecisionStream>,
    node_name: String,
    draw_cap: u64,
    draws: u64,
    branch_seed: Option<u64>,
    branch_after_draws: Option<u64>,
    branch_applied: bool,
}

impl LiveAppRandomDecisionSource {
    fn new(config: &PluginAppRandomConfig) -> Self {
        let streams = config
            .stream_positions()
            .iter()
            .map(|(name, draws)| {
                let mut stream = PluginDecisionStream::new(config.root_seed(), name);
                stream.advance_by(*draws);
                (name.clone(), stream)
            })
            .collect();
        Self {
            root_seed: config.root_seed(),
            streams,
            node_name: config.node_name().to_owned(),
            draw_cap: config.draw_cap(),
            draws: config.draw_offset(),
            branch_seed: config.branch_seed(),
            branch_after_draws: config.branch_after_draws(),
            branch_applied: false,
        }
    }

    fn node_name(&self) -> &str {
        &self.node_name
    }

    fn apply_branch_reseed_if_due(&mut self) {
        if self.branch_applied || self.branch_after_draws != Some(self.draws) {
            return;
        }
        if let Some(seed) = self.branch_seed {
            self.root_seed = seed;
            self.streams.clear();
            self.branch_applied = true;
        }
    }
}

impl AppRandomDecisionSource for LiveAppRandomDecisionSource {
    fn serve_app_random(
        &mut self,
        request: &crate::AppRandomDoorbellRequest,
    ) -> Result<AppRandomDecisionRecord, AppRandomDecisionError> {
        self.apply_branch_reseed_if_due();
        if self.draws >= self.draw_cap {
            return Err(AppRandomDecisionError::new(format!(
                "scenario app-random draw cap {} exceeded by draw {}",
                self.draw_cap,
                self.draws.saturating_add(1)
            )));
        }
        let stream_name = app_random_stream_name(request.node_name(), request.stream_tag());
        let stream = self
            .streams
            .entry(stream_name.clone())
            .or_insert_with(|| PluginDecisionStream::new(self.root_seed, &stream_name));
        let raw_value = stream.next_u64();
        self.draws = self.draws.saturating_add(1);
        let width_bits = request.width_bits();
        let value = if width_bits == 64 {
            raw_value
        } else {
            raw_value & ((1_u64 << width_bits) - 1)
        };
        Ok(AppRandomDecisionRecord::new(
            request.node_name(),
            request.stream_tag(),
            u64::from(request.guest_request_id()),
            width_bits,
            value,
        ))
    }
}

struct PluginDecisionStream {
    state: u64,
}

impl PluginDecisionStream {
    const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
    const NAME_HASH_DOMAIN: &str = "crucible.decision-rng.name-hash.v1";

    fn new(root_seed: u64, stream_name: &str) -> Self {
        Self {
            state: root_seed ^ Self::stable_stream_hash(stream_name),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(Self::GAMMA);
        let mut word = self.state;
        word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        word ^ (word >> 31)
    }

    fn advance_by(&mut self, draws: u64) {
        self.state = self.state.wrapping_add(Self::GAMMA.wrapping_mul(draws));
    }

    fn stable_stream_hash(stream_name: &str) -> u64 {
        let mut hasher = PluginStableHasher::new();
        hasher.write_bytes(Self::NAME_HASH_DOMAIN.as_bytes());
        hasher.write_bytes(Self::NAME_HASH_DOMAIN.as_bytes());
        hasher.write_bytes(stream_name.as_bytes());
        hasher.finish_first_lane()
    }
}

struct PluginStableHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl PluginStableHasher {
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
        self.mix_word(bytes.len() as u64);
        self.bytes_written = self.bytes_written.wrapping_add(8);
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            self.mix_word(u64::from_le_bytes(word));
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut word = [0; 8];
            word[..remainder.len()].copy_from_slice(remainder);
            self.mix_word(u64::from_le_bytes(word));
        }
        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
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

    fn finish_first_lane(&self) -> u64 {
        let mut word = self.lanes[0].wrapping_add(self.bytes_written);
        word ^= word >> 30;
        word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        word ^= word >> 27;
        word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
        word ^ (word >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PluginArgs;

    #[test]
    fn plugin_stream_matches_the_authoritative_engine_stream() {
        let scenario_seed = crucible::Seed::from_u64(1_048_598);
        let root_seed = scenario_seed.decision_rng_root_seed();
        let stream_name = app_random_stream_name("node-a", "live-rng");
        let mut plugin = PluginDecisionStream::new(root_seed, &stream_name);
        let stream = crucible::RngStreamId::from_name(stream_name);
        let mut engine = scenario_seed
            .decision_rng()
            .fork_in_domain(&stream.domain, &stream.name);

        assert_eq!(plugin.next_u64(), engine.next_u64());
        plugin.advance_by(17);
        engine.advance_by(17);
        assert_eq!(plugin.next_u64(), engine.next_u64());
    }

    #[test]
    fn branch_reseed_restarts_every_plugin_stream_at_cursor_zero() {
        let args = PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=11,app_random_cap=8,app_random_node=node-a,app_random_branch_seed=29,app_random_branch_after=1",
        )
        .unwrap_or_else(|error| panic!("branch configuration should parse: {error}"));
        let config = args
            .app_random()
            .unwrap_or_else(|| panic!("branch configuration should include app-random"));
        let mut source = LiveAppRandomDecisionSource::new(config);
        let stream_name = String::from("node-a/workload");
        let prefix_stream = source
            .streams
            .entry(stream_name.clone())
            .or_insert_with(|| PluginDecisionStream::new(source.root_seed, &stream_name));
        let _ = prefix_stream.next_u64();
        source.draws = 1;

        let mut expected = PluginDecisionStream::new(29, &stream_name);
        let expected_first_branch_draw = expected.next_u64();
        source.apply_branch_reseed_if_due();
        let actual_first_branch_draw = source
            .streams
            .entry(stream_name.clone())
            .or_insert_with(|| PluginDecisionStream::new(source.root_seed, &stream_name))
            .next_u64();

        assert!(source.branch_applied);
        assert_eq!(source.root_seed, 29);
        assert_eq!(actual_first_branch_draw, expected_first_branch_draw);
    }
}

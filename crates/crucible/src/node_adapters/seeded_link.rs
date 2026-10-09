//! Selected seeded byte transport with complete original fault and RNG custody.
//!
//! This model uses the existing NetLink integer jitter/reorder semantics and
//! five-draw per-frame stream. It does not reinterpret payloads as Ethernet.
//! Its explicit definition and native snapshot are separate from legacy links.

use crucible_device::netlink::{LinkFaults, LinkSnapshot, NetLink};
use crucible_node_contract::{Bytes, Id, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::host::failure;
use crate::node_contract::OperationFailure;

/// Defines a bounded, seeded jitter/reorder transport with unchanged payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeededLinkDefinition {
    /// Selects the closed native transport definition edition.
    pub version: u32,
    /// Binds the scenario seed used by the existing decision stream.
    pub seed: U64,
    /// Binds the stable name within the seeded-link stream domain.
    pub stream: Id,
    /// Binds the native producer identity without truncation.
    pub source_node: u32,
    /// Selects positive fixed native delivery latency in picoseconds.
    pub latency_ps: U64,
    /// Selects the positive conservative minimum delivery latency.
    pub floor_ps: U64,
    /// Bounds inclusive integer seeded jitter in picoseconds.
    pub jitter_ps: U64,
    /// Bounds inclusive integer seeded reordering delay in picoseconds.
    pub reorder_ps: U64,
}

impl SeededLinkDefinition {
    /// Constructs an inactive native link with the complete selected fault table.
    ///
    /// # Errors
    /// Refuses unknown editions, malformed names, unbounded timing, zero floor,
    /// absent seeded faults, or latency below the conservative floor.
    pub fn instantiate(&self) -> Result<NetLink, OperationFailure> {
        self.stream
            .validate()
            .map_err(|error| failure(&error.to_string()))?;
        if self.version != 1
            || self.floor_ps.get() == 0
            || self.latency_ps < self.floor_ps
            || self.latency_ps.get() > 1_000_000_000
            || self.jitter_ps.get() > 1_000_000_000
            || self.reorder_ps.get() > 1_000_000_000
            || (self.jitter_ps.get() == 0 && self.reorder_ps.get() == 0)
        {
            return Err(failure(
                "selected seeded transport definition is unsupported",
            ));
        }
        NetLink::new(
            self.source_node,
            self.latency_ps.get(),
            self.floor_ps.get(),
            self.faults(),
        )
        .map_err(|error| failure(&error.to_string()))
    }

    /// Returns the complete selected static jitter/reorder fault table.
    #[must_use]
    pub fn faults(&self) -> LinkFaults {
        LinkFaults {
            jitter_window_ticks: self.jitter_ps.get(),
            reorder_window_ticks: self.reorder_ps.get(),
            ..LinkFaults::none()
        }
    }

    /// Restores unchanged native state under this independently selected definition.
    ///
    /// # Errors
    /// Refuses malformed or excessive content, changed seed/stream/timing/faults,
    /// invalid frame credits, or a random cursor inconsistent with original frames.
    pub fn restore(&self, bytes: &[u8], maximum: usize) -> Result<NetLink, OperationFailure> {
        if bytes.len() > maximum {
            return Err(failure("seeded transport capture exceeds its byte ceiling"));
        }
        let value =
            canonical::parse_json(bytes, maximum).map_err(|error| failure(&error.to_string()))?;
        let saved: Snapshot =
            serde_json::from_value(value).map_err(|error| failure(&error.to_string()))?;
        if saved.version != 1
            || saved.definition != *self
            || encode(&saved).map_err(|error| failure(&error.to_string()))? != bytes
        {
            return Err(failure(
                "seeded transport changed its original definition or encoding",
            ));
        }
        let initial = self.instantiate()?.snapshot();
        let snapshot =
            LinkSnapshot::from_canonical_bytes_with_limit(saved.native.as_slice(), maximum as u64)
                .map_err(|error| failure(&error.to_string()))?;
        if snapshot.ticks_per_ns != initial.ticks_per_ns
            || snapshot.src_node != initial.src_node
            || snapshot.base_latency_ticks != initial.base_latency_ticks
            || snapshot.floor_ticks != initial.floor_ticks
            || snapshot.faults != initial.faults
            || snapshot.inflight.len() > 16
            || snapshot.next_seq > 16
            || u64::from(snapshot.next_seq).checked_mul(5) != Some(snapshot.rng_position)
        {
            return Err(failure(
                "seeded transport changed native fault, frame or RNG custody",
            ));
        }
        NetLink::restore(&snapshot).map_err(|error| failure(&error.to_string()))
    }

    pub(super) fn capture(
        &self,
        link: &NetLink,
        maximum: usize,
    ) -> Result<Vec<u8>, OperationFailure> {
        encode(&Snapshot {
            version: 1,
            definition: self.clone(),
            native: Bytes::new(
                link.snapshot()
                    .canonical_bytes_with_limit(maximum as u64)
                    .map_err(|error| failure(&error.to_string()))?,
            ),
        })
        .map_err(|error| failure(&error.to_string()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    definition: SeededLinkDefinition,
    native: Bytes,
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, crucible_node_contract::ContractError> {
    canonical::canonical_json(&serde_json::to_value(value)?)
}

// crucible-lint: allow panic-shortcut -- Seeded transport tests panic when original native state or rejection invariants fail.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crucible_device::netlink::{Frame, PastDeliveryPolicy};

    fn definition() -> SeededLinkDefinition {
        SeededLinkDefinition {
            version: 1,
            seed: 77.into(),
            stream: Id::new("storage/requests").expect("test name"),
            source_node: 17,
            latency_ps: 1000.into(),
            floor_ps: 1000.into(),
            jitter_ps: 5000.into(),
            reorder_ps: 3000.into(),
        }
    }

    #[test]
    fn original_pending_frame_and_next_draw_remain_identical_after_restore() {
        let definition = definition();
        let mut original = definition.instantiate().expect("native link");
        let mut rng = original.rng(77, "crucible/seeded-link-v1", "storage/requests");
        original
            .emit_from_rng(
                &Frame::new(10, 101, vec![1, 2, 3]),
                &mut rng,
                PastDeliveryPolicy::FailLoud,
            )
            .expect("frame");
        assert_eq!(original.rng_position(), 5);
        let bytes = definition.capture(&original, 1024 * 1024).expect("capture");
        let mut restored = definition.restore(&bytes, 1024 * 1024).expect("restore");
        assert_eq!(original.snapshot(), restored.snapshot());
        for link in [&mut original, &mut restored] {
            let mut rng = link.rng(77, "crucible/seeded-link-v1", "storage/requests");
            link.emit_from_rng(
                &Frame::new(11, 102, vec![4]),
                &mut rng,
                PastDeliveryPolicy::FailLoud,
            )
            .expect("next frame");
        }
        assert_eq!(original.snapshot(), restored.snapshot());
        assert_eq!(original.rng_position(), 10);
    }

    #[test]
    fn changed_seed_stream_and_fault_policy_refuse_original_native_snapshot() {
        let original = definition();
        let bytes = original
            .capture(&original.instantiate().expect("link"), 1024 * 1024)
            .expect("capture");
        let mut changed = original.clone();
        changed.seed = 78.into();
        assert!(changed.restore(&bytes, 1024 * 1024).is_err());
        changed = original.clone();
        changed.stream = Id::new("other-stream").expect("name");
        assert!(changed.restore(&bytes, 1024 * 1024).is_err());
        changed = original.clone();
        changed.reorder_ps = 3001.into();
        assert!(changed.restore(&bytes, 1024 * 1024).is_err());
        assert!(original.restore(&bytes, bytes.len() - 1).is_err());
    }

    #[test]
    fn changed_native_faults_or_random_cursor_refuse_even_matching_seed_label() {
        let definition = definition();
        let link = definition.instantiate().expect("native link");
        let bytes = definition.capture(&link, 1024 * 1024).expect("capture");
        let mut saved: Snapshot = serde_json::from_slice(&bytes).expect("snapshot");
        let mut native = link.snapshot();
        native.rng_position = 5;
        saved.native = Bytes::new(
            native
                .canonical_bytes_with_limit(1024 * 1024)
                .expect("native bytes"),
        );
        assert!(
            definition
                .restore(&encode(&saved).expect("encoding"), 1024 * 1024)
                .is_err()
        );
        native = link.snapshot();
        native.faults.jitter_window_ticks = 1;
        saved.native = Bytes::new(
            native
                .canonical_bytes_with_limit(1024 * 1024)
                .expect("native bytes"),
        );
        assert!(
            definition
                .restore(&encode(&saved).expect("encoding"), 1024 * 1024)
                .is_err()
        );
    }
}

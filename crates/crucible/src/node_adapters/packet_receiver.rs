//! Native opaque packet echo custody with bounded input history and pending replies.
//!
//! Packets carry no implied Block, Ethernet or guest protocol validity. Each
//! original admitted packet yields one byte-identical response after the fixed
//! positive delay, preserving the actually received post-fault bytes.
//!
//! The closed native continuation starts with this empty state:
//!
//! ```text
//! {"version":1,"source":17,"latency":"1000","clock":"0","delivered":0,"packets":[]}
//! ```
//!
//! Each retained packet has its original input time, fixed response time and
//! exact opaque bytes. The delivered prefix distinguishes history from pending
//! work; replaying the decoder does not submit or publish any packet.

use crucible_node_contract::{Bytes, U64, canonical};
use serde::{Deserialize, Serialize};

use super::host::failure;
use crate::node_contract::OperationFailure;

/// Owns the complete state of a bounded native opaque packet receiver.
#[derive(Clone)]
pub struct PacketReceiver {
    source: u32,
    latency: u64,
    clock: u64,
    packets: Vec<Packet>,
    delivered: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    input_time: U64,
    response_time: U64,
    payload: Bytes,
}

impl PacketReceiver {
    /// Creates an inactive receiver with a positive fixed response delay.
    ///
    /// # Errors
    /// Refuses zero or excessive latency.
    pub fn new(source: u32, latency: u64) -> Result<Self, OperationFailure> {
        if latency == 0 || latency > 1_000_000_000 {
            return Err(failure("packet receiver latency is unsupported"));
        }
        Ok(Self {
            source,
            latency,
            clock: 0,
            packets: Vec::new(),
            delivered: 0,
        })
    }

    pub(super) fn time_ps(&self) -> u64 {
        self.clock
    }
    pub(super) fn pending_count(&self) -> usize {
        self.packets.len() - self.delivered
    }
    pub(super) fn pending_keys(&self) -> impl Iterator<Item = (u64, u32, u32)> + '_ {
        self.packets
            .iter()
            .enumerate()
            .skip(self.delivered)
            .map(|(sequence, packet)| (packet.response_time.get(), self.source, sequence as u32))
    }
    pub(super) fn next_time(&self) -> Option<u64> {
        self.packets
            .get(self.delivered)
            .map(|packet| packet.response_time.get())
    }

    pub(super) fn consume(
        &mut self,
        time: u64,
        bytes: &[u8],
    ) -> Result<(u64, u32, u32), OperationFailure> {
        if self.packets.len() >= 32
            || bytes.is_empty()
            || bytes.len() > 64 * 1024
            || self
                .packets
                .last()
                .is_some_and(|packet| packet.input_time.get() > time)
        {
            return Err(failure(
                "packet original input or retention credit is invalid",
            ));
        }
        let response = time
            .checked_add(self.latency)
            .ok_or_else(|| failure("packet response time overflow"))?;
        self.packets
            .try_reserve(1)
            .map_err(|_| failure("packet history credit unavailable"))?;
        let sequence = self.packets.len() as u32;
        self.packets.push(Packet {
            input_time: time.into(),
            response_time: response.into(),
            payload: Bytes::new(bytes.to_vec()),
        });
        Ok((response, self.source, sequence))
    }

    pub(super) fn deliver(&mut self, time: u64) -> Vec<((u64, u32, u32), Vec<u8>)> {
        let mut outputs = Vec::new();
        while let Some(packet) = self.packets.get(self.delivered) {
            if packet.response_time.get() > time {
                break;
            }
            outputs.push((
                (
                    packet.response_time.get(),
                    self.source,
                    self.delivered as u32,
                ),
                packet.payload.as_slice().to_vec(),
            ));
            self.delivered += 1;
        }
        outputs
    }

    pub(super) fn park(&mut self, time: u64) -> Result<(), OperationFailure> {
        if time < self.clock {
            return Err(failure("packet native clock regressed"));
        }
        self.clock = time;
        Ok(())
    }

    pub(super) fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        encode(&Snapshot {
            version: 1,
            source: self.source,
            latency: self.latency.into(),
            clock: self.clock.into(),
            delivered: self.delivered as u32,
            packets: self.packets.clone(),
        })
    }

    pub(super) fn restore(&mut self, bytes: &[u8]) -> Result<(), OperationFailure> {
        let parsed = canonical::parse_json(bytes, 4 * 1024 * 1024)
            .map_err(|error| failure(&error.to_string()))?;
        let saved: Snapshot =
            serde_json::from_value(parsed).map_err(|error| failure(&error.to_string()))?;
        if saved.version != 1
            || saved.source != self.source
            || saved.latency.get() != self.latency
            || saved.packets.len() > 32
            || saved.delivered as usize > saved.packets.len()
            || encode(&saved)? != bytes
            || saved
                .packets
                .windows(2)
                .any(|pair| pair[0].input_time > pair[1].input_time)
            || saved.packets.iter().enumerate().any(|(index, packet)| {
                packet.input_time.get().checked_add(self.latency)
                    != Some(packet.response_time.get())
                    || packet.payload.as_slice().is_empty()
                    || packet.payload.as_slice().len() > 64 * 1024
                    || (index < saved.delivered as usize && packet.response_time > saved.clock)
            })
        {
            return Err(failure(
                "packet continuation changed original policy or history",
            ));
        }
        self.clock = saved.clock.get();
        self.delivered = saved.delivered as usize;
        self.packets = saved.packets;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    source: u32,
    latency: U64,
    clock: U64,
    delivered: u32,
    packets: Vec<Packet>,
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(
        &serde_json::to_value(value).map_err(|error| failure(&error.to_string()))?,
    )
    .map_err(|error| failure(&error.to_string()))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Packet custody tests panic on changed originals or an accepted invalid continuation.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pending_received_bytes_restore_and_echo_once_without_protocol_decoding() {
        let mut original = PacketReceiver::new(17, 100).expect("receiver");
        original.consume(10, &[0xff, 0, 0x80]).expect("packet");
        original.park(11).expect("cut");
        let bytes = original.capture().expect("capture");
        let mut restored = PacketReceiver::new(17, 100).expect("fresh receiver");
        restored.restore(&bytes).expect("original native");

        assert_eq!(restored.next_time(), Some(110));
        assert_eq!(restored.deliver(110), original.deliver(110));
        assert!(restored.deliver(110).is_empty());
        restored.park(110).expect("cut");
        original.park(110).expect("cut");
        assert_eq!(
            original.capture().expect("state"),
            restored.capture().expect("state")
        );
    }

    #[test]
    fn changed_latency_or_claimed_delivered_prefix_refuse_original_pending_packet() {
        let mut original = PacketReceiver::new(17, 100).expect("receiver");
        original.consume(10, &[1, 2, 3]).expect("packet");
        original.park(11).expect("cut");
        let bytes = original.capture().expect("capture");
        assert!(
            PacketReceiver::new(17, 101)
                .expect("receiver")
                .restore(&bytes)
                .is_err()
        );
        let mut saved: Snapshot = serde_json::from_slice(&bytes).expect("snapshot");
        saved.delivered = 1;
        assert!(
            PacketReceiver::new(17, 100)
                .expect("receiver")
                .restore(&encode(&saved).expect("encoding"))
                .is_err()
        );
    }
}

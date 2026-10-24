//! Exercises genuine complete-source preparation under its original refused plan.
//!
//! This control does not issue Arm or claim capture and restoration authority.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_node_format::{Id, canonical};
use serde::Serialize;

#[path = "packet_canonical_ack_admission/configuration.rs"]
mod configuration;
#[path = "packet_canonical_ack_admission/content.rs"]
mod content;
#[path = "packet_canonical_ack_admission/definition.rs"]
mod definition;
#[path = "packet_canonical_ack_admission/flight.rs"]
mod flight;
#[path = "packet_canonical_ack_admission/host.rs"]
mod host;
#[path = "packet_canonical_ack_admission/measurement.rs"]
mod measurement;
#[path = "packet_canonical_ack_admission/setup.rs"]
mod setup;
#[path = "packet_canonical_ack_admission/transport.rs"]
mod transport;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn encoded(value: &impl Serialize) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap()
}

#[test]
#[ignore = "requires original measured source-built child and compiler inputs"]
fn three_original_children_verify_once_keyed_protocol_admit_and_reap() {
    flight::run();
}

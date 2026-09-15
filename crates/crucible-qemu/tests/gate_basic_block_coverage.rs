//! Checks `gate:basic-block-coverage` at the QEMU host/plugin boundary.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BasicBlockCoverageConfig, BasicBlockCoverageMode, BlackBoxObservationKind, NodeId,
    basic_block_coverage_map_index,
};
use crucible_protocol::PluginBasicBlockCoverageObservation;
use crucible_qemu::{QemuBasicBlockCoverageBridge, QemuCoverageError};

#[test]
fn gate_basic_block_coverage_consumes_plugin_protocol_observation() {
    let map_entries = 1024;
    let plugin_map_index = basic_block_coverage_map_index(0x4010, map_entries)
        .unwrap_or_else(|error| panic!("test map index should fold: {error}"));
    let observation =
        PluginBasicBlockCoverageObservation::new(77, 2, 0x4010, 16, plugin_map_index as u64, true)
            .unwrap_or_else(|error| panic!("plugin coverage observation should validate: {error}"));
    let bridge = QemuBasicBlockCoverageBridge::new(
        node("plugin-node"),
        BasicBlockCoverageConfig::new(BasicBlockCoverageMode::On, map_entries),
    )
    .unwrap_or_else(|error| panic!("QEMU coverage bridge should build: {error}"));

    let consumed = bridge
        .consume_plugin_observation(observation)
        .unwrap_or_else(|error| panic!("plugin observation should feed engine consumer: {error}"));

    assert_eq!(consumed.map_index(), plugin_map_index);
    assert_eq!(
        consumed.event().payload().black_box_observation_kind(),
        Some(BlackBoxObservationKind::BasicBlockCoverage)
    );
    assert_eq!(consumed.event().at().ticks, 77);

    let wrong_index = PluginBasicBlockCoverageObservation::new(
        77,
        2,
        0x4010,
        16,
        (plugin_map_index + 1) as u64,
        true,
    )
    .unwrap_or_else(|error| panic!("mismatched plugin index observation should validate: {error}"));
    assert_eq!(
        bridge.consume_plugin_observation(wrong_index),
        Err(QemuCoverageError::PluginMapIndexMismatch {
            plugin_map_index: plugin_map_index + 1,
            engine_map_index: plugin_map_index,
        })
    );
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

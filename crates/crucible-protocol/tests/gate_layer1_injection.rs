//! Checks `gate:layer1-injection` protocol control/data-plane separation.

#![forbid(unsafe_code)]

use crucible_protocol::{RUNTIME_DATA_PLANE_CONTRACT, RuntimeDataPlane};

#[test]
fn gate_layer1_injection_control_protocol_carries_no_runtime_injection_data() {
    assert_eq!(
        RUNTIME_DATA_PLANE_CONTRACT.runtime_data_plane,
        RuntimeDataPlane::SharedMemory
    );
    const {
        assert!(!RUNTIME_DATA_PLANE_CONTRACT.control_channel_carries_runtime_frames);
        assert!(!RUNTIME_DATA_PLANE_CONTRACT.control_channel_carries_delivery_icounts);
    }
}

#[test]
fn gate_layer1_injection_control_protocol_is_silent_on_hot_path() {
    const {
        assert!(RUNTIME_DATA_PLANE_CONTRACT.control_channel_silent_between_setup_ack_and_quit);
    }
}

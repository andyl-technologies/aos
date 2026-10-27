//! Checks protocol-only completion commits without another byte transaction.
// SPDX-License-Identifier: Apache-2.0

use crucible_qemu_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleState, ControlLifecycleStream, NegotiatedHandshake,
    PluginHandshakeConfig,
};

fn config() -> PluginHandshakeConfig {
    PluginHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: 33,
    }
}

fn reply() -> NegotiatedHandshake {
    NegotiatedHandshake {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: 33,
        slot_index: 0,
        node_count: 1,
    }
}

#[test]
fn completed_exchange_advances_protocol_once_without_replaying_transport() {
    // A unit stream cannot perform byte I/O. Actual completion facts allow
    // protocol bookkeeping only; this fixture supplies no endpoint authority.
    let mut control = ControlLifecycleStream::connected_unix_stream(()).unwrap();

    control.plugin_commit_written_hello().unwrap();
    assert_eq!(control.state(), ControlLifecycleState::HelloSent);
    control
        .plugin_commit_read_hello_ack(reply(), config())
        .unwrap();
    control.plugin_commit_preexec_setup().unwrap();

    assert_eq!(control.state(), ControlLifecycleState::SetupSent);
    assert!(control.plugin_commit_written_hello().is_err());
    assert!(
        control
            .plugin_commit_read_hello_ack(reply(), config())
            .is_err()
    );
    assert!(control.plugin_commit_preexec_setup().is_err());
    assert_eq!(control.state(), ControlLifecycleState::SetupSent);
}

#[test]
fn invalid_or_partial_exchange_cannot_commit_setup_or_skip_ack_validation() {
    let mut control = ControlLifecycleStream::connected_unix_stream(()).unwrap();
    assert!(control.plugin_commit_preexec_setup().is_err());
    assert!(
        control
            .plugin_commit_read_hello_ack(reply(), config())
            .is_err()
    );
    control.plugin_commit_written_hello().unwrap();
    assert!(control.plugin_commit_preexec_setup().is_err());

    let mut invalid = reply();
    invalid.abi_version = 31;
    assert!(
        control
            .plugin_commit_read_hello_ack(invalid, config())
            .is_err()
    );
    invalid = reply();
    invalid.slot_index = invalid.node_count;
    assert!(
        control
            .plugin_commit_read_hello_ack(invalid, config())
            .is_err()
    );

    assert_eq!(control.state(), ControlLifecycleState::HelloSent);
    control
        .plugin_commit_read_hello_ack(reply(), config())
        .unwrap();
    control.plugin_commit_preexec_setup().unwrap();
}

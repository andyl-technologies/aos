//! Checks `Hello`/`HelloAck` control-protocol negotiation.

#![forbid(unsafe_code)]

use std::io::{Cursor, Read, Write};

use crucible_protocol::{
    CONTROL_PROTOCOL_MIN_VERSION, CONTROL_PROTOCOL_VERSION, HandshakeError, HostHandshakeConfig,
    HostMsg, NegotiatedHandshake, PluginHandshakeConfig, PluginMsg, control_encode_host_msg,
    control_encode_plugin_msg, host_accept_handshake, host_negotiate_handshake,
    plugin_start_handshake, plugin_validate_handshake_ack,
};

#[test]
fn host_accepts_hello_negotiates_minimum_and_writes_hello_ack() {
    let hello = control_encode_plugin_msg(&PluginMsg::Hello {
        proto_version: CONTROL_PROTOCOL_VERSION + 2,
        abi_version: 1,
    });
    let mut io = ScriptedIo::from_input(hello);

    let negotiated = host_accept_handshake(
        &mut io,
        HostHandshakeConfig {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 1,
            slot_index: 3,
            node_count: 8,
        },
    );

    assert_eq!(
        negotiated,
        Ok(NegotiatedHandshake {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 1,
            slot_index: 3,
            node_count: 8,
        })
    );
    assert_eq!(
        io.written(),
        control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 1,
            slot_index: 3,
            node_count: 8,
        })
    );
    assert_eq!(io.flush_count(), 1);
}

#[test]
fn plugin_sends_hello_and_validates_hello_ack_before_setup() {
    let ack = control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_MIN_VERSION,
        abi_version: 1,
        slot_index: 0,
        node_count: 4,
    });
    let mut io = ScriptedIo::from_input(ack);

    let negotiated = plugin_start_handshake(
        &mut io,
        PluginHandshakeConfig {
            proto_version: CONTROL_PROTOCOL_VERSION + 1,
            abi_version: 1,
        },
    );

    assert_eq!(
        negotiated,
        Ok(NegotiatedHandshake {
            proto_version: CONTROL_PROTOCOL_MIN_VERSION,
            abi_version: 1,
            slot_index: 0,
            node_count: 4,
        })
    );
    assert_eq!(
        io.written(),
        control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_VERSION + 1,
            abi_version: 1,
        })
    );
    assert_eq!(io.flush_count(), 1);
}

#[test]
fn host_rejects_handshake_failures_without_hello_ack() {
    let config = HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: 1,
        slot_index: 0,
        node_count: 2,
    };

    assert_eq!(
        host_negotiate_handshake(PluginMsg::SetupAck { status: 0 }, config),
        Err(HandshakeError::UnexpectedPluginMessage {
            message: PluginMsg::SetupAck { status: 0 },
        })
    );
    assert_eq!(
        host_negotiate_handshake(
            PluginMsg::Hello {
                proto_version: CONTROL_PROTOCOL_MIN_VERSION - 1,
                abi_version: 1,
            },
            config,
        ),
        Err(HandshakeError::ProtocolVersionNoOverlap {
            plugin_max: CONTROL_PROTOCOL_MIN_VERSION - 1,
            host_min: CONTROL_PROTOCOL_MIN_VERSION,
            host_max: CONTROL_PROTOCOL_VERSION,
        })
    );
    assert_eq!(
        host_negotiate_handshake(
            PluginMsg::Hello {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: 2,
            },
            config,
        ),
        Err(HandshakeError::AbiMismatch {
            plugin_abi: 2,
            host_abi: 1,
        })
    );
    assert_eq!(
        host_negotiate_handshake(
            PluginMsg::Hello {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: 1,
            },
            HostHandshakeConfig {
                slot_index: 2,
                ..config
            },
        ),
        Err(HandshakeError::InvalidSlot {
            slot_index: 2,
            node_count: 2,
        })
    );

    assert_host_stream_failure_does_not_write_ack(
        PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_MIN_VERSION - 1,
            abi_version: 1,
        },
        config,
    );
    assert_host_stream_failure_does_not_write_ack(
        PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 2,
        },
        config,
    );
    assert_host_stream_failure_does_not_write_ack(
        PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: 1,
        },
        HostHandshakeConfig {
            slot_index: 2,
            ..config
        },
    );
}

#[test]
fn plugin_rejects_invalid_hello_ack() {
    let config = PluginHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: 1,
    };

    assert_eq!(
        plugin_validate_handshake_ack(HostMsg::Quit, config),
        Err(HandshakeError::UnexpectedHostMessage {
            message: HostMsg::Quit,
        })
    );
    assert_eq!(
        plugin_validate_handshake_ack(
            HostMsg::HelloAck {
                proto_version: CONTROL_PROTOCOL_VERSION + 1,
                abi_version: 1,
                slot_index: 0,
                node_count: 2,
            },
            config,
        ),
        Err(HandshakeError::NegotiatedProtocolOutOfRange {
            negotiated: CONTROL_PROTOCOL_VERSION + 1,
            plugin_min: CONTROL_PROTOCOL_MIN_VERSION,
            plugin_max: CONTROL_PROTOCOL_VERSION,
        })
    );
    assert_eq!(
        plugin_validate_handshake_ack(
            HostMsg::HelloAck {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: 2,
                slot_index: 0,
                node_count: 2,
            },
            config,
        ),
        Err(HandshakeError::AbiMismatch {
            plugin_abi: 1,
            host_abi: 2,
        })
    );
    assert_eq!(
        plugin_validate_handshake_ack(
            HostMsg::HelloAck {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: 1,
                slot_index: 2,
                node_count: 2,
            },
            config,
        ),
        Err(HandshakeError::InvalidSlot {
            slot_index: 2,
            node_count: 2,
        })
    );
}

struct ScriptedIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    flush_count: usize,
}

impl ScriptedIo {
    fn from_input(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            flush_count: 0,
        }
    }

    fn written(&self) -> Vec<u8> {
        self.output.clone()
    }

    fn flush_count(&self) -> usize {
        self.flush_count
    }
}

impl Read for ScriptedIo {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

fn assert_host_stream_failure_does_not_write_ack(message: PluginMsg, config: HostHandshakeConfig) {
    let mut io = ScriptedIo::from_input(control_encode_plugin_msg(&message));
    assert!(host_accept_handshake(&mut io, config).is_err());
    assert_eq!(io.written(), Vec::<u8>::new());
    assert_eq!(io.flush_count(), 0);
}

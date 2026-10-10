//! Verifies immediate refusal of predecessor RAM control and shared-memory peers.
//!
//! These component tests exercise the public negotiation boundary. Packaged
//! worker, replay, and retained-process admission need independent VM evidence.

// crucible-lint: allow panic-shortcut -- negotiation fixture failures must stop the test before refusal assertions.
#![allow(clippy::expect_used)]
#![forbid(unsafe_code)]

use std::io::{self, Cursor, Read, Write};

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, HandshakeError, HostHandshakeConfig, HostMsg, PluginHandshakeConfig,
    PluginMsg, control_encode_host_msg, control_encode_plugin_msg, host_accept_handshake,
    plugin_start_handshake,
};

const CURRENT_SHMEM_ABI: u32 = 31;
const PREDECESSOR_CONTROL: u32 = 3;
const PREDECESSOR_SHMEM_ABI: u32 = 30;

struct Transcript {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Transcript {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }
}

impl Read for Transcript {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for Transcript {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn host_config() -> HostHandshakeConfig {
    assert_eq!(CONTROL_PROTOCOL_VERSION, 5);
    HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: CURRENT_SHMEM_ABI,
        slot_index: 0,
        node_count: 1,
    }
}

#[test]
fn current_ram_contract_peer_receives_exact_ack() {
    let config = host_config();
    let mut transcript = Transcript::new(control_encode_plugin_msg(&PluginMsg::Hello {
        proto_version: config.proto_version,
        abi_version: config.abi_version,
    }));

    let negotiated =
        host_accept_handshake(&mut transcript, config).expect("admit current host peer");

    assert_eq!(negotiated.proto_version, CONTROL_PROTOCOL_VERSION);
    assert_eq!(negotiated.abi_version, CURRENT_SHMEM_ABI);
    assert_eq!(
        transcript.output,
        control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: config.proto_version,
            abi_version: config.abi_version,
            slot_index: config.slot_index,
            node_count: config.node_count,
        })
    );
}

#[test]
fn predecessor_and_mixed_peers_are_rejected_without_ack() {
    let config = host_config();
    let predecessors = [
        (0, CURRENT_SHMEM_ABI),
        (1, CURRENT_SHMEM_ABI),
        (2, CURRENT_SHMEM_ABI),
        (PREDECESSOR_CONTROL, PREDECESSOR_SHMEM_ABI),
        (PREDECESSOR_CONTROL, CURRENT_SHMEM_ABI),
        (CONTROL_PROTOCOL_VERSION, PREDECESSOR_SHMEM_ABI),
        (u32::MAX, CURRENT_SHMEM_ABI),
        (CONTROL_PROTOCOL_VERSION, u32::MAX),
    ];

    for (protocol, abi) in predecessors {
        let mut transcript = Transcript::new(control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version: protocol,
            abi_version: abi,
        }));

        let result = host_accept_handshake(&mut transcript, config);

        assert!(result.is_err(), "admitted predecessor {protocol}/{abi}");
        assert!(transcript.output.is_empty(), "refusal published an ACK");
    }
}

#[test]
fn current_plugin_accepts_only_current_ack() {
    let config = host_config();
    let ack = HostMsg::HelloAck {
        proto_version: config.proto_version,
        abi_version: config.abi_version,
        slot_index: config.slot_index,
        node_count: config.node_count,
    };
    let mut transcript = Transcript::new(control_encode_host_msg(&ack));

    let negotiated = plugin_start_handshake(
        &mut transcript,
        PluginHandshakeConfig {
            proto_version: config.proto_version,
            abi_version: config.abi_version,
        },
    )
    .expect("admit current plugin acknowledgement");

    assert_eq!(negotiated.abi_version, CURRENT_SHMEM_ABI);
    assert_eq!(
        transcript.output,
        control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version: config.proto_version,
            abi_version: config.abi_version,
        })
    );
}

#[test]
fn predecessor_ack_cannot_authorize_setup() {
    let config = host_config();
    for (protocol, abi) in [
        (0, CURRENT_SHMEM_ABI),
        (1, CURRENT_SHMEM_ABI),
        (2, CURRENT_SHMEM_ABI),
        (PREDECESSOR_CONTROL, PREDECESSOR_SHMEM_ABI),
        (PREDECESSOR_CONTROL, CURRENT_SHMEM_ABI),
        (CONTROL_PROTOCOL_VERSION, PREDECESSOR_SHMEM_ABI),
        (u32::MAX, CURRENT_SHMEM_ABI),
        (CONTROL_PROTOCOL_VERSION, u32::MAX),
    ] {
        let mut transcript = Transcript::new(control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: protocol,
            abi_version: abi,
            slot_index: 0,
            node_count: 1,
        }));

        let result = plugin_start_handshake(
            &mut transcript,
            PluginHandshakeConfig {
                proto_version: config.proto_version,
                abi_version: config.abi_version,
            },
        );

        assert!(
            matches!(
                result,
                Err(HandshakeError::ProtocolVersionMismatch { .. })
                    | Err(HandshakeError::AbiMismatch { .. })
            ),
            "predecessor ACK {protocol}/{abi} admitted: {result:?}"
        );
        assert_eq!(
            transcript.output,
            control_encode_plugin_msg(&PluginMsg::Hello {
                proto_version: config.proto_version,
                abi_version: config.abi_version,
            })
        );
    }
}

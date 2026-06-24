//! Checks the frozen protocol golden-vector corpus.

#![forbid(unsafe_code)]

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlDirection, ControlGoldenVector, ControlGoldenVectorMessage,
    ControlTag, FRAME_LENGTH_PREFIX_SIZE, FRAME_TAG_SIZE, GOLDEN_CONTROL_VECTORS,
    GOLDEN_VECTOR_PROTOCOL_VERSION, GOLDEN_VECTOR_REGENERATION_RULE, HostMsg, PluginMsg,
    control_decode_host_msg, control_decode_plugin_msg, control_encode_host_msg,
    control_encode_plugin_msg,
};

#[test]
fn golden_vector_protocol_version_matches_current_protocol_version() {
    assert_eq!(GOLDEN_VECTOR_PROTOCOL_VERSION, CONTROL_PROTOCOL_VERSION);
    assert!(GOLDEN_VECTOR_REGENERATION_RULE.contains("CONTROL_PROTOCOL_VERSION"));
    for vector in GOLDEN_CONTROL_VECTORS {
        assert_eq!(vector.protocol_version, GOLDEN_VECTOR_PROTOCOL_VERSION);
    }
}

#[test]
fn golden_vectors_cover_required_protocol_messages_in_stable_order() {
    assert_eq!(
        GOLDEN_CONTROL_VECTORS.map(|vector| vector.name),
        ["hello", "hello-ack", "setup-payload", "setup-ack", "quit"],
    );
    assert_eq!(
        GOLDEN_CONTROL_VECTORS.map(|vector| (vector.direction, vector.tag)),
        [
            (ControlDirection::PluginToHost, ControlTag::Hello),
            (ControlDirection::HostToPlugin, ControlTag::HelloAck),
            (ControlDirection::HostToPlugin, ControlTag::Setup),
            (ControlDirection::PluginToHost, ControlTag::SetupAck),
            (ControlDirection::HostToPlugin, ControlTag::Quit),
        ],
    );
}

#[test]
fn golden_vectors_match_canonical_codec_bytes() {
    for vector in GOLDEN_CONTROL_VECTORS {
        assert_eq!(encode_vector(vector), vector.frame);
        assert_eq!(decode_vector(vector), vector.message);
    }
}

#[test]
fn golden_vectors_freeze_literal_wire_bytes() {
    assert_vector_bytes("hello", &[0, 0, 0, 9, 0xF0, 0, 0, 0, 1, 0, 0, 0, 1]);
    assert_vector_bytes(
        "hello-ack",
        &[
            0, 0, 0, 17, 0xF1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 32,
        ],
    );
    assert_vector_bytes(
        "setup-payload",
        &[0, 0, 0, 9, 0x01, 0, 0, 0, 0, 0, 6, 0xE0, 0],
    );
    assert_vector_bytes("setup-ack", &[0, 0, 0, 2, 0x02, 0]);
    assert_vector_bytes("quit", &[0, 0, 0, 1, 0x12]);
}

#[test]
fn setup_vector_freezes_payload_without_descriptor_sidecar() {
    let setup = vector_by_name("setup-payload");
    assert_eq!(
        setup.message,
        ControlGoldenVectorMessage::SetupPayload {
            region_len: 450_560,
        },
    );
    assert_eq!(
        &setup.frame[FRAME_LENGTH_PREFIX_SIZE + FRAME_TAG_SIZE..],
        &[0, 0, 0, 0, 0, 6, 0xE0, 0],
    );
}

fn encode_vector(vector: ControlGoldenVector) -> Vec<u8> {
    match vector.message {
        ControlGoldenVectorMessage::Hello {
            proto_version,
            abi_version,
        } => control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version,
            abi_version,
        }),
        ControlGoldenVectorMessage::SetupAck { status } => {
            control_encode_plugin_msg(&PluginMsg::SetupAck { status })
        }
        ControlGoldenVectorMessage::HelloAck {
            proto_version,
            abi_version,
            slot_index,
            node_count,
        } => control_encode_host_msg(&HostMsg::HelloAck {
            proto_version,
            abi_version,
            slot_index,
            node_count,
        }),
        ControlGoldenVectorMessage::SetupPayload { region_len } => {
            control_encode_host_msg(&HostMsg::Setup { region_len })
        }
        ControlGoldenVectorMessage::Quit => control_encode_host_msg(&HostMsg::Quit),
    }
}

fn decode_vector(vector: ControlGoldenVector) -> ControlGoldenVectorMessage {
    match vector.direction {
        ControlDirection::PluginToHost => match control_decode_plugin_msg(vector.frame) {
            Ok(PluginMsg::Hello {
                proto_version,
                abi_version,
            }) => ControlGoldenVectorMessage::Hello {
                proto_version,
                abi_version,
            },
            Ok(PluginMsg::SetupAck { status }) => ControlGoldenVectorMessage::SetupAck { status },
            Err(error) => panic!("plugin golden vector should decode: {error}"),
        },
        ControlDirection::HostToPlugin => match control_decode_host_msg(vector.frame) {
            Ok(HostMsg::HelloAck {
                proto_version,
                abi_version,
                slot_index,
                node_count,
            }) => ControlGoldenVectorMessage::HelloAck {
                proto_version,
                abi_version,
                slot_index,
                node_count,
            },
            Ok(HostMsg::Setup { region_len }) => {
                ControlGoldenVectorMessage::SetupPayload { region_len }
            }
            Ok(HostMsg::Quit) => ControlGoldenVectorMessage::Quit,
            Err(error) => panic!("host golden vector should decode: {error}"),
        },
    }
}

fn assert_vector_bytes(name: &str, expected: &[u8]) {
    let vector = vector_by_name(name);
    assert_eq!(vector.frame, expected);
}

fn vector_by_name(name: &str) -> ControlGoldenVector {
    for vector in GOLDEN_CONTROL_VECTORS {
        if vector.name == name {
            return vector;
        }
    }
    panic!("missing golden vector {name}");
}

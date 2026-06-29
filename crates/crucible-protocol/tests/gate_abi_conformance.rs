//! Checks protocol frame vectors for `gate:abi-conformance`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_protocol::{
    CODEC_FUZZ_REGRESSION_CORPUS, CONTROL_PROTOCOL_VERSION, ControlCodecFuzzCase,
    ControlCodecFuzzOutcome, ControlDirection, ControlGoldenVector, ControlGoldenVectorMessage,
    ControlTag, GOLDEN_CONTROL_VECTORS, GOLDEN_VECTOR_PROTOCOL_VERSION,
    GOLDEN_VECTOR_REGENERATION_RULE, HostMsg, PluginMsg, control_decode_host_msg,
    control_decode_plugin_msg, control_encode_host_msg, control_encode_plugin_msg,
    run_control_codec_fuzz_target,
};

#[test]
fn protocol_abi_conformance_runs_named_checks() {
    assert_frozen_golden_vectors();
    assert_decode_encode_roundtrip();
    assert_abi_version_field();
    assert_version_bump_regenerates_vectors();
    assert_structure_aware_fuzz_corpus();
    assert_protocol_codec_fuzz_corpus();
}

#[test]
fn protocol_golden_vector_versions_are_explicit() {
    assert_abi_version_field();
}

fn assert_abi_version_field() {
    assert_eq!(GOLDEN_VECTOR_PROTOCOL_VERSION, CONTROL_PROTOCOL_VERSION);
    assert!(GOLDEN_VECTOR_REGENERATION_RULE.contains("CONTROL_PROTOCOL_VERSION"));
    for vector in GOLDEN_CONTROL_VECTORS {
        assert_eq!(vector.protocol_version, GOLDEN_VECTOR_PROTOCOL_VERSION);
    }
}

#[test]
fn protocol_golden_vectors_cover_required_control_frames() {
    assert_frozen_golden_vectors();
}

fn assert_frozen_golden_vectors() {
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
fn protocol_golden_vectors_match_live_codec_bytes() {
    assert_decode_encode_roundtrip();
}

fn assert_decode_encode_roundtrip() {
    for vector in GOLDEN_CONTROL_VECTORS {
        assert_eq!(encode_vector(vector), vector.frame);
        assert_eq!(decode_vector(vector), vector.message);
    }
}

#[test]
fn protocol_golden_vectors_freeze_literal_frame_bytes() {
    assert_version_bump_regenerates_vectors();
}

fn assert_version_bump_regenerates_vectors() {
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
fn protocol_codec_fuzz_regression_corpus_is_clean_and_deterministic() {
    assert_structure_aware_fuzz_corpus();
    assert_protocol_codec_fuzz_corpus();
}

fn assert_structure_aware_fuzz_corpus() {
    for case in regression_corpus() {
        let outcome = assert_clean_reject_or_deterministic_decode(case.frame);
        match case.name {
            "well-formed-host-frame-in-plugin-decoder"
            | "well-formed-plugin-frame-in-host-decoder" => {
                assert!(outcome.tag.is_ok());
            }
            _ => {
                assert!(
                    outcome.plugin.is_err() || outcome.host.is_err() || outcome.tag.is_err(),
                    "adversarial corpus case `{}` must exercise a typed rejection",
                    case.name
                );
            }
        }
    }
}

fn assert_protocol_codec_fuzz_corpus() {
    let names = regression_corpus()
        .iter()
        .map(|case| case.name)
        .collect::<BTreeSet<_>>();
    for required in [
        "empty",
        "truncated-length-one-byte",
        "oversize-length",
        "unknown-tag",
        "hello-short-payload",
        "setup-ack-truncated-payload",
        "well-formed-host-frame-in-plugin-decoder",
    ] {
        assert!(
            names.contains(required),
            "protocol fuzz corpus missing `{required}`"
        );
    }
}

fn assert_clean_reject_or_deterministic_decode(frame: &[u8]) -> ControlCodecFuzzOutcome {
    let first = match catch_unwind(AssertUnwindSafe(|| run_control_codec_fuzz_target(frame))) {
        Ok(outcome) => outcome,
        Err(_) => panic!("protocol codec fuzz target panicked for frame {frame:?}"),
    };
    let second = run_control_codec_fuzz_target(frame);
    assert_eq!(first, second);
    first
}

fn regression_corpus() -> &'static [ControlCodecFuzzCase] {
    &CODEC_FUZZ_REGRESSION_CORPUS
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
    panic!("missing protocol golden vector {name}");
}

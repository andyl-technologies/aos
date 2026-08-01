//! Checks the structure-aware control-codec fuzz target.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_protocol::{
    CODEC_FUZZ_REGRESSION_CORPUS, ControlCodecFuzzOutcome, ControlDirection, ControlTag,
    FRAME_LENGTH_PREFIX_SIZE, HostMsg, MAX_FRAME_SIZE, PluginMsg, TAG_HELLO, TAG_HELLO_ACK,
    TAG_QUIT, TAG_SETUP, TAG_SETUP_ACK, control_decode_host_msg, control_decode_plugin_msg,
    control_encode_host_msg, control_encode_plugin_msg, run_control_codec_fuzz_target,
};

#[test]
fn seeded_regression_corpus_exercises_malformed_and_adversarial_frames() {
    assert!(CODEC_FUZZ_REGRESSION_CORPUS.len() >= 13);
    assert!(corpus_contains("empty"));
    assert!(corpus_contains("truncated-length-one-byte"));
    assert!(corpus_contains("oversize-length"));
    assert!(corpus_contains("unknown-tag"));
    assert!(corpus_contains("hello-short-payload"));
    assert!(corpus_contains("hello-long-payload"));
    assert!(corpus_contains("setup-ack-truncated-payload"));
    assert!(corpus_contains("max-sized-quit-long-payload"));
}

#[test]
fn fuzz_target_never_panics_on_regression_corpus() {
    for case in CODEC_FUZZ_REGRESSION_CORPUS {
        let outcome = run_without_panic(case.frame);
        assert!(
            outcome.plugin.is_err() || outcome.host.is_err() || outcome.tag.is_err(),
            "regression case {} should exercise an error path",
            case.name,
        );
    }
}

#[test]
fn structure_aware_malformed_frames_never_panic() {
    for tag in [
        ControlTag::Setup,
        ControlTag::SetupAck,
        ControlTag::Quit,
        ControlTag::Hello,
        ControlTag::HelloAck,
    ] {
        for payload_len in structural_payload_lengths(tag) {
            let frame = structured_frame(tag.wire_value(), payload_len);
            let outcome = run_without_panic(&frame);
            if payload_len != tag.payload_len() {
                assert!(outcome.plugin.is_err() || outcome.host.is_err());
            }
        }
    }

    for tag in [0, 0x03, 0x11, 0x13, 0xEF, 0xF2, u8::MAX] {
        let frame = structured_frame(tag, 0);
        let outcome = run_without_panic(&frame);
        assert!(outcome.plugin.is_err());
        assert!(outcome.host.is_err());
        assert!(outcome.tag.is_err());
    }
}

#[test]
fn structure_aware_directional_adversarial_frames_remain_typed_errors() {
    let host_frame = control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: 1,
        abi_version: 1,
        slot_index: 0,
        node_count: 1,
    });
    let host_outcome = run_without_panic(&host_frame);
    assert!(host_outcome.host.is_ok());
    assert!(host_outcome.plugin.is_err());

    let plugin_frame = control_encode_plugin_msg(&PluginMsg::Hello {
        proto_version: 1,
        abi_version: 1,
    });
    let plugin_outcome = run_without_panic(&plugin_frame);
    assert!(plugin_outcome.plugin.is_ok());
    assert!(plugin_outcome.host.is_err());
}

#[test]
fn well_formed_generated_messages_round_trip() {
    for message in generated_plugin_messages() {
        let frame = control_encode_plugin_msg(&message);
        assert_eq!(control_decode_plugin_msg(&frame), Ok(message.clone()));
        let outcome = run_without_panic(&frame);
        assert_eq!(outcome.plugin, Ok(message));
    }

    for message in generated_host_messages() {
        let frame = control_encode_host_msg(&message);
        assert_eq!(control_decode_host_msg(&frame), Ok(message.clone()));
        let outcome = run_without_panic(&frame);
        assert_eq!(outcome.host, Ok(message));
    }
}

#[test]
fn generated_truncations_and_trailing_bytes_stay_typed() {
    for frame in well_formed_frames() {
        for len in 0..frame.len() {
            let truncated = &frame[..len];
            let outcome = run_without_panic(truncated);
            assert!(
                outcome.plugin.is_err() || outcome.host.is_err() || outcome.tag.is_err(),
                "truncated frame should not decode cleanly: {truncated:?}",
            );
        }

        let mut trailing = frame.clone();
        trailing.push(0xA5);
        let outcome = run_without_panic(&trailing);
        assert!(outcome.plugin.is_err() || outcome.host.is_err());
    }
}

fn corpus_contains(name: &str) -> bool {
    CODEC_FUZZ_REGRESSION_CORPUS
        .iter()
        .any(|case| case.name == name)
}

fn run_without_panic(frame: &[u8]) -> ControlCodecFuzzOutcome {
    match catch_unwind(AssertUnwindSafe(|| run_control_codec_fuzz_target(frame))) {
        Ok(outcome) => outcome,
        Err(_) => panic!("codec fuzz target panicked for frame {frame:?}"),
    }
}

fn structural_payload_lengths(tag: ControlTag) -> Vec<usize> {
    let mut lengths = vec![0, tag.payload_len(), MAX_FRAME_SIZE as usize - 1];
    if tag.payload_len() > 0 {
        lengths.push(tag.payload_len() - 1);
    }
    if FRAME_LENGTH_PREFIX_SIZE + tag.payload_len() < MAX_FRAME_SIZE as usize {
        lengths.push(tag.payload_len() + 1);
    }
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

fn structured_frame(tag: u8, payload_len: usize) -> Vec<u8> {
    let declared_len = 1 + payload_len;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_SIZE + declared_len);
    frame.extend_from_slice(&(declared_len as u32).to_be_bytes());
    frame.push(tag);
    for index in 0..payload_len {
        frame.push((index & 0xFF) as u8);
    }
    frame
}

fn generated_plugin_messages() -> Vec<PluginMsg> {
    vec![
        PluginMsg::Hello {
            proto_version: 0,
            abi_version: 0,
        },
        PluginMsg::Hello {
            proto_version: 1,
            abi_version: 1,
        },
        PluginMsg::Hello {
            proto_version: u32::MAX,
            abi_version: u32::MAX,
        },
        PluginMsg::SetupAck { status: 0 },
        PluginMsg::SetupAck { status: 1 },
        PluginMsg::SetupAck { status: u8::MAX },
    ]
}

fn generated_host_messages() -> Vec<HostMsg> {
    vec![
        HostMsg::HelloAck {
            proto_version: 0,
            abi_version: 0,
            slot_index: 0,
            node_count: 0,
        },
        HostMsg::HelloAck {
            proto_version: 1,
            abi_version: 1,
            slot_index: 7,
            node_count: 32,
        },
        HostMsg::HelloAck {
            proto_version: u32::MAX,
            abi_version: u32::MAX,
            slot_index: u32::MAX,
            node_count: u32::MAX,
        },
        HostMsg::Setup { region_len: 0 },
        HostMsg::Setup {
            region_len: 450_560,
        },
        HostMsg::Setup {
            region_len: u64::MAX,
        },
        HostMsg::Quit,
    ]
}

fn well_formed_frames() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for message in generated_plugin_messages() {
        frames.push(control_encode_plugin_msg(&message));
    }
    for message in generated_host_messages() {
        frames.push(control_encode_host_msg(&message));
    }
    frames
}

#[test]
fn tag_constants_are_covered_by_structure_aware_fuzz_generation() {
    assert_eq!(structured_frame(TAG_SETUP, 8)[4], TAG_SETUP);
    assert_eq!(structured_frame(TAG_SETUP_ACK, 1)[4], TAG_SETUP_ACK);
    assert_eq!(structured_frame(TAG_QUIT, 0)[4], TAG_QUIT);
    assert_eq!(structured_frame(TAG_HELLO, 8)[4], TAG_HELLO);
    assert_eq!(structured_frame(TAG_HELLO_ACK, 16)[4], TAG_HELLO_ACK);
}

#[test]
fn fuzz_target_reports_directional_success_only_for_registered_direction() {
    for tag in [
        ControlTag::Setup,
        ControlTag::SetupAck,
        ControlTag::Quit,
        ControlTag::Hello,
        ControlTag::HelloAck,
    ] {
        let frame = structured_frame(tag.wire_value(), tag.payload_len());
        let outcome = run_without_panic(&frame);
        match tag.direction() {
            ControlDirection::HostToPlugin => {
                assert!(outcome.host.is_ok());
                assert!(outcome.plugin.is_err());
            }
            ControlDirection::PluginToHost => {
                assert!(outcome.plugin.is_ok());
                assert!(outcome.host.is_err());
            }
        }
    }
}

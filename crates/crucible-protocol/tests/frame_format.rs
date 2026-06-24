//! Checks the protocol frame-format constants and closed tag registry.

#![forbid(unsafe_code)]

use crucible_protocol::{
    ALL_CONTROL_TAGS, ControlDirection, ControlTag, FRAME_INTEGERS_ARE_BIG_ENDIAN,
    FRAME_LENGTH_INCLUDES_TAG, FRAME_LENGTH_PREFIX_SIZE, FRAME_TAG_SIZE, MAX_FRAME_SIZE,
    MAX_PAYLOAD_SIZE, TAG_HELLO, TAG_HELLO_ACK, TAG_QUIT, TAG_SETUP, TAG_SETUP_ACK,
};

#[test]
fn frame_format_uses_big_endian_length_tag_and_payload() {
    const {
        assert!(FRAME_LENGTH_PREFIX_SIZE == 4);
        assert!(FRAME_TAG_SIZE == 1);
        assert!(MAX_FRAME_SIZE == 64);
        assert!(MAX_PAYLOAD_SIZE == 63);
        assert!(FRAME_LENGTH_INCLUDES_TAG);
        assert!(FRAME_INTEGERS_ARE_BIG_ENDIAN);
    }
}

#[test]
fn closed_tag_registry_matches_rfc_14_table() {
    assert_eq!(
        ALL_CONTROL_TAGS,
        [
            ControlTag::Setup,
            ControlTag::SetupAck,
            ControlTag::Quit,
            ControlTag::Hello,
            ControlTag::HelloAck,
        ]
    );
    assert_eq!(TAG_SETUP, 0x01);
    assert_eq!(TAG_SETUP_ACK, 0x02);
    assert_eq!(TAG_QUIT, 0x12);
    assert_eq!(TAG_HELLO, 0xF0);
    assert_eq!(TAG_HELLO_ACK, 0xF1);
}

#[test]
fn closed_tag_registry_rejects_unregistered_wire_values() {
    for tag in ALL_CONTROL_TAGS {
        assert_eq!(ControlTag::from_wire_value(tag.wire_value()), Some(tag));
    }

    for value in [0x00, 0x03, 0x11, 0x13, 0xEF, 0xF2, u8::MAX] {
        assert_eq!(ControlTag::from_wire_value(value), None);
    }
}

#[test]
fn tag_directions_and_payload_lengths_match_control_lifecycle() {
    let expected = [
        (ControlTag::Setup, ControlDirection::HostToPlugin, 8),
        (ControlTag::SetupAck, ControlDirection::PluginToHost, 1),
        (ControlTag::Quit, ControlDirection::HostToPlugin, 0),
        (ControlTag::Hello, ControlDirection::PluginToHost, 8),
        (ControlTag::HelloAck, ControlDirection::HostToPlugin, 16),
    ];

    for (tag, direction, payload_len) in expected {
        assert_eq!(tag.direction(), direction);
        assert_eq!(tag.payload_len(), payload_len);
        assert!(FRAME_TAG_SIZE + tag.payload_len() <= MAX_FRAME_SIZE as usize);
    }
}

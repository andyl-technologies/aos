//! Checks profile data compatibility and finite independent limits.

#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn compact_profile_roundtrip_is_closed_and_independent() {
    let selected = PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: U64::new(1024),
        native_after_protocol_bytes: U64::new(4096),
        host_protocol_bytes: U64::new(16384),
    };
    selected.validate().unwrap();
    let value = serde_json::to_value(&selected).unwrap();
    let decoded: PacketNative5CaptureProfile = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(decoded, selected);

    let mut foreign = value;
    foreign
        .as_object_mut()
        .unwrap()
        .insert("permission".into(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<PacketNative5CaptureProfile>(foreign).is_err());
}

#[test]
fn compact_profile_refuses_zero_and_overwide_selected_bounds() {
    for bounds in [
        [0, 1, 1],
        [1, 0, 1],
        [1, 1, 0],
        [512 * 1024 * 1024 + 1, 1, 1],
    ] {
        let selected = PacketNative5CaptureProfile::CompactBytes7 {
            native_before_protocol_bytes: U64::new(bounds[0]),
            native_after_protocol_bytes: U64::new(bounds[1]),
            host_protocol_bytes: U64::new(bounds[2]),
        };
        assert!(selected.validate().is_err());
    }
    assert_eq!(
        PacketNative5CaptureProfile::default(),
        PacketNative5CaptureProfile::OriginalArrays6
    );
    PacketNative5CaptureProfile::default().validate().unwrap();
}

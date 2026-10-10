//! Literal CCRC1 compatibility across the neutral and original source paths.

// crucible-lint: allow panic-shortcut -- literal compatibility fixtures localize codec failures.
#![allow(clippy::expect_used)]

use super::GuardedCampaignReplayClosure;
use crate::qemu_campaign_lifecycle as legacy;

#[test]
fn original_empty_wire_bytes_remain_exact() {
    let bytes = b"CCRC\0\0\0\x01\0\0\0\0";
    let neutral = GuardedCampaignReplayClosure::from_canonical_bytes(bytes).expect("neutral empty");
    let old =
        legacy::GuardedCampaignReplayClosure::from_canonical_bytes(bytes).expect("old path empty");

    assert_eq!(neutral, old);
    assert_eq!(
        neutral.to_canonical_bytes().expect("canonical empty"),
        bytes
    );
    assert_eq!(GuardedCampaignReplayClosure::SCHEMA_VERSION, 1);
}

#[test]
fn original_closed_wire_errors_remain_exact() {
    let cases: &[(&[u8], &str)] = &[
        (b"not-CCRC", "replay closure has an invalid header"),
        (b"CCRC\0\0\0\x01", "replay closure is truncated"),
        (
            b"CCRC\0\0\0\x01\x01\0\x01\0",
            "selection count exceeds the replay-closure bound",
        ),
        (
            b"CCRC\0\0\0\x01\0\0\0\0x",
            "replay closure has trailing bytes",
        ),
        (b"CCRC\0\0\0\x01\x01\0\0\0", "replay closure is truncated"),
    ];

    for (bytes, reason) in cases {
        let expected = format!("campaign replay closure is invalid: {reason}");
        assert_eq!(
            GuardedCampaignReplayClosure::from_canonical_bytes(bytes)
                .expect_err("neutral refusal")
                .to_string(),
            expected
        );
        assert_eq!(
            legacy::GuardedCampaignReplayClosure::from_canonical_bytes(bytes)
                .expect_err("legacy refusal")
                .to_string(),
            expected
        );
    }
}

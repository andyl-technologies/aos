//! Independent fixed byte controls for standing observations, never issuance.

use super::*;

fn payload() -> [u8; 1496] {
    let mut bytes = [0; 1496];
    bytes[..8].copy_from_slice(b"CRUCSRV4");
    bytes[8..12].copy_from_slice(&4_u32.to_be_bytes());
    bytes[12..16].copy_from_slice(&1496_u32.to_be_bytes());
    bytes[16..48].fill(7);
    bytes[88..120].fill(7);
    bytes[120..152].fill(11);
    bytes[200..232].fill(5);
    for (offset, value) in [(48, 17_u64), (72, 9), (80, 3), (160, 1), (168, 2), (176, 1)] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes[192..196].copy_from_slice(&256_u32.to_be_bytes());
    bytes[196..200].copy_from_slice(&1_u32.to_be_bytes());
    bytes[232..236].copy_from_slice(&11_u32.to_be_bytes());
    for index in 0..14 {
        let offset = 236 + index * 18;
        bytes[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        bytes[offset + 9] = 1;
        bytes[offset + 10..offset + 18].copy_from_slice(&500_000_u64.to_be_bytes());
    }
    bytes
}

#[test]
fn predecessor_source_cannot_supply_a_typed_park_lender() {
    let mut bytes = payload();
    bytes[..8].copy_from_slice(b"CRUCSRV2");
    bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());

    assert!(decode_source_supervision_payload(&bytes).is_err());
}

#[test]
fn independent_source_observation_preserves_submillisecond_timing_and_raw_event_zero() {
    let observed = decode_source_supervision_payload(&payload()).unwrap();

    assert_eq!(observed.producer_retention_edition, 1);
    assert_eq!(observed.cancellation[2], 1);
    assert_eq!(observed.budgets[5].poll_ns, 1);
    assert_eq!(observed.budgets[5].total_ns, Some(500_000));
    assert_eq!(observed.allowance_ns, None);
    assert_eq!(observed.original_monotonic_ns, 17);
}

#[test]
fn live_policy_update_keeps_original_identity_and_accepts_new_revision() {
    let initial = decode_source_supervision_payload(&payload()).unwrap();
    let mut live = initial;
    live.roster_revision = 1;
    live.budgets[5].total_ns = Some(700_000);
    live.outer_revision = 1;
    live.allowance_ns = Some(10_000_000);

    assert_eq!(validate_source_supervision_update(&initial, &live), Ok(()));
    assert_eq!(live.original_monotonic_ns, initial.original_monotonic_ns);
}

#[test]
fn changed_identity_regressed_revision_or_unrevised_policy_refuses() {
    let initial = decode_source_supervision_payload(&payload()).unwrap();
    for field in 0..7 {
        let mut live = initial;
        match field {
            0 => live.cap[0] ^= 1,
            1 => live.original_monotonic_ns += 1,
            2 => live.reservation[0] ^= 1,
            3 => live.artifact[0] ^= 1,
            4 => live.cancellation[2] += 1,
            5 => live.budgets[5].total_ns = Some(1),
            _ => live.allowance_ns = Some(1),
        }
        assert!(validate_source_supervision_update(&initial, &live).is_err());
    }
    let mut revised = initial;
    revised.roster_revision = 2;
    assert!(validate_source_supervision_update(&revised, &initial).is_err());
}

#[test]
fn standing_decoder_refuses_predecessor_rosters_and_noncanonical_header_padding() {
    for offset in [8, 12, 64, 65, 66, 196, 599] {
        let mut bytes = payload();
        bytes[offset] = 0xff;
        assert!(
            decode_source_supervision_payload(&bytes).is_err(),
            "offset {offset}"
        );
    }
    for version in [9_u32, 10] {
        let mut bytes = payload();
        bytes[232..236].copy_from_slice(&version.to_be_bytes());
        assert!(decode_source_supervision_payload(&bytes).is_err());
    }
}

#[test]
fn event_identity_and_optional_allowance_bounds_are_explicit() {
    for token in [0, i32::MAX as u64 + 2] {
        let mut bytes = payload();
        bytes[176..184].copy_from_slice(&token.to_be_bytes());
        assert!(decode_source_supervision_payload(&bytes).is_err());
    }
    let mut bytes = payload();
    bytes[176..184].copy_from_slice(&(i32::MAX as u64 + 1).to_be_bytes());
    assert!(decode_source_supervision_payload(&bytes).is_ok());
    bytes[64] = 1;
    assert!(decode_source_supervision_payload(&bytes).is_err());
    bytes[184..192].copy_from_slice(&1_u64.to_be_bytes());
    assert!(decode_source_supervision_payload(&bytes).is_ok());
    bytes[184..192].copy_from_slice(&(i64::MAX as u64 + 1).to_be_bytes());
    assert!(decode_source_supervision_payload(&bytes).is_err());
}

#[test]
fn terminal_state_cannot_be_cleared_by_a_new_policy_revision() {
    let mut initial = decode_source_supervision_payload(&payload()).unwrap();
    initial.state = 3;
    let mut live = initial;
    live.roster_revision += 1;
    live.outer_revision += 1;
    live.state = 0;

    assert!(validate_source_supervision_update(&initial, &live).is_err());
}

#[test]
fn predecessor_or_mixed_source_editions_never_imply_producer_retention() {
    for (magic, schema) in [(b"CRUCSRV3", 3_u32), (b"CRUCSRV3", 4), (b"CRUCSRV4", 3)] {
        let mut bytes = payload();
        bytes[..8].copy_from_slice(magic);
        bytes[8..12].copy_from_slice(&schema.to_be_bytes());

        assert!(decode_source_supervision_payload(&bytes).is_err());
    }
}

#[test]
fn missing_or_unknown_producer_retention_promise_refuses_before_observation() {
    for edition in [0_u32, 2, u32::MAX] {
        let mut bytes = payload();
        bytes[196..200].copy_from_slice(&edition.to_be_bytes());

        assert!(decode_source_supervision_payload(&bytes).is_err());
    }
}

#[test]
fn live_or_initial_unknown_retention_cannot_be_validated_by_equal_identity() {
    let initial = decode_source_supervision_payload(&payload()).unwrap();
    for edition in [0_u32, 2, u32::MAX] {
        let mut changed = initial;
        changed.producer_retention_edition = edition;

        assert!(validate_source_supervision_update(&initial, &changed).is_err());
        assert!(validate_source_supervision_update(&changed, &initial).is_err());
        assert!(validate_source_supervision_update(&changed, &changed).is_err());
    }
}

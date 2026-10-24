//! Checks matched publisher plan editions and cross-purpose correspondence.

use super::*;
use crate::publisher_subscription::PublisherPurpose;

fn parts() -> (PluginSetupPlan, [u8; PURPOSE], PublisherPurpose) {
    let bytes = selected();
    let purpose: [u8; PURPOSE] = bytes[bytes.len() - PURPOSE..].try_into().unwrap();
    let startup_start = bytes.len() - PURPOSE - STARTUP_OPERATION_BYTES;
    let startup =
        StartupOperation::decode(&bytes[startup_start..startup_start + STARTUP_OPERATION_BYTES])
            .unwrap();
    let (app, selectable) = PluginSetupPlan::decode_preexec_parts(&bytes).unwrap();
    let plan = PluginSetupPlan::new(app, selectable).with_startup_operation(startup);
    let publisher = PublisherPurpose {
        lender_generation: 17,
        account_generation: 9,
        process_generation: 3,
        capability: [7; 32],
        reservation: purpose[816..848].try_into().unwrap(),
        device: 0,
        inode: 0,
        producer_event: 19,
        receiver_event: 23,
        backing_bytes: 4096,
    };

    (plan, purpose, publisher)
}

#[test]
fn publisher_plan_preserves_exact_legacy_body_and_uses_distinct_edition() {
    let (plan, purpose, publisher) = parts();
    let ordinary = plan.encode_preexec(&purpose, None).unwrap();
    let bytes = plan
        .encode_preexec_publisher(&purpose, None, &publisher)
        .unwrap();

    assert_eq!(ordinary, selected());
    assert_eq!(&bytes[..16], b"CRUCSUP9\0\0\0\x09\0\0\0\x30");
    assert_eq!(&bytes[40..48], b"\0\0\0\xe0\0\0\0\0");
    assert_eq!(&bytes[48..bytes.len() - 224], &ordinary[40..]);
    assert_eq!(bytes.len(), ordinary.len() + 232);
    assert_eq!(
        plan.preexec_publisher_encoded_len(false).unwrap(),
        bytes.len()
    );
    assert_eq!(
        PluginSetupPlan::decode_preexec_publisher_parts(&bytes).unwrap(),
        (
            plan.app_random_branch_plan.clone(),
            plan.selectable_catalog_plan.clone(),
            publisher
        )
    );
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&ordinary).is_err());
    assert!(PluginSetupPlan::decode(&bytes).is_err());
}

#[test]
fn publisher_plan_refuses_every_truncation_header_mismatch_and_trailing_byte() {
    let (plan, purpose, publisher) = parts();
    let original = plan
        .encode_preexec_publisher(&purpose, None, &publisher)
        .unwrap();

    for length in 0..original.len() {
        assert!(PluginSetupPlan::decode_preexec_publisher_parts(&original[..length]).is_err());
    }
    for offset in 0..48 {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err(),
            "offset {offset}"
        );
    }
    let mut bytes = original;
    bytes.push(0);
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
}

#[test]
fn publisher_plan_refuses_each_independent_process_identity_mismatch() {
    let (plan, purpose, publisher) = parts();
    let original = plan
        .encode_preexec_publisher(&purpose, None, &publisher)
        .unwrap();
    let start = original.len() - 224;

    for offset in [24, 32, 40, 72] {
        let mut bytes = original.clone();
        bytes[start + offset + 7] ^= 1;
        assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    }
    let mut changed = publisher;
    changed.account_generation += 1;
    assert!(
        plan.encode_preexec_publisher(&purpose, None, &changed)
            .is_err()
    );
    let mut changed = publisher;
    changed.process_generation += 1;
    assert!(
        plan.encode_preexec_publisher(&purpose, None, &changed)
            .is_err()
    );
    let mut changed = publisher;
    changed.capability[0] ^= 1;
    assert!(
        plan.encode_preexec_publisher(&purpose, None, &changed)
            .is_err()
    );
    let mut changed = publisher;
    changed.reservation[0] ^= 1;
    assert!(
        plan.encode_preexec_publisher(&purpose, None, &changed)
            .is_err()
    );
}

#[test]
fn publisher_plan_keeps_workspace_before_startup_and_binds_its_original() {
    let (plan, purpose, publisher) = parts();
    let mut workspace = [0; DEVICE_DIGEST_PURPOSE_BYTES];
    workspace[..8].copy_from_slice(b"CRUCWSP2");
    workspace[8..12].copy_from_slice(&2_u32.to_be_bytes());
    workspace[12..16].copy_from_slice(&1_u32.to_be_bytes());
    for (destination, source, length) in [(16, 184, 32), (48, 16, 8), (72, 96, 8), (80, 88, 8)] {
        workspace[destination..destination + length]
            .copy_from_slice(&purpose[source..source + length]);
    }
    for offset in [64, 120] {
        workspace[offset..offset + 8]
            .copy_from_slice(&crate::DEVICE_DIGEST_WORKSPACE_BYTES.to_be_bytes());
    }
    let ordinary = plan.encode_preexec(&purpose, Some(&workspace)).unwrap();
    let bytes = plan
        .encode_preexec_publisher(&purpose, Some(&workspace), &publisher)
        .unwrap();

    assert_eq!(
        plan.preexec_publisher_encoded_len(true).unwrap(),
        bytes.len()
    );
    assert_eq!(&bytes[48..bytes.len() - 224], &ordinary[40..]);
    assert_eq!(
        PluginSetupPlan::decode_preexec_publisher_parts(&bytes)
            .unwrap()
            .2,
        publisher
    );

    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_publisher(&purpose, Some(&workspace), &publisher)
            .is_err()
    );
    let app_len = u32::from_be_bytes(bytes[20..24].try_into().unwrap()) as usize;
    let selectable_len = u32::from_be_bytes(bytes[24..28].try_into().unwrap()) as usize;
    let mut changed = bytes;
    changed[48 + app_len + selectable_len + 80] ^= 1;
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&changed).is_err());
}

#[test]
fn publisher_plan_extension_stays_inside_existing_aggregate_cap() {
    let maximum = PLUGIN_SETUP_PLAN_MAX_BYTES;

    assert_eq!(
        super::super::super::publisher::with_publisher_extent(maximum - 232, true).unwrap(),
        maximum
    );
    assert!(super::super::super::publisher::with_publisher_extent(maximum - 231, true).is_err());
    assert!(super::super::super::publisher::with_publisher_extent(usize::MAX, true).is_err());
}

//! Checks the distinct plan-ten carrier without creating a sealed role owner.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

mod stacks;
use crate::publisher_subscription::{PublisherPurpose, quantum::QuantumPublisherPurpose};

fn selected_quantum() -> Vec<u8> {
    let mut ordinary = selected();
    let purpose_start = ordinary.len() - PURPOSE;
    let process = &ordinary[purpose_start..];
    let subscription = QuantumPublisherPurpose {
        session: PublisherPurpose {
            lender_generation: 3,
            account_generation: read_u64(process, 88).unwrap(),
            process_generation: read_u64(process, 96).unwrap(),
            capability: process[184..216].try_into().unwrap(),
            reservation: process[816..848].try_into().unwrap(),
            device: 0,
            inode: 0,
            producer_event: 11,
            receiver_event: 13,
            backing_bytes: 4096,
        },
    };
    ordinary.splice(40..40, [0, 0, 0, 224, 0, 0, 0, 0]);
    ordinary.extend_from_slice(&subscription.encode().unwrap());
    ordinary[..8].copy_from_slice(b"CRUCSU10");
    ordinary[8..12].copy_from_slice(&10_u32.to_be_bytes());
    ordinary[12..16].copy_from_slice(&48_u32.to_be_bytes());
    let length = ordinary.len() as u32;
    ordinary[16..20].copy_from_slice(&length.to_be_bytes());
    ordinary
}

#[test]
fn quantum_plan_matches_literal_header_and_round_trips_through_public_api() {
    let bytes = selected_quantum();
    let (app, selectable, publisher) =
        PluginSetupPlan::decode_preexec_quantum_parts(&bytes).unwrap();
    let purpose_start = bytes.len() - 224 - PURPOSE;
    let startup_start = purpose_start - STARTUP_OPERATION_BYTES;
    let startup = StartupOperation::decode(&bytes[startup_start..purpose_start]).unwrap();
    let plan = PluginSetupPlan::new(app, selectable).with_startup_operation(startup);

    assert_eq!(&bytes[..16], b"CRUCSU10\0\0\0\x0a\0\0\0\x30");
    assert_eq!(&bytes[40..48], &[0, 0, 0, 224, 0, 0, 0, 0]);
    assert_eq!(
        plan.preexec_publisher_encoded_len(false).unwrap(),
        bytes.len()
    );
    assert_eq!(
        plan.encode_preexec_quantum(
            bytes[purpose_start..purpose_start + PURPOSE]
                .try_into()
                .unwrap(),
            None,
            &publisher
        )
        .unwrap(),
        bytes
    );
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&selected()).is_err());
}

#[test]
fn quantum_plan_refuses_mixed_editions_lengths_and_changed_parent_binding() {
    let bytes = selected_quantum();
    let tail = bytes.len() - 224;

    for offset in (0..48)
        .chain(tail..tail + 16)
        .chain(tail + 192..bytes.len())
    {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_quantum_parts(&changed).is_err(),
            "offset {offset}"
        );
    }
    for offset in [24, 32, 40, 72] {
        let mut changed = bytes.clone();
        changed[tail + offset + 7] ^= 1;
        assert!(PluginSetupPlan::decode_preexec_quantum_parts(&changed).is_err());
    }
    for length in 0..bytes.len() {
        assert!(PluginSetupPlan::decode_preexec_quantum_parts(&bytes[..length]).is_err());
    }
    assert!(
        PluginSetupPlan::decode_preexec_quantum_parts(&[bytes.as_slice(), &[0]].concat()).is_err()
    );
}

#[test]
fn quantum_plan_keeps_workspace_order_and_checks_the_same_original() {
    let bytes = selected_quantum();
    let (app, selectable, publisher) =
        PluginSetupPlan::decode_preexec_quantum_parts(&bytes).unwrap();
    let purpose_start = bytes.len() - 224 - PURPOSE;
    let purpose: &[u8; PURPOSE] = bytes[purpose_start..purpose_start + PURPOSE]
        .try_into()
        .unwrap();
    let startup =
        StartupOperation::decode(&bytes[purpose_start - STARTUP_OPERATION_BYTES..purpose_start])
            .unwrap();
    let plan = PluginSetupPlan::new(app, selectable).with_startup_operation(startup);
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

    let encoded = plan
        .encode_preexec_quantum(purpose, Some(&workspace), &publisher)
        .unwrap();
    assert_eq!(
        encoded.len(),
        plan.preexec_publisher_encoded_len(true).unwrap()
    );
    assert_eq!(encoded.len(), bytes.len() + DEVICE_DIGEST_PURPOSE_BYTES);
    assert_eq!(
        PluginSetupPlan::decode_preexec_quantum_parts(&encoded)
            .unwrap()
            .2,
        publisher
    );
    let app_len = read_u32(&encoded, 20).unwrap() as usize;
    let selectable_len = read_u32(&encoded, 24).unwrap() as usize;
    let workspace_start = 48 + app_len + selectable_len;
    assert_eq!(
        &encoded[workspace_start..workspace_start + DEVICE_DIGEST_PURPOSE_BYTES],
        &workspace
    );

    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_quantum(purpose, Some(&workspace), &publisher)
            .is_err()
    );
    let mut changed = encoded;
    changed[workspace_start + 80] ^= 1;
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&changed).is_err());
}

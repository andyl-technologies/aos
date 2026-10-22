//! Checks exact plan-twelve framing and independent Source parent correlations.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::deferred_cleanup::{
    DeferredCleanupDelegation, DeferredCleanupIdentity, DeferredCleanupOuterPolicy,
    DeferredCleanupPurpose,
};
use crate::publisher_subscription::PublisherPurpose;

fn parts() -> (PluginSetupPlan, [u8; PURPOSE], DeferredCleanupPurpose) {
    let (plan, purpose) = issued_fixture_plan();
    let owner = |byte| DeferredCleanupIdentity {
        identity: [byte; 32],
        incarnation: 1,
    };
    let publisher = PublisherPurpose {
        lender_generation: 1,
        account_generation: 9,
        process_generation: 3,
        capability: [7; 32],
        reservation: [11; 32],
        device: 0,
        inode: 0,
        producer_event: 19,
        receiver_event: 23,
        backing_bytes: 4096,
    };
    let delegation = DeferredCleanupDelegation {
        source_capability: publisher.capability,
        source_reservation: publisher.reservation,
        account_incarnation: publisher.account_generation,
        process_incarnation: publisher.process_generation,
        source_issuer_incarnation: 9,
        carrier: owner(21),
        carrier_device: 0,
        carrier_inode: 0,
        carrier_extent: 4096,
        outer_policy: DeferredCleanupOuterPolicy::NoEndpoint,
        clock_domain: [22; 32],
        maximum_duration_ns: 1000,
        maximum_units: 5,
        outer: owner(23),
        resource: DeferredCleanupIdentity {
            identity: publisher.reservation,
            incarnation: publisher.process_generation,
        },
        recipient: owner(24),
        profile: [25; 32],
        physical_extent: 8192,
        issuer: owner(26),
    };
    (
        plan,
        purpose,
        DeferredCleanupPurpose {
            publisher,
            delegation,
        },
    )
}

#[test]
fn dormant_plan_preserves_body_and_refuses_every_other_selected_edition() {
    let (plan, process, purpose) = parts();
    let ordinary = plan.encode_preexec(&process, None).unwrap();
    let bytes = plan
        .encode_preexec_deferred_cleanup(&process, None, &purpose)
        .unwrap();
    let decoded = PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&bytes).unwrap();

    assert_eq!(&bytes[..16], b"CRUCSU12\0\0\0\x0c\0\0\0\x30");
    assert_eq!(&bytes[40..48], &[0, 0, 2, 224, 0, 0, 0, 0]);
    assert_eq!(&bytes[48..bytes.len() - 736], &ordinary[40..]);
    assert_eq!(
        bytes.len(),
        plan.preexec_deferred_cleanup_encoded_len(false).unwrap()
    );
    assert_eq!(decoded.app_random, *plan.app_random_branch_plan());
    assert_eq!(decoded.selectable, *plan.selectable_catalog_plan());
    assert_eq!(decoded.publisher, purpose);
    assert!(PluginSetupPlan::decode(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes).is_err());

    for (magic, version) in [(b"CRUCSUP9", 9_u32), (b"CRUCSU10", 10), (b"CRUCSU11", 11)] {
        let mut changed = bytes.clone();
        changed[..8].copy_from_slice(magic);
        changed[8..12].copy_from_slice(&version.to_be_bytes());
        assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&changed).is_err());
    }
    assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&ordinary).is_err());
}

#[test]
fn dormant_plan_refuses_all_truncations_header_changes_and_trailing_data() {
    let (plan, process, purpose) = parts();
    let bytes = plan
        .encode_preexec_deferred_cleanup(&process, None, &purpose)
        .unwrap();
    for length in 0..bytes.len() {
        assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&bytes[..length]).is_err());
    }
    for offset in 0..48 {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut changed = bytes;
    changed.push(0);
    assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&changed).is_err());
}

#[test]
fn dormant_plan_refuses_independent_source_issuer_and_resource_parent_changes() {
    let (plan, process, purpose) = parts();
    let bytes = plan
        .encode_preexec_deferred_cleanup(&process, None, &purpose)
        .unwrap();
    let tail = bytes.len() - 736;
    // Independently valid purpose observations cannot replace actual Source
    // coordinates or its local process resource parent in this carrier.
    for offset in [32, 64, 112, 304, 336] {
        let mut changed = bytes.clone();
        changed[tail + 224 + offset + 7] ^= 1;
        assert!(DeferredCleanupPurpose::decode(&changed[tail..]).is_ok());
        assert!(
            PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&changed).is_err(),
            "offset {offset}"
        );
    }
    for field in 0..5 {
        let mut changed = purpose;
        match field {
            0 => changed.delegation.source_capability[0] ^= 1,
            1 => changed.delegation.source_reservation[0] ^= 1,
            2 => changed.delegation.source_issuer_incarnation += 1,
            3 => changed.delegation.resource.identity[0] ^= 1,
            _ => changed.delegation.resource.incarnation += 1,
        }
        assert!(
            plan.encode_preexec_deferred_cleanup(&process, None, &changed)
                .is_err()
        );
    }
}

#[test]
fn dormant_plan_binds_optional_workspace_to_the_same_original() {
    let (plan, process, purpose) = parts();
    let mut workspace = [0; DEVICE_DIGEST_PURPOSE_BYTES];
    workspace[..8].copy_from_slice(b"CRUCWSP2");
    workspace[8..12].copy_from_slice(&2_u32.to_be_bytes());
    workspace[12..16].copy_from_slice(&1_u32.to_be_bytes());
    for (destination, source, length) in [(16, 184, 32), (48, 16, 8), (72, 96, 8), (80, 88, 8)] {
        workspace[destination..destination + length]
            .copy_from_slice(&process[source..source + length]);
    }
    for offset in [64, 120] {
        workspace[offset..offset + 8]
            .copy_from_slice(&crate::DEVICE_DIGEST_WORKSPACE_BYTES.to_be_bytes());
    }
    let bytes = plan
        .encode_preexec_deferred_cleanup(&process, Some(&workspace), &purpose)
        .unwrap();
    assert_eq!(
        bytes.len(),
        plan.preexec_deferred_cleanup_encoded_len(true).unwrap()
    );
    assert_eq!(
        PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&bytes)
            .unwrap()
            .publisher,
        purpose
    );
    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_deferred_cleanup(&process, Some(&workspace), &purpose)
            .is_err()
    );
}

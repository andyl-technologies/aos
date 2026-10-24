//! Checks plan eleven's literal carrier and matched parent observations.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publisher_subscription::quantum::{QuantumStackPurpose, QuantumStackReservation};

fn inputs() -> (
    PluginSetupPlan,
    [u8; PURPOSE],
    QuantumPublisherPurpose,
    QuantumStackPurpose,
) {
    let bytes = selected_quantum();
    let (app, selectable, publisher) =
        PluginSetupPlan::decode_preexec_quantum_parts(&bytes).unwrap();
    let start = bytes.len() - 224 - PURPOSE;
    let process = bytes[start..start + PURPOSE].try_into().unwrap();
    let startup = StartupOperation::decode(&bytes[start - STARTUP_OPERATION_BYTES..start]).unwrap();
    let reservation = QuantumStackReservation {
        loan_generation: 11,
        usable_bytes: 8192,
        mapping_bytes: 8192,
        thread_control_bytes: 256,
        loader_tls_bytes: 512,
        page_bytes: 4096,
        profile_digest: [9; 32],
        cleanup_generation: 13,
    };
    let stacks = QuantumStackPurpose {
        grant_set_generation: 17,
        process_generation: publisher.session.process_generation,
        account_generation: publisher.session.account_generation,
        lender_generation: publisher.session.lender_generation,
        capability: publisher.session.capability,
        reservation: publisher.session.reservation,
        main: reservation,
        rr: QuantumStackReservation {
            loan_generation: 19,
            mapping_bytes: 16384,
            ..reservation
        },
    };
    (
        PluginSetupPlan::new(app, selectable).with_startup_operation(startup),
        process,
        publisher,
        stacks,
    )
}

#[test]
fn stack_plan_matches_literal_header_body_order_and_mutual_edition_refusal() {
    let (plan, process, publisher, stacks) = inputs();
    let bytes = plan
        .encode_preexec_quantum_stack(&process, None, &publisher, &stacks)
        .unwrap();
    let decoded = PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes).unwrap();
    assert_eq!(decoded.publisher, publisher);
    assert_eq!(decoded.stacks, stacks);
    assert_eq!(
        bytes.len(),
        plan.preexec_quantum_stack_encoded_len(false).unwrap()
    );
    assert_eq!(&bytes[..16], b"CRUCSU11\0\0\0\x0b\0\0\0\x38");
    assert_eq!(
        &bytes[40..56],
        &[0, 0, 0, 224, 0, 0, 0, 0, 0, 0, 2, 64, 0, 0, 0, 0]
    );
    let stack_start = bytes.len() - 576;
    assert_eq!(&bytes[stack_start..], &stacks.encode().unwrap());
    assert_eq!(
        &bytes[stack_start - 224..stack_start],
        &publisher.encode().unwrap()
    );
    assert_eq!(
        &bytes[stack_start - 224 - PURPOSE..stack_start - 224],
        &process
    );
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&selected_quantum()).is_err());
    let replay = PluginSetupPlan::new(decoded.app_random, decoded.selectable)
        .with_startup_operation(
            StartupOperation::decode(
                &bytes[stack_start - 224 - PURPOSE - STARTUP_OPERATION_BYTES
                    ..stack_start - 224 - PURPOSE],
            )
            .unwrap(),
        );
    assert_eq!(
        replay
            .encode_preexec_quantum_stack(&process, None, &publisher, &stacks)
            .unwrap(),
        bytes
    );
}

#[test]
fn stack_plan_refuses_short_trailing_malformed_and_valid_but_foreign_records() {
    let (plan, process, publisher, stacks) = inputs();
    let bytes = plan
        .encode_preexec_quantum_stack(&process, None, &publisher, &stacks)
        .unwrap();
    for length in 0..bytes.len() {
        assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes[..length]).is_err());
    }
    assert!(
        PluginSetupPlan::decode_preexec_quantum_stack_parts(&[bytes.as_slice(), &[0]].concat())
            .is_err()
    );
    for offset in 0..56 {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_quantum_stack_parts(&changed).is_err(),
            "offset {offset}"
        );
    }
    for field in 0..5 {
        let mut foreign = stacks;
        match field {
            0 => foreign.account_generation += 1,
            1 => foreign.process_generation += 1,
            2 => foreign.lender_generation += 1,
            3 => foreign.capability[0] ^= 1,
            _ => foreign.reservation[0] ^= 1,
        }
        // This remains internally valid: only the actual other parent differs.
        let encoded = foreign.encode().unwrap();
        assert!(
            plan.encode_preexec_quantum_stack(&process, None, &publisher, &foreign)
                .is_err()
        );
        let mut changed = bytes.clone();
        let start = changed.len() - encoded.len();
        changed[start..].copy_from_slice(&encoded);
        assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&changed).is_err());
    }
}

#[test]
fn stack_plan_retains_optional_workspace_and_its_same_process_binding() {
    let (plan, process, publisher, stacks) = inputs();
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
        .encode_preexec_quantum_stack(&process, Some(&workspace), &publisher, &stacks)
        .unwrap();
    assert_eq!(
        bytes.len(),
        plan.preexec_quantum_stack_encoded_len(true).unwrap()
    );
    assert_eq!(
        PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes)
            .unwrap()
            .stacks,
        stacks
    );
    let end = bytes.len() - 576 - 224 - PURPOSE - STARTUP_OPERATION_BYTES;
    assert_eq!(&bytes[end - DEVICE_DIGEST_PURPOSE_BYTES..end], &workspace);

    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_quantum_stack(&process, Some(&workspace), &publisher, &stacks)
            .is_err()
    );
    let mut changed = bytes;
    changed[end - DEVICE_DIGEST_PURPOSE_BYTES + 80] ^= 1;
    assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&changed).is_err());
}

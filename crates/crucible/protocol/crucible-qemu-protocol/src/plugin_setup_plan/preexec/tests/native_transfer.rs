//! Checks the distinct native-transfer plan and unchanged earlier editions.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::native_transfer::{
    NATIVE_TRANSFER_BYTES, NativeLiability, NativeLiabilityDisposition, NativeLiabilityKind,
    NativeTransfer, NativeTransferCoordinates, NativeTransferMemory,
};
use crate::runtime_artifact::RUNTIME_ARTIFACT_PAIR_BYTES;
use sha2::{Digest, Sha256};

use super::runtime_artifact::runtime;

fn transfer() -> NativeTransfer {
    NativeTransfer {
        coordinates: NativeTransferCoordinates {
            issuer_epoch: 1,
            parent_epoch: 2,
            loan_epoch: 3,
            process_generation: 3,
            account_generation: 9,
            producer_request_epoch: 6,
            request_sequence: 7,
            profile_edition: 8,
            parent: [11; 32],
            issuer: [12; 32],
            recipient: [11; 32],
            launcher: [14; 32],
            loan: [15; 32],
            cleanup_holder: [16; 32],
            cleanup_epoch: 9,
        },
        runtime_pair_sha256: Sha256::digest(runtime().encode().unwrap()).into(),
        profile_manifest_sha256: [31; 32],
        process_contract_sha256: [32; 32],
        memory: NativeTransferMemory {
            gross_bytes: 45056,
            native_bytes: 40960,
            retained_bytes: 4096,
            fixed_floor_bytes: 4096,
            progress_bytes: 4096,
            physical_terminal_bytes: 4096,
            creator_history_bytes: 2048,
        },
        page_size: 4096,
        artifact_count: 4,
        paid_probe_sha256: [33; 32],
        liabilities: std::array::from_fn(|index| NativeLiability {
            kind: [
                NativeLiabilityKind::ArtifactBacking,
                NativeLiabilityKind::ImageAndPrivateCopies,
                NativeLiabilityKind::KernelMappings,
                NativeLiabilityKind::InitialTls,
                NativeLiabilityKind::MainStack,
                NativeLiabilityKind::FixedControl,
                NativeLiabilityKind::DynamicMappings,
                NativeLiabilityKind::WorkerStorage,
                NativeLiabilityKind::Progress,
                NativeLiabilityKind::PhysicalTerminal,
            ][index],
            disposition: NativeLiabilityDisposition::Required,
            memory_bytes: 4096,
            virtual_bytes: 8192,
            backing_bytes: 4096,
            maximum_tasks: 1,
            maximum_descriptors: 2,
            alignment: 64,
            producer: [index as u8 + 41; 32],
        }),
    }
}

#[test]
fn native_plan_preserves_prior_sections_and_refuses_all_earlier_editions() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let runtime = runtime();
    let transfer = transfer();
    let earlier = plan
        .encode_preexec_runtime_artifact(&process, None, &publisher, &runtime)
        .unwrap();
    let bytes = plan
        .encode_preexec_native_transfer(&process, None, &publisher, &runtime, &transfer)
        .unwrap();

    assert_eq!(&bytes[..16], b"CRUCSU14\0\0\0\x0e\0\0\0\x40");
    assert_eq!(
        &bytes[48..64],
        &[0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 5, 192, 0, 0, 0, 0]
    );
    assert_eq!(
        &bytes[64..bytes.len() - NATIVE_TRANSFER_BYTES],
        &earlier[56..]
    );
    assert_eq!(
        &bytes[bytes.len() - NATIVE_TRANSFER_BYTES..],
        transfer.encode().unwrap()
    );
    assert_eq!(
        bytes.len(),
        plan.preexec_native_transfer_encoded_len(false).unwrap()
    );
    let decoded = PluginSetupPlan::decode_preexec_native_transfer_parts(&bytes).unwrap();
    assert_eq!(decoded.app_random, *plan.app_random_branch_plan());
    assert_eq!(decoded.selectable, *plan.selectable_catalog_plan());
    assert_eq!(decoded.publisher, publisher);
    assert_eq!(decoded.runtime, runtime);
    assert_eq!(decoded.transfer, transfer);
    assert!(PluginSetupPlan::decode(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_runtime_artifact_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_native_transfer_parts(&earlier).is_err());
}

#[test]
fn native_plan_refuses_every_truncation_changed_header_and_trailing_bytes() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let bytes = plan
        .encode_preexec_native_transfer(&process, None, &publisher, &runtime(), &transfer())
        .unwrap();

    for length in 0..bytes.len() {
        assert!(
            PluginSetupPlan::decode_preexec_native_transfer_parts(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    for offset in 0..64 {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_native_transfer_parts(&changed).is_err(),
            "header {offset}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(PluginSetupPlan::decode_preexec_native_transfer_parts(&trailing).is_err());
}

#[test]
fn native_plan_refuses_independently_valid_foreign_transfer_and_runtime_parents() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let bytes = plan
        .encode_preexec_native_transfer(&process, None, &publisher, &runtime(), &transfer())
        .unwrap();
    let transfer_start = bytes.len() - NATIVE_TRANSFER_BYTES;
    for offset in [40, 48, 144, 240] {
        let mut changed = bytes.clone();
        changed[transfer_start + offset + 7] ^= 1;
        assert!(NativeTransfer::decode(&changed[transfer_start..]).is_ok());
        assert!(PluginSetupPlan::decode_preexec_native_transfer_parts(&changed).is_err());
    }
    // Matching the transfer to a foreign valid runtime cannot bypass Source.
    for field in 0..3 {
        let mut pair = runtime();
        let mut loan = transfer();
        match field {
            0 => {
                pair.process_generation += 1;
                loan.coordinates.process_generation += 1;
            }
            1 => {
                pair.account_generation += 1;
                loan.coordinates.account_generation += 1;
            }
            _ => {
                pair.source_assignment[0] ^= 1;
                loan.coordinates.recipient[0] ^= 1;
            }
        }
        loan.runtime_pair_sha256 = Sha256::digest(pair.encode().unwrap()).into();
        loan.corroborate_runtime(&pair).unwrap();
        assert!(
            plan.encode_preexec_native_transfer(&process, None, &publisher, &pair, &loan)
                .is_err()
        );
        let mut changed = bytes.clone();
        let runtime_start = transfer_start - RUNTIME_ARTIFACT_PAIR_BYTES;
        changed[runtime_start..transfer_start].copy_from_slice(&pair.encode().unwrap());
        changed[transfer_start..].copy_from_slice(&loan.encode().unwrap());
        assert!(PluginSetupPlan::decode_preexec_native_transfer_parts(&changed).is_err());
    }
}

#[test]
fn native_plan_preserves_optional_workspace_and_refuses_foreign_workspace() {
    let (plan, process, publisher) = deferred_cleanup::parts();
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
    let earlier = plan
        .encode_preexec_runtime_artifact(&process, Some(&workspace), &publisher, &runtime())
        .unwrap();
    let bytes = plan
        .encode_preexec_native_transfer(
            &process,
            Some(&workspace),
            &publisher,
            &runtime(),
            &transfer(),
        )
        .unwrap();
    assert_eq!(
        bytes.len(),
        plan.preexec_native_transfer_encoded_len(true).unwrap()
    );
    assert_eq!(
        &bytes[64..bytes.len() - NATIVE_TRANSFER_BYTES],
        &earlier[56..]
    );
    PluginSetupPlan::decode_preexec_native_transfer_parts(&bytes).unwrap();

    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_native_transfer(
            &process,
            Some(&workspace),
            &publisher,
            &runtime(),
            &transfer()
        )
        .is_err()
    );
}

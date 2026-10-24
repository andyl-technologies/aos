//! Checks complete Plan15 framing, containing identities and negative probe facts.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::deferred_cleanup::DeferredCleanupPurpose;
use crate::native_transfer::manifest::NativeProfileManifest;
use crate::native_transfer::probe::{NATIVE_PROBE_REPORT_BYTES, NativeProbeReport};
use crate::native_transfer::{NATIVE_TRANSFER_BYTES, NativeTransfer};
use crate::runtime_artifact::RuntimeArtifactPair;
use sha2::{Digest, Sha256};

type Material = (Vec<u8>, Vec<u8>, NativeTransfer, RuntimeArtifactPair);

fn material() -> Material {
    let (mut report, mut manifest, mut transfer, mut runtime) =
        crate::native_transfer::probe::tests::material();
    let containing = super::runtime_artifact::runtime();
    runtime.process_generation = containing.process_generation;
    runtime.account_generation = containing.account_generation;
    runtime.source_assignment = containing.source_assignment;
    transfer.coordinates.process_generation = runtime.process_generation;
    transfer.coordinates.account_generation = runtime.account_generation;
    transfer.coordinates.recipient = runtime.source_assignment;
    refresh(&mut report, &mut manifest, &mut transfer, &runtime);
    (report, manifest, transfer, runtime)
}

fn refresh(
    report: &mut [u8],
    manifest: &mut [u8],
    transfer: &mut NativeTransfer,
    runtime: &RuntimeArtifactPair,
) {
    transfer.runtime_pair_sha256 = Sha256::digest(runtime.encode().unwrap()).into();
    manifest[32..40].copy_from_slice(&runtime.process_generation.to_be_bytes());
    manifest[40..48].copy_from_slice(&runtime.account_generation.to_be_bytes());
    manifest[48..80].copy_from_slice(&runtime.source_assignment);
    manifest[144..176].copy_from_slice(&transfer.runtime_pair_sha256);
    transfer.profile_manifest_sha256 = Sha256::digest(&*manifest).into();
    report[40..48].copy_from_slice(&runtime.process_generation.to_be_bytes());
    report[48..56].copy_from_slice(&runtime.account_generation.to_be_bytes());
    report[184..216].copy_from_slice(&runtime.source_assignment);
    report[216..248].copy_from_slice(&transfer.profile_manifest_sha256);
    transfer.paid_probe_sha256 = Sha256::digest(&*report).into();
}

fn inputs<'a>(
    material: &'a Material,
    publisher: &'a DeferredCleanupPurpose,
) -> NativeProfilePlanInputs<'a> {
    NativeProfilePlanInputs {
        publisher,
        runtime: &material.3,
        transfer: &material.2,
        manifest: NativeProfileManifest::decode(&material.1).unwrap(),
        probe: NativeProbeReport::decode(&material.0).unwrap(),
    }
}

#[test]
fn profile_plan_borrows_exact_tails_and_preserves_prior_sections() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let material = material();
    let prior = plan
        .encode_preexec_native_transfer(&process, None, &publisher, &material.3, &material.2)
        .unwrap();
    let bytes = plan
        .encode_preexec_native_profile(&process, None, inputs(&material, &publisher))
        .unwrap();

    assert_eq!(&bytes[..16], b"CRUCSU15\0\0\0\x0f\0\0\0\x50");
    assert_eq!(&bytes[20..64], &prior[20..64]);
    assert_eq!(&bytes[64..68], &(material.1.len() as u32).to_be_bytes());
    assert_eq!(&bytes[68..72], &3584_u32.to_be_bytes());
    assert_eq!(&bytes[72..80], &[0; 8]);
    assert_eq!(&bytes[80..80 + prior.len() - 64], &prior[64..]);
    assert_eq!(
        bytes.len(),
        plan.preexec_native_profile_encoded_len(false, material.1.len())
            .unwrap()
    );
    let decoded = PluginSetupPlan::decode_preexec_native_profile_parts(&bytes).unwrap();
    assert_eq!(decoded.app_random, *plan.app_random_branch_plan());
    assert_eq!(decoded.selectable, *plan.selectable_catalog_plan());
    assert_eq!(decoded.publisher, publisher);
    assert_eq!(decoded.runtime, material.3);
    assert_eq!(decoded.transfer, material.2);
    assert_eq!(decoded.manifest.as_bytes(), material.1);
    assert_eq!(decoded.probe.as_bytes(), material.0);
    let probe_start = bytes.len() - NATIVE_PROBE_REPORT_BYTES;
    assert_eq!(
        decoded.probe.as_bytes().as_ptr(),
        bytes[probe_start..].as_ptr()
    );
    assert_eq!(
        decoded.manifest.as_bytes().as_ptr(),
        bytes[probe_start - material.1.len()..].as_ptr()
    );
    assert!(decoded.probe.has_completed_result());
}

#[test]
fn profile_plan_refuses_all_earlier_editions_in_both_directions() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let material = material();
    let bytes = plan
        .encode_preexec_native_profile(&process, None, inputs(&material, &publisher))
        .unwrap();

    assert!(PluginSetupPlan::decode(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_runtime_artifact_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_native_transfer_parts(&bytes).is_err());
    let prior = plan
        .encode_preexec_native_transfer(&process, None, &publisher, &material.3, &material.2)
        .unwrap();
    assert!(PluginSetupPlan::decode_preexec_native_profile_parts(&prior).is_err());
    for (magic, edition) in [(b"CRUCSU13", 13_u32), (b"CRUCSU14", 14)] {
        let mut changed = bytes.clone();
        changed[..8].copy_from_slice(magic);
        changed[8..12].copy_from_slice(&edition.to_be_bytes());
        assert!(PluginSetupPlan::decode_preexec_native_profile_parts(&changed).is_err());
    }
}

#[test]
fn profile_plan_refuses_every_truncation_header_change_and_surplus() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let material = material();
    let bytes = plan
        .encode_preexec_native_profile(&process, None, inputs(&material, &publisher))
        .unwrap();

    for length in 0..bytes.len() {
        assert!(
            PluginSetupPlan::decode_preexec_native_profile_parts(&bytes[..length]).is_err(),
            "truncation {length}"
        );
    }
    for offset in 0..80 {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_native_profile_parts(&changed).is_err(),
            "header {offset}"
        );
    }
    for offset in [64, 68] {
        let mut changed = bytes.clone();
        changed[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(PluginSetupPlan::decode_preexec_native_profile_parts(&changed).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(PluginSetupPlan::decode_preexec_native_profile_parts(&trailing).is_err());
}

#[test]
fn profile_plan_checks_full_manifest_and_probe_digests_and_contracts() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let material = material();
    let bytes = plan
        .encode_preexec_native_profile(&process, None, inputs(&material, &publisher))
        .unwrap();
    let probe_start = bytes.len() - NATIVE_PROBE_REPORT_BYTES;
    let manifest_start = probe_start - material.1.len();
    let transfer_start = manifest_start - NATIVE_TRANSFER_BYTES;

    // These changes remain independently valid descriptions. Refreshing the
    // complete transfer digest cannot make foreign request/producer facts agree.
    for (start, offset, manifest_tail) in [
        (manifest_start, 24, true),
        (manifest_start, 112, true),
        (manifest_start, material.1.len() - 1, true),
        (probe_start, 32, false),
        (probe_start, 280, false),
        (probe_start, 512 + 48, false),
    ] {
        let mut changed = bytes.clone();
        changed[start + offset] ^= 2;
        assert!(PluginSetupPlan::decode_preexec_native_profile_parts(&changed).is_err());
        let mut transfer = material.2;
        if manifest_tail {
            NativeProfileManifest::decode(&changed[manifest_start..probe_start]).unwrap();
            transfer.profile_manifest_sha256 =
                Sha256::digest(&changed[manifest_start..probe_start]).into();
        } else {
            NativeProbeReport::decode(&changed[probe_start..]).unwrap();
            transfer.paid_probe_sha256 = Sha256::digest(&changed[probe_start..]).into();
        }
        changed[transfer_start..manifest_start].copy_from_slice(&transfer.encode().unwrap());
        assert!(
            PluginSetupPlan::decode_preexec_native_profile_parts(&changed).is_err(),
            "refreshed foreign tail {manifest_tail}/{offset}"
        );
    }
}

#[test]
fn profile_plan_refuses_a_mutually_correlated_foreign_containing_assignment() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    for field in 0..3 {
        let (mut report, mut manifest, mut transfer, mut runtime) = material();
        match field {
            0 => {
                runtime.process_generation += 1;
                transfer.coordinates.process_generation += 1;
            }
            1 => {
                runtime.account_generation += 1;
                transfer.coordinates.account_generation += 1;
            }
            _ => {
                runtime.source_assignment[0] ^= 1;
                transfer.coordinates.recipient[0] ^= 1;
            }
        }
        refresh(&mut report, &mut manifest, &mut transfer, &runtime);
        let material = (report, manifest, transfer, runtime);
        let selected = inputs(&material, &publisher);
        selected
            .probe
            .corroborate_transfer(selected.transfer, &selected.manifest, selected.runtime)
            .unwrap();
        assert!(
            plan.encode_preexec_native_profile(&process, None, selected)
                .is_err()
        );
        let original = self::material();
        let mut bytes = plan
            .encode_preexec_native_profile(&process, None, inputs(&original, &publisher))
            .unwrap();
        let report_start = bytes.len() - NATIVE_PROBE_REPORT_BYTES;
        let manifest_start = report_start - material.1.len();
        let transfer_start = manifest_start - NATIVE_TRANSFER_BYTES;
        let runtime_start = transfer_start - crate::runtime_artifact::RUNTIME_ARTIFACT_PAIR_BYTES;
        bytes[runtime_start..transfer_start].copy_from_slice(&runtime.encode().unwrap());
        bytes[transfer_start..manifest_start].copy_from_slice(&transfer.encode().unwrap());
        bytes[manifest_start..report_start].copy_from_slice(&material.1);
        bytes[report_start..].copy_from_slice(&material.0);
        assert!(PluginSetupPlan::decode_preexec_native_profile_parts(&bytes).is_err());
    }
}

#[test]
fn profile_plan_preserves_negative_probe_and_lost_launch_return_facts() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    for (flags, wait, errno, missing_kernel) in [
        (53_u32, 9_u32, 0_u64, false),
        (55, 0, 127, false),
        (55, 0, 0, true),
        (63, 0, 0, false),
    ] {
        let (mut report, manifest, mut transfer, runtime) = material();
        report[376..380].copy_from_slice(&flags.to_be_bytes());
        report[380..384].copy_from_slice(&wait.to_be_bytes());
        report[392..400].copy_from_slice(&errno.to_be_bytes());
        if missing_kernel {
            report[352..360].fill(0);
        }
        transfer.paid_probe_sha256 = Sha256::digest(&report).into();
        let material = (report, manifest, transfer, runtime);
        let bytes = plan
            .encode_preexec_native_profile(&process, None, inputs(&material, &publisher))
            .unwrap();

        let decoded = PluginSetupPlan::decode_preexec_native_profile_parts(&bytes).unwrap();
        assert!(!decoded.probe.has_completed_result());
        assert!(decoded.probe.facts().reaped);
        assert_eq!(decoded.probe.facts().returned, flags & 2 != 0);
        assert_eq!(decoded.probe.facts().raw_wait_status, wait);
        assert_eq!(u64::from(decoded.probe.facts().first_errno), errno);
        assert_eq!(decoded.probe.facts().birth_unknown, flags & 8 != 0);
        assert_eq!(
            decoded.probe.facts().kernel_handle_sequence == 0,
            missing_kernel
        );
        assert_eq!(decoded.probe.as_bytes(), material.0);
    }
}

#[test]
fn profile_plan_preserves_optional_workspace_and_its_original_binding() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let material = material();
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
    let prior = plan
        .encode_preexec_native_transfer(
            &process,
            Some(&workspace),
            &publisher,
            &material.3,
            &material.2,
        )
        .unwrap();
    let bytes = plan
        .encode_preexec_native_profile(&process, Some(&workspace), inputs(&material, &publisher))
        .unwrap();

    assert_eq!(&bytes[80..80 + prior.len() - 64], &prior[64..]);
    assert_eq!(
        bytes.len(),
        plan.preexec_native_profile_encoded_len(true, material.1.len())
            .unwrap()
    );
    PluginSetupPlan::decode_preexec_native_profile_parts(&bytes).unwrap();
    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_native_profile(
            &process,
            Some(&workspace),
            inputs(&material, &publisher)
        )
        .is_err()
    );
}

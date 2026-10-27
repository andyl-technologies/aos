//! Checks plan thirteen and the same-parent runtime-artifact correspondence.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::runtime_artifact::{RuntimeArtifactIdentity, RuntimeArtifactPair};

pub(super) fn runtime() -> RuntimeArtifactPair {
    RuntimeArtifactPair {
        process_generation: 3,
        account_generation: 9,
        source_assignment: [11; 32],
        libc: RuntimeArtifactIdentity {
            file_len: 4096,
            sha256: [21; 32],
        },
        loader: RuntimeArtifactIdentity {
            file_len: 2048,
            sha256: [22; 32],
        },
    }
}

#[test]
fn runtime_plan_preserves_existing_sections_and_refuses_every_other_edition() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let runtime = runtime();
    let ordinary = plan
        .encode_preexec_deferred_cleanup(&process, None, &publisher)
        .unwrap();
    let bytes = plan
        .encode_preexec_runtime_artifact(&process, None, &publisher, &runtime)
        .unwrap();
    let decoded = PluginSetupPlan::decode_preexec_runtime_artifact_parts(&bytes).unwrap();
    assert_eq!(&bytes[..16], b"CRUCSU13\0\0\0\x0d\0\0\0\x38");
    assert_eq!(&bytes[48..56], &[0, 0, 0, 192, 0, 0, 0, 0]);
    assert_eq!(&bytes[56..bytes.len() - 192], &ordinary[48..]);
    assert_eq!(
        bytes.len(),
        plan.preexec_runtime_artifact_encoded_len(false).unwrap()
    );
    assert_eq!(decoded.app_random, *plan.app_random_branch_plan());
    assert_eq!(decoded.selectable, *plan.selectable_catalog_plan());
    assert_eq!(decoded.publisher, publisher);
    assert_eq!(decoded.runtime, runtime);
    assert!(PluginSetupPlan::decode(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_publisher_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_quantum_stack_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_deferred_cleanup_parts(&bytes).is_err());
    assert!(PluginSetupPlan::decode_preexec_runtime_artifact_parts(&ordinary).is_err());
}

#[test]
fn runtime_plan_refuses_all_truncations_header_changes_and_trailing_data() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let bytes = plan
        .encode_preexec_runtime_artifact(&process, None, &publisher, &runtime())
        .unwrap();
    for length in 0..bytes.len() {
        assert!(PluginSetupPlan::decode_preexec_runtime_artifact_parts(&bytes[..length]).is_err());
    }
    for offset in 0..56 {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            PluginSetupPlan::decode_preexec_runtime_artifact_parts(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut changed = bytes;
    changed.push(0);
    assert!(PluginSetupPlan::decode_preexec_runtime_artifact_parts(&changed).is_err());
}

#[test]
fn runtime_plan_refuses_independently_valid_foreign_runtime_parents() {
    let (plan, process, publisher) = deferred_cleanup::parts();
    let bytes = plan
        .encode_preexec_runtime_artifact(&process, None, &publisher, &runtime())
        .unwrap();
    let tail = bytes.len() - 192;
    for offset in [16, 24, 32] {
        let mut changed = bytes.clone();
        changed[tail + offset + 7] ^= 1;
        assert!(RuntimeArtifactPair::decode(&changed[tail..]).is_ok());
        assert!(PluginSetupPlan::decode_preexec_runtime_artifact_parts(&changed).is_err());
    }
    for field in 0..3 {
        let mut changed = runtime();
        match field {
            0 => changed.process_generation += 1,
            1 => changed.account_generation += 1,
            _ => changed.source_assignment[0] ^= 1,
        }
        assert!(
            plan.encode_preexec_runtime_artifact(&process, None, &publisher, &changed)
                .is_err()
        );
    }
}

#[test]
fn runtime_plan_preserves_optional_workspace_and_its_same_source_binding() {
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
    let bytes = plan
        .encode_preexec_runtime_artifact(&process, Some(&workspace), &publisher, &runtime())
        .unwrap();
    assert_eq!(
        bytes.len(),
        plan.preexec_runtime_artifact_encoded_len(true).unwrap()
    );
    let decoded = PluginSetupPlan::decode_preexec_runtime_artifact_parts(&bytes).unwrap();
    assert_eq!(decoded.publisher, publisher);
    assert_eq!(decoded.runtime, runtime());
    workspace[80] ^= 1;
    assert!(
        plan.encode_preexec_runtime_artifact(&process, Some(&workspace), &publisher, &runtime())
            .is_err()
    );
}

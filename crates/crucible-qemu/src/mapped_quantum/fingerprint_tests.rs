//! Black-box execution-fingerprint regressions.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::unwrap_used)]

use crucible_shmem::{FingerprintSample, FingerprintSampleVcpu};

use super::*;

fn sample() -> FingerprintSample {
    let mut sample = FingerprintSample {
        sample_icount: 41,
        vcpu_count: 1,
        rr_current_vcpu: 0,
        rr_position_in_quantum: 41,
        rr_switch_quantum: 4096,
        component_failures: 0,
        ram_bytes: 4096,
        ram_digest: [0x11; 32],
        device_state_bytes: 512,
        device_state_digest: [0x22; 32],
        device_state_schema_digest: [0x33; 32],
        ..FingerprintSample::default()
    };
    sample.vcpus[0] = FingerprintSampleVcpu {
        register_digest: [0x44; 32],
        register_file_bytes: 256,
        retired_instruction_count: 0,
    };
    sample
}

#[test]
fn black_box_fingerprint_covers_live_register_ram_and_device_state() {
    let node = crucible::NodeId {
        name: String::from("vm-a"),
    };
    let baseline = black_box_execution_fingerprint(&node, &sample()).unwrap();

    let mut changed = sample();
    changed.vcpus[0].register_digest[0] ^= 1;
    assert_ne!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
    changed = sample();
    changed.ram_digest[0] ^= 1;
    assert_ne!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
    changed = sample();
    changed.device_state_digest[0] ^= 1;
    assert_ne!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
}

#[test]
fn black_box_fingerprint_excludes_unused_vcpu_slots() {
    let node = crucible::NodeId {
        name: String::from("vm-a"),
    };
    let baseline = black_box_execution_fingerprint(&node, &sample()).unwrap();
    let mut changed = sample();
    changed.vcpus[1].register_digest = [0xff; 32];
    assert_eq!(
        baseline,
        black_box_execution_fingerprint(&node, &changed).unwrap()
    );
}

#[test]
fn black_box_fingerprint_rejects_incomplete_samples() {
    let node = crucible::NodeId {
        name: String::from("vm-a"),
    };
    let mut failed = sample();
    failed.component_failures = 1;
    assert!(black_box_execution_fingerprint(&node, &failed).is_err());

    let mut empty = sample();
    empty.vcpu_count = 0;
    assert!(black_box_execution_fingerprint(&node, &empty).is_err());
}

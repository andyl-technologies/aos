//! Checks partial paid-probe history and exact compiled-contract correlation.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::native_transfer::{manifest, put32, put64};

pub(crate) fn material() -> (Vec<u8>, Vec<u8>, NativeTransfer, RuntimeArtifactPair) {
    let (profile, mut transfer, runtime) = manifest::tests::material();
    let mut bytes = vec![0; NATIVE_PROBE_REPORT_BYTES];
    bytes[..8].copy_from_slice(b"CRUCNPR1");
    put32(&mut bytes, 8, 1);
    put32(&mut bytes, 12, 3584);
    for (offset, value) in [
        (16, 1),
        (24, 2),
        (32, 6),
        (40, 4),
        (48, 5),
        (344, 7),
        (352, 8),
        (360, 123),
        (368, 9),
    ] {
        put64(&mut bytes, offset, value);
    }
    for (offset, identity) in [
        (56, [181; 32]),
        (88, [11; 32]),
        (120, [182; 32]),
        (152, [183; 32]),
        (184, [13; 32]),
        (216, transfer.profile_manifest_sha256),
        (248, transfer.process_contract_sha256),
        (280, [71; 32]),
        (312, [184; 32]),
    ] {
        bytes[offset..offset + 32].copy_from_slice(&identity);
    }
    put32(&mut bytes, 376, 55);
    put32(&mut bytes, 384, 16);
    put32(&mut bytes, 388, 4096);
    bytes[512..].copy_from_slice(&profile[256 + 4 * 128..256 + 4 * 128 + 16 * 192]);
    // Actual probe producer children differ from future recipient children.
    for index in 0..16 {
        bytes[512 + index * 192 + 16..512 + index * 192 + 48].fill(index as u8 + 201);
    }
    transfer.paid_probe_sha256 = Sha256::digest(&bytes).into();
    (bytes, profile, transfer, runtime)
}

#[test]
fn probe_borrows_exact_report_and_correlates_distinct_actual_child_descriptions() {
    let (bytes, profile, transfer, runtime) = material();
    let report = NativeProbeReport::decode(&bytes).unwrap();
    let manifest = NativeProfileManifest::decode(&profile).unwrap();

    assert_eq!(report.as_bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(report.as_bytes(), bytes);
    assert_eq!(report.producers().len(), 16);
    assert_ne!(
        report.producers().next().unwrap().child,
        manifest.producers().next().unwrap().child
    );
    assert!(report.has_completed_result());
    let facts = report.facts();
    assert!(facts.attempted && facts.returned && facts.born && facts.exit_observed && facts.reaped);
    assert!(!facts.birth_unknown && !facts.local_custody_retained && !facts.settlement_consumed);
    assert_eq!(
        (
            facts.birth_attempt_sequence,
            facts.kernel_handle_sequence,
            facts.pid_witness,
            facts.event_sequence
        ),
        (7, 8, 123, 9)
    );
    assert_eq!((facts.raw_wait_status, facts.first_errno), (0, 0));
    report
        .corroborate_transfer(&transfer, &manifest, &runtime)
        .unwrap();
}

#[test]
fn probe_refuses_every_truncation_trailing_byte_and_reserved_header_octet() {
    let (bytes, _, _, _) = material();
    for length in 0..bytes.len() {
        assert!(
            NativeProbeReport::decode(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(NativeProbeReport::decode(&trailing).is_err());
    for offset in (0..16).chain(384..392).chain(400..512) {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            NativeProbeReport::decode(&changed).is_err(),
            "header {offset}"
        );
    }
}

#[test]
fn probe_refuses_missing_identities_and_exhausted_epochs_without_rewriting_facts() {
    let (bytes, _, _, _) = material();
    for offset in [16, 24, 32, 40, 48] {
        for value in [0, u64::MAX] {
            let mut changed = bytes.clone();
            put64(&mut changed, offset, value);
            assert!(
                NativeProbeReport::decode(&changed).is_err(),
                "epoch {offset} {value}"
            );
        }
    }
    for offset in [56, 88, 120, 152, 184, 216, 248, 280, 312] {
        let mut changed = bytes.clone();
        changed[offset..offset + 32].fill(0);
        assert!(
            NativeProbeReport::decode(&changed).is_err(),
            "identity {offset}"
        );
    }
    for offset in [344, 352, 368] {
        let mut changed = bytes.clone();
        put64(&mut changed, offset, u64::MAX);
        assert!(NativeProbeReport::decode(&changed).is_err());
    }
}

#[test]
fn probe_preserves_no_birth_unknown_birth_and_reap_after_lost_launch_return() {
    let (bytes, _, _, _) = material();
    // Literal causal histories: flags, attempt, kernel, PID, event, wait, errno.
    let histories = [
        (0, 0, 0, 0, 0, 0, 22),
        (1, 7, 0, 0, 9, 0, 0),
        (3, 7, 0, 0, 9, 0, 11),
        (9, 7, 0, 0, 9, 0, 5),
        (11, 7, 8, 0, 9, 0, 5),
        (9, 7, 0, 123, 9, 0, 5),
        (5, 7, 8, 123, 9, 0, 0),
        (7, 7, 8, 123, 9, 0, 0),
        (21, 7, 8, 123, 9, 0, 0),
        (53, 7, 8, 123, 9, 9, 0),
        (65, 7, 0, 0, 9, 0, 0),
        (181, 7, 8, 123, 9, 0, 5),
    ];
    for (flags, attempt, kernel, pid, event, wait, errno) in histories {
        let mut changed = bytes.clone();
        put32(&mut changed, 376, flags);
        put32(&mut changed, 380, wait);
        for (offset, value) in [
            (344, attempt),
            (352, kernel),
            (360, pid),
            (368, event),
            (392, errno),
        ] {
            put64(&mut changed, offset, value);
        }
        let report = NativeProbeReport::decode(&changed).unwrap();
        assert!(!report.has_completed_result(), "flags {flags}");
        assert_eq!(report.as_bytes(), changed);
        if flags == 53 {
            assert!(report.facts().reaped);
            assert!(!report.facts().returned);
            assert_eq!(report.facts().raw_wait_status, 9);
        }
    }
}

#[test]
fn probe_refuses_impossible_flags_witnesses_and_unreaped_wait_words() {
    let (bytes, _, _, _) = material();
    for flags in [
        2,
        4,
        8,
        16,
        32,
        64,
        128,
        17,
        33,
        37,
        129,
        256,
        511,
        u32::MAX,
    ] {
        let mut changed = bytes.clone();
        put32(&mut changed, 376, flags);
        assert!(
            NativeProbeReport::decode(&changed).is_err(),
            "flags {flags}"
        );
    }
    for (offset, value) in [(344, 0), (368, 0), (360, i32::MAX as u64 + 1), (392, 4096)] {
        let mut changed = bytes.clone();
        put64(&mut changed, offset, value);
        assert!(
            NativeProbeReport::decode(&changed).is_err(),
            "witness {offset} {value}"
        );
    }
    let mut changed = bytes.clone();
    put32(&mut changed, 376, 7);
    put32(&mut changed, 380, 9);
    assert!(NativeProbeReport::decode(&changed).is_err());
    for flags in [0, 1, 3] {
        let mut changed = bytes.clone();
        put32(&mut changed, 376, flags);
        assert!(
            NativeProbeReport::decode(&changed).is_err(),
            "foreign witnesses {flags}"
        );
    }
}

#[test]
fn probe_preserves_missing_born_witnesses_and_sticky_unknown_without_completion() {
    let (bytes, _, _, _) = material();
    for flags in [5, 7, 21, 53, 55, 119, 183, 247] {
        for (kernel, pid) in [(0, 0), (8, 0), (0, 123)] {
            let mut changed = bytes.clone();
            put32(&mut changed, 376, flags);
            put64(&mut changed, 352, kernel);
            put64(&mut changed, 360, pid);

            let report = NativeProbeReport::decode(&changed).unwrap();
            assert!(report.facts().born);
            assert_eq!(report.facts().kernel_handle_sequence, kernel);
            assert_eq!(u64::from(report.facts().pid_witness), pid);
            assert!(!report.has_completed_result(), "missing witness: {flags}");
            assert_eq!(report.as_bytes(), changed);
        }
    }

    for flags in [13, 15, 61, 63, 127, 191, 255] {
        let mut changed = bytes.clone();
        put32(&mut changed, 376, flags);

        let report = NativeProbeReport::decode(&changed).unwrap();
        assert!(report.facts().born && report.facts().birth_unknown);
        assert!(!report.has_completed_result(), "sticky unknown: {flags}");
        assert_eq!(report.as_bytes(), changed);
    }
}

#[test]
fn probe_preserves_pre_attempt_custody_without_inventing_birth_witnesses() {
    let (mut bytes, _, _, _) = material();
    put32(&mut bytes, 376, 64);
    for offset in [344, 352, 360, 368] {
        put64(&mut bytes, offset, 0);
    }

    let report = NativeProbeReport::decode(&bytes).unwrap();
    let facts = report.facts();
    assert!(facts.local_custody_retained);
    assert!(!facts.attempted && !facts.returned && !facts.born && !facts.birth_unknown);
    assert!(!facts.exit_observed && !facts.reaped && !facts.settlement_consumed);
    assert!(!report.has_completed_result());
    assert_eq!(report.as_bytes(), bytes);

    for offset in [344, 352, 360, 368] {
        let mut changed = bytes.clone();
        put64(&mut changed, offset, 1);
        assert!(
            NativeProbeReport::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    for flag in [2, 4, 8, 16, 32, 128] {
        let mut changed = bytes.clone();
        put32(&mut changed, 376, 64 | flag);
        assert!(NativeProbeReport::decode(&changed).is_err(), "flag {flag}");
    }
}

#[test]
fn probe_keeps_nonzero_wait_and_errno_as_negative_completed_evidence() {
    let (bytes, _, _, _) = material();
    for flags in [55, 119, 183, 247] {
        let mut changed = bytes.clone();
        put32(&mut changed, 376, flags);
        assert!(
            NativeProbeReport::decode(&changed)
                .unwrap()
                .has_completed_result()
        );
        for (wait, errno) in [(256, 0), (9, 0), (0, 127), (u32::MAX, 4095)] {
            put32(&mut changed, 380, wait);
            put64(&mut changed, 392, errno);
            let report = NativeProbeReport::decode(&changed).unwrap();
            assert!(!report.has_completed_result());
            assert_eq!(report.facts().raw_wait_status, wait);
            assert_eq!(u64::from(report.facts().first_errno), errno);
        }
    }
}

#[test]
fn probe_refuses_foreign_contracts_even_when_full_report_digest_is_refreshed() {
    let (bytes, profile, transfer, runtime) = material();
    let manifest = NativeProfileManifest::decode(&profile).unwrap();
    for offset in [
        32,
        40,
        48,
        88,
        184,
        216,
        248,
        280,
        512 + 8,
        512 + 48,
        512 + 80,
        512 + 112,
    ] {
        let mut changed = bytes.clone();
        changed[offset + 7] ^= 2;
        let report = NativeProbeReport::decode(&changed).unwrap();
        let mut refreshed = transfer;
        refreshed.paid_probe_sha256 = Sha256::digest(&changed).into();
        assert!(
            report
                .corroborate_transfer(&refreshed, &manifest, &runtime)
                .is_err(),
            "foreign {offset}"
        );
    }
    let mut wrong_digest = transfer;
    wrong_digest.paid_probe_sha256[0] ^= 1;
    assert!(
        NativeProbeReport::decode(&bytes)
            .unwrap()
            .corroborate_transfer(&wrong_digest, &manifest, &runtime)
            .is_err()
    );

    let mut malformed = bytes.clone();
    malformed[512 + 16..512 + 48].fill(0);
    assert!(NativeProbeReport::decode(&malformed).is_err());
    for row in 0..16 {
        for offset in 184..192 {
            let mut malformed = bytes.clone();
            malformed[512 + row * 192 + offset] = 1;
            assert!(NativeProbeReport::decode(&malformed).is_err());
        }
    }
}

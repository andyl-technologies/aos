//! Exercises whole-record candidate selection and legacy codec compatibility.

#![allow(
    clippy::unwrap_used,
    reason = "Canonical fixture failures intentionally panic."
)]

use super::*;
use alloc::vec;

fn selected_first() -> RefLogRecord {
    let mut record = RefRecord::first([1; 32], 3, Locality::default());
    record.candidate_id = Some([7; 32]);
    RefLogRecord {
        record,
        previous_commit: None,
        principal: "writer".to_string(),
        reason: RefLogReason::Commit,
        timestamp: 10,
        expected_previous: Some(None),
        committed_previous: None,
    }
}

fn selected_next() -> RefLogRecord {
    let previous = selected_first().record;
    let mut record = previous.advance([2; 32], 3).unwrap();
    assert!(record.candidate_id.is_none());
    record.candidate_id = Some([8; 32]);
    RefLogRecord {
        record,
        previous_commit: Some(previous.commit),
        principal: "writer".to_string(),
        reason: RefLogReason::Commit,
        timestamp: 9,
        expected_previous: Some(Some(previous)),
        committed_previous: None,
    }
}

fn unchecked_log(log: &RefLogRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::cbor::write_map(
        &mut bytes,
        5 + usize::from(log.expected_previous.is_some())
            + usize::from(log.committed_previous.is_some()),
    );
    crate::cbor::write_uint(&mut bytes, 1);
    bytes.extend(log.record.encode().unwrap());
    crate::cbor::write_uint(&mut bytes, 2);
    if let Some(commit) = log.previous_commit {
        crate::cbor::write_bytes(&mut bytes, &commit);
    } else {
        bytes.push(0xf6);
    }
    crate::cbor::write_uint(&mut bytes, 3);
    crate::cbor::write_text(&mut bytes, &log.principal);
    crate::cbor::write_uint(&mut bytes, 4);
    crate::cbor::write_text(
        &mut bytes,
        if log.reason == RefLogReason::Migrate {
            "migrate"
        } else {
            "commit"
        },
    );
    crate::cbor::write_uint(&mut bytes, 5);
    crate::cbor::write_uint(&mut bytes, log.timestamp);
    if let Some(previous) = &log.expected_previous {
        crate::cbor::write_uint(&mut bytes, 6);
        if let Some(previous) = previous {
            bytes.extend(previous.encode().unwrap());
        } else {
            bytes.push(0xf6);
        }
    }
    if let Some(previous) = &log.committed_previous {
        crate::cbor::write_uint(&mut bytes, 7);
        bytes.extend(previous.encode().unwrap());
    }
    bytes
}

#[test]
fn ref_candidate_codec_preserves_complete_selected_predecessors() {
    for log in [selected_first(), selected_next()] {
        let bytes = log.encode().unwrap();
        let decoded = RefLogRecord::decode(&bytes).unwrap();
        assert_eq!(decoded, log);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert!(
            log.validate_candidate(
                log.expected_previous.as_ref().unwrap().as_ref(),
                &log.record
            )
            .is_ok()
        );
        assert_eq!(
            log.selected_previous().unwrap(),
            log.expected_previous.as_ref().unwrap().as_ref()
        );
    }
    assert_eq!(selected_first().encode().unwrap()[0], 0xa6);
    assert_eq!(selected_first().record.encode().unwrap()[0], 0xa5);
    let mut legacy = selected_first();
    legacy.record.candidate_id = None;
    legacy.expected_previous = None;
    let bytes = legacy.encode().unwrap();
    assert_eq!(bytes[0], 0xa5);
    let decoded = RefLogRecord::decode(&bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.expected_previous, None);
    assert!(decoded.selected_previous().is_err());
    assert!(decoded.validate_candidate(None, &legacy.record).is_err());
}

#[test]
fn ref_candidate_validation_compares_whole_proposal_and_predecessor() {
    let log = selected_next();
    let previous = log.selected_previous().unwrap().unwrap();
    for field in ["selector", "policy", "home", "epoch", "commit"] {
        let mut changed = previous.clone();
        match field {
            "selector" => changed.candidate_id = Some([9; 32]),
            "policy" => {
                changed.policy = Some(RefPolicy {
                    conflicted: Some(true),
                    ..Default::default()
                })
            }
            "home" => changed.home.region = Some("other".to_string()),
            "epoch" => changed.writer_epoch += 1,
            "commit" => changed.commit = [9; 32],
            _ => unreachable!(),
        }
        assert!(
            log.validate_candidate(Some(&changed), &log.record).is_err(),
            "predecessor {field}"
        );
        assert!(
            log.validate_candidate(Some(previous), &changed).is_err(),
            "successor {field}"
        );
    }
    assert!(log.validate_candidate(None, &log.record).is_err());
}

#[test]
fn ref_candidate_codec_rejects_missing_or_contradictory_predecessor() {
    let first = selected_first();
    let next = selected_next();
    let mut cases = vec![];
    let mut changed = first.clone();
    changed.expected_previous = None;
    cases.push(("missing first predecessor key", changed));
    let mut changed = next.clone();
    changed.expected_previous = None;
    cases.push(("missing next predecessor key", changed));
    let mut changed = next.clone();
    changed.expected_previous = Some(None);
    cases.push(("null successor predecessor", changed));
    let mut changed = first;
    changed.previous_commit = Some([1; 32]);
    cases.push(("first commit contradiction", changed));
    let mut changed = next.clone();
    changed.previous_commit = Some([9; 32]);
    cases.push(("previous commit contradiction", changed));
    let mut changed = next.clone();
    changed.record.seq += 1;
    cases.push(("sequence gap", changed));
    let mut changed = next.clone();
    changed.record.writer_epoch -= 1;
    cases.push(("epoch regression", changed));
    let mut changed = next;
    changed.record.home.region = Some("other".to_string());
    cases.push(("ordinary home change", changed));

    for (name, log) in cases {
        assert!(log.encode().is_err(), "encode {name}");
        assert!(
            RefLogRecord::decode(&unchecked_log(&log)).is_err(),
            "decode {name}"
        );
    }
}

#[test]
fn ref_candidate_codec_checks_selector_width_and_migration_structure() {
    let record = selected_first().record;
    let mut bytes = record.encode().unwrap();
    let width = bytes.len() - 33;
    assert_eq!(bytes[width], 32);
    bytes[width] = 31;
    bytes.pop();
    assert!(RefRecord::decode(&bytes).is_err());

    let mut migration = selected_next();
    migration.reason = RefLogReason::Migrate;
    migration.record.home.region = Some("other".to_string());
    assert_eq!(
        RefLogRecord::decode(&migration.encode().unwrap()).unwrap(),
        migration
    );
    migration.record.writer_epoch = 2;
    assert!(migration.encode().is_err());
}

// The registered canonical gate filters this cohesive fixture module by name.
mod cbor {
    //! Selects canonical reflog history fixtures through the registered gate.

    mod tests {
        //! Checks retained history independently of native backend authority.
        use super::super::*;

        fn digest(bytes: &mut Vec<u8>, value: u8) {
            bytes.extend_from_slice(&[0x58, 0x20]);
            bytes.extend_from_slice(&[value; 32]);
        }

        fn ref_fixture(seq: u8, commit: u8, candidate: u8) -> Vec<u8> {
            let mut bytes = vec![0xa5, 1];
            digest(&mut bytes, commit);
            bytes.extend_from_slice(&[2, seq, 3, 3, 4, 0xa0, 6]);
            digest(&mut bytes, candidate);
            bytes
        }

        fn recreated() -> RefLogRecord {
            let mut log = selected_next();
            log.committed_previous = log.expected_previous.take().unwrap();
            log.expected_previous = Some(None);
            log
        }

        #[test]
        fn recreation_preserves_actual_absence_and_retained_history() {
            let mut fixture = vec![0xa7, 1];
            fixture.extend_from_slice(&ref_fixture(2, 2, 8));
            fixture.push(2);
            digest(&mut fixture, 1);
            fixture.extend_from_slice(&[
                3, 0x66, b'w', b'r', b'i', b't', b'e', b'r', 4, 0x66, b'c', b'o', b'm', b'm', b'i',
                b't', 5, 9, 6, 0xf6, 7,
            ]);
            fixture.extend_from_slice(&ref_fixture(1, 1, 7));

            let log = RefLogRecord::decode(&fixture).unwrap();
            assert_eq!(log, recreated());
            assert_eq!(log.encode().unwrap(), fixture);
            assert_eq!(log.cas_expected_previous().unwrap(), None);
            assert_eq!(
                log.selected_previous().unwrap(),
                log.committed_previous.as_ref()
            );
            assert!(log.validate_candidate(None, &log.record).is_ok());
            assert!(
                log.validate_candidate(log.committed_previous.as_ref(), &log.record)
                    .is_err()
            );
        }

        #[test]
        fn retained_history_rejects_contradictions_and_checked_overflow() {
            let mut cases = vec![];
            let mut log = recreated();
            log.expected_previous = Some(log.committed_previous.clone());
            cases.push(log);
            let mut log = recreated();
            log.expected_previous = None;
            cases.push(log);
            let mut log = recreated();
            log.record.candidate_id = None;
            cases.push(log);
            let mut log = recreated();
            log.previous_commit = None;
            cases.push(log);
            let mut log = recreated();
            log.record.seq = 1;
            cases.push(log);
            let mut log = recreated();
            log.record.writer_epoch = 2;
            cases.push(log);
            let mut log = recreated();
            log.record.home.region = Some("other".to_string());
            cases.push(log);
            let mut log = recreated();
            log.committed_previous.as_mut().unwrap().seq = u64::MAX;
            log.record.seq = 1;
            cases.push(log);

            for log in cases {
                assert!(log.encode().is_err());
                assert!(RefLogRecord::decode(&unchecked_log(&log)).is_err());
            }

            let mut migration = recreated();
            migration.reason = RefLogReason::Migrate;
            migration.record.home.region = Some("other".to_string());
            assert_eq!(
                RefLogRecord::decode(&migration.encode().unwrap()).unwrap(),
                migration
            );
        }

        #[test]
        fn legacy_and_first_write_bytes_keep_their_interpretation() {
            let mut fixture = vec![0xa6, 1];
            fixture.extend_from_slice(&ref_fixture(1, 1, 7));
            fixture.extend_from_slice(&[
                2, 0xf6, 3, 0x66, b'w', b'r', b'i', b't', b'e', b'r', 4, 0x66, b'c', b'o', b'm',
                b'm', b'i', b't', 5, 10, 6, 0xf6,
            ]);
            assert_eq!(selected_first().encode().unwrap(), fixture);
            let decoded = RefLogRecord::decode(&fixture).unwrap();
            assert_eq!(decoded.committed_previous, None);
            assert_eq!(decoded.selected_previous().unwrap(), None);

            let mut legacy_ref = ref_fixture(1, 1, 7);
            legacy_ref[0] = 0xa4;
            legacy_ref.truncate(legacy_ref.len() - 35);
            let mut legacy_fixture = vec![0xa5, 1];
            legacy_fixture.extend_from_slice(&legacy_ref);
            legacy_fixture.extend_from_slice(&[
                2, 0xf6, 3, 0x66, b'w', b'r', b'i', b't', b'e', b'r', 4, 0x66, b'c', b'o', b'm',
                b'm', b'i', b't', 5, 10,
            ]);
            let mut legacy = selected_first();
            legacy.record.candidate_id = None;
            legacy.expected_previous = None;
            assert_eq!(legacy.encode().unwrap(), legacy_fixture);
            let decoded = RefLogRecord::decode(&legacy_fixture).unwrap();
            assert_eq!(decoded, legacy);
            assert!(decoded.cas_expected_previous().is_err());
            assert!(decoded.selected_previous().is_err());

            let mut noncanonical = fixture.clone();
            noncanonical.splice(1..2, [0x18, 1]);
            assert!(RefLogRecord::decode(&noncanonical).is_err());
            let mut null_retained = fixture;
            null_retained[0] = 0xa7;
            null_retained.extend_from_slice(&[7, 0xf6]);
            assert!(RefLogRecord::decode(&null_retained).is_err());
        }
    }
}

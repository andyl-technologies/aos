//! Exercises whole-record candidate selection and legacy codec compatibility.

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
    }
}

fn unchecked_log(log: &RefLogRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 5 + usize::from(log.expected_previous.is_some()));
    cbor::write_uint(&mut bytes, 1);
    bytes.extend(log.record.encode().unwrap());
    cbor::write_uint(&mut bytes, 2);
    if let Some(commit) = log.previous_commit {
        cbor::write_bytes(&mut bytes, &commit);
    } else {
        bytes.push(0xf6);
    }
    cbor::write_uint(&mut bytes, 3);
    cbor::write_text(&mut bytes, &log.principal);
    cbor::write_uint(&mut bytes, 4);
    cbor::write_text(
        &mut bytes,
        if log.reason == RefLogReason::Migrate {
            "migrate"
        } else {
            "commit"
        },
    );
    cbor::write_uint(&mut bytes, 5);
    cbor::write_uint(&mut bytes, log.timestamp);
    if let Some(previous) = &log.expected_previous {
        cbor::write_uint(&mut bytes, 6);
        if let Some(previous) = previous {
            bytes.extend(previous.encode().unwrap());
        } else {
            bytes.push(0xf6);
        }
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

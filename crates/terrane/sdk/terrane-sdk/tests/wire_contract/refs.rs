//! Checks canonical ref forwarding against adversarial redundant wire summaries.

use buffa::Message;
use terrane_format::refs::{Locality, RefPolicy, RefRecord, Retention};
use terrane_sdk::wire::{
    refs::{RefCodec, RefWireError},
    v1::{self, compare_and_swap_ref_request::Expect},
};

fn record() -> RefRecord {
    let mut record = RefRecord::first(
        [7; 32],
        13,
        Locality {
            region: Some("west".into()),
            zone: Some("one".into()),
            host: Some("host".into()),
        },
    );
    record.candidate_id = Some([9; 32]);
    record.policy = Some(RefPolicy {
        multi_writer: Some(false),
        retention: Some(Retention::Ttl(3600)),
        ..Default::default()
    });
    record
}

fn codec() -> RefCodec {
    RefCodec::new(4096).unwrap()
}

#[test]
fn observations_require_independent_commit_context_before_whole_record_delivery() {
    let original = record();
    let value = codec().encode_value(&original, "terrane-v1").unwrap();

    let observation = codec().observe_value(&value).unwrap();

    assert_eq!(observation.commit_hint(), &original.commit);
    assert_eq!(observation.profile_hint(), "terrane-v1");
    assert!(matches!(
        observation.clone().verify(&[8; 32], "terrane-v1"),
        Err(RefWireError::CommitMismatch)
    ));
    for profile in ["", "other-profile"] {
        assert!(matches!(
            observation.clone().verify(&original.commit, profile),
            Err(RefWireError::ProfileMismatch)
        ));
    }
    assert_eq!(
        observation.verify(&original.commit, "terrane-v1").unwrap(),
        original
    );

    let mut malformed = value.clone();
    malformed.writer_epoch += 1;
    assert!(matches!(
        codec().observe_value(&malformed),
        Err(RefWireError::SummaryMismatch)
    ));
    malformed = value;
    malformed.profile.clear();
    assert!(matches!(
        codec().observe_value(&malformed),
        Err(RefWireError::ProfileMismatch)
    ));
}

#[test]
fn whole_records_preserve_policy_home_and_candidate_through_wire_roundtrip() {
    let original = record();
    let encoded = codec()
        .encode_value(&original, "registered-profile")
        .unwrap();
    assert_eq!(encoded.canonical_ref_record, original.encode().unwrap());
    let received = v1::RefValue::decode_from_slice(&encoded.encode_to_vec()).unwrap();
    assert_eq!(
        codec()
            .decode_value(&received, &original.commit, "registered-profile")
            .unwrap(),
        original
    );
}

#[test]
fn missing_or_inconsistent_summaries_never_replace_canonical_records() {
    let original = record();
    let encoded = codec().encode_value(&original, "p").unwrap();
    for change in 0..5 {
        let mut altered = encoded.clone();
        match change {
            0 => altered.commit = Default::default(),
            1 => altered.commit.as_option_mut().unwrap().value[0] ^= 1,
            2 => altered
                .commit
                .as_option_mut()
                .unwrap()
                .value
                .pop()
                .map(|_| ())
                .unwrap(),
            3 => altered.sequence += 1,
            _ => altered.writer_epoch += 1,
        }
        assert_eq!(
            codec().decode_value(&altered, &original.commit, "p"),
            Err(RefWireError::SummaryMismatch)
        );
    }
    let mut summary_only = encoded;
    summary_only.canonical_ref_record.clear();
    assert_eq!(
        codec().decode_value(&summary_only, &original.commit, "p"),
        Err(RefWireError::MissingRecord)
    );
}

#[test]
fn incoming_profile_and_commit_claims_cannot_select_the_verified_context() {
    let original = record();
    let encoded = codec().encode_value(&original, "p").unwrap();
    assert_eq!(
        codec().decode_value(&encoded, &[8; 32], "p"),
        Err(RefWireError::CommitMismatch)
    );
    for profile in ["other", ""] {
        assert_eq!(
            codec().decode_value(&encoded, &original.commit, profile),
            Err(RefWireError::ProfileMismatch)
        );
    }
    assert_eq!(
        codec().encode_value(&original, ""),
        Err(RefWireError::ProfileMismatch)
    );
}

#[test]
fn cas_requires_explicit_absence_or_a_complete_matching_expected_record() {
    let original = record();
    let value = codec().encode_value(&original, "p").unwrap();
    let mut request = v1::CompareAndSwapRefRequest::default();
    for expect in [None, Some(Expect::Absent(false))] {
        request.expect = expect;
        assert_eq!(
            codec().decode_expectation(&request, &original.commit, "p"),
            Err(RefWireError::MissingExpectation)
        );
    }
    request.expect = Some(Expect::Absent(true));
    assert_eq!(
        codec()
            .decode_expectation(&request, &original.commit, "p")
            .unwrap(),
        None
    );
    request.expect = Some(Expect::Expected(Box::new(value.clone())));
    assert_eq!(
        codec()
            .decode_expectation(&request, &original.commit, "p")
            .unwrap(),
        Some(original)
    );
    let mut summary_only = value;
    summary_only.canonical_ref_record.clear();
    request.expect = Some(Expect::Expected(Box::new(summary_only)));
    assert_eq!(
        codec().decode_expectation(&request, &[7; 32], "p"),
        Err(RefWireError::MissingRecord)
    );
}

#[test]
fn identical_summaries_keep_distinct_whole_record_cas_expectations() {
    let first = record();
    let mut second = first.clone();
    second.candidate_id = Some([10; 32]);
    second.home.host = Some("other".into());
    second.policy.as_mut().unwrap().retention = Some(Retention::Forever);
    let one = codec().encode_value(&first, "p").unwrap();
    let two = codec().encode_value(&second, "p").unwrap();
    assert_eq!(
        (&one.commit, one.sequence, one.writer_epoch),
        (&two.commit, two.sequence, two.writer_epoch)
    );
    assert_ne!(one.canonical_ref_record, two.canonical_ref_record);
    let decoded_one = codec().decode_value(&one, &first.commit, "p").unwrap();
    let decoded_two = codec().decode_value(&two, &first.commit, "p").unwrap();
    assert_eq!(decoded_one, first);
    assert_eq!(decoded_two, second);
    assert_ne!(decoded_one, decoded_two);
}

#[test]
fn canonical_record_limits_and_malformed_cbor_fail_before_returning_a_record() {
    assert!(matches!(RefCodec::new(0), Err(RefWireError::InvalidLimit)));
    let original = record();
    let value = codec().encode_value(&original, "p").unwrap();
    let exact = RefCodec::new(value.canonical_ref_record.len()).unwrap();
    assert_eq!(
        exact.decode_value(&value, &original.commit, "p").unwrap(),
        original
    );
    let smaller = RefCodec::new(value.canonical_ref_record.len() - 1).unwrap();
    assert_eq!(
        smaller.encode_value(&original, "p"),
        Err(RefWireError::RecordTooLarge)
    );
    assert_eq!(
        smaller.decode_value(&value, &original.commit, "p"),
        Err(RefWireError::RecordTooLarge)
    );
    for bytes in [
        vec![0xff],
        vec![0xa0],
        [value.canonical_ref_record.as_slice(), &[0]].concat(),
    ] {
        let mut broken = value.clone();
        broken.canonical_ref_record = bytes;
        assert!(matches!(
            codec().decode_value(&broken, &original.commit, "p"),
            Err(RefWireError::Record(_))
        ));
    }
}

fn log_record() -> terrane_format::refs::RefLogRecord {
    terrane_format::refs::RefLogRecord {
        record: record(),
        previous_commit: None,
        principal: "writer".into(),
        reason: terrane_format::refs::RefLogReason::Commit,
        timestamp: 123,
        expected_previous: Some(None),
        committed_previous: None,
    }
}

#[test]
fn complete_reflogs_keep_exact_expectations_and_ref_values() {
    let original = log_record();
    let entry = codec()
        .encode_log(&original, "p", "advisory message")
        .unwrap();
    let received = v1::RefLogEntry::decode_from_slice(&entry.encode_to_vec()).unwrap();
    assert_eq!(
        codec()
            .decode_log(&received, &original.record.commit, "p")
            .unwrap(),
        original
    );
    assert_eq!(
        received.canonical_ref_log_record,
        original.encode().unwrap()
    );

    let previous = original.record.clone();
    let mut successor = previous.advance([8; 32], previous.writer_epoch).unwrap();
    successor.candidate_id = Some([12; 32]);
    let advanced = terrane_format::refs::RefLogRecord {
        record: successor,
        previous_commit: Some(previous.commit),
        expected_previous: Some(Some(previous)),
        ..original.clone()
    };
    let forwarded = codec().encode_log(&advanced, "p", "").unwrap();
    assert_eq!(
        codec()
            .decode_log(&forwarded, &advanced.record.commit, "p")
            .unwrap(),
        advanced
    );

    for alteration in 0..6 {
        let mut changed = received.clone();
        match alteration {
            0 => changed.sequence += 1,
            1 => changed.principal.push('x'),
            2 => changed.at.as_option_mut().unwrap().nanos = 1,
            3 => changed.at = Default::default(),
            4 => changed.value = Default::default(),
            _ => {
                let mut other = original.record.clone();
                other.candidate_id = Some([11; 32]);
                changed.value = codec().encode_value(&other, "p").unwrap().into();
            }
        }
        assert!(
            codec()
                .decode_log(&changed, &original.record.commit, "p")
                .is_err()
        );
    }
}

#[test]
fn reflog_limits_timestamp_bounds_and_incomplete_candidates_are_rejected() {
    let mut original = log_record();
    original.timestamp = 253_402_300_799;
    let entry = codec().encode_log(&original, "p", "").unwrap();
    assert_eq!(
        codec()
            .decode_log(&entry, &original.record.commit, "p")
            .unwrap(),
        original
    );
    original.timestamp += 1;
    assert_eq!(
        codec().encode_log(&original, "p", ""),
        Err(RefWireError::InvalidTimestamp)
    );
    original.timestamp = 0;
    original.expected_previous = None;
    assert!(matches!(
        codec().encode_log(&original, "p", ""),
        Err(RefWireError::Record(_))
    ));
    let smaller = RefCodec::new(entry.canonical_ref_log_record.len() - 1).unwrap();
    assert_eq!(
        smaller.decode_log(&entry, &original.record.commit, "p"),
        Err(RefWireError::RecordTooLarge)
    );
    let mut missing = entry;
    missing.canonical_ref_log_record.clear();
    assert_eq!(
        codec().decode_log(&missing, &original.record.commit, "p"),
        Err(RefWireError::MissingRecord)
    );
}

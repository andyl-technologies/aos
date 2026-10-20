//! Checks bounded retirement metadata through the public parsing API.
//!
//! These tests create no inode and grant no native lease or content authority.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "Retirement record fixtures intentionally fail on invalid setup."
)]

use terrane_sdk::host::publication::{MAX_RETIREMENT_RECORD_BYTES, RetirementRecordCandidate};

fn record() -> String {
    r#"version=1
domain='public'
key=[1,2]
device=7
inode=11
changed_seconds=1
changed_nanoseconds=2
deadline_unix_ms=3
"#
    .to_owned()
}

fn name(key: &[u8]) -> String {
    // Independent fixed public-domain prefix, retaining the existing
    // little-endian length and opaque key bytes in the filename contract.
    let bytes = [[6, 0, 0, 0, 0, 0, 0, 0].as_slice(), b"public", key].concat();
    format!("retirement-{}.toml", blake3::hash(&bytes).to_hex())
}

#[test]
fn retirement_candidate_returns_only_untrusted_key_and_device() {
    let candidate =
        RetirementRecordCandidate::parse("public", &name(&[1, 2]), record().as_bytes()).unwrap();
    assert_eq!(candidate.key(), [1, 2]);
    assert_eq!(candidate.device(), 7);
}

#[test]
fn retirement_candidate_rejects_wrong_names_domains_and_unknown_fields() {
    assert!(
        RetirementRecordCandidate::parse("public", "retirement-other.toml", record().as_bytes())
            .is_err()
    );
    assert!(
        RetirementRecordCandidate::parse("private:other", &name(&[1, 2]), record().as_bytes())
            .is_err()
    );
    assert!(
        RetirementRecordCandidate::parse(
            "public",
            &name(&[1, 2]),
            format!("{}foreign=1\n", record()).as_bytes()
        )
        .is_err()
    );
}

#[test]
fn retirement_candidate_rejects_invalid_record_values() {
    for (field, invalid) in [
        ("version=1", "version=2"),
        ("inode=11", "inode=0"),
        ("changed_nanoseconds=2", "changed_nanoseconds=-1"),
        ("changed_nanoseconds=2", "changed_nanoseconds=1000000000"),
        ("deadline_unix_ms=3", "deadline_unix_ms=0"),
        ("key=[1,2]", "key=[]"),
    ] {
        let bytes = record().replace(field, invalid);
        assert!(
            RetirementRecordCandidate::parse("public", &name(&[1, 2]), bytes.as_bytes()).is_err()
        );
    }
}

#[test]
fn retirement_candidate_bounds_record_and_key_allocations() {
    assert!(
        RetirementRecordCandidate::parse(
            "public",
            &name(&[1, 2]),
            &[b' '; MAX_RETIREMENT_RECORD_BYTES + 1]
        )
        .is_err()
    );
    let key = vec![1; 129];
    let bytes = record().replace("key=[1,2]", &format!("key={key:?}"));
    assert!(RetirementRecordCandidate::parse("public", &name(&key), bytes.as_bytes()).is_err());
}

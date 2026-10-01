//! Compares local-v1 codecs with the independently registered normative bytes.
//!
//! Fixtures are copied verbatim from reference/golden-vectors.md. Regenerate only
//! by copying the reviewed reference hex; never use these codecs to produce them.

#![allow(
    clippy::unwrap_used,
    reason = "Golden byte assertions must fail visibly."
)]

use super::*;

fn bytes(hex: &str) -> Vec<u8> {
    let compact: String = hex
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("Invalid reviewed hex fixture"),
            };
            nibble(pair[0]) * 16 + nibble(pair[1])
        })
        .collect()
}

const OPERATION_KEY: &str = "gc/7/delete/000102030405060708090a0b0c0d0e0f/404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

#[test]
fn gc_local_v1_golden_journals_preserve_registered_bytes_and_field_bounds() {
    let fixtures = [
        (
            "Creation journal pending",
            include_str!("vectors/creation_journal_pending.hex"),
            true,
        ),
        (
            "Creation journal invalidated",
            include_str!("vectors/creation_journal_invalidated.hex"),
            true,
        ),
        (
            "Creation journal pack committed",
            include_str!("vectors/creation_journal_pack_committed.hex"),
            true,
        ),
        (
            "Creation journal pack owned",
            include_str!("vectors/creation_journal_pack_owned.hex"),
            true,
        ),
        (
            "Creation journal index committed",
            include_str!("vectors/creation_journal_index_committed.hex"),
            true,
        ),
        (
            "Creation journal index owned",
            include_str!("vectors/creation_journal_index_owned.hex"),
            true,
        ),
        (
            "Creation journal trash committed",
            include_str!("vectors/creation_journal_trash_committed.hex"),
            true,
        ),
        (
            "Creation journal trash owned",
            include_str!("vectors/creation_journal_trash_owned.hex"),
            true,
        ),
        (
            "Creation journal identity empty",
            include_str!("vectors/creation_journal_identity_empty.hex"),
            false,
        ),
        (
            "Creation journal identity min",
            include_str!("vectors/creation_journal_identity_min.hex"),
            true,
        ),
        (
            "Creation journal identity max",
            include_str!("vectors/creation_journal_identity_max.hex"),
            true,
        ),
        (
            "Creation journal identity long",
            include_str!("vectors/creation_journal_identity_long.hex"),
            false,
        ),
    ];
    for (case, fixture, accepted) in fixtures {
        let encoded = bytes(fixture);
        let result = CreationJournal::decode(&encoded);
        assert_eq!(result.is_ok(), accepted, "{case}");
        if let Ok(record) = result {
            assert_eq!(record.encode().unwrap(), encoded, "{case}");
        }
    }
}

#[test]
fn gc_local_v1_golden_operations_preserve_authorization_and_distinct_epochs() {
    for fixture in [
        include_str!("vectors/delete_operation.hex"),
        include_str!("vectors/delete_operation_cancelled.hex"),
    ] {
        let encoded = bytes(fixture);
        let operation = DeleteOperation::decode(&encoded, OPERATION_KEY).unwrap();
        assert_eq!(operation.encode().unwrap(), encoded);
        assert_eq!(operation.authorization.epoch, 2);
        assert_eq!(operation.authorization.original_lease.epoch, 3);
        assert_eq!(operation.current_lease.epoch, 4);
        assert_eq!(
            operation.authorization.encode().unwrap(),
            bytes(include_str!("vectors/delete_authorization.hex"))
        );
        assert_eq!(
            operation.authorization.digest().unwrap(),
            unhex::<32>("a5802a8ed186b0f68a32c9277ac30f3a39b67941a548d96f2047c082903f6e8c")
                .unwrap()
        );
    }
    assert!(
        DeleteOperation::decode(
            &bytes(include_str!("vectors/delete_operation_null_lease.hex")),
            OPERATION_KEY
        )
        .is_err()
    );
}

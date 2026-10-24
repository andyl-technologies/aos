//! Checks inert trust-context schemas independently of runtime authority.

use super::*;
use crate::cbor;
use crate::provenance::Preset;
use alloc::{vec, vec::Vec};

const VIEW: [u8; 32] = [1; 32];
const DOMAIN: &str = "private:context";

fn bytes(value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    cbor::write_bytes(&mut encoded, value);
    encoded
}

fn text(value: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    cbor::write_text(&mut encoded, value);
    encoded
}

fn array(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut encoded = Vec::new();
    cbor::write_array(&mut encoded, fields.len());
    for field in fields {
        encoded.extend_from_slice(field);
    }
    encoded
}

fn location(commit: &[u8], path: &[u8]) -> Vec<u8> {
    array(&[bytes(commit), bytes(&[2; 32]), bytes(path)])
}

fn side_fields() -> Vec<Vec<u8>> {
    vec![
        bytes(&[3; 32]),
        bytes(&[4; 32]),
        text("hash.sha256"),
        text("sha256"),
        text("1"),
        bytes(&[0x00]),
        bytes(&[5; 32]),
        // Unsigned legacy evidence may authenticate a carrying commit whose
        // inline attribute origin names a different actual producer.
        location(&[6; 32], b"producer/file"),
        array(&[text(DOMAIN), bytes(b"producer/file")]),
    ]
}

fn row_fields(path: &[u8]) -> Vec<Vec<u8>> {
    vec![
        location(&VIEW, path),
        text("hash.sha256"),
        text(DOMAIN),
        bytes(path),
        array(&side_fields()),
    ]
}

fn context(rows: &[Vec<u8>]) -> Vec<u8> {
    array(&[
        vec![2],
        bytes(&VIEW),
        text(DOMAIN),
        bytes(Selector::preset(Preset::Strict).encode()),
        vec![0xf6],
        vec![0],
        bytes(&array(rows)),
    ])
}

fn check_row(fields: &[Vec<u8>]) -> Result<(), Rejected> {
    validate(&context(&[array(fields)]))
}

#[test]
fn prov_context_selected_rows_bind_view_domain_and_name() {
    let original = row_fields(b"file");
    assert_eq!(check_row(&original), Ok(()));
    assert_eq!(validate(&context(&[vec![0x01]])), Err(Rejected));
    assert_eq!(validate(&context(&[])), Err(Rejected));

    let mut wrong_view = original.clone();
    wrong_view[0] = location(&[9; 32], b"file");
    let mut wrong_domain = original.clone();
    wrong_domain[2] = text("private:other");
    let mut wrong_name = original.clone();
    wrong_name[1] = text("hash.sha512");
    let mut too_short = original.clone();
    too_short.pop();
    let mut too_long = original.clone();
    too_long.push(vec![0]);

    for fields in [wrong_view, wrong_domain, wrong_name, too_short, too_long] {
        assert_eq!(check_row(&fields), Err(Rejected));
    }
    for count in [8, 10] {
        let mut fields = original.clone();
        let mut side = side_fields();
        side.resize(count, vec![0]);
        fields[4] = array(&side);
        assert_eq!(check_row(&fields), Err(Rejected), "side width {count}");
    }
}

#[test]
fn prov_context_selected_evidence_enforces_path_and_digest_limits() {
    let original = row_fields(b"file");
    for length in [31, 33] {
        for field in [0, 1, 6] {
            let mut row = original.clone();
            let mut side = side_fields();
            side[field] = bytes(&vec![3; length]);
            row[4] = array(&side);
            assert_eq!(check_row(&row), Err(Rejected), "digest {field}/{length}");
        }
    }

    let mut maximum_path = vec![b'a'; 240];
    for _ in 0..16 {
        maximum_path.push(b'/');
        maximum_path.extend_from_slice(&[b'b'; 240]);
    }
    assert_eq!(maximum_path.len(), tree_format::MAX_KEY);
    assert_eq!(check_row(&row_fields(&maximum_path)), Ok(()));
    assert_eq!(check_row(&row_fields(&[b'a'; 255])), Ok(()));

    let paths = [
        vec![],
        b"/file".to_vec(),
        b"file/".to_vec(),
        b"a//b".to_vec(),
        b"a/./b".to_vec(),
        b"a/../b".to_vec(),
        b"a\0b".to_vec(),
        vec![b'a'; 256],
        [maximum_path.as_slice(), b"x"].concat(),
    ];
    for path in paths {
        assert_eq!(check_row(&row_fields(&path)), Err(Rejected));
        let mut row = original.clone();
        row[3] = bytes(&path);
        assert_eq!(check_row(&row), Err(Rejected));
        let mut side = side_fields();
        side[7] = location(&[6; 32], &path);
        row = original.clone();
        row[4] = array(&side);
        assert_eq!(check_row(&row), Err(Rejected));
        side = side_fields();
        side[8] = array(&[text(DOMAIN), bytes(&path)]);
        row[4] = array(&side);
        assert_eq!(check_row(&row), Err(Rejected));
    }
}

#[test]
fn prov_context_selected_values_and_order_require_canonical_encoding() {
    let first = array(&row_fields(b"a"));
    let second = array(&row_fields(b"b"));
    assert_eq!(validate(&context(&[first.clone(), second.clone()])), Ok(()));
    assert_eq!(
        validate(&context(&[first.clone(), first.clone()])),
        Err(Rejected)
    );
    assert_eq!(validate(&context(&[second, first])), Err(Rejected));

    for value in [
        vec![],
        vec![0x18, 0x00],
        vec![0x00, 0x00],
        vec![0x9f, 0x00, 0xff],
        vec![0xa2, 0x01, 0x00, 0x00, 0x00],
    ] {
        let mut fields = row_fields(b"file");
        let mut side = side_fields();
        side[5] = bytes(&value);
        fields[4] = array(&side);
        assert_eq!(check_row(&fields), Err(Rejected), "value {value:?}");
    }
}

#[test]
fn prov_context_rejects_truncated_and_excessive_claims() {
    let encoded = context(&[array(&row_fields(b"file"))]);
    assert_eq!(validate(&encoded), Ok(()));
    for length in 0..encoded.len() {
        assert_eq!(
            validate(&encoded[..length]),
            Err(Rejected),
            "prefix {length}"
        );
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(validate(&trailing), Err(Rejected));

    // These tiny inputs claim impossible container/text/byte-string lengths.
    // Rejection cannot allocate the advertised u64::MAX bytes or rows.
    let mut fields = row_fields(b"file");
    fields[4] = [vec![0x9b], vec![0xff; 8]].concat();
    assert_eq!(check_row(&fields), Err(Rejected));
    let mut side = side_fields();
    side[0] = [vec![0x5b], vec![0xff; 8]].concat();
    fields[4] = array(&side);
    assert_eq!(check_row(&fields), Err(Rejected));
    let mut fields = row_fields(b"file");
    fields[1] = [vec![0x7b], vec![0xff; 8]].concat();
    assert_eq!(check_row(&fields), Err(Rejected));
}

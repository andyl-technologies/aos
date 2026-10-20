//! Constructs plaintext, descriptor, inline-entry and leaf models independently.
//!
//! ```text
//! entry = {1: 1, 2: 420, 3: 15, 4: [0, chunk_digest]}
//! leaf = {1: 0, 2: [[h'hello.txt', 0, entry]]}
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "normative fixtures must match the independent models"
)]

use super::support::{
    self, REFERENCE, Value, blocks, changed, hexadecimal, section, table, unquote,
};
use terrane_format::{
    identity::{Descriptor, Digest, IdentityKind, TERRANE_V1},
    tree_format::{
        ContentRef, Entry, EntryKind, LeafItem, Node, NodeItems, decode_entry_bytes, decode_node,
        encode_entry, encode_node,
    },
};

/// Computes identity with the raw primitive and an independently selected domain.
pub(super) fn identity(domain: &str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Constructs the complete public inline-file model without decoding a fixture.
pub(super) fn entry() -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 15,
            content: ContentRef::Inline(identity("terrane-chunk-v1", b"hello, terrane\n")),
            link_id: None,
        },
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

/// Constructs primitive entry fields independently of the typed entry model.
pub(super) fn entry_fields() -> Value {
    Value::Map(vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(420)),
        (3, Value::Uint(15)),
        (
            4,
            Value::Array(vec![
                Value::Uint(0),
                Value::Bytes(identity("terrane-chunk-v1", b"hello, terrane\n").to_vec()),
            ]),
        ),
    ])
}

/// Constructs the full-key item, including its uncompressed prefix count.
pub(super) fn item_fields() -> Value {
    Value::Array(vec![
        Value::Bytes(b"hello.txt".to_vec()),
        Value::Uint(0),
        entry_fields(),
    ])
}

fn chunk_rows(source: &str) -> Result<bool, String> {
    let rows = table(
        section(source, "Chunk identities")?,
        "| Input | Identity |",
        2,
    )?;
    let models: [(&str, &[u8]); 2] = [
        ("empty (CDC-5)", b""),
        ("`hello, terrane\\n` (15 bytes)", b"hello, terrane\n"),
    ];
    if rows.len() != models.len() {
        return Ok(false);
    }
    for (row, (label, plaintext)) in rows.iter().zip(models) {
        let expected = hexadecimal(unquote(row[1])?)?;
        let independent = identity("terrane-chunk-v1", plaintext);
        let owning = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .map_err(|error| error.to_string())?
            .terrane_v1_digest()
            .map_err(|error| error.to_string())?;
        if row[0] != label || expected != independent || owning != independent {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Executes both published chunk identities and all corresponding mutation controls.
///
/// # Panics
/// Panics if a reference field is absent, duplicated, malformed or mismatched.
pub(super) fn check_chunks() {
    assert!(chunk_rows(REFERENCE).unwrap());
    let body = section(REFERENCE, "Chunk identities").unwrap();
    for row in table(body, "| Input | Identity |", 2).unwrap() {
        let original = unquote(row[1]).unwrap();
        let replacement = format!(
            "{}{}",
            if original.starts_with('0') { "1" } else { "0" },
            &original[1..]
        );
        let modified = changed(body, original, &replacement);
        assert!(!chunk_rows(&format!("## Chunk identities\n{modified}")).unwrap());
    }

    assert!(section(REFERENCE, "absent witness").is_err());
    assert!(
        section(
            &format!("{REFERENCE}\n## Chunk identities\n"),
            "Chunk identities"
        )
        .is_err()
    );
    assert!(section(&REFERENCE.replace('\n', "\r\n"), "Chunk identities").is_err());
    let interrupted = "## Chunk identities\n\n## interruption\n";
    assert!(chunk_rows(interrupted).is_err());
    assert_eq!(
        section(
            &format!("## earlier\nother\n## Chunk identities\n{body}\n## later\nother\n"),
            "Chunk identities"
        )
        .unwrap()
        .trim_end_matches('\n'),
        body.trim_end_matches('\n')
    );

    let plaintext = b"hello, terrane\n";
    let digest = identity("terrane-chunk-v1", plaintext);
    let descriptor_fields = Value::Array(vec![
        Value::Text("blake3".into()),
        Value::Text("terrane-chunk-v1".into()),
        Value::Bytes(digest.to_vec()),
        Value::Uint(15),
    ]);
    let descriptor =
        Descriptor::from_wire(&TERRANE_V1, "blake3", "terrane-chunk-v1", &digest, 15).unwrap();
    let descriptor_body = section(REFERENCE, "Descriptor").unwrap();
    let published = hexadecimal(blocks(descriptor_body, "hex", 1).unwrap()[0]).unwrap();
    assert_eq!(descriptor_fields.encode(), published);
    assert_eq!(descriptor.encode(), published);
    assert_eq!(
        Descriptor::decode(&TERRANE_V1, &published).unwrap(),
        descriptor
    );
    assert_eq!(
        descriptor.to_string(),
        support::literal_after(descriptor_body, "Display form: `").unwrap()
    );
}

/// Executes the standalone entry and complete leaf with primitive and typed models.
///
/// # Panics
/// Panics if published bytes, decoded models or the node identity disagree.
pub(super) fn check_entry_and_leaf() {
    let body = section(REFERENCE, "Leaf node with one inline file").unwrap();
    let wires = blocks(body, "hex", 2).unwrap();
    let entry_wire = hexadecimal(wires[0]).unwrap();
    let leaf_wire = hexadecimal(wires[1]).unwrap();
    let model = entry();
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"hello.txt".to_vec(),
            entry: entry(),
        }]),
        props: None,
    };
    let primitive = Value::Map(vec![
        (1, Value::Uint(0)),
        (2, Value::Array(vec![item_fields()])),
    ]);

    assert_eq!(entry_fields().encode(), entry_wire);
    assert_eq!(encode_entry(&model, 262_144).unwrap(), entry_wire);
    assert_eq!(decode_entry_bytes(&entry_wire, 262_144).unwrap(), model);
    assert_eq!(primitive.encode(), leaf_wire);
    assert_eq!(encode_node(&node, true, 262_144).unwrap(), leaf_wire);
    assert_eq!(decode_node(&leaf_wire, true, 262_144).unwrap(), node);
    let rows = table(body, "| Quantity | Value |", 2).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0][0], "node identity (domain `terrane-node-v1`)");
    let expected = hexadecimal(unquote(rows[0][1]).unwrap()).unwrap();
    let independent = identity("terrane-node-v1", &primitive.encode());
    assert_eq!(expected, independent);
    let identity_literal = unquote(rows[0][1]).unwrap();
    let altered_identity = format!(
        "`{}{}`",
        if identity_literal.starts_with('0') {
            "1"
        } else {
            "0"
        },
        &identity_literal[1..]
    );
    let altered = changed(body, rows[0][1], &altered_identity);
    let observed = table(&altered, "| Quantity | Value |", 2).unwrap();
    assert_ne!(
        hexadecimal(unquote(observed[0][1]).unwrap()).unwrap(),
        independent
    );
    assert_eq!(
        TERRANE_V1
            .calculate(IdentityKind::Node, &leaf_wire)
            .unwrap()
            .terrane_v1_digest()
            .unwrap(),
        independent
    );

    for (wire, fields) in [(wires[0], entry_fields()), (wires[1], primitive)] {
        let altered = changed(body, wire, &format!("00{}", &wire[2..]));
        let parsed = blocks(&altered, "hex", 2).unwrap();
        assert_ne!(
            hexadecimal(parsed[usize::from(wire == wires[1])]).unwrap(),
            fields.encode()
        );
    }
    for cut in 0..entry_wire.len() {
        assert!(decode_entry_bytes(&entry_wire[..cut], 262_144).is_err());
    }
    for cut in 0..leaf_wire.len() {
        assert!(decode_node(&leaf_wire[..cut], true, 262_144).is_err());
    }
    // Independent primitive headers isolate nonminimal lengths and trailing data.
    let mut nonminimal_entry = vec![0xb8, 4];
    nonminimal_entry.extend_from_slice(&entry_fields().encode()[1..]);
    assert!(decode_entry_bytes(&nonminimal_entry, 262_144).is_err());
    let mut nonminimal_leaf = vec![0xb8, 2];
    nonminimal_leaf.extend_from_slice(
        &Value::Map(vec![
            (1, Value::Uint(0)),
            (2, Value::Array(vec![item_fields()])),
        ])
        .encode()[1..],
    );
    assert!(decode_node(&nonminimal_leaf, true, 262_144).is_err());
    let mut trailing = entry_fields().encode();
    trailing.push(0);
    assert!(decode_entry_bytes(&trailing, 262_144).is_err());
}

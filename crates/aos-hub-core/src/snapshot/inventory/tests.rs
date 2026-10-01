//! Contract, confidentiality and exact encrypted-projection rejection tests.

use std::io::Cursor;

use crate::snapshot::archive::records::DatabaseCaptureCounts;
use crate::snapshot::archive::root::{
    ArchiveSignerTrust, ArchiveSigningKey, ArchiveWrappingKey, ArchiveWrappingKeys,
};
use crate::snapshot::archive::{StreamDecoder, StreamLimits, StreamRole};
use crate::value::{Row, Value};

use super::*;

fn columns(table: &str) -> Vec<String> {
    SOURCE
        .lines()
        .filter(|line| line.starts_with(&format!("{table}\t")))
        .map(|line| line.split('\t').nth(2).unwrap().to_owned())
        .collect()
}

fn row(table: &str) -> Row {
    Row::new(
        SOURCE
            .lines()
            .filter(|line| line.starts_with(&format!("{table}\t")))
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                let value = match fields[3] {
                    "integer" => Value::Int(1),
                    "text" => Value::Text("fixture".into()),
                    "bytes" => Value::Bytes(vec![1]),
                    _ => panic!("unexpected storage"),
                };
                value
            })
            .collect(),
    )
}

#[test]
fn coverage_requires_every_exact_column_and_never_projects_raw_private_cells() {
    let coverage = ObjectRequirementsCoverage::current8().unwrap();
    assert_eq!(coverage.tables.len(), 279);
    assert!(
        ObjectRequirementsCoverage::from_contract(&COVERAGE.replacen(
            "audit_log\tid",
            "audit_log\tunknown",
            1
        ))
        .is_err()
    );
    assert!(
        ObjectRequirementsCoverage::from_contract(&COVERAGE.replacen(
            "secret_excluded",
            "value",
            1
        ))
        .is_err()
    );
    assert!(ObjectRequirementsCoverage::from_contract(
        &COVERAGE.lines().skip(3).collect::<Vec<_>>().join("\n")
    )
    .is_err());
    let historical = SnapshotClassifier::for_supported_generation(7).unwrap();
    assert!(coverage.require_schema(historical.manifest()).is_err());

    let mut original = row("tokens");
    // Both the secret hash and opaque permission original must be absent from
    // plaintext requirements, even inside their independently encrypted stream.
    original = Row::new(
        columns("tokens")
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let value = if name == "comment" {
                    Value::Null
                } else if name == "hash" || name == "permissions" {
                    Value::Text("PRIVATE-SECRET-AND-OPAQUE-ORIGINAL".into())
                } else {
                    original.value(index).unwrap().clone()
                };
                value
            })
            .collect(),
    );
    let mut counts = ObjectRequirementsCounts::default();
    let projection = coverage
        .project("tokens", 0, &original, &mut counts, Default::default())
        .unwrap()
        .unwrap();
    let encoded = bytes(&projection).unwrap();
    assert!(!encoded
        .windows(b"PRIVATE-SECRET-AND-OPAQUE-ORIGINAL".len())
        .any(|part| part == b"PRIVATE-SECRET-AND-OPAQUE-ORIGINAL"));
    let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert!(json["cells"]
        .as_array()
        .unwrap()
        .iter()
        .all(|cell| cell["column"] != "hash"));
    assert_eq!(counts.excluded_secret_cells, 1);
    assert_eq!(counts.opaque_dependencies, 1);
}

#[test]
fn projection_bounds_and_original_ordinals_refuse_without_implicit_truncation() {
    let coverage = ObjectRequirementsCoverage::current8().unwrap();
    let original = row("surface_objects");
    let mut counts = ObjectRequirementsCounts::default();
    assert!(coverage
        .project(
            "surface_objects",
            1,
            &original,
            &mut counts,
            Default::default()
        )
        .is_err());
    let mut counts = ObjectRequirementsCounts::default();
    let limits = ObjectRequirementsLimits { max_rows: 1 };
    assert!(coverage
        .project("surface_objects", 0, &original, &mut counts, limits)
        .unwrap()
        .is_some());
    assert!(coverage
        .project("surface_objects", 1, &original, &mut counts, limits)
        .is_err());
    let wide = Row::new(
        columns("surface_objects")
            .iter()
            .enumerate()
            .map(|(i, name)| {
                if name == "object_key" {
                    Value::Text("x".repeat(RECORD_BYTES))
                } else {
                    original.value(i).unwrap().clone()
                }
            })
            .collect(),
    );
    assert!(coverage
        .project(
            "surface_objects",
            0,
            &wide,
            &mut Default::default(),
            Default::default()
        )
        .is_err());
    assert!(coverage
        .project(
            "unknown",
            0,
            &original,
            &mut Default::default(),
            Default::default()
        )
        .is_err());
}

#[test]
fn paired_encrypted_requirements_bind_exact_source_and_reject_changed_original() {
    let signer = ArchiveSigningKey::from_seed("test-export", [21; 32]).unwrap();
    let wrapping = ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes("m", [22; 32]).unwrap(),
        ArchiveWrappingKey::from_bytes("p", [23; 32]).unwrap(),
    )
    .unwrap();
    let trust = ArchiveSignerTrust::new([(signer.id().into(), signer.public_key())]).unwrap();
    let source = "a".repeat(64);
    let mut writer = ObjectRequirementsWriter::new(
        Vec::new(),
        Vec::new(),
        &source,
        &signer,
        &wrapping,
        &[],
        &mut rand::rngs::OsRng,
        StreamLimits::default(),
        Default::default(),
    )
    .unwrap();
    let schema = SnapshotClassifier::for_supported_generation(8).unwrap();
    writer.require_schema(schema.manifest()).unwrap();
    let original = row("surface_objects");
    writer.row("surface_objects", 0, &original).unwrap();
    let counts = DatabaseCaptureCounts {
        retained_rows: 1,
        ..Default::default()
    };
    let output = writer.finish(&signer, &counts).unwrap();
    let make = || {
        ObjectRequirementsReader::new(
            output.root.as_bytes(),
            &trust,
            &wrapping,
            &[],
            Cursor::new(&output.metadata),
            Cursor::new(&output.private),
            &source,
            StreamLimits::default(),
            Default::default(),
        )
        .unwrap()
    };
    let mut reader = make();
    reader.require_schema(schema.manifest()).unwrap();
    reader.row("surface_objects", 0, &original).unwrap();
    assert_eq!(reader.finish(&counts).unwrap(), output.counts);
    let changed = Row::new(
        columns("surface_objects")
            .iter()
            .enumerate()
            .map(|(i, name)| {
                if name == "object_key" {
                    Value::Text("different-incarnation-key".into())
                } else {
                    original.value(i).unwrap().clone()
                }
            })
            .collect(),
    );
    let mut rejected = make();
    assert!(rejected.row("surface_objects", 0, &changed).is_err());
    assert!(rejected.row("surface_objects", 1, &original).is_err());
    assert!(rejected.finish(&counts).is_err());

    let mut rejected_writer = ObjectRequirementsWriter::new(
        Vec::new(),
        Vec::new(),
        &source,
        &signer,
        &wrapping,
        &[],
        &mut rand::rngs::OsRng,
        StreamLimits::default(),
        Default::default(),
    )
    .unwrap();
    assert!(rejected_writer.row("unknown", 0, &original).is_err());
    assert!(rejected_writer.finish(&signer, &counts).is_err());
    assert!(ObjectRequirementsReader::new(
        output.root.as_bytes(),
        &trust,
        &wrapping,
        &[],
        Cursor::new(&output.metadata),
        Cursor::new(&output.private),
        &"b".repeat(64),
        StreamLimits::default(),
        Default::default()
    )
    .is_err());
    let mut damaged = output.private.clone();
    damaged.truncate(damaged.len() - 1);
    let mut reader = ObjectRequirementsReader::new(
        output.root.as_bytes(),
        &trust,
        &wrapping,
        &[],
        Cursor::new(&output.metadata),
        Cursor::new(damaged),
        &source,
        StreamLimits::default(),
        Default::default(),
    )
    .unwrap();
    reader.row("surface_objects", 0, &original).unwrap();
    assert!(reader.finish(&counts).is_err());

    // Inspect actual decrypted inner framing without exporting it: storage
    // readiness and activation are fixed pending contracts, never true flags.
    let root = crate::snapshot::archive::root::verify_declared_root(output.root.as_bytes(), &trust)
        .unwrap();
    let (_, key) = root
        .unwrap_reader_keys(&wrapping, &[])
        .unwrap()
        .into_role_keys();
    let mut decoder = StreamDecoder::new(
        Cursor::new(&output.private),
        key,
        root.stream_context(StreamRole::Private),
        StreamLimits::default(),
    )
    .unwrap();
    let first = decoder.next_chunk().unwrap().unwrap();
    first.with_private_bytes(|bytes| {
        assert!(std::str::from_utf8(bytes)
            .unwrap()
            .contains("old_writer_fencing"))
    });
}

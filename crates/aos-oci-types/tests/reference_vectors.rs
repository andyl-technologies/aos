//! Shared Nix/Rust canonical-reference vectors.

#![allow(clippy::expect_used)]

use aos_oci_types::{ManifestReference, RepositoryName, Tag};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceVectors {
    repositories: AcceptedRejected,
    tags: AcceptedRejected,
    tagged_references: AcceptedRejected,
    manifest_references: AcceptedRejected,
}

#[derive(Deserialize)]
struct AcceptedRejected {
    valid: Vec<String>,
    invalid: Vec<String>,
}

#[test]
fn nix_and_rust_reference_parsers_share_vectors() {
    let vectors: ReferenceVectors = serde_json::from_str(include_str!("reference-vectors.json"))
        .expect("reference vectors must be valid JSON");

    assert_vectors(&vectors.repositories, RepositoryName::parse);
    assert_vectors(&vectors.tags, Tag::parse);
    assert_vectors(&vectors.manifest_references, ManifestReference::parse);
    assert_vectors(&vectors.tagged_references, |value| {
        let (repository, tag) = value
            .split_once(':')
            .ok_or_else(|| "missing tag separator".to_string())?;
        RepositoryName::parse(repository).map_err(|error| error.to_string())?;
        Tag::parse(tag).map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    });
}

fn assert_vectors<T, E>(vectors: &AcceptedRejected, parser: impl Fn(&str) -> Result<T, E>) {
    for value in &vectors.valid {
        assert!(
            parser(value).is_ok(),
            "rejected shared valid vector {value}"
        );
    }
    for value in &vectors.invalid {
        assert!(
            parser(value).is_err(),
            "accepted shared invalid vector {value}"
        );
    }
}

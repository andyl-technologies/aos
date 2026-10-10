//! Checks the closed metadata roster without deriving native authority from bytes.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Synthetic closed-codec controls deliberately fail on an altered original role or credit.
#![allow(clippy::unwrap_used)]

use super::*;

fn original() -> MetadataClosure {
    let record = Record {
        schema: "crucible.independent-group.metadata.v1",
        members: vec![Member {
            reference: canonical::content_ref(b"opaque source-owned definition", "text/plain")
                .unwrap(),
            role: MetadataRole::SourceDefinition,
        }],
    };
    let body = canonical::canonical_json(&serde_json::to_value(&record).unwrap()).unwrap();
    MetadataClosure {
        root: canonical::content_ref(&body, "application/json").unwrap(),
        body,
        members: record.members,
    }
}

#[test]
fn exact_root_is_complete_and_role_is_independent_of_media_shape() {
    let original = original();
    let edges = original
        .dependencies(&original.root, &original.body, 1)
        .unwrap();

    assert_eq!(edges, vec![original.members[0].reference.clone()]);
    assert!(
        original
            .dependencies(&original.root, &original.body, 0)
            .is_err()
    );
    assert!(
        original
            .dependencies(&edges[0], b"opaque source-owned definition", 0)
            .unwrap()
            .is_empty()
    );

    let mut foreign_media = edges[0].clone();
    foreign_media.media_type = "application/json".into();
    assert_eq!(foreign_media.hash, edges[0].hash);
    assert!(
        original
            .dependencies(&foreign_media, b"opaque source-owned definition", 1)
            .is_err()
    );
}

#[test]
fn rehashed_omission_foreign_member_or_role_cannot_replace_original_root() {
    let original = original();
    let value = serde_json::from_slice::<serde_json::Value>(&original.body).unwrap();
    let mut omitted = value.clone();
    omitted["members"] = serde_json::json!([]);
    let mut foreign = value.clone();
    foreign["members"][0]["reference"] = serde_json::to_value(
        canonical::content_ref(b"foreign unqualified object", "text/plain").unwrap(),
    )
    .unwrap();
    let mut role = value;
    role["members"][0]["role"] = "native_authority".into();

    for changed in [omitted, foreign, role] {
        let body = canonical::canonical_json(&changed).unwrap();
        let rehashed = canonical::content_ref(&body, "application/json").unwrap();
        rehashed.verify(&body).unwrap();
        assert!(original.dependencies(&rehashed, &body, 1).is_err());
        assert!(original.dependencies(&original.root, &body, 1).is_err());
    }
}

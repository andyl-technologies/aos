//! Exercises native pack/index creation without importing collector authority.
//!
//! Every top-level witness invokes genuine ContentStore writers against native
//! initialized storage. Focused helpers retain the real fault/control matrices.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

#[path = "creation_tests/faults.rs"]
mod faults;
#[path = "creation_tests/support.rs"]
mod support;

use crate::store::{
    ChunkPosition, ChunkUpload, ContentStore, ContentUpload, MetaUpload, TokioClock,
};
use support::*;
use terrane_format::gc::{CreationJournal, JournalState};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn native_creation_commits_pack_and_index_from_real_container_writers() {
    let fixture = support::fixture().await;
    let plaintext = b"native individually admitted chunk";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let mut encoded = vec![0];
    encoded.extend(plaintext);
    let chunk = fixture
        .bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &fixture.config.chunk_profile,
        }))
        .await
        .unwrap();
    assert_eq!(fixture.bucket.get(&chunk, None).await.unwrap(), encoded);

    let tree = terrane_format::tree_builder::Tree::build(
        Vec::new(),
        None,
        262144,
        terrane_format::tree_format::TreeUse::Ordinary,
    )
    .unwrap();
    let node = fixture
        .bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Node, tree.root().encoded()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        fixture.bucket.get(&node, None).await.unwrap(),
        tree.root().encoded()
    );
    let imported = support::pack().await;
    let whole = put(&fixture.bucket, &imported).await.unwrap();
    assert_eq!(
        fixture.bucket.get(&whole, None).await.unwrap(),
        imported.bytes()
    );
    let index = TERRANE_V1
        .calculate(IdentityKind::Index, imported.index_object())
        .unwrap();
    assert_eq!(
        fixture.bucket.get(&index, None).await.unwrap(),
        imported.index_object()
    );

    let rows = inventory(fixture.bucket.root()).await;
    assert_eq!(rows.len(), 3);
    let mut incarnation_nonces = std::collections::BTreeSet::new();
    for row in &rows {
        let id = crate::pack::PackId::from_random_bytes(row.pack_id);
        for (key, digest, size) in [
            (id.pack_key(), row.pack_hash, row.pack_size),
            (id.index_key(), row.index_hash, row.index_size),
        ] {
            let bytes = tokio::fs::read(fixture.bucket.root().join(&key))
                .await
                .unwrap();
            let kind = if key.ends_with(".pack") {
                IdentityKind::Pack
            } else {
                IdentityKind::Index
            };
            assert_eq!(
                TERRANE_V1
                    .calculate(kind, &bytes)
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
                digest
            );
            assert_eq!(bytes.len() as u64, size);
            let record = assert_committed(&fixture, &key, &bytes).await;
            assert!(incarnation_nonces.insert(record.nonce));
        }
    }
    assert_eq!(incarnation_nonces.len(), 6);
    let effects = fixture.fs.effects();
    assert_eq!(
        effects
            .iter()
            .filter(|kind| matches!(kind, Kind::Pending(_)))
            .count(),
        6
    );
    assert_eq!(
        effects
            .iter()
            .filter(|kind| matches!(kind, Kind::Seal(_)))
            .count(),
        6
    );
    assert_eq!(
        effects
            .iter()
            .filter(|kind| matches!(kind, Kind::Commit(_)))
            .count(),
        6
    );
    assert_eq!(fixture.fs.ordinary_writes(), 0);
    let mut staged = 0;
    for kind in &effects {
        if let Kind::Write(path) = kind
            && let Some(suffix) = path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix(".terrane-tmp:")
        {
            assert_eq!(suffix.len(), 32);
            assert!(
                suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            staged += 1;
        }
    }
    assert!(staged > 0);
    let keys: Vec<_> = rows
        .iter()
        .flat_map(|row| {
            let id = crate::pack::PackId::from_random_bytes(row.pack_id);
            [id.pack_key(), id.index_key()]
        })
        .collect();
    let journals = journal_images(&fixture, &keys).await;
    let before_cap = tokio::fs::read(fixture.bucket.root().join("CAPABILITIES"))
        .await
        .unwrap();
    let before_pointer = tokio::fs::read(fixture.bucket.root().join("publication/PORTABLE"))
        .await
        .unwrap();
    fixture.fs.clear();
    let reopened = crate::bucket::FileBucket::open(
        fixture.config.clone(),
        fixture.fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_current_open(&fixture, &before_cap, &before_pointer).await;
    assert_eq!(journal_images(&fixture, &keys).await, journals);
    assert_eq!(inventory(reopened.root()).await, rows);
    assert_eq!(reopened.get(&chunk, None).await.unwrap(), encoded);
    assert_eq!(
        reopened.get(&node, None).await.unwrap(),
        tree.root().encoded()
    );
    assert_eq!(reopened.get(&whole, None).await.unwrap(), imported.bytes());
}

#[tokio::test]
async fn native_creation_selects_pending_before_any_artifact_mutation() {
    faults::pending_order_and_closed_results().await;
}

#[tokio::test]
async fn native_creation_preserves_imported_unknown_and_existing_versions() {
    let fixture = support::fixture().await;
    let pack = support::pack().await;
    unselected(&fixture, &pack).await;
    let id = pack.header().id();
    let keys = [id.pack_key(), id.index_key()];
    let original: Vec<_> = journal_images(&fixture, &keys).await;
    fixture.fs.clear();
    put(&fixture.bucket, &pack).await.unwrap();
    assert_eq!(journal_images(&fixture, &keys).await, original);
    assert!(
        !fixture
            .fs
            .effects()
            .iter()
            .any(|kind| matches!(kind, Kind::Pending(_) | Kind::Seal(_) | Kind::Commit(_)))
    );

    // Recreate the real unselected baseline for each valid old-record state.
    for state in [
        None,
        Some(JournalState::Pending),
        Some(JournalState::Invalidated),
    ] {
        let fixture = support::fixture().await;
        let pack = support::pack().await;
        unselected(&fixture, &pack).await;
        let keys = [
            pack.header().id().pack_key(),
            pack.header().id().index_key(),
        ];
        for key in &keys {
            let path = journal(&fixture.control, key);
            if let Some(state) = &state {
                let mut record =
                    CreationJournal::decode(&tokio::fs::read(&path).await.unwrap()).unwrap();
                record.state = state.clone();
                tokio::fs::write(path, record.encode().unwrap())
                    .await
                    .unwrap();
            } else {
                tokio::fs::remove_file(path).await.unwrap();
            }
        }
        let before = image(&fixture.control).await;
        fixture.fs.clear();
        put(&fixture.bucket, &pack).await.unwrap();
        let after = image(&fixture.control).await;
        for key in &keys {
            let relative = journal(&fixture.control, key)
                .strip_prefix(&fixture.control)
                .unwrap()
                .to_owned();
            assert_eq!(after.get(&relative), before.get(&relative));
        }
        assert!(
            !fixture
                .fs
                .effects()
                .iter()
                .any(|kind| matches!(kind, Kind::Pending(_) | Kind::Seal(_) | Kind::Commit(_)))
        );
    }
    faults::copied_payload_has_no_creation_authority().await;
}

async fn journal_images(fixture: &Fixture, keys: &[String]) -> Vec<Vec<u8>> {
    let mut bytes = Vec::new();
    for key in keys {
        bytes.push(
            tokio::fs::read(journal(&fixture.control, key))
                .await
                .unwrap(),
        );
    }
    bytes
}

#[tokio::test]
async fn native_creation_recreation_uses_fresh_nonce_for_equal_bytes() {
    use std::os::unix::fs::MetadataExt;
    let fixture = support::fixture().await;
    let pack = support::pack().await;
    unselected(&fixture, &pack).await;
    let keys = [
        pack.header().id().pack_key(),
        pack.header().id().index_key(),
    ];
    let mut previous = Vec::new();
    // Hold old descriptors, so actual fresh creations cannot accidentally reuse
    // their inodes; nonce checks remain independent of that physical fact.
    let mut retained = Vec::new();
    for key in &keys {
        let path = fixture.bucket.root().join(key);
        retained.push(std::fs::File::open(&path).unwrap());
        previous.push(
            CreationJournal::decode(
                &tokio::fs::read(journal(&fixture.control, key))
                    .await
                    .unwrap(),
            )
            .unwrap(),
        );
        tokio::fs::remove_file(path).await.unwrap();
    }
    fixture.fs.clear();
    put(&fixture.bucket, &pack).await.unwrap();
    for (position, (key, body)) in keys
        .iter()
        .zip([pack.bytes(), pack.index_object()])
        .enumerate()
    {
        let fresh = assert_committed(&fixture, key, body).await;
        assert_ne!(fresh.nonce, previous[position].nonce);
        let old = retained[position].metadata().unwrap();
        let new = std::fs::symlink_metadata(fixture.bucket.root().join(key)).unwrap();
        assert_ne!((old.dev(), old.ino()), (new.dev(), new.ino()));
        assert_eq!(
            tokio::fs::read(fixture.bucket.root().join(key))
                .await
                .unwrap(),
            body
        );
    }
    faults::fresh_nonce_collision_refuses_without_artifact_mutation().await;
}

#[tokio::test]
async fn native_creation_refuses_owned_journals_and_invalid_preimages() {
    faults::owned_and_invalid_preimages().await;
    faults::retained_handoff_replacements().await;
}

#[tokio::test]
async fn native_creation_sync_failures_never_acknowledge_unqualified_versions() {
    faults::durability_fault_matrix().await;
}

#[tokio::test]
async fn native_creation_cancellation_retains_actual_exclusion_through_completion() {
    faults::cancellation_retains_exclusion().await;
}

#[tokio::test]
async fn native_creation_readonly_and_unavailable_retention_create_nothing() {
    faults::readonly_and_retention().await;
}

#[tokio::test]
async fn native_creation_keys_remain_external_and_exactly_associated() {
    let fixture = support::fixture().await;
    let pack = support::pack().await;
    put(&fixture.bucket, &pack).await.unwrap();
    assert!(!fixture.control.starts_with(fixture.bucket.root()));
    assert!(!fixture.bucket.root().join(".terrane-creation").exists());
    let root_image = image(fixture.bucket.root()).await;
    assert!(
        root_image
            .keys()
            .all(|key| !key.starts_with(".terrane-creation"))
    );
    let mut entries = tokio::fs::read_dir(fixture.control.join(".terrane-creation"))
        .await
        .unwrap();
    let mut names = std::collections::BTreeSet::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let record =
            CreationJournal::decode(&tokio::fs::read(entry.path()).await.unwrap()).unwrap();
        assert_eq!(entry.path(), journal(&fixture.control, &record.key));
        assert!(names.insert(record.key));
        assert!(
            terrane_format::bucket::BucketKey::parse(&format!(
                ".terrane-creation/{}",
                entry.file_name().to_str().unwrap()
            ))
            .is_err()
        );
    }
    assert_eq!(
        names,
        [
            pack.header().id().pack_key(),
            pack.header().id().index_key()
        ]
        .into_iter()
        .collect()
    );
    assert!(
        inventory(fixture.bucket.root())
            .await
            .iter()
            .all(|row| row.pack_id == *pack.header().id().as_bytes())
    );
}

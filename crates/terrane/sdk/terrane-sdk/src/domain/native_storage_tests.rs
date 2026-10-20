//! Exercises scoped records through independently registered native buckets.
//!
//! These storage fixtures use enforcement-layer decisions to isolate the
//! backend contract. Full current-authority disclosure belongs to the native
//! ref-admission fixtures, which independently exercise Guard and publication.

#![allow(
    clippy::unwrap_used,
    reason = "Isolated test setup and assertions intentionally panic."
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use terrane_format::{
    auth::Verb,
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
    refs::{Locality, RefRecord},
    tree_builder::Tree,
    tree_format::TreeUse,
};

use super::{DomainAccess, DomainBinding, DomainStore};
use crate::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    repository::MetadataValidator,
    store::{
        ChunkPosition, ChunkUpload, ContentStore, ContentUpload, LocalFs, MetaUpload,
        StoreErrorKind, TokioClock, TokioLocalFs,
    },
};

type Bucket = FileBucket<TokioLocalFs, TokioClock, MetadataValidator>;

fn decision(domain: &str, verb: Verb, readable: &[Identity]) -> DomainAccess {
    DomainAccess::authorized(
        DomainBinding {
            domain: domain.into(),
            reference: "refs/heads/main".into(),
            root: TERRANE_V1
                .calculate(IdentityKind::Node, b"decision binding")
                .unwrap(),
            path: b"/".to_vec(),
        },
        verb,
        "storage-fixture".into(),
        [1; 16],
    )
    .unwrap()
    .with_read_identities(readable.to_vec())
}

async fn configuration(
    root: PathBuf,
    control: PathBuf,
    profile: &ChunkProfile,
) -> FileBucketConfig {
    let metadata = TokioLocalFs
        .symlink_metadata(root.parent().unwrap())
        .await
        .unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);

    FileBucketConfig {
        root,
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: profile.clone(),
        locality: Locality::default(),
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid: metadata.uid(),
            control: Some(control),
        }),
    }
}

async fn open(config: &FileBucketConfig, domain: &str) -> DomainStore<Bucket> {
    let bucket = FileBucket::open(
        config.clone(),
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(config.chunk_profile.clone()),
    )
    .await
    .unwrap();

    DomainStore::new(domain.into(), bucket).unwrap()
}

async fn administration() -> PathBuf {
    let random = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = std::env::temp_dir().join(format!("terrane-domain-records-{suffix}"));
    TokioLocalFs.create_dir_new(&directory).await.unwrap();
    directory
}

async fn present(
    store: &DomainStore<Bucket>,
    readable: &DomainAccess,
    records: &[Identity],
    expected: bool,
) {
    assert_eq!(
        store.has(readable, records).await.unwrap(),
        vec![expected; records.len()]
    );
    assert_eq!(
        store.backend.has(records).await.unwrap(),
        vec![expected; records.len()]
    );
}

async fn cleanup(directory: &Path) {
    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn dom_dedup_scope_native_chunks_manifests_and_nodes_are_independent_after_reopen() {
    let directory = administration().await;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let first_config = configuration(
        directory.join("first"),
        directory.join("first-control"),
        &profile,
    )
    .await;
    let second_config = configuration(
        directory.join("second"),
        directory.join("second-control"),
        &profile,
    )
    .await;
    let first = open(&first_config, "private:first").await;
    let second = open(&second_config, "private:second").await;

    let plaintext = vec![b'd'; 32768];
    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .unwrap();
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks: vec![ChunkRef {
            digest: chunk.terrane_v1_digest().unwrap(),
            length: plaintext.len() as u64,
        }],
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(&profile)
    .unwrap();
    let node = Tree::build(
        Vec::new(),
        None,
        profile.minimum() as u64,
        TreeUse::Ordinary,
    )
    .unwrap()
    .root()
    .encoded()
    .to_vec();
    let identities = vec![
        chunk.clone(),
        TERRANE_V1
            .calculate(IdentityKind::Manifest, &manifest)
            .unwrap(),
        TERRANE_V1.calculate(IdentityKind::Node, &node).unwrap(),
    ];
    let first_read = decision(first.domain(), Verb::Read, &identities);
    let second_read = decision(second.domain(), Verb::Read, &identities);
    let upload_chunk = ContentUpload::Chunk(ChunkUpload {
        encoded: &encoded,
        identity: &chunk,
        declared_plaintext_len: plaintext.len(),
        position: ChunkPosition::Final,
        profile: &profile,
    });
    let uploads = [
        upload_chunk,
        ContentUpload::Meta(MetaUpload::new(IdentityKind::Manifest, &manifest).unwrap()),
        ContentUpload::Meta(MetaUpload::new(IdentityKind::Node, &node).unwrap()),
    ];

    for (upload, identity) in uploads.iter().zip(&identities) {
        let record = first
            .put_record(&decision(first.domain(), Verb::Commit, &[]), *upload)
            .await
            .unwrap();
        assert_eq!(record.identity(), identity);
        assert_eq!(record.domain(), "private:first");
    }
    present(&first, &first_read, &identities, true).await;
    present(&second, &second_read, &identities, false).await;

    // Existing bytes in the first namespace cannot satisfy the second manifest's
    // required chunk. Admission must establish its own verified dependency.
    assert!(
        second
            .put(&decision(second.domain(), Verb::Commit, &[]), uploads[1])
            .await
            .is_err()
    );
    for (upload, identity) in uploads.iter().zip(&identities) {
        let record = second
            .put_record(&decision(second.domain(), Verb::Commit, &[]), *upload)
            .await
            .unwrap();
        assert_eq!(record.identity(), identity);
        assert_eq!(record.domain(), "private:second");
    }
    present(&second, &second_read, &identities, true).await;

    for identity in &identities {
        assert!(matches!(
            second
                .get(&first_read, identity, None)
                .await
                .unwrap_err()
                .kind(),
            StoreErrorKind::Denied { .. }
        ));
        assert_eq!(
            first.get(&first_read, identity, None).await.unwrap(),
            second.get(&second_read, identity, None).await.unwrap()
        );
    }
    drop(first);
    drop(second);

    let first = open(&first_config, "private:first").await;
    let second = open(&second_config, "private:second").await;
    present(&first, &first_read, &identities, true).await;
    present(&second, &second_read, &identities, true).await;
    let hidden = decision(second.domain(), Verb::Read, &[]);
    assert_eq!(
        second.has(&hidden, &identities).await.unwrap(),
        vec![false; identities.len()]
    );
    for identity in &identities {
        assert_eq!(
            second
                .get(&hidden, identity, None)
                .await
                .unwrap_err()
                .kind(),
            &StoreErrorKind::Absent(identity.clone())
        );
    }

    drop(first);
    drop(second);
    cleanup(&directory).await;
}

#[tokio::test]
async fn dom_dedup_scope_native_disclosure_verifies_recompressed_plaintext() {
    let directory = administration().await;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let source_config = configuration(
        directory.join("source"),
        directory.join("source-control"),
        &profile,
    )
    .await;
    let destination_config = configuration(
        directory.join("destination"),
        directory.join("destination-control"),
        &profile,
    )
    .await;
    let source = open(&source_config, "private:source").await;
    let destination = open(&destination_config, "public").await;
    let plaintext = vec![b'r'; 32768];
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .unwrap();
    let mut raw = vec![0];
    raw.extend_from_slice(&plaintext);
    let compressed = crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, None).unwrap();
    assert_ne!(raw, compressed);
    let offer = |encoded| {
        ContentUpload::Chunk(ChunkUpload {
            encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &profile,
        })
    };
    source
        .put(&decision(source.domain(), Verb::Commit, &[]), offer(&raw))
        .await
        .unwrap();

    // Guard supplies the selected-entry and live-record binding in production;
    // this fixture exercises verified native byte admission after that decision.
    let selected = TERRANE_V1
        .calculate(IdentityKind::Commit, b"selected source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let source_read = decision(source.domain(), Verb::Read, std::slice::from_ref(&identity))
        .with_reference_record(RefRecord {
            commit: selected,
            seq: 1,
            writer_epoch: 1,
            home: Locality::default(),
            policy: None,
            candidate_id: None,
        })
        .with_read_commit(selected)
        .with_read_path(identity.clone(), b"/file".to_vec())
        .unwrap();
    let destination_write = decision(destination.domain(), Verb::Commit, &[]);
    let records = std::slice::from_ref(&identity);

    // Declaring the selected identity cannot bypass independent verification.
    let wrong_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"different plaintext")
        .unwrap();
    let wrong_offer = ContentUpload::Chunk(ChunkUpload {
        encoded: &compressed,
        identity: &wrong_identity,
        declared_plaintext_len: plaintext.len(),
        position: ChunkPosition::Final,
        profile: &profile,
    });
    assert!(
        destination
            .disclose_from(
                &destination_write,
                &source,
                &source_read,
                &identity,
                wrong_offer
            )
            .await
            .is_err()
    );
    assert_eq!(destination.backend.has(records).await.unwrap(), [false]);
    assert!(
        destination
            .disclose_from(
                &destination_write,
                &source,
                &source_read,
                &identity,
                offer(&[9])
            )
            .await
            .is_err()
    );
    assert_eq!(destination.backend.has(records).await.unwrap(), [false]);
    let disclosure = destination
        .disclose_from(
            &destination_write,
            &source,
            &source_read,
            &identity,
            offer(&compressed),
        )
        .await
        .unwrap();
    assert_eq!(disclosure.record().identity(), &identity);
    assert_eq!(disclosure.record().domain(), "public");
    assert!(
        destination
            .disclose_from(
                &destination_write,
                &source,
                &source_read,
                &identity,
                offer(&[9])
            )
            .await
            .is_err()
    );
    assert_eq!(
        source.get(&source_read, &identity, None).await.unwrap(),
        raw
    );
    let destination_read = decision(destination.domain(), Verb::Read, records);
    assert_eq!(
        destination
            .get(&destination_read, &identity, None)
            .await
            .unwrap(),
        compressed
    );

    drop(source);
    drop(destination);
    cleanup(&directory).await;
}

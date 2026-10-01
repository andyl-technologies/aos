//! Verifies actual metadata-pack persistence, catalog reopening, and tombstones.

use super::*;
use crate::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    store::{
        ChunkPosition, ChunkUpload, ContentStore, ContentUpload, ContentValidator, InvalidReason,
        LocalFs, MetaUpload, StoreErrorKind, StoreFailure, TokioClock, TokioLocalFs,
    },
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_core::{
    chunking::ChunkProfile,
    codec::{Codec, EncodedChunk, encode_envelope},
    derived::{AttrRecord, AttributeName, AttributeValue, Magic},
    identity::{IdentityKind, TERRANE_V1},
    refs::Locality,
    tree_format::ContentRef,
};

pub(super) struct Validator;
impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        if upload.kind() != IdentityKind::Attribute {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload { rule_id: "DRV-1" },
            )));
        }
        AttrRecord::decode(upload.bytes())
            .map(|_| ())
            .map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DRV-1" }),
                    error,
                )
            })
    }
}

struct Untrusted;
impl ProducerVerifier for Untrusted {
    fn verify(&self, _: &AttrRecord) -> Result<Option<ProducerEvidence>, Error> {
        Ok(None)
    }
}

struct UnavailableEvidence;

impl ProducerVerifier for UnavailableEvidence {
    fn verify(&self, _: &AttrRecord) -> Result<Option<ProducerEvidence>, Error> {
        Err(StoreFailure::with_source(
            StoreErrorKind::Unavailable { retry_after: None },
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "producing commit retrieval outcome is indeterminate",
            ),
        )
        .into())
    }
}

#[tokio::test]
async fn unavailable_producer_evidence_never_publishes_durable_quarantine() {
    let entropy = TokioLocalFs
        .random_bytes(16)
        .await
        .expect("isolated fixture entropy");
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let administration =
        std::env::temp_dir().join(format!("terrane-derived-availability-{suffix}"));
    TokioLocalFs
        .create_dir_new(&administration)
        .await
        .expect("create private administrative fixture");
    let metadata = TokioLocalFs
        .symlink_metadata(&administration)
        .await
        .expect("inspect independently configured fixture operator");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);

    let root = administration.join("bucket");
    let config = FileBucketConfig {
        root: root.clone(),
        chunk_profile_name: "cdc-1m".to_owned(),
        chunk_profile: ChunkProfile::cdc_1m([0; 32]),
        locality: Locality::default(),
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid: metadata.uid(),
            control: None,
        }),
    };
    let bucket = FileBucket::open(config.clone(), TokioLocalFs, TokioClock, Validator)
        .await
        .expect("open actual bucket");
    let record = AttrRecord::new([1; 32], AttributeValue::Magic(Magic::Text), [2; 32]);
    let mut original = SideTable::new();
    let identity = original
        .put(&bucket, record.clone(), &Untrusted)
        .await
        .expect("persist immutable supplied record");

    let error = SideTable::rebuild_durable(&bucket, &bucket, &UnavailableEvidence)
        .await
        .err()
        .expect("unavailable producer evidence must propagate");
    assert!(matches!(
        error,
        Error::Store(ref error) if matches!(error.kind(), StoreErrorKind::Unavailable { .. })
    ));
    drop(bucket);

    let reopened = FileBucket::open(config, TokioLocalFs, TokioClock, Validator)
        .await
        .expect("reopen durable authoritative generation");
    let retry = SideTable::rebuild_durable(&reopened, &reopened, &Untrusted)
        .await
        .expect("recovered producer policy can rebuild original record");
    assert!(retry.quarantined().is_empty());
    assert_eq!(
        retry.current(record.object, AttributeName::Magic, false),
        Some(&record)
    );
    assert_eq!(
        reopened.get(&identity, None).await.expect("still serving"),
        record.encode().expect("canonical original record")
    );
    let readmitted = SideTable::new()
        .put(&reopened, record, &Untrusted)
        .await
        .expect("ordinary dedup upload remains eligible");
    assert_eq!(readmitted, identity);
    drop(reopened);
    tokio::fs::remove_dir_all(administration)
        .await
        .expect("remove isolated fixture");
}

#[tokio::test]
async fn durable_catalog_reopen_and_quarantine_preserve_other_attributes() {
    let entropy = TokioLocalFs
        .random_bytes(16)
        .await
        .expect("isolated fixture entropy");
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let administration = std::env::temp_dir().join(format!("terrane-derived-{suffix}"));
    TokioLocalFs
        .create_dir_new(&administration)
        .await
        .expect("create private administrative fixture");
    let metadata = TokioLocalFs
        .symlink_metadata(&administration)
        .await
        .expect("inspect administrative fixture ownership");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);

    // Establish the configured operator independently before creating payload.
    let operator_uid = metadata.uid();
    let root = administration.join("bucket");
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let config = FileBucketConfig {
        root: root.clone(),
        chunk_profile_name: "cdc-1m".to_owned(),
        chunk_profile: profile.clone(),
        locality: Locality::default(),
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid,
            control: None,
        }),
    };
    let bucket = FileBucket::open(config.clone(), TokioLocalFs, TokioClock, Validator)
        .await
        .expect("open actual bucket");
    let plaintext = b"text payload";
    let object_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .expect("object chunk identity");
    let envelope = encode_envelope(EncodedChunk {
        codec: Codec::Raw,
        body: plaintext,
    });
    bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &envelope,
            identity: &object_identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &profile,
        }))
        .await
        .expect("persist verified object chunk");
    let digest = object_identity.terrane_v1_digest().expect("object digest");
    let object = StoreObject::open(
        &bucket,
        &NoDictionaries,
        &profile,
        ContentRef::Inline(digest),
        plaintext.len() as u64,
    )
    .await
    .expect("open actual plaintext reader");
    let good = AttrRecord::new(digest, AttributeValue::Magic(Magic::Text), [1; 32]);
    let bad = AttrRecord::new(digest, AttributeValue::Magic(Magic::Other), [2; 32]);
    let mut table = SideTable::new();
    let good_id = table
        .put(&bucket, good.clone(), &Untrusted)
        .await
        .expect("persist good meta record");
    let bad_id = table
        .put(&bucket, bad.clone(), &Untrusted)
        .await
        .expect("persist supplied canonical record");

    assert!(
        table
            .verify_durable(&bad_id, &object, &bucket)
            .await
            .is_err()
    );
    assert_eq!(table.quarantined().len(), 1);
    drop(object);
    drop(bucket);
    let reopened = FileBucket::open(config, TokioLocalFs, TokioClock, Validator)
        .await
        .expect("reopen selected durable generation");
    let rebuilt = SideTable::rebuild_durable(&reopened, &reopened, &Untrusted)
        .await
        .expect("rebuild authoritative side table");
    assert_eq!(
        rebuilt.current(digest, AttributeName::Magic, false),
        Some(&good)
    );
    assert!(
        rebuilt
            .lookup(
                digest,
                AttributeName::Magic,
                &bad.function,
                bad.producer,
                false
            )
            .is_none()
    );
    assert_eq!(
        reopened
            .get(&good_id, None)
            .await
            .expect("good attribute still served"),
        good.encode().expect("canonical good record")
    );
    assert!(reopened.get(&bad_id, None).await.is_err());
    let bad_bytes = bad
        .encode()
        .expect("bad value still has canonical record schema");
    let repeated = reopened
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Attribute, &bad_bytes).expect("meta upload"),
        ))
        .await
        .expect_err("ordinary put cannot undo quarantine");
    assert!(matches!(repeated.kind(), StoreErrorKind::Corrupt(_)));
    let after_put = SideTable::rebuild_durable(&reopened, &reopened, &Untrusted)
        .await
        .expect("catalog after rejected upload");
    assert!(
        after_put
            .lookup(
                digest,
                AttributeName::Magic,
                &bad.function,
                bad.producer,
                false
            )
            .is_none()
    );
    assert_eq!(
        reopened
            .get(&object_identity, None)
            .await
            .expect("object survives attribute quarantine"),
        envelope
    );
    drop(reopened);
    tokio::fs::remove_dir_all(administration)
        .await
        .expect("remove isolated fixture");
}

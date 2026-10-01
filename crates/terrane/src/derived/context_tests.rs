//! Preserves actual durable records while signed root context remains unfinished.

use super::*;
use crate::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    derived::storage_tests::Validator,
    store::{ChunkPosition, ChunkUpload, LocalFs, TokioClock, TokioLocalFs},
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_core::{
    auth::RequestRoot,
    chunking::ChunkProfile,
    codec::{Codec, EncodedChunk, encode_envelope},
    properties::Defaults,
    provenance::{
        OriginalBootstrapPolicy, derive_fresh_roots, sign_authored, verify_root_context,
        verify_root_context_with_bootstrap,
    },
    refs::CommitContext,
};

// Protected physical configuration is retained independently of this signed
// candidate and any current ACL. The original fixture baseline was empty.
const ORIGINAL_PHYSICAL_AUTHORITY: &str = "fixture-original-physical-authority";
const ORIGINAL_BOOTSTRAP: OriginalBootstrapPolicy<'static> = OriginalBootstrapPolicy {
    authority: "fixture-original-physical-authority",
    reference: "refs/heads/main",
    writer_epoch: 4,
    acl: &[],
};

#[tokio::test]
async fn pending_actual_root_context_propagates_without_durable_quarantine() {
    let object = Object::new(b"abc".to_vec());
    let (legacy, mut history, mut location, secret) = fixture(&object);
    let defaults = Defaults {
        store: "test",
        private_domain: "private:routing-default",
        home: "west",
    };
    let plan = derive_fresh_roots(&history, legacy.commit(), defaults)
        .expect("derive canonical root owner before authoring original claims");
    let domain = plan
        .affected()
        .iter()
        .find(|root| root.path() == b"/")
        .expect("view root")
        .domain();
    let roots = [RequestRoot { path: b"/", domain }];
    let locality = Locality::default();
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &roots,
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    let mut commit = legacy.commit().clone();
    commit.profile_pair.commit_context =
        Some(CommitContext::from_request(&request).expect("original context"));
    commit.signature = None;
    let producer = sign_authored(
        commit,
        &secret,
        &[IssuerKey {
            issuer: "issuer".to_owned(),
            key_id: "key".to_owned(),
            public_key: legacy.signing_public_key(),
            retirement: None,
        }],
        &request,
        4,
    )
    .expect("authenticated producer before actual-root validation");
    location.commit = producer.identity();
    history
        .insert_commit(producer.clone())
        .expect("signed producer context");
    let mut record = AttrRecord::new(
        object.digest(),
        AttributeValue::Magic(Magic::Text),
        producer.identity(),
    );
    record.sign(&producer, &secret).expect("detached signature");
    let entropy = TokioLocalFs
        .random_bytes(16)
        .await
        .expect("isolated fixture entropy");
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let administration = std::env::temp_dir().join(format!("terrane-derived-context-{suffix}"));
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
    let object_identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, &object.digest())
        .expect("actual object identity");
    let envelope = encode_envelope(EncodedChunk {
        codec: Codec::Raw,
        body: &object.bytes,
    });
    bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &envelope,
            identity: &object_identity,
            declared_plaintext_len: object.bytes.len(),
            position: ChunkPosition::Final,
            profile: &config.chunk_profile,
        }))
        .await
        .expect("persist the producer witness's actual object plaintext");

    let identity = SideTable::new()
        .put(&bucket, record.clone(), &Untrusted)
        .await
        .expect("persist supplied signed record");

    let error = SideTable::rebuild_durable(
        &bucket,
        &bucket,
        &Checked {
            history: &history,
            location: &location,
        },
    )
    .await
    .err()
    .expect("unfinished actual-root context propagates");
    assert!(matches!(
        error,
        Error::Derived(terrane_core::derived::Error::UnverifiedContext)
    ));
    drop(bucket);

    assert!(verify_root_context(&mut history, producer.identity(), defaults).is_err());
    verify_root_context_with_bootstrap(
        &mut history,
        producer.identity(),
        defaults,
        ORIGINAL_PHYSICAL_AUTHORITY,
        ORIGINAL_BOOTSTRAP,
    )
    .expect("canonical root matches original authenticated claim");
    let reopened = FileBucket::open(config.clone(), TokioLocalFs, TokioClock, Validator)
        .await
        .expect("reopen original selected generation");
    let verifier = Checked {
        history: &history,
        location: &location,
    };
    let mut rebuilt = SideTable::rebuild_durable(&reopened, &reopened, &verifier)
        .await
        .expect("completed producer context admits original immutable record");
    assert!(rebuilt.quarantined().is_empty());
    assert_eq!(rebuilt.trust(&identity), Some(Trust::VerifiedProducer));
    assert_eq!(
        reopened.get(&identity, None).await.expect("still serving"),
        record.encode().expect("canonical signed bytes")
    );
    let stored_object = StoreObject::open(
        &reopened,
        &NoDictionaries,
        &config.chunk_profile,
        ContentRef::Inline(object.digest()),
        object.size(),
    )
    .await
    .expect("reopen the exact verified object from native storage");
    rebuilt
        .verify(&identity, &stored_object)
        .await
        .expect("signed attribute value matches actual stored plaintext");

    let records = produce_required_signed(
        &mut rebuilt,
        &reopened,
        &stored_object,
        &Requirements {
            hashes: vec![AttributeName::Sha256],
            classify: vec![Magic::Text],
        },
        &SignedProducer::new(&producer, &secret),
        &verifier,
        true,
    )
    .await
    .expect("native missing hash production and existing classification reuse");
    assert_eq!(records.len(), 2);
    for produced in &records {
        assert_eq!(produced.object, object.digest());
        assert_eq!(produced.producer, producer.identity());
        assert!(produced.signature.is_some());
        assert!(
            rebuilt
                .producer_evidence(&produced.identity().expect("record identity"))
                .is_some()
        );
    }
    drop(stored_object);

    let repeated = SideTable::new()
        .put(&reopened, record, &verifier)
        .await
        .expect("ordinary upload was never durably excluded");
    assert_eq!(repeated, identity);
    drop(reopened);

    let reopened = FileBucket::open(config, TokioLocalFs, TokioClock, Validator)
        .await
        .expect("reopen signed side-table production");
    let retained = SideTable::rebuild_durable(&reopened, &reopened, &verifier)
        .await
        .expect("rebind retained immutable records to independently verified history");
    assert!(retained.quarantined().is_empty());
    for produced in records {
        let identity = produced.identity().expect("record identity");
        assert_eq!(retained.trust(&identity), Some(Trust::VerifiedProducer));
        assert_eq!(
            retained.current(object.digest(), produced.value.name(), true),
            Some(&produced)
        );
    }
    drop(reopened);

    tokio::fs::remove_dir_all(administration)
        .await
        .expect("remove isolated fixture");
}

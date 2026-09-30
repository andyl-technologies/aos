//! Exercises trusted metadata declarations without backend schema interpretation.

#![allow(clippy::unwrap_used)]

use super::content_tests::{chunk_identity, fixture, raw, upload};
use super::tests::config;
use super::*;
use crate::store::{
    ChunkPosition, ChunkRequirement, ContentStore, ContentUpload, InvalidReason, MetaUpload,
    TokioClock, TokioLocalFs,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};

struct DeclaringValidator {
    identity: Identity,
    length: usize,
    mode: AtomicUsize,
    trace: Mutex<Vec<&'static str>>,
}

impl ContentValidator for DeclaringValidator {
    fn validate_meta(&self, _upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        self.trace.lock().unwrap().push("metadata");
        Ok(())
    }

    fn chunk_requirements(
        &self,
        _upload: &MetaUpload<'_>,
    ) -> Result<Vec<ChunkRequirement>, StoreFailure> {
        self.trace.lock().unwrap().push("requirements");
        let mode = self.mode.load(Ordering::Relaxed);
        let identity = match mode {
            3 => TERRANE_V1.calculate(IdentityKind::Memo, &[0xa0]).unwrap(),
            4 => TERRANE_V1
                .from_digest(IdentityKind::Chunk, &[99; 32])
                .unwrap(),
            _ => self.identity.clone(),
        };
        Ok(vec![ChunkRequirement {
            identity,
            declared_plaintext_len: self.length + usize::from(mode == 1),
            position: if mode == 2 {
                ChunkPosition::NonFinal
            } else {
                ChunkPosition::Final
            },
            missing_rule_id: "TEST-META-CHUNK",
        }])
    }
}

#[tokio::test]
async fn opaque_metadata_callback_verifies_real_chunks_before_every_dedup() {
    let initial = fixture().await;
    let plaintext = b"short final chunk for opaque metadata";
    let identity = chunk_identity(plaintext);
    let validator = DeclaringValidator {
        identity: identity.clone(),
        length: plaintext.len(),
        mode: AtomicUsize::new(0),
        trace: Mutex::new(Vec::new()),
    };
    let bucket = FileBucket::open(
        config(initial.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        validator,
    )
    .await
    .unwrap();
    bucket
        .put(upload(
            &raw(plaintext),
            &identity,
            plaintext.len(),
            &bucket.inner.config.chunk_profile,
            ChunkPosition::Final,
        ))
        .await
        .unwrap();
    assert!(bucket.inner.validator.trace.lock().unwrap().is_empty());

    // This schema is deliberately opaque to the backend. Its trusted validator
    // supplies a chunk declaration even though the body is not a Manifest.
    let meta = MetaUpload::new(IdentityKind::Memo, &[0xa0]).unwrap();
    let stored = bucket.put(ContentUpload::Meta(meta)).await.unwrap();
    assert_eq!(bucket.get(&stored, None).await.unwrap(), vec![0xa0]);
    bucket.inner.validator.trace.lock().unwrap().clear();
    let capabilities = tokio::fs::read(bucket.root().join("CAPABILITIES"))
        .await
        .unwrap();
    assert_eq!(bucket.put(ContentUpload::Meta(meta)).await.unwrap(), stored);
    assert_eq!(
        *bucket.inner.validator.trace.lock().unwrap(),
        vec!["metadata", "requirements"]
    );
    assert_eq!(
        tokio::fs::read(bucket.root().join("CAPABILITIES"))
            .await
            .unwrap(),
        capabilities
    );

    for (mode, rule_id) in [(1, "CDC-12"), (2, "CDC-15"), (4, "TEST-META-CHUNK")] {
        bucket.inner.validator.mode.store(mode, Ordering::Relaxed);
        let error = bucket.put(ContentUpload::Meta(meta)).await.unwrap_err();
        assert!(
            matches!(error.kind(), StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: actual })
            if *actual == rule_id)
        );
        assert_eq!(
            tokio::fs::read(bucket.root().join("CAPABILITIES"))
                .await
                .unwrap(),
            capabilities
        );
    }
    bucket.inner.validator.mode.store(3, Ordering::Relaxed);
    assert!(matches!(
        bucket
            .put(ContentUpload::Meta(meta))
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    ));
    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

//! Exercises canonical final boundaries at actual manifest admission.

use super::*;

#[tokio::test]
async fn manifest_admission_rejects_a_final_chunk_with_an_earlier_boundary() {
    let bucket = fixture().await;
    let profile = &bucket.inner.config.chunk_profile;
    let mut plaintext = vec![0; profile.maximum()];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-cdc-boundaries-v1\0");
    hasher.finalize_xof().fill(&mut plaintext);
    let first = profile.first_boundary(&plaintext);
    assert!(first > profile.minimum() && first < plaintext.len());

    let mut manifests = Vec::new();
    for bytes in [&plaintext[..first], plaintext.as_slice()] {
        let identity = chunk_identity(bytes);
        bucket
            .put(upload(
                &raw(bytes),
                &identity,
                bytes.len(),
                profile,
                ChunkPosition::Final,
            ))
            .await
            .unwrap();
        let manifest = Manifest {
            size: bytes.len() as u64,
            chunks: vec![ChunkRef {
                digest: identity.terrane_v1_digest().unwrap(),
                length: bytes.len() as u64,
            }],
            hashes: BTreeMap::from([("blake3".into(), blake3::hash(bytes).as_bytes().to_vec())]),
            media_type: None,
        };
        manifests.push(manifest.encode(profile).unwrap());
    }

    let canonical = MetaUpload::new(IdentityKind::Manifest, &manifests[0]).unwrap();
    let canonical_id = bucket.put(ContentUpload::Meta(canonical)).await.unwrap();
    assert_eq!(bucket.get(&canonical_id, None).await.unwrap(), manifests[0]);

    // The final chunk already exists as an admissible standalone chunk.
    // Referencing it as object content must still prove its canonical cut.
    let capabilities = tokio::fs::read(bucket.root().join("CAPABILITIES"))
        .await
        .unwrap();
    let generation = bucket.catalog().await.unwrap().capabilities.generation;
    let malformed_id = TERRANE_V1
        .calculate(IdentityKind::Manifest, &manifests[1])
        .unwrap();
    let malformed = MetaUpload::new(IdentityKind::Manifest, &manifests[1]).unwrap();
    let error = bucket
        .put(ContentUpload::Meta(malformed))
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-19" })
    ));
    assert_eq!(
        bucket.catalog().await.unwrap().capabilities.generation,
        generation,
    );
    assert_eq!(
        tokio::fs::read(bucket.root().join("CAPABILITIES"))
            .await
            .unwrap(),
        capabilities,
    );
    assert_eq!(bucket.has(&[malformed_id]).await.unwrap(), vec![false]);
    assert_eq!(bucket.get(&canonical_id, None).await.unwrap(), manifests[0]);

    tokio::fs::remove_dir_all(bucket.root()).await.unwrap();
}

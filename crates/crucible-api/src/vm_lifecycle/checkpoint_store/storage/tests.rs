//! Checkpoint retained-artifact authentication regressions.

use super::*;

#[test]
fn retained_parent_publication_rejects_mutation_and_replacement_without_rehashing() {
    let root = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("create retained-object fixture: {error}"));
    let first_payload = vec![0x3c; ARTIFACT_CHUNK_BYTES];
    let second_payload = b"authenticated final parent chunk";
    let first_chunk = ContentHash::from_bytes(&first_payload);
    let second_chunk = ContentHash::from_bytes(second_payload);
    let first_path = object_path(root.path(), first_chunk);
    for (path, payload) in [
        (&first_path, first_payload.as_slice()),
        (
            &object_path(root.path(), second_chunk),
            second_payload.as_slice(),
        ),
    ] {
        fs::create_dir_all(
            path.parent()
                .unwrap_or_else(|| panic!("object path should have a prefix directory")),
        )
        .unwrap_or_else(|error| panic!("create object prefix: {error}"));
        fs::write(path, payload).unwrap_or_else(|error| panic!("write retained object: {error}"));
    }
    let mut payload = first_payload.clone();
    payload.extend_from_slice(second_payload);
    let manifest = ArtifactManifest {
        identity: ContentHash::from_bytes(&payload),
        length: payload.len() as u64,
        chunks: vec![first_chunk, second_chunk],
        sparse: false,
        extents: Vec::new(),
    };
    let staged = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::ChunkStore(root.path().to_path_buf()),
        identity: manifest.identity,
        length: manifest.length,
        chunks: manifest.chunks.clone(),
        sparse: false,
        extents: Vec::new(),
    };
    let artifact =
        install_retained_artifact_from_manifest(&staged, root.path(), &manifest, &mut || Ok(()))
            .unwrap_or_else(|error| panic!("lease authenticated fixture: {error}"));
    CHECKPOINT_PAYLOAD_BYTES_READ.with(|observed| observed.set(0));
    let transferred =
        install_retained_artifact_from_manifest(&artifact, root.path(), &manifest, &mut || Ok(()))
            .unwrap_or_else(|error| panic!("transfer retained fixture lease: {error}"));
    match (&artifact.source, &transferred.source) {
        (
            ProductionCheckpointArtifactSource::RetainedChunkStore(first),
            ProductionCheckpointArtifactSource::RetainedChunkStore(second),
        ) => assert!(Arc::ptr_eq(first, second)),
        _ => panic!("retained artifact transfer should preserve its capability"),
    }
    let mut boundaries = 0_u8;

    persist_chunked_artifact_with_boundary(root.path(), &manifest, &transferred, &mut || {
        boundaries = boundaries.saturating_add(1);
        Ok(())
    })
    .unwrap_or_else(|error| panic!("reuse retained parent artifact: {error}"));

    assert_eq!(boundaries, 4);
    CHECKPOINT_PAYLOAD_BYTES_READ.with(|observed| assert_eq!(observed.get(), 0));
    std::thread::sleep(std::time::Duration::from_millis(2));
    fs::write(&first_path, vec![0xa5; first_payload.len()])
        .unwrap_or_else(|error| panic!("mutate retained object: {error}"));
    assert!(
        persist_chunked_artifact_with_boundary(root.path(), &manifest, &artifact, &mut || Ok(()),)
            .is_err()
    );

    let replacement = first_path.with_extension("replacement");
    fs::write(&replacement, &first_payload)
        .unwrap_or_else(|error| panic!("write replacement object: {error}"));
    fs::rename(&replacement, &first_path)
        .unwrap_or_else(|error| panic!("replace retained object: {error}"));
    assert!(
        persist_chunked_artifact_with_boundary(root.path(), &manifest, &artifact, &mut || Ok(()),)
            .is_err()
    );
}

#[test]
fn interrupted_multichunk_authentication_does_not_install_a_retained_lease() {
    let root = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("create interrupted-auth fixture: {error}"));
    let first_payload = vec![0x91; ARTIFACT_CHUNK_BYTES];
    let second_payload = b"second checkpoint chunk";
    let first_chunk = ContentHash::from_bytes(&first_payload);
    let second_chunk = ContentHash::from_bytes(second_payload);
    for (identity, payload) in [
        (first_chunk, first_payload.as_slice()),
        (second_chunk, second_payload.as_slice()),
    ] {
        let path = object_path(root.path(), identity);
        fs::create_dir_all(
            path.parent()
                .unwrap_or_else(|| panic!("object path should have a prefix directory")),
        )
        .unwrap_or_else(|error| panic!("create object prefix: {error}"));
        fs::write(path, payload)
            .unwrap_or_else(|error| panic!("write interrupted-auth object: {error}"));
    }
    let mut payload = first_payload;
    payload.extend_from_slice(second_payload);
    let manifest = ArtifactManifest {
        identity: ContentHash::from_bytes(&payload),
        length: payload.len() as u64,
        chunks: vec![first_chunk, second_chunk],
        sparse: false,
        extents: Vec::new(),
    };
    let staged = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::ChunkStore(root.path().to_path_buf()),
        identity: manifest.identity,
        length: manifest.length,
        chunks: manifest.chunks.clone(),
        sparse: false,
        extents: Vec::new(),
    };
    let mut boundary_calls = 0_u8;
    CHECKPOINT_PAYLOAD_BYTES_READ.with(|observed| observed.set(0));

    let result =
        install_retained_artifact_from_manifest(&staged, root.path(), &manifest, &mut || {
            boundary_calls = boundary_calls.saturating_add(1);
            if boundary_calls == 7 {
                Err(store_error("injected retained-auth interruption"))
            } else {
                Ok(())
            }
        });

    assert!(result.is_err());
    assert!(matches!(
        staged.source,
        ProductionCheckpointArtifactSource::ChunkStore(_)
    ));
    CHECKPOINT_PAYLOAD_BYTES_READ.with(|observed| {
        assert!(observed.get() > 0);
        assert!(observed.get() < manifest.length);
    });
}

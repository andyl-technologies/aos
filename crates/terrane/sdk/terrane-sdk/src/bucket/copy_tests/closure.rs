//! Exercises the complete portable-copy closure and exact-read refusal matrix.

use super::*;

/// Exercises exact closure, historical deltas, unavailable inputs, and changed reads.
///
/// # Panics
/// Panics if a fixture operation or any required closure assertion fails.
pub(super) async fn run() {
    let (native, head) = source().await;
    let authority = native.guard().configured_original_authority().unwrap();
    let lease = crate::gc::lease::Collector::new(native.guard(), &authority)
        .acquire("source collector".into(), 60)
        .await
        .unwrap();
    assert!(logical(native.store()).await["gc/lease"].is_some());
    let configuration = destination(native.store()).await;
    assert_eq!(
        tokio::fs::read(configuration.root.join("gc/lease"))
            .await
            .unwrap(),
        lease.lease.encode().unwrap()
    );
    // Mutable caches may reflect an interrupted projection. Only the exact
    // portable pointer and verified immutable closure choose copied data.
    tokio::fs::write(
        configuration.root.join("CAPABILITIES"),
        b"stale individual cache",
    )
    .await
    .unwrap();
    tokio::fs::write(
        configuration.root.join(format!("{NAME}:record")),
        b"stale ref cache",
    )
    .await
    .unwrap();
    tokio::fs::write(
        configuration.root.join("publication/SELECTED-HISTORY"),
        b"stale history cache",
    )
    .await
    .unwrap();
    let fs = ReadFs::default();
    let copied = FileBucket::initialize_portable_copy(
        configuration.clone(),
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let temporary_paths = fs.temporary_paths();
    assert!(!temporary_paths.is_empty());
    for path in temporary_paths {
        let suffix = path
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .strip_prefix(b".terrane-tmp:")
            .unwrap();
        assert_eq!(suffix.len(), 32, "{}", path.display());
        assert!(
            suffix
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        );
    }
    assert_eq!(copied.ref_get(NAME).await.unwrap(), Some(head.clone()));
    assert_eq!(
        copied
            .ref_log_read(NAME, 1)
            .await
            .unwrap()
            .last()
            .unwrap()
            .record,
        head
    );
    let chunk = TERRANE_V1.calculate(IdentityKind::Chunk, BODY).unwrap();
    assert_eq!(
        copied.get(&chunk, None).await.unwrap(),
        crate::bucket::content_tests::raw(BODY)
    );
    assert!(!configuration.root.join("gc/lease").exists());
    let source_data = native.store().portable_copy_payload().await.unwrap();
    assert_eq!(source_data.logical["gc/lease"], None);
    assert!(
        !source_data
            .reads
            .iter()
            .any(|read| read.path() == native.store().root().join("gc/lease"))
    );
    let selected = copied.selected_publication_locked().await.unwrap();
    assert!(selected.state.guard.is_none());
    assert!(selected.state.sources.is_empty());
    assert_eq!(selected.logical["gc/lease"], None);
    assert_ne!(
        selected.state.binding,
        origin(&logical(native.store()).await)
    );
    let verified_trace = fs.reads();
    remove(&configuration).await;

    let configuration = destination(native.store()).await;
    let mut unknown = portable(native.store()).await;
    unknown.insert(format!("{NAME}:record"), None);
    let mut history =
        SelectedHistory::decode(unknown["publication/SELECTED-HISTORY"].as_deref().unwrap())
            .unwrap();
    history.branches[0].selection = CommittedSelection::Unknown;
    unknown.insert(
        "publication/SELECTED-HISTORY".into(),
        Some(history.encode().unwrap()),
    );
    checkpoint(&configuration.root, &unknown, origin(&unknown), 0).await;
    assert!(
        matches!(initialize(configuration.clone()).await, Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported))
    );
    assert!(!control(&configuration).exists());
    remove(&configuration).await;

    let catalog = native.store().catalog().await.unwrap();
    let live = catalog
        .shards
        .iter()
        .flat_map(MergedShard::entries)
        .find(|row| row.entry().hash() == &head.commit)
        .unwrap();
    let pack = live.pack();
    let selected_log =
        BucketKey::reflog_candidate(NAME, head.seq, head.candidate_id.as_ref().unwrap()).unwrap();
    for case in [
        "pointer absent",
        "pointer corrupt",
        "pointer digest",
        "snapshot absent",
        "snapshot corrupt",
        "manifest absent",
        "shard absent",
        "pack absent",
        "index absent",
        "pack corrupt",
        "log absent",
        "log corrupt",
        "log wrong whole head",
        "commit membership absent",
    ] {
        let configuration = destination(native.store()).await;
        let pointer_path = configuration.root.join("publication/PORTABLE");
        let mut pointer =
            PortableCurrent::decode(&tokio::fs::read(&pointer_path).await.unwrap()).unwrap();
        match case {
            "pointer absent" => tokio::fs::remove_file(&pointer_path).await.unwrap(),
            "pointer corrupt" => tokio::fs::write(&pointer_path, b"malformed").await.unwrap(),
            "pointer digest" => {
                pointer.digest[0] ^= 1;
                tokio::fs::write(&pointer_path, pointer.encode().unwrap())
                    .await
                    .unwrap();
            }
            "snapshot absent" => tokio::fs::remove_file(configuration.root.join(&pointer.key))
                .await
                .unwrap(),
            "snapshot corrupt" => {
                tokio::fs::write(configuration.root.join(&pointer.key), b"malformed")
                    .await
                    .unwrap()
            }
            "manifest absent" => tokio::fs::remove_file(configuration.root.join(format!(
                "objects/index/{}/MANIFEST",
                catalog.capabilities.generation.unwrap()
            )))
            .await
            .unwrap(),
            "shard absent" => tokio::fs::remove_file(configuration.root.join(format!(
                "objects/index/{}/{}.idx",
                catalog.capabilities.generation.unwrap(),
                catalog.shards[0].shard()
            )))
            .await
            .unwrap(),
            "pack absent" => tokio::fs::remove_file(configuration.root.join(pack.pack_key()))
                .await
                .unwrap(),
            "index absent" => tokio::fs::remove_file(configuration.root.join(pack.index_key()))
                .await
                .unwrap(),
            "pack corrupt" => {
                tokio::fs::write(configuration.root.join(pack.pack_key()), b"corrupt")
                    .await
                    .unwrap()
            }
            "log absent" => tokio::fs::remove_file(configuration.root.join(selected_log.as_str()))
                .await
                .unwrap(),
            "log corrupt" => {
                tokio::fs::write(configuration.root.join(selected_log.as_str()), b"corrupt")
                    .await
                    .unwrap()
            }
            "log wrong whole head" => {
                let other = terrane_format::refs::RefRecord::first(
                    head.commit,
                    head.writer_epoch + 1,
                    head.home.clone(),
                )
                .selected();
                let bytes = log(other.clone(), None).encode().unwrap();
                assert_eq!(
                    terrane_format::refs::RefLogRecord::decode(&bytes)
                        .unwrap()
                        .record,
                    other
                );
                tokio::fs::write(configuration.root.join(selected_log.as_str()), bytes)
                    .await
                    .unwrap();
            }
            "commit membership absent" => {
                let mut projection = portable(native.store()).await;
                let generation = catalog.capabilities.generation.unwrap();
                let key = format!("objects/index/{generation}/{}.idx", head.commit[0]);
                let shard = projection[&key].as_ref().unwrap();
                let records = shard[12..]
                    .as_chunks::<72>()
                    .0
                    .iter()
                    .filter(|record| record[..32] != head.commit)
                    .collect::<Vec<_>>();
                let mut bytes = b"TRIX".to_vec();
                bytes.extend_from_slice(&(records.len() as u64).to_le_bytes());
                for record in records {
                    bytes.extend_from_slice(record);
                }
                MergedShard::decode(&bytes, generation, head.commit[0]).unwrap();
                let manifest_key = format!("objects/index/{generation}/MANIFEST");
                let mut manifest =
                    GenerationManifest::decode(projection[&manifest_key].as_deref().unwrap())
                        .unwrap();
                let row = manifest
                    .shards
                    .iter_mut()
                    .find(|row| row.shard == u64::from(head.commit[0]))
                    .unwrap();
                row.index_hash = TERRANE_V1
                    .calculate(IdentityKind::Index, &bytes)
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap();
                row.index_size = bytes.len() as u64;
                projection.insert(key.clone(), Some(bytes.clone()));
                projection.insert(manifest_key.clone(), Some(manifest.encode().unwrap()));
                tokio::fs::write(configuration.root.join(&key), bytes)
                    .await
                    .unwrap();
                tokio::fs::write(
                    configuration.root.join(&manifest_key),
                    projection[&manifest_key].as_ref().unwrap(),
                )
                .await
                .unwrap();
                checkpoint(&configuration.root, &projection, origin(&projection), 0).await;
            }
            _ => unreachable!(),
        }
        let fs = ReadFs::default();
        let error = match FileBucket::initialize_portable_copy(
            configuration.clone(),
            fs.clone(),
            TokioClock,
            Validator,
        )
        .await
        {
            Ok(_) => panic!("accepted {case}"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error.kind(),
                StoreErrorKind::Corrupt(_) | StoreErrorKind::Absent(_)
            ),
            "{case}: {error:?}"
        );
        assert_eq!(fs.effects(), 0, "{case}");
        assert!(!control(&configuration).exists(), "{case}");
        remove(&configuration).await;
    }
    let configuration = destination(native.store()).await;
    let fs = ReadFs::default();
    fs.unavailable(configuration.root.join(pack.pack_key()));
    let error = match FileBucket::initialize_portable_copy(
        configuration.clone(),
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    {
        Ok(_) => panic!("unavailable read accepted"),
        Err(error) => error,
    };
    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(fs.effects(), 0);
    assert!(!control(&configuration).exists());
    remove(&configuration).await;

    // Each hidden intermediate transition starts with the same complete valid
    // checkpoint and ends with restored valid current bytes. Only the changed
    // predecessor relationship distinguishes the negative case.
    let baseline = portable(native.store()).await;
    for case in [
        "profile transition",
        "protocol transition",
        "generation regression",
        "inventory disappearance",
        "origin transition",
        "revision gap",
        "predecessor absent",
    ] {
        let configuration = destination(native.store()).await;
        let mut previous = checkpoint(&configuration.root, &baseline, origin(&baseline), 0).await;
        let mut middle = baseline.clone();
        let mut cap =
            BucketCapabilities::decode(middle["CAPABILITIES"].as_deref().unwrap()).unwrap();
        match case {
            "profile transition" => cap.profile.seed[0] ^= 1,
            "protocol transition" => cap.publication_protocol = None,
            "generation regression" => cap.generation = Some(cap.generation.unwrap() - 1),
            "inventory disappearance" => cap.ref_names = Some(Vec::new()),
            _ => {}
        }
        middle.insert("CAPABILITIES".into(), Some(cap.encode().unwrap()));
        let mut stamp = origin(&baseline);
        if case == "origin transition"
            && let terrane_format::gc::publication::BackendBinding::Local { root_inode, .. } =
                &mut stamp
        {
            *root_inode += 1;
        }
        let revision = if case == "revision gap" { 2 } else { 1 };
        let mut snapshot = PortableSnapshot {
            revision,
            origin: stamp,
            predecessor: Some(previous.clone()),
            projection: middle
                .iter()
                .filter(|(key, value)| baseline.get(*key) != Some(*value))
                .map(|(key, value)| ProjectionEntry {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
        };
        let bytes = if case == "revision gap" {
            snapshot.revision = 1;
            let mut bytes = snapshot.encode().unwrap();
            assert_eq!(&bytes[..5], &[0xa5, 0, 1, 1, 1]);
            bytes[4] = 2;
            assert_eq!(
                PortableSnapshot::decode(&bytes),
                Err(terrane_format::gc::publication::PublicationError::Contradiction)
            );
            snapshot.revision = 2;
            bytes
        } else {
            snapshot.encode().unwrap()
        };
        let key = format!("publication/snapshots/{revision}:{}", "11".repeat(32));
        tokio::fs::write(configuration.root.join(&key), &bytes)
            .await
            .unwrap();
        let checkpoint_key = previous.key.clone();
        previous = PortableCurrent {
            key,
            digest: *blake3::hash(&bytes).as_bytes(),
        };
        snapshot.revision = revision + 1;
        snapshot.origin = origin(&baseline);
        snapshot.predecessor = Some(previous);
        snapshot.projection = baseline
            .iter()
            .filter(|(key, value)| middle.get(*key) != Some(*value))
            .map(|(key, value)| ProjectionEntry {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();
        let bytes = snapshot.encode().unwrap();
        let pointer = PortableCurrent {
            key: format!(
                "publication/snapshots/{}:{}",
                snapshot.revision,
                "22".repeat(32)
            ),
            digest: *blake3::hash(&bytes).as_bytes(),
        };
        tokio::fs::write(configuration.root.join(&pointer.key), &bytes)
            .await
            .unwrap();
        tokio::fs::write(
            configuration.root.join("publication/PORTABLE"),
            pointer.encode().unwrap(),
        )
        .await
        .unwrap();
        if case == "predecessor absent" {
            tokio::fs::remove_file(configuration.root.join(checkpoint_key))
                .await
                .unwrap();
        }
        assert!(initialize(configuration.clone()).await.is_err(), "{case}");
        assert!(!control(&configuration).exists(), "{case}");
        remove(&configuration).await;
    }

    let configuration = destination(native.store()).await;
    let fs = ReadFs::default();
    fs.change_after_read(
        configuration.root.join(pack.pack_key()),
        b"changed after original body read".to_vec(),
    );
    assert!(
        FileBucket::initialize_portable_copy(
            configuration.clone(),
            fs.clone(),
            TokioClock,
            Validator
        )
        .await
        .is_err()
    );
    assert_eq!(fs.effects(), 0);
    assert!(!control(&configuration).exists());
    assert!(
        fs.reads()
            .contains(&configuration.root.join(pack.pack_key()))
    );
    remove(&configuration).await;

    // The configured validator consumes the final returned Commit bytes before
    // this binding changes the same physical pack. Native receipt construction
    // must compare every retained preimage before its first create event.
    let verified_count = verified_trace
        .iter()
        .filter(|path| path.ends_with(pack.pack_key()))
        .count();
    assert_eq!(verified_count, 4);
    let configuration = destination(native.store()).await;
    let path = configuration.root.join(pack.pack_key());
    let mut replacement = tokio::fs::read(&path).await.unwrap();
    replacement[usize::try_from(live.entry().offset()).unwrap()] ^= 1;
    let fs = ReadFs::default();
    fs.change_after_read_number(path.clone(), replacement, verified_count);
    assert!(
        FileBucket::initialize_portable_copy(
            configuration.clone(),
            fs.clone(),
            TokioClock,
            Validator
        )
        .await
        .is_err()
    );
    assert_eq!(
        fs.reads().iter().filter(|read| **read == path).count(),
        verified_count
    );
    assert_eq!(fs.effects(), 0);
    assert!(!control(&configuration).exists());
    remove(&configuration).await;
}

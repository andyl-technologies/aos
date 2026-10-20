//! Checks held uploads against actual catalogue reads and native refusal boundaries.

mod fixture;

use super::*;
use fixture::{Trace, arm, artifacts, filtered, prefix};
use terrane_format::bucket::GenerationManifest;

#[tokio::test]
async fn held_upload_preserves_direct_artifact_reads_and_reduces_selected_reads() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        ..
    } = filtered().await;
    let expected_artifacts = artifacts(&bucket).await;
    let control = Control::open(&bucket, false).await.unwrap();
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let destination = holder.destination();

    // Measure repair, direct catalogue reads and physical dedup verification
    // independently, under this same actual exclusion.
    bucket.inner.fs.reset_read_counters();
    let observed = destination.observe_publication().await.unwrap();
    bucket.write_layout_locked().await.unwrap();
    let preparation = Trace::capture(&bucket);
    assert!(preparation.effects.1 > 0);

    bucket.inner.fs.reset_read_counters();
    let direct_catalog = bucket.catalog_observed(&observed).await.unwrap();
    let direct = Trace::capture(&bucket);
    assert_eq!(direct.effects, (0, 0));
    for artifact in &expected_artifacts {
        assert_eq!(direct.count(artifact), 1, "direct artifact: {artifact:?}");
    }

    // A selected row does not prove presence: dedup verifies the protected
    // physical placement and complete stored body before its final checks.
    bucket.inner.fs.reset_read_counters();
    let placement = bucket
        .placement_observed(&destination, &observed, &direct_catalog, &identity)
        .await
        .unwrap()
        .unwrap();
    assert!(!placement.is_missing());
    assert_eq!(
        bucket
            .verified_body(&direct_catalog, &identity)
            .await
            .unwrap(),
        encoded
    );
    let physical = Trace::capture(&bucket);
    assert_eq!(physical.effects, (0, 0));

    bucket.inner.fs.reset_read_counters();
    observed.revalidate().await.unwrap();
    bucket.recheck_placement(&placement).await.unwrap();
    let final_check = Trace::capture(&bucket);
    assert_eq!(final_check.effects, (0, 0));
    drop(observed);

    // The ordinary catalogue path performs its own actual logical selections.
    bucket.inner.fs.reset_read_counters();
    let observed = destination.observe_publication().await.unwrap();
    bucket.write_layout_locked().await.unwrap();
    let ordinary_catalog = bucket.catalog().await.unwrap();
    let placement = bucket
        .placement_observed(&destination, &observed, &ordinary_catalog, &identity)
        .await
        .unwrap()
        .unwrap();
    assert!(!placement.is_missing());
    assert_eq!(
        bucket
            .verified_body(&ordinary_catalog, &identity)
            .await
            .unwrap(),
        encoded
    );
    observed.revalidate().await.unwrap();
    bucket.recheck_placement(&placement).await.unwrap();
    let ordinary = Trace::capture(&bucket);
    assert_eq!(
        ordinary_catalog.capability_bytes,
        direct_catalog.capability_bytes
    );
    drop(observed);

    bucket.inner.fs.reset_read_counters();
    let profile = &bucket.inner.config.chunk_profile;
    assert_eq!(
        destination
            .put(upload(
                &encoded,
                &identity,
                b"held content disclosure".len(),
                profile,
                ChunkPosition::Final,
            ))
            .await
            .unwrap(),
        identity
    );
    let held = Trace::capture(&bucket);
    let mut expected_paths = preparation.paths.clone();
    expected_paths.extend(direct.paths.iter().cloned());
    expected_paths.extend(physical.paths.iter().cloned());
    expected_paths.extend(final_check.paths.iter().cloned());
    expected_paths.sort();
    let mut held_paths = held.paths.clone();
    held_paths.sort();
    assert_eq!(held_paths, expected_paths);
    assert_eq!(held.effects, preparation.effects);
    assert_eq!(ordinary.effects, preparation.effects);
    for artifact in &expected_artifacts {
        assert_eq!(
            held.count(artifact),
            preparation.count(artifact)
                + direct.count(artifact)
                + physical.count(artifact)
                + final_check.count(artifact),
            "actual repair/direct/physical/final artifact reads: {artifact:?}"
        );
    }
    let ordinary_selected = ordinary
        .paths
        .iter()
        .filter(|path| path.starts_with(&control.path))
        .count();
    let held_selected = held
        .paths
        .iter()
        .filter(|path| path.starts_with(&control.path))
        .count();
    assert!(held_selected > 0);
    assert!(held_selected < ordinary_selected);
    eprintln!(
        "actual metadata/dispatches/GETs {:?}->{:?}; selected GETs {ordinary_selected}->{held_selected}; retained repair effects {:?}",
        ordinary.reads, held.reads, held.effects
    );

    // Dedup never waives independent upload validation. Required repair may
    // run first, but this invalid nonfinal offer adds no admission effects.
    bucket.inner.fs.reset_read_counters();
    let failure = destination
        .put(upload(
            &encoded,
            &identity,
            b"held content disclosure".len(),
            profile,
            ChunkPosition::NonFinal,
        ))
        .await
        .unwrap_err();
    assert!(matches!(failure.kind(), StoreErrorKind::Invalid(_)));
    assert_eq!(Trace::capture(&bucket).effects, preparation.effects);
    assert_eq!(destination.get(&identity, None).await.unwrap(), encoded);
    drop(destination);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_upload_rejects_missing_corrupt_and_unavailable_direct_artifacts() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        ..
    } = filtered().await;
    let expected_artifacts = artifacts(&bucket).await;
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let destination = holder.destination();
    let profile = &bucket.inner.config.chunk_profile;
    let new_bytes = b"new held upload";
    let new_identity = chunk_identity(new_bytes);
    let new_encoded = raw(new_bytes);

    for artifact in expected_artifacts {
        let bytes = TokioLocalFs.read_nofollow(&artifact).await.unwrap();

        // Selected journal bytes can recreate an absent immutable row. A
        // conflicting existing row must be refused rather than overwritten.
        let before = destination.observe_publication().await.unwrap().stamp();
        tokio::fs::remove_file(&artifact).await.unwrap();
        assert_eq!(
            destination
                .put(upload(
                    &encoded,
                    &identity,
                    b"held content disclosure".len(),
                    profile,
                    ChunkPosition::Final
                ))
                .await
                .unwrap_or_else(|error| panic!("missing immutable row {artifact:?}: {error:?}")),
            identity
        );
        assert_eq!(TokioLocalFs.read_nofollow(&artifact).await.unwrap(), bytes);
        assert_eq!(
            destination.observe_publication().await.unwrap().stamp(),
            before
        );

        let mut damaged = bytes.clone();
        *damaged.last_mut().unwrap() ^= 1;
        tokio::fs::write(&artifact, &damaged).await.unwrap();
        let failure = destination
            .put(upload(
                &encoded,
                &identity,
                b"held content disclosure".len(),
                profile,
                ChunkPosition::Final,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName("publication".into())),
            "conflicting immutable row {artifact:?}"
        );
        assert_eq!(
            TokioLocalFs.read_nofollow(&artifact).await.unwrap(),
            damaged
        );
        assert_eq!(
            destination.observe_for_read().await.unwrap().stamp(),
            before
        );
        tokio::fs::write(&artifact, &bytes).await.unwrap();

        for defect in ["missing", "corrupt", "unavailable"] {
            for (offer, offered_identity, length) in [
                (&encoded, &identity, b"held content disclosure".len()),
                (&new_encoded, &new_identity, new_bytes.len()),
            ] {
                let preparation = prefix(&bucket, &destination).await;
                let (arrived, release) = arm(&bucket, &artifact, &preparation);
                bucket.inner.fs.reset_read_counters();
                let (put, ()) = tokio::join!(
                    destination.put(upload(
                        offer,
                        offered_identity,
                        length,
                        profile,
                        ChunkPosition::Final
                    )),
                    async {
                        arrived.await.unwrap();
                        assert_eq!(Trace::capture(&bucket).effects, preparation.effects);
                        match defect {
                            "missing" => tokio::fs::remove_file(&artifact).await.unwrap(),
                            "corrupt" => {
                                let mut damaged = bytes.clone();
                                *damaged.last_mut().unwrap() ^= 1;
                                tokio::fs::write(&artifact, damaged).await.unwrap();
                            }
                            _ => {
                                *bucket.inner.fs.read_failure.lock().unwrap() =
                                    Some(artifact.clone())
                            }
                        }
                        release.send(()).unwrap();
                    }
                );
                let failure = put.unwrap_err();
                if defect == "unavailable" {
                    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
                } else {
                    assert_eq!(
                        failure.kind(),
                        crate::bucket::files::layout_corrupt().kind()
                    );
                }
                assert!(bucket.inner.fs.before_read_gate.lock().unwrap().is_none());
                assert_eq!(Trace::capture(&bucket).effects, preparation.effects);
                bucket.inner.fs.read_failure.lock().unwrap().take();
                tokio::fs::write(&artifact, &bytes).await.unwrap();
            }
        }
    }
    assert_eq!(destination.get(&identity, None).await.unwrap(), encoded);
    assert!(!destination.has(&[new_identity]).await.unwrap()[0]);
    drop(destination);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_upload_revalidates_actual_ancestry_before_dedup_or_staging() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        ..
    } = filtered().await;
    let artifact = artifacts(&bucket).await.remove(0);
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let destination = holder.destination();
    let profile = &bucket.inner.config.chunk_profile;
    let new_bytes = b"refused new held upload";
    let new_identity = chunk_identity(new_bytes);
    let new_encoded = raw(new_bytes);

    for (offer, offered_identity, length) in [
        (&encoded, &identity, b"held content disclosure".len()),
        (&new_encoded, &new_identity, new_bytes.len()),
    ] {
        let preparation = prefix(&bucket, &destination).await;
        let (arrived, release) = arm(&bucket, &artifact, &preparation);
        bucket.inner.fs.reset_read_counters();
        let (put, ()) = tokio::join!(
            destination.put(upload(
                offer,
                offered_identity,
                length,
                profile,
                ChunkPosition::Final
            )),
            async {
                arrived.await.unwrap();
                assert_eq!(Trace::capture(&bucket).effects, preparation.effects);
                TokioLocalFs
                    .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o775))
                    .await
                    .unwrap();
                release.send(()).unwrap();
            }
        );
        assert!(put.is_err());
        assert!(bucket.inner.fs.before_read_gate.lock().unwrap().is_none());
        assert_eq!(Trace::capture(&bucket).effects, preparation.effects);
        TokioLocalFs
            .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
    }
    assert_eq!(destination.get(&identity, None).await.unwrap(), encoded);
    assert!(!destination.has(&[new_identity]).await.unwrap()[0]);
    drop(destination);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

#[tokio::test]
async fn held_upload_refuses_intervening_selected_publication_before_success() {
    let ContentFixture {
        parent,
        bucket,
        identity,
        encoded,
        ..
    } = filtered().await;
    let artifact = artifacts(&bucket).await.remove(0);
    let holder = SingleHeld::acquire(&bucket).await.unwrap();
    let destination = holder.destination();
    let profile = &bucket.inner.config.chunk_profile;
    let new_bytes = b"interrupted new held upload";
    let new_identity = chunk_identity(new_bytes);
    let new_encoded = raw(new_bytes);

    for (offer, offered_identity, length) in [
        (&encoded, &identity, b"held content disclosure".len()),
        (&new_encoded, &new_identity, new_bytes.len()),
    ] {
        let preparation = prefix(&bucket, &destination).await;
        let before = destination.observe_publication().await.unwrap();
        let (arrived, release) = arm(&bucket, &artifact, &preparation);
        bucket.inner.fs.reset_read_counters();
        let (put, written) = tokio::join!(
            destination.put(upload(
                offer,
                offered_identity,
                length,
                profile,
                ChunkPosition::Final
            )),
            async {
                arrived.await.unwrap();
                assert_eq!(Trace::capture(&bucket).effects, preparation.effects);
                let written = destination.publish_raw(&before, Vec::new()).await.unwrap();
                // Only the paused upload remains active after this genuine
                // publication finishes. Measure its remaining effects alone.
                bucket.inner.fs.reset_read_counters();
                release.send(()).unwrap();
                written
            }
        );
        assert!(matches!(
            put.unwrap_err().kind(),
            StoreErrorKind::Unavailable { .. }
        ));
        assert!(bucket.inner.fs.before_read_gate.lock().unwrap().is_none());
        assert_eq!(written.stamp.0, before.stamp().0 + 1);
        assert_eq!(Trace::capture(&bucket).effects, (0, 0));
        assert_eq!(
            destination.observe_publication().await.unwrap().stamp(),
            written.stamp
        );
    }
    assert_eq!(destination.get(&identity, None).await.unwrap(), encoded);
    assert!(!destination.has(&[new_identity]).await.unwrap()[0]);
    drop(destination);
    drop(holder);
    tokio::fs::remove_dir_all(parent).await.unwrap();
}

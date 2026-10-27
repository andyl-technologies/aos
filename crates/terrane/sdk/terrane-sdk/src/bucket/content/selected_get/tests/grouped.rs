//! Exercises complete grouped reads against actual persisted native artifacts.

use super::*;

#[tokio::test]
async fn ordinary_get_many_preserves_order_duplicates_and_group_boundaries() -> TestResult {
    let fixture = Fixture::new().await?;
    let plaintext = b"a distinct final body in a separate actual pack";
    let second = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    let encoded = raw(plaintext);
    admit(&fixture.bucket, &second, &encoded, plaintext.len()).await?;

    let identities: Vec<_> = (0..130)
        .map(|position| {
            if position % 3 == 0 {
                second.clone()
            } else {
                fixture.identity.clone()
            }
        })
        .collect();
    fixture.bucket.observe_content_for_tests().reset();
    let values = fixture.bucket.get_many(&identities).await?;

    assert_eq!(values.len(), identities.len());
    for (identity, bytes) in identities.iter().zip(values) {
        assert_eq!(
            bytes,
            if identity == &second {
                &encoded
            } else {
                &fixture.encoded
            }
            .as_slice()
        );
    }
    assert_eq!(
        fixture
            .bucket
            .observe_content_for_tests()
            .snapshot()
            .chunk_gets,
        identities.len()
    );

    fixture.remove().await
}

#[tokio::test]
async fn ordinary_get_many_refuses_absent_suffix_and_avoids_empty_backend_access() -> TestResult {
    let fixture = Fixture::new().await?;
    let absent = TERRANE_V1.calculate(IdentityKind::Chunk, b"never admitted")?;
    let error = fixture
        .bucket
        .get_many(&[fixture.identity.clone(), absent])
        .await
        .err()
        .ok_or("missing suffix unexpectedly returned a partial group")?;
    assert!(matches!(error.kind(), StoreErrorKind::Absent(_)));

    let bucket = fixture.bucket.clone();
    fixture.remove().await?;
    assert!(bucket.get_many(&[]).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn ordinary_get_many_closes_every_payload_and_complete_selected_catalog() -> TestResult {
    for fault in 0..5 {
        let fixture = Fixture::new().await?;
        let plaintext = b"another pack that must retain its own closing recipe";
        let second = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
        admit(&fixture.bucket, &second, &raw(plaintext), plaintext.len()).await?;

        let target = {
            let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
            let held = holder.source();
            let observed = held.observe_for_read().await?;
            let catalog = fixture.bucket.catalog_observed(&observed).await?;
            let location = fixture.bucket.location(&catalog, &second)?;
            match fault {
                0 => fixture.pack.clone(),
                1 => fixture.bucket.root().join(location.pack().pack_key()),
                2 => fixture.bucket.root().join(location.pack().index_key()),
                3 => {
                    let generation = catalog.capabilities.generation.ok_or("no generation")?;
                    // A shard unrelated to either requested body is still part
                    // of the complete selected projection and must close.
                    let shard = catalog
                        .shards
                        .iter()
                        .map(|shard| shard.shard())
                        .find(|shard| {
                            *shard != fixture.identity.digest()[0] && *shard != second.digest()[0]
                        })
                        .ok_or("no independent shard")?;
                    fixture
                        .bucket
                        .root()
                        .join(format!("objects/index/{generation}/{shard}.idx"))
                }
                _ => control_path(fixture.bucket.root())
                    .join(format!("publication/commits/{}", observed.state().revision)),
            }
        };

        let pause = fixture.bucket.observe_content_for_tests().pause_next_get();
        let bucket = fixture.bucket.clone();
        let identities = [fixture.identity.clone(), second];
        let request = tokio::spawn(async move { bucket.get_many(&identities).await });
        if let Err(error) =
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.arrived.notified()).await
        {
            request.abort();
            let outcome = request.await;
            return Err(format!("group did not reach closing: {error}; {outcome:?}").into());
        }

        replace_equal(&target).await?;
        pause.release.notify_one();
        assert!(
            request.await?.is_err(),
            "changed group input returned bytes"
        );
        fixture.remove().await?;
    }
    Ok(())
}

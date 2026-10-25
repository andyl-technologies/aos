//! Qualifies fresh-cycle recovery without repairing an older Trash incarnation.

use super::*;
use crate::store::Clock;
use std::os::unix::fs::MetadataExt;
use terrane_format::gc::{ArtifactBinding, CreationJournal, JournalState};

async fn optional_journal(path: &std::path::Path) -> Option<Vec<u8>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read protected creation journal: {error}"),
    }
}

#[tokio::test]
async fn gc_refresh_native_missing_trash_uses_fresh_cycle_and_preserves_old_journal() {
    for interrupted_creation in [false, true] {
        let fixture = Fixture::new().await;
        let (id, upper) = orphan(&fixture).await;
        let base = upper.checked_add(windows().grace() + 1).unwrap();
        let mut original = completed(&fixture, base, windows()).await;

        if interrupted_creation {
            fixture.fs.fail_next_retirement(
                RetirementPhase::Pending,
                EffectFault::BeforeFileSync,
                false,
            );
            assert!(
                original
                    .retire_one(fixture.repository.coordinator())
                    .await
                    .is_err()
            );
            fixture.fs.assert_retirement_hook_consumed();
        } else {
            let trash = original
                .retire_one(fixture.repository.coordinator())
                .await
                .unwrap()
                .unwrap();
            tokio::fs::remove_file(
                fixture
                    .config
                    .root
                    .join(format!("trash/{}/{id}", trash.cycle)),
            )
            .await
            .unwrap();
        }

        let before = image(&fixture).await;
        let old = before
            .manifest
            .exclusions
            .as_ref()
            .unwrap()
            .iter()
            .find(|row| row.pack_id == *id.as_bytes())
            .unwrap()
            .clone();
        let old_key = format!("trash/{}/{id}", old.cycle);
        assert!(!fixture.config.root.join(&old_key).exists());
        let old_journal = optional_journal(&journal(&fixture, &old_key)).await;
        if !interrupted_creation {
            assert!(old_journal.is_some());
        }
        let versions = [id.pack_key(), id.index_key()].map(|key| {
            let metadata = std::fs::symlink_metadata(fixture.config.root.join(key)).unwrap();
            (metadata.dev(), metadata.ino(), metadata.len())
        });
        let expiry = original.lease().expiry;
        let ticks = fixture.clock.monotonic().as_secs();
        drop(original);

        fixture.clock.set(expiry + 1, ticks + 1);
        let mut current = Collection::start_next(
            fixture.guard(),
            &fixture.authority,
            "fresh-missing-trash-recovery".into(),
            1_000,
            windows(),
        )
        .await
        .unwrap();
        assert!(current.state().cycle > old.cycle);
        assert!(current.lease().epoch > old.epoch);

        let lease = current.lease().clone();
        let unmarked = image(&fixture).await;
        assert!(
            current
                .refresh_exclusion(fixture.repository.coordinator(), old.clone())
                .await
                .is_err()
        );
        assert_eq!(current.lease(), &lease);
        let unchanged = image(&fixture).await;
        assert_eq!(unchanged.state, unmarked.state);
        assert_eq!(unchanged.logical, unmarked.logical);

        current.mark_batch(32).await.unwrap();
        current.finish_mark().await.unwrap();
        let checkpoint = current.state().clone();
        let refreshed = current
            .refresh_exclusion(fixture.repository.coordinator(), old.clone())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(refreshed.pack, old.pack_id);
        assert_eq!(refreshed.cycle, current.state().cycle);
        assert_eq!(refreshed.epoch, current.lease().epoch);
        assert_eq!(refreshed.timestamp, expiry + 1);
        assert_eq!(current.state(), &checkpoint);
        let after = image(&fixture).await;
        assert_eq!(after.state.branches, before.state.branches);
        assert_eq!(after.state.sources, before.state.sources);
        assert_eq!(
            after.state.loss_generation,
            before.state.loss_generation + 1
        );
        assert_eq!(after.manifest.inventory, before.manifest.inventory);
        assert_eq!(after.manifest.burns, before.manifest.burns);
        assert_eq!(after.manifest.exclusions, Some(vec![selector(&refreshed)]));

        let new_key = format!("trash/{}/{id}", refreshed.cycle);
        let bytes = tokio::fs::read(fixture.config.root.join(&new_key))
            .await
            .unwrap();
        assert_eq!(bytes, refreshed.encode());
        let created =
            CreationJournal::decode(&tokio::fs::read(journal(&fixture, &new_key)).await.unwrap())
                .unwrap();
        assert_eq!(created.key, new_key);
        assert!(matches!(created.state, JournalState::Committed {
            binding: ArtifactBinding::Trash(ref binding), ref file_identity,
        } if binding == &bytes && !file_identity.is_empty()));
        if let Some(previous) = &old_journal {
            assert_ne!(
                created.nonce,
                CreationJournal::decode(previous).unwrap().nonce
            );
        }
        assert!(!fixture.config.root.join(&old_key).exists());
        assert_eq!(
            optional_journal(&journal(&fixture, &old_key)).await,
            old_journal
        );
        for (key, version) in [id.pack_key(), id.index_key()].into_iter().zip(versions) {
            let metadata = std::fs::symlink_metadata(fixture.config.root.join(key)).unwrap();
            assert_eq!((metadata.dev(), metadata.ino(), metadata.len()), version);
        }
        assert!(
            current
                .refresh_exclusion(fixture.repository.coordinator(), old)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            current
                .refresh_exclusion(fixture.repository.coordinator(), selector(&refreshed))
                .await
                .is_err()
        );
        assert_eq!(current.state(), &checkpoint);
        assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    }
}

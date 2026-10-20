//! Executes seven genuine native physical-loss and closed Raw durability witnesses.
//!
//! These tests create actual signed selected Nodes through Repository. Physical
//! loss is an explicit storage fault; neither decoded journal bytes nor fixture
//! observations construct creator, current, retirement or deletion permission.

mod fs;
mod support;

use crate::store::{ContentStore, ContentUpload, EffectFault, MetaUpload, StoreErrorKind};
use fs::RawMode;
use std::{error::Error, io, os::unix::fs::MetadataExt, sync::mpsc, time::Duration};
use support::{Fixture, TestResult, assert_identity_corrupt, files, rejected, required};
use terrane_format::identity::IdentityKind;

#[tokio::test]
async fn missing_pack_reoffering_selects_fresh_verified_placement() -> TestResult {
    let fixture = Fixture::new().await?;
    let before = fixture.snapshot().await?;
    let pack = std::fs::read(&fixture.pack)?;
    let index = std::fs::read(&fixture.index)?;
    let inventory = required(
        before
            .inventory
            .as_ref()
            .ok_or("modern old inventory absent"),
    );
    let member = required(
        inventory
            .iter()
            .find(|entry| entry.pack_id == *fixture.row.pack().as_bytes())
            .ok_or("old inventory member absent"),
    );
    assert_eq!(member.pack_size, pack.len() as u64);
    assert_eq!(
        member.pack_hash,
        terrane_format::identity::TERRANE_V1
            .calculate(IdentityKind::Pack, &pack)?
            .terrane_v1_digest()?
    );
    std::fs::remove_file(&fixture.pack)?;

    assert_eq!(fixture.offer().await?, fixture.identity);

    assert!(!fixture.pack.exists());
    assert_eq!(std::fs::read(&fixture.index)?, index);
    fixture.assert_replaced(&before).await?;
    // A later dedup must verify actual replacement bytes and create nothing.
    fixture.fs.reset();
    let selected = fixture.snapshot().await?;
    assert_eq!(fixture.offer().await?, fixture.identity);
    assert_eq!(fixture.snapshot().await?, selected);
    let trace = fixture.fs.observations();
    assert_eq!(trace.raw, 0);
    assert!(trace.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn missing_index_reoffering_selects_fresh_verified_placement() -> TestResult {
    let fixture = Fixture::new().await?;
    let before = fixture.snapshot().await?;
    let pack = std::fs::read(&fixture.pack)?;
    std::fs::remove_file(&fixture.index)?;

    assert_eq!(fixture.offer().await?, fixture.identity);

    assert!(!fixture.index.exists());
    assert_eq!(std::fs::read(&fixture.pack)?, pack);
    fixture.assert_replaced(&before).await
}

#[tokio::test]
async fn present_corruption_never_becomes_missing_placement() -> TestResult {
    // Present corruption refuses even when the other member really is absent.
    for (corrupt_pack, remove_counterpart) in
        [(true, false), (false, false), (true, true), (false, true)]
    {
        let fixture = Fixture::new().await?;
        let path = if corrupt_pack {
            &fixture.pack
        } else {
            &fixture.index
        };
        let counterpart = if corrupt_pack {
            &fixture.index
        } else {
            &fixture.pack
        };
        let original = fixture.snapshot().await?;
        let inventory = required(original.inventory.as_ref().ok_or("modern inventory absent"));
        let member = required(
            inventory
                .iter()
                .find(|entry| entry.pack_id == *fixture.row.pack().as_bytes())
                .ok_or("old inventory member absent"),
        );
        let (kind, digest) = if corrupt_pack {
            (IdentityKind::Pack, member.pack_hash)
        } else {
            (IdentityKind::Index, member.index_hash)
        };
        let expected_corrupt = terrane_format::identity::TERRANE_V1.from_digest(kind, &digest)?;
        let mut bytes = std::fs::read(path)?;
        terrane_format::identity::TERRANE_V1.verify(&expected_corrupt, &bytes)?;
        let first = required(bytes.first_mut().ok_or("empty original artifact"));
        *first ^= 1;
        std::fs::write(path, &bytes)?;
        if remove_counterpart {
            std::fs::remove_file(counterpart)?;
        }
        let before = fixture.snapshot().await?;
        let physical = files(fixture.bucket().root())?;

        let error = rejected(fixture.offer().await);

        assert_identity_corrupt(&error, &expected_corrupt, &fixture.fs);
        assert_eq!(fixture.snapshot().await?, before);
        assert_eq!(files(fixture.bucket().root())?, physical);
        assert_eq!(std::fs::read(path)?, bytes);
    }
    Ok(())
}

#[tokio::test]
async fn quarantine_and_exclusion_never_become_missing_placement() -> TestResult {
    let fixture = Fixture::new().await?;
    // This is the genuine identity-exclusion producer, not fabricated GC key6,
    // encoded DeleteOwned or a claim of physical collector retirement.
    fixture.bucket().exclude(&fixture.identity).await?;
    std::fs::remove_file(&fixture.pack)?;
    fixture.fs.reset();
    let before = fixture.snapshot().await?;
    let physical = files(fixture.bucket().root())?;
    let catalog = fixture.bucket().catalog().await?;
    assert!(
        fixture
            .bucket()
            .is_quarantined(&catalog, &fixture.identity)?
    );
    assert!(fixture.bucket().is_excluded(&catalog, &fixture.identity)?);

    let error = rejected(fixture.offer().await);

    assert_identity_corrupt(&error, &fixture.identity, &fixture.fs);
    assert_eq!(fixture.snapshot().await?, before);
    assert_eq!(files(fixture.bucket().root())?, physical);
    assert_eq!(
        fixture
            .bucket()
            .has(std::slice::from_ref(&fixture.identity))
            .await?,
        [false]
    );
    Ok(())
}

#[tokio::test]
async fn unavailable_artifact_read_never_becomes_missing_placement() -> TestResult {
    for (fail_pack, remove_other) in [(true, false), (false, true)] {
        let fixture = Fixture::new().await?;
        let unavailable = if fail_pack {
            fixture.pack.clone()
        } else {
            fixture.index.clone()
        };
        if remove_other {
            std::fs::remove_file(&fixture.pack)?;
        }
        let before = fixture.snapshot().await?;
        let physical = files(fixture.bucket().root())?;
        fixture.fs.unavailable(unavailable);

        let error = rejected(fixture.offer().await);

        assert!(
            matches!(
                error.kind(),
                StoreErrorKind::Unavailable { retry_after: None }
            ),
            "wrong typed outcome: {error:?}"
        );
        let source = required(error.source().ok_or("backend cause lost"));
        let cause = required(
            source
                .downcast_ref::<io::Error>()
                .ok_or("original I/O cause not preserved"),
        );
        assert_eq!(cause.kind(), io::ErrorKind::Other);
        assert_eq!(
            cause.to_string(),
            "missing-placement fixture exact nofollow read unavailable"
        );
        let trace = fixture.fs.observations();
        assert_eq!(trace.unavailable_reads, 1);
        assert_eq!(trace.raw, 0);
        assert!(trace.pending.is_empty());
        assert_eq!(fixture.snapshot().await?, before);
        assert_eq!(files(fixture.bucket().root())?, physical);
    }
    Ok(())
}

#[tokio::test]
async fn original_absence_and_ancestry_survive_native_publication_handoff() -> TestResult {
    for replace_parent in [false, true] {
        let fixture = Fixture::new().await?;
        let pack = std::fs::read(&fixture.pack)?;
        let permissions = std::fs::metadata(&fixture.pack)?.permissions();
        let before = fixture.snapshot().await?;
        std::fs::remove_file(&fixture.pack)?;
        let (arrive, arrived) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (after, synchronized) = mpsc::channel();
        fixture.fs.arm(RawMode::Pause(arrive, released, after));
        let bucket = fixture.bucket().clone();
        let body = fixture.bytes.clone();
        let operation = tokio::spawn(async move {
            bucket
                .put(ContentUpload::Meta(MetaUpload::new(
                    IdentityKind::Node,
                    &body,
                )?))
                .await
        });
        // Uses the unchanged native handoff bound. Arrival is signaled by the
        // actual worker after output file sync, before its directory syscall.
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)))
            .await??;
        if replace_parent {
            let parent = required(fixture.pack.parent().ok_or("pack parent absent"));
            let inode = std::fs::symlink_metadata(parent)?.ino();
            let backup = parent.with_file_name(format!(
                "{}-replaced",
                required(parent.file_name().ok_or("parent name absent")).to_string_lossy()
            ));
            let permissions = std::fs::metadata(parent)?.permissions();
            std::fs::rename(parent, &backup)?;
            std::fs::create_dir(parent)?;
            std::fs::set_permissions(parent, permissions)?;
            // Move real descendants, preserving every file body/incarnation.
            // Only the exact original ancestor is replaced by this storage fault.
            for entry in std::fs::read_dir(&backup)? {
                let entry = entry?;
                std::fs::rename(entry.path(), parent.join(entry.file_name()))?;
            }
            assert_ne!(std::fs::symlink_metadata(parent)?.ino(), inode);
            assert!(!fixture.pack.exists());
        } else {
            std::fs::write(&fixture.pack, &pack)?;
            std::fs::set_permissions(&fixture.pack, permissions)?;
            assert_eq!(std::fs::read(&fixture.pack)?, pack);
        }
        release.send(())?;

        let error = rejected(operation.await?);

        assert!(
            matches!(error.kind(), StoreErrorKind::Unavailable { .. }),
            "wrong native preimage refusal: {error:?}"
        );
        assert!(
            error.source().is_some(),
            "actual native diagnostic was lost"
        );
        assert!(
            synchronized.try_recv().is_err(),
            "directory syscall ran after changed original preimage"
        );
        let trace = fixture.fs.observations();
        assert_eq!(trace.raw, 1);
        assert_eq!(trace.committed.len(), 2);
        // Earlier selected renames may be visible despite refusal. We require
        // no acknowledgment and exact unrelated authority preservation, not rollback.
        let current = fixture.snapshot().await?;
        assert_eq!(current.original_files, before.original_files);
        assert_eq!(current.registration, before.registration);
        assert_eq!(current.state.guard, before.state.guard);
        assert_eq!(current.state.branches, before.state.branches);
        assert_eq!(current.state.burn_owners, before.state.burn_owners);
    }
    Ok(())
}

#[tokio::test]
async fn raw_publication_ack_requires_actual_complete_durability() -> TestResult {
    // Finite physical faults cover both sides of file synchronization and both
    // actual namespace/control roots. Each swallowed worker error must occur;
    // selecting a wrapper branch alone is insufficient.
    for case in 0..7 {
        let fixture = Fixture::new().await?;
        let before = fixture.snapshot().await?;
        std::fs::remove_file(&fixture.pack)?;
        let mode = match case {
            0 => RawMode::Noop,
            1 => RawMode::Swallow(EffectFault::BeforeFileSync),
            2 => RawMode::Swallow(EffectFault::AfterFileSync),
            3 => RawMode::Swallow(EffectFault::BeforeDirectorySyncAt(
                fixture.bucket().root().to_owned(),
            )),
            4 => RawMode::Swallow(EffectFault::AfterDirectorySyncAt(
                fixture.bucket().root().to_owned(),
            )),
            5 => RawMode::Swallow(EffectFault::BeforeDirectorySyncAt(fixture.backend.clone())),
            6 => RawMode::Swallow(EffectFault::AfterDirectorySyncAt(fixture.backend.clone())),
            _ => unreachable!("finite fixture strategy"),
        };
        fixture.fs.arm(mode);

        let error = rejected(fixture.offer().await);

        assert!(
            matches!(error.kind(), StoreErrorKind::Unsupported),
            "missing native result accepted or misclassified: {error:?}"
        );
        let source = required(error.source().ok_or("missing-result cause lost"));
        let cause = required(
            source
                .downcast_ref::<io::Error>()
                .ok_or("actual missing-result I/O source lost"),
        );
        assert_eq!(cause.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            cause.to_string(),
            "native raw publication acknowledgment unavailable"
        );
        let trace = fixture.fs.observations();
        assert_eq!(trace.raw, 1);
        assert_eq!(trace.pending.len(), 2);
        assert_eq!(trace.committed.len(), 2);
        assert_eq!(trace.swallowed.len(), usize::from(case != 0));
        let current = fixture.snapshot().await?;
        assert_eq!(current.original_files, before.original_files);
        assert_eq!(current.registration, before.registration);
        assert_eq!(current.state.guard, before.state.guard);
        assert_eq!(current.state.branches, before.state.branches);
        assert_eq!(current.exclusions, before.exclusions);
        assert_eq!(current.burns, before.burns);
        // The fresh pair is genuinely Committed even though this later catalog
        // acknowledgment fails; it grants no returned put success or lineage carry.
        assert!(current.state.sources.is_empty());
        assert_eq!(
            current.state.loss_generation,
            before
                .state
                .loss_generation
                .checked_add(1)
                .ok_or("loss overflow")?
        );
    }
    let fixture = Fixture::new().await?;
    let before = fixture.snapshot().await?;
    std::fs::remove_file(&fixture.pack)?;
    fixture.fs.arm(RawMode::Real);

    assert_eq!(fixture.offer().await?, fixture.identity);

    fixture.assert_replaced(&before).await?;
    assert!(fixture.fs.observations().swallowed.is_empty());
    Ok(())
}

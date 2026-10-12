//! Refuses physical and live-current changes after full source qualification.

use super::*;
use crate::selected_bridge::native_guard::cold_fork::tests::ordinary::fs::SourceMutation;

enum Fault {
    Original,
    Source,
    Log,
    Control,
    Time,
}

async fn check_changed_source(fault: Fault) -> TestResult {
    let fixture = Fixture::open().await?;
    install_raw_alias(&fixture, DESTINATION).await?;
    let before = SourceSnapshot::capture(&fixture.repository, &fixture.clock, DESTINATION).await?;
    let original = fixture
        .repository
        .coordinator()
        .guard()
        .original_commit(&before.record.commit)?;
    let original_path = original
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{}.cbor", hex(before.record.commit)));
    let original_body = fixture.fs.read_nofollow(&original_path).await?;
    let timed = matches!(fault, Fault::Time);
    let mutation = match fault {
        Fault::Original => SourceMutation::RemoveOriginal(original_path.clone()),
        Fault::Source => replacement(&before.source_transaction)?,
        Fault::Log => replacement(before.history.first().ok_or("missing actual source log")?)?,
        Fault::Control => SourceMutation::MakeControlWritable(original_path.clone()),
        Fault::Time => SourceMutation::ExpireToken(fixture.clock.clone()),
    };
    fixture
        .fs
        .mutate_requalification_at_lineage(before.control.join("publication/lineage"), mutation)?;
    fixture
        .fs
        .observe_requalification_ack(before.ack_slot(), false)?;
    let observer = fixture
        .repository
        .coordinator()
        .store()
        .observe_content_for_tests();
    observer.reset();

    let failure = fixture
        .repository
        .requalify_fork_source(DESTINATION, fixture.authority.token(), "sdk")
        .await
        .err()
        .ok_or("changed qualified source acknowledged")?;

    assert_eq!(
        fixture.fs.requalification_mutations(),
        1,
        "real immutable lineage effect must trigger the physical change"
    );
    assert!(
        observer.snapshot().node_gets > 0,
        "actual full completion precedes lineage installation"
    );
    assert!(observer.snapshot().node_decodes > 0);
    let error = store_failure(&failure)?;
    if timed {
        assert!(
            matches!(error.kind(), StoreErrorKind::Denied { verb: "fork", .. }),
            "{failure:?}"
        );
    } else {
        assert!(
            matches!(failure, Error::Advance(AdvanceError::Indeterminate { .. })),
            "{failure:?}"
        );
        assert!(
            matches!(error.kind(), StoreErrorKind::Unavailable { .. }),
            "{error:?}"
        );
    }
    assert_eq!(fixture.fs.requalification_ack_counts().1, 0);
    assert!(
        !before.ack_slot().exists(),
        "pre-publication refusal must not select a new slot"
    );
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(DESTINATION)
            .await?,
        Some(before.record.clone())
    );
    let commit = TERRANE_V1.from_digest(IdentityKind::Commit, &before.record.commit)?;
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .store()
            .get(&commit, None)
            .await?,
        before.commit
    );
    for read in &before.history {
        assert_eq!(
            fixture.fs.read_nofollow(read.path()).await?.as_slice(),
            read.bytes().ok_or("missing log body")?
        );
    }
    // Equal-byte source/log replacements still invalidate retained incarnations;
    // they cannot manufacture a logical advance while namespace exclusion holds.
    assert_eq!(
        fixture
            .fs
            .read_nofollow(before.source_transaction.path())
            .await?
            .as_slice(),
        before
            .source_transaction
            .bytes()
            .ok_or("missing source transaction")?
    );
    if original_path.exists() {
        assert_eq!(
            fixture.fs.read_nofollow(&original_path).await?,
            original_body
        );
    }
    Ok(())
}

fn replacement(read: &RecordRead) -> TestResult<SourceMutation> {
    Ok(SourceMutation::ReplaceRecord {
        path: read.path().to_owned(),
        bytes: read
            .bytes()
            .ok_or("missing actual source preimage")?
            .to_vec(),
        permissions: read
            .metadata()
            .ok_or("missing actual source incarnation")?
            .permissions(),
    })
}

fn hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn requalification_refuses_original_loss_at_lineage_install() -> TestResult {
    check_changed_source(Fault::Original).await
}

#[tokio::test]
async fn requalification_refuses_source_record_replacement_at_lineage_install() -> TestResult {
    check_changed_source(Fault::Source).await
}

#[tokio::test]
async fn requalification_refuses_selected_log_replacement_at_lineage_install() -> TestResult {
    check_changed_source(Fault::Log).await
}

#[tokio::test]
async fn requalification_refuses_control_permission_change_at_lineage_install() -> TestResult {
    check_changed_source(Fault::Control).await
}

#[tokio::test]
async fn requalification_refuses_token_expiry_at_lineage_install() -> TestResult {
    check_changed_source(Fault::Time).await
}

#[tokio::test]
async fn requalification_refuses_native_sync_without_ack() -> TestResult {
    let fixture = Fixture::open().await?;
    install_raw_alias(&fixture, DESTINATION).await?;
    let before = SourceSnapshot::capture(&fixture.repository, &fixture.clock, DESTINATION).await?;
    fixture
        .fs
        .observe_requalification_ack(before.ack_slot(), true)?;
    let observer = fixture
        .repository
        .coordinator()
        .store()
        .observe_content_for_tests();
    observer.reset();

    let failure = fixture
        .repository
        .requalify_fork_source(DESTINATION, fixture.authority.token(), "sdk")
        .await
        .err()
        .ok_or("failed real native synchronization acknowledged")?;

    assert!(
        matches!(failure, Error::Advance(AdvanceError::Indeterminate { .. })),
        "{failure:?}"
    );
    assert!(matches!(
        store_failure(&failure)?.kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    assert_eq!(fixture.fs.requalification_ack_counts(), (1, 0));
    assert!(observer.snapshot().node_gets > 0);
    assert!(observer.snapshot().node_decodes > 0);
    before
        .assert_source_unchanged(&fixture.repository, &fixture.fs, DESTINATION)
        .await?;
    // The slot may have become visible before its synchronization failed.
    // An unchanged source head is never a substitute for the missing ACK.
    Ok(())
}

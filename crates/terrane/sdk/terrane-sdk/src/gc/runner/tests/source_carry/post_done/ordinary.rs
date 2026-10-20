//! Checks actual native Done preserves an ordinary complete signed source.

use super::super::{
    SOURCE,
    support::{PublicFixture, public_orphan},
};
use super::{cold, fs::ProbeFs, support};

#[tokio::test]
async fn ordinary_source_and_original_survive_done_reopen_and_zero_node_cold_fork() {
    let fixture = PublicFixture::open_file().await;
    let (pack, modified) = public_orphan(&fixture).await;
    let fs = ProbeFs::new(fixture.repository.coordinator().fs().clone());
    let repository = support::reopen(&fixture, &fs).await;
    let completed =
        support::delete_orphan(&fixture, &repository, SOURCE, pack, modified, &fs).await;
    assert!(!completed.lineage.used.views.is_empty());
    assert!(
        completed
            .lineage
            .used
            .check_supported_view_contexts()
            .unwrap()
    );
    drop(repository);

    let reopened = support::reopen(&fixture, &fs).await;
    let current = support::snapshot(&reopened, SOURCE).await;
    support::assert_preserved(&completed, &current, true);
    cold::fork(
        &reopened,
        &fixture,
        SOURCE,
        "refs/heads/_/post-done-ordinary-fork",
        &current,
    )
    .await;
    assert_eq!(
        fs.successful_ref_ack("refs/heads/_/post-done-ordinary-fork"),
        1
    );
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .fs()
            .data_body_read_attempts(),
        0
    );
}

#[tokio::test]
async fn consumed_original_reincarnation_after_done_refuses_cold_publication_without_tree_io() {
    use crate::store::{ContentStore, RefStore, StoreErrorKind};
    use terrane_format::gc::publication::evidence::ControlKind;
    use terrane_format::identity::{IdentityKind, TERRANE_V1};

    const TARGET: &str = "refs/heads/_/post-done-refused-fork";
    let fixture = PublicFixture::open_file().await;
    let (pack, modified) = public_orphan(&fixture).await;
    let fs = ProbeFs::new(fixture.repository.coordinator().fs().clone());
    let repository = support::reopen(&fixture, &fs).await;
    let completed =
        support::delete_orphan(&fixture, &repository, SOURCE, pack, modified, &fs).await;
    drop(repository);
    let reopened = support::reopen(&fixture, &fs).await;
    let current = support::snapshot(&reopened, SOURCE).await;
    support::assert_preserved(&completed, &current, true);
    let pin = current
        .lineage
        .controls
        .iter()
        .find(|pin| pin.kind == ControlKind::Association)
        .unwrap();
    let control = current
        .controls
        .iter()
        .find(|file| file.path.file_name().unwrap() == pin.key.as_str())
        .unwrap()
        .clone();
    pin.check_record(&control.bytes).unwrap();

    let store = reopened.coordinator().store();
    let observer = store.observe_metadata_for_tests().unwrap();
    let root = terrane_format::refs::Commit::decode(&current.lineage.commit_bytes)
        .unwrap()
        .tree;
    observer.reset();
    let bytes = store
        .get(
            &TERRANE_V1.from_digest(IdentityKind::Node, &root).unwrap(),
            None,
        )
        .await
        .unwrap();
    assert!(observer.snapshot().node_gets > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &bytes).unwrap(),
        ))
        .await
        .unwrap();
    assert!(observer.snapshot().node_puts > 0);
    assert!(observer.snapshot().node_decodes > 0);
    let before = support::snapshot(&reopened, SOURCE).await;
    observer.reset();
    // Replacement before the call could be legitimately observed anew. This
    // hook waits for real source qualification and immutable staging instead.
    fs.arm(control.path.clone());
    let error = reopened
        .fork(
            SOURCE,
            TARGET,
            reopened.source_request(
                &fixture.authority,
                super::super::support::public_metadata(
                    "Refuse changed consumed Original after Done",
                ),
            ),
        )
        .await
        .unwrap_err();
    let failure = match &error {
        crate::repository::Error::Store(failure) => failure,
        crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(failure)) => {
            failure
        }
        crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Indeterminate {
            source,
            ..
        }) => source,
        other => panic!("expected typed native storage refusal: {other:?}"),
    };
    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
    assert!(fs.reached());
    assert_eq!(fs.successful_ref_ack(TARGET), 0);
    assert!(store.ref_get(TARGET).await.unwrap().is_none());
    let after = support::snapshot(&reopened, SOURCE).await;
    assert_eq!(after.record, before.record);
    assert_eq!(after.lineage, before.lineage);
    assert_eq!(after.state.sources, before.state.sources);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.selected_files, before.selected_files);
    let replaced = super::support::Physical::read(&control.path);
    assert_eq!(replaced.bytes, control.bytes);
    assert_ne!(replaced.identity, control.identity);
    for file in &before.controls {
        if file.path != control.path {
            file.assert_current();
        }
    }
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_puts, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .fs()
            .data_body_read_attempts(),
        0
    );
}

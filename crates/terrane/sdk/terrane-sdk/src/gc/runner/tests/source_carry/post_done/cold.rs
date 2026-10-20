//! Calibrates the real validator and verifies zero-TreeNode post-Done cold forks.

use super::super::support::{PublicFixture, public_metadata};
use super::support::{NativeRepository, Snapshot, snapshot};
use crate::store::{ContentStore, RefStore};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::refs::Commit;

/// Verifies cold reuse against actual source authority after real physical loss.
///
/// # Panics
/// Panics on failed calibration, tree I/O, incorrect ancestry or invalid signature.
pub(super) async fn fork(
    repository: &NativeRepository,
    fixture: &PublicFixture,
    source: &str,
    destination: &str,
    preserved: &Snapshot,
) {
    let store = repository.coordinator().store();
    let observer = store.observe_metadata_for_tests().unwrap();
    let root = Commit::decode(&preserved.lineage.commit_bytes)
        .unwrap()
        .tree;
    let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root).unwrap();
    observer.reset();
    let bytes = store.get(&identity, None).await.unwrap();
    assert!(observer.snapshot().node_gets > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &bytes).unwrap(),
        ))
        .await
        .unwrap();
    let calibrated = observer.snapshot();
    assert!(calibrated.node_puts > 0);
    assert!(calibrated.node_decodes > 0);
    let before = snapshot(repository, source).await;
    assert_eq!(before.record, preserved.record);
    assert_eq!(before.lineage, preserved.lineage);
    assert_eq!(
        before.state.loss_generation,
        preserved.state.loss_generation
    );
    assert_eq!(before.controls, preserved.controls);
    for file in &preserved.controls {
        file.assert_current();
    }
    observer.reset();

    let fork = repository
        .fork(
            source,
            destination,
            repository.source_request(
                &fixture.authority,
                public_metadata("Fork source after actual native Done"),
            ),
        )
        .await
        .unwrap();
    let counts = observer.snapshot();
    assert_eq!(counts.node_gets, 0);
    assert_eq!(counts.node_puts, 0);
    assert_eq!(counts.node_decodes, 0);
    assert_eq!(counts.commit_puts, 1);
    assert_ne!(fork.commit, preserved.record.commit);
    let commit_bytes = store
        .get(
            &TERRANE_V1
                .from_digest(IdentityKind::Commit, &fork.commit)
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    let commit = Commit::decode(&commit_bytes).unwrap();
    assert_eq!(commit.tree, root);
    assert_eq!(commit.parents, vec![preserved.record.commit]);
    assert!(commit.signature.is_some());
    let context = commit.profile_pair.commit_context.as_ref().unwrap();
    assert_eq!(context.reference(), destination);
    let roots = context
        .roots()
        .iter()
        .map(|row| terrane_format::auth::RequestRoot {
            path: row.path(),
            domain: row.domain(),
        })
        .collect::<Vec<_>>();
    let verified = terrane_format::provenance::verify_history(
        &commit,
        repository.coordinator().guard().keys(),
        &roots,
        &[(destination, fork.writer_epoch)],
    )
    .unwrap();
    assert_eq!(verified.identity(), fork.commit);
    assert_eq!(
        store.ref_get(source).await.unwrap(),
        Some(preserved.record.clone())
    );
    assert_eq!(store.ref_get(destination).await.unwrap(), Some(fork));
    let after = snapshot(repository, source).await;
    assert_eq!(after.record, before.record);
    assert_eq!(after.lineage, before.lineage);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.controls, before.controls);
    assert_eq!(after.selected_files, before.selected_files);
    for file in &before.controls {
        file.assert_current();
    }
    assert_eq!(observer.snapshot().node_gets, 0);
    assert_eq!(observer.snapshot().node_puts, 0);
    assert_eq!(observer.snapshot().node_decodes, 0);
}

//! Checks genuine foreign used-view Original authority after local native Done.

use super::super::support::{PublicFixture, disclose_public_file, public_orphan};
use super::{cold, fs::ProbeFs, support};
use crate::store::ContentStore;
use terrane_format::gc::publication::evidence::ControlKind;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn foreign_used_view_and_original_survive_done_reopen_and_zero_node_cold_fork() {
    const SOURCE: &str = "refs/heads/_/post-done-foreign-view";
    const TARGET: &str = "refs/heads/_/post-done-foreign-fork";
    let foreign = PublicFixture::open_file().await;
    let destination = PublicFixture::open().await;
    let source = disclose_public_file(&foreign, &destination, SOURCE).await;
    let (pack, modified) = public_orphan(&destination).await;
    let fs = ProbeFs::new(destination.repository.coordinator().fs().clone());
    let repository = support::reopen(&destination, &fs).await;
    let prior = support::snapshot(&repository, SOURCE).await;
    assert_eq!(prior.record, source);
    let guard = repository.coordinator().guard();
    let local = guard.original_commit(&source.commit).unwrap();
    let imported = guard.original_commit(&foreign.record.commit).unwrap();
    assert_ne!(
        local.baseline().authority().id(),
        imported.baseline().authority().id()
    );
    assert_eq!(
        imported.baseline().authority().id(),
        foreign
            .repository
            .coordinator()
            .guard()
            .configured_original_authority()
            .unwrap()
            .id()
    );
    assert!(
        prior
            .lineage
            .used
            .views
            .iter()
            .any(|view| view.view == foreign.record.commit)
    );
    for kind in [
        ControlKind::Import,
        ControlKind::ImportBinding,
        ControlKind::ImportTrust,
    ] {
        assert!(prior.lineage.controls.iter().any(|pin| pin.kind == kind));
    }
    let foreign_commit = terrane_format::refs::Commit::decode(
        &foreign
            .repository
            .coordinator()
            .store()
            .get(
                &TERRANE_V1
                    .from_digest(IdentityKind::Commit, &foreign.record.commit)
                    .unwrap(),
                None,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let interpretation = prior
        .lineage
        .used
        .view_interpretations
        .as_ref()
        .unwrap()
        .iter()
        .find(|row| row.view == foreign.record.commit)
        .unwrap();
    assert_eq!(interpretation.original_root, foreign_commit.tree);
    let foreign_owner = imported.baseline().authority();
    let foreign_control = super::support::Physical::read(&foreign_owner.control().join(format!(
            "commit-{}.cbor",
            foreign
                .record
                .commit
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )));

    let completed =
        support::delete_orphan(&destination, &repository, SOURCE, pack, modified, &fs).await;
    assert_eq!(completed.lineage.source, prior.lineage.source);
    assert_eq!(completed.lineage.original, prior.lineage.original);
    assert_eq!(completed.lineage.controls, prior.lineage.controls);
    assert_eq!(
        completed.lineage.used.view_interpretations,
        prior.lineage.used.view_interpretations
    );
    assert_eq!(completed.controls, prior.controls);
    foreign_control.assert_current();
    drop(repository);

    let reopened = support::reopen(&destination, &fs).await;
    let current = support::snapshot(&reopened, SOURCE).await;
    support::assert_preserved(&completed, &current, true);
    let checked_foreign = reopened
        .coordinator()
        .guard()
        .original_commit(&foreign.record.commit)
        .unwrap();
    assert_eq!(checked_foreign.baseline().authority(), foreign_owner);
    foreign_control.assert_current();
    cold::fork(&reopened, &destination, SOURCE, TARGET, &current).await;
    assert_eq!(fs.successful_ref_ack(TARGET), 1);
    foreign_control.assert_current();
    assert_eq!(
        destination
            .repository
            .coordinator()
            .fs()
            .data_body_read_attempts(),
        0
    );
}

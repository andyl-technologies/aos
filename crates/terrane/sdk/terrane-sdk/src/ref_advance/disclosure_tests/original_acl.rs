//! Keeps imported original authoring policy independent of current destination policy.

use super::*;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::local_authority::retention::{ImportRecord, Record};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};

/// Rechecks retained original ACL evidence after its physical source is unavailable.
///
/// # Panics
/// Panics if genuine authoring or disclosure fails, source erasure changes the
/// original authoring reference, or corrupted original controls remain readable.
pub(super) async fn retain_original_authorization() {
    let (source, authority, credentials) = independent_factory("public").await;
    let (destination, destination_authority, _) = independent_factory_claims(
        "public",
        terrane_format::refs::PrincipalKind::Human,
        vec!["destination-current-policy".into()],
    )
    .await;
    let source_reference = "refs/heads/_/original";
    let destination_reference = "refs/heads/_/main";
    let plaintext = b"original authoring ACL remains independently retained";
    let mut source_session = source
        .begin(source_reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), plaintext);
    let mut proposal = authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    let original = source
        .guard()
        .original_commit(&source_head.commit)
        .unwrap()
        .retained_import_record()
        .unwrap();
    assert_eq!(original.baseline.reference, source_reference);
    assert_eq!(original.association.reference, source_reference);
    assert!(
        original
            .baseline
            .acl
            .iter()
            .any(|(name, verbs)| { name == "writer" && verbs & 1 != 0 })
    );
    assert_ne!(
        authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );

    let mut session = destination
        .begin(destination_reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), plaintext);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: source_reference.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    let retained = destination
        .guard()
        .original_commit(&source_head.commit)
        .unwrap()
        .retained_import_record()
        .unwrap();
    assert_eq!(retained, original);
    let checked = destination
        .guard()
        .read_snapshot(
            destination_reference,
            destination_authority.token(),
            b"/file",
            "sdk",
        )
        .await
        .unwrap();
    let (location, _) = checked.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        source_head.commit
    );
    assert!(checked.history.commit(&source_head.commit).is_some());

    let source_root = source.store().root().to_owned();
    let control = |root: &std::path::Path| {
        root.with_file_name(format!(
            "{}-original-control",
            root.file_name().unwrap().to_string_lossy()
        ))
    };
    let destination_root = destination.store().root().to_owned();
    let destination_control = control(&destination_root);
    let destination_config = destination.guard().config().clone();
    drop(checked);
    drop(source_session);
    drop(session);
    drop(source);
    drop(authority);
    for path in [control(&source_root), source_root, credentials] {
        tokio::fs::remove_dir_all(path).await.unwrap();
    }
    drop(destination);

    let bucket = FileBucket::open(
        config(destination_root).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let reopened = NativeFixture::reopen(Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![destination_authority.issuer_key().clone()],
            destination_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    ))
    .await;
    let checked = reopened
        .guard()
        .read_snapshot(
            destination_reference,
            destination_authority.token(),
            b"/file",
            "sdk",
        )
        .await
        .unwrap();
    assert_eq!(
        reopened
            .guard()
            .original_commit(&source_head.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
        original
    );
    let retained_path = destination_control.join(original.selector());
    let bytes = tokio::fs::read(&retained_path).await.unwrap();
    assert_eq!(ImportRecord::decode(&bytes).unwrap(), original);
    let mut changed = original.clone();
    changed.baseline.acl = vec![("unrelated-original-author".into(), 31)];
    let changed_bytes = changed.encode().unwrap();
    assert_eq!(ImportRecord::decode(&changed_bytes).unwrap(), changed);
    drop(checked);

    // Current destination authorization cannot repair a changed original ACL.
    tokio::fs::write(&retained_path, &changed_bytes)
        .await
        .unwrap();
    let Err(failure) = reopened
        .guard()
        .read_snapshot(
            destination_reference,
            destination_authority.token(),
            b"/file",
            "sdk",
        )
        .await
    else {
        panic!("canonical changed original policy must fail its exact retained binding");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert_eq!(
        reopened
            .store()
            .ref_get(destination_reference)
            .await
            .unwrap(),
        Some(published.clone())
    );
    tokio::fs::write(&retained_path, &bytes).await.unwrap();
    let checked = reopened
        .guard()
        .read_snapshot(
            destination_reference,
            destination_authority.token(),
            b"/file",
            "sdk",
        )
        .await
        .unwrap();
    let (location, _) = checked.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        source_head.commit
    );
    let entry = checked.history.entry(&location).unwrap();
    let EntryKind::File { content, size, .. } = entry.kind else {
        panic!("retained disclosure changed file kind")
    };
    assert_eq!(
        reopened
            .guard()
            .read_content(&checked, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
}

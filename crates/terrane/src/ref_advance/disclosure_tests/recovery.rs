//! Checks a genuine interrupted paired import and strict ordinary reopening.

use super::{CommitTiming, Coordinator, FileBucket, Guard, TokioClock, TokioLocalFs, Validator};
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::{Error, Repository};
use crate::store::{LocalFs, StoreErrorKind};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

pub(super) async fn recover_cached_transition() {
    let (source, source_authority, _) = super::independent_factory("public").await;
    let (destination, destination_authority, _) = super::independent_factory("public").await;
    assert_ne!(
        source_authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key,
    );
    let reference = "refs/heads/_/main";
    let plaintext = b"paired recovery keeps current authority and exact original bindings";
    let mut source_session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let original = super::request_file(Vec::new(), plaintext);
    let mut original_request = source_authority.commit_request(original.commit, "sdk".into());
    original_request.uploads = original.uploads;
    let source_head = source
        .advance(&mut source_session, original_request)
        .await
        .unwrap();
    let mut session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let request = || {
        let staged = super::request_file(Vec::new(), plaintext);
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        DisclosureCommitRequest {
            selections: vec![DisclosureCommitSelection {
                source_reference: reference.into(),
                source_commit: source_head.commit,
                source_path: b"/file".to_vec(),
                source_token: source_authority.token().to_vec(),
                destination_path: b"/file".to_vec(),
            }],
            proposal,
        }
    };

    // Interrupt after genuine durable import installation but before the first
    // Guard selection. This leaves the exact cached/selected mismatch that a
    // retry must recover without granting ordinary open a repair capability.
    crate::selected_bridge::native_guard::disclosure::interrupt_next_import_selection(
        destination.store().root(),
    )
    .unwrap();
    assert!(
        destination
            .advance_disclosure(source.guard(), &mut session, request())
            .await
            .is_err()
    );
    assert!(session.record().is_none());
    let installed = destination
        .guard()
        .original_commit(&source_head.commit)
        .unwrap();
    assert_eq!(installed.commit(), &source_head.commit);

    let root = destination.store().root().to_owned();
    let control = root.with_file_name(format!(
        "{}-original-control",
        root.file_name().unwrap().to_string_lossy(),
    ));
    let owner = TokioLocalFs.symlink_metadata(&root).await.unwrap().uid();
    let bucket = FileBucket::open(
        super::config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let ordinary = Repository::reopen_native_retention(
        Coordinator::new(
            Guard::new(
                bucket,
                TokioClock,
                vec![destination_authority.issuer_key().clone()],
                destination.guard().config().clone(),
            ),
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .unwrap(),
            TokioLocalFs,
        ),
        &crate::domain::DomainNamespace {
            root,
            domain: "public".into(),
        },
        &control,
        owner,
    )
    .await;
    match ordinary {
        Err(Error::Store(error)) => assert!(matches!(
            error.kind(),
            StoreErrorKind::Denied {
                verb: "guard-install",
                ..
            }
        )),
        _ => panic!("ordinary reopen must refuse the interrupted import snapshot"),
    }

    let published = destination
        .advance_disclosure(source.guard(), &mut session, request())
        .await
        .unwrap();
    assert_eq!(session.record(), Some(&published));
    let snapshot = destination
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), published.commit);
    let (location, _) = snapshot.history.locate(published.commit, b"file").unwrap();
    let terrane_core::tree_format::EntryKind::File { content, size, .. } =
        snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("recovered publication must contain the certified file");
    };
    assert_eq!(
        destination
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        plaintext,
    );
}

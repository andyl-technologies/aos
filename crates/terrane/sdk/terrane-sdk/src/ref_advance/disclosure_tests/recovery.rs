//! Checks a genuine interrupted paired import and strict ordinary reopening.

use super::{CommitTiming, Coordinator, FileBucket, Guard, TokioClock, TokioLocalFs, Validator};
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::{Error, Repository};
use crate::store::{InvalidReason, LocalFs, RefStore, StoreErrorKind};
use std::error::Error as _;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use terrane_format::auth::{Attenuation, Grant, Token, Verb, Verbs};

/// Checks exact paired recovery without granting ordinary reopening repair authority.
///
/// Uses a genuinely interrupted import, valid restricted tokens, and restored
/// trust to distinguish current authorization refusals from selection failures.
///
/// # Panics
/// Panics if fixture setup, retained-file I/O, or any recovery assertion fails.
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
    let source_terminal_secret = original_request.terminal_secret;
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

    let before_denial = super::witness_support::physical_snapshot(destination.store().root()).await;

    let source_denied = restricted_token(
        source_authority.token(),
        &source_terminal_secret,
        Grant::new("refs/heads/_/other".into(), Verbs::new(1).unwrap()).unwrap(),
    );
    assert!(
        Token::decode(&source_denied)
            .unwrap()
            .verify(
                std::slice::from_ref(source_authority.issuer_key()),
                source.guard().now(reference, Verb::Read).unwrap(),
            )
            .is_ok()
    );
    let mut denied_request = request();
    denied_request.selections[0].source_token = source_denied;
    let failure = destination
        .advance_disclosure(source.guard(), &mut session, denied_request)
        .await
        .unwrap_err();
    let AdvanceError::Store(failure) = failure else {
        panic!("expected current read denial: {failure:?}");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Denied {
            verb: "read",
            pattern: reference.into(),
        },
    );
    assert!(failure.source().is_none());
    assert!(session.record().is_none());
    assert_eq!(destination.store().ref_get(reference).await.unwrap(), None);
    assert_eq!(
        super::witness_support::physical_snapshot(destination.store().root()).await,
        before_denial,
    );

    let mut denied_request = request();
    denied_request.proposal.token = restricted_token(
        destination_authority.token(),
        &denied_request.proposal.terminal_secret,
        Grant::new("refs/**".into(), Verbs::new(1).unwrap()).unwrap(),
    );
    assert!(
        Token::decode(&denied_request.proposal.token)
            .unwrap()
            .verify(
                std::slice::from_ref(destination_authority.issuer_key()),
                destination.guard().now(reference, Verb::Read).unwrap(),
            )
            .is_ok()
    );
    let failure = destination
        .advance_disclosure(source.guard(), &mut session, denied_request)
        .await
        .unwrap_err();
    let AdvanceError::Store(failure) = failure else {
        panic!("expected current commit denial: {failure:?}");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Denied {
            verb: "commit",
            pattern: reference.into(),
        },
    );
    assert!(failure.source().is_none());
    assert!(session.record().is_none());
    assert_eq!(destination.store().ref_get(reference).await.unwrap(), None);
    assert_eq!(
        super::witness_support::physical_snapshot(destination.store().root()).await,
        before_denial,
    );

    // A still well-formed historical trust row with a changed validity window
    // must not become this pair's expected row merely because labels agree.
    use crate::repository::local_authority::{public_trust::PublicTrustRecord, retention::Record};
    let import = installed.retained_import_record().unwrap();
    let import_digest = blake3::hash(&import.encode().unwrap());
    let trust_path = control.join(format!("import-trust-{}.cbor", import_digest.to_hex()));
    let retained_bytes = tokio::fs::read(&trust_path).await.unwrap();
    let mut changed = PublicTrustRecord::decode(&retained_bytes).unwrap();
    changed.disclosure_roles.first_mut().unwrap().not_after = Some(u64::MAX);
    changed.validate().unwrap();
    tokio::fs::write(&trust_path, changed.encode().unwrap())
        .await
        .unwrap();
    assert!(
        destination
            .advance_disclosure(source.guard(), &mut session, request())
            .await
            .is_err()
    );
    assert!(session.record().is_none());
    tokio::fs::write(&trust_path, retained_bytes).await.unwrap();

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
    let terrane_format::tree_format::EntryKind::File { content, size, .. } =
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

/// Attenuates a fixture token to the supplied grant with its terminal secret.
///
/// # Panics
/// Panics if the token cannot be decoded or the supplied attenuation is invalid.
pub(super) fn restricted_token(token: &[u8], secret: &[u8; 32], grant: Grant) -> Vec<u8> {
    Token::decode(token)
        .unwrap()
        .attenuate(
            Attenuation {
                grants: Some(vec![grant]),
                ..Attenuation::default()
            },
            secret,
            terrane_format::auth::public_key_from_secret(secret),
        )
        .unwrap()
        .encode()
}

/// Checks that one source cannot recover another source's pending import.
///
/// The unrelated attempt preserves the published head; the genuine source then
/// recovers its own interrupted transition and publishes its certified content.
///
/// # Panics
/// Panics if fixture setup or any refusal, recovery, or content assertion fails.
pub(super) async fn refuse_unrelated_transition() {
    let (source_a, authority_a, _) = super::independent_factory("public").await;
    let (source_b, authority_b, _) = super::independent_factory("public").await;
    let (destination, authority_destination, _) = super::independent_factory("public").await;
    let reference = "refs/heads/_/main";
    let bytes_a = b"first independently authenticated source";
    let bytes_b = b"second independently authenticated source";
    let head_a = author_file(&source_a, &authority_a, reference, bytes_a).await;
    let head_b = author_file(&source_b, &authority_b, reference, bytes_b).await;
    let mut session = destination
        .begin(reference, authority_destination.token(), "sdk")
        .await
        .unwrap();
    let published_a = destination
        .advance_disclosure(
            source_a.guard(),
            &mut session,
            paired_request(
                &authority_a,
                &authority_destination,
                reference,
                head_a.commit,
                Vec::new(),
                bytes_a,
            ),
        )
        .await
        .unwrap();

    // B's pending carrier is produced by its own genuinely authorized pair,
    // rather than fabricated or copied into A's claimed source history.
    crate::selected_bridge::native_guard::disclosure::interrupt_next_import_selection(
        destination.store().root(),
    )
    .unwrap();
    let request_b = || {
        paired_request(
            &authority_b,
            &authority_destination,
            reference,
            head_b.commit,
            vec![published_a.commit],
            bytes_b,
        )
    };
    assert!(
        destination
            .advance_disclosure(source_b.guard(), &mut session, request_b())
            .await
            .is_err()
    );
    assert_eq!(session.record(), Some(&published_a));
    assert!(destination.guard().original_commit(&head_b.commit).is_ok());

    assert!(
        destination
            .advance_disclosure(
                source_a.guard(),
                &mut session,
                paired_request(
                    &authority_a,
                    &authority_destination,
                    reference,
                    head_a.commit,
                    vec![published_a.commit],
                    bytes_a,
                ),
            )
            .await
            .is_err()
    );
    assert_eq!(session.record(), Some(&published_a));
    assert_eq!(
        destination.store().ref_get(reference).await.unwrap(),
        Some(published_a.clone()),
    );

    let retry_b = destination
        .advance_disclosure(source_b.guard(), &mut session, request_b())
        .await;
    assert!(
        retry_b.is_ok(),
        "B's exact paired retry must recover its own interrupted import: {retry_b:?}",
    );
    let published_b = retry_b.unwrap();
    assert_eq!(session.record(), Some(&published_b));
    let snapshot = destination
        .guard()
        .read_snapshot(reference, authority_destination.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot
        .history
        .locate(published_b.commit, b"file")
        .unwrap();
    let terrane_format::tree_format::EntryKind::File { content, size, .. } =
        snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("B's exact paired retry must publish its certified file");
    };
    assert_eq!(
        destination
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        bytes_b,
    );
}

/// Checks that matching subject names do not equate different principal kinds.
///
/// Independently authorized source Read and destination Commit still produce a
/// malformed-request refusal, preserving the head and retained physical state.
///
/// # Panics
/// Panics if fixture setup or any authorization or preservation assertion fails.
pub(super) async fn refuse_cross_kind_pair() {
    let (source, source_authority, _) = super::independent_factory("public").await;
    let (destination, destination_authority, _) =
        super::independent_factory_kind("public", terrane_format::refs::PrincipalKind::Service)
            .await;
    let reference = "refs/heads/_/main";
    let bytes = b"an equal subject name cannot collapse distinct principal kinds";
    let head = author_file(&source, &source_authority, reference, bytes).await;
    let paths = [b"/file".to_vec()];
    let read = source
        .guard()
        .authorize(
            reference,
            source_authority.token(),
            Verb::Read,
            &paths,
            "sdk",
        )
        .await
        .unwrap();
    let commit = destination
        .guard()
        .authorize(
            reference,
            destination_authority.token(),
            Verb::Commit,
            &paths,
            "sdk",
        )
        .await
        .unwrap();
    assert_eq!(read.subject(), commit.subject());
    assert!(!read.same_principal(&commit));

    let mut session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    // Preliminary destination admission retains this authorized session's epoch
    // baseline before checking the paired principals. Complete that genuine
    // setup before measuring refusal, preserving the full physical-state oracle.
    let guard = destination.guard();
    let retention = crate::repository::local_authority::NativeRetention {
        authority: guard.configured_original_authority().unwrap(),
        owner_uid: destination.store().publication_operator_uid().unwrap(),
        authoring_acl: guard.config().initial_acl.clone(),
    };
    retention
        .retain_baseline(guard, &TokioLocalFs, &session)
        .await
        .unwrap();
    let baseline = guard
        .original_bootstrap(reference, session.epoch())
        .unwrap();
    assert_eq!(baseline.authority(), &retention.authority);
    assert_eq!(baseline.reference(), reference);
    assert_eq!(baseline.epoch(), session.epoch());
    assert!(session.record().is_none());
    assert_eq!(destination.store().ref_get(reference).await.unwrap(), None);
    assert!(destination.guard().original_commit(&head.commit).is_err());

    let before = super::witness_support::physical_snapshot(destination.store().root()).await;
    let failure = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            paired_request(
                &source_authority,
                &destination_authority,
                reference,
                head.commit,
                Vec::new(),
                bytes,
            ),
        )
        .await
        .unwrap_err();
    let AdvanceError::Store(failure) = failure else {
        panic!("expected cross-kind pair refusal: {failure:?}");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
    );
    assert!(failure.source().is_none());
    assert_eq!(
        super::witness_support::physical_snapshot(destination.store().root()).await,
        before,
    );
    assert!(session.record().is_none());
    assert!(destination.guard().original_commit(&head.commit).is_err());
    assert_eq!(destination.store().ref_get(reference).await.unwrap(), None);
}

async fn author_file(
    source: &super::NativeFixture<TokioLocalFs>,
    authority: &crate::repository::local_authority::LocalAuthority,
    reference: &str,
    bytes: &[u8],
) -> terrane_format::refs::RefRecord {
    let mut session = source
        .begin(reference, authority.token(), "sdk")
        .await
        .unwrap();
    let staged = super::request_file(Vec::new(), bytes);
    let mut request = authority.commit_request(staged.commit, "sdk".into());
    request.uploads = staged.uploads;
    source.advance(&mut session, request).await.unwrap()
}

fn paired_request(
    source: &crate::repository::local_authority::LocalAuthority,
    destination: &crate::repository::local_authority::LocalAuthority,
    reference: &str,
    head: terrane_format::identity::Digest,
    parents: Vec<terrane_format::identity::Digest>,
    bytes: &[u8],
) -> DisclosureCommitRequest {
    let staged = super::request_file(parents, bytes);
    let mut proposal = destination.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    DisclosureCommitRequest {
        selections: vec![DisclosureCommitSelection {
            source_reference: reference.into(),
            source_commit: head,
            source_path: b"/file".to_vec(),
            source_token: source.token().to_vec(),
            destination_path: b"/file".to_vec(),
        }],
        proposal,
    }
}

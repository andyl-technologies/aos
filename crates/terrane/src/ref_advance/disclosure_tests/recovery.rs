//! Checks a genuine interrupted paired import and strict ordinary reopening.

use super::{CommitTiming, Coordinator, FileBucket, Guard, TokioClock, TokioLocalFs, Validator};
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::{Error, Repository};
use crate::store::{LocalFs, RefStore, StoreErrorKind};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use terrane_core::auth::{Attenuation, Grant, Token, Verb, Verbs};

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
    assert!(
        destination
            .advance_disclosure(source.guard(), &mut session, denied_request)
            .await
            .is_err()
    );
    assert!(session.record().is_none());

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
    assert!(
        destination
            .advance_disclosure(source.guard(), &mut session, denied_request)
            .await
            .is_err()
    );
    assert!(session.record().is_none());

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

fn restricted_token(token: &[u8], secret: &[u8; 32], grant: Grant) -> Vec<u8> {
    Token::decode(token)
        .unwrap()
        .attenuate(
            Attenuation {
                grants: Some(vec![grant]),
                ..Attenuation::default()
            },
            secret,
            terrane_core::auth::public_key_from_secret(secret),
        )
        .unwrap()
        .encode()
}

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

    let published_b = destination
        .advance_disclosure(source_b.guard(), &mut session, request_b())
        .await
        .unwrap();
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
    let terrane_core::tree_format::EntryKind::File { content, size, .. } =
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

async fn author_file(
    source: &super::NativeFixture<TokioLocalFs>,
    authority: &crate::repository::local_authority::LocalAuthority,
    reference: &str,
    bytes: &[u8],
) -> terrane_core::refs::RefRecord {
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
    head: terrane_core::identity::Digest,
    parents: Vec<terrane_core::identity::Digest>,
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

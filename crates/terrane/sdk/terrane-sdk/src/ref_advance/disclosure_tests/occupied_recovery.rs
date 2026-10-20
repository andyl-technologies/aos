//! Checks same-factory disclosure recovery over an already selected destination.
//!
//! An actual interrupted import leaves protected Original evidence ahead of the
//! selected Guard. Current source Read and destination Commit remain independent
//! requirements for recovery, and ordinary reopening cannot repair the mismatch.

use super::{
    CommitTiming, Coordinator, FileBucket, Guard, NativeFixture, TokioClock, TokioLocalFs,
    Validator, config, independent_factory, recovery::restricted_token, request_file,
    witness_support,
};
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::local_authority::{public_trust::PublicTrustRecord, retention::Record};
use crate::repository::{Error, Repository};
use crate::store::{InvalidReason, LocalFs, RefStore, StoreErrorKind};
use std::collections::BTreeMap;
use std::error::Error as _;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;
use terrane_format::auth::{Grant, Token, Verb, Verbs};
use terrane_format::gc::publication::{PublicationState, RawDigest};
use terrane_format::identity::Digest;
use terrane_format::tree_format::EntryKind;

const REFERENCE: &str = "refs/heads/_/main";
const PREVIOUS_BYTES: &[u8] = b"the occupied destination has its own selected history";
const DISCLOSED_BYTES: &[u8] = b"the same destination factory recovers the paired import";

/// Checks occupied recovery against retained controls and both current principals.
///
/// Keeps the actual destination factory and writer session through interruption,
/// authorization and trust refusals, and successful paired retry. A subsequent
/// destination-only reopen checks durable publication after source erasure.
///
/// # Panics
/// Panics if genuine fixture setup, retained-file I/O, cleanup, or any original,
/// authorization, physical preservation, recovery or content assertion fails.
#[tokio::test]
async fn disclosure_occupied_destination_recovers_interrupted_guard_transition_in_same_factory() {
    let (source, source_authority, source_credentials) = independent_factory("public").await;
    let (destination, destination_authority, destination_credentials) =
        independent_factory("public").await;
    assert_ne!(
        source_authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key,
    );
    let mut source_session = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), DISCLOSED_BYTES);
    let mut proposal = source_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let source_terminal_secret = proposal.terminal_secret;
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    let source_original = source.guard().original_commit(&source_head.commit).unwrap();

    let mut session = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let staged = request_file(Vec::new(), PREVIOUS_BYTES);
    let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
    proposal.uploads = staged.uploads;
    let previous = destination.advance(&mut session, proposal).await.unwrap();
    assert_eq!(session.record(), Some(&previous));
    assert_file_bytes(
        &destination,
        destination_authority.token(),
        previous.commit,
        PREVIOUS_BYTES,
    )
    .await;
    let previous_original = destination
        .guard()
        .original_commit(&previous.commit)
        .unwrap();
    let selected_before = selected_guard(&destination).await;
    let source_selected_before = selected_guard(&source).await;
    let request = || {
        let staged = request_file(vec![previous.commit], DISCLOSED_BYTES);
        let mut proposal = destination_authority.commit_request(staged.commit, "sdk".into());
        proposal.uploads = staged.uploads;
        DisclosureCommitRequest {
            proposal,
            selections: vec![DisclosureCommitSelection {
                source_reference: REFERENCE.into(),
                source_commit: source_head.commit,
                source_path: b"/file".to_vec(),
                source_token: source_authority.token().to_vec(),
                destination_path: b"/file".to_vec(),
            }],
        }
    };

    // The fault fires after actual durable import installation. A selected
    // predecessor makes preliminary destination history verification necessary.
    crate::selected_bridge::native_guard::disclosure::interrupt_next_import_selection(
        destination.store().root(),
    )
    .unwrap();
    let failure = destination
        .advance_disclosure(source.guard(), &mut session, request())
        .await
        .unwrap_err();
    assert_failure(
        failure,
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
    );
    assert_eq!(session.record(), Some(&previous));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(previous.clone()),
    );
    assert_eq!(selected_guard(&destination).await, selected_before);
    let installed = destination
        .guard()
        .original_commit(&source_head.commit)
        .unwrap();
    assert_eq!(installed.commit(), &source_head.commit);
    assert_eq!(installed.baseline(), source_original.baseline());
    assert_eq!(
        installed.retained_import_record().unwrap(),
        source_original.retained_import_record().unwrap(),
    );

    // Writable backend startup records its genuine capability probe before the
    // Guard factory runs. It must preserve the pending Original and selected
    // head; the full refusal oracle starts after this required backend setup.
    let original_controls = witness_support::control_snapshot(destination.store().root()).await;
    let bucket = FileBucket::open(
        config(destination.store().root().to_owned()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(selected_guard(&destination).await, selected_before);
    assert_eq!(session.record(), Some(&previous));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(previous.clone()),
    );
    assert_eq!(
        destination
            .guard()
            .original_commit(&source_head.commit)
            .unwrap(),
        installed,
    );
    assert_eq!(
        destination
            .guard()
            .original_commit(&previous.commit)
            .unwrap(),
        previous_original,
    );
    assert_eq!(
        witness_support::control_snapshot(destination.store().root()).await,
        original_controls,
    );

    let before_source = witness_support::physical_snapshot(source.store().root()).await;
    let before_destination = witness_support::physical_snapshot(destination.store().root()).await;
    let before_publication = selected_publication(&destination).await;
    let ordinary = ordinary_reopen(&destination, &destination_authority, bucket).await;
    let Err(Error::Store(failure)) = ordinary else {
        panic!("ordinary reopen must refuse the pending occupied Guard transition");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Denied {
            verb: "guard-install",
            pattern: destination.store().root().display().to_string(),
        },
    );
    assert!(failure.source().is_none());
    assert_eq!(
        witness_support::physical_snapshot(destination.store().root()).await,
        before_destination,
    );
    assert_eq!(selected_publication(&destination).await, before_publication);

    let mut denied = request();
    denied.selections[0].source_token = restricted_token(
        source_authority.token(),
        &source_terminal_secret,
        Grant::new("refs/heads/_/other".into(), Verbs::new(1).unwrap()).unwrap(),
    );
    assert!(
        Token::decode(&denied.selections[0].source_token)
            .unwrap()
            .verify(
                std::slice::from_ref(source_authority.issuer_key()),
                source.guard().now(REFERENCE, Verb::Read).unwrap(),
            )
            .is_ok()
    );
    let failure = destination
        .advance_disclosure(source.guard(), &mut session, denied)
        .await
        .unwrap_err();
    assert_failure(
        failure,
        StoreErrorKind::Denied {
            verb: "read",
            pattern: REFERENCE.into(),
        },
    );
    assert_eq!(session.record(), Some(&previous));
    assert_eq!(source_session.record(), Some(&source_head));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(previous.clone())
    );
    assert_eq!(
        source.store().ref_get(REFERENCE).await.unwrap(),
        Some(source_head.clone())
    );
    assert_eq!(selected_guard(&source).await, source_selected_before);
    assert_eq!(selected_guard(&destination).await, selected_before);
    assert_eq!(
        witness_support::physical_snapshot(source.store().root()).await,
        before_source
    );
    assert_eq!(
        witness_support::physical_snapshot(destination.store().root()).await,
        before_destination
    );

    let mut denied = request();
    denied.proposal.token = restricted_token(
        destination_authority.token(),
        &denied.proposal.terminal_secret,
        Grant::new("refs/**".into(), Verbs::new(1).unwrap()).unwrap(),
    );
    assert!(
        Token::decode(&denied.proposal.token)
            .unwrap()
            .verify(
                std::slice::from_ref(destination_authority.issuer_key()),
                destination.guard().now(REFERENCE, Verb::Commit).unwrap(),
            )
            .is_ok()
    );
    let failure = destination
        .advance_disclosure(source.guard(), &mut session, denied)
        .await
        .unwrap_err();
    assert_failure(
        failure,
        StoreErrorKind::Denied {
            verb: "commit",
            pattern: REFERENCE.into(),
        },
    );
    assert_eq!(session.record(), Some(&previous));
    assert_eq!(source_session.record(), Some(&source_head));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(previous.clone())
    );
    assert_eq!(
        source.store().ref_get(REFERENCE).await.unwrap(),
        Some(source_head.clone())
    );
    assert_eq!(selected_guard(&source).await, source_selected_before);
    assert_eq!(selected_guard(&destination).await, selected_before);
    assert_eq!(
        witness_support::physical_snapshot(source.store().root()).await,
        before_source
    );
    assert_eq!(
        witness_support::physical_snapshot(destination.store().root()).await,
        before_destination
    );

    // Equal historical keys cannot authorize a different retained trust row.
    // Snapshot after the deliberate edit so only retry effects are compared.
    let import = installed.retained_import_record().unwrap();
    let trust_path = witness_support::control(destination.store().root()).join(format!(
        "import-trust-{}.cbor",
        blake3::hash(&import.encode().unwrap()).to_hex(),
    ));
    let retained_trust = tokio::fs::read(&trust_path).await.unwrap();
    let mut changed_trust = PublicTrustRecord::decode(&retained_trust).unwrap();
    changed_trust
        .disclosure_roles
        .first_mut()
        .unwrap()
        .not_after = Some(u64::MAX);
    changed_trust.validate().unwrap();
    tokio::fs::write(&trust_path, changed_trust.encode().unwrap())
        .await
        .unwrap();
    let changed_destination = witness_support::physical_snapshot(destination.store().root()).await;
    let failure = destination
        .advance_disclosure(source.guard(), &mut session, request())
        .await
        .unwrap_err();
    assert_failure(
        failure,
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
    );
    assert_eq!(session.record(), Some(&previous));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(previous.clone())
    );
    assert_eq!(selected_guard(&destination).await, selected_before);
    assert_eq!(
        witness_support::physical_snapshot(source.store().root()).await,
        before_source
    );
    assert_eq!(
        witness_support::physical_snapshot(destination.store().root()).await,
        changed_destination
    );
    tokio::fs::write(&trust_path, retained_trust).await.unwrap();

    let published = destination
        .advance_disclosure(source.guard(), &mut session, request())
        .await
        .unwrap();
    assert_eq!(session.record(), Some(&published));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(published.clone())
    );
    assert_ne!(published.commit, previous.commit);
    assert_eq!(published.seq, previous.seq + 1);
    assert_ne!(selected_guard(&destination).await, selected_before);
    assert_eq!(
        destination
            .guard()
            .original_commit(&source_head.commit)
            .unwrap(),
        installed
    );
    assert_eq!(
        destination
            .guard()
            .original_commit(&previous.commit)
            .unwrap(),
        previous_original
    );
    assert_file_bytes(
        &destination,
        destination_authority.token(),
        published.commit,
        DISCLOSED_BYTES,
    )
    .await;

    drop(session);
    drop(source_session);
    erase_fixture(source, source_credentials).await;
    let destination = witness_support::reopen(destination, &destination_authority).await;
    assert_eq!(
        destination
            .guard()
            .original_commit(&source_head.commit)
            .unwrap(),
        installed
    );
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(published.clone())
    );
    assert_file_bytes(
        &destination,
        destination_authority.token(),
        published.commit,
        DISCLOSED_BYTES,
    )
    .await;
    erase_fixture(destination, destination_credentials).await;
}

/// Requires the actual storage error taxonomy without a fabricated source chain.
fn assert_failure(failure: AdvanceError, expected: StoreErrorKind) {
    let AdvanceError::Store(failure) = failure else {
        panic!("expected native storage refusal: {failure:?}");
    };
    assert_eq!(failure.kind(), &expected);
    assert!(failure.source().is_none());
}

/// Observes the durable Guard selector through the actual backend exclusion.
async fn selected_guard(destination: &NativeFixture<TokioLocalFs>) -> Vec<u8> {
    let holder = crate::bucket::held::SingleHeld::acquire(destination.store())
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_publication().await.unwrap();
    let selected = held
        .selected_guard_snapshot(&observed)
        .await
        .unwrap()
        .unwrap();
    observed.revalidate().await.unwrap();
    selected
}

/// Records complete selected publication data without conferring authority.
#[derive(Debug, Eq, PartialEq)]
struct PublicationObservation {
    state: PublicationState,
    stamp: (u64, RawDigest),
    logical: BTreeMap<String, Option<Vec<u8>>>,
}

/// Observes exact state, slot and logical bytes without repairing backend caches.
async fn selected_publication(destination: &NativeFixture<TokioLocalFs>) -> PublicationObservation {
    let holder = crate::bucket::held::SingleHeld::acquire(destination.store())
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_for_read().await.unwrap();
    let publication = PublicationObservation {
        state: observed.state().clone(),
        stamp: observed.stamp(),
        logical: observed.logical().clone(),
    };
    observed.revalidate().await.unwrap();
    publication
}

/// Requires real guarded file reads and the publicly verified introducing commit.
async fn assert_file_bytes(
    destination: &NativeFixture<TokioLocalFs>,
    token: &[u8],
    commit: Digest,
    expected: &[u8],
) {
    let snapshot = destination
        .guard()
        .read_snapshot(REFERENCE, token, b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), commit);
    let (location, _) = snapshot.history.locate(commit, b"file").unwrap();
    assert_eq!(
        snapshot.history.introducing_commit(&location).unwrap(),
        commit
    );
    let EntryKind::File { content, size, .. } = snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("expected the selected certified file");
    };
    assert_eq!(
        destination
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        expected
    );
}

/// Attempts ordinary protected reopening while retaining the interrupted factory.
///
/// # Errors
/// Preserves the actual protected reopening refusal without attempting recovery.
async fn ordinary_reopen(
    destination: &NativeFixture<TokioLocalFs>,
    authority: &crate::repository::local_authority::LocalAuthority,
    bucket: FileBucket<TokioLocalFs, TokioClock, Validator>,
) -> Result<
    Repository<FileBucket<TokioLocalFs, TokioClock, Validator>, TokioClock, TokioLocalFs>,
    Error,
> {
    let root = destination.store().root().to_owned();
    let owner = TokioLocalFs.symlink_metadata(&root).await.unwrap().uid();
    let control = witness_support::control(&root);
    Repository::reopen_native_retention(
        Coordinator::new(
            Guard::new(
                bucket,
                TokioClock,
                vec![authority.issuer_key().clone()],
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
    .await
}

/// Erases only this fixture's payload, exact protected owners and credentials.
async fn erase_fixture(fixture: NativeFixture<TokioLocalFs>, credentials: PathBuf) {
    let root = fixture.store().root().to_owned();
    let publication_control = {
        let holder = crate::bucket::held::SingleHeld::acquire(fixture.store())
            .await
            .unwrap();
        let held = holder.destination();
        let observed = held.observe_publication().await.unwrap();
        let registration = observed.physical_reads().first().unwrap();
        assert_eq!(
            registration.path().file_name().unwrap(),
            "backend-registration.cbor"
        );
        registration.path().parent().unwrap().to_owned()
    };
    let operator = root.with_file_name(format!(
        "{}-operator",
        root.file_name().unwrap().to_string_lossy()
    ));
    drop(fixture);
    for path in [
        witness_support::control(&root),
        publication_control,
        root,
        credentials,
        operator,
    ] {
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(!path.exists());
    }
}

//! Reopens the actual protected fixture with the production metadata validator.
//!
//! Layer publication and ordinary overlay outputs use the retained Repository;
//! the factory never fabricates a source authority, receipt or serving head.

use super::super::witness_support::{control, storage_failure};
use super::super::*;
use crate::ref_advance::{AdvanceError, CommitRequest, WriterSession};
use crate::repository::local_authority::LocalAuthority;
use crate::repository::{MetadataValidator, Repository};
use crate::store::LocalFs;
use std::ops::Deref;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use terrane_format::refs::RefRecord;

type NativeCoordinator =
    Coordinator<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

/// Owns the genuinely reopened Repository used by contextual layer producers.
pub(super) struct Fixture {
    /// Actual protected Repository owning layer and ordinary output publication.
    pub(super) repository: Repository<
        FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
        TokioClock,
        TokioLocalFs,
    >,
}

impl Deref for Fixture {
    type Target = NativeCoordinator;

    fn deref(&self) -> &Self::Target {
        self.repository.coordinator()
    }
}

impl Fixture {
    /// Publishes ordinary authoring through the actual protected Repository.
    ///
    /// # Errors
    /// Preserves the fixture's genuine typed native storage refusal.
    ///
    /// # Panics
    /// Panics if the fixture fails in an unrelated non-storage phase.
    pub(super) async fn advance(
        &self,
        session: &mut WriterSession,
        proposal: CommitRequest,
    ) -> Result<RefRecord, AdvanceError> {
        self.repository
            .commit_request(session, proposal)
            .await
            .map_err(|error| AdvanceError::Store(storage_failure(error)))
    }
}

/// Opens the same actual authority with the production metadata decoder.
///
/// # Panics
/// Panics if checked protected reopening fails.
pub(super) async fn production(
    fixture: NativeFixture<TokioLocalFs>,
    authority: &LocalAuthority,
) -> Fixture {
    let root = fixture.store().root().to_owned();
    let policy = fixture.guard().config().clone();
    drop(fixture);
    open(root, policy, authority).await
}

/// Rechecks every retained Original and selected native dependency on reopen.
///
/// # Panics
/// Panics if historical or selected evidence no longer verifies.
pub(super) async fn reopen(fixture: Fixture, authority: &LocalAuthority) -> Fixture {
    let root = fixture.store().root().to_owned();
    let policy = fixture.guard().config().clone();
    drop(fixture);
    open(root, policy, authority).await
}

/// Removes the production source only after releasing its Repository handles.
///
/// # Panics
/// Panics if the source, protected controls or credentials cannot be removed,
/// or if any erased fixture path remains.
pub(super) async fn erase_source(source: Fixture, credentials: PathBuf) {
    let root = source.store().root().to_owned();
    drop(source);

    for path in [control(&root), root, credentials] {
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(!path.exists());
    }
}

async fn open(
    root: PathBuf,
    policy: crate::guard::GuardConfig,
    authority: &LocalAuthority,
) -> Fixture {
    let validator = MetadataValidator::new(policy.chunk_profile.as_ref().clone());
    let bucket = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        validator,
    )
    .await
    .unwrap();
    let owner = TokioLocalFs.metadata(&root).await.unwrap().uid();
    let namespace = crate::domain::DomainNamespace {
        root: root.clone(),
        domain: policy.storage_domain.clone(),
    };
    let coordinator = Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            policy,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let repository =
        Repository::reopen_native_retention(coordinator, &namespace, &control(&root), owner)
            .await
            .unwrap();
    Fixture { repository }
}

/// Removes the physical source, dedicated seeds, Original controls and credentials.
///
/// # Panics
/// Panics if source erasure fails or any runtime fixture path remains.
pub(super) async fn erase(fixture: Fixture, credentials: PathBuf) {
    let root = fixture.store().root().to_owned();
    drop(fixture);
    for path in [control(&root), root, credentials] {
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(!path.exists());
    }
}

/// Keeps the independently verified identities carried by the safe materialization.
pub(super) struct MaterializedOrigins {
    /// Acknowledged ordinary output whose complete signed recipe verified.
    pub(super) materialized: [u8; 32],
    /// Original public introducing commit preserved by the materialization.
    pub(super) introducer: [u8; 32],
    /// Independently retainable public producer of the survivor's note attribute.
    pub(super) producer: [u8; 32],
}

/// Certifies the visible file after safe materialization and erases the actual source.
///
/// Public attribute history remains independently retained; the certificate
/// certifies the visible file projection rather than an overlay absence claim.
///
/// # Panics
/// Panics if native disclosure, complete public producer retention, source
/// erasure or independent destination reopen fails.
pub(super) async fn disclose_and_reopen(
    source: Fixture,
    authority: LocalAuthority,
    credentials: PathBuf,
    origins: MaterializedOrigins,
    expected: &Tree<'_>,
    plaintext: &[u8],
) {
    use super::super::witness_support::{REFERENCE, proposal};
    use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
    use terrane_format::provenance::{DisclosureCandidate, OriginalBootstrapPolicy};

    let MaterializedOrigins {
        materialized,
        introducer,
        producer,
    } = origins;
    let source_snapshot = source
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/keep", "sdk")
        .await
        .unwrap();
    assert_eq!(source_snapshot.commit.identity(), materialized);
    let (source_location, _) = source_snapshot
        .history
        .locate(materialized, b"keep")
        .unwrap();
    assert_eq!(
        source_snapshot
            .history
            .introducing_commit(&source_location)
            .unwrap(),
        introducer
    );
    assert_eq!(
        source_snapshot
            .history
            .attribute_producer(&source_location, "note")
            .unwrap(),
        producer
    );
    let attestation = ExpectedDisclosure {
        source: terrane_format::refs::EntrySource {
            commit: source_location.commit,
            root: source_location.root,
            path: source_location.path,
        },
        introducer,
        producer,
    };
    drop(source_snapshot);

    let (destination, destination_authority, _) = independent_factory("public").await;
    let destination = production(destination, &destination_authority).await;
    assert_ne!(
        authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );
    let mut target = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&destination_authority, Vec::new(), expected, &[plaintext]),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: materialized,
                    source_path: b"/keep".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/keep".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/keep", "sdk")
        .await
        .unwrap();
    assert_public_view(
        &destination,
        &checked,
        published.commit,
        &attestation,
        expected,
        plaintext,
    )
    .await;

    let roles = destination.guard().history_disclosure_roles().unwrap();
    let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
    let original = destination
        .guard()
        .original_commit(&published.commit)
        .unwrap();
    let baseline = original.baseline();
    let owner = baseline
        .authority()
        .id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let acl = baseline
        .acl()
        .iter()
        .map(|(subject, verbs)| (subject.as_str(), *verbs))
        .collect::<Vec<_>>();
    let (_, batch) = DisclosureCandidate::new_with_bootstrap(
        &checked.history,
        published.commit,
        &authorities,
        destination.guard().defaults_for(&checked.evidence),
        &owner,
        OriginalBootstrapPolicy {
            authority: &owner,
            reference: baseline.reference(),
            writer_epoch: baseline.epoch(),
            acl: &acl,
        },
    )
    .and_then(|candidate| candidate.finish())
    .unwrap();
    assert_eq!(batch.boundaries().len(), 1);
    let boundary = &batch.boundaries()[0];
    assert_eq!(boundary.source(), &attestation.source);
    assert_eq!(boundary.original_introducer(), introducer);
    assert_eq!(boundary.root_occurrences(), &[b"/".to_vec()]);
    assert!(checked.history.commit(&materialized).is_none());
    assert!(checked.history.commit(&producer).is_some());
    assert!(checked.history.commit(&introducer).is_some());
    drop(checked);
    drop(target);
    drop(authority);
    erase(source, credentials).await;

    let destination = reopen(destination, &destination_authority).await;
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/keep", "sdk")
        .await
        .unwrap();
    assert_public_view(
        &destination,
        &checked,
        published.commit,
        &attestation,
        expected,
        plaintext,
    )
    .await;
    assert!(checked.history.commit(&materialized).is_none());
    assert!(checked.history.commit(&producer).is_some());
    assert!(checked.history.commit(&introducer).is_some());
}

/// Holds the actual completed source witness used by the native disclosure.
struct ExpectedDisclosure {
    source: terrane_format::refs::EntrySource,
    introducer: [u8; 32],
    producer: [u8; 32],
}

async fn assert_public_view(
    destination: &Fixture,
    checked: &crate::guard::AuthorizedSnapshot,
    view: [u8; 32],
    attestation: &ExpectedDisclosure,
    expected: &Tree<'_>,
    plaintext: &[u8],
) {
    assert_eq!(checked.commit.identity(), view);
    let (location, _) = checked.history.locate(view, b"keep").unwrap();
    assert_eq!(checked.history.introducing_commit(&location).unwrap(), view);
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, "note")
            .unwrap(),
        attestation.producer
    );
    let visible = checked.history.entry(&location).unwrap();
    let marker_name = "provenance.reintroduced-from";
    let user_attributes = visible
        .attrs
        .iter()
        .filter(|attribute| attribute.name != marker_name)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(user_attributes, expected.get(b"keep").unwrap().attrs);
    let markers = visible
        .attrs
        .iter()
        .filter(|attribute| attribute.name == marker_name)
        .collect::<Vec<_>>();
    assert_eq!(markers.len(), 1);
    let mut decoder = terrane_format::cbor::Decoder::new(markers[0].value);
    let marked_introducer: [u8; 32] = decoder.bytes(32).unwrap().try_into().unwrap();
    decoder.finish().unwrap();
    assert_eq!(marked_introducer, attestation.introducer);
    assert_eq!(
        checked
            .history
            .attribute_producer(&location, marker_name)
            .unwrap(),
        view
    );

    let receipt = checked
        .commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_ref()
        .unwrap()
        .iter()
        .find(|receipt| receipt.root == location.root && receipt.path == location.path)
        .unwrap();
    assert_eq!(receipt.origin, terrane_format::refs::EntryOrigin::Current);
    assert_eq!(
        receipt.reintroduced_from.as_ref(),
        Some(&attestation.source)
    );
    assert_eq!(
        receipt
            .attributes
            .as_ref()
            .unwrap()
            .iter()
            .find(|(name, _)| name == marker_name)
            .unwrap()
            .1,
        terrane_format::refs::EntryOrigin::Current
    );
    assert!(receipt.disclosure_proof.is_some());
    let expected_file = expected.get(b"keep").unwrap();
    assert_eq!(visible.kind, expected_file.kind);
    let actual = checked
        .evidence
        .tree(
            checked.evidence.root,
            super::super::witness_support::MINIMUM,
        )
        .unwrap();
    assert_eq!(
        actual
            .iter()
            .map(|item| item.key.clone())
            .collect::<Vec<_>>(),
        vec![b"keep".to_vec()]
    );
    assert_eq!(actual.props(), expected.props());
    drop(actual);
    assert!(checked.history.locate(view, b"gone").is_err());

    let EntryKind::File { content, size, .. } = &visible.kind else {
        panic!("the visible survivor must remain a file");
    };
    assert_eq!(
        destination
            .guard()
            .read_content(checked, b"/keep", *content, *size)
            .await
            .unwrap(),
        plaintext
    );
}

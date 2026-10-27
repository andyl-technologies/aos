//! Checks retained disclosure trust during current and direct historical reads.

use super::witness_support::*;
use super::*;
use crate::guard::HistoryObservation;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection, WriterSession};
use crate::repository::local_authority::{
    import_binding::ImportBindingRecord,
    public_trust::PublicTrustRecord,
    retention::{ImportRecord, Record},
};
use crate::store::{InvalidReason, LocalFs, RefStore, StoreErrorKind, StoreFailure};
use std::collections::BTreeMap;
use std::error::Error as _;
use std::path::PathBuf;
use terrane_format::gc::publication::{PublicationState, RawDigest, evidence::ControlKind};
use terrane_format::identity::Digest;
use terrane_format::provenance::{
    DisclosureAuthority, DisclosureCandidate, OriginalBootstrapPolicy,
};
use terrane_format::refs::{Commit, RefRecord};

/// Retains genuine old certificate evidence and refuses a freshly revoked Read.
///
/// # Panics
/// Panics if native publication/reopening fails, pure issue windows disagree,
/// retained keys change, or a current denied read borrows historical authority.
pub(super) async fn retain_keys_and_revoke_current_read() {
    let (source, authority, credentials) = independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let plaintext = b"signed issue time is independent of later destination policy";
    let private = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file(plaintext),
        }],
        materialization::properties(true),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let public = Tree::build(
        private.iter().cloned().collect(),
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut source_session = source
        .begin(REFERENCE, authority.token(), "sdk")
        .await
        .unwrap();
    let original = source
        .advance(
            &mut source_session,
            proposal(&authority, Vec::new(), &private, &[plaintext]),
        )
        .await
        .unwrap();
    let imported = source
        .guard()
        .original_commit(&original.commit)
        .unwrap()
        .retained_import_record()
        .unwrap();
    let mut target = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&destination_authority, Vec::new(), &public, &[plaintext]),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: original.commit,
                    source_path: b"/file".to_vec(),
                    source_token: authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    assert_ne!(
        authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );
    assert_eq!(
        destination
            .guard()
            .original_commit(&original.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
        imported
    );
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let roles = destination.guard().history_disclosure_roles().unwrap();
    let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
    let baseline = destination
        .guard()
        .original_commit(&published.commit)
        .unwrap();
    let baseline = baseline.baseline();
    let original_authority = baseline
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
    let verify = |roles: &[DisclosureAuthority<'_>]| {
        DisclosureCandidate::new_with_bootstrap(
            &checked.history,
            published.commit,
            roles,
            destination.guard().defaults_for(&checked.evidence),
            &original_authority,
            OriginalBootstrapPolicy {
                authority: &original_authority,
                reference: baseline.reference(),
                writer_epoch: baseline.epoch(),
                acl: &acl,
            },
        )
        .and_then(|candidate| candidate.finish())
    };
    let (_, batch) = verify(&authorities).unwrap();
    assert_eq!(batch.boundaries().len(), 1);
    let boundary = &batch.boundaries()[0];
    assert_eq!(boundary.source().commit, original.commit);
    assert_eq!(boundary.original_introducer(), original.commit);
    let issued = boundary.observed_at();
    let after = issued.checked_add(1).unwrap();
    let old = DisclosureAuthority {
        repository: boundary.authority_repository(),
        domain: boundary.authority_domain(),
        public_key: *boundary.authority_key(),
        not_before: issued,
        not_after: Some(after),
    };

    // These are pure interval/rotation oracles on an actual signed receipt.
    // Native additive rotation has its own real selected-transition fixture;
    // these interval oracles never edit protected historical role rows.
    assert!(verify(&[old]).is_ok());
    assert!(
        verify(&[DisclosureAuthority {
            not_before: after,
            not_after: None,
            ..old
        }])
        .is_err()
    );
    assert!(
        verify(&[DisclosureAuthority {
            not_before: issued.saturating_sub(1),
            not_after: Some(issued),
            ..old
        }])
        .is_err()
    );
    assert!(verify(&[]).is_err());
    let later = DisclosureAuthority {
        public_key: terrane_format::auth::public_key_from_secret(&[0x79; 32]),
        not_before: after,
        not_after: None,
        ..old
    };
    assert!(verify(&[old, later]).is_ok());
    assert!(checked.history.commit(&original.commit).is_none());
    let (location, _) = checked.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        checked.history.introducing_commit(&location).unwrap(),
        published.commit
    );
    let retained_tree = checked
        .evidence
        .tree(checked.evidence.root, MINIMUM)
        .unwrap();
    let absent = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &original.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private.root_identity())
            .unwrap(),
    ];
    assert_eq!(destination.store().has(&absent).await.unwrap(), [false; 2]);
    drop(source_session);
    drop(authority);
    drop(target);
    erase_source(source, credentials).await;
    let destination = reopen(destination, &destination_authority).await;
    assert_eq!(
        destination
            .guard()
            .original_commit(&original.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
        imported
    );
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), published.commit);
    assert!(checked.history.commit(&original.commit).is_none());
    drop(checked);

    // Genuine Admin authority from the old policy admits its own narrowing.
    let mut properties = retained_tree.props().unwrap().to_vec();
    properties
        .iter_mut()
        .find(|property| property.name == "acl")
        .unwrap()
        .value = b"\x81\x82\x66writer\x00";
    let revoked = retained_tree
        .with_properties(Some(properties))
        .unwrap()
        .tree;
    let mut target = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let narrowed = destination
        .advance(
            &mut target,
            proposal(
                &destination_authority,
                vec![published.commit],
                &revoked,
                &[plaintext],
            ),
        )
        .await
        .unwrap();
    assert!(
        destination
            .guard()
            .verified_history(narrowed.commit)
            .await
            .is_ok()
    );
    let physical_before = physical_snapshot(destination.store().root()).await;
    let denied = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await;
    let observed = denied
        .as_ref()
        .err()
        .map(|error| format!("{error:?}"))
        .unwrap_or_else(|| "authorized current Read".into());
    assert!(
        matches!(denied, Err(error) if matches!(error.kind(), StoreErrorKind::Denied { verb: "read", .. })),
        "observed current decision: {observed}"
    );
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(narrowed)
    );
    assert_eq!(destination.store().has(&absent).await.unwrap(), [false; 2]);
    assert_eq!(
        physical_snapshot(destination.store().root()).await,
        physical_before
    );
}

/// Refuses an actual pending import through both tokenless immutable entry points.
///
/// The occupied destination remains open throughout the genuine interruption,
/// direct refusals and paired recovery. No current authorization or reopen can
/// substitute its earlier refusal for the default-observation direct call.
///
/// # Panics
/// Panics if fixture setup, genuine interruption, direct refusal, preservation,
/// paired recovery, canonical completion or fixture cleanup fails.
pub(super) async fn refuse_pending_guard_mismatch() {
    let fixture = DirectImportFixture::initialize().await;
    let native = fixture.destination.fs.observe_native_reads().unwrap();
    let native_counts = fixture
        .destination
        .coordinator()
        .store()
        .observe_content_for_tests();
    for mode in [ImportedReadMode::History, ImportedReadMode::Tree] {
        mode.verify(&fixture, &fixture.previous, fixture.previous_root)
            .await
            .unwrap();
    }
    let mut writer = fixture.writer().await;
    let selected = publication_observation(&fixture.destination).await;
    crate::selected_bridge::native_guard::disclosure::interrupt_next_import_selection(
        fixture.destination.coordinator().store().root(),
    )
    .unwrap();
    let interrupted = fixture
        .destination
        .repository
        .commit_disclosure(&fixture.source.repository, &mut writer, fixture.request())
        .await
        .unwrap_err();
    assert_eq!(
        storage_failure(interrupted).kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    let imported = fixture
        .destination
        .coordinator()
        .guard()
        .original_commit(&fixture.source_head.commit)
        .unwrap();
    assert_eq!(
        imported.retained_import_record().unwrap(),
        fixture
            .source
            .coordinator()
            .guard()
            .original_commit(&fixture.source_head.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
    );
    assert_eq!(writer.record(), Some(&fixture.previous));
    assert_eq!(
        publication_observation(&fixture.destination).await,
        selected
    );
    let destination_before =
        physical_snapshot(fixture.destination.coordinator().store().root()).await;
    let source_before = physical_snapshot(fixture.source.coordinator().store().root()).await;

    for mode in [ImportedReadMode::History, ImportedReadMode::Tree] {
        // This target already completed before interruption. Its immutable
        // bytes remain present; only the genuine selected Guard mismatch changed.
        native_counts.reset();
        let failure = mode
            .verify(&fixture, &fixture.previous, fixture.previous_root)
            .await
            .unwrap_err();
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
            "{mode:?}: {failure:?}"
        );
        assert!(failure.source().is_none(), "{mode:?}: {failure:?}");
        let counts = native_counts.snapshot();
        assert_eq!(counts.commit_puts, 0);
        assert_eq!(counts.node_puts, 0);
        assert_eq!(writer.record(), Some(&fixture.previous));
        assert_eq!(
            fixture
                .destination
                .coordinator()
                .store()
                .ref_get(REFERENCE)
                .await
                .unwrap(),
            Some(fixture.previous.clone())
        );
        assert_eq!(
            publication_observation(&fixture.destination).await,
            selected
        );
        assert_eq!(
            physical_snapshot(fixture.destination.coordinator().store().root()).await,
            destination_before
        );
        assert_eq!(
            physical_snapshot(fixture.source.coordinator().store().root()).await,
            source_before
        );
    }

    let published = fixture
        .destination
        .repository
        .commit_disclosure(&fixture.source.repository, &mut writer, fixture.request())
        .await
        .unwrap();
    assert_eq!(writer.record(), Some(&published));
    let root = fixture.signed_root(&published).await;
    for mode in [ImportedReadMode::History, ImportedReadMode::Tree] {
        mode.verify(&fixture, &published, root).await.unwrap();
    }
    assert_eq!(
        fixture
            .destination
            .coordinator()
            .guard()
            .original_commit(&fixture.source_head.commit)
            .unwrap(),
        imported
    );
    drop(writer);
    drop(native);
    fixture.erase().await;
}

/// Refuses each changed imported control after genuine native DATA capture.
///
/// Import, destination binding and historical public trust change separately
/// while the actual immutable request retains its original native result. Each
/// mode refuses without exposing completion; restoration permits a fresh walk.
///
/// # Panics
/// Panics if publication, pin selection, real DATA arrival, mutation, exact
/// refusal, preservation, restored completion or fixture cleanup fails.
pub(super) async fn close_retained_import_controls() {
    let fixture = DirectImportFixture::initialize().await;
    let mut writer = fixture.writer().await;
    let published = fixture
        .destination
        .repository
        .commit_disclosure(&fixture.source.repository, &mut writer, fixture.request())
        .await
        .unwrap();
    drop(writer);
    let native = fixture.destination.fs.observe_native_reads().unwrap();
    let native_counts = fixture
        .destination
        .coordinator()
        .store()
        .observe_content_for_tests();
    let root = fixture.signed_root(&published).await;
    let imported = fixture
        .destination
        .coordinator()
        .guard()
        .original_commit(&fixture.source_head.commit)
        .unwrap();
    let pins = crate::guard::publication_original_pins(&imported).unwrap();
    let authority = fixture
        .destination
        .coordinator()
        .guard()
        .configured_original_authority()
        .unwrap();
    let selected = publication_observation(&fixture.destination).await;
    let source_before = physical_snapshot(fixture.source.coordinator().store().root()).await;

    for mode in [ImportedReadMode::History, ImportedReadMode::Tree] {
        mode.verify(&fixture, &published, root).await.unwrap();
        for kind in [
            ControlKind::Import,
            ControlKind::ImportBinding,
            ControlKind::ImportTrust,
        ] {
            let pin = pins.iter().find(|pin| pin.kind == kind).unwrap();
            assert_eq!(pin.owner, crate::guard::consumed_registration(&authority));
            let path = authority.control().join(&pin.key);
            let bytes = TokioLocalFs.read_nofollow(&path).await.unwrap();
            pin.check_record(&bytes).unwrap();
            let changed = changed_import_control(kind, &bytes);
            assert_ne!(changed, bytes);
            let identity = TokioLocalFs.symlink_metadata(&path).await.unwrap();
            let mut barrier = fixture
                .destination
                .fs
                .pause_native_data(fixture.destination.coordinator().store().root().to_owned())
                .unwrap();
            native_counts.reset();
            let read = mode.verify(&fixture, &published, root);
            let mutate = async {
                let data_path = tokio::time::timeout(Duration::from_secs(10), barrier.reached())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    data_path.starts_with(
                        fixture
                            .destination
                            .coordinator()
                            .store()
                            .root()
                            .join("objects/pack")
                    )
                );
                assert_eq!(data_path.extension().unwrap(), "pack");
                assert_eq!(TokioLocalFs.read_nofollow(&path).await.unwrap(), bytes);
                // Change actual canonical bytes on the same protected inode.
                // The old read receipt must not become a new capture of this row.
                tokio::fs::write(&path, changed).await.unwrap();
                use std::os::unix::fs::MetadataExt;
                let edited = TokioLocalFs.symlink_metadata(&path).await.unwrap();
                assert_eq!(
                    (edited.dev(), edited.ino()),
                    (identity.dev(), identity.ino())
                );
                let after_edit =
                    physical_snapshot(fixture.destination.coordinator().store().root()).await;
                barrier.release().unwrap();
                after_edit
            };
            let (result, after_edit) = tokio::join!(read, mutate);
            let failure = result.unwrap_err();
            assert_eq!(
                failure.kind(),
                &StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
                "{mode:?} {kind:?}: {failure:?}"
            );
            assert!(failure.source().is_none(), "{mode:?} {kind:?}: {failure:?}");
            let counts = native_counts.snapshot();
            assert!(counts.commit_gets > 0, "{mode:?} {kind:?}");
            assert_eq!(counts.commit_puts, 0);
            assert_eq!(counts.node_puts, 0);
            assert_eq!(
                fixture
                    .destination
                    .coordinator()
                    .store()
                    .ref_get(REFERENCE)
                    .await
                    .unwrap(),
                Some(published.clone())
            );
            assert_eq!(
                publication_observation(&fixture.destination).await,
                selected
            );
            assert_eq!(
                physical_snapshot(fixture.destination.coordinator().store().root()).await,
                after_edit
            );
            assert_eq!(
                physical_snapshot(fixture.source.coordinator().store().root()).await,
                source_before
            );
            tokio::fs::write(&path, bytes).await.unwrap();
            mode.verify(&fixture, &published, root).await.unwrap();
        }
    }
    drop(native);
    fixture.erase().await;
}

/// Selects genuine tokenless History and Tree modes with default observation.
#[derive(Clone, Copy, Debug)]
enum ImportedReadMode {
    History,
    Tree,
}

impl ImportedReadMode {
    /// Requires canonical completion without supplying a token or current request.
    async fn verify(
        self,
        fixture: &DirectImportFixture,
        target: &RefRecord,
        root: Digest,
    ) -> Result<(), StoreFailure> {
        let guard = fixture.destination.coordinator().guard();
        match self {
            Self::History => {
                let history = guard
                    .verified_history_observed(target.commit, HistoryObservation::default())
                    .await?;
                let verified = history.commit(&target.commit).unwrap();
                assert_eq!(verified.commit().tree, root);
                if target.commit != fixture.previous.commit {
                    assert_eq!(
                        verified.commit().parents,
                        fixture.expected_disclosure_parents
                    );
                    assert!(history.commit(&fixture.previous.commit).is_some());
                    assert!(history.commit(&fixture.source_head.commit).is_none());
                    let (entry, _) = history.locate(target.commit, b"file").unwrap();
                    assert_eq!(history.introducing_commit(&entry).unwrap(), target.commit);
                }
            }
            Self::Tree => {
                let verified = guard
                    .verified_tree_observed(target.commit, HistoryObservation::default())
                    .await?;
                assert_eq!(verified.commit.identity(), target.commit);
                assert_eq!(verified.evidence.root, root);
                assert_eq!(verified.commit.commit().tree, root);
                if target.commit != fixture.previous.commit {
                    assert_eq!(
                        verified.commit.commit().parents,
                        fixture.expected_disclosure_parents
                    );
                }
            }
        }
        Ok(())
    }
}

/// Retains independently generated private source and occupied public destination factories.
struct DirectImportFixture {
    source: super::current_authority::Factory,
    destination: super::current_authority::Factory,
    source_head: RefRecord,
    previous: RefRecord,
    expected_disclosure_parents: [Digest; 2],
    previous_root: Digest,
    public_tree: Tree<'static>,
}

const DIRECT_BYTES: &[u8] = b"direct immutable history closes the retained imported controls";
const DIRECT_PREVIOUS_BYTES: &[u8] = b"an independently authored public predecessor";

impl DirectImportFixture {
    /// Publishes independently signed source and destination baselines through actual factories.
    async fn initialize() -> Self {
        let source = super::current_authority::Factory::initialize(true).await;
        let destination = super::current_authority::Factory::initialize(false).await;
        let tree = |private, bytes| {
            Tree::build(
                vec![LeafItem {
                    key: b"file".to_vec(),
                    entry: file(bytes),
                }],
                materialization::properties(private),
                MINIMUM,
                TreeUse::Ordinary,
            )
            .unwrap()
        };
        let private_tree = tree(true, DIRECT_BYTES);
        let public_tree = tree(false, DIRECT_BYTES);
        let previous_tree = tree(false, DIRECT_PREVIOUS_BYTES);
        let mut source_writer = source
            .repository
            .begin(REFERENCE, source.authority.token(), "sdk")
            .await
            .unwrap();
        let source_head = source
            .repository
            .commit_request(
                &mut source_writer,
                proposal(
                    &source.authority,
                    Vec::new(),
                    &private_tree,
                    &[DIRECT_BYTES],
                ),
            )
            .await
            .unwrap();
        let mut target_writer = destination
            .repository
            .begin(REFERENCE, destination.authority.token(), "sdk")
            .await
            .unwrap();
        let previous = destination
            .repository
            .commit_request(
                &mut target_writer,
                proposal(
                    &destination.authority,
                    Vec::new(),
                    &previous_tree,
                    &[DIRECT_PREVIOUS_BYTES],
                ),
            )
            .await
            .unwrap();
        assert_ne!(
            source.authority.issuer_key().public_key,
            destination.authority.issuer_key().public_key
        );
        // The private input remains a signed audit-only parent after the public
        // predecessor. Capture both actual identities before disclosure exists.
        let expected_disclosure_parents = [previous.commit, source_head.commit];
        Self {
            source,
            destination,
            source_head,
            previous,
            expected_disclosure_parents,
            previous_root: previous_tree.root_identity(),
            public_tree,
        }
    }

    /// Begins the actual paired writer before any interrupted Guard transition.
    async fn writer(&self) -> WriterSession {
        let writer = self
            .destination
            .repository
            .begin(REFERENCE, self.destination.authority.token(), "sdk")
            .await
            .unwrap();
        assert_eq!(writer.record(), Some(&self.previous));
        writer
    }

    /// Supplies genuine source Read and destination Commit for the paired producer.
    fn request(&self) -> DisclosureCommitRequest {
        DisclosureCommitRequest {
            proposal: proposal(
                &self.destination.authority,
                vec![self.previous.commit],
                &self.public_tree,
                &[DIRECT_BYTES],
            ),
            selections: vec![DisclosureCommitSelection {
                source_reference: REFERENCE.into(),
                source_commit: self.source_head.commit,
                source_path: b"/file".to_vec(),
                source_token: self.source.authority.token().to_vec(),
                destination_path: b"/file".to_vec(),
            }],
        }
    }

    /// Decodes the canonical signed target independently of the direct verifier result.
    async fn signed_root(&self, target: &RefRecord) -> Digest {
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Commit, &target.commit)
            .unwrap();
        let bytes = self
            .destination
            .coordinator()
            .store()
            .get(&identity, None)
            .await
            .unwrap();
        Commit::decode(&bytes).unwrap().tree
    }

    /// Removes only the two genuine runtime fixtures and their protected owners.
    async fn erase(self) {
        erase_direct_factory(self.source).await;
        erase_direct_factory(self.destination).await;
    }
}

/// Records complete selected state without repairing materialized backend caches.
#[derive(Debug, Eq, PartialEq)]
struct ImportedPublication {
    state: PublicationState,
    stamp: (u64, RawDigest),
    logical: BTreeMap<String, Option<Vec<u8>>>,
}

/// Observes the actual backend selection without starting current authorization.
async fn publication_observation(
    factory: &super::current_authority::Factory,
) -> ImportedPublication {
    let holder = crate::bucket::held::SingleHeld::acquire_read_only(factory.coordinator().store())
        .await
        .unwrap();
    let source = holder.source();
    let observed = source.observe_for_read().await.unwrap();
    let publication = ImportedPublication {
        state: observed.state().clone(),
        stamp: observed.stamp(),
        logical: observed.logical().clone(),
    };
    observed.revalidate().await.unwrap();
    publication
}

/// Changes one well-formed canonical record while preserving its physical selector.
fn changed_import_control(kind: ControlKind, bytes: &[u8]) -> Vec<u8> {
    match kind {
        ControlKind::Import => {
            let mut record = ImportRecord::decode(bytes).unwrap();
            record.baseline.acl.first_mut().unwrap().1 = 15;
            record.validate().unwrap();
            record.encode().unwrap()
        }
        ControlKind::ImportBinding => {
            let mut record = ImportBindingRecord::decode(bytes).unwrap();
            record.destination_authority[0] ^= 1;
            let changed = record.encode().unwrap();
            ImportBindingRecord::decode(&changed).unwrap();
            changed
        }
        ControlKind::ImportTrust => {
            let mut record = PublicTrustRecord::decode(bytes).unwrap();
            record.disclosure_roles.first_mut().unwrap().not_after = Some(u64::MAX);
            record.validate().unwrap();
            record.encode().unwrap()
        }
        _ => panic!("expected one actual imported control kind"),
    }
}

/// Removes this factory's exact backend control and uniquely named runtime directories.
async fn erase_direct_factory(factory: super::current_authority::Factory) {
    let root = factory.coordinator().store().root().to_owned();
    let publication = factory.control().await;
    let sibling = |suffix| {
        root.with_file_name(format!(
            "{}-{suffix}",
            root.file_name().unwrap().to_string_lossy()
        ))
    };
    let paths: [PathBuf; 5] = [
        control(&root),
        publication,
        sibling("current-credentials"),
        sibling("operator"),
        root,
    ];
    drop(factory);
    for path in paths {
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(!path.exists());
    }
}

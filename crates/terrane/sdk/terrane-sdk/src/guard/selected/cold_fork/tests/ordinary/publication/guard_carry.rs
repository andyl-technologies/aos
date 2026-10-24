//! Checks real unrelated trust installation and unrelated branch changes.
//!
//! Metadata observations are attached and calibrated on every actual bucket.
//! The carry span covers qualification through the Guard's native durable ACK;
//! the separately measured public fork covers preparation through its own ACK.

use super::*;

use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection, StagedUpload};
use crate::selected_bridge::native_guard::guard_carry::observations;
use terrane_format::gc::publication::evidence::CheckedLineage;

const TRUST_TARGET: &str = "refs/heads/_/unrelated-trust";
const OTHER: &str = "refs/heads/_/unrelated";

struct PublicFixture {
    repository: NativeRepository,
    authority: LocalAuthority,
    record: RefRecord,
    root: [u8; 32],
    _directory: FixtureDirectory,
}

impl PublicFixture {
    async fn open() -> TestResult<Self> {
        let fs = CountingFs::default();
        let clock = TestClock::new(1000);
        let entropy = fs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("terrane-guard-carry-{suffix}"));
        fs.create_dir_new(&parent).await?;
        let directory = FixtureDirectory(parent.clone());
        let owner_uid = fs.metadata(&parent).await?.uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let mut configured = policy()?;
        configured.domain = "public".into();
        let (repository, authority) = Repository::initialize_local(
            &location,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "owner".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: 1010,
                    not_before: None,
                    token_id: entropy.try_into().map_err(|_| "invalid entropy")?,
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                    workload: None,
                },
            },
            configured,
            SOURCE,
            fs,
            clock,
        )
        .await?;
        let record = repository
            .coordinator()
            .store()
            .ref_get(SOURCE)
            .await?
            .ok_or("missing initialized head")?;
        let snapshot = repository
            .coordinator()
            .guard()
            .read_snapshot(SOURCE, authority.token(), b"/", "sdk")
            .await?;
        let root = snapshot.evidence.root;
        calibrate(&repository, root).await?;
        Ok(Self {
            repository,
            authority,
            record,
            root,
            _directory: directory,
        })
    }

    /// Imports an actual public file through normal signed durable publication.
    ///
    /// # Errors
    /// Preserves filesystem, current authority, import and publication failures.
    async fn open_file() -> TestResult<Self> {
        let mut fixture = Self::open().await?;
        let repository = &fixture.repository;
        let directory = fixture._directory.0.join("source");
        repository
            .coordinator()
            .fs()
            .create_dir_new(&directory)
            .await?;
        repository
            .coordinator()
            .fs()
            .write_new(
                &directory.join("file"),
                b"independently public attributed content",
            )
            .await?;

        let mut session = repository
            .begin(SOURCE, fixture.authority.token(), "sdk")
            .await?;
        let record = repository
            .commit_directory(
                &mut session,
                &directory,
                &fixture.authority,
                metadata("Import independently public source"),
            )
            .await?;
        assert_ne!(record.commit, fixture.record.commit);
        let snapshot = repository
            .coordinator()
            .guard()
            .read_snapshot(SOURCE, fixture.authority.token(), b"/file", "sdk")
            .await?;
        let completed = lineage(repository, SOURCE).await?;
        assert!(completed.used.check_supported_view_contexts()?);
        assert!(
            completed
                .used
                .views
                .iter()
                .any(|view| view.view == record.commit)
        );
        calibrate(repository, snapshot.evidence.root).await?;

        fixture.record = record;
        fixture.root = snapshot.evidence.root;
        Ok(fixture)
    }
}

async fn calibrate(repository: &NativeRepository, root: [u8; 32]) -> TestResult {
    let store = repository.coordinator().store();
    let observer = store.observe_metadata_for_tests()?;
    observer.reset();
    let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root)?;
    let bytes = store.get(&identity, None).await?;
    assert!(observer.snapshot().node_gets > 0);
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &bytes)?,
        ))
        .await?;
    assert!(observer.snapshot().node_puts > 0);
    assert!(observer.snapshot().node_decodes > 0);
    observer.reset();
    Ok(())
}

async fn lineage(repository: &NativeRepository, reference: &str) -> TestResult<CheckedLineage> {
    let held = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = held.destination();
    let observed = destination.observe_publication().await?;
    let record = destination
        .selected_lineage_record(&observed, reference)
        .await?
        .ok_or("missing genuine selected source lineage")?;
    Ok(CheckedLineage::decode(
        record.bytes().ok_or("missing lineage body")?,
    )?)
}

async fn disclose_unrelated(
    source: &Fixture,
    destination: &PublicFixture,
) -> TestResult<RefRecord> {
    let repository = &destination.repository;
    let snapshot = source
        .repository
        .coordinator()
        .guard()
        .read_snapshot(SOURCE, source.authority.token(), b"/file", "sdk")
        .await?;
    let (location, _) = snapshot.history.locate(source.record.commit, b"file")?;
    let mut entry = snapshot.history.entry(&location)?.clone();
    assert!(!entry.attrs.is_empty());
    for attribute in &entry.attrs {
        assert_eq!(
            snapshot
                .history
                .attribute_producer(&location, attribute.name)?,
            source.record.commit
        );
    }

    // Content certificates do not cover the imported file's private attribute
    // producers. This public target deliberately omits those optional attributes.
    entry.attrs.clear();
    entry.attrs_present = false;
    entry.provenance = None;
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry,
        }],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x65owner\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        repository.chunk_profile().minimum() as u64,
        TreeUse::Ordinary,
    )?;
    let mut session = repository
        .begin(TRUST_TARGET, destination.authority.token(), "sdk")
        .await?;
    let mut proposal =
        repository.source_request(&destination.authority, metadata("Install unrelated trust"));
    proposal.commit.tree = tree.root_identity();
    proposal.commit.parents = session
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    proposal.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    Ok(repository
        .commit_disclosure(
            &source.repository,
            &mut session,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: SOURCE.into(),
                    source_commit: source.record.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await?)
}

/// Preserves the actual public source's independently verified attribute producers.
///
/// # Errors
/// Preserves source reads, signed disclosure and ordinary dependency failures.
async fn disclose_public_source(
    source: &PublicFixture,
    destination: &PublicFixture,
) -> TestResult<RefRecord> {
    let repository = &destination.repository;
    let snapshot = source
        .repository
        .coordinator()
        .guard()
        .read_snapshot(SOURCE, source.authority.token(), b"/file", "sdk")
        .await?;
    let (location, _) = snapshot.history.locate(source.record.commit, b"file")?;
    let mut entry = snapshot.history.entry(&location)?.clone();
    assert!(!entry.attrs.is_empty());
    for attribute in &entry.attrs {
        assert_eq!(
            snapshot
                .history
                .attribute_producer(&location, attribute.name)?,
            source.record.commit
        );
    }

    // These independently public attribute origins remain ordinary dependencies,
    // so the completed destination must retain their real foreign Original.
    entry.provenance = None;
    let (root, uploads) = {
        let tree = Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry,
            }],
            Some(vec![
                Property {
                    name: "acl",
                    value: b"\x81\x82\x65owner\x18\x1f",
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
            ]),
            repository.chunk_profile().minimum() as u64,
            TreeUse::Ordinary,
        )?;
        let uploads = tree
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        (tree.root_identity(), uploads)
    };
    let mut session = repository
        .begin(TRUST_TARGET, destination.authority.token(), "sdk")
        .await?;
    let mut proposal =
        repository.source_request(&destination.authority, metadata("Install unrelated trust"));
    proposal.commit.tree = root;
    proposal.commit.parents = session
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    proposal.uploads = uploads;
    Ok(repository
        .commit_disclosure(
            &source.repository,
            &mut session,
            DisclosureCommitRequest {
                proposal,
                selections: vec![DisclosureCommitSelection {
                    source_reference: SOURCE.into(),
                    source_commit: source.record.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await?)
}

async fn assert_cold_fork(
    repository: &NativeRepository,
    authority: &LocalAuthority,
    record: &RefRecord,
    root: [u8; 32],
) -> TestResult {
    let observer = repository.coordinator().store().observe_content_for_tests();
    observer.reset();
    let fork = repository
        .fork(
            SOURCE,
            DESTINATION,
            repository.source_request(authority, metadata("Fork preserved source")),
        )
        .await?;
    let measured = observer.snapshot();
    assert_eq!(
        [
            measured.node_gets,
            measured.node_puts,
            measured.node_decodes
        ],
        [0; 3]
    );
    assert_eq!(measured.commit_puts, 1);
    assert_ne!(fork.commit, record.commit);
    assert_eq!(
        repository.coordinator().store().ref_get(SOURCE).await?,
        Some(record.clone())
    );
    assert_eq!(
        repository
            .coordinator()
            .store()
            .ref_get(DESTINATION)
            .await?,
        Some(fork.clone())
    );
    let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &fork.commit)?;
    let bytes = repository
        .coordinator()
        .store()
        .get(&identity, None)
        .await?;
    let commit = terrane_format::refs::Commit::decode(&bytes)?;
    assert_eq!(commit.tree, root);
    assert_eq!(commit.parents, vec![record.commit]);
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or("missing signed context")?;
    assert_eq!(context.reference(), DESTINATION);
    let roots = context
        .roots()
        .iter()
        .map(|claim| terrane_format::auth::RequestRoot {
            path: claim.path(),
            domain: claim.domain(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        terrane_format::provenance::verify_history(
            &commit,
            repository.coordinator().guard().keys(),
            &roots,
            &[(DESTINATION, fork.writer_epoch)],
        )?
        .identity(),
        fork.commit
    );
    let measured = observer.snapshot();
    assert_eq!(
        [
            measured.node_gets,
            measured.node_puts,
            measured.node_decodes
        ],
        [0; 3]
    );
    Ok(())
}

#[tokio::test]
async fn unrelated_public_trust_install_carries_selected_source_without_node_io() -> TestResult {
    let source = Fixture::open().await?;
    let destination = PublicFixture::open().await?;
    assert_ne!(
        source.authority.issuer_key().public_key,
        destination.authority.issuer_key().public_key
    );
    let before = lineage(&destination.repository, SOURCE).await?;
    observations::take(destination.repository.coordinator().store().root());

    disclose_unrelated(&source, &destination).await?;
    let spans = observations::take(destination.repository.coordinator().store().root());
    assert_eq!(spans.len(), 1);
    assert!(spans[0].qualified);
    assert_eq!(spans[0].nodes, [0; 3]);
    assert_eq!(spans[0].installed_nodes, Some([0; 3]));
    assert!(spans[0].sources.iter().any(|name| name == SOURCE));
    let after = lineage(&destination.repository, SOURCE).await?;
    assert_ne!(before.guard_digest, after.guard_digest);
    let mut expected = before;
    expected.guard_digest = after.guard_digest;
    assert_eq!(after, expected);
    assert_eq!(
        destination
            .repository
            .coordinator()
            .store()
            .ref_get(SOURCE)
            .await?,
        Some(destination.record.clone())
    );

    assert_cold_fork(
        &destination.repository,
        &destination.authority,
        &destination.record,
        destination.root,
    )
    .await
}

#[tokio::test]
async fn unrelated_public_branch_advance_preserves_separate_zero_node_fork() -> TestResult {
    let fixture = Fixture::open().await?;
    let repository = &fixture.repository;
    let before = lineage(repository, SOURCE).await?;
    let other = repository
        .fork(
            SOURCE,
            OTHER,
            repository.source_request(&fixture.authority, metadata("Create unrelated branch")),
        )
        .await?;
    let directory = fixture
        .location
        .bucket
        .parent()
        .ok_or("missing fixture parent")?
        .join("other-source");
    fixture.fs.create_dir_new(&directory).await?;
    fixture
        .fs
        .write_new(&directory.join("changed"), b"unrelated branch content")
        .await?;
    let mut session = repository
        .begin(OTHER, fixture.authority.token(), "sdk")
        .await?;

    let advanced = repository
        .commit_directory(
            &mut session,
            &directory,
            &fixture.authority,
            metadata("Advance unrelated branch"),
        )
        .await?;
    assert_ne!(advanced.commit, other.commit);
    assert!(advanced.seq > other.seq);
    assert_eq!(
        repository.coordinator().store().ref_get(OTHER).await?,
        Some(advanced)
    );
    assert_eq!(lineage(repository, SOURCE).await?, before);

    assert_cold_fork(
        repository,
        &fixture.authority,
        &fixture.record,
        fixture.root,
    )
    .await
}

#[tokio::test]
async fn successive_public_trust_installs_recheck_foreign_original_dependencies() -> TestResult {
    let first_source = PublicFixture::open_file().await?;
    let second_source = Fixture::open().await?;
    let destination = PublicFixture::open().await?;
    let initial = lineage(&destination.repository, SOURCE).await?;
    observations::take(destination.repository.coordinator().store().root());
    disclose_public_source(&first_source, &destination).await?;
    let imported_source = lineage(&destination.repository, TRUST_TARGET).await?;
    let first_original = destination
        .repository
        .coordinator()
        .guard()
        .original_commit(&first_source.record.commit)?;
    assert_ne!(
        first_original.baseline().authority().id(),
        destination
            .repository
            .coordinator()
            .guard()
            .configured_original_authority()?
            .id()
    );
    assert!(
        imported_source
            .used
            .views
            .iter()
            .any(|view| view.view == first_source.record.commit)
    );
    assert!(
        imported_source
            .controls
            .iter()
            .any(|pin| pin.kind
                == terrane_format::gc::publication::evidence::ControlKind::ImportTrust)
    );
    assert!(imported_source.used.check_supported_view_contexts()?);

    // The second genuine install must carry the first certified source's used
    // foreign contexts before its own separate ordinary candidate publication.
    disclose_unrelated(&second_source, &destination).await?;
    let spans = observations::take(destination.repository.coordinator().store().root());
    assert_eq!(spans.len(), 2);
    assert!(spans[1].sources.iter().any(|name| name == TRUST_TARGET));
    for span in spans {
        assert!(span.qualified);
        assert_eq!(span.nodes, [0; 3]);
        assert_eq!(span.installed_nodes, Some([0; 3]));
    }
    let after = lineage(&destination.repository, SOURCE).await?;
    let mut expected = initial;
    expected.guard_digest = after.guard_digest;
    assert_eq!(after, expected);
    assert_cold_fork(
        &destination.repository,
        &destination.authority,
        &destination.record,
        destination.root,
    )
    .await
}

#[tokio::test]
async fn final_guard_install_refuses_original_lost_after_carry_qualification() -> TestResult {
    let source = Fixture::open().await?;
    let destination = PublicFixture::open().await?;
    let repository = &destination.repository;
    let store = repository.coordinator().store();
    let before = lineage(repository, SOURCE).await?;
    let (selected_before, prior_path) = {
        let held = SingleHeld::acquire(store).await?;
        let destination = held.destination();
        let observed = destination.observe_publication().await?;
        let record = destination
            .selected_lineage_record(&observed, SOURCE)
            .await?
            .ok_or("missing actual prior lineage receipt")?;
        (observed.state().clone(), record.path().to_owned())
    };
    let original_context = repository
        .coordinator()
        .guard()
        .original_commit(&destination.record.commit)?;
    assert_eq!(original_context.commit(), &destination.record.commit);
    let association = crate::guard::publication_original_pins(&original_context)?
        .into_iter()
        .find(|pin| pin.kind == terrane_format::gc::publication::evidence::ControlKind::Association)
        .ok_or("missing independently checked source Original pin")?;
    assert!(before.controls.contains(&association));
    let original = original_context
        .baseline()
        .authority()
        .control()
        .join(&association.key);
    let original_bytes = store.fs().read(&original).await?;
    association.check_record(&original_bytes)?;
    let checked_association =
        terrane_format::gc::publication::evidence::OriginalAssociation::decode(&original_bytes)?;
    assert_eq!(checked_association.commit, *original_context.commit());
    let prior_bytes = store.fs().read(&prior_path).await?;
    let lineage_directory = prior_path
        .parent()
        .ok_or("missing actual selected lineage directory")?
        .to_owned();
    store
        .fs()
        .lose_original_at_guard_lineage(lineage_directory, original.clone())?;
    observations::take(store.root());

    let failure = match disclose_unrelated(&source, &destination).await {
        Err(failure) => failure,
        Ok(_) => panic!("missing actual Original must refuse final Guard installation"),
    };

    assert!(matches!(
        failure.downcast_ref::<crate::repository::Error>(),
        Some(crate::repository::Error::Advance(
            crate::ref_advance::AdvanceError::Store(_)
        ))
    ));
    assert!(matches!(
        store.fs().metadata(&original).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    let spans = observations::take(store.root());
    assert_eq!(spans.len(), 1);
    assert!(spans[0].qualified);
    assert_eq!(spans[0].nodes, [0; 3]);
    assert_eq!(spans[0].installed_nodes, None);
    assert!(spans[0].sources.iter().any(|name| name == SOURCE));
    assert_eq!(
        store.ref_get(SOURCE).await?,
        Some(destination.record.clone())
    );
    assert!(store.ref_get(TRUST_TARGET).await?.is_none());
    assert_eq!(store.fs().read(&prior_path).await?, prior_bytes);
    assert_eq!(lineage(repository, SOURCE).await?, before);
    let held = SingleHeld::acquire(store).await?;
    let destination = held.destination();
    let observed = destination.observe_publication().await?;
    assert_eq!(observed.state(), &selected_before);
    Ok(())
}

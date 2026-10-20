//! Prepares authentic signed maintenance fixtures and native physical counterproofs.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

use crate::guard::{
    AuthoringNamespaceProfile, Guard, RecordedNamespaceProfile, RecordedNamespaceProfiles,
};
use crate::ref_advance::Coordinator;
use crate::repository::local_authority::retention::{self, CommitAssociation};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{
    ContentStore, ContentUpload, LocalFs, MetaUpload, RefStore, TokioClock, TokioLocalFs,
};
use terrane_format::auth::{Request, RequestRoot, Verb};
use terrane_format::derived::AttributeValue;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::properties::semantics::associations::RecordedAssociation;
use terrane_format::refs::{Commit, EntryOrigin, EntrySource, RefRecord};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Property, TreeUse};

use super::super::{IndexVerificationStatus, Purpose};
use super::fixture::{self, Fixture, NativeRepository, REFERENCE, SHA256, TestResult};

const ATTRIBUTE: &str = "hash.sha256";

/// Prints an opted-in diagnostic phase without changing operation evidence.
pub(super) fn trace(phase: &str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!("index-rebuild phase={phase}");
    }
}

/// Publishes complete indexed inputs through genuine native backfill.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn complete() -> TestResult<Fixture> {
    trace("complete-native-factory");
    complete_fixture(Fixture::new().await?).await
}

/// Publishes a positive indexed population under its preserved bucket policy.
///
/// # Errors
/// Preserves real fixture preparation, canonical admission and publication failures.
pub(super) async fn complete_population() -> TestResult<Fixture> {
    trace("complete-native-factory");
    complete_fixture(Fixture::new_population().await?).await
}

async fn complete_fixture(fixture: Fixture) -> TestResult<Fixture> {
    trace("complete-partial");
    let first = fixture.partial().await?;
    trace("complete-side");
    fixture
        .side(first.commit, AttributeValue::Sha256(SHA256), true)
        .await?;
    trace("complete-policy");
    fixture.policy(&[ATTRIBUTE], None, None).await?;
    trace("complete-canonical-prestage");
    // Pre-stage derived Nodes into independent native packs. These bytes grant
    // no owner binding; actual guarded backfill authenticates and publishes it.
    let guard = fixture.repository.coordinator().guard();
    let current = guard.store().ref_get(REFERENCE).await?.ok_or("source")?;
    let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &current.commit)?;
    let bytes = guard.store().get(&identity, None).await?;
    let commit = Commit::decode(&bytes)?;
    let evidence =
        crate::guard::TreeEvidence::load_tree(guard.store(), commit.tree, &[], 262144).await?;
    let value = AttributeValue::Sha256(SHA256).encode()?;
    let owner = {
        let source = evidence.tree(evidence.root, 262144)?;
        let mut items = source.iter().cloned().collect::<Vec<_>>();
        for item in &mut items {
            if !item
                .entry
                .attrs
                .iter()
                .any(|attribute| attribute.name == ATTRIBUTE)
            {
                item.entry
                    .attrs
                    .push(terrane_format::tree_format::Attribute {
                        name: ATTRIBUTE,
                        value: &value,
                    });
                item.entry
                    .attrs
                    .sort_by(|left, right| left.name.cmp(right.name));
            }
        }
        Tree::build(
            items,
            source.props().map(|properties| properties.to_vec()),
            262144,
            TreeUse::Ordinary,
        )?
    };
    let recipe =
        terrane_format::indexing::IndexEvaluationRecipe::new(owner.root_identity(), ATTRIBUTE)?;
    let mut trees = BTreeMap::new();
    trees.insert(owner.root_identity(), owner);
    let data = terrane_format::indexing::evaluation::construct(
        &recipe,
        &trees,
        262144,
        terrane_format::indexing::carrier::SemanticContext::new(3, 2, 1)?,
    )?;
    for bytes in data.nodes.values() {
        guard
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                bytes,
            )?))
            .await?;
    }
    trace("complete-template");
    let (mut session, request) = fixture.template().await?;
    trace("complete-native-backfill");
    let report = fixture
        .repository
        .backfill_index_inputs(&mut session, request)
        .await?;
    assert!(report.is_complete());
    trace("complete-finished");
    Ok(fixture)
}

/// Stages an independently signed defective historical source.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn divergent(fixture: &Fixture) -> TestResult<(NativeRepository, RefRecord)> {
    divergent_with_producer(fixture, false).await
}

/// Retains signed source and producer views under actual native Original controls.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
///
/// # Panics
/// Panics if the constructed signed producer or source witnesses contradict fixture assertions.
pub(super) async fn divergent_with_producer(
    fixture: &Fixture,
    deny_producer: bool,
) -> TestResult<(NativeRepository, RefRecord)> {
    trace("divergent-signed-source");
    let old = fixture.repository.coordinator().guard();
    let current = old
        .store()
        .ref_get(REFERENCE)
        .await?
        .ok_or("current source")?;
    let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &current.commit)?;
    let mut commit = Commit::decode(&old.store().get(&identity, None).await?)?;
    let evidence =
        crate::guard::TreeEvidence::load_tree(old.store(), commit.tree, &[], 262144).await?;
    let empty = Tree::build(Vec::new(), None, 262144, TreeUse::Index)?;
    let mut wrapper = b"\xa2\x65value\xa1\x6bhash.sha256".to_vec();
    let hexadecimal = empty
        .root_identity()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    terrane_format::cbor::write_text(&mut wrapper, &hexadecimal);
    wrapper.extend_from_slice(b"\x67inherit\xf4");
    let tree = {
        let source = evidence.tree(evidence.root, 262144)?;
        let mut properties = source
            .props()
            .unwrap_or_default()
            .iter()
            .filter(|property| property.name != "index-roots")
            .cloned()
            .collect::<Vec<_>>();
        properties.push(Property {
            name: "index-roots",
            value: &wrapper,
        });
        Tree::build(
            source.iter().cloned().collect(),
            Some(properties),
            262144,
            TreeUse::Ordinary,
        )?
    };
    commit.signature = None;
    commit.tree = tree.root_identity();
    commit.parents = vec![current.commit];
    for receipt in commit.profile_pair.entry_receipts.iter_mut().flatten() {
        receipt.root = commit.tree;
        receipt.origin = EntryOrigin::Source(EntrySource {
            commit: current.commit,
            root: evidence.root,
            path: receipt.path.clone(),
        });
        if let Some(attributes) = &mut receipt.attributes {
            for (_, origin) in attributes {
                *origin = EntryOrigin::Source(EntrySource {
                    commit: current.commit,
                    root: evidence.root,
                    path: receipt.path.clone(),
                });
            }
        }
    }
    let template = crate::ref_advance::tests::request(vec![current.commit]);
    let roots = [RequestRoot {
        path: b"/",
        domain: "public",
    }];
    let epochs = [(REFERENCE, current.writer_epoch)];
    let request = Request {
        reference: REFERENCE.as_bytes(),
        verb: Verb::Commit,
        roots: &roots,
        now: commit.timestamp,
        surface: "sdk",
        locality: &old.config().home,
        epochs: &epochs,
    };
    let producer = if deny_producer {
        let trust = terrane_format::provenance::Selector::preset(
            terrane_format::provenance::Preset::Attested,
        )
        .encode()
        .to_vec();
        let producer_tree = {
            let source = evidence.tree(evidence.root, 262144)?;
            let mut properties = source
                .props()
                .unwrap_or_default()
                .iter()
                .filter(|property| property.name != "trust")
                .cloned()
                .collect::<Vec<_>>();
            properties.push(Property {
                name: "trust",
                value: &trust,
            });
            Tree::build(
                source.iter().cloned().collect(),
                Some(properties),
                262144,
                TreeUse::Ordinary,
            )?
        };
        let mut producer = commit.clone();
        producer.tree = producer_tree.root_identity();
        for receipt in producer.profile_pair.entry_receipts.iter_mut().flatten() {
            receipt.root = producer.tree;
            receipt.origin = EntryOrigin::Source(EntrySource {
                commit: current.commit,
                root: evidence.root,
                path: receipt.path.clone(),
            });
            if let Some(attributes) = &mut receipt.attributes {
                for (_, origin) in attributes {
                    *origin = EntryOrigin::Current;
                }
            }
        }
        let producer = terrane_format::provenance::sign_authored(
            producer,
            &template.terminal_secret,
            old.keys(),
            &request,
            current.writer_epoch,
        )?;
        for node in producer_tree.nodes() {
            old.store()
                .put(ContentUpload::Meta(MetaUpload::new(
                    IdentityKind::Node,
                    node.encoded(),
                )?))
                .await?;
        }
        let bytes = producer.commit().encode()?;
        old.store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Commit,
                &bytes,
            )?))
            .await?;
        retain_signed(fixture, old, &current, producer.identity()).await?;
        for receipt in commit.profile_pair.entry_receipts.iter_mut().flatten() {
            if let Some(attributes) = &mut receipt.attributes {
                for (_, origin) in attributes {
                    *origin = EntryOrigin::Source(EntrySource {
                        commit: producer.identity(),
                        root: producer.commit().tree,
                        path: receipt.path.clone(),
                    });
                }
            }
        }
        commit.parents.push(producer.identity());
        Some(producer.identity())
    } else {
        None
    };
    let signed = terrane_format::provenance::sign_authored(
        commit,
        &template.terminal_secret,
        old.keys(),
        &request,
        current.writer_epoch,
    )?;
    for node in tree.nodes().chain(empty.nodes()) {
        old.store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                node.encoded(),
            )?))
            .await?;
    }
    let encoded = signed.commit().encode()?;
    old.store()
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Commit,
            &encoded,
        )?))
        .await?;
    retain_signed(fixture, old, &current, signed.identity()).await?;
    trace("divergent-native-reopen");
    let repository = reopen(
        fixture,
        old,
        &[signed.identity()]
            .into_iter()
            .chain(producer)
            .collect::<Vec<_>>(),
    )
    .await?;
    let mut selected = current.clone();
    selected.commit = signed.identity();
    selected.seq += 1;
    selected.candidate_id = Some(signed.identity());
    let log = terrane_format::refs::RefLogRecord {
        record: selected.clone(),
        previous_commit: Some(current.commit),
        principal: signed.authority().subject.clone(),
        reason: terrane_format::refs::RefLogReason::Commit,
        timestamp: signed.commit().timestamp,
        expected_previous: Some(Some(current.clone())),
        committed_previous: None,
    };
    trace("divergent-raw-log-append");
    repository
        .coordinator()
        .store()
        .ref_log_append(REFERENCE, selected.seq, &log)
        .await?;
    trace("divergent-raw-log-appended");
    trace("divergent-raw-cas");
    assert!(matches!(
        repository
            .coordinator()
            .store()
            .ref_cas(REFERENCE, Some(&current), &selected)
            .await?,
        crate::store::RefCasOutcome::Applied
    ));
    trace("divergent-raw-cas-applied");
    trace("divergent-selected");
    Ok((repository, selected))
}

/// Durably associates a genuinely signed fixture commit with its original baseline.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn retain_signed(
    fixture: &Fixture,
    old: &Guard<fixture::Bucket, TokioClock>,
    current: &RefRecord,
    identity: terrane_format::identity::Digest,
) -> TestResult {
    let original = old.original_commit(&current.commit)?;
    let association = CommitAssociation {
        commit: identity,
        id: *original.baseline().authority().id(),
        reference: REFERENCE.to_owned(),
        epoch: current.writer_epoch,
    };
    let owner = TokioLocalFs.symlink_metadata(&fixture.control).await?.uid();
    {
        let holder = crate::bucket::held::SingleHeld::acquire(old.store()).await?;
        let destination = holder.destination();
        let proof = destination.identity_proof();
        let _controls = old
            .hold_original_registration_write(original.baseline().authority(), &proof)
            .await?;
        retention::retain(
            &TokioLocalFs,
            &fixture.control,
            owner,
            &association.selector(),
            &association,
            false,
        )
        .await?;
    }
    Ok(())
}

/// Reopens actual retained Original records and independently configured view profiles.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn reopen(
    fixture: &Fixture,
    old: &Guard<fixture::Bucket, TokioClock>,
    additional: &[terrane_format::identity::Digest],
) -> TestResult<NativeRepository> {
    trace("reopen-literal-profile-inputs");
    let owner = TokioLocalFs.symlink_metadata(&fixture.control).await?.uid();
    let authoring = AuthoringNamespaceProfile::new(3, 3, &[], 2)?;
    let mut views = old
        .original_commits
        .read()
        .map_err(|_| "original lock")?
        .keys()
        .copied()
        .collect::<Vec<_>>();
    views.extend_from_slice(additional);
    let mut profiles = Vec::new();
    for view in views {
        trace("reopen-retained-profile-commit");
        let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &view)?;
        let commit = Commit::decode(&old.store().get(&identity, None).await?)?;
        profiles.push(RecordedNamespaceProfile::new(
            RecordedAssociation::new(view, commit.tree, authoring.context().clone()),
            2,
        )?);
    }
    let root = old.store().root().to_path_buf();
    let config = crate::bucket::FileBucketConfig {
        root: root.clone(),
        publication_control: Some(crate::bucket::FileBucketPublicationConfig {
            operator_uid: owner,
            control: None,
        }),
        chunk_profile_name: old.config().chunk_profile_name.clone(),
        chunk_profile: (*old.config().chunk_profile).clone(),
        locality: old.config().home.clone(),
    };
    trace("reopen-native-bucket");
    let bucket = crate::bucket::FileBucket::open(
        config,
        fixture.fs.clone(),
        TokioClock,
        MetadataValidator::new((*old.config().chunk_profile).clone()),
    )
    .await?;
    trace("reopen-configured-authoring");
    let guard = Guard::new_active(
        bucket,
        TokioClock,
        old.keys().to_vec(),
        old.config().clone(),
    )
    .with_recorded_authoring(authoring.context().clone(), 2)?;
    trace("reopen-configured-retained-profiles");
    let guard =
        guard.with_recorded_namespace_profiles(RecordedNamespaceProfiles::new(profiles)?)?;
    trace("reopen-native-original-retention");
    Repository::reopen_native_retention(
        Coordinator::new(guard, fixture.timing, fixture.fs.clone()),
        &crate::domain::DomainNamespace {
            root,
            domain: "public".into(),
        },
        &fixture.control,
        owner,
    )
    .await
    .map_err(Into::into)
}

/// Captures actual immutable filesystem bytes for mutation assertions.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn physical(
    root: &std::path::Path,
) -> TestResult<BTreeMap<std::path::PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = TokioLocalFs.symlink_metadata(&path).await?;
        if metadata.is_dir() {
            pending.extend(TokioLocalFs.read_dir(&path).await?);
        } else if metadata.is_file() {
            let body = TokioLocalFs.read_nofollow(&path).await?;
            result.insert(path, body);
        }
    }
    Ok(result)
}

/// Captures genuine protected selected-publication readbacks.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn publication_image(
    repository: &NativeRepository,
) -> TestResult<BTreeMap<std::path::PathBuf, Option<Vec<u8>>>> {
    let holder =
        crate::bucket::held::SingleHeld::acquire_read_only(repository.coordinator().store())
            .await?;
    let held = holder.source();
    let observed = held.observe_publication_unrepaired().await?;
    Ok(observed
        .physical_reads()
        .iter()
        .map(|read| {
            (
                read.path().to_path_buf(),
                read.bytes().map(ToOwned::to_owned),
            )
        })
        .collect())
}

/// Begins a real maintenance session and builds its unsigned metadata template.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
pub(super) async fn repair_request(
    repository: &NativeRepository,
) -> TestResult<(
    crate::ref_advance::WriterSession,
    crate::guard::CommitRequest,
)> {
    let token = crate::ref_advance::tests::token();
    let session = repository
        .begin_index_rebuild(REFERENCE, &token, "sdk")
        .await?;
    let selected = session.record().ok_or("repair source")?;
    let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &selected.commit)?;
    let bytes = repository
        .coordinator()
        .store()
        .get(&identity, None)
        .await?;
    let commit = Commit::decode(&bytes)?;
    let mut request = crate::ref_advance::tests::request(vec![selected.commit]);
    request.commit.tree = commit.tree;
    request.uploads.clear();
    Ok((session, request))
}

/// Selects the actual indexed metadata object removed or corrupted by a fixture.
#[derive(Clone, Copy)]
pub(super) enum Loss {
    Primary,
    CorruptPrimary,
    PresentRoute,
    Gap,
    MissingRoute,
}

/// Publishes canonical indexed present and gap inputs in independent native packs.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
///
/// # Panics
/// Panics if canonical population or the required gap and producer assertions fail.
pub(super) async fn partial_index_population() -> TestResult<Fixture> {
    let fixture = Fixture::new_population().await?;
    fixture.partial().await?;
    let guard = fixture.repository.coordinator().guard();
    let source = guard
        .read_snapshot(REFERENCE, &crate::ref_advance::tests::token(), b"/", "sdk")
        .await?;
    let tree = source.evidence.tree(source.evidence.root, 262144)?;
    let recipe =
        terrane_format::indexing::IndexEvaluationRecipe::new(tree.root_identity(), ATTRIBUTE)?;
    let trees = BTreeMap::from([(tree.root_identity(), tree)]);
    let data = terrane_format::indexing::evaluation::construct(
        &recipe,
        &trees,
        262144,
        terrane_format::indexing::carrier::SemanticContext::new(3, 2, 1)?,
    )?;
    for bytes in data.nodes.values() {
        guard
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                bytes,
            )?))
            .await?;
    }
    fixture.bound_requirement().await?;
    let report = guard
        .verify_index(
            REFERENCE,
            &crate::ref_advance::tests::token(),
            "sdk",
            ATTRIBUTE,
        )
        .await?;
    assert!(
        report
            .indexes
            .iter()
            .all(|index| matches!(index.status, IndexVerificationStatus::Verified))
    );
    assert!(
        report
            .indexes
            .iter()
            .any(|index| !index.missing_values.is_empty())
    );
    Ok(fixture)
}

/// Removes or corrupts one auxiliary pack while retaining source packs.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
///
/// # Panics
/// Panics if the observed auxiliary identity or selected source invariants differ from the fixture.
pub(super) async fn lose_auxiliary(fixture: &Fixture, loss: Loss) -> TestResult<RefRecord> {
    let guard = fixture.repository.coordinator().guard();
    trace("loss-ref-get");
    let record = guard
        .store()
        .ref_get(REFERENCE)
        .await?
        .ok_or("selected source")?;
    trace("loss-ref-got");
    let token = crate::ref_advance::tests::token();
    trace("loss-source-read");
    let snapshot = guard.read_snapshot(REFERENCE, &token, b"/", "sdk").await?;
    trace("loss-source-read-complete");
    trace("loss-selected-profile");
    let (_, profile) = guard.selected_view_profile(
        &snapshot.commit,
        crate::guard::HistoryObservation::default(),
    )?;
    trace("loss-selected-profile-complete");
    trace("loss-index-load");
    let loaded = crate::indexing::load(
        guard.store(),
        snapshot.evidence.root,
        ATTRIBUTE,
        crate::indexing::SemanticRevisions {
            property: profile.property_revision,
            attribute: profile.attribute_revision,
            tree: profile.tree_revision,
        },
        262144,
    )
    .await?;
    trace("loss-index-loaded");
    trace("loss-index-sources");
    let sources = loaded.sources()?;
    trace("loss-index-sources-complete");
    trace("loss-index-prepare");
    let prepared = loaded.prepare(&sources.trees)?;
    trace("loss-index-prepared");
    let value = AttributeValue::Sha256(SHA256).encode()?;
    trace("loss-role-select");
    let root = match loss {
        Loss::Primary | Loss::CorruptPrimary => prepared.root(),
        Loss::PresentRoute => prepared
            .candidates(&value)?
            .rows
            .first()
            .ok_or("present route")?
            .route(),
        Loss::Gap => prepared.gap_root().ok_or("gap root")?,
        Loss::MissingRoute => prepared
            .all_missing()?
            .rows
            .first()
            .ok_or("missing route")?
            .route(),
    };
    trace("loss-role-selected");
    let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root)?;
    let pack = {
        trace("loss-held-acquire");
        let holder = crate::bucket::held::SingleHeld::acquire_read_only(guard.store()).await?;
        trace("loss-held-acquired");
        let held = holder.source();
        trace("loss-observe-unrepaired");
        let observed = held.observe_publication_unrepaired().await?;
        trace("loss-observed-unrepaired");
        trace("loss-auxiliary-placement");
        let pack = held
            .metadata_pack_path_for_tests(&observed, &identity)
            .await?;
        trace("loss-auxiliary-placement-complete");
        for source in [
            TERRANE_V1.from_digest(IdentityKind::Node, &snapshot.evidence.root)?,
            TERRANE_V1.from_digest(IdentityKind::Commit, &record.commit)?,
        ] {
            trace("loss-source-placement");
            let retained = held
                .metadata_pack_path_for_tests(&observed, &source)
                .await?;
            trace("loss-source-placement-complete");
            trace("loss-source-pack-compare");
            assert_ne!(
                retained, pack,
                "auxiliary loss must preserve authoritative source packs"
            );
        }
        trace("loss-source-packs-preserved");
        pack
    };
    let damaged = if matches!(loss, Loss::CorruptPrimary) {
        let metadata = fixture.fs.metadata(&pack).await?;
        let mut bytes = fixture.fs.read_nofollow(&pack).await?;
        let last = bytes.last_mut().ok_or("nonempty auxiliary pack")?;
        *last ^= 1;
        Some((bytes, metadata.permissions()))
    } else {
        None
    };
    trace("loss-remove-pack");
    fixture.fs.remove_file(&pack).await?;
    trace("loss-pack-removed");
    if let Some((bytes, permissions)) = damaged {
        fixture.fs.write_new(&pack, &bytes).await?;
        fixture
            .fs
            .set_permissions_and_sync(&pack, permissions)
            .await?;
    }
    fixture
        .fs
        .sync_directory(pack.parent().ok_or("pack parent")?)
        .await?;
    trace("loss-removal-durable");
    Ok(record)
}

/// Selects the protected input invalidated after genuine source capture.
#[derive(Clone, Copy)]
pub(super) enum Late {
    SourceOriginal,
    ProducerOriginal,
    CurrentSelection,
}

/// Invalidates a real protected control after source capture during candidate staging.
///
/// # Errors
/// Preserves actual fixture storage, signed-history, authorization and assertion failures.
///
/// # Panics
/// Panics if late invalidation fails to preserve the expected refusal and selected-state invariants.
pub(super) async fn late_refusal(kind: Late) -> TestResult {
    use std::sync::atomic::Ordering;
    let token = crate::ref_advance::tests::token();
    let late = complete().await?;
    let (repository, selected) = divergent(&late).await?;
    let purpose = Purpose {
        source: selected.commit,
    };
    let observation = crate::guard::HistoryObservation::default().maintenance(&purpose);
    let guard = repository.coordinator().guard();
    let snapshot = guard
        .read_commit_snapshot_observed(selected.commit, &token, b"/", "sdk", observation)
        .await?;
    let (location, _) = snapshot.history.locate(selected.commit, b"file")?;
    let producer = snapshot.history.attribute_producer(&location, ATTRIBUTE)?;
    assert_ne!(producer, selected.commit);
    let target = match kind {
        Late::CurrentSelection => {
            let holder = crate::bucket::held::SingleHeld::acquire_read_only(guard.store()).await?;
            let held = holder.source();
            let observed = held.observe_publication_unrepaired().await?;
            let suffix = std::path::PathBuf::from(format!(
                "publication/commits/{}",
                observed.state().revision
            ));
            observed
                .physical_reads()
                .iter()
                .find(|read| read.path().ends_with(&suffix))
                .ok_or("selected native slot")?
                .path()
                .to_path_buf()
        }
        Late::SourceOriginal | Late::ProducerOriginal => {
            let identity = if matches!(kind, Late::SourceOriginal) {
                selected.commit
            } else {
                producer
            };
            let original = guard.original_commit(&identity)?;
            let association = CommitAssociation {
                commit: identity,
                id: *original.baseline().authority().id(),
                reference: original.baseline().reference().to_owned(),
                epoch: original.baseline().epoch(),
            };
            late.control.join(association.selector())
        }
    };
    let permissions = late.fs.symlink_metadata(&target).await?.permissions();
    let counter = guard.store().observe_metadata_for_tests()?;
    let (mut session, request) = repair_request(&repository).await?;
    counter.reset();
    *late.fs.late_control.lock().map_err(|_| "fault lock")? = Some(target.clone());
    let result = repository
        .rebuild_index(&mut session, request, ATTRIBUTE)
        .await;
    late.fs
        .set_permissions_and_sync(&target, permissions)
        .await?;
    assert!(result.is_err());
    assert_eq!(
        late.fs.late_hits.load(Ordering::SeqCst),
        1,
        "late authority fault did not fire: {result:?}"
    );
    assert!(counter.snapshot().commit_puts > 0);
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(selected)
    );

    Ok(())
}

/// Refuses changed authority immediately after a genuine durable replacement.
///
/// # Errors
/// Preserves genuine population, native replacement and refusal assertion failures.
///
/// # Panics
/// Panics if recovery succeeds unexpectedly or changes the retained source and selected state.
pub(super) async fn recovery_boundary_refusal(kind: Option<Late>) -> TestResult {
    use super::fixture::RecoveryFault;
    use crate::store::Clock;
    use std::sync::atomic::Ordering;

    let fixture = complete_population().await?;
    let token = crate::ref_advance::tests::token();
    let old = fixture.repository.coordinator().guard();
    let snapshot = old.read_snapshot(REFERENCE, &token, b"/", "sdk").await?;
    let selected = old
        .store()
        .ref_get(REFERENCE)
        .await?
        .ok_or("selected source")?;
    // Only this boundary fixture uses the existing retained test clock. Seed
    // its wall sample from Tokio and enable genuine native timer progression.
    let wall = TokioClock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)?
        .as_secs();
    let clock = crate::store::TestClock::new(wall);
    clock.enable_timer();
    let fault = match kind {
        Some(Late::CurrentSelection) => RecoveryFault::CurrentSelection,
        Some(original_kind) => {
            let (location, _) = snapshot.history.locate(selected.commit, b"file")?;
            let identity = match original_kind {
                Late::SourceOriginal => selected.commit,
                Late::ProducerOriginal => {
                    snapshot.history.attribute_producer(&location, ATTRIBUTE)?
                }
                Late::CurrentSelection => unreachable!(),
            };
            let original = old.original_commit(&identity)?;
            let association = CommitAssociation {
                commit: identity,
                id: *original.baseline().authority().id(),
                reference: original.baseline().reference().to_owned(),
                epoch: original.baseline().epoch(),
            };
            RecoveryFault::Control(fixture.control.join(association.selector()))
        }
        None => RecoveryFault::Deadline(clock.clone()),
    };
    lose_auxiliary(&fixture, Loss::Primary).await?;

    // Configuration alone carries no Original evidence. Reopen restores actual
    // protected records using the existing native factory before any operation.
    let guard = old.read_configuration_adapter(old.store().clone(), clock);
    let owner = TokioLocalFs.symlink_metadata(&fixture.control).await?.uid();
    let repository = Repository::reopen_native_retention(
        Coordinator::new(guard, fixture.timing, fixture.fs.clone()),
        &crate::domain::DomainNamespace {
            root: old.store().root().to_owned(),
            domain: "public".into(),
        },
        &fixture.control,
        owner,
    )
    .await?;
    // Recovery captures the authoritative namespace without requiring the lost
    // auxiliary binding to be readable before its actual durable replacement.
    let mut session = repository
        .begin_index_rebuild(REFERENCE, &token, "sdk")
        .await?;
    let mut request = crate::ref_advance::tests::request(vec![selected.commit]);
    request.commit.tree = snapshot.evidence.root;
    request.uploads.clear();
    *fixture
        .fs
        .recovery_fault
        .lock()
        .map_err(|_| "recovery fault lock")? = Some(fault);

    let result = repository
        .rebuild_index(&mut session, request, ATTRIBUTE)
        .await;

    let changed = fixture
        .fs
        .recovery_changed
        .lock()
        .map_err(|_| "recovery restore lock")?
        .take();
    if let Some((target, permissions)) = changed {
        fixture
            .fs
            .set_permissions_and_sync(&target, permissions)
            .await?;
    }
    assert_eq!(fixture.fs.recovery_hits.load(Ordering::SeqCst), 1);
    if kind.is_none() {
        // The immutable producer refreshes its retained final request after
        // the durable offer. STORE-30 preserves that deadline refusal as Denied.
        assert!(matches!(
            result,
            Err(crate::repository::Error::Advance(
                crate::ref_advance::AdvanceError::Store(ref failure)
            )) if matches!(failure.kind(), crate::store::StoreErrorKind::Denied { .. })
        ));
    } else {
        assert!(result.is_err());
    }
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(selected)
    );
    Ok(())
}

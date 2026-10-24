//! Checks separate full source completion and a subsequent zero-Node public fork.
//!
//! Snapshots below retain actual selected and filesystem observations as test
//! data. They cannot construct completion, native evidence or current authority.

use super::*;

use crate::bucket::publication::receipts::RecordRead;
use crate::ref_advance::AdvanceError;
use crate::repository::Error;
use crate::store::{StoreErrorKind, StoreFailure};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt, path::PathBuf};
use terrane_format::gc::publication::{PublicationState, PublicationTransaction};

#[path = "requalification/faults.rs"]
mod faults;

#[path = "requalification/indexes.rs"]
mod indexes;

/// Retains actual source selection, signed bytes and complete log observations.
pub(super) struct SourceSnapshot {
    /// Retains the complete selected source head.
    pub(super) record: RefRecord,
    commit: Vec<u8>,
    /// Retains the complete selected publication state.
    pub(super) state: PublicationState,
    logical: BTreeMap<String, Option<Vec<u8>>>,
    history: Vec<RecordRead>,
    source_transaction: RecordRead,
    original: OriginalImage,
    /// Retains the optional actual protected lineage read.
    pub(super) lineage: Option<RecordRead>,
    /// Identifies the backend control from its actual selected Guard receipt.
    pub(super) control: PathBuf,
}

// An independently configured source Original remains distinct from backend
// publication registration, including when those registrations are foreign.
struct OriginalImage {
    path: PathBuf,
    bytes: Vec<u8>,
    metadata: std::fs::Metadata,
}

impl SourceSnapshot {
    /// Reads exact selected source data under a genuine held backend.
    ///
    /// # Errors
    /// Preserves unavailable, malformed or incomplete actual selected inputs.
    ///
    /// # Panics
    /// Panics when actual selected records violate the fixture invariants.
    pub(super) async fn capture(
        repository: &NativeRepository,
        clock: &TestClock,
        source: &str,
    ) -> TestResult<Self> {
        let store = repository.coordinator().store();
        let holder = SingleHeld::acquire(store).await?;
        let current = repository
            .coordinator()
            .guard()
            .held_guard(holder.destination(), clock.clone())?;
        let observed = current.store().observe_publication().await?;
        let record = current
            .store()
            .ref_get(source)
            .await?
            .ok_or("missing selected source")?;
        let history = current
            .store()
            .selected_source_history_records(&observed, source, &record)
            .await?;
        assert!(!history.is_empty());
        let source_key = terrane_format::bucket::BucketKey::ref_record(source)?;
        let encoded = record.encode()?;
        let source_transaction = observed
            .physical_reads()
            .iter()
            .rev()
            .find(|read| {
                read.bytes()
                    .and_then(|bytes| PublicationTransaction::decode(bytes).ok())
                    .is_some_and(|transaction| {
                        transaction.changes.iter().any(|change| {
                            change.key == source_key.as_str()
                                && change.new.as_deref() == Some(encoded.as_slice())
                        })
                    })
            })
            .cloned()
            .ok_or("missing actual source selection transaction")?;
        let snapshot = current
            .store()
            .selected_guard_snapshot_record(&observed)
            .await?
            .ok_or("missing actual Guard record")?;
        let control = snapshot
            .path()
            .ancestors()
            .nth(3)
            .ok_or("missing protected publication control")?
            .to_owned();
        let lineage = current
            .store()
            .selected_lineage_record(&observed, source)
            .await?;
        let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &record.commit)?;
        let commit = current.store().get(&identity, None).await?;
        let original = repository
            .coordinator()
            .guard()
            .original_commit(&record.commit)?;
        let suffix = record
            .commit
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = original
            .baseline()
            .authority()
            .control()
            .join(format!("commit-{suffix}.cbor"));
        let original = OriginalImage {
            bytes: store.fs().read_nofollow(&path).await?,
            metadata: store.fs().symlink_metadata(&path).await?,
            path,
        };
        assert_eq!(
            terrane_format::refs::Commit::decode(&commit)?.identity()?,
            record.commit
        );
        Ok(Self {
            record,
            commit,
            state: observed.state().clone(),
            logical: observed.logical().clone(),
            history,
            source_transaction,
            original,
            lineage,
            control,
        })
    }

    fn ack_slot(&self) -> PathBuf {
        self.control
            .join("publication/commits")
            .join((self.state.revision + 1).to_string())
    }

    async fn assert_source_unchanged(
        &self,
        repository: &NativeRepository,
        fs: &CountingFs,
        source: &str,
    ) -> TestResult {
        let store = repository.coordinator().store();
        assert_eq!(store.ref_get(source).await?, Some(self.record.clone()));
        let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &self.record.commit)?;
        assert_eq!(store.get(&identity, None).await?, self.commit);
        for read in &self.history {
            assert_eq!(
                fs.read_nofollow(read.path()).await?.as_slice(),
                read.bytes().ok_or("missing observed log body")?
            );
            let previous = read.metadata().ok_or("missing observed log metadata")?;
            let current = fs.symlink_metadata(read.path()).await?;
            assert_eq!(
                (
                    current.dev(),
                    current.ino(),
                    current.mode(),
                    current.len(),
                    current.mtime(),
                    current.mtime_nsec()
                ),
                (
                    previous.dev(),
                    previous.ino(),
                    previous.mode(),
                    previous.len(),
                    previous.mtime(),
                    previous.mtime_nsec()
                )
            );
        }
        assert_eq!(
            fs.read_nofollow(&self.original.path).await?,
            self.original.bytes
        );
        let current = fs.symlink_metadata(&self.original.path).await?;
        let previous = &self.original.metadata;
        assert_eq!(
            (
                current.dev(),
                current.ino(),
                current.uid(),
                current.mode(),
                current.len(),
                current.mtime(),
                current.mtime_nsec()
            ),
            (
                previous.dev(),
                previous.ino(),
                previous.uid(),
                previous.mode(),
                previous.len(),
                previous.mtime(),
                previous.mtime_nsec()
            )
        );
        if let Some(read) = &self.lineage {
            assert_eq!(
                fs.read_nofollow(read.path()).await?.as_slice(),
                read.bytes().ok_or("missing prior lineage body")?
            );
        }
        Ok(())
    }
}

// The observer is the reopened bucket's actual Arc and MetadataValidator.
// Its decoder count measures that validator, not Core read-side TreeEvidence.
async fn calibrate(repository: &NativeRepository, root: [u8; 32]) -> TestResult {
    let store = repository.coordinator().store();
    let observer = store.observe_metadata_for_tests()?;
    observer.reset();
    let node = TERRANE_V1.from_digest(IdentityKind::Node, &root)?;
    let bytes = store.get(&node, None).await?;
    store
        .put(crate::store::ContentUpload::Meta(
            crate::store::MetaUpload::new(IdentityKind::Node, &bytes)?,
        ))
        .await?;
    let measured = observer.snapshot();
    assert!(measured.node_gets > 0);
    assert!(measured.node_puts > 0);
    assert!(measured.node_decodes > 0);
    observer.reset();
    Ok(())
}

/// Publishes an actual raw alias and its complete committed log through RefStore.
///
/// # Errors
/// Preserves log and native selected-CAS failures.
///
/// # Panics
/// Panics when the genuine native CAS does not apply the new raw alias.
pub(super) async fn install_raw_alias(fixture: &Fixture, reference: &str) -> TestResult<RefRecord> {
    let record = RefRecord {
        seq: 1,
        writer_epoch: 0,
        candidate_id: Some([19; 32]),
        ..fixture.record.clone()
    };
    let log = RefLogRecord {
        record: record.clone(),
        previous_commit: None,
        principal: "owner".into(),
        reason: RefLogReason::Commit,
        timestamp: 1000,
        expected_previous: Some(None),
        committed_previous: None,
    };
    let store = fixture.repository.coordinator().store();
    store.ref_log_append(reference, record.seq, &log).await?;
    assert_eq!(
        store.ref_cas(reference, None, &record).await?,
        RefCasOutcome::Applied
    );
    Ok(record)
}

/// Completes a source separately, then measures a full public cold publication.
///
/// # Errors
/// Preserves normal completion, native ACK and subsequent public fork failures.
///
/// # Panics
/// Panics when measured I/O, selected inputs or signed publication violate the witness.
pub(super) async fn requalify_then_cold(
    repository: &NativeRepository,
    authority: &LocalAuthority,
    fs: &CountingFs,
    clock: &TestClock,
    source: &str,
    target: &str,
) -> TestResult {
    let before = SourceSnapshot::capture(repository, clock, source).await?;
    let source_commit = terrane_format::refs::Commit::decode(&before.commit)?;
    let root = source_commit.tree;
    calibrate(repository, root).await?;
    let store = repository.coordinator().store();
    let observer = store.observe_content_for_tests();

    // Missing lineage/context cannot turn a fork into a hidden warm traversal.
    let request = repository.source_request(authority, metadata("Unqualified source refusal"));
    let failure = repository
        .fork(source, target, request)
        .await
        .err()
        .ok_or("unqualified native fork succeeded")?;
    assert!(matches!(
        store_failure(&failure)?.kind(),
        StoreErrorKind::Unsupported
    ));
    assert!(store.ref_get(target).await?.is_none());
    let refused = observer.snapshot();
    assert_eq!(
        (refused.node_gets, refused.node_puts, refused.node_decodes),
        (0, 0, 0)
    );
    before
        .assert_source_unchanged(repository, fs, source)
        .await?;
    observer.reset();
    fs.observe_requalification_ack(before.ack_slot(), false)?;

    let returned = repository
        .requalify_fork_source(source, authority.token(), "sdk")
        .await?;
    assert_eq!(returned, before.record);
    let completed = observer.snapshot();
    assert!(
        completed.node_gets > 0,
        "separate normal completion reads real Nodes"
    );
    assert!(
        completed.node_decodes > 0,
        "actual MetadataValidator is attached"
    );
    assert_eq!(completed.node_puts, 0);
    assert_eq!(completed.commit_puts, 0);
    assert_eq!(fs.requalification_ack_counts(), (1, 1));
    before
        .assert_source_unchanged(repository, fs, source)
        .await?;

    let after = SourceSnapshot::capture(repository, clock, source).await?;
    assert_eq!(after.logical, before.logical);
    let (lineage, _) = selected_fixture_lineage(repository, clock, source).await?;
    let mut expected = before.state.clone();
    expected.revision += 1;
    expected.sources.retain(|row| row.name != source);
    expected
        .sources
        .push(terrane_format::gc::publication::SourceLineage {
            name: source.into(),
            digest: *blake3::hash(
                after
                    .lineage
                    .as_ref()
                    .and_then(RecordRead::bytes)
                    .ok_or("missing fresh lineage")?,
            )
            .as_bytes(),
        });
    expected
        .sources
        .sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    assert_eq!(after.state, expected);
    assert_eq!(lineage.source, before.record);
    assert_eq!(lineage.commit_bytes, before.commit);
    let original = repository
        .coordinator()
        .guard()
        .original_commit(&before.record.commit)?;
    assert_eq!(
        lineage.original,
        crate::guard::consumed_registration(original.baseline().authority())
    );
    assert!(!lineage.used.views.is_empty());
    assert!(!lineage.controls.is_empty());
    let contexts = lineage
        .used
        .view_interpretations
        .as_ref()
        .ok_or("missing independently completed contexts")?;
    assert_eq!(contexts.len(), lineage.used.views.len());
    for view in &lineage.used.views {
        let context = contexts
            .iter()
            .find(|row| row.view == view.view)
            .ok_or("missing used context")?;
        let original_root = view.roots.first().ok_or("missing actual used root")?.root;
        repository
            .coordinator()
            .guard()
            .compare_cold_fork_view_inputs(Some(context), view.view, original_root)?;
    }

    // The full source operation and real native ACK finish before this interval.
    observer.reset();
    let request = repository.source_request(
        authority,
        metadata("Cold fork after separate requalification"),
    );
    let next = repository.fork(source, target, request).await?;
    let measured = observer.snapshot();
    assert_eq!(
        (
            measured.node_gets,
            measured.node_puts,
            measured.node_decodes
        ),
        (0, 0, 0)
    );
    assert_eq!(measured.commit_puts, 1);
    assert_ne!(next.commit, before.record.commit);
    assert_eq!(store.ref_get(target).await?, Some(next.clone()));
    before
        .assert_source_unchanged(repository, fs, source)
        .await?;
    let final_source = SourceSnapshot::capture(repository, clock, source).await?;
    assert_eq!(final_source.state.guard, after.state.guard);
    assert_eq!(
        final_source.state.loss_generation,
        after.state.loss_generation
    );
    assert_eq!(final_source.state.binding, after.state.binding);
    for selected in &after.state.sources {
        assert!(final_source.state.sources.contains(selected));
    }
    for branch in &after.state.branches {
        assert!(final_source.state.branches.contains(branch));
    }
    let (cold, _) = selected_fixture_lineage(repository, clock, target).await?;
    let commit = terrane_format::refs::Commit::decode(&cold.commit_bytes)?;
    assert_eq!(commit.tree, root);
    assert_eq!(commit.parents, vec![before.record.commit]);
    let signed = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or("missing fresh signed context")?;
    assert_eq!(signed.reference(), target);
    let roots = signed
        .roots()
        .iter()
        .map(|row| terrane_format::auth::RequestRoot {
            path: row.path(),
            domain: row.domain(),
        })
        .collect::<Vec<_>>();
    let verified = terrane_format::provenance::verify_history(
        &commit,
        repository.coordinator().guard().keys(),
        &roots,
        &[(target, next.writer_epoch)],
    )?;
    assert_eq!(verified.identity(), next.commit);
    let final_counts = observer.snapshot();
    assert_eq!(
        (
            final_counts.node_gets,
            final_counts.node_puts,
            final_counts.node_decodes
        ),
        (0, 0, 0)
    );
    Ok(())
}

fn store_failure(failure: &Error) -> TestResult<&StoreFailure> {
    match failure {
        Error::Store(error) | Error::Advance(AdvanceError::Store(error)) => Ok(error),
        Error::Advance(AdvanceError::Indeterminate { source, .. }) => Ok(source),
        other => Err(format!("unexpected typed failure: {other:?}").into()),
    }
}

#[tokio::test]
async fn requalification_byte_identical_context_refuses_fresh_ack() -> TestResult {
    let fixture = Fixture::open().await?;
    install_raw_alias(&fixture, DESTINATION).await?;
    fixture
        .repository
        .requalify_fork_source(DESTINATION, fixture.authority.token(), "sdk")
        .await?;
    let before = SourceSnapshot::capture(&fixture.repository, &fixture.clock, DESTINATION).await?;
    fixture
        .fs
        .observe_requalification_ack(before.ack_slot(), false)?;
    fixture.fs.observe_requalification_effects()?;
    fixture.fs.effects.store(0, Ordering::SeqCst);

    let failure = fixture
        .repository
        .requalify_fork_source(DESTINATION, fixture.authority.token(), "sdk")
        .await
        .err()
        .ok_or("byte-identical completion falsely acknowledged")?;

    assert!(matches!(
        store_failure(&failure)?.kind(),
        StoreErrorKind::Unsupported
    ));
    assert_eq!(fixture.fs.requalification_ack_counts(), (0, 0));
    assert_eq!(fixture.fs.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.fs.requalification_effect_observations()?,
        vec![(
            "DirectorySync",
            Some(fixture.repository.coordinator().store().root().to_owned()),
        )]
    );
    let after = SourceSnapshot::capture(&fixture.repository, &fixture.clock, DESTINATION).await?;
    assert_eq!(after.state, before.state);
    assert_eq!(after.logical, before.logical);
    before
        .assert_source_unchanged(&fixture.repository, &fixture.fs, DESTINATION)
        .await?;
    Ok(())
}

#[tokio::test]
async fn requalification_preserves_current_fork_and_token_refusals() -> TestResult {
    for case in ["acl", "grant", "root", "domain", "surface", "time"] {
        let mut fixture = Fixture::open().await?;
        if case == "acl" {
            fixture.revoke_fork().await?;
        }
        let signing = fixture
            .repository
            .source_request(&fixture.authority, metadata("Restricted requalification"));
        let mut attenuation = Attenuation::default();
        match case {
            "grant" => {
                attenuation.grants = Some(vec![Grant::new("refs/**".into(), Verbs::new(4)?)?])
            }
            "root" => attenuation.caveats = vec![Caveat::Root("/missing".into())],
            "domain" => attenuation.caveats = vec![Caveat::Domain("private:other".into())],
            "surface" => attenuation.caveats = vec![Caveat::Surface("other".into())],
            "time" => attenuation.caveats = vec![Caveat::Before(1000)],
            "acl" => {}
            _ => unreachable!("fixed cases"),
        }
        let token = if case == "acl" {
            fixture.authority.token().to_vec()
        } else {
            Token::decode(fixture.authority.token())?
                .attenuate(
                    attenuation,
                    &signing.terminal_secret,
                    auth::public_key_from_secret(&[73; 32]),
                )?
                .encode()
        };
        let before = SourceSnapshot::capture(&fixture.repository, &fixture.clock, SOURCE).await?;
        fixture
            .fs
            .observe_requalification_ack(before.ack_slot(), false)?;
        fixture.fs.observe_requalification_effects()?;
        fixture.fs.effects.store(0, Ordering::SeqCst);

        let failure = fixture
            .repository
            .requalify_fork_source(SOURCE, &token, "sdk")
            .await
            .err()
            .ok_or_else(|| format!("{case} source accepted"))?;

        assert!(
            matches!(
                store_failure(&failure)?.kind(),
                StoreErrorKind::Denied { verb: "fork", .. }
            ),
            "{case}: {failure:?}"
        );
        assert_eq!(fixture.fs.requalification_ack_counts(), (0, 0), "{case}");
        assert_eq!(fixture.fs.effects.load(Ordering::SeqCst), 1, "{case}");
        assert_eq!(
            fixture.fs.requalification_effect_observations()?,
            vec![(
                "DirectorySync",
                Some(fixture.repository.coordinator().store().root().to_owned()),
            )],
            "{case}"
        );
        let after = SourceSnapshot::capture(&fixture.repository, &fixture.clock, SOURCE).await?;
        assert_eq!(after.state, before.state, "{case}");
        assert_eq!(after.logical, before.logical, "{case}");
        before
            .assert_source_unchanged(&fixture.repository, &fixture.fs, SOURCE)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn requalification_refuses_malformed_selected_lineage() -> TestResult {
    let fixture = Fixture::open().await?;
    let before = SourceSnapshot::capture(&fixture.repository, &fixture.clock, SOURCE).await?;
    let read = before
        .lineage
        .as_ref()
        .ok_or("missing actual prior lineage")?;
    let mut bytes = read.bytes().ok_or("missing actual lineage bytes")?.to_vec();
    bytes[0] ^= 1;
    fixture.fs.remove_file(read.path()).await?;
    fixture.fs.write_new(read.path(), &bytes).await?;
    fixture
        .fs
        .set_permissions(
            read.path(),
            read.metadata()
                .ok_or("missing lineage metadata")?
                .permissions(),
        )
        .await?;
    fixture
        .fs
        .observe_requalification_ack(before.ack_slot(), false)?;

    for cold in [false, true] {
        let result = if cold {
            let request = fixture.repository.source_request(
                &fixture.authority,
                metadata("Malformed lineage cannot fall back"),
            );
            fixture.repository.fork(SOURCE, DESTINATION, request).await
        } else {
            fixture
                .repository
                .requalify_fork_source(SOURCE, fixture.authority.token(), "sdk")
                .await
        };
        let failure = result.err().ok_or("malformed selected lineage accepted")?;
        assert!(
            matches!(store_failure(&failure)?.kind(), StoreErrorKind::Corrupt(_)),
            "{failure:?}"
        );
    }
    assert_eq!(fixture.fs.requalification_ack_counts(), (0, 0));
    assert_eq!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(SOURCE)
            .await?,
        Some(before.record)
    );
    assert!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get(DESTINATION)
            .await?
            .is_none()
    );
    Ok(())
}

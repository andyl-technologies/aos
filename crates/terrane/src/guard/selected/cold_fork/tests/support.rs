//! Builds genuine native repositories and calibrates their actual Node observers.

use super::fs::ProbeFs;
use crate::{
    bucket::publication::receipts::RecordRead,
    bucket::{
        BucketBinding, FileBucket, FileBucketConfig, FileBucketPublicationConfig, held::SingleHeld,
    },
    domain::DomainNamespace,
    guard::{Guard, GuardConfig},
    ref_advance::{AdvanceError, CommitRequest, CommitTiming, Coordinator, StagedUpload},
    repository::{Error as RepositoryError, MetadataValidator, Repository},
    store::{
        Clock, ContentStore, ContentUpload, LocalFs, MetaUpload, RefCasOutcome, RefStore,
        StoreFailure, TokioClock, TokioLocalFs,
    },
};
use std::{
    collections::BTreeMap,
    error::Error,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use terrane_core::{
    auth::{self, Authority, Grant, IssuerKey, Token, Verb, Verbs},
    chunking::ChunkProfile,
    gc::publication::{PublicationState, evidence::CheckedLineage},
    identity::{Digest, IdentityKind, TERRANE_V1},
    refs::{
        Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance, RefLogReason,
        RefLogRecord, RefRecord,
    },
    tree_builder::Tree,
    tree_format::{Property, TreeUse},
};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub(super) const ALL_VERBS: u8 =
    Verb::Read as u8 | Verb::Fork as u8 | Verb::Commit as u8 | Verb::Tag as u8 | Verb::Admin as u8;
pub(super) const READ_COMMIT: u8 = Verb::Read as u8 | Verb::Commit as u8;
pub(super) const SOURCE: &str = "refs/heads/_/source";
pub(super) const FORK_COMMIT: u8 = Verb::Fork as u8 | Verb::Commit as u8;
pub(super) const TARGET: &str = "refs/heads/_/cold";

const SECRET: [u8; 32] = [29; 32];

pub(super) type Bucket<C = TokioClock> = FileBucket<ProbeFs, C, MetadataValidator>;

/// Requires setup to succeed while retaining its original typed diagnostic.
///
/// # Panics
/// Panics with the original error when a required fixture operation fails.
pub(super) fn required<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("native cold fixture setup failed: {error:?}"),
    }
}

/// Rejects an unexpected success without substituting another failure.
///
/// # Panics
/// Panics when the required refusal unexpectedly succeeds.
pub(super) fn rejected<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("unexpected native cold success: {value:?}"),
        Err(error) => error,
    }
}

pub(super) fn token(grants: Vec<Grant>) -> TestResult<Vec<u8>> {
    Ok(Token::issue(
        Authority {
            issuer: "cold-test".into(),
            key_id: "key".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [11; 16],
            grants,
            workload: None,
        },
        &SECRET,
        auth::public_key_from_secret(&SECRET),
    )?
    .encode())
}

pub(super) fn full_token() -> TestResult<Vec<u8>> {
    token(vec![Grant::new("refs/**".into(), Verbs::new(ALL_VERBS)?)?])
}

/// Builds canonical empty local Legacy trees before any asynchronous operation.
pub(super) fn request(parents: Vec<Digest>, verbs: u8) -> TestResult<CommitRequest> {
    let mut acl = vec![0x81, 0x82, 0x66];
    acl.extend_from_slice(b"writer");
    terrane_core::cbor::write_uint(&mut acl, u64::from(verbs));
    let (root, uploads) = {
        let tree = Tree::build(
            Vec::new(),
            Some(vec![
                Property {
                    name: "acl",
                    value: &acl,
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
            ]),
            262144,
            TreeUse::Ordinary,
        )?;
        let root = tree.root_identity();
        let uploads = tree
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        (root, uploads)
    };
    Ok(CommitRequest {
        commit: Commit {
            tree: root,
            parents,
            provenance: Provenance {
                issuer: String::new(),
                token_id: [0; 16],
                subject: String::new(),
                kind: PrincipalKind::Human,
                workload_identity: None,
                process: "cold-witness".into(),
                observed_at: 0,
                writer_epoch: 0,
                source: CommitSource::Built,
                embedded_token: None,
            },
            timestamp: 0,
            message: "ordinary complete local source".into(),
            profile_pair: ProfilePair {
                tree_format: 1,
                chunk_profile: "cdc-1m".into(),
                recipe: None,
                conflicted: None,
                lease: None,
                required_properties: None,
                entry_receipts: None,
                commit_context: None,
            },
            packs: None,
            signature: None,
        },
        uploads,
        token: full_token()?,
        terminal_secret: SECRET,
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    })
}

/// Supplies genuine additional-principal widening through ordinary signed admission.
pub(super) fn widened_request(parents: Vec<Digest>) -> TestResult<CommitRequest> {
    let mut proposal = request(parents, ALL_VERBS)?;
    let mut acl = vec![0x82, 0x82, 0x66];
    acl.extend_from_slice(b"writer");
    terrane_core::cbor::write_uint(&mut acl, u64::from(ALL_VERBS));
    acl.extend([0x82, 0x6a]);
    acl.extend_from_slice(b"additional");
    terrane_core::cbor::write_uint(&mut acl, Verb::Commit as u64);
    let (root, uploads) = {
        let tree = Tree::build(
            Vec::new(),
            Some(vec![
                Property {
                    name: "acl",
                    value: &acl,
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
            ]),
            262144,
            TreeUse::Ordinary,
        )?;
        (
            tree.root_identity(),
            tree.nodes()
                .map(|node| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes: node.encoded().to_vec(),
                })
                .collect(),
        )
    };
    proposal.commit.tree = root;
    proposal.uploads = uploads;
    Ok(proposal)
}

pub(super) fn fork_request() -> TestResult<CommitRequest> {
    let mut request = request(Vec::new(), ALL_VERBS)?;
    request.uploads.clear();
    request.commit.message = "fresh signed cold namespace".into();
    Ok(request)
}

/// Keeps real opened backend, protected controls and independently configured keys.
pub(super) struct Fixture<C: Clock + BucketBinding = TokioClock> {
    pub(super) repository: Repository<Bucket<C>, C, ProbeFs>,
    pub(super) fs: ProbeFs,
    pub(super) clock: C,
    pub(super) original: PathBuf,
    owner: u32,
}

impl Fixture {
    pub(super) async fn open() -> TestResult<Self> {
        Self::with_clock(TokioClock).await
    }
}

impl<C: Clock + BucketBinding + Clone + Sync + 'static> Fixture<C> {
    pub(super) async fn with_clock(clock: C) -> TestResult<Self> {
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-root-cold-{suffix}"));
        let original = root.with_file_name(format!("terrane-root-cold-{suffix}-original"));
        TokioLocalFs.create_dir_new(&original).await?;
        TokioLocalFs
            .set_permissions_and_sync(&original, std::fs::Permissions::from_mode(0o700))
            .await?;
        let owner = TokioLocalFs.symlink_metadata(&original).await?.uid();
        let fs = ProbeFs::default();
        let bucket = FileBucket::open(
            config(&root, owner),
            fs.clone(),
            clock.clone(),
            MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
        )
        .await?;
        let repository = Repository::initialize_native_retention(
            coordinator(bucket, clock.clone(), fs.clone())?,
            &DomainNamespace {
                root,
                domain: "public".into(),
            },
            &original,
            owner,
        )
        .await?;
        let observer = repository
            .coordinator()
            .store()
            .observe_metadata_for_tests()?;
        assert!(Arc::ptr_eq(
            &observer,
            &repository.coordinator().store().observe_content_for_tests()
        ));
        fs.reset();
        Ok(Self {
            repository,
            fs,
            clock,
            original,
            owner,
        })
    }

    pub(super) fn bucket(&self) -> &Bucket<C> {
        self.repository.coordinator().store()
    }

    pub(super) async fn publish(
        &self,
        reference: &str,
        request: CommitRequest,
    ) -> TestResult<RefRecord> {
        let mut session = self
            .repository
            .begin(reference, &request.token, "sdk")
            .await?;
        Ok(self
            .repository
            .commit_request(&mut session, request)
            .await?)
    }

    pub(super) async fn complete_source(&self, verbs: u8) -> TestResult<RefRecord> {
        let first = self.publish(SOURCE, request(Vec::new(), verbs)?).await?;
        let observer = self.bucket().observe_metadata_for_tests()?;
        observer.reset();
        let second = self
            .publish(SOURCE, request(vec![first.commit], verbs)?)
            .await?;
        assert!(
            observer.snapshot().node_gets > 0,
            "ordinary history must fetch actual Nodes"
        );
        let selected = Snapshot::capture(self, SOURCE).await?;
        let lineage = selected.lineage()?;
        assert!(
            lineage
                .used
                .views
                .iter()
                .any(|view| view.view == first.commit)
        );
        assert!(
            lineage
                .used
                .views
                .iter()
                .any(|view| view.view == second.commit)
        );
        self.assert_full_context(&lineage)?;
        Ok(second)
    }

    pub(super) fn assert_full_context(&self, lineage: &CheckedLineage) -> TestResult {
        let contexts = lineage
            .used
            .view_interpretations
            .as_ref()
            .ok_or("missing actual completed contexts")?;
        let distinct = lineage
            .used
            .views
            .iter()
            .map(|row| row.view)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(contexts.len(), distinct.len());
        for view in &lineage.used.views {
            self.repository
                .coordinator()
                .guard()
                .compare_requalification_view_inputs(lineage, view)?;
            assert!(contexts.iter().any(|context| context.view == view.view));
        }
        assert!(!lineage.controls.is_empty());
        Ok(())
    }

    /// Calibrates PUT, GET and a fresh reopen against each bucket's own observer.
    ///
    /// Validator Node decodes are distinct from read-side Core TreeEvidence decodes.
    pub(super) async fn calibrate(&self, root: Digest) -> TestResult {
        let observer = self.bucket().observe_metadata_for_tests()?;
        assert!(Arc::ptr_eq(
            &observer,
            &self.bucket().observe_content_for_tests()
        ));
        observer.reset();
        let identity = TERRANE_V1.from_digest(IdentityKind::Node, &root)?;
        let bytes = self.bucket().get(&identity, None).await?;
        assert_eq!(
            self.bucket()
                .put(ContentUpload::Meta(MetaUpload::new(
                    IdentityKind::Node,
                    &bytes
                )?))
                .await?,
            identity
        );
        let counts = observer.snapshot();
        assert!(counts.node_gets > 0 && counts.node_puts > 0 && counts.node_decodes > 0);

        self.fs
            .report_raw_diagnostics("after-main-node-calibration-before-reopen");

        let reopened = FileBucket::open(
            config(self.bucket().root(), self.owner),
            self.fs.clone(),
            self.clock.clone(),
            MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
        )
        .await?;
        self.fs
            .report_raw_diagnostics("after-reopen-before-fresh-node-calibration");
        let fresh = reopened.observe_metadata_for_tests()?;
        assert!(Arc::ptr_eq(&fresh, &reopened.observe_content_for_tests()));
        assert!(!Arc::ptr_eq(&fresh, &observer));
        assert_eq!(reopened.get(&identity, None).await?, bytes);
        assert_eq!(
            reopened
                .put(ContentUpload::Meta(MetaUpload::new(
                    IdentityKind::Node,
                    &bytes
                )?))
                .await?,
            identity
        );
        let counts = fresh.snapshot();
        assert!(counts.node_gets > 0 && counts.node_puts > 0 && counts.node_decodes > 0);
        drop(reopened);
        self.fs.report_raw_diagnostics("calibration-before-reset");
        observer.reset();
        self.fs.reset();
        Ok(())
    }

    pub(super) async fn assert_cold(&self, source: &str, target: &str) -> TestResult<RefRecord> {
        let before = Snapshot::capture(self, source).await?;
        let prior = Commit::decode(&before.commit)?;
        self.calibrate(prior.tree).await?;
        let observer = self.bucket().observe_content_for_tests();

        let next = self
            .repository
            .fork(source, target, fork_request()?)
            .await?;

        let counts = observer.snapshot();
        assert_no_nodes(&counts);
        assert_eq!(counts.commit_puts, 1);
        assert_eq!(self.fs.successful_ref_ack(target), 1);
        let mutation = self
            .fs
            .mutations()
            .into_iter()
            .find(|row| {
                row.acknowledged
                    && row
                        .transaction
                        .changes
                        .iter()
                        .any(|change| change.key == format!("{target}:record"))
            })
            .ok_or("actual final acknowledged Candidate request")?;
        assert!(self.fs.effects().contains(&(
            "SealMutationPublication".into(),
            Some(mutation.path.clone())
        )));
        let old = mutation
            .transaction
            .old
            .as_ref()
            .ok_or("actual prior native selection")?;
        assert_eq!(mutation.transaction.new.revision, old.revision + 1);
        assert!(matches!(
            mutation.transaction.proof,
            terrane_core::gc::publication::PublicationProof::Candidate(_)
        ));

        assert_ne!(next.commit, before.record.commit);
        assert_eq!(self.bucket().ref_get(target).await?, Some(next.clone()));
        before.assert_source_unchanged(self, source).await?;
        let after = Snapshot::capture(self, source).await?;
        assert_eq!(after.state.guard, before.state.guard);
        assert_eq!(after.state.loss_generation, before.state.loss_generation);
        assert_eq!(after.state.binding, before.state.binding);
        for row in &before.state.sources {
            assert!(after.state.sources.contains(row));
        }
        for row in &before.state.branches {
            assert!(after.state.branches.contains(row));
        }

        let fresh = Snapshot::capture(self, target).await?;
        let commit = Commit::decode(&fresh.commit)?;
        assert_eq!(commit.tree, prior.tree);
        assert_eq!(commit.parents, vec![prior.identity()?]);
        assert!(commit.profile_pair.recipe.is_none());
        assert!(commit.profile_pair.entry_receipts.is_none());
        let mut expected_profile = prior.profile_pair.clone();
        expected_profile.recipe = None;
        expected_profile.entry_receipts = None;
        expected_profile.commit_context = commit.profile_pair.commit_context.clone();
        assert_eq!(commit.profile_pair, expected_profile);
        assert_eq!(commit.packs, prior.packs);
        let context = commit
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or("fresh signed context")?;
        assert_eq!(context.reference(), target);
        assert_eq!(context.surface(), "sdk");
        assert_eq!(commit.provenance.writer_epoch, next.writer_epoch);
        assert_eq!(
            commit.provenance.embedded_token.as_deref(),
            Some(full_token()?.as_slice())
        );
        let roots = context
            .roots()
            .iter()
            .map(|root| auth::RequestRoot {
                path: root.path(),
                domain: root.domain(),
            })
            .collect::<Vec<_>>();
        let verified = terrane_core::provenance::verify_history(
            &commit,
            self.repository.coordinator().guard().keys(),
            &roots,
            &[(target, next.writer_epoch)],
        )?;
        assert_eq!(verified.identity(), next.commit);
        let lineage = fresh.lineage()?;
        assert_eq!(lineage.source, next);
        assert_eq!(lineage.commit_id, next.commit);
        assert_eq!(lineage.commit_bytes, fresh.commit);
        self.assert_full_context(&lineage)?;
        assert_no_nodes(&observer.snapshot());
        Ok(next)
    }
}

fn config(root: &Path, owner: u32) -> FileBucketConfig {
    FileBucketConfig {
        root: root.to_owned(),
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid: owner,
            control: None,
        }),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: ChunkProfile::cdc_1m([0; 32]),
        locality: Locality::default(),
    }
}

fn coordinator<C: Clock + BucketBinding + Clone>(
    bucket: Bucket<C>,
    clock: C,
    fs: ProbeFs,
) -> TestResult<Coordinator<Bucket<C>, C, ProbeFs>> {
    Ok(Coordinator::new(
        Guard::new(
            bucket,
            clock,
            vec![IssuerKey {
                issuer: "cold-test".into(),
                key_id: "key".into(),
                public_key: auth::public_key_from_secret(&SECRET),
                retirement: None,
            }],
            GuardConfig {
                store_name: "local".into(),
                private_domain: "private:cold".into(),
                home: Locality::default(),
                initial_acl: vec![("writer".into(), ALL_VERBS)],
                min_chunk_size: 262144,
                storage_domain: "public".into(),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
                policy_authority: None,
            },
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?,
        fs,
    ))
}

/// Preserves complete source/ref/log and protected Original read observations.
pub(super) struct Snapshot {
    pub(super) record: RefRecord,
    pub(super) commit: Vec<u8>,
    pub(super) state: PublicationState,
    pub(super) selected_stamp: (u64, Digest),
    pub(super) snapshot_pointer: terrane_core::gc::publication::PortableCurrent,
    pub(super) control_identity: (u64, u64),
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    pub(super) lineage_read: Option<RecordRead>,
    pub(super) guard_read: RecordRead,
    history: Vec<RecordRead>,
    pub(super) originals: Vec<FileImage>,
}

impl Snapshot {
    pub(super) async fn capture<C: Clock + BucketBinding + Clone + Sync + 'static>(
        fixture: &Fixture<C>,
        source: &str,
    ) -> TestResult<Self> {
        let holder = SingleHeld::acquire(fixture.bucket()).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        let record = held.ref_get(source).await?.ok_or("source whole record")?;
        let history = held
            .selected_source_history_records(&observed, source, &record)
            .await?;
        let lineage_read = held.selected_lineage_record(&observed, source).await?;
        let guard_read = held
            .selected_guard_snapshot_record(&observed)
            .await?
            .ok_or("actual selected Guard")?;
        let commit = held
            .get(
                &TERRANE_V1.from_digest(IdentityKind::Commit, &record.commit)?,
                None,
            )
            .await?;
        let mut paths = vec![
            fixture
                .original
                .join(format!("commit-{}.cbor", hex(&record.commit))),
        ];
        if let Some(read) = &lineage_read {
            let lineage = CheckedLineage::decode(read.bytes().ok_or("selected lineage body")?)?;
            for pin in &lineage.controls {
                assert_eq!(pin.owner, lineage.original);
                match &pin.owner {
                    terrane_core::gc::publication::evidence::PhysicalRegistration::Local(row) => {
                        assert_eq!(row.control, fixture.original.as_os_str().as_bytes())
                    }
                    _ => return Err("foreign control in bounded local fixture".into()),
                }
                paths.push(fixture.original.join(&pin.key));
            }
        }
        // These extra snapshots are non-authoritative postcondition oracles.
        // They include preexisting ancestor Originals even for an alias without
        // lineage; unrelated rows are never fed to qualification or key7 inputs.
        for path in fixture.fs.read_dir(&fixture.original).await? {
            if path.extension() == Some(std::ffi::OsStr::new("cbor")) {
                paths.push(path);
            }
        }
        paths.sort();
        paths.dedup();
        let mut originals = Vec::new();
        for path in paths {
            originals.push(FileImage {
                bytes: fixture.fs.read_nofollow(&path).await?,
                metadata: fixture.fs.symlink_metadata(&path).await?,
                path,
            });
        }
        observed.revalidate().await?;
        Ok(Self {
            record,
            commit,
            state: observed.state().clone(),
            selected_stamp: observed.stamp(),
            snapshot_pointer: observed.snapshot().clone(),
            control_identity: observed.control_identity(),
            logical: observed.logical().clone(),
            lineage_read,
            guard_read,
            history,
            originals,
        })
    }

    pub(super) fn lineage(&self) -> TestResult<CheckedLineage> {
        Ok(CheckedLineage::decode(
            self.lineage_read
                .as_ref()
                .and_then(RecordRead::bytes)
                .ok_or("actual selected complete lineage")?,
        )?)
    }

    pub(super) async fn assert_head_and_history_unchanged<
        C: Clock + BucketBinding + Clone + Sync + 'static,
    >(
        &self,
        fixture: &Fixture<C>,
        source: &str,
    ) -> TestResult {
        assert_eq!(
            fixture.bucket().ref_get(source).await?,
            Some(self.record.clone())
        );
        assert_eq!(
            fixture
                .bucket()
                .get(
                    &TERRANE_V1.from_digest(IdentityKind::Commit, &self.record.commit)?,
                    None
                )
                .await?,
            self.commit
        );
        for read in &self.history {
            assert_read_unchanged(&fixture.fs, read).await?;
        }
        Ok(())
    }

    pub(super) async fn assert_source_unchanged<
        C: Clock + BucketBinding + Clone + Sync + 'static,
    >(
        &self,
        fixture: &Fixture<C>,
        source: &str,
    ) -> TestResult {
        assert_eq!(
            fixture.bucket().ref_get(source).await?,
            Some(self.record.clone())
        );
        assert_eq!(
            fixture
                .bucket()
                .get(
                    &TERRANE_V1.from_digest(IdentityKind::Commit, &self.record.commit)?,
                    None
                )
                .await?,
            self.commit
        );
        for read in self
            .history
            .iter()
            .chain(std::iter::once(&self.guard_read))
            .chain(self.lineage_read.iter())
        {
            assert_read_unchanged(&fixture.fs, read).await?;
        }
        for image in &self.originals {
            image.assert_unchanged(&fixture.fs).await?;
        }
        Ok(())
    }
}

/// Stores fixture observations without constructing a native read receipt.
pub(super) struct FileImage {
    pub(super) path: PathBuf,
    bytes: Vec<u8>,
    metadata: std::fs::Metadata,
}

impl FileImage {
    async fn assert_unchanged(&self, fs: &ProbeFs) -> TestResult {
        assert_eq!(fs.read_nofollow(&self.path).await?, self.bytes);
        assert_eq!(
            stamp(&fs.symlink_metadata(&self.path).await?),
            stamp(&self.metadata)
        );
        Ok(())
    }
}

pub(super) async fn assert_read_unchanged(fs: &ProbeFs, read: &RecordRead) -> TestResult {
    assert_eq!(
        fs.read_nofollow(read.path()).await?.as_slice(),
        read.bytes().ok_or("actual read bytes")?
    );
    let current = fs.symlink_metadata(read.path()).await?;
    let previous = read.metadata().ok_or("actual read metadata")?;
    assert_eq!(stamp(&current), stamp(previous));
    Ok(())
}

pub(super) fn stamp(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
    )
}

pub(super) fn assert_no_nodes(counts: &crate::bucket::content_observation::ContentCounts) {
    assert_eq!(
        (counts.node_gets, counts.node_puts, counts.node_decodes),
        (0, 0, 0)
    );
}

pub(super) fn store_failure(error: &RepositoryError) -> &StoreFailure {
    match error {
        RepositoryError::Store(failure)
        | RepositoryError::Advance(AdvanceError::Store(failure)) => failure,
        RepositoryError::Advance(AdvanceError::Indeterminate { source, .. }) => source,
        other => panic!("expected actual typed Store failure: {other:?}"),
    }
}

pub(super) fn hex(digest: &Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Activates a genuine protocol Selected alias with its complete normal log.
pub(super) async fn raw_alias(
    fixture: &Fixture,
    source: &RefRecord,
    reference: &str,
) -> TestResult<RefRecord> {
    let record = RefRecord {
        seq: 1,
        writer_epoch: 0,
        candidate_id: Some([19; 32]),
        ..source.clone()
    };
    let signed = Commit::decode(
        &fixture
            .bucket()
            .get(
                &TERRANE_V1.from_digest(IdentityKind::Commit, &source.commit)?,
                None,
            )
            .await?,
    )?;
    let log = RefLogRecord {
        record: record.clone(),
        previous_commit: None,
        principal: "writer".into(),
        reason: RefLogReason::Commit,
        timestamp: signed.timestamp,
        expected_previous: Some(None),
        committed_previous: None,
    };
    fixture
        .bucket()
        .ref_log_append(reference, record.seq, &log)
        .await?;
    assert_eq!(
        fixture.bucket().ref_cas(reference, None, &record).await?,
        RefCasOutcome::Applied
    );
    Ok(record)
}

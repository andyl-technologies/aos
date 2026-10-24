//! Builds genuine native repositories and calibrates their actual Node observers.

#[path = "calibration.rs"]
mod calibration;

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
use terrane_format::{
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

/// Carries the original typed diagnostic from a native test operation.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Grants every registered operation to the fixture principal.
pub(super) const ALL_VERBS: u8 =
    Verb::Read as u8 | Verb::Fork as u8 | Verb::Commit as u8 | Verb::Tag as u8 | Verb::Admin as u8;
/// Combines scoped Read and Commit for ordinary fixture publication.
pub(super) const READ_COMMIT: u8 = Verb::Read as u8 | Verb::Commit as u8;
/// Names the independently published source reference.
pub(super) const SOURCE: &str = "refs/heads/_/source";
/// Combines source Fork and destination Commit for fixture copying.
pub(super) const FORK_COMMIT: u8 = Verb::Fork as u8 | Verb::Commit as u8;
/// Names the independently selected cold destination reference.
pub(super) const TARGET: &str = "refs/heads/_/cold";

const SECRET: [u8; 32] = [29; 32];

/// Names the actual native bucket with effect observation and metadata validation.
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

/// Issues a genuine fixture token with the supplied exact grants.
///
/// # Errors
/// Preserves authority validation and token issuance failures.
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

/// Issues a genuine fixture token covering every registered reference operation.
///
/// # Errors
/// Preserves grant validation and token issuance failures.
pub(super) fn full_token() -> TestResult<Vec<u8>> {
    token(vec![Grant::new("refs/**".into(), Verbs::new(ALL_VERBS)?)?])
}

/// Builds canonical empty local Legacy trees before any asynchronous operation.
///
/// # Errors
/// Preserves canonical tree construction and token issuance failures.
pub(super) fn request(parents: Vec<Digest>, verbs: u8) -> TestResult<CommitRequest> {
    let mut acl = vec![0x81, 0x82, 0x66];
    acl.extend_from_slice(b"writer");
    terrane_format::cbor::write_uint(&mut acl, u64::from(verbs));
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
///
/// # Errors
/// Preserves canonical tree construction and token issuance failures.
pub(super) fn widened_request(parents: Vec<Digest>) -> TestResult<CommitRequest> {
    let mut proposal = request(parents, ALL_VERBS)?;
    let mut acl = vec![0x82, 0x82, 0x66];
    acl.extend_from_slice(b"writer");
    terrane_format::cbor::write_uint(&mut acl, u64::from(ALL_VERBS));
    acl.extend([0x82, 0x6a]);
    acl.extend_from_slice(b"additional");
    terrane_format::cbor::write_uint(&mut acl, Verb::Commit as u64);
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

/// Builds a fresh copied-tree proposal without unreachable staged uploads.
///
/// # Errors
/// Preserves canonical baseline construction and token issuance failures.
pub(super) fn fork_request() -> TestResult<CommitRequest> {
    let mut request = request(Vec::new(), ALL_VERBS)?;
    request.uploads.clear();
    request.commit.message = "fresh signed cold namespace".into();
    Ok(request)
}

/// Keeps real opened backend, protected controls and independently configured keys.
pub(super) struct Fixture<C: Clock + BucketBinding = TokioClock> {
    /// Owns the actual native coordinator and protected retention setup.
    pub(super) repository: Repository<Bucket<C>, C, ProbeFs>,
    /// Retains the forwarding filesystem observer used by the native backend.
    pub(super) fs: ProbeFs,
    /// Retains the same injected clock used by the fixture publication producer.
    pub(super) clock: C,
    /// Names the protected Original control directory created for this fixture.
    pub(super) original: PathBuf,
    owner: u32,
}

impl Fixture {
    /// Opens a genuine native fixture with its ordinary Tokio clock.
    ///
    /// # Errors
    /// Preserves filesystem setup, bucket opening and Original initialization failures.
    ///
    /// # Panics
    /// Panics if metadata and content observers differ or fixture synchronization is poisoned.
    pub(super) async fn open() -> TestResult<Self> {
        Self::with_clock(TokioClock).await
    }
}

impl<C: Clock + BucketBinding + Clone + Sync + 'static> Fixture<C> {
    /// Opens a genuine native fixture with the supplied actual injected clock.
    ///
    /// # Errors
    /// Preserves entropy, filesystem setup, bucket opening and Original initialization failures.
    ///
    /// # Panics
    /// Panics if metadata and content observers differ or fixture synchronization is poisoned.
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

    /// Borrows the actual opened bucket owned by the fixture repository.
    pub(super) fn bucket(&self) -> &Bucket<C> {
        self.repository.coordinator().store()
    }

    /// Publishes a proposal through an actual native writer session.
    ///
    /// # Errors
    /// Preserves session opening, current admission and native publication failures.
    ///
    /// # Panics
    /// Panics if the forwarding filesystem observation synchronization is poisoned.
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

    /// Publishes two genuine source commits and checks their completed lineage context.
    ///
    /// # Errors
    /// Preserves proposal, publication, observation and lineage qualification failures.
    ///
    /// # Panics
    /// Panics if actual Node reads, completed contexts or protected controls are missing.
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

    /// Requires exact completed contexts for every genuine lineage view.
    ///
    /// # Errors
    /// Rejects missing contexts or mismatched independently selected view inputs.
    ///
    /// # Panics
    /// Panics if view contexts are incomplete or protected control dependencies are absent.
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
    ///
    /// # Errors
    /// Preserves actual selection, metadata I/O, reopen and successor-check failures.
    ///
    /// # Panics
    /// Panics if observer identity, metadata counters or addressed bytes contradict calibration.
    pub(super) async fn calibrate(&self, root: Digest) -> TestResult {
        let before = calibration::Selection::capture(self).await?;
        let mutation_start = self.fs.mutations().len();
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

        let reopened = FileBucket::open(
            config(self.bucket().root(), self.owner),
            self.fs.clone(),
            self.clock.clone(),
            MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
        )
        .await?;
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
        let after = calibration::Selection::capture(self).await?;
        before
            .assert_probe_successor(self, &after, mutation_start)
            .await?;
        observer.reset();
        self.fs.reset();
        Ok(())
    }

    /// Requires genuine cold publication without Node I/O and with a native acknowledgment.
    ///
    /// # Errors
    /// Preserves source observations, calibration, publication and retained-state checks.
    ///
    /// # Panics
    /// Panics if cold counters, actual acknowledgment or selected-state invariants fail.
    pub(super) async fn assert_cold(&self, source: &str, target: &str) -> TestResult<RefRecord> {
        let before = Snapshot::capture(self, source).await?;
        let prior = Commit::decode(&before.commit)?;
        self.calibrate(prior.tree).await?;
        let calibrated = Snapshot::capture(self, source).await?;
        let publication_start = calibration::Selection::capture(self).await?;
        assert_eq!(publication_start.state(), &calibrated.state);
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
        publication_start
            .assert_commit_catalog_chain(self, target, &next)
            .await?;
        assert_eq!(mutation.transaction.new.revision, old.revision + 1);
        assert!(matches!(
            mutation.transaction.proof,
            terrane_format::gc::publication::PublicationProof::Candidate(_)
        ));

        assert_ne!(next.commit, before.record.commit);
        assert_eq!(self.bucket().ref_get(target).await?, Some(next.clone()));
        before.assert_source_unchanged(self, source).await?;
        let after = Snapshot::capture(self, source).await?;
        assert_eq!(mutation.transaction.new, after.state);
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
        let verified = terrane_format::provenance::verify_history(
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
    /// Retains the exact selected whole source record.
    pub(super) record: RefRecord,
    /// Retains the addressed signed source commit bytes.
    pub(super) commit: Vec<u8>,
    /// Retains the complete actual selected publication state.
    pub(super) state: PublicationState,
    /// Retains the exact logical projection of selected control values.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Retains the actual selected lineage record observation when present.
    pub(super) lineage_read: Option<RecordRead>,
    /// Retains the actual selected Guard snapshot record observation.
    pub(super) guard_read: RecordRead,
    history: Vec<RecordRead>,
    /// Retains exact protected Original file bytes and incarnations.
    pub(super) originals: Vec<FileImage>,
}

impl Snapshot {
    /// Captures actual selected source and protected Original observations under exclusion.
    ///
    /// # Errors
    /// Preserves holder acquisition, selected reads, identity decoding and protected file failures.
    ///
    /// # Panics
    /// Panics if captured lineage controls name a different Original owner or control directory.
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
                    terrane_format::gc::publication::evidence::PhysicalRegistration::Local(row) => {
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
            logical: observed.logical().clone(),
            lineage_read,
            guard_read,
            history,
            originals,
        })
    }

    /// Decodes the actual retained selected lineage bytes without constructing authority.
    ///
    /// # Errors
    /// Rejects absent lineage bytes or invalid canonical lineage encoding.
    pub(super) fn lineage(&self) -> TestResult<CheckedLineage> {
        Ok(CheckedLineage::decode(
            self.lineage_read
                .as_ref()
                .and_then(RecordRead::bytes)
                .ok_or("actual selected complete lineage")?,
        )?)
    }

    /// Requires the exact source head, signed commit and retained history observations.
    ///
    /// # Errors
    /// Preserves actual head, commit and retained history read failures.
    ///
    /// # Panics
    /// Panics if source head, signed bytes or history observations changed.
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

    /// Requires exact source history and protected Original observations to remain unchanged.
    ///
    /// # Errors
    /// Preserves source and protected control read failures.
    ///
    /// # Panics
    /// Panics if any captured source or protected Original observation changed.
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
    /// Names the exact protected file observed by the fixture.
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

/// Requires the bytes and incarnation of an actual native read to remain unchanged.
///
/// # Errors
/// Rejects missing captured bytes or metadata and preserves current filesystem read failures.
///
/// # Panics
/// Panics if bytes or the complete metadata stamp changed.
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

/// Copies the complete incarnation and metadata tuple compared by the fixture.
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

/// Requires zero actual Node GET, PUT and validator decode observations.
///
/// # Panics
/// Panics if any observed Node counter is nonzero.
pub(super) fn assert_no_nodes(counts: &crate::bucket::content_observation::ContentCounts) {
    assert_eq!(
        (counts.node_gets, counts.node_puts, counts.node_decodes),
        (0, 0, 0)
    );
}

/// Borrows the original typed store failure from supported repository error forms.
///
/// # Panics
/// Panics if the repository error does not contain an actual store failure.
pub(super) fn store_failure(error: &RepositoryError) -> &StoreFailure {
    match error {
        RepositoryError::Store(failure)
        | RepositoryError::Advance(AdvanceError::Store(failure)) => failure,
        RepositoryError::Advance(AdvanceError::Indeterminate { source, .. }) => source,
        other => panic!("expected actual typed Store failure: {other:?}"),
    }
}

/// Encodes a fixture digest as lowercase hexadecimal text.
pub(super) fn hex(digest: &Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Activates a genuine protocol Selected alias with its complete normal log.
///
/// # Errors
/// Preserves signed commit reads, canonical decoding, log append and ref CAS failures.
///
/// # Panics
/// Panics if the actual ref CAS does not apply the alias.
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

//! Builds ordinary native repositories and independent selected/body/creator oracles.

use super::fs::ProbeFs;
use crate::{
    bucket::{BucketBinding, FileBucket, held::SingleHeld},
    domain::DomainNamespace,
    guard::Guard,
    pack::{MergedEntry, MergedShard, PackIndexSnapshot, PackReader, RawBodyDecoder, RecordState},
    ref_advance::{CommitRequest, CommitTiming, Coordinator, StagedUpload},
    repository::Repository,
    store::{
        ChunkPosition, ChunkRequirement, Clock, ContentStore, ContentUpload, ContentValidator,
        InvalidReason, LocalFs, MetaUpload, RefStore, StoreErrorKind, StoreFailure, TestClock,
        TokioClock, TokioLocalFs,
    },
};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt::Debug,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use terrane_core::{
    bucket::{BucketCapabilities, GenerationManifest},
    gc::{
        ArtifactBinding, CreationJournal, JournalState,
        publication::{
            CommittedSelection, PublicationCommit, PublicationProof, PublicationState,
            PublicationTransaction,
        },
    },
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    refs::{Commit, RefLogRecord, RefRecord},
    tree_builder::Tree,
    tree_format::{self, ContentRef, EntryKind, NodeItems, Property, TreeUse},
};

/// Preserves original typed errors from each actual fixture operation.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Requires actual setup success without converting a refusal into evidence.
///
/// # Panics
/// Panics with the original error when a required fixture step fails.
pub(super) fn required<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("required native batch fixture step failed: {error:?}"),
    }
}

/// Requires a specific negative operation to return its original error.
///
/// # Panics
/// Panics if the operation unexpectedly succeeds.
pub(super) fn rejected<T: Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("unexpected native batch success: {value:?}"),
        Err(error) => error,
    }
}

/// Names schema-validation observations without constructing checked evidence.
type ValidatedOffers = Vec<(IdentityKind, Vec<u8>)>;

/// Records actual configured-validator calls, never publication permission.
#[derive(Clone, Default)]
pub(super) struct Validator(Arc<Mutex<ValidatedOffers>>);

impl Validator {
    /// Counts exact offered bytes that reached the real configured schema validator.
    ///
    /// # Panics
    /// Panics if instrumentation was poisoned by another failed fixture assertion.
    pub(super) fn calls(&self, kind: IdentityKind, bytes: &[u8]) -> usize {
        required(self.0.lock())
            .iter()
            .filter(|(actual, body)| *actual == kind && body == bytes)
            .count()
    }
}

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        required(self.0.lock()).push((upload.kind(), upload.bytes().to_vec()));
        let valid = match upload.kind() {
            IdentityKind::Node => {
                tree_format::decode_node_for(upload.bytes(), true, 262144, TreeUse::Ordinary)
                    .is_ok()
            }
            IdentityKind::Commit => Commit::decode(upload.bytes()).is_ok(),
            IdentityKind::Memo => terrane_core::derivation::Memo::decode(upload.bytes()).is_ok(),
            IdentityKind::Pack => PackReader::open(upload.bytes()).is_ok(),
            IdentityKind::Index => PackIndexSnapshot::decode(upload.bytes(), 0).is_ok(),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload {
                    rule_id: "STORE-33",
                },
            )))
        }
    }

    fn chunk_requirements(
        &self,
        upload: &MetaUpload<'_>,
    ) -> Result<Vec<ChunkRequirement>, StoreFailure> {
        if upload.kind() != IdentityKind::Node {
            return Ok(Vec::new());
        }
        let node = tree_format::decode_node_for(upload.bytes(), true, 262144, TreeUse::Ordinary)
            .map_err(|_| {
                StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {
                    rule_id: "STORE-33",
                }))
            })?;
        let mut requirements = Vec::new();
        if let NodeItems::Leaf(items) = node.items {
            for item in items {
                let mut pending = vec![&item.entry];
                while let Some(entry) = pending.pop() {
                    match &entry.kind {
                        EntryKind::File {
                            size,
                            content: ContentRef::Inline(hash),
                            ..
                        } => {
                            requirements.push(ChunkRequirement {
                                identity: TERRANE_V1
                                    .from_digest(IdentityKind::Chunk, hash)
                                    .map_err(|_| crate::guard::invalid())?,
                                declared_plaintext_len: usize::try_from(*size)
                                    .map_err(|_| crate::guard::invalid())?,
                                position: ChunkPosition::Final,
                                missing_rule_id: "STORE-33",
                            });
                        }
                        EntryKind::Conflict { candidates, base } => {
                            pending.extend(candidates);
                            if let Some(Some(base)) = base {
                                pending.push(base);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(requirements)
    }
}

/// Names the actual native backend using only finite observation/fault adapters.
pub(super) type Bucket<C> = FileBucket<ProbeFs, C, Validator>;

/// Keeps genuine configured Original controls independent of offered metadata.
pub(super) struct Fixture<C: Clock + BucketBinding = TokioClock> {
    /// The production repository, initialized through its closed native factory.
    pub(super) repository: Repository<Bucket<C>, C, ProbeFs>,
    /// The real filesystem adapter and finite test instrumentation.
    pub(super) fs: ProbeFs,
    /// The fixed configured validator and its actual call observations.
    pub(super) validator: Validator,
    /// The actual private Original directory chosen before any candidate exists.
    pub(super) original: PathBuf,
}

impl Fixture {
    /// Initializes ordinary native storage with the existing production Tokio clock.
    ///
    /// # Errors
    /// Preserves real bucket, Original, control, codec and configuration failures.
    ///
    /// # Panics
    /// Propagates the actual independent configuration fixture's setup assertions.
    pub(super) async fn new() -> TestResult<Self> {
        Self::with_clock(TokioClock).await
    }
}

impl<C: Clock + BucketBinding + Clone + Sync + 'static> Fixture<C> {
    /// Installs the independently configured clock before native authority initialization.
    ///
    /// # Errors
    /// Preserves actual protected directory, bucket activation and Original factory failures.
    ///
    /// # Panics
    /// Propagates the existing independently configured fixture's setup assertions.
    pub(super) async fn with_clock(clock: C) -> TestResult<Self> {
        let seed = crate::ref_advance::tests::raw_fixture().await;
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-meta-batch-{suffix}"));
        let original = root.with_file_name(format!("terrane-meta-batch-{suffix}-original"));
        TokioLocalFs.create_dir_new(&original).await?;
        TokioLocalFs
            .set_permissions_and_sync(&original, std::fs::Permissions::from_mode(0o700))
            .await?;
        let owner = TokioLocalFs.symlink_metadata(&original).await?.uid();
        let fs = ProbeFs::default();
        let validator = Validator::default();
        let bucket = FileBucket::open(
            crate::ref_advance::tests::config(root.clone()).await,
            fs.clone(),
            clock.clone(),
            validator.clone(),
        )
        .await?;
        let guard = Guard::new(
            bucket,
            clock.clone(),
            seed.guard().keys().to_vec(),
            seed.guard().config().clone(),
        );
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            fs.clone(),
        );
        let repository = Repository::initialize_native_retention(
            coordinator,
            &DomainNamespace {
                root,
                domain: "public".into(),
            },
            &original,
            owner,
        )
        .await?;
        fs.reset();
        Ok(Self {
            repository,
            fs,
            validator,
            original,
        })
    }

    /// Borrows the genuine configured bucket without constructing a held permit.
    pub(super) fn bucket(&self) -> &Bucket<C> {
        self.repository.coordinator().store()
    }

    /// Executes ordinary retained signing, staging and checked publication.
    ///
    /// # Errors
    /// Preserves the original repository/admission/current/Original/native refusal.
    pub(super) async fn publish(
        &self,
        request: CommitRequest,
    ) -> Result<RefRecord, crate::repository::Error> {
        let mut session = self
            .repository
            .begin(
                "refs/heads/_/main",
                &crate::ref_advance::tests::token(),
                "sdk",
            )
            .await?;
        self.repository.commit_request(&mut session, request).await
    }

    /// Decodes actual selected outputs under genuine namespace exclusion.
    ///
    /// # Errors
    /// Preserves selected resolution, exact shard identity/length, codec and I/O failures.
    ///
    /// # Panics
    /// Panics if a present selected generation omits its canonical manifest or Guard read.
    pub(super) async fn snapshot(&self) -> TestResult<Snapshot> {
        let holder = SingleHeld::acquire(self.bucket()).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        let caps = BucketCapabilities::decode(required(
            observed
                .logical()
                .get("CAPABILITIES")
                .and_then(Option::as_deref)
                .ok_or("selected CAP"),
        ))?;
        let mut rows = BTreeMap::new();
        let manifest = if let Some(generation) = caps.generation {
            let name = format!("objects/index/{generation}/MANIFEST");
            let manifest = GenerationManifest::decode(required(
                observed
                    .logical()
                    .get(&name)
                    .and_then(Option::as_deref)
                    .ok_or("selected manifest"),
            ))?;
            assert_eq!(manifest.generation, generation);
            for shard in &manifest.shards {
                let bytes = self
                    .fs
                    .read_nofollow(
                        &self
                            .bucket()
                            .root()
                            .join(format!("objects/index/{generation}/{}.idx", shard.shard)),
                    )
                    .await?;
                assert_eq!(bytes.len() as u64, shard.index_size);
                TERRANE_V1.verify(
                    &TERRANE_V1.from_digest(IdentityKind::Index, &shard.index_hash)?,
                    &bytes,
                )?;
                let decoded = MergedShard::decode(&bytes, generation, u8::try_from(shard.shard)?)?;
                rows.extend(
                    decoded
                        .entries()
                        .iter()
                        .map(|entry| (*entry.entry().hash(), entry.clone())),
                );
            }
            Some(manifest)
        } else {
            None
        };
        let backend = required(
            observed
                .physical_reads()
                .first()
                .and_then(|read| read.path().parent())
                .ok_or("backend registration parent"),
        )
        .to_owned();
        let guard = held
            .selected_guard_snapshot_record(&observed)
            .await?
            .map(|read| read.path().to_owned());
        observed.revalidate().await?;
        Ok(Snapshot {
            state: observed.state().clone(),
            manifest,
            rows,
            backend,
            guard,
        })
    }

    /// Verifies the actual final Candidate request, exact ref/log and selected slot.
    ///
    /// This reads already-installed immutable outputs as independent fixture oracles,
    /// never as a publication permit. A failed final acknowledgment may already have
    /// selected this record; no durable success or rollback is inferred.
    ///
    /// # Errors
    /// Preserves actual storage, canonical decoding and candidate-log association failures.
    ///
    /// # Panics
    /// Panics if the request ordinal, actual configured backend path, predecessor,
    /// signed root, exact ref change, candidate log or authoritative selection differs.
    pub(super) async fn assert_final_mutation(
        &self,
        expected_root: &Identity,
        previous: Option<&RefRecord>,
        backend: &Path,
    ) -> TestResult<RefRecord> {
        let observations = self.fs.observations();
        // Initialization installed the Guard before reset. There is exactly one
        // CheckedMutation in this ordinary publication, the final Candidate.
        assert_eq!(observations.mutations.len(), 1);
        let observed = &observations.mutations[0];
        let transaction = &observed.transaction;
        assert!(matches!(&transaction.proof, PublicationProof::Candidate(_)));
        let old = required(transaction.old.as_ref().ok_or("exact old mutation state"));
        assert_eq!(
            transaction.new.revision,
            required(
                old.revision
                    .checked_add(1)
                    .ok_or("actual revision successor")
            )
        );
        assert_eq!(observed.slot.revision, transaction.new.revision);
        assert_eq!(
            observed.path,
            backend.join(format!("publication/commits/{}", transaction.new.revision))
        );

        let prior_slot = required(
            observations
                .raw
                .last()
                .ok_or("last real immutable catalog slot"),
        );
        let prior_bytes = self.fs.read_nofollow(prior_slot).await?;
        let prior = PublicationCommit::decode(&prior_bytes)?;
        let prior_transaction_bytes = self
            .fs
            .read_nofollow(&backend.join(&prior.transaction_key))
            .await?;
        prior.check_transaction(
            &format!("publication/commits/{}", prior.revision),
            &prior_transaction_bytes,
        )?;
        let prior_transaction = PublicationTransaction::decode(&prior_transaction_bytes)?;
        assert_eq!(transaction.old.as_ref(), Some(&prior_transaction.new));
        let predecessor = required(
            transaction
                .predecessor
                .as_ref()
                .ok_or("candidate exact predecessor"),
        );
        assert_eq!(predecessor.revision, prior.revision);
        assert_eq!(predecessor.digest, *blake3::hash(&prior_bytes).as_bytes());
        assert_eq!(observed.slot.predecessor, Some(predecessor.digest));

        let change = required(
            transaction
                .changes
                .iter()
                .find(|change| change.key == "refs/heads/_/main:record")
                .ok_or("actual main ref transition"),
        );
        let selected_old = match old
            .branches
            .iter()
            .find(|row| row.name == "refs/heads/_/main")
            .map(|row| &row.selection)
        {
            Some(CommittedSelection::Selected(record)) => Some(record.as_ref()),
            Some(CommittedSelection::Never) | None => None,
            Some(CommittedSelection::Unknown) => {
                panic!("ordinary fixture retained unknown main history")
            }
        };
        assert_eq!(selected_old, previous);
        let expected = change
            .expected
            .as_deref()
            .map(RefRecord::decode)
            .transpose()?;
        assert_eq!(expected.as_ref(), previous);
        let record =
            RefRecord::decode(required(change.new.as_deref().ok_or("new exact main ref")))?;
        RefRecord::validate_successor(previous, &record)?;
        let branch = required(
            transaction
                .new
                .branches
                .iter()
                .find(|row| row.name == "refs/heads/_/main")
                .ok_or("new selected main history"),
        );
        assert_eq!(
            branch.selection,
            CommittedSelection::Selected(record.clone().into())
        );
        let candidate = required(
            record
                .candidate_id
                .as_ref()
                .ok_or("actual fresh candidate selector"),
        );
        let key = terrane_core::bucket::BucketKey::reflog_candidate(
            "refs/heads/_/main",
            record.seq,
            candidate,
        )?;
        let log = RefLogRecord::decode(
            &self
                .fs
                .read_nofollow(&self.bucket().root().join(key.as_str()))
                .await?,
        )?;
        log.validate_candidate(previous, &record)?;
        assert_eq!(log.record, record);
        assert_eq!(log.selected_previous()?, previous);
        let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &record.commit)?;
        let commit = Commit::decode(&self.bucket().get(&identity, None).await?)?;
        assert_eq!(commit.tree, expected_root.terrane_v1_digest()?);
        assert_eq!(
            commit.parents,
            previous
                .map(|record| vec![record.commit])
                .unwrap_or_default()
        );
        assert_eq!(
            commit
                .profile_pair
                .commit_context
                .as_ref()
                .map(|context| context.reference()),
            Some("refs/heads/_/main")
        );

        let selected = self.snapshot().await?;
        assert_eq!(selected.state, transaction.new);
        assert_eq!(
            self.bucket().ref_get("refs/heads/_/main").await?,
            Some(record.clone())
        );
        Ok(record)
    }

    /// Verifies actual selected rows, one shared pair and each real creator incarnation.
    ///
    /// # Errors
    /// Preserves canonical decoding, full body identity verification and real native I/O errors.
    ///
    /// # Panics
    /// Panics if selected members, inventory or actual protected creator evidence differ.
    pub(super) async fn assert_pair(&self, members: &[(Identity, Vec<u8>)]) -> TestResult {
        let snapshot = self.snapshot().await?;
        let first = required(members.first().ok_or("nonempty member oracle"));
        let row = required(
            snapshot
                .rows
                .get(&first.0.terrane_v1_digest()?)
                .ok_or("selected member"),
        );
        let pack = row.pack();
        let manifest = required(snapshot.manifest.as_ref().ok_or("selected manifest"));
        let inventory = required(
            manifest
                .inventory
                .as_ref()
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|entry| entry.pack_id == *pack.as_bytes())
                })
                .ok_or("selected pair inventory"),
        );
        let body = self
            .fs
            .read_nofollow(&self.bucket().root().join(pack.pack_key()))
            .await?;
        let index = self
            .fs
            .read_nofollow(&self.bucket().root().join(pack.index_key()))
            .await?;
        assert_eq!(body.len() as u64, inventory.pack_size);
        assert_eq!(index.len() as u64, inventory.index_size);
        TERRANE_V1.verify(
            &TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash)?,
            &body,
        )?;
        TERRANE_V1.verify(
            &TERRANE_V1.from_digest(IdentityKind::Index, &inventory.index_hash)?,
            &index,
        )?;
        let reader = PackReader::open(&body)?;
        reader.check_index_object(&index)?;
        assert_eq!(reader.entries().len(), members.len());
        for (identity, expected) in members {
            let hash = identity.terrane_v1_digest()?;
            let actual = required(snapshot.rows.get(&hash).ok_or("selected member"));
            assert_eq!(actual.pack(), pack);
            assert_eq!(actual.state(), RecordState::Live);
            let indexed = required(
                reader
                    .entries()
                    .iter()
                    .find(|entry| entry.hash() == &hash)
                    .ok_or("embedded member"),
            );
            assert_eq!(actual.entry(), indexed);
            assert_eq!(
                reader.read(indexed.kind(), &hash, &RawBodyDecoder)?,
                *expected
            );
            assert_eq!(self.bucket().get(identity, None).await?, *expected);
        }
        for (key, binding) in [
            (
                pack.pack_key(),
                ArtifactBinding::Pack {
                    digest: inventory.pack_hash,
                    size: inventory.pack_size,
                },
            ),
            (
                pack.index_key(),
                ArtifactBinding::Index {
                    digest: inventory.index_hash,
                    size: inventory.index_size,
                },
            ),
        ] {
            let suffix: String = blake3::hash(key.as_bytes())
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let path = snapshot.backend.join(format!(".terrane-creation/{suffix}"));
            let journal = CreationJournal::decode(&self.fs.read_nofollow(&path).await?)?;
            assert_eq!(journal.key, key);
            assert!(
                matches!(&journal.state, JournalState::Committed { binding: actual, file_identity } if *actual == binding && !file_identity.is_empty())
            );
            let observations = self.fs.observations();
            let pending = required(
                observations
                    .pending
                    .iter()
                    .find(|(_, pending)| pending.key == key)
                    .ok_or("actual synchronized Pending"),
            );
            assert_eq!(pending.1.nonce, journal.nonce);
            assert!(
                observations
                    .committed
                    .iter()
                    .any(|(_, committed)| *committed == journal)
            );
        }
        assert!(
            self.fs
                .observations()
                .entropy_lengths
                .iter()
                .any(|length| *length == 16)
        );
        Ok(())
    }
}

/// Contains selected observation data only; it confers no authority.
#[derive(Clone, Debug)]
pub(super) struct Snapshot {
    /// The actual selected whole state before or after the tested transition.
    pub(super) state: PublicationState,
    /// The actual selected complete generation manifest.
    pub(super) manifest: Option<GenerationManifest>,
    /// Independently verified actual merged rows.
    pub(super) rows: BTreeMap<Digest, MergedEntry>,
    /// The actual configured backend directory from its protected registration read.
    pub(super) backend: PathBuf,
    /// The actual selected protected Guard record, when already installed.
    pub(super) guard: Option<PathBuf>,
}

/// Builds a distinct canonical public empty Node using an independent literal ACL.
///
/// # Errors
/// Preserves the pure canonical tree/identity failures.
///
/// # Panics
/// Panics if a successfully built canonical empty tree contains no root Node.
pub(super) fn node(verbs: u8) -> TestResult<(Identity, Vec<u8>)> {
    let mut acl = vec![0x81, 0x82, 0x66];
    acl.extend_from_slice(b"writer");
    terrane_core::cbor::write_uint(&mut acl, u64::from(verbs));
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
    let bytes = required(tree.nodes().next().ok_or("empty root node"))
        .encoded()
        .to_vec();
    Ok((TERRANE_V1.calculate(IdentityKind::Node, &bytes)?, bytes))
}

/// Offers multiple actual canonical Meta members to the unchanged signed writer.
///
/// # Errors
/// Preserves pure canonical metadata and identity failures.
///
/// # Panics
/// Propagates the fixed signed-request helper assertion and canonical root assertion.
pub(super) fn request(
    parents: Vec<Digest>,
    extras: &[u8],
) -> TestResult<(CommitRequest, Vec<(Identity, Vec<u8>)>)> {
    let mut request = crate::ref_advance::tests::request(parents);
    let root = node(31)?;
    request.commit.tree = root.0.terrane_v1_digest()?;
    let mut members = vec![root];
    for verbs in extras {
        members.push(node(*verbs)?);
    }
    request.uploads = members
        .iter()
        .map(|(_, bytes)| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        })
        .collect();
    Ok((request, members))
}

/// Replaces a real protected pathname with byte-identical data and a new inode.
///
/// # Errors
/// Preserves real file creation, mode, write and rename failures.
///
/// # Panics
/// Panics if the original mode/incarnation or replacement bytes are unexpected.
pub(super) fn replace(path: &Path) -> TestResult {
    let before = std::fs::symlink_metadata(path)?;
    let bytes = std::fs::read(path)?;
    let replacement = path.with_extension("meta-batch-replacement");
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&replacement)?;
    std::fs::set_permissions(
        &replacement,
        std::fs::Permissions::from_mode(before.mode() & 0o777),
    )?;
    drop(file);
    std::fs::write(&replacement, &bytes)?;
    std::fs::rename(&replacement, path)?;
    let after = std::fs::symlink_metadata(path)?;
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(std::fs::read(path)?, bytes);
    Ok(())
}

/// Keeps the same actual manually injected worker clock for expiry-only cases.
pub(super) fn expiry_clock() -> TestClock {
    TestClock::new(2_000_000_000)
}

/// Installs exact canonical ordinary metadata through the genuine backend.
///
/// # Errors
/// Preserves registered schema, dependency, identity and native durability refusal.
///
/// # Panics
/// Panics if actual native admission returns another identity.
pub(super) async fn put<C: Clock + BucketBinding + Sync>(
    bucket: &Bucket<C>,
    body: &(Identity, Vec<u8>),
) -> TestResult {
    assert_eq!(
        bucket
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                &body.1
            )?))
            .await?,
        body.0
    );
    Ok(())
}

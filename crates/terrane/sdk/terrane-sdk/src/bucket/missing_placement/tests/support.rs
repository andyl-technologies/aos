//! Creates genuine signed native placements and independent physical/selected oracles.

use super::fs::ProbeFs;
use crate::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    domain::DomainNamespace,
    guard::{Guard, StagedUpload, TreeEvidence},
    pack::{Codec, EntryKind, MergedEntry, RecordState},
    ref_advance::{CommitTiming, Coordinator},
    repository::{PreparedTree, Repository},
    store::{
        ContentStore, ContentUpload, ContentValidator, CorruptSubject, LocalFs, MetaUpload,
        StoreErrorKind, StoreFailure, TokioClock, TokioLocalFs,
    },
};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt::Debug,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use terrane_format::{
    bucket::{PackExclusion, PackInventoryEntry},
    gc::publication::PublicationState,
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    refs::Commit,
    tree_format::{self, TreeUse},
};

/// Names a native bucket using only a finite observing adapter around TokioLocalFs.
pub(super) type Bucket = FileBucket<ProbeFs, TokioClock, Validator>;

/// Names the genuine native Repository whose Original records remain independently configured.
pub(super) type NativeRepository = Repository<Bucket, TokioClock, ProbeFs>;

/// Preserves typed setup errors instead of replacing their subjects with strings.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Requires setup or synchronization success as an explicit fixture assertion.
///
/// # Panics
/// Panics with the original diagnostic when the supplied result is an error.
pub(super) fn required<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("fixture operation failed: {error:?}"),
    }
}

/// Extracts the actual typed refusal from a supposed successful operation.
///
/// # Panics
/// Panics if the operation unexpectedly succeeds.
pub(super) fn rejected<T: Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("unexpected success: {value:?}"),
        Err(error) => error,
    }
}

/// Validates actual metadata with its registered canonical format and role parsers.
#[derive(Clone)]
pub(super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let valid = match upload.kind() {
            IdentityKind::Node => [TreeUse::Ordinary, TreeUse::Index]
                .into_iter()
                .any(|usage| {
                    tree_format::decode_node_for(upload.bytes(), true, 262144, usage).is_ok()
                }),
            IdentityKind::Commit => Commit::decode(upload.bytes()).is_ok(),
            IdentityKind::Attribute => {
                terrane_format::derived::AttrRecord::decode(upload.bytes()).is_ok()
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(crate::guard::invalid())
        }
    }
}

/// Retains independent expected data from a genuinely signed, selected ordinary Node.
pub(super) struct Fixture {
    /// Actual configured native Repository, retaining its genuine Original controls.
    pub(super) repository: NativeRepository,
    /// Shared adapter used solely for finite faults and observation.
    pub(super) fs: ProbeFs,
    /// Actual signed Commit selected by the ordinary guarded writer.
    pub(super) commit: Digest,
    /// Actual canonical root Node identity bound by that signed Commit.
    pub(super) identity: Identity,
    /// Verified original Node bytes retained before any storage fault.
    pub(super) bytes: Vec<u8>,
    /// Actual original live row, independent of the replacement under test.
    pub(super) row: MergedEntry,
    /// Original canonical pack path.
    pub(super) pack: PathBuf,
    /// Original canonical detached-index path.
    pub(super) index: PathBuf,
    /// Actual protected backend control directory selected by the native factory.
    pub(super) backend: PathBuf,
    /// Actual independently configured Original control directory.
    pub(super) original: PathBuf,
}

/// Captures selected state and complete row data without claiming decoded authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    /// Genuine held selected state, including exact loss/source/Guard/burn-owner data.
    pub(super) state: PublicationState,
    /// Complete logical selected values, including absence.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Complete independently decoded merged rows.
    pub(super) rows: BTreeMap<Digest, MergedEntry>,
    /// Complete selected container inventory, including legacy unknown.
    pub(super) inventory: Option<Vec<PackInventoryEntry>>,
    /// Complete active physical exclusions, including legacy unknown.
    pub(super) exclusions: Option<Vec<PackExclusion>>,
    /// Complete permanent burns, including legacy unknown.
    pub(super) burns: Option<Vec<[u8; 16]>>,
    /// Original control file names/bytes observed independently of backend selection.
    pub(super) original_files: BTreeMap<PathBuf, Vec<u8>>,
    /// Exact backend registration body and descriptor identity/protection.
    pub(super) registration: (Vec<u8>, u64, u64, u32, u32),
}

impl Fixture {
    /// Initializes real retention and publishes a signed ordinary tree through Repository.
    ///
    /// # Errors
    /// Preserves entropy, canonical staging, storage, Original, admission and publication errors.
    /// # Panics
    /// Propagates shared seed/request/token assertions and independent fixture invariants.
    pub(super) async fn new() -> TestResult<Self> {
        let seed = crate::ref_advance::tests::fixture().await;
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("terrane-missing-placement-{suffix}"));
        let original = root.with_file_name(format!("terrane-missing-placement-{suffix}-original"));
        TokioLocalFs.create_dir_new(&original).await?;
        TokioLocalFs
            .set_permissions_and_sync(&original, std::fs::Permissions::from_mode(0o700))
            .await?;
        let owner = TokioLocalFs.symlink_metadata(&original).await?.uid();
        let fs = ProbeFs::default();
        let config = seed.guard().config().clone();
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: root.clone(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                chunk_profile_name: config.chunk_profile_name.clone(),
                chunk_profile: (*config.chunk_profile).clone(),
                locality: config.home.clone(),
            },
            fs.clone(),
            TokioClock,
            Validator,
        )
        .await?;
        let guard = Guard::new(bucket, TokioClock, seed.guard().keys().to_vec(), config);
        let repository = Repository::initialize_native_retention(
            Coordinator::new(
                guard,
                CommitTiming::new(
                    Duration::from_secs(30),
                    Duration::from_secs(60),
                    Duration::from_secs(10),
                )?,
                fs.clone(),
            ),
            &DomainNamespace {
                root: root.clone(),
                domain: "public".into(),
            },
            &original,
            owner,
        )
        .await?;
        let token = crate::ref_advance::tests::token();
        let mut session = repository.begin("refs/heads/_/main", &token, "sdk").await?;
        let mut request = crate::ref_advance::tests::request_file(
            Vec::new(),
            b"genuine missing-placement selected file",
        );
        // Keep the physical-loss target independent of immutable signed authority.
        // Ordinary admission validates these genuine proposal bytes before publication.
        for upload in &request.uploads {
            repository
                .coordinator()
                .guard()
                .store()
                .put(upload.as_upload()?)
                .await?;
        }

        let evidence = TreeEvidence::load_tree(
            repository.coordinator().guard().store(),
            request.commit.tree,
            &request.uploads,
            262144,
        )
        .await?;
        let (tree, prepared_nodes) = {
            let ordinary_tree = evidence.tree(evidence.root, 262144)?;
            let prepared_nodes = ordinary_tree
                .nodes()
                .map(|node| node.encoded().to_vec())
                .collect::<Vec<_>>();
            let tree = PreparedTree::from_tree(&ordinary_tree)?;
            (tree, prepared_nodes)
        };

        // PreparedTree owns these exact Node uploads; retain every other proposal input.
        request.uploads.retain(|upload| match upload {
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } => !prepared_nodes.contains(bytes),
            _ => true,
        });
        let record = repository.commit(&mut session, tree, request).await?;
        let history = repository
            .coordinator()
            .guard()
            .verified_history(record.commit)
            .await?;
        let verified = required(
            history
                .commit(&record.commit)
                .ok_or("signed candidate absent from history"),
        );
        let identity = TERRANE_V1.from_digest(IdentityKind::Node, &verified.commit().tree)?;
        let bucket = repository.coordinator().guard().store();
        let bytes = bucket.get(&identity, None).await?;
        assert_eq!(TERRANE_V1.calculate(IdentityKind::Node, &bytes)?, identity);
        let catalog = bucket.catalog().await?;
        let row = bucket.location(&catalog, &identity)?.clone();
        assert_eq!(row.state(), RecordState::Live);
        let commit_identity = TERRANE_V1.from_digest(IdentityKind::Commit, &record.commit)?;
        let commit_row = bucket.location(&catalog, &commit_identity)?;
        assert_ne!(row.pack(), commit_row.pack());
        let pack = root.join(row.pack().pack_key());
        let index = root.join(row.pack().index_key());
        let backend = crate::bucket::tests::control_path(&root);
        fs.reset();
        let fixture = Self {
            repository,
            fs,
            commit: record.commit,
            identity,
            bytes,
            row,
            pack,
            index,
            backend,
            original,
        };
        fixture.assert_original_current().await?;
        fixture.fs.reset();
        Ok(fixture)
    }

    /// Borrows the actual configured native content store.
    pub(super) fn bucket(&self) -> &Bucket {
        self.repository.coordinator().guard().store()
    }

    /// Offers exactly the verified original Node through ordinary content admission.
    ///
    /// # Errors
    /// Preserves the original typed validation, physical-loss, creation or publication failure.
    pub(super) async fn offer(&self) -> Result<Identity, StoreFailure> {
        self.bucket()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Node,
                &self.bytes,
            )?))
            .await
    }

    /// Independently completes signed Original history and current scoped read authority.
    ///
    /// # Errors
    /// Preserves real Original, signature, current policy/trust and addressed-content errors.
    /// # Panics
    /// Panics when the selected signed identity or exact old root binding changed.
    pub(super) async fn assert_original_current(&self) -> TestResult {
        let guard = self.repository.coordinator().guard();
        let history = guard.verified_history(self.commit).await?;
        let commit = required(
            history
                .commit(&self.commit)
                .ok_or("signed Original history lost"),
        );
        assert_eq!(commit.commit().tree, self.identity.terrane_v1_digest()?);
        let token = crate::ref_advance::tests::token();
        let current = guard
            .read_snapshot("refs/heads/_/main", &token, b"/", "sdk")
            .await?;
        assert_eq!(current.commit.identity(), self.commit);
        assert_eq!(
            current.commit.commit().tree,
            self.identity.terrane_v1_digest()?
        );
        Ok(())
    }

    /// Captures complete actual selected evidence while holding the genuine backend exclusion.
    ///
    /// # Errors
    /// Preserves selected/catalog verification, filesystem and native-retention failures.
    pub(super) async fn snapshot(&self) -> TestResult<Snapshot> {
        let holder = crate::bucket::held::SingleHeld::acquire(self.bucket()).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        let catalog = self.bucket().catalog().await?;
        observed.revalidate().await?;
        let rows = catalog
            .shards
            .iter()
            .flat_map(|shard| shard.entries())
            .map(|row| (*row.entry().hash(), row.clone()))
            .collect();
        let path = self.backend.join("backend-registration.cbor");
        let metadata = std::fs::symlink_metadata(&path)?;
        let registration = (
            std::fs::read(&path)?,
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode(),
        );
        Ok(Snapshot {
            state: observed.state().clone(),
            logical: observed.logical().clone(),
            rows,
            inventory: catalog.inventory,
            exclusions: catalog.exclusions,
            burns: catalog.burns,
            original_files: files(&self.original)?,
            registration,
        })
    }

    /// Independently verifies the exact replacement row, loss transition and signed Original binding.
    ///
    /// # Errors
    /// Preserves selected, actual body and full signed-history verification errors.
    /// # Panics
    /// Panics on any changed unrelated row/control, wrong new placement or missing creator witness.
    pub(super) async fn assert_replaced(&self, before: &Snapshot) -> TestResult {
        let after = self.snapshot().await?;
        let hash = self.identity.terrane_v1_digest()?;
        let row = required(after.rows.get(&hash).ok_or("replacement row absent"));
        assert_eq!(row.state(), RecordState::Live);
        assert_ne!(row.pack(), self.row.pack());
        assert_eq!(*row.entry().hash(), hash);
        assert_eq!(row.entry().kind(), EntryKind::Node);
        assert_eq!(row.entry().codec(), Codec::Raw);
        assert_eq!(row.entry().offset(), crate::pack::HEADER_SIZE as u64);
        assert_eq!(row.entry().body_len(), self.bytes.len() as u32);
        assert_eq!(row.entry().plaintext_len(), self.bytes.len() as u32);
        for (identity, old) in &before.rows {
            if identity != &hash {
                assert_eq!(after.rows.get(identity), Some(old));
            }
        }
        let old_inventory = required(before.inventory.as_ref().ok_or("modern inventory absent"));
        let inventory = required(
            after
                .inventory
                .as_ref()
                .ok_or("replacement inventory absent"),
        );
        assert_eq!(inventory.len(), old_inventory.len() + 1);
        for old in old_inventory {
            assert!(inventory.contains(old));
        }
        assert_eq!(after.exclusions, before.exclusions);
        assert_eq!(after.burns, before.burns);
        assert_eq!(after.state.binding, before.state.binding);
        assert_eq!(after.state.guard, before.state.guard);
        assert_eq!(after.state.branches, before.state.branches);
        assert_eq!(after.state.burn_owners, before.state.burn_owners);
        assert!(
            !before.state.sources.is_empty(),
            "fixture never installed genuine source lineage"
        );
        assert!(after.state.sources.is_empty());
        assert_eq!(
            after.state.loss_generation,
            before
                .state
                .loss_generation
                .checked_add(1)
                .ok_or("loss overflow")?
        );
        for (key, value) in &before.logical {
            if key != "CAPABILITIES" {
                assert_eq!(
                    after.logical.get(key),
                    Some(value),
                    "changed old logical key {key}"
                );
            }
        }
        assert_eq!(after.original_files, before.original_files);
        assert_eq!(after.registration, before.registration);
        assert_eq!(self.bucket().get(&self.identity, None).await?, self.bytes);
        assert_eq!(
            self.bucket()
                .has(std::slice::from_ref(&self.identity))
                .await?,
            [true]
        );
        let history = self
            .repository
            .coordinator()
            .guard()
            .verified_history(self.commit)
            .await?;
        let old = required(
            history
                .commit(&self.commit)
                .ok_or("old signed history lost"),
        );
        assert_eq!(old.commit().tree, hash);
        self.assert_original_current().await?;
        let trace = self.fs.observations();
        assert_eq!(trace.raw, 1);
        let successor = before
            .state
            .revision
            .checked_add(1)
            .ok_or("revision overflow")?;
        assert_eq!(after.state.revision, successor);
        assert_eq!(
            trace.raw_slots,
            [self
                .backend
                .join(format!("publication/commits/{successor}"))]
        );
        assert_eq!(trace.pending.len(), 2);
        assert_eq!(trace.committed.len(), 2);
        assert_eq!(trace.artifact_writes, 2);
        assert_ne!(trace.pending[0].1.nonce, trace.pending[1].1.nonce);
        assert!(
            trace
                .entropy_lengths
                .iter()
                .filter(|length| **length == 32)
                .count()
                >= 2
        );
        for (path, pending) in &trace.pending {
            let committed = required(
                trace
                    .committed
                    .iter()
                    .find(|(other, _)| other == path)
                    .ok_or("missing actual Committed receipt"),
            );
            assert_eq!(committed.1.nonce, pending.nonce);
            assert_eq!(committed.1.key, pending.key);
            let path = self.bucket().root().join(&pending.key);
            let body = std::fs::read(&path)?;
            let kind = if pending.key == row.pack().pack_key() {
                IdentityKind::Pack
            } else {
                IdentityKind::Index
            };
            let digest = TERRANE_V1.calculate(kind, &body)?.terrane_v1_digest()?;
            let binding = match kind {
                IdentityKind::Pack => terrane_format::gc::ArtifactBinding::Pack {
                    digest,
                    size: body.len() as u64,
                },
                IdentityKind::Index => terrane_format::gc::ArtifactBinding::Index {
                    digest,
                    size: body.len() as u64,
                },
                _ => unreachable!("two canonical container kinds"),
            };
            assert!(matches!(&committed.1.state,
                terrane_format::gc::JournalState::Committed { binding: actual, file_identity }
                if actual == &binding && !file_identity.is_empty()));
            assert!(pending.key == row.pack().pack_key() || pending.key == row.pack().index_key());
        }
        Ok(())
    }
}

/// Reads actual file names and bytes without treating them as authority or a metadata inventory.
///
/// # Errors
/// Preserves filesystem read/list errors and rejects symlink/nonregular descendants.
pub(super) fn files(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in std::fs::read_dir(path)? {
            let path = entry?.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                visit(root, &path, output)?;
            } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                output.insert(path.strip_prefix(root)?.to_owned(), std::fs::read(&path)?);
            } else {
                return Err("fixture contains unsafe descendant".into());
            }
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

/// Asserts an exact identity-corruption refusal and no creator/catalog request.
///
/// # Panics
/// Panics on a different subject/category or any unexpected creation/Raw effect.
pub(super) fn assert_identity_corrupt(error: &StoreFailure, identity: &Identity, fs: &ProbeFs) {
    assert!(
        matches!(error.kind(), StoreErrorKind::Corrupt(CorruptSubject::Identity(actual)) if actual == identity),
        "wrong refusal: {error:?}"
    );
    let trace = fs.observations();
    assert_eq!(trace.raw, 0);
    assert!(trace.pending.is_empty());
    assert!(trace.committed.is_empty());
    assert_eq!(trace.artifact_writes, 0);
}

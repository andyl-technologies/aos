//! Uses real metadata admission and independently modeled replay closures.
//!
//! Signed source history lives in a separate Repository. Cache damage therefore
//! tests ordinary advisory loss without turning an Original or current-policy
//! refusal into a successful cache miss. Delegated observations count actual
//! upload attempts and read the independently expected closure before Memo put.

use super::{TestResult, wire};
use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::derivation::{
    Selection,
    persistence::{PersistedOutcome, PersistenceMode, replay_and_persist},
};
use crate::domain::DomainNamespace;
use crate::guard::{
    AuthoringNamespaceProfile, AuthorizedSnapshot, Guard, GuardConfig, RecordedNamespaceProfile,
    RecordedNamespaceProfiles, StagedUpload,
};
use crate::pack::{EntryKind, PackReader};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{
    LocalAuthority, LocalAuthorityParameters, LocalRepositoryLocation, MetadataValidator,
    Repository,
};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ChunkPosition, ChunkUpload, ContentStore,
    ContentUpload, IdentityPrefix, LocalFs, MetaUpload, RefStore, StoreErrorKind, StoreFailure,
    TokioClock, TokioLocalFs,
};
use terrane_format::auth::{Authority, Grant, Verbs};
use terrane_format::chunking::ChunkProfile;
use terrane_format::derivation::{cache::ReplayMode, evaluation::EvaluationInputs};
use terrane_format::identity::{Digest, Identity, IdentityError, IdentityKind, TERRANE_V1};
use terrane_format::indexing::carrier::SemanticContext;
use terrane_format::properties::semantics::{RecordedContext, associations::RecordedAssociation};
use terrane_format::provenance::{Preset, Selector};
use terrane_format::refs::{
    Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance, RefRecord,
};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Entry, EntryKind as TreeEntryKind, LeafItem, Property, TreeUse};

/// Names a native cache using the production schema and content validator.
pub(super) type Bucket = FileBucket<TokioLocalFs, TokioClock, MetadataValidator>;

/// Names an actual native Repository with protected Original retention.
pub(super) type SourceRepository = Repository<Bucket, TokioClock, TokioLocalFs>;

/// Names the separately configured historical Guard installed by native reopening.
pub(super) type SourceGuard = Guard<Bucket, TokioClock>;

/// Holds configuration needed to reopen the actual admitted cache.
pub(super) struct Cache {
    /// Real backend for every upload, lookup and physical artifact check.
    pub bucket: Bucket,
    config: FileBucketConfig,
}

impl Cache {
    /// Opens a fresh private cache through the actual backend factory.
    ///
    /// # Errors
    /// Preserves entropy, native open and secure directory failures.
    pub async fn new() -> TestResult<Self> {
        let parent = private_parent("memo-cache").await?;
        let config = FileBucketConfig {
            root: parent.join("bucket"),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: TokioLocalFs.metadata(&parent).await?.uid(),
                control: None,
            }),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: ChunkProfile::cdc_1m([0; 32]),
            locality: Locality::default(),
        };
        let bucket = open(&config).await?;
        Ok(Self { bucket, config })
    }

    /// Reopens the same immutable native objects without constructing any cache row.
    ///
    /// # Errors
    /// Preserves the backend's original recovery and physical verification failures.
    pub async fn reopen(&self) -> TestResult<Bucket> {
        open(&self.config).await
    }

    /// Stores the independently modeled operands and actual inline object.
    ///
    /// # Errors
    /// Preserves actual chunk and metadata admission failures.
    ///
    /// # Panics
    /// Panics if independently calculated content identities disagree.
    pub async fn operands(&self, model: &wire::Fixture) -> TestResult {
        let encoded = [0, b'x'];
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, b"x")?;
        let actual = self
            .bucket
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: &encoded,
                identity: &identity,
                declared_plaintext_len: 1,
                position: ChunkPosition::Final,
                profile: &self.config.chunk_profile,
            }))
            .await?;
        assert_eq!(actual, identity);
        for (root, bytes) in &model.source {
            assert_eq!(
                put(&self.bucket, IdentityKind::Node, bytes)
                    .await?
                    .terrane_v1_digest()?,
                *root
            );
            assert_eq!(
                self.bucket
                    .get(&id(IdentityKind::Node, *root)?, None)
                    .await?,
                *bytes
            );
        }
        Ok(())
    }

    /// Removes or damages the actual immutable pack that contains one admitted item.
    ///
    /// The pack's own index, rather than its filename, identifies the item. No
    /// replacement catalog, detached index or pack body is manufactured.
    ///
    /// # Errors
    /// Preserves artifact enumeration, pack parsing and native write failures.
    ///
    /// # Panics
    /// Panics if the admitted item cannot be found in an actual native pack.
    pub async fn damage(&self, kind: EntryKind, digest: Digest, corrupt: bool) -> TestResult {
        let mut directories = tokio::fs::read_dir(self.bucket.root().join("objects/pack")).await?;
        while let Some(directory) = directories.next_entry().await? {
            if !directory.file_type().await?.is_dir() {
                continue;
            }
            let mut files = tokio::fs::read_dir(directory.path()).await?;
            while let Some(file) = files.next_entry().await? {
                if file
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "pack")
                {
                    continue;
                }
                let bytes = tokio::fs::read(file.path()).await?;
                let pack = PackReader::open(&bytes)?;
                if pack
                    .entries()
                    .iter()
                    .any(|entry| entry.kind() == kind && entry.hash() == &digest)
                {
                    if corrupt {
                        let mut damaged = bytes;
                        damaged[0] ^= 1;
                        tokio::fs::write(file.path(), damaged).await?;
                    } else {
                        tokio::fs::remove_file(file.path()).await?;
                    }
                    return Ok(());
                }
            }
        }
        panic!("admitted item absent from actual packs")
    }

    /// Changes only the advisory cache root's security state for a real put refusal.
    ///
    /// # Errors
    /// Preserves descriptor-based permissions and durability failures.
    pub async fn permissions(&self, mode: u32) -> TestResult {
        TokioLocalFs
            .set_permissions_and_sync(self.bucket.root(), std::fs::Permissions::from_mode(mode))
            .await?;
        Ok(())
    }
}

async fn open(config: &FileBucketConfig) -> TestResult<Bucket> {
    Ok(FileBucket::open(
        config.clone(),
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(config.chunk_profile.clone()),
    )
    .await?)
}

async fn private_parent(label: &str) -> TestResult<PathBuf> {
    let entropy = TokioLocalFs.random_bytes(16).await?;
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-{label}-{suffix}"));
    TokioLocalFs.create_dir_new(&parent).await?;
    TokioLocalFs
        .set_permissions_and_sync(&parent, std::fs::Permissions::from_mode(0o700))
        .await?;
    Ok(parent)
}

/// Calculates an actual native upload address under its explicit identity domain.
///
/// # Errors
/// Preserves metadata framing, schema, content and native durability errors.
pub(super) async fn put(
    bucket: &Bucket,
    kind: IdentityKind,
    bytes: &[u8],
) -> Result<Identity, StoreFailure> {
    bucket
        .put(ContentUpload::Meta(MetaUpload::new(kind, bytes)?))
        .await
}

/// Constructs an ordinary identity for an independently known digest.
///
/// # Errors
/// Preserves the registered identity profile's kind or digest refusal.
pub(super) fn id(kind: IdentityKind, digest: Digest) -> Result<Identity, IdentityError> {
    TERRANE_V1.from_digest(kind, &digest)
}

/// Rebinds the raw index fixture to a genuinely admitted one-byte Chunk.
///
/// Only equal-length address literals change. Rows, properties, profile and
/// expected P/G/route topology remain the independent raw fixture oracle; neither
/// replay nor the index builder supplies expected output.
///
/// # Errors
/// Preserves actual identity construction errors and refuses missing or cyclic
/// literal fixture address dependencies without inventing another address.
pub(super) fn native_model(mut model: wire::Fixture) -> TestResult<wire::Fixture> {
    let object = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"x")?
        .terrane_v1_digest()?;
    let mut pending: BTreeMap<_, _> = model
        .source
        .iter()
        .chain(&model.output)
        .map(|(root, bytes)| (*root, bytes.clone()))
        .collect();
    let mut addresses = BTreeMap::from([([7; 32], object)]);
    while !pending.is_empty() {
        let ready: Vec<_> = pending
            .iter()
            .filter(|(_, bytes)| {
                !pending
                    .keys()
                    .any(|root| contains(bytes, root) || contains(bytes, hex(root).as_bytes()))
            })
            .map(|(root, _)| *root)
            .collect();
        if ready.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "literal address cycle").into());
        }
        for root in ready {
            let original = pending.remove(&root).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing pending literal Node")
            })?;
            let bytes = remap(&original, &addresses);
            addresses.insert(root, wire::hash(b"terrane-node-v1", &bytes));
        }
    }
    let map = |nodes: BTreeMap<Digest, Vec<u8>>| -> TestResult<BTreeMap<Digest, Vec<u8>>> {
        nodes
            .into_iter()
            .map(|(root, bytes)| Ok((address(&addresses, &root)?, remap(&bytes, &addresses))))
            .collect()
    };
    model.source = map(model.source)?;
    model.output = map(model.output)?;
    model.overlay = model
        .overlay
        .into_iter()
        .map(|root| address(&addresses, &root))
        .collect::<TestResult<_>>()?;
    model.recipe = remap(&model.recipe, &addresses);
    model.first_operand = address(&addresses, &model.first_operand)?;
    model.root = address(&addresses, &model.root)?;
    Ok(model)
}

fn address(addresses: &BTreeMap<Digest, Digest>, root: &Digest) -> TestResult<Digest> {
    addresses.get(root).copied().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing literal Node address").into()
    })
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn hex(digest: &Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn remap(bytes: &[u8], addresses: &BTreeMap<Digest, Digest>) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    for (old, new) in addresses {
        for (from, to) in [
            (old.to_vec(), new.to_vec()),
            (hex(old).into_bytes(), hex(new).into_bytes()),
        ] {
            let mut cursor = 0;
            while cursor + from.len() <= bytes.len() {
                if bytes[cursor..cursor + from.len()] == from {
                    bytes[cursor..cursor + to.len()].copy_from_slice(&to);
                    cursor += from.len();
                } else {
                    cursor += 1;
                }
            }
        }
    }
    bytes
}

/// Delegates storage and independently observes complete closure before Memo admission.
pub(super) struct ObservedCache<'a> {
    /// Actual native backend; no operation outcome is synthesized.
    pub bucket: &'a Bucket,
    /// Independently framed complete expected output Nodes.
    pub expected: &'a BTreeMap<Digest, Vec<u8>>,
    attempts: Mutex<Vec<IdentityKind>>,
    refuse_after: Option<usize>,
}

impl<'a> ObservedCache<'a> {
    /// Installs fixture-local instrumentation around the actual backend.
    pub fn new(bucket: &'a Bucket, expected: &'a BTreeMap<Digest, Vec<u8>>) -> Self {
        Self {
            bucket,
            expected,
            attempts: Mutex::new(Vec::new()),
            refuse_after: None,
        }
    }

    /// Changes actual cache security before the next put after a known acknowledged prefix.
    ///
    /// The backend still executes its real admission/refusal path. This fixture
    /// handoff supplies no storage outcome, publication receipt or permission.
    pub fn refuse_after(
        bucket: &'a Bucket,
        expected: &'a BTreeMap<Digest, Vec<u8>>,
        acknowledged: usize,
    ) -> Self {
        Self {
            bucket,
            expected,
            attempts: Mutex::new(Vec::new()),
            refuse_after: Some(acknowledged),
        }
    }

    /// Returns only actual upload attempts since fixture construction.
    ///
    /// # Errors
    /// Preserves the observation mutex's poisoning diagnostic without recovery.
    pub fn attempts(&self) -> io::Result<Vec<IdentityKind>> {
        let attempts = self
            .attempts
            .lock()
            .map_err(|error| io::Error::other(format!("Memo observation mutex: {error}")))?;
        Ok(attempts.clone())
    }
}

impl CapabilityReport for ObservedCache<'_> {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for ObservedCache<'_> {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        let ContentUpload::Meta(meta) = &upload else {
            panic!("replay output is metadata")
        };
        let attempt = {
            let mut attempts = self.attempts.lock().map_err(|error| {
                observation_failure(io::Error::other(format!("Memo observation mutex: {error}")))
            })?;
            let attempt = attempts.len();
            attempts.push(meta.kind());
            attempt
        };
        if meta.kind() == IdentityKind::Memo {
            for (root, bytes) in self.expected {
                assert_eq!(
                    self.bucket
                        .get(
                            &id(IdentityKind::Node, *root).map_err(observation_failure)?,
                            None
                        )
                        .await?,
                    *bytes,
                    "complete independent closure must exist before Memo put"
                );
            }
        }
        if self.refuse_after == Some(attempt) {
            TokioLocalFs
                .set_permissions_and_sync(
                    self.bucket.root(),
                    std::fs::Permissions::from_mode(0o777),
                )
                .await
                .map_err(observation_failure)?;
        }
        self.bucket.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.bucket.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.bucket.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.bucket.list(prefix).await
    }
}

// The closed store trait carries actual observer/fixture I/O failures as
// availability errors with their original source. Backend outcomes are always
// delegated; this translation never acknowledges an upload or recovers poison.
fn observation_failure<E: std::error::Error + Send + Sync + 'static>(error: E) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}

/// Selects one adversarial immutable input defect without manufacturing evidence.
#[derive(Clone, Copy)]
pub(super) enum InputDefect {
    /// Preserves the actual complete factory result.
    None,
    /// Omits genuine side contexts rather than fabricating replacements.
    MissingTrust,
    /// Reverses genuine side contexts to test recorded side binding.
    ReversedTrust,
    /// Omits actual operand owners to test mandatory resolution.
    MissingTrees,
}

/// Supplies ordinary replay choices to the same genuine source caller path.
pub(super) struct CheckedReplay<'a> {
    /// Original encoded recipe remains distinct from all cache bytes.
    pub recipe: &'a [u8],
    /// Explicit Check or same-evaluator Rebuild choice.
    pub mode: ReplayMode,
    /// Explicit untrusted native cache association, if any.
    pub selection: Selection<'a>,
    /// Ordinary optional upload choice.
    pub persistence: PersistenceMode,
    /// Deliberately mismatched independently installed root input.
    pub wrong_root: bool,
    /// Deliberately unavailable or misordered mandatory evaluator inputs.
    pub defect: InputDefect,
}

/// Retains genuine native current authority, Original controls and signed versions.
pub(super) struct Source {
    /// Actual repository remains the only current publication owner.
    pub repository: SourceRepository,
    /// Actual local token and signing authority created by the native factory.
    pub authority: LocalAuthority,
    /// Independent configuration location for reopening protected retention.
    pub location: LocalRepositoryLocation,
    /// Actual base, ours and theirs signed selected records in publication order.
    pub records: [RefRecord; 3],
    /// Exact signed original roots; no offered pre-admission roots are substituted.
    pub roots: [Digest; 3],
    owner: u32,
    authoring: AuthoringNamespaceProfile,
}

impl Source {
    /// Publishes conflicting symlinks through normal admission and retained publication.
    ///
    /// # Errors
    /// Preserves full native initialization, source admission and publication errors.
    pub async fn new() -> TestResult<Self> {
        let parent = private_parent("memo-source").await?;
        let owner = TokioLocalFs.metadata(&parent).await?.uid();
        let location = LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        };
        let token_id = TokioLocalFs
            .random_bytes(16)
            .await?
            .try_into()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native token identifier entropy length",
                )
            })?;
        let authority = LocalAuthority::initialize(
            &TokioLocalFs,
            &location.bucket,
            &location.authority,
            LocalAuthorityParameters {
                owner_uid: owner,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "owner".into(),
                    kind: PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: u64::MAX,
                    not_before: None,
                    token_id,
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                    workload: None,
                },
            },
        )
        .await?;
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: location.bucket.clone(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: profile.clone(),
                locality: Locality::default(),
            },
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(profile.clone()),
        )
        .await?;
        // Choose actual candidate semantics BEFORE the first protected Guard.
        // Reopening below retains these exact inputs; it never reinterprets an
        // installed attr1 Guard as attr2 or manufactures historical authority.
        let authoring = AuthoringNamespaceProfile::new(3, 3, &[], 2)?;
        let guard = Guard::new_active(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            GuardConfig {
                store_name: "local".into(),
                private_domain: "private:owner".into(),
                home: Locality::default(),
                initial_acl: vec![("owner".into(), 31)],
                min_chunk_size: wire::MINIMUM,
                storage_domain: "private:owner".into(),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: Box::new(profile),
                policy_authority: Some("refs/heads/_/main".into()),
            },
        )
        .with_recorded_authoring(
            authoring.clone().context().clone(),
            authoring.clone().registries().attribute_revision,
        )?;
        let repository = Repository::initialize_native_retention(
            Coordinator::new(guard, timing()?, TokioLocalFs),
            &DomainNamespace {
                root: location.bucket.clone(),
                domain: "private:owner".into(),
            },
            &location.authority,
            owner,
        )
        .await?;
        let mut session = repository
            .begin("refs/heads/_/main", authority.token(), "sdk")
            .await?;
        let base = publish(&repository, &authority, &mut session, b"base", false).await?;
        let ours = publish(&repository, &authority, &mut session, b"ours", false).await?;
        let theirs = publish(&repository, &authority, &mut session, b"theirs", false).await?;
        let records = [base, ours, theirs];
        let mut roots = [[0; 32]; 3];
        for (index, record) in records.iter().enumerate() {
            let bytes = repository
                .coordinator()
                .store()
                .get(&id(IdentityKind::Commit, record.commit)?, None)
                .await?;
            roots[index] = Commit::decode(&bytes)?.tree;
        }
        Ok(Self {
            repository,
            authority,
            location,
            records,
            roots,
            owner,
            authoring,
        })
    }

    /// Installs explicit exact profiles and rechecks actual protected retention.
    ///
    /// # Errors
    /// Preserves ordinary association validation and genuine native Original reopening failures.
    pub async fn recorded(&self, wrong_root: bool) -> TestResult<SourceRepository> {
        let source = self.repository.coordinator().guard();
        let mut rows = Vec::new();
        for (index, (record, root)) in self.records.iter().zip(self.roots).enumerate() {
            rows.push(RecordedNamespaceProfile::new(
                RecordedAssociation::new(
                    record.commit,
                    if wrong_root && index == 1 {
                        self.roots[2]
                    } else {
                        root
                    },
                    RecordedContext::new(3, 3, &[])?,
                ),
                2,
            )?);
        }
        // Current policy can advance independently of the immutable source
        // views. Explicit current input is selected by its actual signed root,
        // not by a global revision fallback or an unrelated table entry.
        if let Some(current) = source.store().ref_get("refs/heads/_/main").await?
            && !self
                .records
                .iter()
                .any(|record| record.commit == current.commit)
        {
            let bytes = source
                .store()
                .get(&id(IdentityKind::Commit, current.commit)?, None)
                .await?;
            let root = Commit::decode(&bytes)?.tree;
            rows.push(RecordedNamespaceProfile::new(
                RecordedAssociation::new(current.commit, root, RecordedContext::new(3, 3, &[])?),
                2,
            )?);
        }
        let profiles = RecordedNamespaceProfiles::new(rows)?;
        let guard = Guard::new_active(
            source.store().clone(),
            TokioClock,
            source.keys().to_vec(),
            source.config().clone(),
        )
        .with_recorded_authoring(
            self.authoring.clone().context().clone(),
            self.authoring.clone().registries().attribute_revision,
        )?
        .with_recorded_namespace_profiles(profiles)?;
        Ok(Repository::reopen_native_retention(
            Coordinator::new(guard, timing()?, TokioLocalFs),
            &DomainNamespace {
                root: self.location.bucket.clone(),
                domain: source.config().storage_domain.clone(),
            },
            &self.location.authority,
            self.owner,
        )
        .await?)
    }

    /// Completes immutable source reads under freshly checked live policy and Original evidence.
    ///
    /// # Errors
    /// Preserves exact history, interpretation, current token/ACL and Original refusals.
    pub async fn snapshots(
        &self,
        guard: &SourceGuard,
    ) -> Result<Vec<AuthorizedSnapshot>, StoreFailure> {
        let mut snapshots = Vec::new();
        for record in &self.records {
            snapshots.push(
                guard
                    .read_commit_snapshot(record.commit, self.authority.token(), b"/", "sdk")
                    .await?,
            );
        }
        Ok(snapshots)
    }

    /// Qualifies actual sources and current authority before the shared persistence call.
    ///
    /// Every positive and negative native witness follows this exact composition:
    /// actual configured factory, full historical/Original checks, fresh current
    /// rechecks, genuine provenance binding, then ordinary replay/persistence.
    /// There is no factory shortcut or decoded-data authorization constructor.
    ///
    /// # Errors
    /// Preserves actual factory, Original, current policy, context and mandatory
    /// replay refusals before optional uploads; successful optional failures stay
    /// in the primitive's report.
    ///
    /// # Panics
    /// Propagates bounded immutable fixture reconstruction assertions.
    pub async fn replay<S: ContentStore + ?Sized>(
        &self,
        store: &S,
        request: CheckedReplay<'_>,
    ) -> TestResult<PersistedOutcome> {
        let repository = self.recorded(request.wrong_root).await?;
        let guard = repository.coordinator().guard();
        let snapshots = self.snapshots(guard).await?;
        for snapshot in &snapshots {
            guard.authorize_snapshot_path(snapshot, b"/").await?;
        }
        let mut trees = trees(&snapshots)?;
        let mut provenance = snapshots[1..]
            .iter()
            .map(|snapshot| {
                snapshot.interpretation.evaluator(
                    &snapshot.history,
                    (snapshot.commit.identity(), snapshot.commit.commit().tree),
                    Selector::preset(Preset::Any),
                    &snapshot.storage_domain,
                    None,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        match request.defect {
            InputDefect::None => {}
            InputDefect::MissingTrust => provenance.clear(),
            InputDefect::ReversedTrust => provenance.reverse(),
            InputDefect::MissingTrees => trees.clear(),
        }
        // These exact semantic inputs were configured before the first Guard,
        // retained unchanged by reopening, and independently selected for each
        // historical view above. Neither index pointers nor Memo fields select them.
        let registries = self.authoring.registries();
        let context = SemanticContext::new(
            registries.property_revision,
            registries.attribute_revision,
            registries.tree_revision,
        )?;
        let input = EvaluationInputs {
            trees: &trees,
            minimum: guard.config().min_chunk_size,
            context,
            domains: None,
            provenance: &provenance,
            fold: None,
            overlay: None,
        };
        Ok(replay_and_persist(
            store,
            request.recipe,
            &input,
            request.mode,
            request.selection,
            request.persistence,
        )
        .await?)
    }

    /// Publishes a genuine current ACL that excludes the previously authorized subject.
    ///
    /// # Errors
    /// Preserves ordinary current-admin admission, Original and checked publication failures.
    pub async fn revoke_read(&self) -> TestResult {
        let mut session = self
            .repository
            .begin("refs/heads/_/main", self.authority.token(), "sdk")
            .await?;
        publish(
            &self.repository,
            &self.authority,
            &mut session,
            b"theirs",
            true,
        )
        .await?;
        Ok(())
    }

    /// Returns the actual protected selector for a genuinely retained signed view.
    ///
    /// # Errors
    /// Preserves protected record decoding, metadata and owner checks.
    pub async fn original_row(&self, view: Digest) -> TestResult<PathBuf> {
        use crate::repository::local_authority::retention::{self, CommitAssociation};
        let selector = format!("commit-{}.cbor", hex(&view));
        let record: CommitAssociation = retention::read(
            &TokioLocalFs,
            &self.location.authority,
            self.owner,
            &selector,
        )
        .await?;
        Ok(self.location.authority.join(record.selector()))
    }
}

fn timing() -> Result<CommitTiming, crate::ref_advance::AdvanceError> {
    CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )
}

async fn publish(
    repository: &SourceRepository,
    authority: &LocalAuthority,
    session: &mut crate::ref_advance::WriterSession,
    target: &[u8],
    revoke: bool,
) -> TestResult<RefRecord> {
    let (parents, properties) = match session.record() {
        Some(record) => {
            let current = repository
                .coordinator()
                .guard()
                .read_snapshot(session.reference(), authority.token(), b"/", "sdk")
                .await?;
            let prior = current
                .evidence
                .tree(current.evidence.root, wire::MINIMUM)?;
            (
                vec![record.commit],
                prior
                    .props()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "signed source root properties absent",
                        )
                    })?
                    .iter()
                    .map(|property| (property.name.to_owned(), property.value.to_vec()))
                    .collect::<Vec<_>>(),
            )
        }
        None => (
            Vec::new(),
            vec![
                ("acl".into(), b"\x81\x82\x65owner\x18\x1f".to_vec()),
                ("domain".into(), b"\x6dprivate:owner".to_vec()),
                ("durability".into(), b"\x65local".to_vec()),
            ],
        ),
    };
    let (root, nodes) = {
        let mut props = properties
            .iter()
            .map(|(name, value)| Property { name, value })
            .collect::<Vec<_>>();
        if revoke {
            props
                .iter_mut()
                .find(|property| property.name == "acl")
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "signed source root ACL absent")
                })?
                .value = b"\x81\x82\x65other\x01";
        }
        let tree = Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: Entry {
                    kind: TreeEntryKind::Symlink { target },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            }],
            Some(props),
            wire::MINIMUM,
            TreeUse::Ordinary,
        )?;
        (
            tree.root_identity(),
            tree.nodes()
                .map(|node| node.encoded().to_vec())
                .collect::<Vec<_>>(),
        )
    };
    // This is an ordinary unsigned proposal. The existing native producer fills
    // signed provenance, history receipts and Original association independently.
    let mut request = authority.commit_request(
        Commit {
            tree: root,
            parents,
            provenance: Provenance {
                issuer: String::new(),
                token_id: [0; 16],
                subject: String::new(),
                kind: PrincipalKind::Human,
                workload_identity: None,
                process: "sdk".into(),
                observed_at: 0,
                writer_epoch: 0,
                source: CommitSource::Built,
                embedded_token: None,
            },
            timestamp: 0,
            message: "Publish native Memo source".into(),
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
        "sdk".into(),
    );
    request.uploads = nodes
        .into_iter()
        .map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        })
        .collect();
    Ok(repository.commit_request(session, request).await?)
}

/// Reconstructs actual signed operands without borrowing temporary owner buffers.
///
/// # Errors
/// Preserves canonical metadata parsing and tree reconstruction failures.
///
/// # Panics
/// Panics if a bounded source fixture is not a leaf or reconstructs another root.
pub(super) fn trees(snapshots: &[AuthorizedSnapshot]) -> TestResult<BTreeMap<Digest, Tree<'_>>> {
    let mut trees = BTreeMap::new();
    for snapshot in snapshots {
        for root in &snapshot.evidence.roots {
            let tree = snapshot.evidence.tree(*root, wire::MINIMUM)?;
            assert_eq!(tree.root_identity(), *root);
            trees.insert(*root, tree);
        }
    }
    Ok(trees)
}

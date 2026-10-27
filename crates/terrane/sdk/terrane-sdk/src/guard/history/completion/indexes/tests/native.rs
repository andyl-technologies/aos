//! Stages genuine signed historical inputs through native Original retention.
//!
//! Immutable object staging never claims a selected ref or lineage publication.
//! Measured read adapters preserve the actual native Original verifier and refuse
//! every write. Counters cover ordinary Guard ContentStore dispatch; inherited
//! protected Original callbacks retain their separate genuine native I/O checks.

use super::{Required as _, TestResult, wire};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{
    AuthoringNamespaceProfile, Guard, RecordedNamespaceProfile, RecordedNamespaceProfiles,
    StagedUpload,
};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::Repository;
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, ContentValidator,
    Durability, IdentityPrefix, MetaUpload, RangeCapability, RefCapability, RefCasOutcome,
    RefLogAppendOutcome, RefStore, StoreErrorKind, StoreFailure, TokioClock, TokioLocalFs,
};
use terrane_format::gc::publication::evidence::ConfiguredRegistryInputs;
use terrane_format::identity::{Digest, Identity, IdentityKind};
use terrane_format::properties::PropertyName;
use terrane_format::properties::semantics::{RecordedContext, associations::RecordedAssociation};
use terrane_format::provenance::VerifiedCommit;
use terrane_format::refs::{Commit, RefLogRecord, RefRecord};
use terrane_format::tree_format::{self, TreeUse};

/// Names the actual contextual metadata bucket used by historical fixtures.
pub(super) type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

/// Names an instrumented Guard retaining genuine native Original callbacks.
pub(super) type MeasuredGuard = Guard<MeasuredStore, TokioClock>;

/// Keeps the real configured pure schema validator outside opaque storage code.
#[derive(Clone)]
pub(super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let valid = match upload.kind() {
            IdentityKind::Node => [TreeUse::Ordinary, TreeUse::Index]
                .into_iter()
                .any(|usage| {
                    tree_format::decode_node_for(upload.bytes(), true, wire::MINIMUM, usage).is_ok()
                }),
            IdentityKind::Commit => Commit::decode(upload.bytes()).is_ok(),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(crate::guard::invalid())
        }
    }
}

/// Owns a real Repository and its independently prepared signed historical view.
pub(super) struct Fixture {
    /// Repository owns actual protected registration/bootstrap/association setup.
    pub(super) repository: Repository<Bucket, TokioClock, TokioLocalFs>,
    /// Signed Commit came from genuine current-authorized preparation.
    pub(super) commit: VerifiedCommit,
    /// Independently modeled immutable namespace and index closure.
    pub(super) graph: wire::Graph,
}

impl Fixture {
    /// Retains actual Original evidence under explicitly supplied authoring inputs.
    ///
    /// Ordinary immutable staging preserves the independent historical wire graph.
    ///
    /// # Errors
    /// Preserves native open, preparation, durability and object admission errors.
    /// # Panics
    /// Panics if native setup, immutable addresses or preserved selected-state
    /// assertions fail.
    pub(super) async fn new(
        graph: wire::Graph,
        authoring: AuthoringNamespaceProfile,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let seed = crate::ref_advance::tests::fixture().await;
        let root = seed.store().root().to_owned();
        let authority = seed.guard().configured_original_authority()?;
        let owner = std::fs::symlink_metadata(&root)?.uid();
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: root.clone(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                chunk_profile_name: seed.guard().config().chunk_profile_name.clone(),
                chunk_profile: (*seed.guard().config().chunk_profile).clone(),
                locality: seed.guard().config().home.clone(),
            },
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await?;
        // Retain these historical bytes without assigning active index meaning
        // or letting authoring maintenance replace the independent wire graph.
        let guard = Guard::new_with_authoring_namespace_profile(
            bucket,
            TokioClock,
            seed.guard().keys().to_vec(),
            seed.guard().config().clone(),
            authoring,
        );
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            TokioLocalFs,
        );
        let repository = Repository::reopen_native_retention(
            coordinator,
            &DomainNamespace {
                root,
                domain: "public".into(),
            },
            authority.control(),
            owner,
        )
        .await?;
        let token = crate::ref_advance::tests::token();
        let mut session = repository
            .begin("refs/heads/_/historical", &token, "sdk")
            .await?;
        let mut request = crate::ref_advance::tests::request_file(Vec::new(), wire::BODY);
        request.commit.tree = graph.owner;
        request.uploads.retain(|upload| {
            !matches!(
                upload,
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    ..
                }
            )
        });
        request
            .uploads
            .extend(graph.nodes.values().map(|bytes| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: bytes.clone(),
            }));
        let before = selected(&repository).await?;
        let (commit, uploads) = repository
            .prepare_retained_history_fixture(&mut session, request)
            .await?;
        for upload in &uploads {
            let identity = repository
                .coordinator()
                .store()
                .put(upload.as_upload()?)
                .await?;
            if let StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } = upload
            {
                assert_eq!(identity.terrane_v1_digest()?, wire::hash(bytes));
            }
        }
        let encoded = commit.commit().encode()?;
        let actual = repository
            .coordinator()
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Commit,
                &encoded,
            )?))
            .await?;
        assert_eq!(actual.terrane_v1_digest()?, commit.identity());
        assert!(
            repository
                .coordinator()
                .store()
                .ref_get("refs/heads/_/historical")
                .await?
                .is_none()
        );
        let after = selected(&repository).await?;
        assert_eq!(before.0.guard, after.0.guard);
        assert_eq!(before.0.sources, after.0.sources);
        assert_eq!(before.0.branches, after.0.branches);
        assert_eq!(before.0.loss_generation, after.0.loss_generation);
        Ok(Self {
            repository,
            commit,
            graph,
        })
    }

    /// Installs the requested exact view/root input through the genuine Guard factory.
    ///
    /// # Errors
    /// Preserves invalid ordinary input and native Original reinstallation errors.
    ///
    /// # Panics
    /// Panics if a genuine verifier observation lock is poisoned.
    pub(super) async fn guard(
        &self,
        attribute: u64,
    ) -> Result<MeasuredGuard, Box<dyn std::error::Error>> {
        let source = self.repository.coordinator().guard();
        let profile = RecordedNamespaceProfile::new(
            RecordedAssociation::new(
                self.commit.identity(),
                self.graph.owner,
                RecordedContext::new(3, 3, &["future-name"])?,
            ),
            attribute,
        )?;
        let configured = Guard::new_with_recorded_namespace_profiles(
            source.store().clone(),
            TokioClock,
            source.keys().to_vec(),
            source.config().clone(),
            RecordedNamespaceProfiles::new([profile])?,
        );
        let authority = source.configured_original_authority()?;
        let owner = std::fs::symlink_metadata(authority.root())?.uid();
        let coordinator = Coordinator::new(
            configured,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            TokioLocalFs,
        );
        // Native reopening loads and independently checks the actual retained
        // bootstrap and Commit associations as well as the verifier callbacks.
        let reopened = Repository::reopen_native_retention(
            coordinator,
            &DomainNamespace {
                root: authority.root().to_owned(),
                domain: authority.domain().to_owned(),
            },
            authority.control(),
            owner,
        )
        .await?;
        Ok(measured(reopened.coordinator().guard()))
    }
}

/// Records actual whole immutable metadata reads without resetting body traps.
#[derive(Default)]
struct Reads {
    gets: Vec<(IdentityKind, Digest, usize)>,
    effects: usize,
}

/// Wraps the actual bucket without replacing native protected-read callbacks.
pub(super) struct MeasuredStore {
    bucket: Bucket,
    reads: Arc<Mutex<Reads>>,
}

impl MeasuredStore {
    /// Requires zero writes and zero immutable Data-body requests.
    ///
    /// # Panics
    /// Panics on a forbidden request or poisoned observation mutex.
    pub(super) fn assert_read_only(&self) {
        let reads = self.reads.lock().required();
        assert_eq!(reads.effects, 0);
        assert!(
            reads
                .gets
                .iter()
                .all(|(kind, _, _)| matches!(kind, IdentityKind::Node | IdentityKind::Commit))
        );
    }

    /// Returns each actual whole-Node request and successful returned byte length.
    ///
    /// # Panics
    /// Panics if the observation mutex is poisoned.
    pub(super) fn node_reads(&self) -> Vec<(Digest, usize)> {
        self.reads
            .lock()
            .required()
            .gets
            .iter()
            .filter(|(kind, _, _)| *kind == IdentityKind::Node)
            .map(|(_, digest, len)| (*digest, *len))
            .collect()
    }
}

fn measured(source: &Guard<Bucket, TokioClock>) -> MeasuredGuard {
    let guard = source.configuration_adapter(
        MeasuredStore {
            bucket: source.store().clone(),
            reads: Arc::default(),
        },
        TokioClock,
    );
    *guard.original_verifier.write().required() =
        source.original_verifier.read().required().clone();
    *guard.original_baselines.write().required() =
        source.original_baselines.read().required().clone();
    *guard.original_commits.write().required() = source.original_commits.read().required().clone();
    guard
}

impl CapabilityReport for MeasuredStore {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for MeasuredStore {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("historical completion wrote")
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        assert!(matches!(
            identity.kind(),
            IdentityKind::Node | IdentityKind::Commit
        ));
        assert_eq!(range, None);
        let bytes = self.bucket.get(identity, range).await?;
        self.reads.lock().required().gets.push((
            identity.kind(),
            identity.terrane_v1_digest().required(),
            bytes.len(),
        ));
        Ok(bytes)
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("historical completion queried membership")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("historical completion listed storage")
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl RefStore for MeasuredStore {
    type Watch = <Bucket as RefStore>::Watch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.bucket.ref_get(name).await
    }

    async fn ref_cas(
        &self,
        _: &str,
        _: Option<&RefRecord>,
        _: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        panic!("historical completion changed ref")
    }

    async fn ref_log_append(
        &self,
        _: &str,
        _: u64,
        _: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        panic!("historical completion appended log")
    }

    async fn ref_log_read(&self, name: &str, seq: u64) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.bucket.ref_log_read(name, seq).await
    }

    async fn ref_watch(&self, name: &str, seq: u64) -> Result<Self::Watch, StoreFailure> {
        self.bucket.ref_watch(name, seq).await
    }
}

/// Retains ordinary literal inputs and finite store failures for isolated checks.
pub(super) struct Memory {
    /// Exact immutable Node buffers offered by the isolated backend.
    pub(super) nodes: BTreeMap<Digest, Vec<u8>>,
    /// Optional original typed failure for an exact requested Node.
    pub(super) failure: Option<(Digest, StoreErrorKind)>,
    /// Complete ordered actual Node reads and successful returned lengths.
    pub(super) reads: Mutex<Vec<(Digest, usize)>>,
    capabilities: Capabilities,
}

impl Memory {
    /// Copies ordinary wire inputs without making any verification claim.
    pub(super) fn new(nodes: BTreeMap<Digest, Vec<u8>>) -> Self {
        Self {
            nodes,
            failure: None,
            reads: Mutex::default(),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: terrane_format::refs::Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }
}

impl CapabilityReport for Memory {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for Memory {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("read-only index wrote")
    }

    async fn get(&self, id: &Identity, range: Option<ByteRange>) -> Result<Vec<u8>, StoreFailure> {
        assert_eq!(id.kind(), IdentityKind::Node);
        assert_eq!(range, None);
        let node = id.terrane_v1_digest().required();
        if let Some((subject, kind)) = &self.failure
            && *subject == node
        {
            self.reads.lock().required().push((node, 0));
            return Err(StoreFailure::with_source(
                kind.clone(),
                std::io::Error::other("actual finite store failure"),
            ));
        }
        let bytes = self
            .nodes
            .get(&node)
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(id.clone())))?;
        self.reads.lock().required().push((node, bytes.len()));
        Ok(bytes)
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("read-only index has")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("read-only index list")
    }
}

/// Selects the independently supplied active inputs for pure relationship tests.
pub(super) fn profile() -> ConfiguredRegistryInputs {
    let mut names: Vec<_> = PropertyName::ALL
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect();
    names.sort();
    ConfiguredRegistryInputs {
        property_revision: 3,
        behavioral_properties: names,
        attribute_revision: 2,
        selector_revision: 1,
        tree_revision: 1,
        chunk_revision: 1,
        identity_profile: "terrane-v1".into(),
        later_properties: Vec::new(),
    }
}

/// Runs genuine signed history and records only successfully completed contexts.
///
/// # Errors
/// Preserves complete Original/history and immutable relationship refusals.
pub(super) async fn complete(
    guard: &MeasuredGuard,
    commit: &VerifiedCommit,
) -> Result<terrane_format::gc::publication::evidence::LineageUsedInputs, StoreFailure> {
    let original = guard.original_commit(&commit.identity())?;
    let consumed = crate::guard::ConsumedResolver::new(guard, original.baseline().authority())?;
    guard
        .verified_history_observed(
            commit.identity(),
            crate::guard::HistoryObservation::default().tracked(&consumed),
        )
        .await?;
    consumed.finish()
}

/// Owns selected observations without keeping a namespace lock across history.
pub(super) type Selected = (
    terrane_format::gc::publication::PublicationState,
    BTreeMap<String, Option<Vec<u8>>>,
);

/// Copies the complete actual selected state and logical projection.
///
/// # Errors
/// Preserves genuine namespace acquisition and selected-chain verification errors.
pub(super) async fn selected(
    repository: &Repository<Bucket, TokioClock, TokioLocalFs>,
) -> Result<Selected, StoreFailure> {
    let holder =
        crate::bucket::held::SingleHeld::acquire_read_only(repository.coordinator().store())
            .await?;
    let source = holder.source();
    let observation = source.observe_publication().await?;
    Ok((observation.state().clone(), observation.logical().clone()))
}

/// Checks all selected state around an independently read-only history operation.
///
/// # Errors
/// Preserves actual selected observation or current-ref read failures.
/// # Panics
/// Panics if historical completion changes any selected logical value or ref.
pub(super) async fn unchanged(fixture: &Fixture, before: &Selected) -> TestResult {
    assert_eq!(*before, selected(&fixture.repository).await?);
    assert!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get("refs/heads/_/historical")
            .await?
            .is_none()
    );
    Ok(())
}

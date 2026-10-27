//! Observes actual native content reads without supplying publication authority.
//!
//! The native fixture establishes every protected association. This observer
//! retains its actual dispatcher and delegates store operations to the same
//! bucket; it neither invents original evidence nor replaces physical checks.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::bucket::FileBucket;
use crate::guard::Guard;
use crate::ref_advance::CommitRequest;
use crate::ref_advance::tests::{Validator, request_file};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    RefCasOutcome, RefLogAppendOutcome, RefStore, StoreFailure, TokioClock, TokioLocalFs,
};
use terrane_format::identity::{Digest, Identity, IdentityKind, TERRANE_V1};
use terrane_format::refs::{RefLogRecord, RefRecord};

/// Names the actual bucket used by the production native fixture.
pub(in crate::guard) type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

/// Names a measured admission guard backed by that same bucket.
pub(in crate::guard) type ObservedGuard = Guard<ObservedStore, TokioClock>;

#[derive(Default)]
struct Reads {
    content: BTreeMap<ContentAddress, usize>,
    references: BTreeMap<String, usize>,
    effects: usize,
}

/// Retains the complete profile, registered kind domain and digest without hashing.
type ContentAddress = (&'static str, &'static str, Vec<u8>);

/// Uses the closed v1 domain registry to distinguish every immutable kind.
fn content_address(identity: &Identity) -> ContentAddress {
    (
        identity.profile(),
        TERRANE_V1.domain(identity.kind()).unwrap(),
        identity.digest().to_vec(),
    )
}

/// Delegates every operation while counting addressed content/ref observations.
pub(in crate::guard) struct ObservedStore {
    bucket: Bucket,
    reads: Arc<Mutex<Reads>>,
}

impl ObservedStore {
    /// Clears only test observations between independently checked admissions.
    ///
    /// # Panics
    /// Panics if the observation mutex was poisoned.
    pub(in crate::guard) fn reset(&self) {
        *self.reads.lock().unwrap() = Reads::default();
    }

    /// Returns the number of actual GET calls for one complete immutable address.
    ///
    /// # Panics
    /// Panics if the observation mutex was poisoned.
    pub(in crate::guard) fn content_reads(&self, kind: IdentityKind, digest: Digest) -> usize {
        let identity = terrane_format::identity::TERRANE_V1
            .from_digest(kind, &digest)
            .unwrap();
        self.reads
            .lock()
            .unwrap()
            .content
            .get(&content_address(&identity))
            .copied()
            .unwrap_or(0)
    }

    /// Returns all addressed ordinary GET calls for one immutable kind.
    ///
    /// Native retained namespace readers are observed separately by the bucket.
    ///
    /// # Panics
    /// Panics if the closed kind registry rejects the kind or the mutex is poisoned.
    pub(in crate::guard) fn total_content_reads(&self, kind: IdentityKind) -> usize {
        let domain = TERRANE_V1.domain(kind).unwrap();
        self.reads
            .lock()
            .unwrap()
            .content
            .iter()
            .filter(|((_, observed_domain, _), _)| *observed_domain == domain)
            .map(|(_, reads)| *reads)
            .sum()
    }

    /// Returns the number of whole current-ref reads for one canonical name.
    ///
    /// # Panics
    /// Panics if the observation mutex was poisoned.
    pub(in crate::guard) fn reference_reads(&self, reference: &str) -> usize {
        self.reads
            .lock()
            .unwrap()
            .references
            .get(reference)
            .copied()
            .unwrap_or(0)
    }

    /// Requires admission to leave all delegated write methods unused.
    ///
    /// # Panics
    /// Panics if a write was attempted or the observation mutex was poisoned.
    pub(in crate::guard) fn assert_no_effects(&self) {
        assert_eq!(self.reads.lock().unwrap().effects, 0);
    }
}

/// Retains only genuine fixture state, including its real protected-record dispatcher.
///
/// # Panics
/// Panics if a fixture's protected-state lock was poisoned.
pub(in crate::guard) fn observed(source: &Guard<Bucket, TokioClock>) -> ObservedGuard {
    let guard = source.configuration_adapter(
        ObservedStore {
            bucket: source.store().clone(),
            reads: Arc::default(),
        },
        *source.clock(),
    );
    *guard.original_verifier.write().unwrap() = source.original_verifier.read().unwrap().clone();
    *guard.original_baselines.write().unwrap() = source.original_baselines.read().unwrap().clone();
    *guard.original_commits.write().unwrap() = source.original_commits.read().unwrap().clone();
    guard
}

/// Constructs an actual independently configured authoring Guard over the observer.
///
/// Historical retention remains the genuine fixture's original verifier state.
/// This helper installs no selected Guard snapshot or current publication record.
///
/// # Panics
/// Panics if a fixture's protected-state lock was poisoned.
pub(in crate::guard) fn observed_with_authoring(
    source: &Guard<Bucket, TokioClock>,
    authoring: crate::guard::AuthoringNamespaceProfile,
) -> ObservedGuard {
    let guard = Guard::new_with_authoring_namespace_profile(
        ObservedStore {
            bucket: source.store().clone(),
            reads: Arc::default(),
        },
        *source.clock(),
        source.keys().to_vec(),
        source.config().clone(),
        authoring,
    );
    let mut guard = guard;
    guard.configured_current = source.configured_current;
    guard.view_selections = source.view_selections.clone();
    *guard.original_verifier.write().unwrap() = source.original_verifier.read().unwrap().clone();
    *guard.original_baselines.write().unwrap() = source.original_baselines.read().unwrap().clone();
    *guard.original_commits.write().unwrap() = source.original_commits.read().unwrap().clone();
    guard
}

/// Selects an independent Legacy replay of one real signed view for mismatch controls.
///
/// This fresh ordinary configuration retains the actual current capture and
/// protected Original callbacks. It shares no installed/executed interpretation
/// rows and cannot replace the source Guard's immutable Recorded meaning.
///
/// # Errors
/// Rejects invalid independently selected view/root inputs.
///
/// # Panics
/// Panics if an existing protected Original observation lock is poisoned.
pub(in crate::guard) fn observed_with_legacy_selection(
    source: &Guard<Bucket, TokioClock>,
    view: terrane_format::identity::Digest,
    original_root: terrane_format::identity::Digest,
) -> Result<ObservedGuard, StoreFailure> {
    let mut guard = Guard::new(
        ObservedStore {
            bucket: source.store().clone(),
            reads: Arc::default(),
        },
        *source.clock(),
        source.keys().to_vec(),
        source.config().clone(),
    );
    guard.configured_current = source.configured_current;
    let guard = guard.with_view_selections(vec![crate::guard::ViewSelection::new(
        view,
        original_root,
        terrane_format::properties::selected::Selection::Legacy,
        1,
    )?])?;
    *guard.original_verifier.write().unwrap() = source.original_verifier.read().unwrap().clone();
    *guard.original_baselines.write().unwrap() = source.original_baselines.read().unwrap().clone();
    *guard.original_commits.write().unwrap() = source.original_commits.read().unwrap().clone();
    Ok(guard)
}

/// Installs independent historical rows before retaining actual protected callbacks.
///
/// The fresh reader keeps the source's actual current capture, but shares no
/// installed or executed selection table. Rows grant no Original authority.
///
/// # Panics
/// Panics if an existing fixture protected-state lock is poisoned.
pub(in crate::guard) fn observed_with_recorded_selections(
    source: &Guard<Bucket, TokioClock>,
    rows: terrane_format::properties::semantics::associations::RecordedAssociations,
) -> ObservedGuard {
    let mut guard = Guard::new_with_recorded_views(
        ObservedStore {
            bucket: source.store().clone(),
            reads: Arc::default(),
        },
        *source.clock(),
        source.keys().to_vec(),
        source.config().clone(),
        rows,
    );
    guard.configured_current = source.configured_current;
    *guard.original_verifier.write().unwrap() = source.original_verifier.read().unwrap().clone();
    *guard.original_baselines.write().unwrap() = source.original_baselines.read().unwrap().clone();
    *guard.original_commits.write().unwrap() = source.original_commits.read().unwrap().clone();
    guard
}

/// Copies newly factory-retained contexts after an actual publication, without repair.
///
/// # Panics
/// Panics if a fixture's protected-state lock was poisoned.
pub(in crate::guard) fn refresh_retained(
    source: &Guard<Bucket, TokioClock>,
    target: &ObservedGuard,
) {
    *target.original_baselines.write().unwrap() = source.original_baselines.read().unwrap().clone();
    *target.original_commits.write().unwrap() = source.original_commits.read().unwrap().clone();
}

/// Supplies independent readable records for a real fork's unchanged file content.
///
/// # Panics
/// Panics if the genuine fixture's tree or referenced content fails verification.
pub(in crate::guard) async fn fork_request(
    source: &Guard<Bucket, TokioClock>,
    head: Digest,
) -> CommitRequest {
    let evidence = source.verified_tree(head).await.unwrap().evidence;
    let mut request = request_file(Vec::new(), b"placeholder overwritten by fork admission");
    request.uploads.clear();
    request.reference_records = source.existing_records(&evidence).await.unwrap();
    request
}

/// Temporarily removes a genuine protected association to test fresh history reads.
///
/// The caller restores the returned original and archived paths after refusal.
///
/// # Panics
/// Panics if the fixture has no real association or its rename fails.
pub(in crate::guard) async fn archive_original(
    source: &Guard<Bucket, TokioClock>,
    commit: Digest,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let context = source.original_commit(&commit).unwrap();
    let hex = commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let original = context
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{hex}.cbor"));
    let archived = original.with_extension("removed");
    tokio::fs::rename(&original, &archived).await.unwrap();
    (original, archived)
}

impl CapabilityReport for ObservedStore {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

#[async_trait::async_trait]
impl ContentStore for ObservedStore {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.reads.lock().unwrap().effects += 1;
        self.bucket.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        *self
            .reads
            .lock()
            .unwrap()
            .content
            .entry(content_address(identity))
            .or_default() += 1;
        self.bucket.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.bucket.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.bucket.list(prefix).await
    }
}

#[async_trait::async_trait]
impl RefStore for ObservedStore {
    type Watch = <Bucket as RefStore>::Watch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        *self
            .reads
            .lock()
            .unwrap()
            .references
            .entry(name.to_owned())
            .or_default() += 1;
        self.bucket.ref_get(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        self.reads.lock().unwrap().effects += 1;
        self.bucket.ref_cas(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        self.reads.lock().unwrap().effects += 1;
        self.bucket.ref_log_append(name, seq, record).await
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.bucket.ref_log_read(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        self.bucket.ref_watch(name, from_seq).await
    }
}

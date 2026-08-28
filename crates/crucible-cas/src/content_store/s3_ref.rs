//! Strong-CAS S3 reference storage for a single authoritative daemon.
//!
//! Reference names are retained in authenticated small-object bodies while a
//! domain-separated digest selects a fixed-size S3 key. This preserves the
//! complete [`RefName`] language under S3's 1,024-byte key ceiling. Construction
//! shares one process-wide lifecycle authority for each exact endpoint, bucket,
//! and prefix so every in-daemon instance serializes scans and replacements.
//! A configured service MUST independently pass the strong conditional-write
//! and strongly consistent listing conformance gate; ordinary S3 client
//! capability is intentionally insufficient.

use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, Weak};

use super::s3::{StoreS3EndpointId, validate_configuration};
use super::{
    ContentId, MAX_REF_SCAN_VISITS, MutableRefBackend, RefCasOutcome, RefName, RefPublicationGuard,
    RefScanEntry, RefScanPage, StoreError, encode_hex, ref_name_is_descendant,
    validate_ref_scan_basis,
};

const REF_RECORD_MAGIC: &[u8] = b"crucible.content-store.s3-ref.v1\0";
const REF_KEY_DOMAIN: &[u8] = b"crucible.content-store.s3-ref-key.v1";
const MAX_SMALL_OBJECT_BYTES: usize = 4 * 1024;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_PROVIDER_TOKEN_BYTES: usize = 4 * 1024;
const MAX_LIVE_REF_NAMESPACES: usize = 1_024;

/// Maximum committed S3 ref objects returned by one provider list call.
pub const MAX_S3_REF_LIST_ITEMS: u16 = 1_000;

/// Opaque exact provider version used by a conditional replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3ObjectVersion(String);

impl StoreS3ObjectVersion {
    /// Validates one bounded nonempty provider version token.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for an empty or oversized token.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROVIDER_TOKEN_BYTES {
            return Err(StoreError::Incompatible);
        }
        Ok(Self(value))
    }

    /// Returns the exact provider version token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bounded small object together with its conditional-write version.
pub struct StoreS3VersionedObject {
    bytes: Arc<[u8]>,
    version: StoreS3ObjectVersion,
}

impl StoreS3VersionedObject {
    /// Builds one bounded versioned object returned by an admitted client.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Quota`] when the body exceeds 4 KiB.
    pub fn new(bytes: Arc<[u8]>, version: StoreS3ObjectVersion) -> Result<Self, StoreError> {
        if bytes.len() > MAX_SMALL_OBJECT_BYTES {
            return Err(StoreError::Quota);
        }
        Ok(Self { bytes, version })
    }

    /// Returns the complete bounded object body.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact provider conditional-write version.
    #[must_use]
    pub const fn version(&self) -> &StoreS3ObjectVersion {
        &self.version
    }
}

/// Outcome of one provider-enforced conditional small-object write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreS3ConditionalWriteOutcome {
    /// The exact precondition held and the replacement committed.
    Committed(StoreS3ObjectVersion),
    /// The exact absent/version precondition did not hold.
    PreconditionFailed,
}

/// Opaque bounded continuation for one committed-object listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3ObjectListCursor(String);

impl StoreS3ObjectListCursor {
    /// Validates one bounded nonempty provider continuation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for an empty or oversized token.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROVIDER_TOKEN_BYTES {
            return Err(StoreError::Incompatible);
        }
        Ok(Self(value))
    }

    /// Returns the exact provider continuation token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bounded page of committed S3 object keys.
pub struct StoreS3ObjectListPage {
    keys: Vec<String>,
    next: Option<StoreS3ObjectListCursor>,
}

/// One bounded committed-object scan under a single absolute service deadline.
///
/// The session owns provider pagination. Every page and small-object read MUST
/// consume the same absolute deadline established at session creation; progress
/// must not reset it. This prevents a bounded logical ref scan from multiplying
/// a per-request timeout across many provider calls.
pub trait StoreS3ObjectScan {
    /// Returns the next bounded key page.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error on timeout, invalid pagination, or
    /// after this session has already observed EOF.
    fn next_page(&mut self, maximum_items: u16) -> Result<StoreS3ObjectListPage, StoreError>;

    /// Reads one listed small object under this session's remaining deadline.
    ///
    /// # Errors
    ///
    /// Returns a classified credential, availability, quota, or protocol error.
    fn get_small_versioned_object(
        &self,
        key: &str,
        maximum_bytes: u16,
    ) -> Result<Option<StoreS3VersionedObject>, StoreError>;
}

impl StoreS3ObjectListPage {
    /// Validates one provider page against its requested ceiling and cursor.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for invalid keys, excessive output,
    /// an empty continuing page, or a repeated continuation.
    pub fn new(
        keys: Vec<String>,
        next: Option<StoreS3ObjectListCursor>,
        after: Option<&StoreS3ObjectListCursor>,
        maximum_items: u16,
    ) -> Result<Self, StoreError> {
        let strictly_ordered = keys.windows(2).all(|pair| pair[0] < pair[1]);
        if maximum_items == 0
            || maximum_items > MAX_S3_REF_LIST_ITEMS
            || keys.len() > usize::from(maximum_items)
            || keys
                .iter()
                .any(|key| key.is_empty() || key.len() > MAX_OBJECT_KEY_BYTES)
            || !strictly_ordered
            || (next.is_some() && keys.is_empty())
            || next
                .as_ref()
                .zip(after)
                .is_some_and(|(next, after)| next == after)
        {
            return Err(StoreError::Incompatible);
        }
        Ok(Self { keys, next })
    }

    /// Returns the exact committed object keys in this page.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// Returns the provider continuation, or `None` at observed EOF.
    #[must_use]
    pub const fn next(&self) -> Option<&StoreS3ObjectListCursor> {
        self.next.as_ref()
    }

    fn into_parts(self) -> (Vec<String>, Option<StoreS3ObjectListCursor>) {
        (self.keys, self.next)
    }
}

/// S3 transport contract admitted only after strong-CAS service conformance.
///
/// Implementations MUST provide strongly consistent reads and listings after a
/// successful conditional write. `put_small_if_absent` and
/// `replace_small_if_version` MUST be atomic and MUST NOT report success unless
/// the returned version names the exact committed body. Conditional mismatch is
/// an ordinary [`StoreS3ConditionalWriteOutcome::PreconditionFailed`].
pub trait StoreS3StrongCasClient: Send + Sync {
    /// Returns the exact non-secret endpoint policy bound to this client.
    fn endpoint_id(&self) -> &StoreS3EndpointId;

    /// Reads one complete object no larger than `maximum_bytes`.
    ///
    /// # Errors
    ///
    /// Returns a classified credential, availability, quota, or protocol error.
    fn get_small_versioned_object(
        &self,
        bucket: &str,
        key: &str,
        maximum_bytes: u16,
    ) -> Result<Option<StoreS3VersionedObject>, StoreError>;

    /// Conditionally creates one absent small object.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error without replacing an existing key.
    fn put_small_if_absent(
        &self,
        bucket: &str,
        key: &str,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3ConditionalWriteOutcome, StoreError>;

    /// Conditionally replaces one exact provider version.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error without writing on version mismatch.
    fn replace_small_if_version(
        &self,
        bucket: &str,
        key: &str,
        expected: &StoreS3ObjectVersion,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3ConditionalWriteOutcome, StoreError>;

    /// Begins one strongly consistent committed-object scan below `prefix`.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when one absolute scan deadline or
    /// exact pagination cannot be established.
    fn begin_small_object_scan(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Box<dyn StoreS3ObjectScan + '_>, StoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RefNamespaceKey {
    endpoint: StoreS3EndpointId,
    bucket: String,
    prefix: String,
}

#[derive(Default)]
struct RefNamespaceLifecycle {
    publication: RwLock<()>,
    state: Mutex<()>,
}

static REF_NAMESPACE_LIFECYCLES: OnceLock<
    Mutex<BTreeMap<RefNamespaceKey, Weak<RefNamespaceLifecycle>>>,
> = OnceLock::new();

/// Exact strong-CAS service and lifecycle capability for one S3 ref namespace.
///
/// Every capability constructed for the same endpoint, bucket, and prefix in
/// this process shares one lifecycle authority. The deployment MUST ensure this
/// daemon is the namespace's only ordinary writer. A different process or
/// external S3 writer is outside this single-host capability and invalidates
/// admission. No ref-inventory/GC authority is provided by this checkpoint.
#[derive(Clone)]
pub struct StoreS3RefCapability {
    endpoint: StoreS3EndpointId,
    bucket: String,
    prefix: String,
    client: Arc<dyn StoreS3StrongCasClient>,
    lifecycle: Arc<RefNamespaceLifecycle>,
}

impl StoreS3RefCapability {
    /// Validates and binds one exact strong-CAS S3 ref namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unauthorized`] for endpoint mismatch,
    /// [`StoreError::InvalidComposition`] for invalid namespace configuration,
    /// or [`StoreError::Poisoned`] when lifecycle admission cannot complete.
    pub fn new(
        endpoint: StoreS3EndpointId,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        client: Arc<dyn StoreS3StrongCasClient>,
    ) -> Result<Self, StoreError> {
        let bucket = bucket.into();
        let prefix = prefix.into();
        validate_configuration(&endpoint, &bucket, &prefix, 1, 5 * 1024 * 1024)?;
        if client.endpoint_id() != &endpoint {
            return Err(StoreError::Unauthorized);
        }
        let key = RefNamespaceKey {
            endpoint: endpoint.clone(),
            bucket: bucket.clone(),
            prefix: prefix.clone(),
        };
        let registry = REF_NAMESPACE_LIFECYCLES.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut registry = registry.lock().map_err(|_| StoreError::Poisoned {
            operation: "admit-S3-ref-lifecycle",
        })?;
        registry.retain(|_, lifecycle| lifecycle.strong_count() != 0);
        if !registry.contains_key(&key) && registry.len() >= MAX_LIVE_REF_NAMESPACES {
            return Err(StoreError::Quota);
        }
        let lifecycle = match registry.entry(key) {
            Entry::Occupied(mut entry) => match entry.get().upgrade() {
                Some(lifecycle) => lifecycle,
                None => {
                    let lifecycle = Arc::new(RefNamespaceLifecycle::default());
                    entry.insert(Arc::downgrade(&lifecycle));
                    lifecycle
                }
            },
            Entry::Vacant(entry) => {
                let lifecycle = Arc::new(RefNamespaceLifecycle::default());
                entry.insert(Arc::downgrade(&lifecycle));
                lifecycle
            }
        };
        Ok(Self {
            endpoint,
            bucket,
            prefix,
            client,
            lifecycle,
        })
    }

    /// Returns the exact endpoint policy admitted for this namespace.
    #[must_use]
    pub const fn endpoint_id(&self) -> &StoreS3EndpointId {
        &self.endpoint
    }
}

/// Authoritative S3 mutable refs behind an explicit strong-CAS capability.
pub struct S3RefBackend {
    capability: StoreS3RefCapability,
}

impl S3RefBackend {
    /// Constructs one backend from an already admitted strong-CAS capability.
    #[must_use]
    pub const fn new(capability: StoreS3RefCapability) -> Self {
        Self { capability }
    }

    fn object_prefix(&self) -> String {
        if self.capability.prefix.is_empty() {
            "refs/".to_string()
        } else {
            format!("{}/refs/", self.capability.prefix)
        }
    }

    fn key(&self, name: &RefName) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REF_KEY_DOMAIN);
        hasher.update(&(name.as_str().len() as u64).to_be_bytes());
        hasher.update(name.as_str().as_bytes());
        format!(
            "{}{}",
            self.object_prefix(),
            encode_hex(hasher.finalize().as_bytes())
        )
    }

    fn lock_state(&self, operation: &'static str) -> Result<MutexGuard<'_, ()>, StoreError> {
        self.capability
            .lifecycle
            .state
            .lock()
            .map_err(|_| StoreError::Poisoned { operation })
    }

    fn read_current(
        &self,
        name: &RefName,
    ) -> Result<Option<(ContentId, StoreS3ObjectVersion)>, StoreError> {
        let key = self.key(name);
        let object = self.capability.client.get_small_versioned_object(
            &self.capability.bucket,
            &key,
            MAX_SMALL_OBJECT_BYTES as u16,
        )?;
        object
            .map(|object| {
                let (stored_name, target) = decode_ref_record(object.bytes())?;
                if &stored_name != name || self.key(&stored_name) != key {
                    return Err(StoreError::Incompatible);
                }
                Ok((target, object.version().clone()))
            })
            .transpose()
    }

    fn conflict_after_failed_write(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
    ) -> Result<RefCasOutcome, StoreError> {
        let current = self
            .read_current(name)?
            .map(|(target, _version)| target)
            .ok_or(StoreError::Incompatible)?;
        Ok(RefCasOutcome::Conflict {
            expected,
            current: Some(current),
        })
    }
}

impl MutableRefBackend for S3RefBackend {
    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        let guard =
            self.capability
                .lifecycle
                .publication
                .read()
                .map_err(|_| StoreError::Poisoned {
                    operation: "acquire-S3-ref-publication-guard",
                })?;
        Ok(Box::new(S3RefPublicationGuard { _guard: guard }))
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let _state = self.lock_state("read-S3-ref-state")?;
        Ok(self.read_current(name)?.map(|(target, _version)| target))
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        validate_ref_scan_basis(namespace, after, limit)?;
        let _state = self.lock_state("scan-S3-ref-state")?;
        let object_prefix = self.object_prefix();
        let mut visited = 0_u64;
        let mut pages = 0_u64;
        let mut candidates = BTreeMap::new();
        let mut prior_key = None;
        let mut scan = self
            .capability
            .client
            .begin_small_object_scan(&self.capability.bucket, &object_prefix)?;
        loop {
            pages = pages.checked_add(1).ok_or(StoreError::Quota)?;
            if pages > MAX_REF_SCAN_VISITS.saturating_add(1) {
                return Err(StoreError::Quota);
            }
            let page = scan.next_page(MAX_S3_REF_LIST_ITEMS)?;
            let (keys, next) = page.into_parts();
            for key in keys {
                if prior_key.as_ref().is_some_and(|prior| &key <= prior) {
                    return Err(StoreError::Incompatible);
                }
                visited = visited.checked_add(1).ok_or(StoreError::Quota)?;
                if visited > MAX_REF_SCAN_VISITS {
                    return Err(StoreError::Quota);
                }
                if !key.starts_with(&object_prefix) {
                    return Err(StoreError::Incompatible);
                }
                prior_key = Some(key.clone());
                let object = scan
                    .get_small_versioned_object(&key, MAX_SMALL_OBJECT_BYTES as u16)?
                    .ok_or(StoreError::Incompatible)?;
                let (name, target) = decode_ref_record(object.bytes())?;
                if self.key(&name) != key {
                    return Err(StoreError::Incompatible);
                }
                if !ref_name_is_descendant(namespace, &name)
                    || after.is_some_and(|cursor| &name <= cursor)
                {
                    continue;
                }
                if candidates.insert(name, target).is_some() {
                    return Err(StoreError::Incompatible);
                }
                if candidates.len() > limit.saturating_add(1) {
                    candidates.pop_last();
                }
            }
            if next.is_none() {
                break;
            }
        }

        let has_more = candidates.len() > limit;
        if has_more {
            candidates.pop_last();
        }
        let entries = candidates
            .into_iter()
            .map(|(name, target)| RefScanEntry::new(name, target))
            .collect::<Vec<_>>();
        let next_after = has_more
            .then(|| entries.last().map(|entry| entry.name().clone()))
            .flatten();
        Ok(RefScanPage::new(entries, next_after, visited))
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let _state = self.lock_state("replace-S3-ref-state")?;
        let key = self.key(name);
        let current = self.read_current(name)?;
        if current.as_ref().map(|(target, _version)| *target) != expected {
            return Ok(RefCasOutcome::Conflict {
                expected,
                current: current.map(|(target, _version)| target),
            });
        }
        let bytes = Arc::<[u8]>::from(encode_ref_record(name, next)?);
        let outcome = match current {
            Some((_target, version)) => self.capability.client.replace_small_if_version(
                &self.capability.bucket,
                &key,
                &version,
                bytes,
            )?,
            None => {
                self.capability
                    .client
                    .put_small_if_absent(&self.capability.bucket, &key, bytes)?
            }
        };
        match outcome {
            StoreS3ConditionalWriteOutcome::Committed(version) => {
                let (observed, observed_version) =
                    self.read_current(name)?.ok_or(StoreError::Incompatible)?;
                if observed != next || observed_version != version {
                    return Err(StoreError::Incompatible);
                }
                Ok(RefCasOutcome::Advanced { next })
            }
            StoreS3ConditionalWriteOutcome::PreconditionFailed => {
                self.conflict_after_failed_write(name, expected)
            }
        }
    }
}

struct S3RefPublicationGuard<'a> {
    _guard: RwLockReadGuard<'a, ()>,
}

impl RefPublicationGuard for S3RefPublicationGuard<'_> {}

fn encode_ref_record(name: &RefName, target: ContentId) -> Result<Vec<u8>, StoreError> {
    let name = name.as_str().as_bytes();
    let target = target.encode();
    let name_length = u16::try_from(name.len()).map_err(|_| StoreError::Quota)?;
    let target_length = u16::try_from(target.len()).map_err(|_| StoreError::Quota)?;
    let capacity = REF_RECORD_MAGIC
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(name.len()))
        .and_then(|value| value.checked_add(2))
        .and_then(|value| value.checked_add(target.len()))
        .ok_or(StoreError::Quota)?;
    if capacity > MAX_SMALL_OBJECT_BYTES {
        return Err(StoreError::Quota);
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(REF_RECORD_MAGIC);
    bytes.extend_from_slice(&name_length.to_be_bytes());
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(&target_length.to_be_bytes());
    bytes.extend_from_slice(target.as_bytes());
    Ok(bytes)
}

fn decode_ref_record(bytes: &[u8]) -> Result<(RefName, ContentId), StoreError> {
    if bytes.len() > MAX_SMALL_OBJECT_BYTES || !bytes.starts_with(REF_RECORD_MAGIC) {
        return Err(StoreError::Incompatible);
    }
    let mut offset = REF_RECORD_MAGIC.len();
    let name_length = read_u16(bytes, &mut offset)?;
    let name_end = offset
        .checked_add(usize::from(name_length))
        .ok_or(StoreError::Incompatible)?;
    let name = bytes
        .get(offset..name_end)
        .ok_or(StoreError::Incompatible)?;
    offset = name_end;
    let target_length = read_u16(bytes, &mut offset)?;
    let target_end = offset
        .checked_add(usize::from(target_length))
        .ok_or(StoreError::Incompatible)?;
    let target = bytes
        .get(offset..target_end)
        .ok_or(StoreError::Incompatible)?;
    if target_end != bytes.len() {
        return Err(StoreError::Incompatible);
    }
    let name = std::str::from_utf8(name).map_err(|_| StoreError::Incompatible)?;
    let target = std::str::from_utf8(target).map_err(|_| StoreError::Incompatible)?;
    Ok((
        RefName::new(name).map_err(|_| StoreError::Incompatible)?,
        ContentId::parse(target).map_err(|_| StoreError::Incompatible)?,
    ))
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, StoreError> {
    let end = offset.checked_add(2).ok_or(StoreError::Incompatible)?;
    let field: [u8; 2] = bytes
        .get(*offset..end)
        .ok_or(StoreError::Incompatible)?
        .try_into()
        .map_err(|_| StoreError::Incompatible)?;
    *offset = end;
    Ok(u16::from_be_bytes(field))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;

    use super::*;
    use crate::content_store::ObjectKind;

    struct FakeStrongCasClient {
        endpoint: StoreS3EndpointId,
        objects: Mutex<BTreeMap<(String, String), (Arc<[u8]>, u64)>>,
        next_version: AtomicU64,
        corrupt_reads: AtomicBool,
        lie_about_committed_version: AtomicBool,
    }

    impl FakeStrongCasClient {
        fn new(endpoint: StoreS3EndpointId) -> Self {
            Self {
                endpoint,
                objects: Mutex::new(BTreeMap::new()),
                next_version: AtomicU64::new(1),
                corrupt_reads: AtomicBool::new(false),
                lie_about_committed_version: AtomicBool::new(false),
            }
        }

        fn version(&self) -> Result<(u64, StoreS3ObjectVersion), StoreError> {
            let version = self.next_version.fetch_add(1, Ordering::SeqCst);
            let reported = if self.lie_about_committed_version.load(Ordering::SeqCst) {
                format!("etag-{}", version.saturating_add(1_000))
            } else {
                format!("etag-{version}")
            };
            Ok((version, StoreS3ObjectVersion::new(reported)?))
        }
    }

    impl StoreS3StrongCasClient for FakeStrongCasClient {
        fn endpoint_id(&self) -> &StoreS3EndpointId {
            &self.endpoint
        }

        fn get_small_versioned_object(
            &self,
            bucket: &str,
            key: &str,
            maximum_bytes: u16,
        ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
            let object = self
                .objects
                .lock()
                .expect("object lock")
                .get(&(bucket.to_string(), key.to_string()))
                .cloned();
            object
                .map(|(mut bytes, version)| {
                    if bytes.len() > usize::from(maximum_bytes) {
                        return Err(StoreError::Quota);
                    }
                    if self.corrupt_reads.load(Ordering::SeqCst) {
                        let mut corrupt = bytes.to_vec();
                        corrupt[0] ^= 0xff;
                        bytes = Arc::from(corrupt);
                    }
                    StoreS3VersionedObject::new(
                        bytes,
                        StoreS3ObjectVersion::new(format!("etag-{version}"))?,
                    )
                })
                .transpose()
        }

        fn put_small_if_absent(
            &self,
            bucket: &str,
            key: &str,
            bytes: Arc<[u8]>,
        ) -> Result<StoreS3ConditionalWriteOutcome, StoreError> {
            let mut objects = self.objects.lock().expect("object lock");
            match objects.entry((bucket.to_string(), key.to_string())) {
                Entry::Occupied(_) => Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed),
                Entry::Vacant(entry) => {
                    let (version, token) = self.version()?;
                    entry.insert((bytes, version));
                    Ok(StoreS3ConditionalWriteOutcome::Committed(token))
                }
            }
        }

        fn replace_small_if_version(
            &self,
            bucket: &str,
            key: &str,
            expected: &StoreS3ObjectVersion,
            bytes: Arc<[u8]>,
        ) -> Result<StoreS3ConditionalWriteOutcome, StoreError> {
            let mut objects = self.objects.lock().expect("object lock");
            let Some((current, version)) = objects.get_mut(&(bucket.to_string(), key.to_string()))
            else {
                return Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed);
            };
            if expected.as_str() != format!("etag-{version}") {
                return Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed);
            }
            let (next_version, token) = self.version()?;
            *current = bytes;
            *version = next_version;
            Ok(StoreS3ConditionalWriteOutcome::Committed(token))
        }

        fn begin_small_object_scan(
            &self,
            bucket: &str,
            prefix: &str,
        ) -> Result<Box<dyn StoreS3ObjectScan + '_>, StoreError> {
            Ok(Box::new(FakeStrongCasScan {
                client: self,
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
                after: None,
                finished: false,
            }))
        }
    }

    struct FakeStrongCasScan<'a> {
        client: &'a FakeStrongCasClient,
        bucket: String,
        prefix: String,
        after: Option<StoreS3ObjectListCursor>,
        finished: bool,
    }

    impl StoreS3ObjectScan for FakeStrongCasScan<'_> {
        fn next_page(&mut self, maximum_items: u16) -> Result<StoreS3ObjectListPage, StoreError> {
            if self.finished {
                return Err(StoreError::Incompatible);
            }
            let mut keys = self
                .client
                .objects
                .lock()
                .expect("object lock")
                .keys()
                .filter(|(bucket, key)| bucket == &self.bucket && key.starts_with(&self.prefix))
                .map(|(_bucket, key)| key.clone())
                .filter(|key| {
                    self.after
                        .as_ref()
                        .is_none_or(|cursor| key.as_str() > cursor.as_str())
                })
                .collect::<Vec<_>>();
            let truncated = keys.len() > usize::from(maximum_items);
            keys.truncate(usize::from(maximum_items));
            let next = truncated
                .then(|| keys.last().cloned())
                .flatten()
                .map(StoreS3ObjectListCursor::new)
                .transpose()?;
            let page =
                StoreS3ObjectListPage::new(keys, next.clone(), self.after.as_ref(), maximum_items)?;
            self.after = next;
            self.finished = self.after.is_none();
            Ok(page)
        }

        fn get_small_versioned_object(
            &self,
            key: &str,
            maximum_bytes: u16,
        ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
            self.client
                .get_small_versioned_object(&self.bucket, key, maximum_bytes)
        }
    }

    fn endpoint() -> StoreS3EndpointId {
        StoreS3EndpointId::new("tests/strong-cas").expect("endpoint")
    }

    fn backend(client: Arc<FakeStrongCasClient>) -> S3RefBackend {
        let capability =
            StoreS3RefCapability::new(client.endpoint.clone(), "campaign-refs", "tenant-a", client)
                .expect("strong CAS capability");
        S3RefBackend::new(capability)
    }

    #[test]
    fn strong_cas_refs_round_trip_conflict_and_scan_in_name_order() {
        let client = Arc::new(FakeStrongCasClient::new(endpoint()));
        let refs = backend(client);
        let namespace = RefName::new("campaigns").expect("namespace");
        let alpha = RefName::new("campaigns/alpha").expect("alpha");
        let zeta = RefName::new("campaigns/zeta").expect("zeta");
        let alpha_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"alpha");
        let zeta_target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"zeta");

        assert_eq!(refs.read_ref(&alpha).expect("empty ref"), None);
        assert_eq!(
            refs.compare_exchange(&zeta, None, zeta_target)
                .expect("create zeta"),
            RefCasOutcome::Advanced { next: zeta_target }
        );
        assert_eq!(
            refs.compare_exchange(&alpha, None, alpha_target)
                .expect("create alpha"),
            RefCasOutcome::Advanced { next: alpha_target }
        );
        assert_eq!(
            refs.compare_exchange(&alpha, None, zeta_target)
                .expect("stale create"),
            RefCasOutcome::Conflict {
                expected: None,
                current: Some(alpha_target)
            }
        );

        let first = refs
            .scan_refs(&namespace, None, 1)
            .expect("first scan page");
        assert_eq!(first.entries().len(), 1);
        assert_eq!(first.entries()[0].name(), &alpha);
        assert_eq!(first.next_after(), Some(&alpha));
        let second = refs
            .scan_refs(&namespace, first.next_after(), 1)
            .expect("second scan page");
        assert_eq!(second.entries().len(), 1);
        assert_eq!(second.entries()[0].name(), &zeta);
        assert!(second.next_after().is_none());
    }

    #[test]
    fn maximum_ref_name_uses_fixed_key_and_corruption_fails_closed() {
        let client = Arc::new(FakeStrongCasClient::new(endpoint()));
        let refs = backend(client.clone());
        let name = RefName::new(format!(
            "{}/{}/{}/{}",
            "a".repeat(255),
            "b".repeat(255),
            "c".repeat(255),
            "d".repeat(255)
        ))
        .expect("1,023-byte ref name");
        assert_eq!(name.as_str().len(), 1_023);
        assert!(refs.key(&name).len() <= MAX_OBJECT_KEY_BYTES);
        let target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, u32::MAX, b"target");
        refs.compare_exchange(&name, None, target)
            .expect("create maximum ref");
        assert_eq!(
            refs.read_ref(&name).expect("read maximum ref"),
            Some(target)
        );

        client.corrupt_reads.store(true, Ordering::SeqCst);
        assert!(matches!(
            refs.read_ref(&name),
            Err(StoreError::Incompatible)
        ));
    }

    #[test]
    fn independently_constructed_instances_preserve_one_cas_winner() {
        let client = Arc::new(FakeStrongCasClient::new(endpoint()));
        let first = backend(client.clone());
        let second = backend(client);
        let name = RefName::new("campaigns/race").expect("race ref");
        let initial = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"initial");
        first
            .compare_exchange(&name, None, initial)
            .expect("initial ref");
        let left = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"left");
        let right = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"right");
        let left_name = name.clone();
        let right_name = name.clone();
        let left_thread = thread::spawn(move || {
            first
                .compare_exchange(&left_name, Some(initial), left)
                .expect("left CAS")
        });
        let right_thread = thread::spawn(move || {
            second
                .compare_exchange(&right_name, Some(initial), right)
                .expect("right CAS")
        });
        let outcomes = [
            left_thread.join().expect("left thread"),
            right_thread.join().expect("right thread"),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RefCasOutcome::Advanced { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RefCasOutcome::Conflict { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn endpoint_and_committed_version_evidence_fail_closed() {
        let client = Arc::new(FakeStrongCasClient::new(endpoint()));
        let wrong_endpoint = StoreS3EndpointId::new("tests/wrong").expect("wrong endpoint");
        assert!(matches!(
            StoreS3RefCapability::new(wrong_endpoint, "campaign-refs", "tenant-a", client.clone(),),
            Err(StoreError::Unauthorized)
        ));

        let refs = backend(client.clone());
        let name = RefName::new("campaigns/lying-service").expect("ref name");
        let target = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"target");
        client
            .lie_about_committed_version
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            refs.compare_exchange(&name, None, target),
            Err(StoreError::Incompatible)
        ));
        client
            .lie_about_committed_version
            .store(false, Ordering::SeqCst);
        assert_eq!(refs.read_ref(&name).expect("committed body"), Some(target));
    }
}

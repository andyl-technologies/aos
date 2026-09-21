//! Bounded S3-compatible immutable-object storage below logical identity.
//!
//! Canonical graph configuration records only a non-secret endpoint identity,
//! bucket, key prefix, and hard transfer bounds. A daemon-owned client
//! capability supplies credentials and transport. The leaf authenticates every
//! complete download, validates every source again while uploading, and uses
//! conditional multipart completion so concurrent writers cannot replace an
//! existing content-addressed key.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, Read};
use std::sync::Arc;
#[cfg(feature = "destructive-recovery-faults")]
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    BackendCapabilities, BlobHandle, BlobSource, ByteRange, ContentId, ImmutableBlobBackend,
    PlacementReceipt, PutReceipt, StoreError, content_hasher, read_retry, validate_range,
    validate_source,
};

mod backend;
mod blob_admin;

pub(super) use backend::validate_configuration;
use backend::validate_object_key;
pub use backend::{S3BlobBackend, S3BlobBackendConfig, S3MultipartCleanupAdmin};
pub use blob_admin::{
    MAX_S3_COMMITTED_OBJECT_VISITS, StoreS3BlobAdminClient, StoreS3ConditionalDeleteOutcome,
};
use blob_admin::{S3BlobAdministration, S3BlobLifecycle, admit_blob_namespace};

const MAX_ENDPOINT_ID_BYTES: usize = 512;
const MAX_BUCKET_BYTES: usize = 63;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_CONTENT_ID_TEXT_BYTES: usize = 93;
const OBJECT_NAMESPACE_SEPARATOR_BYTES: usize = 9;
const MAX_PREFIX_BYTES: usize =
    MAX_OBJECT_KEY_BYTES - MAX_CONTENT_ID_TEXT_BYTES - OBJECT_NAMESPACE_SEPARATOR_BYTES;
const MAX_MULTIPART_TOKEN_BYTES: usize = 4_096;
const MAX_MULTIPART_PARTS: u32 = 10_000;
const MIN_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
const MAX_MULTIPART_PART_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const MULTIPART_REMOVE_LEAF_TRIGGER: &str = "crucible.destructive-recovery.multipart-remove-leaf";
#[cfg(feature = "destructive-recovery-faults")]
static MULTIPART_REMOVE_LEAF_TRIGGERED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "destructive-recovery-faults")]
const STORE_CREDENTIAL_EXPIRY_TRIGGER: &str =
    "crucible.destructive-recovery.store-credential-expiry";
#[cfg(feature = "destructive-recovery-faults")]
static STORE_CREDENTIAL_EXPIRY_TRIGGERED: AtomicBool = AtomicBool::new(false);

/// Maximum unfinished multipart uploads returned or reclaimed by one call.
pub const MAX_S3_MULTIPART_LIST_ITEMS: u16 = 1_000;

/// Validated non-secret identity of one S3 endpoint and credential policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreS3EndpointId(String);

impl StoreS3EndpointId {
    /// Validates one bounded slash-separated endpoint-policy identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] for an empty, oversized, or
    /// non-canonical identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_ENDPOINT_ID_BYTES
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= 255
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(StoreError::InvalidComposition {
                reason: "store S3 endpoint identifier is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated endpoint identifier spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One opened S3 response body and its exact declared object length.
pub struct StoreS3ObjectDownload {
    logical_length: u64,
    reader: Box<dyn Read + Send>,
}

impl StoreS3ObjectDownload {
    /// Builds one opened response body.
    #[must_use]
    pub fn new(logical_length: u64, reader: Box<dyn Read + Send>) -> Self {
        Self {
            logical_length,
            reader,
        }
    }

    fn into_parts(self) -> (u64, Box<dyn Read + Send>) {
        (self.logical_length, self.reader)
    }
}

/// Opaque identity of one admitted multipart upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3MultipartUpload(String);

impl StoreS3MultipartUpload {
    /// Validates one bounded nonempty provider upload token.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] when the token is empty or larger
    /// than the protocol bound.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_MULTIPART_TOKEN_BYTES {
            return Err(StoreError::Incompatible);
        }
        Ok(Self(value))
    }

    /// Returns the provider token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider evidence for one successfully uploaded multipart part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3UploadedPart {
    part_number: u32,
    provider_tag: String,
}

impl StoreS3UploadedPart {
    /// Validates one 1-based part number and bounded provider tag.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for an invalid part or tag.
    pub fn new(part_number: u32, provider_tag: impl Into<String>) -> Result<Self, StoreError> {
        let provider_tag = provider_tag.into();
        if part_number == 0
            || part_number > MAX_MULTIPART_PARTS
            || provider_tag.is_empty()
            || provider_tag.len() > MAX_MULTIPART_TOKEN_BYTES
        {
            return Err(StoreError::Incompatible);
        }
        Ok(Self {
            part_number,
            provider_tag,
        })
    }

    /// Returns the 1-based part number.
    #[must_use]
    pub const fn part_number(&self) -> u32 {
        self.part_number
    }

    /// Returns the opaque provider completion tag.
    #[must_use]
    pub fn provider_tag(&self) -> &str {
        &self.provider_tag
    }
}

/// Outcome of one conditional S3 publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreS3ConditionalPutOutcome {
    /// The final object key was absent and is now committed.
    Created,
    /// Another writer had already committed the final object key.
    AlreadyExists,
}

/// Exact provider continuation for one bounded multipart-upload listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3MultipartListCursor {
    key_marker: String,
    upload_id_marker: StoreS3MultipartUpload,
}

impl StoreS3MultipartListCursor {
    /// Builds one bounded provider continuation pair.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for an empty or oversized key.
    pub fn new(
        key_marker: impl Into<String>,
        upload_id_marker: StoreS3MultipartUpload,
    ) -> Result<Self, StoreError> {
        let key_marker = key_marker.into();
        validate_object_key(&key_marker)?;
        Ok(Self {
            key_marker,
            upload_id_marker,
        })
    }

    /// Returns the exact provider key marker.
    #[must_use]
    pub fn key_marker(&self) -> &str {
        &self.key_marker
    }

    /// Returns the exact provider upload-ID marker.
    #[must_use]
    pub const fn upload_id_marker(&self) -> &StoreS3MultipartUpload {
        &self.upload_id_marker
    }
}

/// One unfinished multipart upload returned by the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3MultipartUploadRecord {
    key: String,
    upload: StoreS3MultipartUpload,
}

impl StoreS3MultipartUploadRecord {
    /// Builds one bounded unfinished-upload record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] for an empty or oversized key.
    pub fn new(key: impl Into<String>, upload: StoreS3MultipartUpload) -> Result<Self, StoreError> {
        let key = key.into();
        validate_object_key(&key)?;
        Ok(Self { key, upload })
    }

    /// Returns the exact object key named by the upload.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the exact provider upload token.
    #[must_use]
    pub const fn upload(&self) -> &StoreS3MultipartUpload {
        &self.upload
    }
}

/// One bounded provider page of unfinished multipart uploads.
pub struct StoreS3MultipartListPage {
    uploads: Vec<StoreS3MultipartUploadRecord>,
    next: Option<StoreS3MultipartListCursor>,
}

impl StoreS3MultipartListPage {
    /// Validates one provider page against its requested item ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] when the requested bound is
    /// invalid, the provider exceeds it, or pagination cannot make progress.
    pub fn new(
        uploads: Vec<StoreS3MultipartUploadRecord>,
        next: Option<StoreS3MultipartListCursor>,
        after: Option<&StoreS3MultipartListCursor>,
        maximum_items: u16,
    ) -> Result<Self, StoreError> {
        let continuation_matches_last = next.as_ref().is_none_or(|next| {
            uploads.last().is_some_and(|last| {
                next.key_marker() == last.key() && next.upload_id_marker() == last.upload()
            })
        });
        if maximum_items == 0
            || maximum_items > MAX_S3_MULTIPART_LIST_ITEMS
            || uploads.len() > usize::from(maximum_items)
            || (next.is_some() && uploads.is_empty())
            || next
                .as_ref()
                .zip(after)
                .is_some_and(|(next, after)| next == after)
            || !continuation_matches_last
        {
            return Err(StoreError::Incompatible);
        }
        Ok(Self { uploads, next })
    }

    /// Returns the exact unfinished uploads in this page.
    #[must_use]
    pub fn uploads(&self) -> &[StoreS3MultipartUploadRecord] {
        &self.uploads
    }

    /// Returns the exact provider continuation, or `None` at observed EOF.
    #[must_use]
    pub const fn next(&self) -> Option<&StoreS3MultipartListCursor> {
        self.next.as_ref()
    }

    fn into_parts(
        self,
    ) -> (
        Vec<StoreS3MultipartUploadRecord>,
        Option<StoreS3MultipartListCursor>,
    ) {
        (self.uploads, self.next)
    }
}

/// Result of one bounded unfinished-upload cleanup page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreS3MultipartCleanupPage {
    aborted: u16,
    next: Option<StoreS3MultipartListCursor>,
}

impl StoreS3MultipartCleanupPage {
    /// Returns the number of uploads idempotently aborted by this call.
    #[must_use]
    pub const fn aborted(&self) -> u16 {
        self.aborted
    }

    /// Returns the exact provider continuation, or `None` at observed EOF.
    #[must_use]
    pub const fn next(&self) -> Option<&StoreS3MultipartListCursor> {
        self.next.as_ref()
    }
}

/// Synchronous bounded transport contract implemented by an S3 adapter.
///
/// Implementations must classify expired or rejected credentials as
/// [`StoreError::Unauthorized`], transient service/transport failures as
/// [`StoreError::Unavailable`], and malformed provider responses as
/// [`StoreError::Incompatible`]. Conditional methods must use the service's
/// `If-None-Match: *` equivalent and must never replace an existing key.
pub trait StoreS3Client: Send + Sync {
    /// Returns the exact non-secret endpoint policy bound to this client.
    fn endpoint_id(&self) -> &StoreS3EndpointId;

    /// Returns the exact object length, or `None` when the key is absent.
    ///
    /// # Errors
    ///
    /// Returns a classified credential, availability, or protocol error.
    fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StoreError>;

    /// Opens a complete object body.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] for absence or another classified
    /// backend error. Mid-stream failures are returned by the reader.
    fn get_object(&self, bucket: &str, key: &str) -> Result<StoreS3ObjectDownload, StoreError>;

    /// Conditionally publishes one empty object.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error without replacing an existing key.
    fn put_empty_if_absent(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError>;

    /// Begins one multipart upload for an absent-or-concurrently-created key.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when the upload cannot be admitted.
    fn begin_multipart(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoreS3MultipartUpload, StoreError>;

    /// Uploads one bounded part.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error. Exact retry with the same upload
    /// and part number must be idempotent.
    fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
        part_number: u32,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3UploadedPart, StoreError>;

    /// Conditionally completes one exact ordered part list.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error. Completion must use an atomic
    /// absent-key precondition and exact retry must be idempotent.
    fn complete_multipart_if_absent(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
        parts: &[StoreS3UploadedPart],
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError>;

    /// Idempotently aborts an incomplete multipart upload.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when cleanup cannot be confirmed.
    fn abort_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
    ) -> Result<(), StoreError>;

    /// Lists one bounded page of unfinished multipart uploads.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error when listing is unavailable or the
    /// provider cannot supply an exact resumable continuation.
    fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&StoreS3MultipartListCursor>,
        maximum_items: u16,
    ) -> Result<StoreS3MultipartListPage, StoreError>;
}

/// External S3 clients used while constructing one closed store graph.
#[derive(Default)]
pub struct StoreGraphS3Clients {
    clients: BTreeMap<StoreS3EndpointId, Arc<dyn StoreS3Client>>,
    administration: BTreeMap<StoreS3EndpointId, Arc<dyn StoreS3BlobAdminClient>>,
}

impl StoreGraphS3Clients {
    /// Creates an empty S3 capability collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            administration: BTreeMap::new(),
        }
    }

    /// Inserts one exact endpoint capability.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] for a duplicate identifier
    /// or [`StoreError::Unauthorized`] when the client's identity differs.
    pub fn insert(
        &mut self,
        endpoint: StoreS3EndpointId,
        client: Arc<dyn StoreS3Client>,
    ) -> Result<(), StoreError> {
        if client.endpoint_id() != &endpoint {
            return Err(StoreError::Unauthorized);
        }
        match self.clients.entry(endpoint) {
            Entry::Vacant(entry) => {
                entry.insert(client);
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::InvalidComposition {
                reason: "store S3 capability collection contains a duplicate identifier",
            }),
        }
    }

    pub(super) fn resolve(
        &self,
        endpoint: &StoreS3EndpointId,
    ) -> Result<Arc<dyn StoreS3Client>, StoreError> {
        self.clients
            .get(endpoint)
            .cloned()
            .ok_or(StoreError::Unauthorized)
    }

    /// Inserts separate committed-object administration for one endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] for a duplicate identifier
    /// or [`StoreError::Unauthorized`] when the client's identity differs.
    pub fn insert_administration(
        &mut self,
        endpoint: StoreS3EndpointId,
        client: Arc<dyn StoreS3BlobAdminClient>,
    ) -> Result<(), StoreError> {
        if client.endpoint_id() != &endpoint {
            return Err(StoreError::Unauthorized);
        }
        match self.administration.entry(endpoint) {
            Entry::Vacant(entry) => {
                entry.insert(client);
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::InvalidComposition {
                reason: "store S3 administration collection contains a duplicate identifier",
            }),
        }
    }

    pub(super) fn resolve_administration(
        &self,
        endpoint: &StoreS3EndpointId,
    ) -> Option<Arc<dyn StoreS3BlobAdminClient>> {
        self.administration.get(endpoint).cloned()
    }
}

#[cfg(test)]
mod tests;

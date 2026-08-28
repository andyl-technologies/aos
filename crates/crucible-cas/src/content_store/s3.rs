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

use super::{
    BackendCapabilities, BlobHandle, BlobSource, ByteRange, ContentId, ImmutableBlobBackend,
    PlacementReceipt, PutReceipt, StoreError, content_hasher, read_retry, validate_range,
    validate_source,
};

mod blob_admin;

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

/// Durable S3-compatible immutable-object leaf.
pub struct S3BlobBackend {
    name: String,
    endpoint: StoreS3EndpointId,
    bucket: String,
    prefix: String,
    maximum_logical_object_bytes: u64,
    multipart_part_bytes: u64,
    client: Arc<dyn StoreS3Client>,
    lifecycle: Arc<S3BlobLifecycle>,
    administration: Option<S3BlobAdministration>,
}

/// Separate bounded authority for reclaiming unfinished multipart uploads.
///
/// This capability is intentionally weaker than physical inventory/delete
/// administration. It neither lists committed objects nor fences concurrent
/// publication, and therefore cannot serve as a garbage-collection authority.
pub struct S3MultipartCleanupAdmin {
    bucket: String,
    object_prefix: String,
    client: Arc<dyn StoreS3Client>,
}

impl S3MultipartCleanupAdmin {
    /// Reclaims one bounded provider page under this exact object namespace.
    ///
    /// Exact retry is safe because abort is idempotent. The returned cursor is
    /// provider-owned and may be persisted by the maintenance owner to resume
    /// a long sweep without retaining an unbounded upload set in memory.
    ///
    /// # Errors
    ///
    /// Returns a classified credential, availability, or protocol error when
    /// the page cannot be listed or every named upload cannot be aborted.
    pub fn cleanup_page(
        &self,
        after: Option<&StoreS3MultipartListCursor>,
        maximum_items: u16,
    ) -> Result<StoreS3MultipartCleanupPage, StoreError> {
        if after.is_some_and(|cursor| !self.owns_object_key(cursor.key_marker())) {
            return Err(StoreError::Incompatible);
        }
        let page = self.client.list_multipart_uploads(
            &self.bucket,
            &self.object_prefix,
            after,
            maximum_items,
        )?;
        let (uploads, next) = page.into_parts();
        if uploads
            .iter()
            .any(|upload| !self.owns_object_key(upload.key()))
            || next
                .as_ref()
                .is_some_and(|cursor| !self.owns_object_key(cursor.key_marker()))
        {
            return Err(StoreError::Incompatible);
        }
        for upload in &uploads {
            self.client
                .abort_multipart(&self.bucket, upload.key(), upload.upload())?;
        }
        let aborted = u16::try_from(uploads.len()).map_err(|_| StoreError::Quota)?;
        Ok(StoreS3MultipartCleanupPage { aborted, next })
    }

    fn owns_object_key(&self, key: &str) -> bool {
        key.strip_prefix(&self.object_prefix)
            .and_then(|suffix| ContentId::parse(suffix).ok())
            .is_some()
    }
}

impl S3BlobBackend {
    /// Validates and constructs one exact S3 object namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when bucket, prefix, bounds,
    /// or endpoint binding are invalid.
    pub fn new(
        name: impl Into<String>,
        endpoint: StoreS3EndpointId,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        maximum_logical_object_bytes: u64,
        multipart_part_bytes: u64,
        client: Arc<dyn StoreS3Client>,
    ) -> Result<Self, StoreError> {
        Self::new_inner(
            name,
            endpoint,
            bucket,
            prefix,
            maximum_logical_object_bytes,
            multipart_part_bytes,
            client,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_inner(
        name: impl Into<String>,
        endpoint: StoreS3EndpointId,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        maximum_logical_object_bytes: u64,
        multipart_part_bytes: u64,
        client: Arc<dyn StoreS3Client>,
        admin_client: Option<Arc<dyn StoreS3BlobAdminClient>>,
    ) -> Result<Self, StoreError> {
        let name = name.into();
        let bucket = bucket.into();
        let prefix = prefix.into();
        validate_configuration(
            &endpoint,
            &bucket,
            &prefix,
            maximum_logical_object_bytes,
            multipart_part_bytes,
        )?;
        if client.endpoint_id() != &endpoint {
            return Err(StoreError::Unauthorized);
        }
        let administrative = admin_client.is_some();
        let lifecycle = admit_blob_namespace(
            &name,
            &endpoint,
            &bucket,
            &prefix,
            maximum_logical_object_bytes,
            administrative,
        )?;
        let administration = admin_client
            .map(|client| S3BlobAdministration::new(&endpoint, client))
            .transpose()?;
        Ok(Self {
            name,
            endpoint,
            bucket,
            prefix,
            maximum_logical_object_bytes,
            multipart_part_bytes,
            client,
            lifecycle,
            administration,
        })
    }

    /// Returns the exact non-secret endpoint policy.
    #[must_use]
    pub const fn endpoint_id(&self) -> &StoreS3EndpointId {
        &self.endpoint
    }

    pub(super) fn multipart_cleanup_admin(&self) -> S3MultipartCleanupAdmin {
        S3MultipartCleanupAdmin {
            bucket: self.bucket.clone(),
            object_prefix: self.object_prefix(),
            client: self.client.clone(),
        }
    }

    fn key(&self, id: ContentId) -> String {
        format!("{}{id}", self.object_prefix())
    }

    fn object_prefix(&self) -> String {
        if self.prefix.is_empty() {
            "objects/".to_string()
        } else {
            format!("{}/objects/", self.prefix)
        }
    }

    fn authenticate_existing(&self, id: ContentId) -> Result<PutReceipt, StoreError> {
        let handle = self.read(id, None)?;
        let logical_length = handle.logical_length();
        handle.copy_to(&mut io::sink())?;
        Ok(self.receipt(id, logical_length))
    }

    fn read_length(&self, id: ContentId) -> Result<u64, StoreError> {
        let key = self.key(id);
        let length = self
            .client
            .head_object(&self.bucket, &key)?
            .ok_or(StoreError::NotFound { id })?;
        if length > self.maximum_logical_object_bytes {
            return Err(StoreError::Corrupt { id });
        }
        Ok(length)
    }

    fn receipt(&self, id: ContentId, logical_length: u64) -> PutReceipt {
        PutReceipt::one(
            id,
            PlacementReceipt {
                backend: self.name.clone(),
                durable: true,
                logical_length,
            },
        )
    }

    fn upload_multipart(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
        let key = self.key(id);
        let upload = self.client.begin_multipart(&self.bucket, &key)?;
        let result = self.upload_multipart_inner(id, source, &key, &upload);
        match result {
            Ok(StoreS3ConditionalPutOutcome::Created) => Ok(StoreS3ConditionalPutOutcome::Created),
            Ok(StoreS3ConditionalPutOutcome::AlreadyExists) => {
                self.client
                    .abort_multipart(&self.bucket, &key, &upload)
                    .map_err(|_| StoreError::MultipartCleanupRequired)?;
                Ok(StoreS3ConditionalPutOutcome::AlreadyExists)
            }
            Err(error) => {
                if self
                    .client
                    .abort_multipart(&self.bucket, &key, &upload)
                    .is_err()
                {
                    Err(StoreError::MultipartCleanupRequired)
                } else {
                    Err(error)
                }
            }
        }
    }

    fn upload_multipart_inner(
        &self,
        id: ContentId,
        source: &BlobHandle,
        key: &str,
        upload: &StoreS3MultipartUpload,
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
        let logical_length = source.logical_length();
        let mut reader = source.open()?;
        let mut hasher = content_hasher(id.kind(), id.schema_version(), logical_length);
        let mut remaining = logical_length;
        let mut parts = Vec::new();
        let mut part_number = 1_u32;
        while remaining != 0 {
            if part_number > MAX_MULTIPART_PARTS {
                return Err(StoreError::Quota);
            }
            let wanted = usize::try_from(remaining.min(self.multipart_part_bytes))
                .map_err(|_| StoreError::Quota)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(wanted)
                .map_err(|_| StoreError::Quota)?;
            bytes.resize(wanted, 0);
            let mut offset = 0;
            while offset < wanted {
                let read = read_retry(&mut reader, &mut bytes[offset..]).map_err(|source| {
                    StoreError::StreamIo {
                        operation: "read-S3-multipart-source",
                        source,
                    }
                })?;
                if read == 0 {
                    return Err(StoreError::Corrupt { id });
                }
                offset += read;
            }
            hasher.update(&bytes);
            remaining -= wanted as u64;
            let part = self.client.upload_part(
                &self.bucket,
                key,
                upload,
                part_number,
                Arc::from(bytes),
            )?;
            if part.part_number() != part_number {
                return Err(StoreError::Incompatible);
            }
            parts.push(part);
            part_number = part_number.checked_add(1).ok_or(StoreError::Quota)?;
        }
        let mut extra = [0_u8; 1];
        if read_retry(&mut reader, &mut extra).map_err(|source| StoreError::StreamIo {
            operation: "verify-S3-multipart-source-length",
            source,
        })? != 0
            || *hasher.finalize().as_bytes() != id.digest()
        {
            return Err(StoreError::Corrupt { id });
        }
        self.client
            .complete_multipart_if_absent(&self.bucket, key, upload, &parts)
    }
}

impl ImmutableBlobBackend for S3BlobBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: self.administration.is_some(),
            planned_delete: self.administration.is_some(),
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        let Some(length) = self.client.head_object(&self.bucket, &self.key(id))? else {
            return Ok(false);
        };
        if length > self.maximum_logical_object_bytes {
            return Err(StoreError::Corrupt { id });
        }
        Ok(true)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let logical_length = self.read_length(id)?;
        if let Some(range) = range {
            validate_range(logical_length, range)?;
        }
        BlobHandle::integrity_checked(
            id,
            Arc::new(S3BlobSource {
                client: self.client.clone(),
                bucket: self.bucket.clone(),
                key: self.key(id),
                id,
                logical_length,
            }),
        )
        .slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let _publication = self.acquire_admin_publication_guard()?;
        let logical_length = source.logical_length();
        if logical_length > self.maximum_logical_object_bytes {
            return Err(StoreError::Quota);
        }
        validate_source(id, source)?;
        if self.contains(id)? {
            return self.authenticate_existing(id);
        }
        self.advance_admin_generation()?;
        let outcome = if logical_length == 0 {
            self.client
                .put_empty_if_absent(&self.bucket, &self.key(id))?
        } else {
            self.upload_multipart(id, source)?
        };
        match outcome {
            StoreS3ConditionalPutOutcome::Created => {
                self.authenticate_existing(id)?;
                Ok(self.receipt(id, logical_length))
            }
            StoreS3ConditionalPutOutcome::AlreadyExists => self.authenticate_existing(id),
        }
    }
}

struct S3BlobSource {
    client: Arc<dyn StoreS3Client>,
    bucket: String,
    key: String,
    id: ContentId,
    logical_length: u64,
}

impl BlobSource for S3BlobSource {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let download = self.client.get_object(&self.bucket, &self.key)?;
        let (logical_length, reader) = download.into_parts();
        if logical_length != self.logical_length {
            return Err(StoreError::Corrupt { id: self.id });
        }
        Ok(Box::new(AuthenticatingS3Reader {
            reader,
            id: self.id,
            remaining: logical_length,
            hasher: content_hasher(self.id.kind(), self.id.schema_version(), logical_length),
            finalized: false,
        }))
    }
}

struct AuthenticatingS3Reader {
    reader: Box<dyn Read + Send>,
    id: ContentId,
    remaining: u64,
    hasher: blake3::Hasher,
    finalized: bool,
}

impl Read for AuthenticatingS3Reader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        if self.remaining != 0 {
            let limit = usize::try_from(self.remaining.min(output.len() as u64))
                .map_err(|_| invalid_object_data())?;
            let read = read_retry(&mut self.reader, &mut output[..limit])?;
            if read == 0 {
                return Err(invalid_object_data());
            }
            self.hasher.update(&output[..read]);
            self.remaining -= read as u64;
            return Ok(read);
        }
        let mut extra = [0_u8; 1];
        if read_retry(&mut self.reader, &mut extra)? != 0
            || *self.hasher.finalize().as_bytes() != self.id.digest()
        {
            return Err(invalid_object_data());
        }
        self.finalized = true;
        Ok(0)
    }
}

fn invalid_object_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "content authentication failed")
}

fn validate_object_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() || key.len() > MAX_OBJECT_KEY_BYTES {
        return Err(StoreError::Incompatible);
    }
    Ok(())
}

pub(super) fn validate_configuration(
    _endpoint: &StoreS3EndpointId,
    bucket: &str,
    prefix: &str,
    maximum_logical_object_bytes: u64,
    multipart_part_bytes: u64,
) -> Result<(), StoreError> {
    let valid_bucket = (3..=MAX_BUCKET_BYTES).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    let valid_prefix = prefix.len() <= MAX_PREFIX_BYTES
        && !prefix.starts_with('/')
        && !prefix.ends_with('/')
        && (prefix.is_empty()
            || prefix.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.len() <= 255
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            }));
    let maximum_upload_bytes = multipart_part_bytes
        .checked_mul(u64::from(MAX_MULTIPART_PARTS))
        .ok_or(StoreError::InvalidComposition {
            reason: "store S3 multipart geometry overflows",
        })?;
    if !valid_bucket
        || !valid_prefix
        || maximum_logical_object_bytes == 0
        || !(MIN_MULTIPART_PART_BYTES..=MAX_MULTIPART_PART_BYTES).contains(&multipart_part_bytes)
        || maximum_logical_object_bytes > maximum_upload_bytes
    {
        return Err(StoreError::InvalidComposition {
            reason: "store S3 configuration is invalid",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::content_store::graph::{
        StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeKind, StoreNodeSpec,
    };
    use crate::content_store::{
        BlobStoreAdmin, ObjectKind, PlannedDeleteDisposition, StoreS3ConditionalWriteOutcome,
        StoreS3ObjectListCursor, StoreS3ObjectListPage, StoreS3ObjectScan, StoreS3ObjectVersion,
        StoreS3StrongCasClient, StoreS3VersionedObject, StoreS3VersionedObjectMetadata,
    };

    struct UploadState {
        bucket: String,
        key: String,
        parts: BTreeMap<u32, Arc<[u8]>>,
    }

    struct FakeS3Client {
        endpoint: StoreS3EndpointId,
        objects: Mutex<BTreeMap<(String, String), Arc<[u8]>>>,
        uploads: Mutex<BTreeMap<String, UploadState>>,
        next_upload: AtomicUsize,
        upload_parts: AtomicUsize,
        aborts: AtomicUsize,
        authorized: AtomicBool,
        fail_part: AtomicBool,
        fail_abort: AtomicBool,
        malformed_listing: AtomicBool,
    }

    impl FakeS3Client {
        fn new(endpoint: StoreS3EndpointId) -> Self {
            Self {
                endpoint,
                objects: Mutex::new(BTreeMap::new()),
                uploads: Mutex::new(BTreeMap::new()),
                next_upload: AtomicUsize::new(1),
                upload_parts: AtomicUsize::new(0),
                aborts: AtomicUsize::new(0),
                authorized: AtomicBool::new(true),
                fail_part: AtomicBool::new(false),
                fail_abort: AtomicBool::new(false),
                malformed_listing: AtomicBool::new(false),
            }
        }

        fn require_authorized(&self) -> Result<(), StoreError> {
            if self.authorized.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(StoreError::Unauthorized)
            }
        }

        fn corrupt_only_object(&self) {
            let mut objects = self.objects.lock().expect("object lock");
            let value = objects.values_mut().next().expect("stored object");
            let mut bytes = value.to_vec();
            bytes[0] ^= 0xff;
            *value = Arc::from(bytes);
        }
    }

    impl StoreS3Client for FakeS3Client {
        fn endpoint_id(&self) -> &StoreS3EndpointId {
            &self.endpoint
        }

        fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StoreError> {
            self.require_authorized()?;
            Ok(self
                .objects
                .lock()
                .expect("object lock")
                .get(&(bucket.to_string(), key.to_string()))
                .map(|bytes| bytes.len() as u64))
        }

        fn get_object(&self, bucket: &str, key: &str) -> Result<StoreS3ObjectDownload, StoreError> {
            self.require_authorized()?;
            let bytes = self
                .objects
                .lock()
                .expect("object lock")
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
                .ok_or_else(|| {
                    key.rsplit('/')
                        .next()
                        .and_then(|value| ContentId::parse(value).ok())
                        .map_or(StoreError::Incompatible, |id| StoreError::NotFound { id })
                })?;
            Ok(StoreS3ObjectDownload::new(
                bytes.len() as u64,
                Box::new(Cursor::new(bytes)),
            ))
        }

        fn put_empty_if_absent(
            &self,
            bucket: &str,
            key: &str,
        ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
            self.require_authorized()?;
            let mut objects = self.objects.lock().expect("object lock");
            let location = (bucket.to_string(), key.to_string());
            if let std::collections::btree_map::Entry::Vacant(entry) = objects.entry(location) {
                entry.insert(Arc::from([]));
                Ok(StoreS3ConditionalPutOutcome::Created)
            } else {
                Ok(StoreS3ConditionalPutOutcome::AlreadyExists)
            }
        }

        fn begin_multipart(
            &self,
            bucket: &str,
            key: &str,
        ) -> Result<StoreS3MultipartUpload, StoreError> {
            self.require_authorized()?;
            let token = format!("upload-{}", self.next_upload.fetch_add(1, Ordering::SeqCst));
            self.uploads.lock().expect("upload lock").insert(
                token.clone(),
                UploadState {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    parts: BTreeMap::new(),
                },
            );
            StoreS3MultipartUpload::new(token)
        }

        fn upload_part(
            &self,
            bucket: &str,
            key: &str,
            upload: &StoreS3MultipartUpload,
            part_number: u32,
            bytes: Arc<[u8]>,
        ) -> Result<StoreS3UploadedPart, StoreError> {
            self.require_authorized()?;
            if self.fail_part.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable);
            }
            let mut uploads = self.uploads.lock().expect("upload lock");
            let state = uploads
                .get_mut(upload.as_str())
                .ok_or(StoreError::Incompatible)?;
            if state.bucket != bucket || state.key != key {
                return Err(StoreError::Incompatible);
            }
            state.parts.insert(part_number, bytes);
            self.upload_parts.fetch_add(1, Ordering::SeqCst);
            StoreS3UploadedPart::new(part_number, format!("etag-{part_number}"))
        }

        fn complete_multipart_if_absent(
            &self,
            bucket: &str,
            key: &str,
            upload: &StoreS3MultipartUpload,
            parts: &[StoreS3UploadedPart],
        ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
            self.require_authorized()?;
            let location = (bucket.to_string(), key.to_string());
            if self
                .objects
                .lock()
                .expect("object lock")
                .contains_key(&location)
            {
                return Ok(StoreS3ConditionalPutOutcome::AlreadyExists);
            }
            let state = self
                .uploads
                .lock()
                .expect("upload lock")
                .remove(upload.as_str())
                .ok_or(StoreError::Incompatible)?;
            if state.bucket != bucket || state.key != key || parts.len() != state.parts.len() {
                return Err(StoreError::Incompatible);
            }
            let mut bytes = Vec::new();
            for (index, part) in parts.iter().enumerate() {
                let expected = u32::try_from(index + 1).map_err(|_| StoreError::Quota)?;
                if part.part_number() != expected
                    || part.provider_tag() != format!("etag-{expected}")
                {
                    return Err(StoreError::Incompatible);
                }
                bytes
                    .extend_from_slice(state.parts.get(&expected).ok_or(StoreError::Incompatible)?);
            }
            self.objects
                .lock()
                .expect("object lock")
                .insert(location, Arc::from(bytes));
            Ok(StoreS3ConditionalPutOutcome::Created)
        }

        fn abort_multipart(
            &self,
            _bucket: &str,
            _key: &str,
            upload: &StoreS3MultipartUpload,
        ) -> Result<(), StoreError> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            if self.fail_abort.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable);
            }
            self.uploads
                .lock()
                .expect("upload lock")
                .remove(upload.as_str());
            Ok(())
        }

        fn list_multipart_uploads(
            &self,
            bucket: &str,
            prefix: &str,
            after: Option<&StoreS3MultipartListCursor>,
            maximum_items: u16,
        ) -> Result<StoreS3MultipartListPage, StoreError> {
            self.require_authorized()?;
            if maximum_items == 0 || maximum_items > MAX_S3_MULTIPART_LIST_ITEMS {
                return Err(StoreError::Incompatible);
            }
            let mut matching = self
                .uploads
                .lock()
                .expect("upload lock")
                .iter()
                .filter(|(_, state)| state.bucket == bucket && state.key.starts_with(prefix))
                .map(|(upload, state)| (state.key.clone(), upload.clone()))
                .collect::<Vec<_>>();
            matching.sort();
            if self.malformed_listing.load(Ordering::SeqCst)
                && let Some((key, _)) = matching.first_mut()
            {
                *key = "other/objects/not-a-content-id".to_string();
            }
            if let Some(after) = after {
                matching.retain(|(key, upload)| {
                    (key.as_str(), upload.as_str())
                        > (after.key_marker(), after.upload_id_marker().as_str())
                });
            }
            let truncated = matching.len() > usize::from(maximum_items);
            matching.truncate(usize::from(maximum_items));
            let next = if truncated {
                let (key, upload) = matching.last().ok_or(StoreError::Incompatible)?;
                Some(StoreS3MultipartListCursor::new(
                    key.clone(),
                    StoreS3MultipartUpload::new(upload.clone())?,
                )?)
            } else {
                None
            };
            let uploads = matching
                .into_iter()
                .map(|(key, upload)| {
                    Ok(StoreS3MultipartUploadRecord::new(
                        key,
                        StoreS3MultipartUpload::new(upload)?,
                    )?)
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            StoreS3MultipartListPage::new(uploads, next, after, maximum_items)
        }
    }

    struct FakeBlobAdminClient {
        ordinary: Arc<FakeS3Client>,
        state: Mutex<BTreeMap<(String, String), (Arc<[u8]>, u64)>>,
        next_version: AtomicU64,
        malformed_scan: AtomicBool,
        force_delete_conflict: AtomicBool,
    }

    impl FakeBlobAdminClient {
        fn new(ordinary: Arc<FakeS3Client>) -> Self {
            Self {
                ordinary,
                state: Mutex::new(BTreeMap::new()),
                next_version: AtomicU64::new(1),
                malformed_scan: AtomicBool::new(false),
                force_delete_conflict: AtomicBool::new(false),
            }
        }

        fn next_version(&self) -> (u64, StoreS3ObjectVersion) {
            let version = self.next_version.fetch_add(1, Ordering::SeqCst);
            (
                version,
                StoreS3ObjectVersion::new(format!("state-{version}")).expect("state version"),
            )
        }

        fn ordinary_version(bytes: &[u8]) -> StoreS3ObjectVersion {
            StoreS3ObjectVersion::new(format!("object-{}", blake3::hash(bytes).to_hex()))
                .expect("object version")
        }

        fn metadata(
            &self,
            bucket: &str,
            key: &str,
        ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
            self.ordinary.require_authorized()?;
            if let Some((bytes, version)) = self
                .state
                .lock()
                .expect("state lock")
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
            {
                return Ok(Some(StoreS3VersionedObjectMetadata::new(
                    bytes.len() as u64,
                    StoreS3ObjectVersion::new(format!("state-{version}"))?,
                )));
            }
            Ok(self
                .ordinary
                .objects
                .lock()
                .expect("object lock")
                .get(&(bucket.to_string(), key.to_string()))
                .map(|bytes| {
                    StoreS3VersionedObjectMetadata::new(
                        bytes.len() as u64,
                        Self::ordinary_version(bytes),
                    )
                }))
        }
    }

    impl StoreS3StrongCasClient for FakeBlobAdminClient {
        fn endpoint_id(&self) -> &StoreS3EndpointId {
            &self.ordinary.endpoint
        }

        fn get_small_versioned_object(
            &self,
            bucket: &str,
            key: &str,
            maximum_bytes: u16,
        ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
            self.ordinary.require_authorized()?;
            self.state
                .lock()
                .expect("state lock")
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
                .map(|(bytes, version)| {
                    if bytes.len() > usize::from(maximum_bytes) {
                        return Err(StoreError::Quota);
                    }
                    StoreS3VersionedObject::new(
                        bytes,
                        StoreS3ObjectVersion::new(format!("state-{version}"))?,
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
            self.ordinary.require_authorized()?;
            let mut state = self.state.lock().expect("state lock");
            match state.entry((bucket.to_string(), key.to_string())) {
                Entry::Occupied(_) => Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed),
                Entry::Vacant(entry) => {
                    let (version, token) = self.next_version();
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
            self.ordinary.require_authorized()?;
            let mut state = self.state.lock().expect("state lock");
            let Some((current, version)) = state.get_mut(&(bucket.to_string(), key.to_string()))
            else {
                return Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed);
            };
            if expected.as_str() != format!("state-{version}") {
                return Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed);
            }
            let (next, token) = self.next_version();
            *current = bytes;
            *version = next;
            Ok(StoreS3ConditionalWriteOutcome::Committed(token))
        }

        fn begin_small_object_scan(
            &self,
            bucket: &str,
            prefix: &str,
        ) -> Result<Box<dyn StoreS3ObjectScan + '_>, StoreError> {
            self.ordinary.require_authorized()?;
            Ok(Box::new(FakeBlobAdminScan {
                client: self,
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
                after: None,
                finished: false,
            }))
        }
    }

    impl StoreS3BlobAdminClient for FakeBlobAdminClient {
        fn head_versioned_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
            self.metadata(bucket, key)
        }

        fn delete_object_if_version(
            &self,
            bucket: &str,
            key: &str,
            expected: &StoreS3ObjectVersion,
        ) -> Result<StoreS3ConditionalDeleteOutcome, StoreError> {
            self.ordinary.require_authorized()?;
            if self.force_delete_conflict.load(Ordering::SeqCst) {
                return Ok(StoreS3ConditionalDeleteOutcome::PreconditionFailed);
            }
            let mut objects = self.ordinary.objects.lock().expect("object lock");
            let location = (bucket.to_string(), key.to_string());
            let Some(bytes) = objects.get(&location) else {
                return Ok(StoreS3ConditionalDeleteOutcome::Deleted);
            };
            if &Self::ordinary_version(bytes) != expected {
                return Ok(StoreS3ConditionalDeleteOutcome::PreconditionFailed);
            }
            objects.remove(&location);
            Ok(StoreS3ConditionalDeleteOutcome::Deleted)
        }
    }

    struct FakeBlobAdminScan<'a> {
        client: &'a FakeBlobAdminClient,
        bucket: String,
        prefix: String,
        after: Option<StoreS3ObjectListCursor>,
        finished: bool,
    }

    impl StoreS3ObjectScan for FakeBlobAdminScan<'_> {
        fn next_page(&mut self, maximum_items: u16) -> Result<StoreS3ObjectListPage, StoreError> {
            if self.finished {
                return Err(StoreError::Incompatible);
            }
            let mut keys = self
                .client
                .ordinary
                .objects
                .lock()
                .expect("object lock")
                .keys()
                .filter(|(bucket, key)| bucket == &self.bucket && key.starts_with(&self.prefix))
                .map(|(_bucket, key)| key.clone())
                .filter(|key| {
                    self.after
                        .as_ref()
                        .is_none_or(|after| key.as_str() > after.as_str())
                })
                .collect::<Vec<_>>();
            keys.sort();
            if self.client.malformed_scan.load(Ordering::SeqCst) && !keys.is_empty() {
                keys[0] = "foreign/not-a-content-id".to_string();
            }
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

        fn head_versioned_object(
            &self,
            key: &str,
        ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
            self.client.metadata(&self.bucket, key)
        }
    }

    fn administrative_backend(
        ordinary: Arc<FakeS3Client>,
        administration: Arc<FakeBlobAdminClient>,
    ) -> S3BlobBackend {
        S3BlobBackend::new_with_admin(
            "archive-admin",
            ordinary.endpoint.clone(),
            "campaign-archive",
            "tenant-admin",
            12 * 1024 * 1024,
            5 * 1024 * 1024,
            ordinary,
            administration,
        )
        .expect("administrative S3 backend")
    }

    fn backend(client: Arc<FakeS3Client>) -> S3BlobBackend {
        S3BlobBackend::new(
            "archive",
            client.endpoint.clone(),
            "campaign-archive",
            "tenant-a",
            12 * 1024 * 1024,
            5 * 1024 * 1024,
            client,
        )
        .expect("S3 backend")
    }

    #[test]
    fn s3_blob_leaf_passes_the_shared_persistent_conformance_suite() {
        let endpoint = StoreS3EndpointId::new("minio/blob-conformance").expect("endpoint");
        let ordinary = Arc::new(FakeS3Client::new(endpoint));
        let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
        let backend = administrative_backend(ordinary, administration);
        super::super::conformance::assert_blob_leaf_conformance(&backend);
    }

    #[test]
    fn committed_inventory_is_restart_stable_aba_safe_and_deletable() {
        let endpoint = StoreS3EndpointId::new("minio/administration").expect("endpoint");
        let ordinary = Arc::new(FakeS3Client::new(endpoint));
        let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
        let backend = administrative_backend(ordinary.clone(), administration.clone());
        let first_bytes = b"first object".to_vec();
        let second_bytes = b"second object".to_vec();
        let first = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &first_bytes);
        let second = ContentId::for_bytes(ObjectKind::Observation, 1, &second_bytes);
        backend
            .put_if_absent(first, &BlobHandle::from_bytes(first_bytes.clone()))
            .expect("put first object");

        let mut initial_records = Vec::new();
        let initial = backend
            .acquire_inventory_fence()
            .expect("initial inventory fence")
            .visit_inventory(&mut |record| {
                initial_records.push(record);
                Ok(())
            })
            .expect("initial inventory");
        assert_eq!(initial.objects(), 1);
        assert_eq!(initial.logical_bytes(), first_bytes.len() as u64);
        assert_eq!(initial_records[0].id(), first);

        backend
            .put_if_absent(first, &BlobHandle::from_bytes(first_bytes.clone()))
            .expect("exact replay");
        let after_replay = backend
            .acquire_inventory_fence()
            .expect("replay inventory fence")
            .visit_inventory(&mut |_record| Ok(()))
            .expect("replay inventory");
        assert_eq!(after_replay, initial);

        let restarted = administrative_backend(ordinary, administration);
        let after_restart = restarted
            .acquire_inventory_fence()
            .expect("restart inventory fence")
            .visit_inventory(&mut |_record| Ok(()))
            .expect("restart inventory");
        assert_eq!(after_restart, initial);

        let mut deletion = restarted.acquire_inventory_fence().expect("deletion fence");
        assert_eq!(
            deletion.delete_candidate(first).expect("delete first"),
            PlannedDeleteDisposition::Deleted
        );
        assert_eq!(
            deletion.delete_candidate(first).expect("retry deletion"),
            PlannedDeleteDisposition::AlreadyAbsent
        );
        drop(deletion);

        restarted
            .put_if_absent(first, &BlobHandle::from_bytes(first_bytes))
            .expect("restore first object after ABA");
        restarted
            .put_if_absent(second, &BlobHandle::from_bytes(second_bytes))
            .expect("put second object");
        let restored = restarted
            .acquire_inventory_fence()
            .expect("restored inventory fence")
            .visit_inventory(&mut |_record| Ok(()))
            .expect("restored inventory");
        assert_ne!(restored.generation(), initial.generation());
        assert_eq!(restored.objects(), 2);
    }

    #[test]
    fn committed_inventory_fails_closed_on_stale_delete_and_bad_listing() {
        let endpoint = StoreS3EndpointId::new("minio/admin-fail-closed").expect("endpoint");
        let ordinary = Arc::new(FakeS3Client::new(endpoint));
        let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
        let backend = administrative_backend(ordinary, administration.clone());
        let bytes = b"retained object";
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .expect("put object");

        administration
            .force_delete_conflict
            .store(true, Ordering::SeqCst);
        let mut fence = backend
            .acquire_inventory_fence()
            .expect("stale-delete fence");
        assert!(matches!(
            fence.delete_candidate(id),
            Err(StoreError::Incompatible)
        ));
        drop(fence);
        assert!(backend.contains(id).expect("object retained"));

        administration
            .force_delete_conflict
            .store(false, Ordering::SeqCst);
        administration.malformed_scan.store(true, Ordering::SeqCst);
        let mut malformed = backend
            .acquire_inventory_fence()
            .expect("malformed inventory fence");
        assert!(matches!(
            malformed.visit_inventory(&mut |_record| Ok(())),
            Err(StoreError::Incompatible)
        ));
        drop(malformed);

        administration.malformed_scan.store(false, Ordering::SeqCst);
        administration
            .ordinary
            .authorized
            .store(false, Ordering::SeqCst);
        assert!(matches!(
            backend.acquire_inventory_fence(),
            Err(StoreError::Unauthorized)
        ));
    }

    #[test]
    fn committed_inventory_excludes_cross_instance_publication() {
        let endpoint = StoreS3EndpointId::new("minio/admin-publication").expect("endpoint");
        let ordinary = Arc::new(FakeS3Client::new(endpoint));
        let administration = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
        let inventor = administrative_backend(ordinary.clone(), administration.clone());
        let publisher = administrative_backend(ordinary, administration);
        let fence = inventor.acquire_inventory_fence().expect("inventory fence");
        let bytes = b"blocked publication".to_vec();
        let id = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &bytes);
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (finished_sender, finished_receiver) = mpsc::sync_channel(1);
        let publisher_thread = thread::spawn(move || {
            started_sender.send(()).expect("announce publication");
            let result = publisher.put_if_absent(id, &BlobHandle::from_bytes(bytes));
            finished_sender
                .send(result)
                .expect("return publication result");
        });
        started_receiver.recv().expect("publication started");
        assert!(
            finished_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err()
        );
        drop(fence);
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("publication unblocked")
            .expect("publication result");
        publisher_thread.join().expect("publisher thread");
    }

    #[test]
    fn multipart_round_trip_ranges_replay_and_corruption_are_authenticated() {
        let endpoint = StoreS3EndpointId::new("minio/archive").expect("endpoint");
        let client = Arc::new(FakeS3Client::new(endpoint));
        let backend = backend(client.clone());
        let mut bytes = vec![0x31; 5 * 1024 * 1024 + 137];
        bytes[5 * 1024 * 1024 + 1] = 0x92;
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);

        let receipt = backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
            .expect("multipart put");
        assert!(receipt.is_durable());
        assert_eq!(client.upload_parts.load(Ordering::SeqCst), 2);
        assert_eq!(
            backend
                .read(
                    id,
                    Some(ByteRange::new(5 * 1024 * 1024 - 2, 8).expect("range"))
                )
                .expect("range handle")
                .read_all(8)
                .expect("authenticated range"),
            bytes[5 * 1024 * 1024 - 2..5 * 1024 * 1024 + 6]
        );

        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("exact replay");
        assert_eq!(client.upload_parts.load(Ordering::SeqCst), 2);

        client.corrupt_only_object();
        assert!(matches!(
            backend
                .read(id, None)
                .expect("deferred corrupt handle")
                .copy_to(&mut io::sink()),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn interrupted_upload_aborts_and_failed_abort_is_explicit() {
        let endpoint = StoreS3EndpointId::new("minio/interruption").expect("endpoint");
        let client = Arc::new(FakeS3Client::new(endpoint));
        let backend = backend(client.clone());
        let bytes = vec![0x44; 5 * 1024 * 1024 + 1];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        client.fail_part.store(true, Ordering::SeqCst);

        assert!(matches!(
            backend.put_if_absent(id, &BlobHandle::from_bytes(bytes.clone())),
            Err(StoreError::Unavailable)
        ));
        assert_eq!(client.aborts.load(Ordering::SeqCst), 1);
        assert!(!backend.contains(id).expect("absent interrupted object"));

        client.fail_abort.store(true, Ordering::SeqCst);
        assert!(matches!(
            backend.put_if_absent(id, &BlobHandle::from_bytes(bytes)),
            Err(StoreError::MultipartCleanupRequired)
        ));
        assert_eq!(client.aborts.load(Ordering::SeqCst), 2);

        client.fail_abort.store(false, Ordering::SeqCst);
        let cleanup = backend
            .multipart_cleanup_admin()
            .cleanup_page(None, 1)
            .expect("reclaim retained upload");
        assert_eq!(cleanup.aborted(), 1);
        assert!(cleanup.next().is_none());
        assert!(client.uploads.lock().expect("upload lock").is_empty());
    }

    #[test]
    fn multipart_cleanup_is_bounded_resumable_and_namespace_scoped() {
        let endpoint = StoreS3EndpointId::new("minio/cleanup").expect("endpoint");
        let client = Arc::new(FakeS3Client::new(endpoint));
        let backend = backend(client.clone());
        let ids = [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
            .map(|bytes| ContentId::for_bytes(ObjectKind::Trace, 1, bytes));
        let mut keys = ids
            .map(|id| format!("tenant-a/objects/{id}"))
            .into_iter()
            .collect::<Vec<_>>();
        keys.push(format!("tenant-b/objects/{}", ids[0]));
        for key in &keys {
            client
                .begin_multipart("campaign-archive", key)
                .expect("unfinished upload");
        }

        let admin = backend.multipart_cleanup_admin();
        client.malformed_listing.store(true, Ordering::SeqCst);
        assert!(matches!(
            admin.cleanup_page(None, 2),
            Err(StoreError::Incompatible)
        ));
        assert_eq!(client.aborts.load(Ordering::SeqCst), 0);
        client.malformed_listing.store(false, Ordering::SeqCst);

        let first = admin.cleanup_page(None, 2).expect("first cleanup page");
        assert_eq!(first.aborted(), 2);
        let second = admin
            .cleanup_page(first.next(), 2)
            .expect("second cleanup page");
        assert_eq!(second.aborted(), 1);
        assert!(second.next().is_none());
        let uploads = client.uploads.lock().expect("upload lock");
        assert_eq!(uploads.len(), 1);
        assert_eq!(
            uploads.values().next().expect("foreign upload").key,
            keys[3]
        );
    }

    #[test]
    fn credential_expiry_and_configuration_bounds_fail_closed() {
        let endpoint = StoreS3EndpointId::new("minio/credentials").expect("endpoint");
        let client = Arc::new(FakeS3Client::new(endpoint.clone()));
        let backend = backend(client.clone());
        let bytes = b"credential-bound object";
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        client.authorized.store(false, Ordering::SeqCst);
        assert!(matches!(
            backend.contains(id),
            Err(StoreError::Unauthorized)
        ));
        assert!(matches!(
            S3BlobBackend::new(
                "invalid",
                endpoint.clone(),
                "ab",
                "bad//prefix",
                1,
                1,
                client.clone(),
            ),
            Err(StoreError::InvalidComposition { .. })
        ));
        let maximum_prefix = format!(
            "{}/{}/{}/{}",
            "a".repeat(255),
            "b".repeat(255),
            "c".repeat(255),
            "d".repeat(154)
        );
        assert_eq!(maximum_prefix.len(), MAX_PREFIX_BYTES);
        let longest_id = ContentId::for_bytes(ObjectKind::CampaignSnapshot, u32::MAX, b"");
        assert_eq!(longest_id.encode().len(), MAX_CONTENT_ID_TEXT_BYTES);
        assert_eq!(
            format!("{maximum_prefix}/objects/{longest_id}").len(),
            MAX_OBJECT_KEY_BYTES
        );
        assert!(
            S3BlobBackend::new(
                "maximum-prefix",
                endpoint.clone(),
                "valid-bucket",
                maximum_prefix.clone(),
                5 * 1024 * 1024,
                5 * 1024 * 1024,
                client.clone(),
            )
            .is_ok()
        );
        let oversized_prefix = format!("{maximum_prefix}e");
        assert!(matches!(
            S3BlobBackend::new(
                "oversized-prefix",
                endpoint,
                "valid-bucket",
                oversized_prefix,
                5 * 1024 * 1024,
                5 * 1024 * 1024,
                client,
            ),
            Err(StoreError::InvalidComposition { .. })
        ));
    }

    #[test]
    fn graph_binds_exact_endpoint_capability_and_canonical_configuration() {
        let endpoint = StoreS3EndpointId::new("minio/graph").expect("endpoint");
        let client = Arc::new(FakeS3Client::new(endpoint.clone()));
        let administration = Arc::new(FakeBlobAdminClient::new(client.clone()));
        let mut clients = StoreGraphS3Clients::new();
        clients
            .insert(endpoint.clone(), client)
            .expect("S3 capability");
        let root = StoreNodeId::new("archive").expect("node");
        let config = StoreGraphConfig {
            root: root.clone(),
            admitted_kinds: std::collections::BTreeSet::from([ObjectKind::Finding]),
            nodes: BTreeMap::from([(
                root,
                StoreNodeSpec::S3 {
                    endpoint,
                    bucket: "campaign-archive".to_string(),
                    prefix: "tenant-a".to_string(),
                    maximum_logical_object_bytes: 12 * 1024 * 1024,
                    multipart_part_bytes: 5 * 1024 * 1024,
                },
            )]),
        };
        assert!(matches!(
            StoreGraph::build(config.clone()),
            Err(StoreError::Unauthorized)
        ));
        let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
            config.clone(),
            &super::super::StoreGraphKeyring::new(),
            &super::super::StoreGraphNamespaceAuthorizers::new(),
            &super::super::StoreGraphObjectProfilers::new(),
            &super::super::StoreGraphPhysicalQuotaBinders::new(),
            &clients,
        )
        .expect("S3 graph");
        assert_eq!(graph.describe()[0].kind, StoreNodeKind::S3);
        assert!(admin.physical().is_empty());
        assert_eq!(admin.s3_multipart_cleanup().len(), 1);
        assert_eq!(admin.s3_multipart_cleanup()[0].node().as_str(), "archive");
        assert_eq!(
            super::super::encode_hex(&graph.configuration_id().as_bytes()),
            "09019301ef9ff104a49cf0a9e44b2b6c016daf668888ebff0575ceb9f8181342"
        );

        clients
            .insert_administration(
                StoreS3EndpointId::new("minio/graph").expect("admin endpoint"),
                administration,
            )
            .expect("S3 administration capability");
        assert!(matches!(
            StoreGraph::build_with_admin_and_all_capabilities(
                config.clone(),
                &super::super::StoreGraphKeyring::new(),
                &super::super::StoreGraphNamespaceAuthorizers::new(),
                &super::super::StoreGraphObjectProfilers::new(),
                &super::super::StoreGraphPhysicalQuotaBinders::new(),
                &clients,
            ),
            Err(StoreError::InvalidComposition { .. })
        ));
        drop(graph);
        drop(admin);
        let (_graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
            config,
            &super::super::StoreGraphKeyring::new(),
            &super::super::StoreGraphNamespaceAuthorizers::new(),
            &super::super::StoreGraphObjectProfilers::new(),
            &super::super::StoreGraphPhysicalQuotaBinders::new(),
            &clients,
        )
        .expect("administrable S3 graph");
        assert_eq!(admin.physical().len(), 1);
        assert_eq!(admin.physical()[0].node().as_str(), "archive");
        assert_eq!(admin.s3_multipart_cleanup().len(), 1);
    }
}

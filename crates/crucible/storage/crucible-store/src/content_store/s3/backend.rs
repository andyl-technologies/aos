//! S3 immutable-object backend and multipart cleanup authority.

use super::*;

/// Namespace and transfer policy for one S3 immutable-object backend.
pub struct S3BlobBackendConfig {
    name: String,
    endpoint: StoreS3EndpointId,
    bucket: String,
    prefix: String,
    maximum_logical_object_bytes: u64,
    multipart_part_bytes: u64,
}

impl S3BlobBackendConfig {
    /// Collects the namespace identity and hard object-transfer bounds.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        endpoint: StoreS3EndpointId,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        maximum_logical_object_bytes: u64,
        multipart_part_bytes: u64,
    ) -> Self {
        Self {
            name: name.into(),
            endpoint,
            bucket: bucket.into(),
            prefix: prefix.into(),
            maximum_logical_object_bytes,
            multipart_part_bytes,
        }
    }
}

/// Durable S3-compatible immutable-object leaf.
pub struct S3BlobBackend {
    pub(super) name: String,
    endpoint: StoreS3EndpointId,
    pub(super) bucket: String,
    pub(super) prefix: String,
    pub(super) maximum_logical_object_bytes: u64,
    multipart_part_bytes: u64,
    pub(super) client: Arc<dyn StoreS3Client>,
    pub(super) lifecycle: Arc<S3BlobLifecycle>,
    pub(super) administration: Option<S3BlobAdministration>,
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
        config: S3BlobBackendConfig,
        client: Arc<dyn StoreS3Client>,
    ) -> Result<Self, StoreError> {
        Self::new_inner(config, client, None)
    }

    pub(super) fn new_inner(
        config: S3BlobBackendConfig,
        client: Arc<dyn StoreS3Client>,
        admin_client: Option<Arc<dyn StoreS3BlobAdminClient>>,
    ) -> Result<Self, StoreError> {
        let S3BlobBackendConfig {
            name,
            endpoint,
            bucket,
            prefix,
            maximum_logical_object_bytes,
            multipart_part_bytes,
        } = config;
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

    pub(in crate::content_store) fn multipart_cleanup_admin(&self) -> S3MultipartCleanupAdmin {
        S3MultipartCleanupAdmin {
            bucket: self.bucket.clone(),
            object_prefix: self.object_prefix(),
            client: self.client.clone(),
        }
    }

    pub(super) fn key(&self, id: ContentId) -> String {
        format!("{}{id}", self.object_prefix())
    }

    pub(super) fn object_prefix(&self) -> String {
        if self.prefix.is_empty() {
            "objects/".to_string()
        } else {
            format!("{}/objects/", self.prefix)
        }
    }

    pub(super) fn authenticate_existing(&self, id: ContentId) -> Result<PutReceipt, StoreError> {
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

    pub(super) fn receipt(&self, id: ContentId, logical_length: u64) -> PutReceipt {
        PutReceipt::one(
            id,
            PlacementReceipt {
                backend: self.name.clone(),
                durable: true,
                logical_length,
            },
        )
    }

    pub(super) fn upload_multipart(
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
            #[cfg(feature = "destructive-recovery-faults")]
            // Inject the missing-leaf failure only after the remote upload has a partial effect.
            inject_multipart_remove_leaf(id, part_number)?;
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

#[cfg(feature = "destructive-recovery-faults")]
fn inject_multipart_remove_leaf(id: ContentId, part_number: u32) -> Result<(), StoreError> {
    if part_number != 1 {
        return Ok(());
    }
    let requested = std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT);
    if requested.as_deref() != Some(std::ffi::OsStr::new(MULTIPART_REMOVE_LEAF_TRIGGER))
        || MULTIPART_REMOVE_LEAF_TRIGGERED.swap(true, Ordering::AcqRel)
    {
        return Ok(());
    }

    Err(StoreError::NotFound { id })
}

#[cfg(feature = "destructive-recovery-faults")]
fn inject_store_credential_expiry() -> Result<(), StoreError> {
    let requested = std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT);
    if requested.as_deref() != Some(std::ffi::OsStr::new(STORE_CREDENTIAL_EXPIRY_TRIGGER))
        || STORE_CREDENTIAL_EXPIRY_TRIGGERED.swap(true, Ordering::AcqRel)
    {
        return Ok(());
    }

    Err(StoreError::Unauthorized)
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
        #[cfg(feature = "destructive-recovery-faults")]
        // Fail before provider lookup so denied access cannot be mistaken for absence.
        inject_store_credential_expiry()?;
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

pub(super) fn validate_object_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() || key.len() > MAX_OBJECT_KEY_BYTES {
        return Err(StoreError::Incompatible);
    }
    Ok(())
}

pub(in crate::content_store) fn validate_configuration(
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

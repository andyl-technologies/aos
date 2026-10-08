//! S3 client fixtures shared by the backend behavior tests.

use std::collections::BTreeMap;
use std::fmt::Debug;
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
    BlobStoreAdmin, ObjectKind, PlannedDeleteDisposition, StoreGraphKeyring,
    StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders,
    StoreS3ConditionalWriteOutcome, StoreS3ObjectListCursor, StoreS3ObjectListPage,
    StoreS3ObjectScan, StoreS3ObjectVersion, StoreS3StrongCasClient, StoreS3VersionedObject,
    StoreS3VersionedObjectMetadata, conformance, encode_hex,
};

type ObjectLocation = (String, String);
type ObjectBytes = Arc<[u8]>;
type ObjectMap = BTreeMap<ObjectLocation, ObjectBytes>;
type VersionedObjectMap = BTreeMap<ObjectLocation, (ObjectBytes, u64)>;

trait FixtureValue<T> {
    fn assert_value(self, context: &str) -> T;
}

impl<T, E> FixtureValue<T> for Result<T, E>
where
    E: Debug,
{
    fn assert_value(self, context: &str) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }
}

impl<T> FixtureValue<T> for Option<T> {
    fn assert_value(self, context: &str) -> T {
        match self {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }
}

#[cfg(feature = "destructive-recovery-faults")]
const MULTIPART_REMOVE_LEAF_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_MULTIPART_REMOVE_LEAF_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const MULTIPART_REMOVE_LEAF_TEST_NAME: &str = "content_store::s3::tests::behavior::multipart_remove_leaf_aborts_before_completion_and_retries";
#[cfg(feature = "destructive-recovery-faults")]
const MULTIPART_REMOVE_LEAF_CHILD_EXIT_CODE: i32 = 88;
#[cfg(feature = "destructive-recovery-faults")]
const STORE_CREDENTIAL_EXPIRY_CHILD_ENVIRONMENT: &str =
    "CRUCIBLE_DESTRUCTIVE_RECOVERY_STORE_CREDENTIAL_EXPIRY_CHILD";
#[cfg(feature = "destructive-recovery-faults")]
const STORE_CREDENTIAL_EXPIRY_TEST_NAME: &str = "content_store::s3::tests::behavior::credential_expiry_preserves_identity_and_authenticated_retry";
#[cfg(feature = "destructive-recovery-faults")]
const STORE_CREDENTIAL_EXPIRY_CHILD_EXIT_CODE: i32 = 89;

struct UploadState {
    bucket: String,
    key: String,
    parts: BTreeMap<u32, Arc<[u8]>>,
}

struct FakeS3Client {
    endpoint: StoreS3EndpointId,
    objects: Mutex<ObjectMap>,
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
        let mut objects = self.objects.lock().assert_value("object lock");
        let value = objects.values_mut().next().assert_value("stored object");
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
            .assert_value("object lock")
            .get(&(bucket.to_string(), key.to_string()))
            .map(|bytes| bytes.len() as u64))
    }

    fn get_object(&self, bucket: &str, key: &str) -> Result<StoreS3ObjectDownload, StoreError> {
        self.require_authorized()?;
        let bytes = self
            .objects
            .lock()
            .assert_value("object lock")
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
        let mut objects = self.objects.lock().assert_value("object lock");
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
        self.uploads.lock().assert_value("upload lock").insert(
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
        let mut uploads = self.uploads.lock().assert_value("upload lock");
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
            .assert_value("object lock")
            .contains_key(&location)
        {
            return Ok(StoreS3ConditionalPutOutcome::AlreadyExists);
        }
        let state = self
            .uploads
            .lock()
            .assert_value("upload lock")
            .remove(upload.as_str())
            .ok_or(StoreError::Incompatible)?;
        if state.bucket != bucket || state.key != key || parts.len() != state.parts.len() {
            return Err(StoreError::Incompatible);
        }
        let mut bytes = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| StoreError::Quota)?;
            if part.part_number() != expected || part.provider_tag() != format!("etag-{expected}") {
                return Err(StoreError::Incompatible);
            }
            bytes.extend_from_slice(state.parts.get(&expected).ok_or(StoreError::Incompatible)?);
        }
        self.objects
            .lock()
            .assert_value("object lock")
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
            .assert_value("upload lock")
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
            .assert_value("upload lock")
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
                StoreS3MultipartUploadRecord::new(key, StoreS3MultipartUpload::new(upload)?)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        StoreS3MultipartListPage::new(uploads, next, after, maximum_items)
    }
}

struct FakeBlobAdminClient {
    ordinary: Arc<FakeS3Client>,
    state: Mutex<VersionedObjectMap>,
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
            StoreS3ObjectVersion::new(format!("state-{version}")).assert_value("state version"),
        )
    }

    fn ordinary_version(bytes: &[u8]) -> StoreS3ObjectVersion {
        StoreS3ObjectVersion::new(format!("object-{}", blake3::hash(bytes).to_hex()))
            .assert_value("object version")
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
            .assert_value("state lock")
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
            .assert_value("object lock")
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
            .assert_value("state lock")
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
        let mut state = self.state.lock().assert_value("state lock");
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
        let mut state = self.state.lock().assert_value("state lock");
        let Some((current, version)) = state.get_mut(&(bucket.to_string(), key.to_string())) else {
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
        let mut objects = self.ordinary.objects.lock().assert_value("object lock");
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
            .assert_value("object lock")
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
        S3BlobBackendConfig::new(
            "archive-admin",
            ordinary.endpoint.clone(),
            "campaign-archive",
            "tenant-admin",
            12 * 1024 * 1024,
            5 * 1024 * 1024,
        ),
        ordinary,
        administration,
    )
    .assert_value("administrative S3 backend")
}

fn backend(client: Arc<FakeS3Client>) -> S3BlobBackend {
    S3BlobBackend::new(
        S3BlobBackendConfig::new(
            "archive",
            client.endpoint.clone(),
            "campaign-archive",
            "tenant-a",
            12 * 1024 * 1024,
            5 * 1024 * 1024,
        ),
        client,
    )
    .assert_value("S3 backend")
}

mod behavior;

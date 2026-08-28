//! AWS SDK transport for Crucible's S3-compatible immutable-store leaf.
//!
//! [`AwsSdkS3Client`] owns a bounded command queue and a dedicated Tokio
//! runtime. This keeps the synchronous, streaming `crucible-cas` contract free
//! of credential and runtime policy while reusing one configured SDK client.
//! Callers must invoke the synchronous CAS surface from their admitted blocking
//! worker pool rather than an async reactor thread.

#![forbid(unsafe_code)]

use std::io::{self, Cursor, Read};
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use crucible_cas::content_store::{
    ContentId, MAX_S3_MULTIPART_LIST_ITEMS, MAX_S3_OBJECT_LIST_ITEMS, StoreError,
    StoreS3BlobAdminClient, StoreS3Client, StoreS3ConditionalDeleteOutcome,
    StoreS3ConditionalPutOutcome, StoreS3ConditionalWriteOutcome, StoreS3EndpointId,
    StoreS3MultipartListCursor, StoreS3MultipartListPage, StoreS3MultipartUpload,
    StoreS3MultipartUploadRecord, StoreS3ObjectDownload, StoreS3ObjectListCursor,
    StoreS3ObjectListPage, StoreS3ObjectScan, StoreS3ObjectVersion, StoreS3StrongCasClient,
    StoreS3UploadedPart, StoreS3VersionedObject, StoreS3VersionedObjectMetadata,
};

mod deadline;

use deadline::OperationalDeadline;

const MAX_COMMAND_QUEUE: usize = 1_024;
const MAX_IN_FLIGHT_OPERATIONS: usize = 64;
const MIN_RETAINED_COMMAND_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RETAINED_COMMAND_BYTES: u64 = 1024 * 1024 * 1024;
const DOWNLOAD_CHANNEL_CHUNKS: usize = 2;
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;
const MAX_BUCKET_REQUEST_BYTES: usize = 63;
const MAX_OBJECT_KEY_BYTES: usize = 1_024;
const MAX_MULTIPART_PART_BYTES: usize = 64 * 1024 * 1024;
const MAX_MULTIPART_PARTS: usize = 10_000;
const MAX_STRONG_CAS_OBJECT_BYTES: usize = 4 * 1024;
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_OPERATION_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Bounded queue, concurrency, and deadline policy for one AWS SDK worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AwsSdkS3ClientConfig {
    maximum_queued_commands: usize,
    maximum_in_flight_operations: usize,
    maximum_retained_command_bytes: u64,
    operation_timeout: Duration,
}

impl AwsSdkS3ClientConfig {
    /// Validates the worker queue, active-operation, and deadline bounds.
    ///
    /// The deadline covers queue admission, the SDK request, and any streamed
    /// response body. A full queue is rejected immediately rather than waiting
    /// behind unrelated object operations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the queue is empty or
    /// larger than 1,024 commands, the active-operation limit is empty or
    /// larger than 64, the aggregate retained-command budget is outside 128
    /// MiB through 1 GiB inclusive, or the timeout is outside 100 ms through
    /// one hour inclusive.
    pub fn new(
        maximum_queued_commands: usize,
        maximum_in_flight_operations: usize,
        maximum_retained_command_bytes: u64,
        operation_timeout: Duration,
    ) -> Result<Self, StoreError> {
        if maximum_queued_commands == 0
            || maximum_queued_commands > MAX_COMMAND_QUEUE
            || maximum_in_flight_operations == 0
            || maximum_in_flight_operations > MAX_IN_FLIGHT_OPERATIONS
            || !(MIN_RETAINED_COMMAND_BYTES..=MAX_RETAINED_COMMAND_BYTES)
                .contains(&maximum_retained_command_bytes)
            || !(MIN_OPERATION_TIMEOUT..=MAX_OPERATION_TIMEOUT).contains(&operation_timeout)
        {
            return Err(StoreError::InvalidComposition {
                reason: "S3 SDK worker bounds are invalid",
            });
        }
        Ok(Self {
            maximum_queued_commands,
            maximum_in_flight_operations,
            maximum_retained_command_bytes,
            operation_timeout,
        })
    }

    /// Returns the maximum number of admitted commands waiting for execution.
    #[must_use]
    pub const fn maximum_queued_commands(self) -> usize {
        self.maximum_queued_commands
    }

    /// Returns the maximum number of concurrently active SDK operations.
    #[must_use]
    pub const fn maximum_in_flight_operations(self) -> usize {
        self.maximum_in_flight_operations
    }

    /// Returns the aggregate byte ceiling for queued and active commands.
    #[must_use]
    pub const fn maximum_retained_command_bytes(self) -> u64 {
        self.maximum_retained_command_bytes
    }

    /// Returns the absolute deadline applied to each command.
    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }
}

/// Bounded synchronous adapter over one configured AWS SDK S3 client.
pub struct AwsSdkS3Client {
    endpoint: StoreS3EndpointId,
    operation_timeout: Duration,
    worker: Arc<Worker>,
}

/// Explicit strong-CAS/listing view of one configured AWS SDK client.
///
/// Construction is an operator assertion that the exact configured service
/// has passed the deployment's strong-CAS service conformance procedure and
/// that no writer outside the admitted single daemon mutates the selected
/// namespace. Use as committed-object administration additionally requires
/// the selected bucket to be unversioned, with no retained delete markers or
/// noncurrent versions, so current-key listing and deletion account for all
/// retained object bytes. The
/// ordinary [`AwsSdkS3Client`] remains usable for immutable objects without
/// making these stronger assertions.
pub struct AwsSdkS3StrongCasClient {
    client: Arc<AwsSdkS3Client>,
}

impl AwsSdkS3StrongCasClient {
    /// Admits a configured SDK client after external service conformance.
    ///
    /// This constructor performs no remote mutation. Callers MUST first run the
    /// exact deployment service through its strong-CAS conformance procedure;
    /// compatible endpoints without that evidence are not admissible.
    #[must_use]
    pub const fn from_conformant_service(client: Arc<AwsSdkS3Client>) -> Self {
        Self { client }
    }
}

impl AwsSdkS3Client {
    /// Starts one dedicated SDK worker for an already configured client.
    ///
    /// `client` may target AWS S3 or a compatible endpoint such as MinIO. Its
    /// credentials, region, endpoint URL, path-style policy, retries, and HTTP
    /// deadlines are operational configuration and are deliberately absent
    /// from canonical store-graph bytes; `endpoint` is their non-secret exact
    /// policy identity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] when the worker/runtime cannot start
    /// within the configured operation deadline.
    pub fn start(
        endpoint: StoreS3EndpointId,
        client: aws_sdk_s3::Client,
        config: AwsSdkS3ClientConfig,
    ) -> Result<Self, StoreError> {
        let (commands, receiver) = mpsc::sync_channel(config.maximum_queued_commands());
        let (started, startup) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("crucible-s3-sdk".to_string())
            .spawn(move || {
                run_worker(
                    client,
                    receiver,
                    config.maximum_in_flight_operations(),
                    started,
                );
            })
            .map_err(|_| StoreError::Unavailable)?;
        startup
            .recv_timeout(config.operation_timeout())
            .map_err(|_| StoreError::Unavailable)??;
        Ok(Self {
            endpoint,
            operation_timeout: config.operation_timeout(),
            worker: Arc::new(Worker {
                commands: Mutex::new(Some(commands)),
                thread: Mutex::new(Some(thread)),
                budget: Arc::new(CommandBudget::new(config.maximum_retained_command_bytes())),
            }),
        })
    }

    fn call<T>(
        &self,
        dynamic_retained_bytes: u64,
        build: impl FnOnce(SyncSender<Result<T, StoreError>>) -> Command,
    ) -> Result<T, StoreError> {
        let deadline =
            OperationalDeadline::after(self.operation_timeout).ok_or(StoreError::Unavailable)?;
        self.call_at(deadline, dynamic_retained_bytes, build)
    }

    fn call_at<T>(
        &self,
        deadline: OperationalDeadline,
        dynamic_retained_bytes: u64,
        build: impl FnOnce(SyncSender<Result<T, StoreError>>) -> Command,
    ) -> Result<T, StoreError> {
        if deadline.remaining().is_zero() {
            return Err(StoreError::Unavailable);
        }
        let (response, result) = mpsc::sync_channel(1);
        let retained_bytes = u64::try_from(mem::size_of::<Command>())
            .map_err(|_| StoreError::Quota)?
            .checked_add(dynamic_retained_bytes)
            .ok_or(StoreError::Quota)?;
        let budget = self.worker.budget.reserve(retained_bytes)?;
        let command = build(response);
        if command.retained_bytes()? != retained_bytes {
            return Err(StoreError::Incompatible);
        }
        let commands = self
            .worker
            .commands
            .try_lock()
            .map_err(|error| match error {
                TryLockError::Poisoned(_) => StoreError::Poisoned {
                    operation: "lock-S3-SDK-command-sender",
                },
                TryLockError::WouldBlock => StoreError::Unavailable,
            })?;
        commands
            .as_ref()
            .ok_or(StoreError::Unavailable)?
            .try_send(QueuedCommand {
                deadline,
                command,
                _budget: budget,
            })
            .map_err(|_| StoreError::Unavailable)?;
        drop(commands);
        let remaining = deadline.remaining();
        result
            .recv_timeout(remaining)
            .map_err(|_| StoreError::Unavailable)?
    }
}

impl StoreS3Client for AwsSdkS3Client {
    fn endpoint_id(&self) -> &StoreS3EndpointId {
        &self.endpoint
    }

    fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.call(retained, |response| Command::Head {
            bucket,
            key,
            response,
        })
    }

    fn get_object(&self, bucket: &str, key: &str) -> Result<StoreS3ObjectDownload, StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.call(retained, |response| Command::Get {
            bucket,
            key,
            response,
        })
    }

    fn put_empty_if_absent(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.call(retained, |response| Command::PutEmpty {
            bucket,
            key,
            response,
        })
    }

    fn begin_multipart(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoreS3MultipartUpload, StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.call(retained, |response| Command::BeginMultipart {
            bucket,
            key,
            response,
        })
    }

    fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
        part_number: u32,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3UploadedPart, StoreError> {
        if bytes.len() > MAX_MULTIPART_PART_BYTES {
            return Err(StoreError::Quota);
        }
        let (bucket, key) = request_location(bucket, key)?;
        let retained =
            retained_lengths(&[bucket.len(), key.len(), upload.as_str().len(), bytes.len()])?;
        self.call(retained, |response| Command::UploadPart {
            bucket,
            key,
            upload: upload.as_str().to_string(),
            part_number,
            bytes,
            response,
        })
    }

    fn complete_multipart_if_absent(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
        parts: &[StoreS3UploadedPart],
    ) -> Result<StoreS3ConditionalPutOutcome, StoreError> {
        if parts.len() > MAX_MULTIPART_PARTS {
            return Err(StoreError::Quota);
        }
        let (bucket, key) = request_location(bucket, key)?;
        let part_struct_bytes = parts
            .len()
            .checked_mul(mem::size_of::<StoreS3UploadedPart>())
            .ok_or(StoreError::Quota)?;
        let mut retained = retained_lengths(&[
            bucket.len(),
            key.len(),
            upload.as_str().len(),
            part_struct_bytes,
        ])?;
        for part in parts {
            retained = retained
                .checked_add(
                    u64::try_from(part.provider_tag().len()).map_err(|_| StoreError::Quota)?,
                )
                .ok_or(StoreError::Quota)?;
        }
        self.call(retained, |response| Command::CompleteMultipart {
            bucket,
            key,
            upload: upload.as_str().to_string(),
            parts: parts.to_vec(),
            response,
        })
    }

    fn abort_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload: &StoreS3MultipartUpload,
    ) -> Result<(), StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len(), upload.as_str().len()])?;
        self.call(retained, |response| Command::AbortMultipart {
            bucket,
            key,
            upload: upload.as_str().to_string(),
            response,
        })
    }

    fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&StoreS3MultipartListCursor>,
        maximum_items: u16,
    ) -> Result<StoreS3MultipartListPage, StoreError> {
        if maximum_items == 0 || maximum_items > MAX_S3_MULTIPART_LIST_ITEMS {
            return Err(StoreError::Quota);
        }
        let (bucket, prefix) = request_location(bucket, prefix)?;
        let mut retained = retained_lengths(&[bucket.len(), prefix.len()])?;
        if let Some(after) = after {
            retained = retained
                .checked_add(retained_lengths(&[
                    after.key_marker().len(),
                    after.upload_id_marker().as_str().len(),
                ])?)
                .ok_or(StoreError::Quota)?;
        }
        let after = after.cloned();
        self.call(retained, |response| Command::ListMultipartUploads {
            bucket,
            prefix,
            after,
            maximum_items,
            response,
        })
    }
}

impl StoreS3StrongCasClient for AwsSdkS3StrongCasClient {
    fn endpoint_id(&self) -> &StoreS3EndpointId {
        &self.client.endpoint
    }

    fn get_small_versioned_object(
        &self,
        bucket: &str,
        key: &str,
        maximum_bytes: u16,
    ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
        if maximum_bytes == 0 || usize::from(maximum_bytes) > MAX_STRONG_CAS_OBJECT_BYTES {
            return Err(StoreError::Quota);
        }
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.client
            .call(retained, |response| Command::GetSmallVersioned {
                bucket,
                key,
                maximum_bytes,
                response,
            })
    }

    fn put_small_if_absent(
        &self,
        bucket: &str,
        key: &str,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3ConditionalWriteOutcome, StoreError> {
        if bytes.len() > MAX_STRONG_CAS_OBJECT_BYTES {
            return Err(StoreError::Quota);
        }
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len(), bytes.len()])?;
        self.client
            .call(retained, |response| Command::PutSmallIfAbsent {
                bucket,
                key,
                bytes,
                response,
            })
    }

    fn replace_small_if_version(
        &self,
        bucket: &str,
        key: &str,
        expected: &StoreS3ObjectVersion,
        bytes: Arc<[u8]>,
    ) -> Result<StoreS3ConditionalWriteOutcome, StoreError> {
        if bytes.len() > MAX_STRONG_CAS_OBJECT_BYTES {
            return Err(StoreError::Quota);
        }
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[
            bucket.len(),
            key.len(),
            expected.as_str().len(),
            bytes.len(),
        ])?;
        self.client
            .call(retained, |response| Command::ReplaceSmallIfVersion {
                bucket,
                key,
                expected: expected.as_str().to_string(),
                bytes,
                response,
            })
    }

    fn begin_small_object_scan(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Box<dyn StoreS3ObjectScan + '_>, StoreError> {
        let (bucket, prefix) = request_location(bucket, prefix)?;
        let deadline = OperationalDeadline::after(self.client.operation_timeout)
            .ok_or(StoreError::Unavailable)?;
        Ok(Box::new(AwsSdkS3StrongCasScan {
            client: self.client.clone(),
            bucket,
            prefix,
            after: None,
            deadline,
            finished: false,
        }))
    }
}

struct AwsSdkS3StrongCasScan {
    client: Arc<AwsSdkS3Client>,
    bucket: String,
    prefix: String,
    after: Option<StoreS3ObjectListCursor>,
    deadline: OperationalDeadline,
    finished: bool,
}

impl StoreS3ObjectScan for AwsSdkS3StrongCasScan {
    fn next_page(&mut self, maximum_items: u16) -> Result<StoreS3ObjectListPage, StoreError> {
        if self.finished {
            return Err(StoreError::Incompatible);
        }
        if maximum_items == 0 || maximum_items > MAX_S3_OBJECT_LIST_ITEMS {
            return Err(StoreError::Quota);
        }
        let mut retained = retained_lengths(&[self.bucket.len(), self.prefix.len()])?;
        if let Some(after) = &self.after {
            retained = retained
                .checked_add(retained_lengths(&[after.as_str().len()])?)
                .ok_or(StoreError::Quota)?;
        }
        let bucket = self.bucket.clone();
        let prefix = self.prefix.clone();
        let after = self.after.clone();
        let page = self.client.call_at(self.deadline, retained, |response| {
            Command::ListSmallObjects {
                bucket,
                prefix,
                after,
                maximum_items,
                response,
            }
        })?;
        self.after = page.next().cloned();
        self.finished = self.after.is_none();
        Ok(page)
    }

    fn get_small_versioned_object(
        &self,
        key: &str,
        maximum_bytes: u16,
    ) -> Result<Option<StoreS3VersionedObject>, StoreError> {
        if maximum_bytes == 0 || usize::from(maximum_bytes) > MAX_STRONG_CAS_OBJECT_BYTES {
            return Err(StoreError::Quota);
        }
        let (_bucket, key) = request_location(&self.bucket, key)?;
        let bucket = self.bucket.clone();
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.client.call_at(self.deadline, retained, |response| {
            Command::GetSmallVersioned {
                bucket,
                key,
                maximum_bytes,
                response,
            }
        })
    }

    fn head_versioned_object(
        &self,
        key: &str,
    ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
        let (_bucket, key) = request_location(&self.bucket, key)?;
        let bucket = self.bucket.clone();
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.client
            .call_at(self.deadline, retained, |response| Command::HeadVersioned {
                bucket,
                key,
                response,
            })
    }
}

impl StoreS3BlobAdminClient for AwsSdkS3StrongCasClient {
    fn head_versioned_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len()])?;
        self.client
            .call(retained, |response| Command::HeadVersioned {
                bucket,
                key,
                response,
            })
    }

    fn delete_object_if_version(
        &self,
        bucket: &str,
        key: &str,
        expected: &StoreS3ObjectVersion,
    ) -> Result<StoreS3ConditionalDeleteOutcome, StoreError> {
        let (bucket, key) = request_location(bucket, key)?;
        let retained = retained_lengths(&[bucket.len(), key.len(), expected.as_str().len()])?;
        self.client
            .call(retained, |response| Command::DeleteIfVersion {
                bucket,
                key,
                expected: expected.as_str().to_string(),
                response,
            })
    }
}

fn request_location(bucket: &str, key: &str) -> Result<(String, String), StoreError> {
    if bucket.is_empty()
        || bucket.len() > MAX_BUCKET_REQUEST_BYTES
        || key.is_empty()
        || key.len() > MAX_OBJECT_KEY_BYTES
    {
        return Err(StoreError::Incompatible);
    }
    Ok((bucket.to_string(), key.to_string()))
}

fn retained_lengths(lengths: &[usize]) -> Result<u64, StoreError> {
    lengths.iter().try_fold(0_u64, |total, length| {
        total
            .checked_add(u64::try_from(*length).map_err(|_| StoreError::Quota)?)
            .ok_or(StoreError::Quota)
    })
}

struct Worker {
    commands: Mutex<Option<SyncSender<QueuedCommand>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    budget: Arc<CommandBudget>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(commands) = self.commands.get_mut() {
            commands.take();
        }
        if let Ok(thread) = self.thread.get_mut()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

enum Command {
    Head {
        bucket: String,
        key: String,
        response: SyncSender<Result<Option<u64>, StoreError>>,
    },
    Get {
        bucket: String,
        key: String,
        response: SyncSender<Result<StoreS3ObjectDownload, StoreError>>,
    },
    PutEmpty {
        bucket: String,
        key: String,
        response: SyncSender<Result<StoreS3ConditionalPutOutcome, StoreError>>,
    },
    BeginMultipart {
        bucket: String,
        key: String,
        response: SyncSender<Result<StoreS3MultipartUpload, StoreError>>,
    },
    UploadPart {
        bucket: String,
        key: String,
        upload: String,
        part_number: u32,
        bytes: Arc<[u8]>,
        response: SyncSender<Result<StoreS3UploadedPart, StoreError>>,
    },
    CompleteMultipart {
        bucket: String,
        key: String,
        upload: String,
        parts: Vec<StoreS3UploadedPart>,
        response: SyncSender<Result<StoreS3ConditionalPutOutcome, StoreError>>,
    },
    AbortMultipart {
        bucket: String,
        key: String,
        upload: String,
        response: SyncSender<Result<(), StoreError>>,
    },
    ListMultipartUploads {
        bucket: String,
        prefix: String,
        after: Option<StoreS3MultipartListCursor>,
        maximum_items: u16,
        response: SyncSender<Result<StoreS3MultipartListPage, StoreError>>,
    },
    GetSmallVersioned {
        bucket: String,
        key: String,
        maximum_bytes: u16,
        response: SyncSender<Result<Option<StoreS3VersionedObject>, StoreError>>,
    },
    PutSmallIfAbsent {
        bucket: String,
        key: String,
        bytes: Arc<[u8]>,
        response: SyncSender<Result<StoreS3ConditionalWriteOutcome, StoreError>>,
    },
    ReplaceSmallIfVersion {
        bucket: String,
        key: String,
        expected: String,
        bytes: Arc<[u8]>,
        response: SyncSender<Result<StoreS3ConditionalWriteOutcome, StoreError>>,
    },
    ListSmallObjects {
        bucket: String,
        prefix: String,
        after: Option<StoreS3ObjectListCursor>,
        maximum_items: u16,
        response: SyncSender<Result<StoreS3ObjectListPage, StoreError>>,
    },
    HeadVersioned {
        bucket: String,
        key: String,
        response: SyncSender<Result<Option<StoreS3VersionedObjectMetadata>, StoreError>>,
    },
    DeleteIfVersion {
        bucket: String,
        key: String,
        expected: String,
        response: SyncSender<Result<StoreS3ConditionalDeleteOutcome, StoreError>>,
    },
}

struct QueuedCommand {
    deadline: OperationalDeadline,
    command: Command,
    _budget: CommandBudgetReservation,
}

impl Command {
    fn retained_bytes(&self) -> Result<u64, StoreError> {
        let mut bytes = u64::try_from(mem::size_of::<Self>()).map_err(|_| StoreError::Quota)?;
        let mut add = |value: usize| -> Result<(), StoreError> {
            let value = u64::try_from(value).map_err(|_| StoreError::Quota)?;
            bytes = bytes.checked_add(value).ok_or(StoreError::Quota)?;
            Ok(())
        };
        match self {
            Self::Head { bucket, key, .. }
            | Self::Get { bucket, key, .. }
            | Self::PutEmpty { bucket, key, .. }
            | Self::BeginMultipart { bucket, key, .. } => {
                add(bucket.len())?;
                add(key.len())?;
            }
            Self::UploadPart {
                bucket,
                key,
                upload,
                bytes: part,
                ..
            } => {
                add(bucket.len())?;
                add(key.len())?;
                add(upload.len())?;
                add(part.len())?;
            }
            Self::CompleteMultipart {
                bucket,
                key,
                upload,
                parts,
                ..
            } => {
                add(bucket.len())?;
                add(key.len())?;
                add(upload.len())?;
                add(parts
                    .len()
                    .saturating_mul(mem::size_of::<StoreS3UploadedPart>()))?;
                for part in parts {
                    add(part.provider_tag().len())?;
                }
            }
            Self::AbortMultipart {
                bucket,
                key,
                upload,
                ..
            } => {
                add(bucket.len())?;
                add(key.len())?;
                add(upload.len())?;
            }
            Self::ListMultipartUploads {
                bucket,
                prefix,
                after,
                ..
            } => {
                add(bucket.len())?;
                add(prefix.len())?;
                if let Some(after) = after {
                    add(after.key_marker().len())?;
                    add(after.upload_id_marker().as_str().len())?;
                }
            }
            Self::GetSmallVersioned { bucket, key, .. }
            | Self::HeadVersioned { bucket, key, .. } => {
                add(bucket.len())?;
                add(key.len())?;
            }
            Self::PutSmallIfAbsent {
                bucket,
                key,
                bytes: body,
                ..
            } => {
                add(bucket.len())?;
                add(key.len())?;
                add(body.len())?;
            }
            Self::ReplaceSmallIfVersion {
                bucket,
                key,
                expected,
                bytes: body,
                ..
            } => {
                add(bucket.len())?;
                add(key.len())?;
                add(expected.len())?;
                add(body.len())?;
            }
            Self::ListSmallObjects {
                bucket,
                prefix,
                after,
                ..
            } => {
                add(bucket.len())?;
                add(prefix.len())?;
                if let Some(after) = after {
                    add(after.as_str().len())?;
                }
            }
            Self::DeleteIfVersion {
                bucket,
                key,
                expected,
                ..
            } => {
                add(bucket.len())?;
                add(key.len())?;
                add(expected.len())?;
            }
        }
        Ok(bytes)
    }

    fn respond_unavailable(self) {
        match self {
            Self::Head { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::Get { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::PutEmpty { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::BeginMultipart { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::UploadPart { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::CompleteMultipart { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::AbortMultipart { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::ListMultipartUploads { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::GetSmallVersioned { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::PutSmallIfAbsent { response, .. }
            | Self::ReplaceSmallIfVersion { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::ListSmallObjects { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::HeadVersioned { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
            Self::DeleteIfVersion { response, .. } => {
                let _ = response.send(Err(StoreError::Unavailable));
            }
        }
    }
}

struct CommandBudget {
    maximum: u64,
    retained: AtomicU64,
}

impl CommandBudget {
    const fn new(maximum: u64) -> Self {
        Self {
            maximum,
            retained: AtomicU64::new(0),
        }
    }

    fn reserve(self: &Arc<Self>, bytes: u64) -> Result<CommandBudgetReservation, StoreError> {
        let mut current = self.retained.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes).ok_or(StoreError::Quota)?;
            if next > self.maximum {
                return Err(StoreError::Quota);
            }
            match self.retained.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(CommandBudgetReservation {
                        budget: self.clone(),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct CommandBudgetReservation {
    budget: Arc<CommandBudget>,
    bytes: u64,
}

impl Drop for CommandBudgetReservation {
    fn drop(&mut self) {
        self.budget.retained.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn run_worker(
    client: aws_sdk_s3::Client,
    receiver: Receiver<QueuedCommand>,
    maximum_in_flight_operations: usize,
    started: SyncSender<Result<(), StoreError>>,
) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = started.send(Err(StoreError::Unavailable));
            return;
        }
    };
    if started.send(Ok(())).is_err() {
        return;
    }
    let permits = Arc::new(tokio::sync::Semaphore::new(maximum_in_flight_operations));
    loop {
        let Ok(permit) = runtime.block_on(permits.clone().acquire_owned()) else {
            break;
        };
        let Ok(queued) = receiver.recv() else {
            break;
        };
        let remaining = queued.deadline.remaining();
        if remaining.is_zero() {
            queued.command.respond_unavailable();
            continue;
        }
        let QueuedCommand {
            command,
            _budget: budget,
            ..
        } = queued;
        let client = client.clone();
        runtime.spawn(async move {
            let _permit = permit;
            let _budget = budget;
            let _ = tokio::time::timeout(remaining, handle_command(client, command)).await;
        });
    }
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
}

async fn handle_command(client: aws_sdk_s3::Client, command: Command) {
    match command {
        Command::Head {
            bucket,
            key,
            response,
        } => {
            let result = match client.head_object().bucket(&bucket).key(&key).send().await {
                Ok(output) => output
                    .content_length()
                    .map(|length| u64::try_from(length).map_err(|_| StoreError::Incompatible))
                    .transpose(),
                Err(error) if is_missing(&error) => Ok(None),
                Err(error) => Err(classify_sdk_error(&error)),
            };
            let _ = response.send(result);
        }
        Command::Get {
            bucket,
            key,
            response,
        } => match client.get_object().bucket(&bucket).key(&key).send().await {
            Ok(output) => {
                let Some(content_length) = output.content_length() else {
                    let _ = response.send(Err(StoreError::Incompatible));
                    return;
                };
                let Ok(logical_length) = u64::try_from(content_length) else {
                    let _ = response.send(Err(StoreError::Incompatible));
                    return;
                };
                let (chunks, reader) = tokio::sync::mpsc::channel(DOWNLOAD_CHANNEL_CHUNKS);
                if response
                    .send(Ok(StoreS3ObjectDownload::new(
                        logical_length,
                        Box::new(ChannelReader::new(reader)),
                    )))
                    .is_err()
                {
                    return;
                }
                let mut body = output.body.into_async_read();
                let mut buffer = vec![0_u8; DOWNLOAD_CHUNK_BYTES];
                loop {
                    match tokio::io::AsyncReadExt::read(&mut body, &mut buffer).await {
                        Ok(0) => {
                            let _ = chunks.send(DownloadChunk::Eof).await;
                            return;
                        }
                        Ok(read) => {
                            if chunks
                                .send(DownloadChunk::Bytes(buffer[..read].to_vec()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(error) => {
                            let _ = chunks.send(DownloadChunk::Error(error)).await;
                            return;
                        }
                    }
                }
            }
            Err(error) if is_missing(&error) => {
                let error = key_content_id(&key)
                    .map_or(StoreError::Incompatible, |id| StoreError::NotFound { id });
                let _ = response.send(Err(error));
            }
            Err(error) => {
                let _ = response.send(Err(classify_sdk_error(&error)));
            }
        },
        Command::PutEmpty {
            bucket,
            key,
            response,
        } => {
            let result = client
                .put_object()
                .bucket(&bucket)
                .key(&key)
                .if_none_match("*")
                .body(ByteStream::from_static(&[]))
                .send()
                .await;
            let _ = response.send(match result {
                Ok(_) => Ok(StoreS3ConditionalPutOutcome::Created),
                Err(error) if is_conditional_conflict(&error) => {
                    Ok(StoreS3ConditionalPutOutcome::AlreadyExists)
                }
                Err(error) => Err(classify_sdk_error(&error)),
            });
        }
        Command::BeginMultipart {
            bucket,
            key,
            response,
        } => {
            let result = client
                .create_multipart_upload()
                .bucket(&bucket)
                .key(&key)
                .send()
                .await;
            let _ = response.send(match result {
                Ok(output) => output
                    .upload_id()
                    .ok_or(StoreError::Incompatible)
                    .and_then(StoreS3MultipartUpload::new),
                Err(error) => Err(classify_sdk_error(&error)),
            });
        }
        Command::UploadPart {
            bucket,
            key,
            upload,
            part_number,
            bytes,
            response,
        } => {
            let Ok(part_number_i32) = i32::try_from(part_number) else {
                let _ = response.send(Err(StoreError::Incompatible));
                return;
            };
            let result = client
                .upload_part()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload)
                .part_number(part_number_i32)
                .body(ByteStream::from(bytes.to_vec()))
                .send()
                .await;
            let _ = response.send(match result {
                Ok(output) => output
                    .e_tag()
                    .ok_or(StoreError::Incompatible)
                    .and_then(|tag| StoreS3UploadedPart::new(part_number, tag)),
                Err(error) => Err(classify_sdk_error(&error)),
            });
        }
        Command::CompleteMultipart {
            bucket,
            key,
            upload,
            parts,
            response,
        } => {
            let mut completed = Vec::with_capacity(parts.len());
            for part in &parts {
                let Ok(part_number) = i32::try_from(part.part_number()) else {
                    let _ = response.send(Err(StoreError::Incompatible));
                    return;
                };
                completed.push(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(part_number)
                        .e_tag(part.provider_tag())
                        .build(),
                );
            }
            let result = client
                .complete_multipart_upload()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload)
                .if_none_match("*")
                .multipart_upload(
                    aws_sdk_s3::types::CompletedMultipartUpload::builder()
                        .set_parts(Some(completed))
                        .build(),
                )
                .send()
                .await;
            let _ = response.send(match result {
                Ok(_) => Ok(StoreS3ConditionalPutOutcome::Created),
                Err(error) if is_conditional_conflict(&error) => {
                    Ok(StoreS3ConditionalPutOutcome::AlreadyExists)
                }
                Err(error) if is_no_such_upload(&error) => {
                    match client.head_object().bucket(&bucket).key(&key).send().await {
                        Ok(output) if output.content_length().is_some() => {
                            Ok(StoreS3ConditionalPutOutcome::AlreadyExists)
                        }
                        Ok(_) => Err(StoreError::Incompatible),
                        Err(head_error) if is_missing(&head_error) => Err(StoreError::Incompatible),
                        Err(head_error) => Err(classify_sdk_error(&head_error)),
                    }
                }
                Err(error) => Err(classify_sdk_error(&error)),
            });
        }
        Command::AbortMultipart {
            bucket,
            key,
            upload,
            response,
        } => {
            let result = client
                .abort_multipart_upload()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload)
                .send()
                .await;
            let _ = response.send(match result {
                Ok(_) => Ok(()),
                Err(error) if is_no_such_upload(&error) => Ok(()),
                Err(error) => Err(classify_sdk_error(&error)),
            });
        }
        Command::ListMultipartUploads {
            bucket,
            prefix,
            after,
            maximum_items,
            response,
        } => {
            let mut request = client
                .list_multipart_uploads()
                .bucket(&bucket)
                .prefix(&prefix)
                .max_uploads(i32::from(maximum_items));
            if let Some(after) = &after {
                request = request
                    .key_marker(after.key_marker())
                    .upload_id_marker(after.upload_id_marker().as_str());
            }
            let result = match request.send().await {
                Ok(output) => decode_multipart_list_page(
                    &bucket,
                    &prefix,
                    after.as_ref(),
                    maximum_items,
                    &output,
                ),
                Err(error) => Err(classify_sdk_error(&error)),
            };
            let _ = response.send(result);
        }
        Command::GetSmallVersioned {
            bucket,
            key,
            maximum_bytes,
            response,
        } => {
            let result = match client.get_object().bucket(&bucket).key(&key).send().await {
                Ok(output) => decode_small_versioned_object(output, maximum_bytes)
                    .await
                    .map(Some),
                Err(error) if is_missing(&error) => Ok(None),
                Err(error) => Err(classify_sdk_error(&error)),
            };
            let _ = response.send(result);
        }
        Command::PutSmallIfAbsent {
            bucket,
            key,
            bytes,
            response,
        } => {
            let result = client
                .put_object()
                .bucket(&bucket)
                .key(&key)
                .if_none_match("*")
                .body(ByteStream::from(bytes.to_vec()))
                .send()
                .await;
            let _ = response.send(decode_conditional_small_write(result));
        }
        Command::ReplaceSmallIfVersion {
            bucket,
            key,
            expected,
            bytes,
            response,
        } => {
            let result = client
                .put_object()
                .bucket(&bucket)
                .key(&key)
                .if_match(expected)
                .body(ByteStream::from(bytes.to_vec()))
                .send()
                .await;
            let _ = response.send(decode_conditional_small_write(result));
        }
        Command::ListSmallObjects {
            bucket,
            prefix,
            after,
            maximum_items,
            response,
        } => {
            let mut request = client
                .list_objects_v2()
                .bucket(&bucket)
                .prefix(&prefix)
                .max_keys(i32::from(maximum_items));
            if let Some(after) = &after {
                request = request.continuation_token(after.as_str());
            }
            let result = match request.send().await {
                Ok(output) => decode_small_object_list_page(
                    &bucket,
                    &prefix,
                    after.as_ref(),
                    maximum_items,
                    &output,
                ),
                Err(error) => Err(classify_sdk_error(&error)),
            };
            let _ = response.send(result);
        }
        Command::HeadVersioned {
            bucket,
            key,
            response,
        } => {
            let result = match client.head_object().bucket(&bucket).key(&key).send().await {
                Ok(output) => decode_versioned_metadata(&output).map(Some),
                Err(error) if is_missing(&error) => Ok(None),
                Err(error) => Err(classify_sdk_error(&error)),
            };
            let _ = response.send(result);
        }
        Command::DeleteIfVersion {
            bucket,
            key,
            expected,
            response,
        } => {
            let result = client
                .delete_object()
                .bucket(&bucket)
                .key(&key)
                .if_match(expected)
                .send()
                .await;
            let _ = response.send(match result {
                Ok(_) => Ok(StoreS3ConditionalDeleteOutcome::Deleted),
                Err(error) if is_conditional_conflict(&error) => {
                    Ok(StoreS3ConditionalDeleteOutcome::PreconditionFailed)
                }
                Err(error) => Err(classify_sdk_error(&error)),
            });
        }
    }
}

fn decode_versioned_metadata(
    output: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
) -> Result<StoreS3VersionedObjectMetadata, StoreError> {
    let logical_length = output
        .content_length()
        .ok_or(StoreError::Incompatible)
        .and_then(|length| u64::try_from(length).map_err(|_| StoreError::Incompatible))?;
    let version = output
        .e_tag()
        .ok_or(StoreError::Incompatible)
        .and_then(StoreS3ObjectVersion::new)?;
    Ok(StoreS3VersionedObjectMetadata::new(logical_length, version))
}

async fn decode_small_versioned_object(
    output: aws_sdk_s3::operation::get_object::GetObjectOutput,
    maximum_bytes: u16,
) -> Result<StoreS3VersionedObject, StoreError> {
    let length = output
        .content_length()
        .ok_or(StoreError::Incompatible)
        .and_then(|length| usize::try_from(length).map_err(|_| StoreError::Incompatible))?;
    if length > usize::from(maximum_bytes) {
        return Err(StoreError::Quota);
    }
    let version = output
        .e_tag()
        .ok_or(StoreError::Incompatible)
        .and_then(StoreS3ObjectVersion::new)?;
    let mut reader = output.body.into_async_read();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| StoreError::Quota)?;
    let mut limited =
        tokio::io::AsyncReadExt::take(&mut reader, u64::from(maximum_bytes).saturating_add(1));
    tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut bytes)
        .await
        .map_err(|_| StoreError::Unavailable)?;
    if bytes.len() != length {
        return Err(StoreError::Incompatible);
    }
    StoreS3VersionedObject::new(Arc::from(bytes), version)
}

fn decode_conditional_small_write<E, R>(
    result: Result<aws_sdk_s3::operation::put_object::PutObjectOutput, SdkError<E, R>>,
) -> Result<StoreS3ConditionalWriteOutcome, StoreError>
where
    E: ProvideErrorMetadata,
{
    match result {
        Ok(output) => output
            .e_tag()
            .ok_or(StoreError::Incompatible)
            .and_then(StoreS3ObjectVersion::new)
            .map(StoreS3ConditionalWriteOutcome::Committed),
        Err(error) if is_conditional_conflict(&error) => {
            Ok(StoreS3ConditionalWriteOutcome::PreconditionFailed)
        }
        Err(error) => Err(classify_sdk_error(&error)),
    }
}

fn decode_small_object_list_page(
    bucket: &str,
    prefix: &str,
    after: Option<&StoreS3ObjectListCursor>,
    maximum_items: u16,
    output: &aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output,
) -> Result<StoreS3ObjectListPage, StoreError> {
    let expected_after = after.map(StoreS3ObjectListCursor::as_str);
    let key_count = output
        .key_count()
        .ok_or(StoreError::Incompatible)
        .and_then(|count| usize::try_from(count).map_err(|_| StoreError::Incompatible))?;
    if output.name() != Some(bucket)
        || output.prefix() != Some(prefix)
        || output.max_keys() != Some(i32::from(maximum_items))
        || output.continuation_token() != expected_after
        || key_count != output.contents().len()
        || key_count > usize::from(maximum_items)
    {
        return Err(StoreError::Incompatible);
    }
    let keys = output
        .contents()
        .iter()
        .map(|object| {
            object
                .key()
                .map(str::to_string)
                .ok_or(StoreError::Incompatible)
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let next = match output.is_truncated() {
        Some(true) => Some(StoreS3ObjectListCursor::new(
            output
                .next_continuation_token()
                .ok_or(StoreError::Incompatible)?,
        )?),
        Some(false) if output.next_continuation_token().is_none() => None,
        _ => return Err(StoreError::Incompatible),
    };
    StoreS3ObjectListPage::new(keys, next, after, maximum_items)
}

fn decode_multipart_list_page(
    bucket: &str,
    prefix: &str,
    after: Option<&StoreS3MultipartListCursor>,
    maximum_items: u16,
    output: &aws_sdk_s3::operation::list_multipart_uploads::ListMultipartUploadsOutput,
) -> Result<StoreS3MultipartListPage, StoreError> {
    let expected_key_marker = after.map(StoreS3MultipartListCursor::key_marker);
    let expected_upload_marker = after.map(|cursor| cursor.upload_id_marker().as_str());
    if output.bucket() != Some(bucket)
        || output.prefix() != Some(prefix)
        || output.max_uploads() != Some(i32::from(maximum_items))
        || output.key_marker() != expected_key_marker
        || output.upload_id_marker() != expected_upload_marker
        || output.uploads().len() > usize::from(maximum_items)
    {
        return Err(StoreError::Incompatible);
    }
    let uploads = output
        .uploads()
        .iter()
        .map(|upload| {
            let key = upload.key().ok_or(StoreError::Incompatible)?;
            let upload = upload
                .upload_id()
                .ok_or(StoreError::Incompatible)
                .and_then(StoreS3MultipartUpload::new)?;
            StoreS3MultipartUploadRecord::new(key, upload)
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let next = match output.is_truncated() {
        Some(true) => Some(StoreS3MultipartListCursor::new(
            output.next_key_marker().ok_or(StoreError::Incompatible)?,
            output
                .next_upload_id_marker()
                .ok_or(StoreError::Incompatible)
                .and_then(StoreS3MultipartUpload::new)?,
        )?),
        Some(false)
            if output.next_key_marker().is_none() && output.next_upload_id_marker().is_none() =>
        {
            None
        }
        _ => return Err(StoreError::Incompatible),
    };
    StoreS3MultipartListPage::new(uploads, next, after, maximum_items)
}

enum DownloadChunk {
    Bytes(Vec<u8>),
    Error(io::Error),
    Eof,
}

struct ChannelReader {
    chunks: tokio::sync::mpsc::Receiver<DownloadChunk>,
    current: Cursor<Vec<u8>>,
    finished: bool,
}

impl ChannelReader {
    fn new(chunks: tokio::sync::mpsc::Receiver<DownloadChunk>) -> Self {
        Self {
            chunks,
            current: Cursor::new(Vec::new()),
            finished: false,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }
        loop {
            let read = self.current.read(output)?;
            if read != 0 {
                return Ok(read);
            }
            match self.chunks.blocking_recv() {
                Some(DownloadChunk::Bytes(bytes)) => self.current = Cursor::new(bytes),
                Some(DownloadChunk::Error(error)) => return Err(error),
                Some(DownloadChunk::Eof) => {
                    self.finished = true;
                    return Ok(0);
                }
                None => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            }
        }
    }
}

fn key_content_id(key: &str) -> Option<ContentId> {
    key.rsplit('/')
        .next()
        .and_then(|value| ContentId::parse(value).ok())
}

fn service_code<E, R>(error: &SdkError<E, R>) -> Option<&str>
where
    E: ProvideErrorMetadata,
{
    error
        .as_service_error()
        .and_then(ProvideErrorMetadata::code)
}

fn is_missing<E, R>(error: &SdkError<E, R>) -> bool
where
    E: ProvideErrorMetadata,
{
    matches!(service_code(error), Some("NoSuchKey" | "NotFound" | "404"))
}

fn is_conditional_conflict<E, R>(error: &SdkError<E, R>) -> bool
where
    E: ProvideErrorMetadata,
{
    matches!(
        service_code(error),
        Some("PreconditionFailed" | "ConditionalRequestConflict")
    )
}

fn is_no_such_upload<E, R>(error: &SdkError<E, R>) -> bool
where
    E: ProvideErrorMetadata,
{
    service_code(error) == Some("NoSuchUpload")
}

fn classify_sdk_error<E, R>(error: &SdkError<E, R>) -> StoreError
where
    E: ProvideErrorMetadata,
{
    match error {
        SdkError::ConstructionFailure(_) => StoreError::Incompatible,
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => {
            StoreError::Unavailable
        }
        SdkError::ServiceError(_) => match service_code(error) {
            Some(
                "AccessDenied"
                | "ExpiredToken"
                | "InvalidAccessKeyId"
                | "InvalidToken"
                | "SignatureDoesNotMatch"
                | "Unauthorized",
            ) => StoreError::Unauthorized,
            Some(
                "InternalError"
                | "RequestTimeout"
                | "ServiceUnavailable"
                | "SlowDown"
                | "Throttling"
                | "TooManyRequestsException",
            ) => StoreError::Unavailable,
            _ => StoreError::Incompatible,
        },
        _ => StoreError::Incompatible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn endpoint() -> StoreS3EndpointId {
        StoreS3EndpointId::new("tests/minio").expect("endpoint")
    }

    #[test]
    fn worker_configuration_bounds_are_exact() {
        assert!(
            AwsSdkS3ClientConfig::new(0, 1, MIN_RETAINED_COMMAND_BYTES, MIN_OPERATION_TIMEOUT)
                .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(
                MAX_COMMAND_QUEUE + 1,
                1,
                MIN_RETAINED_COMMAND_BYTES,
                MIN_OPERATION_TIMEOUT
            )
            .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(1, 0, MIN_RETAINED_COMMAND_BYTES, MIN_OPERATION_TIMEOUT)
                .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(
                1,
                MAX_IN_FLIGHT_OPERATIONS + 1,
                MIN_RETAINED_COMMAND_BYTES,
                MIN_OPERATION_TIMEOUT
            )
            .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(1, 1, MIN_RETAINED_COMMAND_BYTES - 1, MIN_OPERATION_TIMEOUT)
                .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(1, 1, MAX_RETAINED_COMMAND_BYTES + 1, MIN_OPERATION_TIMEOUT)
                .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(
                1,
                1,
                MIN_RETAINED_COMMAND_BYTES,
                MIN_OPERATION_TIMEOUT - Duration::from_nanos(1)
            )
            .is_err()
        );
        assert!(
            AwsSdkS3ClientConfig::new(
                1,
                1,
                MIN_RETAINED_COMMAND_BYTES,
                MAX_OPERATION_TIMEOUT + Duration::from_nanos(1)
            )
            .is_err()
        );

        let minimum =
            AwsSdkS3ClientConfig::new(1, 1, MIN_RETAINED_COMMAND_BYTES, MIN_OPERATION_TIMEOUT)
                .expect("minimum");
        let maximum = AwsSdkS3ClientConfig::new(
            MAX_COMMAND_QUEUE,
            MAX_IN_FLIGHT_OPERATIONS,
            MAX_RETAINED_COMMAND_BYTES,
            MAX_OPERATION_TIMEOUT,
        )
        .expect("maximum");
        assert_eq!(minimum.maximum_queued_commands(), 1);
        assert_eq!(minimum.maximum_in_flight_operations(), 1);
        assert_eq!(
            minimum.maximum_retained_command_bytes(),
            MIN_RETAINED_COMMAND_BYTES
        );
        assert_eq!(minimum.operation_timeout(), MIN_OPERATION_TIMEOUT);
        assert_eq!(maximum.maximum_queued_commands(), MAX_COMMAND_QUEUE);
        assert_eq!(
            maximum.maximum_in_flight_operations(),
            MAX_IN_FLIGHT_OPERATIONS
        );
        assert_eq!(
            maximum.maximum_retained_command_bytes(),
            MAX_RETAINED_COMMAND_BYTES
        );
        assert_eq!(maximum.operation_timeout(), MAX_OPERATION_TIMEOUT);
    }

    #[test]
    fn synchronous_call_has_one_absolute_deadline() {
        let (commands, receiver) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let _command = receiver.recv().expect("one command");
            thread::sleep(Duration::from_millis(250));
        });
        let client = AwsSdkS3Client {
            endpoint: endpoint(),
            operation_timeout: MIN_OPERATION_TIMEOUT,
            worker: Arc::new(Worker {
                commands: Mutex::new(Some(commands)),
                thread: Mutex::new(Some(thread)),
                budget: Arc::new(CommandBudget::new(MIN_RETAINED_COMMAND_BYTES)),
            }),
        };

        let started = Instant::now();
        assert!(matches!(
            client.head_object("bucket", "objects/key"),
            Err(StoreError::Unavailable)
        ));
        assert!(started.elapsed() < Duration::from_millis(225));
    }

    #[test]
    fn ref_scan_pages_share_one_absolute_deadline() {
        let (commands, receiver) = mpsc::sync_channel::<QueuedCommand>(2);
        let thread = thread::spawn(move || {
            let first = receiver.recv().expect("first list command");
            thread::sleep(Duration::from_millis(150));
            match first.command {
                Command::ListSmallObjects {
                    after, response, ..
                } => {
                    let next = StoreS3ObjectListCursor::new("next-page").expect("cursor");
                    let page = StoreS3ObjectListPage::new(
                        vec!["tenant/refs/a".to_string()],
                        Some(next),
                        after.as_ref(),
                        1,
                    )
                    .expect("first page");
                    let _ = response.send(Ok(page));
                }
                _ => panic!("unexpected first command"),
            }

            let second = receiver.recv().expect("second list command");
            thread::sleep(Duration::from_millis(500));
            match second.command {
                Command::ListSmallObjects {
                    after, response, ..
                } => {
                    let page = StoreS3ObjectListPage::new(Vec::new(), None, after.as_ref(), 1)
                        .expect("EOF page");
                    let _ = response.send(Ok(page));
                }
                _ => panic!("unexpected second command"),
            }
        });
        let client = Arc::new(AwsSdkS3Client {
            endpoint: endpoint(),
            operation_timeout: Duration::from_millis(200),
            worker: Arc::new(Worker {
                commands: Mutex::new(Some(commands)),
                thread: Mutex::new(Some(thread)),
                budget: Arc::new(CommandBudget::new(MIN_RETAINED_COMMAND_BYTES)),
            }),
        });
        let strong = AwsSdkS3StrongCasClient::from_conformant_service(client);
        let started = Instant::now();
        let mut scan = strong
            .begin_small_object_scan("bucket", "tenant/refs/")
            .expect("scan session");
        scan.next_page(1).expect("first page before deadline");
        assert!(matches!(scan.next_page(1), Err(StoreError::Unavailable)));
        assert!(started.elapsed() < Duration::from_millis(300));
    }

    #[test]
    fn committed_inventory_metadata_shares_the_scan_deadline() {
        let (commands, receiver) = mpsc::sync_channel::<QueuedCommand>(2);
        let thread = thread::spawn(move || {
            let list = receiver.recv().expect("list command");
            thread::sleep(Duration::from_millis(150));
            match list.command {
                Command::ListSmallObjects {
                    after, response, ..
                } => {
                    let page = StoreS3ObjectListPage::new(
                        vec!["tenant/objects/object".to_string()],
                        None,
                        after.as_ref(),
                        1,
                    )
                    .expect("object page");
                    let _ = response.send(Ok(page));
                }
                _ => panic!("unexpected list command"),
            }

            let metadata = receiver.recv().expect("metadata command");
            thread::sleep(Duration::from_millis(500));
            match metadata.command {
                Command::HeadVersioned { response, .. } => {
                    let _ = response.send(Ok(Some(StoreS3VersionedObjectMetadata::new(
                        6,
                        StoreS3ObjectVersion::new("etag").expect("version"),
                    ))));
                }
                _ => panic!("unexpected metadata command"),
            }
        });
        let client = Arc::new(AwsSdkS3Client {
            endpoint: endpoint(),
            operation_timeout: Duration::from_millis(200),
            worker: Arc::new(Worker {
                commands: Mutex::new(Some(commands)),
                thread: Mutex::new(Some(thread)),
                budget: Arc::new(CommandBudget::new(MIN_RETAINED_COMMAND_BYTES)),
            }),
        });
        let strong = AwsSdkS3StrongCasClient::from_conformant_service(client);
        let started = Instant::now();
        let mut scan = strong
            .begin_small_object_scan("bucket", "tenant/objects/")
            .expect("scan session");
        scan.next_page(1).expect("object page before deadline");
        assert!(matches!(
            scan.head_versioned_object("tenant/objects/object"),
            Err(StoreError::Unavailable)
        ));
        assert!(started.elapsed() < Duration::from_millis(300));
    }

    #[test]
    fn command_byte_budget_is_shared_and_released() {
        let budget = Arc::new(CommandBudget::new(10));
        let first = budget.reserve(7).expect("first reservation");
        assert!(matches!(budget.reserve(4), Err(StoreError::Quota)));
        let second = budget.reserve(3).expect("remaining reservation");
        drop(first);
        let replacement = budget.reserve(7).expect("released reservation");
        drop((second, replacement));
        assert_eq!(budget.retained.load(Ordering::Acquire), 0);
    }

    #[test]
    fn queue_bounds_and_channel_reader_are_exact() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .blocking_send(DownloadChunk::Bytes(vec![1, 2]))
            .expect("first chunk");
        sender
            .blocking_send(DownloadChunk::Bytes(vec![3]))
            .expect("second chunk");
        drop(sender);
        let mut reader = ChannelReader::new(receiver);
        let mut bytes = Vec::new();
        assert!(reader.read_to_end(&mut bytes).is_err());
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn canonical_content_key_recovers_the_logical_id() {
        let id = ContentId::for_bytes(crucible_cas::content_store::ObjectKind::Trace, 1, b"S3 key");
        assert_eq!(key_content_id(&format!("prefix/objects/{id}")), Some(id));
        assert_eq!(key_content_id("prefix/objects/not-an-id"), None);
        assert!(request_location("", "objects/key").is_err());
        assert!(request_location("bucket", "").is_err());
        assert!(request_location("bucket", &"x".repeat(MAX_OBJECT_KEY_BYTES + 1)).is_err());
    }

    #[test]
    fn multipart_listing_requires_exact_bounded_pagination() {
        let upload = aws_sdk_s3::types::MultipartUpload::builder()
            .key("tenant/objects/a")
            .upload_id("upload-a")
            .build();
        let output =
            aws_sdk_s3::operation::list_multipart_uploads::ListMultipartUploadsOutput::builder()
                .bucket("bucket")
                .prefix("tenant/objects/")
                .max_uploads(1)
                .is_truncated(true)
                .next_key_marker("tenant/objects/a")
                .next_upload_id_marker("upload-a")
                .uploads(upload)
                .build();
        let page = decode_multipart_list_page("bucket", "tenant/objects/", None, 1, &output)
            .expect("exact multipart page");
        assert_eq!(page.uploads().len(), 1);
        assert_eq!(
            page.next().expect("continuation").key_marker(),
            "tenant/objects/a"
        );

        let malformed =
            aws_sdk_s3::operation::list_multipart_uploads::ListMultipartUploadsOutput::builder()
                .bucket("bucket")
                .prefix("tenant/objects/")
                .max_uploads(1)
                .is_truncated(true)
                .uploads(
                    aws_sdk_s3::types::MultipartUpload::builder()
                        .key("tenant/objects/a")
                        .upload_id("upload-a")
                        .build(),
                )
                .build();
        assert!(matches!(
            decode_multipart_list_page("bucket", "tenant/objects/", None, 1, &malformed),
            Err(StoreError::Incompatible)
        ));
    }

    #[test]
    fn small_versioned_reads_and_list_pages_are_strictly_bounded() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let object = aws_sdk_s3::operation::get_object::GetObjectOutput::builder()
            .content_length(3)
            .e_tag("etag-1")
            .body(ByteStream::from_static(b"ref"))
            .build();
        let decoded = runtime
            .block_on(decode_small_versioned_object(object, 4))
            .expect("bounded versioned object");
        assert_eq!(decoded.bytes(), b"ref");
        assert_eq!(decoded.version().as_str(), "etag-1");

        let metadata = aws_sdk_s3::operation::head_object::HeadObjectOutput::builder()
            .content_length(3)
            .e_tag("etag-1")
            .build();
        let metadata = decode_versioned_metadata(&metadata).expect("versioned metadata");
        assert_eq!(metadata.logical_length(), 3);
        assert_eq!(metadata.version().as_str(), "etag-1");
        let missing_version = aws_sdk_s3::operation::head_object::HeadObjectOutput::builder()
            .content_length(3)
            .build();
        assert!(matches!(
            decode_versioned_metadata(&missing_version),
            Err(StoreError::Incompatible)
        ));

        let listed = aws_sdk_s3::types::Object::builder()
            .key("tenant/refs/abc")
            .build();
        let output = aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output::builder()
            .name("bucket")
            .prefix("tenant/refs/")
            .max_keys(1)
            .key_count(1)
            .is_truncated(true)
            .next_continuation_token("next-page")
            .contents(listed)
            .build();
        let page = decode_small_object_list_page("bucket", "tenant/refs/", None, 1, &output)
            .expect("strict object page");
        assert_eq!(page.keys(), &["tenant/refs/abc".to_string()]);
        assert_eq!(page.next().expect("continuation").as_str(), "next-page");

        let malformed = aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output::builder()
            .name("bucket")
            .prefix("tenant/refs/")
            .max_keys(1)
            .key_count(0)
            .is_truncated(true)
            .next_continuation_token("next-page")
            .build();
        assert!(matches!(
            decode_small_object_list_page("bucket", "tenant/refs/", None, 1, &malformed),
            Err(StoreError::Incompatible)
        ));
    }
}

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
    ContentId, StoreError, StoreS3Client, StoreS3ConditionalPutOutcome, StoreS3EndpointId,
    StoreS3MultipartUpload, StoreS3ObjectDownload, StoreS3UploadedPart,
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
const MAX_OBJECT_KEY_BYTES: usize = 2_048;
const MAX_MULTIPART_PART_BYTES: usize = 64 * 1024 * 1024;
const MAX_MULTIPART_PARTS: usize = 10_000;
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
    }
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
}

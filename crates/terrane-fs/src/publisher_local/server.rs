//! Dispatches authenticated packets directly to the concrete native command owner.
//!
//! Connection owners are bounded OS threads. Wait deadlines return an error
//! without cancelling native effects; late result descriptors close before
//! another command is accepted. The native actor retains physical custody
//! even when this socket or its runtime disappears.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    os::fd::AsFd,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use terrane::host::publication::{PublicationClaim, PublicationRecipe};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Descriptor, TERRANE_V1},
};

use super::{
    Error,
    socket::{Connection, Listener, ReceivedPacket, RoleIdentities},
    validation::ValidationPolicy,
    wire::{BodyKey, BodyKind, Operation, Packet, ResultCode},
};
use crate::publisher_io::{
    NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeOperation,
    NativePublicationWorker,
};

/// Configured publisher-local endpoint policy and bounded connection resources.
pub struct ServerConfig {
    /// The protected absolute Unix socket path.
    pub socket_path: PathBuf,
    /// The distinct configured request and publication role identities.
    pub identities: RoleIdentities,
    /// The configured physical disclosure domain.
    pub domain: String,
    /// The configured registered profile label carried in claims.
    pub chunk_profile_name: String,
    /// The actual chunking profile used to validate native publication claims.
    pub chunk_profile: ChunkProfile,
    /// The maximum concurrent authenticated connection owners (1 through 1024).
    pub max_connections: usize,
}

/// The concrete native publisher endpoint, without a caller callback surface.
pub struct Server {
    listener: Listener,
    config: Arc<ServerConfig>,
    worker: Arc<NativePublicationWorker>,
}

impl Server {
    /// Binds a publisher socket backed by the concrete native command owner.
    ///
    /// # Errors
    ///
    /// Rejects invalid resource policy, empty configured labels, unsafe socket
    /// custody, the wrong role identity and kernel bind failures.
    pub fn bind(config: ServerConfig, worker: NativePublicationWorker) -> Result<Self, Error> {
        if !(1..=1024).contains(&config.max_connections)
            || config.domain.is_empty()
            || config.chunk_profile_name.is_empty()
        {
            return Err(Error::Invalid("server configuration"));
        }
        let listener = Listener::bind(&config.socket_path, config.identities)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
            worker: Arc::new(worker),
        })
    }

    /// Runs bounded connection owners until a listener or thread creation fails.
    ///
    /// This blocking entry point requires no caller Tokio runtime. Native actor
    /// custody outlives every connection runtime and wait deadline.
    ///
    /// # Errors
    ///
    /// Returns kernel listener errors and failures to create a connection owner.
    /// Unauthorized peers and malformed connections close without terminating
    /// the listener or dispatching native effects.
    pub fn run(self) -> Result<(), Error> {
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let connection = match self.listener.accept() {
                Ok(connection) => connection,
                Err(Error::Denied) => continue,
                Err(error) => return Err(error),
            };
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < self.config.max_connections).then_some(count + 1)
                })
                .is_err()
            {
                continue;
            }
            let permit = ConnectionPermit(Arc::clone(&active));
            let config = Arc::clone(&self.config);
            let worker = Arc::clone(&self.worker);
            thread::Builder::new()
                .name("publisher-local-owner".into())
                .spawn(move || {
                    let _permit = permit;
                    // Connection failures close all retained packet/reply files.
                    let _ = run_connection(connection, &config, &worker);
                })?;
        }
    }
}

struct ConnectionPermit(Arc<AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Cursor {
    incarnation: Vec<u8>,
    native: Vec<u8>,
}

fn run_connection(
    connection: Connection,
    config: &ServerConfig,
    worker: &NativePublicationWorker,
) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let policy = ValidationPolicy {
        domain: &config.domain,
        identity: &TERRANE_V1,
        chunk_profile: &config.chunk_profile_name,
    };
    let mut cursors = BTreeMap::<Vec<u8>, Cursor>::new();
    loop {
        let request = connection.receive(&policy)?;
        let header = request.packet.clone();
        let context = NativeCommandContext {
            domain: config.domain.clone(),
            cache_incarnation: header
                .cache_incarnation
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("cache incarnation"))?,
        };
        let operation = match native_operation(request, config, &mut cursors) {
            Ok(operation) => operation,
            Err(error) => {
                connection.send(&error_response(&header, error_code(&error)), &[], &policy)?;
                continue;
            }
        };
        let outcome = runtime.block_on(async {
            let execution = worker.execute(context, operation);
            tokio::pin!(execution);
            match tokio::time::timeout(Duration::from_millis(header.wait_budget_ms), &mut execution)
                .await
            {
                Ok(result) => Ok::<_, Error>(Some(result)),
                Err(_) => {
                    let sent = connection.send(
                        &error_response(&header, ResultCode::Unavailable),
                        &[],
                        &policy,
                    );
                    // A timed-out request cannot be reused while its accepted
                    // native effect is still active. Finish waiting before
                    // accepting another command; late result files close here.
                    drop(execution.await);
                    sent?;
                    Ok(None)
                }
            }
        })?;
        let result = match outcome {
            Some(Ok(result)) => result,
            Some(Err(error)) => {
                connection.send(
                    &error_response(&header, io_error_code(&error)),
                    &[],
                    &policy,
                )?;
                continue;
            }
            None => continue,
        };
        let (response, files) = native_response(&header, result, &mut cursors)?;
        let borrowed = files.iter().map(AsFd::as_fd).collect::<Vec<_>>();
        connection.send(&response, &borrowed, &policy)?;
    }
}

fn native_operation(
    request: ReceivedPacket,
    config: &ServerConfig,
    cursors: &mut BTreeMap<Vec<u8>, Cursor>,
) -> Result<NativeOperation, Error> {
    let ReceivedPacket { packet, files } = request;
    let operation =
        Operation::try_from(packet.operation).map_err(|_| Error::Invalid("operation"))?;
    let mut files = files.into_iter();
    let claim = match packet.claim {
        Some(claim) => {
            if claim.manifest_length != 0 {
                // A wire retention ID cannot mint the cache owner's durable pin.
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "manifest publication requires native retention receipt composition",
                )
                .into());
            }
            let chunk = Descriptor::decode(&TERRANE_V1, &claim.descriptor)
                .map_err(|_| Error::Invalid("claim descriptor"))?;
            Some(PublicationClaim::new(
                config.domain.clone(),
                PublicationRecipe::Inline { chunk },
                &config.chunk_profile,
            )?)
        }
        None => None,
    };
    let body = packet.body.map(native_key).transpose()?;
    let token = || {
        packet
            .body_incarnation
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("body incarnation"))
    };
    let required_body = || body.clone().ok_or(Error::Invalid("missing body"));
    Ok(match operation {
        Operation::Probe => NativeOperation::Probe,
        Operation::Publish => NativeOperation::Publish {
            claim: claim.ok_or(Error::Invalid("missing claim"))?,
            source: files.next().ok_or(Error::Invalid("missing source"))?,
        },
        Operation::Adopt => NativeOperation::Adopt {
            claim: claim.ok_or(Error::Invalid("missing claim"))?,
        },
        Operation::InspectBody => NativeOperation::InspectBody {
            key: required_body()?,
            claim,
        },
        Operation::Retire => NativeOperation::Retire {
            key: required_body()?,
            incarnation: token()?,
        },
        Operation::Restore => NativeOperation::Restore {
            key: required_body()?,
            incarnation: token()?,
        },
        Operation::FinishRetirement => NativeOperation::FinishRetirement {
            key: required_body()?,
            incarnation: token()?,
        },
        Operation::Drain => {
            cursors.clear();
            NativeOperation::Drain
        }
        Operation::Inventory => {
            let cursor = if packet.inventory_cursor.is_empty() {
                None
            } else {
                let cursor = cursors
                    .remove(&packet.inventory_cursor)
                    .ok_or(Error::Invalid("unknown connection inventory cursor"))?;
                if cursor.incarnation != packet.cache_incarnation {
                    return Err(Error::Invalid("cursor owner incarnation"));
                }
                Some(cursor.native)
            };
            NativeOperation::Inventory { cursor }
        }
        Operation::Resume => {
            cursors.clear();
            NativeOperation::Resume
        }
        Operation::InspectPending => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pending inspection awaits the concrete native custody command",
            )
            .into());
        }
        Operation::Unspecified => return Err(Error::Invalid("operation")),
    })
}

fn native_key(key: BodyKey) -> Result<NativeBodyKey, Error> {
    match BodyKind::try_from(key.kind).map_err(|_| Error::Invalid("body kind"))? {
        BodyKind::Sealed => Ok(NativeBodyKey::Sealed {
            descriptor: Descriptor::decode(&TERRANE_V1, &key.descriptor)
                .map_err(|_| Error::Invalid("sealed descriptor"))?,
        }),
        BodyKind::Chunk => Ok(NativeBodyKey::Chunk {
            descriptor: Descriptor::decode(&TERRANE_V1, &key.descriptor)
                .map_err(|_| Error::Invalid("chunk descriptor"))?,
            codec: u8::try_from(key.codec).map_err(|_| Error::Invalid("codec"))?,
        }),
        BodyKind::Pack => Ok(NativeBodyKey::Pack {
            pack_id: key
                .pack_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("pack ID"))?,
        }),
        BodyKind::Unspecified => Err(Error::Invalid("body kind")),
    }
}

fn wire_key(key: NativeBodyKey) -> BodyKey {
    match key {
        NativeBodyKey::Sealed { descriptor } => BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor: descriptor.encode(),
            ..BodyKey::default()
        },
        NativeBodyKey::Chunk { descriptor, codec } => BodyKey {
            kind: BodyKind::Chunk as i32,
            descriptor: descriptor.encode(),
            codec: u32::from(codec),
            ..BodyKey::default()
        },
        NativeBodyKey::Pack { pack_id } => BodyKey {
            kind: BodyKind::Pack as i32,
            pack_id: pack_id.to_vec(),
            ..BodyKey::default()
        },
    }
}

fn native_response(
    header: &Packet,
    result: NativeCommandResult,
    cursors: &mut BTreeMap<Vec<u8>, Cursor>,
) -> Result<(Packet, Vec<File>), Error> {
    let mut packet = error_response(header, ResultCode::Ok);
    let mut files = Vec::new();
    match result {
        NativeCommandResult::Probe { file, binding } => {
            packet.verity_algorithm = u32::from(binding.algorithm);
            packet.verity_digest = binding.digest;
            files.push(file);
        }
        NativeCommandResult::Published {
            object,
            incarnation,
        } => {
            packet.verity_algorithm = u32::from(object.binding().algorithm);
            packet.verity_digest = object.binding().digest.clone();
            packet.body_incarnation = incarnation.bytes().to_vec();
            files.push(object.into_handle());
        }
        NativeCommandResult::Inspected { body, incarnation } => {
            packet.body_incarnation = incarnation.bytes().to_vec();
            files.push(body.into_handle());
        }
        NativeCommandResult::Complete => {}
        NativeCommandResult::Inventory { keys, next_cursor } => {
            packet.inventory = keys.into_iter().map(wire_key).collect();
            if let Some(native) = next_cursor {
                let mut opaque = vec![0u8; 32];
                File::open("/dev/urandom")?.read_exact(&mut opaque)?;
                cursors.clear();
                cursors.insert(
                    opaque.clone(),
                    Cursor {
                        incarnation: header.cache_incarnation.clone(),
                        native,
                    },
                );
                packet.inventory_cursor = opaque;
            }
        }
    }
    Ok((packet, files))
}

fn error_response(header: &Packet, result: ResultCode) -> Packet {
    Packet {
        version: header.version,
        request_id: header.request_id,
        operation: header.operation,
        domain: header.domain.clone(),
        cache_incarnation: header.cache_incarnation.clone(),
        response: true,
        result: result as i32,
        ..Packet::default()
    }
}

fn error_code(error: &Error) -> ResultCode {
    match error {
        Error::Io(error) => io_error_code(error),
        Error::Denied => ResultCode::Denied,
        _ => ResultCode::Invalid,
    }
}

fn io_error_code(error: &io::Error) -> ResultCode {
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => ResultCode::Invalid,
        io::ErrorKind::PermissionDenied => ResultCode::Denied,
        io::ErrorKind::NotFound => ResultCode::NotFound,
        io::ErrorKind::AlreadyExists => ResultCode::Conflict,
        io::ErrorKind::Unsupported => ResultCode::Unsupported,
        io::ErrorKind::OutOfMemory => ResultCode::ResourceExhausted,
        _ => ResultCode::Unavailable,
    }
}

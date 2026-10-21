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
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use terrane_format::{
    chunking::ChunkProfile,
    identity::{Descriptor, TERRANE_V1},
    properties::Domain,
};
use terrane_sdk::host::{
    cache::HostReadLimits,
    publication::{PublicationClaim, PublicationRecipe},
};

use super::{
    Error,
    socket::{Connection, Listener, ReceivedPacket, RoleIdentities},
    validation::ValidationPolicy,
    wire::{BodyKey, BodyKind, Operation, Packet, ResultCode},
};
use crate::publisher_io::{
    NativeBodyKey, NativeCommandContext, NativeCommandResult, NativeManifestWitness,
    NativeOperation, NativePublicationWorker, ReceivedManifest,
};

/// Configured publisher-local endpoint policy and bounded connection resources.
pub struct ServerConfig {
    /// The protected absolute Unix socket path.
    pub socket_path: PathBuf,
    /// The distinct configured request and publication role identities.
    pub identities: RoleIdentities,
    /// The maximum concurrent authenticated connection owners (1 through 1024).
    pub max_connections: usize,
}

/// Binds one configured domain and profile to its concrete native command owner.
pub struct DomainPublisher {
    /// The configured physical disclosure domain.
    pub domain: String,
    /// The configured registered profile label carried in claims.
    pub chunk_profile_name: String,
    /// The actual chunking profile used to validate native publication claims.
    pub chunk_profile: ChunkProfile,
    /// The actual independently owning native worker for this domain.
    pub worker: NativePublicationWorker,
}

/// The concrete native publisher endpoint, without a caller callback surface.
pub struct Server {
    listener: Listener,
    config: Arc<ServerConfig>,
    domains: Arc<BTreeMap<String, DomainPublisher>>,
    custody: Option<Arc<crate::configured::ConfiguredPublisherCustody>>,
    metadata: Arc<MetadataVerification>,
}

struct MetadataVerification {
    limits: HostReadLimits,
    gate: Mutex<()>,
}

impl Server {
    /// Binds a publisher socket backed by the concrete native command owner.
    ///
    /// # Errors
    ///
    /// Rejects invalid resource policy, empty configured labels, unsafe socket
    /// custody, duplicate/noncanonical domain labels, the wrong role identity
    /// and kernel bind failures. Unknown request domains never use a fallback.
    pub fn bind(config: ServerConfig, domains: Vec<DomainPublisher>) -> Result<Self, Error> {
        Self::bind_with_metadata_limits(config, domains, HostReadLimits::default())
    }

    /// Binds with a trusted per-allocation metadata verification budget.
    ///
    /// Only one full received-pack verification runs at a time across all
    /// configured domains. The default constructor uses a 64 MiB per-allocation
    /// budget. Encoded pack and decoded canonical payload allocations are
    /// separately bounded; this is not a total heap or retained-row budget.
    ///
    /// # Errors
    ///
    /// Returns the configuration, identity and kernel errors of `bind`, or an
    /// invalid-resource-policy error for a zero allocation limit.
    pub fn bind_with_metadata_limits(
        config: ServerConfig,
        domains: Vec<DomainPublisher>,
        limits: HostReadLimits,
    ) -> Result<Self, Error> {
        if limits.max_allocation_bytes == 0 {
            return Err(Error::Invalid("metadata allocation resource policy"));
        }
        if !(1..=1024).contains(&config.max_connections) || domains.is_empty() {
            return Err(Error::Invalid("server configuration"));
        }
        let mut registered = BTreeMap::new();
        for domain in domains {
            Domain::parse(&domain.domain)
                .map_err(|_| Error::Invalid("configured disclosure domain"))?;
            if domain.chunk_profile_name.is_empty() {
                return Err(Error::Invalid("configured chunk profile"));
            }
            if registered.insert(domain.domain.clone(), domain).is_some() {
                return Err(Error::Invalid("duplicate configured domain"));
            }
        }
        let listener = Listener::bind(&config.socket_path, config.identities)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
            domains: Arc::new(registered),
            custody: None,
            metadata: Arc::new(MetadataVerification {
                limits,
                gate: Mutex::new(()),
            }),
        })
    }

    /// Retains genuine configured quota custody through accepted native work.
    pub(crate) fn with_configured_custody(
        mut self,
        custody: Arc<crate::configured::ConfiguredPublisherCustody>,
    ) -> Self {
        self.custody = Some(custody);
        self
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
            let domains = Arc::clone(&self.domains);
            let custody = self.custody.clone();
            let metadata = Arc::clone(&self.metadata);
            thread::Builder::new()
                .name("publisher-local-owner".into())
                .spawn(move || {
                    let _permit = permit;
                    let _custody = custody;
                    // Connection failures close all retained packet/reply files.
                    let _ = run_connection(connection, &domains, &metadata);
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
    domain: String,
    incarnation: Vec<u8>,
    native: Vec<u8>,
}

fn run_connection(
    connection: Connection,
    domains: &BTreeMap<String, DomainPublisher>,
    metadata: &MetadataVerification,
) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let policies = domains
        .values()
        .map(|domain| ValidationPolicy {
            domain: &domain.domain,
            identity: &TERRANE_V1,
            chunk_profile: &domain.chunk_profile_name,
        })
        .collect::<Vec<_>>();
    let mut cursors = BTreeMap::<Vec<u8>, Cursor>::new();
    loop {
        let request = connection.receive_selected(&policies)?;
        let header = request.packet.clone();
        let selected = domains.get(&header.domain).ok_or(Error::Denied)?;
        let policy = ValidationPolicy {
            domain: &selected.domain,
            identity: &TERRANE_V1,
            chunk_profile: &selected.chunk_profile_name,
        };
        let context = NativeCommandContext {
            domain: selected.domain.clone(),
            cache_incarnation: header
                .cache_incarnation
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("cache incarnation"))?,
        };
        let operation = match native_operation(request, selected, &mut cursors, metadata) {
            Ok(operation) => operation,
            Err(error) => {
                connection.send(&error_response(&header, error_code(&error)), &[], &policy)?;
                continue;
            }
        };
        let outcome = runtime.block_on(async {
            let execution = selected.worker.execute(context, operation);
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
    config: &DomainPublisher,
    cursors: &mut BTreeMap<Vec<u8>, Cursor>,
    metadata: &MetadataVerification,
) -> Result<NativeOperation, Error> {
    let ReceivedPacket { packet, files } = request;
    let operation =
        Operation::try_from(packet.operation).map_err(|_| Error::Invalid("operation"))?;
    let mut files = files.into_iter();
    if packet
        .claim
        .as_ref()
        .is_some_and(|claim| claim.manifest_length != 0)
    {
        return manifest_operation(operation, packet, files, config, metadata);
    }
    let claim = match packet.claim {
        Some(claim) => {
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
            cursors.retain(|_, cursor| cursor.domain != packet.domain);
            NativeOperation::Drain
        }
        Operation::Inventory => {
            let cursor = if packet.inventory_cursor.is_empty() {
                None
            } else {
                let cursor = cursors
                    .remove(&packet.inventory_cursor)
                    .ok_or(Error::Invalid("unknown connection inventory cursor"))?;
                if cursor.domain != packet.domain || cursor.incarnation != packet.cache_incarnation
                {
                    return Err(Error::Invalid("cursor owner incarnation"));
                }
                Some(cursor.native)
            };
            NativeOperation::Inventory { cursor }
        }
        Operation::Resume => {
            cursors.retain(|_, cursor| cursor.domain != packet.domain);
            NativeOperation::Resume
        }
        Operation::InspectPending => NativeOperation::InspectPending {
            key: required_body()?,
        },
        Operation::InspectQuarantine => NativeOperation::InspectQuarantine {
            key: required_body()?,
            incarnation: if packet.body_incarnation.is_empty() {
                None
            } else {
                Some(token()?)
            },
        },
        Operation::Quarantine => NativeOperation::Quarantine {
            key: required_body()?,
            incarnation: token()?,
        },
        Operation::Unspecified => return Err(Error::Invalid("operation")),
    })
}

fn manifest_operation(
    operation: Operation,
    packet: Packet,
    mut files: std::vec::IntoIter<File>,
    config: &DomainPublisher,
    metadata: &MetadataVerification,
) -> Result<NativeOperation, Error> {
    let source = match operation {
        Operation::Publish => Some(
            files
                .next()
                .ok_or(Error::Invalid("missing plaintext source"))?,
        ),
        Operation::Adopt | Operation::InspectBody => None,
        _ => return Err(Error::Invalid("manifest command")),
    };
    let pack = files
        .next()
        .ok_or(Error::Invalid("missing reconstruction metadata pack"))?;
    if files.next().is_some() {
        return Err(Error::Invalid("excess manifest descriptors"));
    }
    let claim = packet
        .claim
        .ok_or(Error::Invalid("missing manifest claim"))?;
    let descriptor = Descriptor::decode(&TERRANE_V1, &claim.descriptor)
        .map_err(|_| Error::Invalid("manifest descriptor"))?;
    // This independently verifies the actual bounded pack/range and copies
    // canonical metadata with positioned reads. A retention ID is not passed
    // to the witness factory and never becomes native durable-pin authority.
    let _permit = metadata
        .gate
        .lock()
        .map_err(|_| Error::Invalid("poisoned metadata verification owner"))?;
    let witness = NativeManifestWitness::verify_received(
        ReceivedManifest {
            domain: config.domain.clone(),
            descriptor,
            metadata_pack: pack,
            offset: claim.manifest_offset,
            length: claim.manifest_length,
            plaintext_size: claim.plaintext_size,
        },
        &config.chunk_profile,
        metadata.limits,
    )?;
    Ok(match operation {
        Operation::Publish => NativeOperation::PublishManifest {
            witness,
            source: source.ok_or(Error::Invalid("missing plaintext source"))?,
        },
        Operation::Adopt => NativeOperation::AdoptManifest { witness },
        Operation::InspectBody => NativeOperation::InspectManifest {
            key: native_key(packet.body.ok_or(Error::Invalid("missing sealed key"))?)?,
            witness,
        },
        _ => return Err(Error::Invalid("manifest command")),
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
        NativeCommandResult::Probe { probe } => {
            packet.verity_algorithm = u32::from(probe.binding().algorithm);
            packet.verity_digest = probe.binding().digest.clone();
            files.push(probe.into_handle());
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
        NativeCommandResult::Pending { incarnation } => {
            packet.body_incarnation = incarnation.bytes().to_vec();
        }
        NativeCommandResult::Quarantined { body } => files.push(body.into_handle()),
        NativeCommandResult::Complete => {}
        NativeCommandResult::Inventory { keys, next_cursor } => {
            packet.inventory = keys.into_iter().map(wire_key).collect();
            if let Some(native) = next_cursor {
                let mut opaque = vec![0u8; 32];
                File::open("/dev/urandom")?.read_exact(&mut opaque)?;
                cursors.retain(|_, cursor| cursor.domain != header.domain);
                cursors.insert(
                    opaque.clone(),
                    Cursor {
                        domain: header.domain.clone(),
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

//! Lease-bound daemon relay for stable GDB byte streams.
//!
//! A relay connects only to a private Unix or loopback endpoint reported by the session actor.
//! Every operation presents the authenticated client and controller generation;
//! reconnecting the HTTP/2 transport never transfers relay ownership. Each
//! relay retains one idempotent holder on the active controller lease. Other
//! commands from that principal use independent holders, while another
//! principal remains excluded until the final holder closes.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
// crucible-lint: allow host-monotonic-time -- relay expiry releases only daemon-local transport resources and never enters scenario, replay, or fingerprint state.
use std::time::{Duration, Instant as RelayInstant};

use crucible_session::{DebugClientId, DebugControllerLease};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Mutex;

use crate::SessionRef;
use crate::debug_holders::DebugControllerHolderId;

/// Maximum GDB bytes read or written by one relay RPC.
pub const DEBUG_RELAY_CHUNK_MAX_BYTES: usize = 64 * 1024;

const DEBUG_RELAY_IO_TIMEOUT: Duration = Duration::from_secs(5);
const DEBUG_RELAY_STALE_AFTER: Duration = Duration::from_secs(30);
const DEBUG_RELAY_TOMBSTONE_LIMIT: usize = 128;

/// Reads the operational relay clock outside deterministic scenario state.
// crucible-lint: allow clippy-disallowed-method -- relay expiry governs only daemon-local transport resource reclamation.
#[allow(clippy::disallowed_methods)]
fn relay_clock_now() -> RelayInstant {
    RelayInstant::now()
}

/// Opaque daemon-local identifier for one GDB relay connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugRelayId(
    /// Monotonic process-local numeric identity.
    pub u64,
);

/// One nonblocking read from a debug relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRelayChunk {
    /// Bytes currently available from the gateway.
    pub bytes: Vec<u8>,
    /// Whether the gateway side closed the stream.
    pub eof: bool,
}

#[derive(Default)]
pub(crate) struct DebugRelayRegistry {
    next_id: u64,
    relays: BTreeMap<DebugRelayId, DebugRelay>,
    tombstones: BTreeMap<DebugRelayId, DebugRelayTombstone>,
}

struct DebugRelay {
    session: SessionRef,
    lease: DebugControllerLease,
    holder: DebugControllerHolderId,
    stream: Arc<Mutex<DebugRelayStream>>,
    access: DebugRelayAccess,
    read_only_filter: ReadOnlyGdbFilter,
    last_activity: RelayInstant,
}

pub(crate) enum DebugRelayStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl DebugRelayStream {
    #[cfg(test)]
    async fn readable(&self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.readable().await,
            Self::Unix(stream) => stream.readable().await,
        }
    }

    fn try_read(&self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.try_read(bytes),
            Self::Unix(stream) => stream.try_read(bytes),
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(bytes).await,
            Self::Unix(stream) => stream.write_all(bytes).await,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DebugRelayAccess {
    ReadWrite,
    ReadOnly,
}

#[derive(Default)]
struct ReadOnlyGdbFilter {
    pending: Vec<u8>,
}

struct DebugRelayTombstone {
    session: SessionRef,
    lease: DebugControllerLease,
    holder: DebugControllerHolderId,
}

pub(crate) struct DebugRelayClose {
    pub(crate) lease: DebugControllerLease,
    pub(crate) holder: DebugControllerHolderId,
}

impl DebugRelayRegistry {
    #[cfg(test)]
    pub(crate) fn has_for_lease(&self, session: SessionRef, lease: &DebugControllerLease) -> bool {
        self.relays
            .values()
            .any(|relay| relay.session == session && relay.lease == *lease)
    }

    pub(crate) fn existing(
        &mut self,
        session: SessionRef,
        lease: &DebugControllerLease,
        holder: DebugControllerHolderId,
    ) -> Option<DebugRelayId> {
        self.relays.iter_mut().find_map(|(id, relay)| {
            if relay.session == session && relay.lease == *lease && relay.holder == holder {
                relay.last_activity = relay_clock_now();
                Some(*id)
            } else {
                None
            }
        })
    }

    pub(crate) fn has_holder(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        holder: DebugControllerHolderId,
    ) -> bool {
        self.relays.values().any(|relay| {
            relay.session == session && relay.lease == *lease && relay.holder == holder
        })
    }

    pub(crate) async fn connect(endpoint: &str) -> Result<DebugRelayStream, DebugRelayError> {
        if let Some(path) = endpoint.strip_prefix("unix:") {
            let path = Path::new(path);
            let parent = path
                .parent()
                .ok_or(DebugRelayError::InvalidGatewayEndpoint)?;
            let directory =
                std::fs::metadata(parent).map_err(|_| DebugRelayError::InvalidGatewayEndpoint)?;
            let socket =
                std::fs::metadata(path).map_err(|_| DebugRelayError::InvalidGatewayEndpoint)?;
            if !path.is_absolute()
                || !directory.is_dir()
                || directory.permissions().mode() & 0o077 != 0
                || !socket.file_type().is_socket()
                || socket.permissions().mode() & 0o077 != 0
            {
                return Err(DebugRelayError::InvalidGatewayEndpoint);
            }
            return tokio::time::timeout(DEBUG_RELAY_IO_TIMEOUT, UnixStream::connect(path))
                .await
                .map_err(|_| DebugRelayError::ConnectTimeout)?
                .map(DebugRelayStream::Unix)
                .map_err(|error| DebugRelayError::Connect {
                    message: error.to_string(),
                });
        }
        let address: SocketAddr = endpoint
            .parse()
            .map_err(|_| DebugRelayError::InvalidGatewayEndpoint)?;
        if !address.ip().is_loopback() {
            return Err(DebugRelayError::GatewayEndpointNotLoopback);
        }
        tokio::time::timeout(DEBUG_RELAY_IO_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| DebugRelayError::ConnectTimeout)?
            .map(DebugRelayStream::Tcp)
            .map_err(|error| DebugRelayError::Connect {
                message: error.to_string(),
            })
    }

    pub(crate) fn register(
        &mut self,
        stream: DebugRelayStream,
        session: SessionRef,
        lease: DebugControllerLease,
        holder: DebugControllerHolderId,
        access: DebugRelayAccess,
    ) -> Result<DebugRelayId, DebugRelayError> {
        if let Some(id) = self.existing(session, &lease, holder) {
            return Ok(id);
        }
        if self.relays.values().any(|relay| relay.session == session) {
            return Err(DebugRelayError::CapacityExhausted);
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(DebugRelayError::IdentifierExhausted)?;
        let id = DebugRelayId(self.next_id);
        self.relays.insert(
            id,
            DebugRelay {
                session,
                lease,
                holder,
                stream: Arc::new(Mutex::new(stream)),
                access,
                read_only_filter: ReadOnlyGdbFilter::default(),
                last_activity: relay_clock_now(),
            },
        );
        Ok(id)
    }

    pub(crate) async fn write_stream(
        stream: Arc<Mutex<DebugRelayStream>>,
        bytes: &[u8],
    ) -> Result<usize, DebugRelayError> {
        if bytes.len() > DEBUG_RELAY_CHUNK_MAX_BYTES {
            return Err(DebugRelayError::ChunkTooLarge {
                length: bytes.len(),
            });
        }
        let mut stream = stream.lock().await;
        tokio::time::timeout(DEBUG_RELAY_IO_TIMEOUT, stream.write_all(bytes))
            .await
            .map_err(|_| DebugRelayError::IoTimeout)?
            .map_err(|error| DebugRelayError::Io {
                message: error.to_string(),
            })?;
        Ok(bytes.len())
    }

    pub(crate) fn prepare_write(
        &mut self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        holder: DebugControllerHolderId,
        bytes: &[u8],
    ) -> Result<(Arc<Mutex<DebugRelayStream>>, Vec<u8>), DebugRelayError> {
        if bytes.len() > DEBUG_RELAY_CHUNK_MAX_BYTES {
            return Err(DebugRelayError::ChunkTooLarge {
                length: bytes.len(),
            });
        }
        let relay = self.checked_relay_mut(id, session, client, generation, holder)?;
        relay.last_activity = relay_clock_now();
        let forwarded = match relay.access {
            DebugRelayAccess::ReadWrite => bytes.to_vec(),
            DebugRelayAccess::ReadOnly => relay.read_only_filter.accept(bytes)?,
        };
        Ok((Arc::clone(&relay.stream), forwarded))
    }

    pub(crate) fn touch(
        &mut self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        holder: DebugControllerHolderId,
    ) -> Result<(), DebugRelayError> {
        self.checked_relay_mut(id, session, client, generation, holder)?
            .last_activity = relay_clock_now();
        Ok(())
    }

    pub(crate) fn read(
        &mut self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        holder: DebugControllerHolderId,
        maximum: usize,
    ) -> Result<DebugRelayChunk, DebugRelayError> {
        if maximum == 0 || maximum > DEBUG_RELAY_CHUNK_MAX_BYTES {
            return Err(DebugRelayError::InvalidReadMaximum { maximum });
        }
        let relay = self.checked_relay_mut(id, session, client, generation, holder)?;
        relay.last_activity = relay_clock_now();
        let stream = relay.stream.try_lock().map_err(|_| DebugRelayError::Busy)?;
        let mut bytes = vec![0_u8; maximum];
        match stream.try_read(&mut bytes) {
            Ok(0) => Ok(DebugRelayChunk {
                bytes: Vec::new(),
                eof: true,
            }),
            Ok(length) => {
                bytes.truncate(length);
                Ok(DebugRelayChunk { bytes, eof: false })
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(DebugRelayChunk {
                bytes: Vec::new(),
                eof: false,
            }),
            Err(error) => Err(DebugRelayError::Io {
                message: error.to_string(),
            }),
        }
    }

    pub(crate) fn close(
        &mut self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        holder: DebugControllerHolderId,
    ) -> Result<DebugRelayClose, DebugRelayError> {
        if let Some(relay) = self.relays.get(&id) {
            if relay.session != session
                || relay.lease.client != *client
                || relay.lease.generation != generation
                || relay.holder != holder
            {
                return Err(DebugRelayError::StaleOrForeignLease);
            }
        } else if let Some(closed) = self.tombstones.get(&id) {
            if closed.session != session
                || closed.lease.client != *client
                || closed.lease.generation != generation
                || closed.holder != holder
            {
                return Err(DebugRelayError::StaleOrForeignLease);
            }
            return Ok(DebugRelayClose {
                lease: closed.lease.clone(),
                holder: closed.holder,
            });
        } else {
            return Err(DebugRelayError::NotFound);
        }
        let relay = self.relays.remove(&id).ok_or(DebugRelayError::NotFound)?;
        let close = DebugRelayClose {
            lease: relay.lease.clone(),
            holder: relay.holder,
        };
        self.tombstones.insert(
            id,
            DebugRelayTombstone {
                session: relay.session,
                lease: relay.lease,
                holder: relay.holder,
            },
        );
        while self.tombstones.len() > DEBUG_RELAY_TOMBSTONE_LIMIT {
            let Some(oldest) = self.tombstones.keys().next().copied() else {
                break;
            };
            self.tombstones.remove(&oldest);
        }
        Ok(close)
    }

    pub(crate) fn close_for_session(
        &mut self,
        session: SessionRef,
    ) -> Vec<(DebugControllerLease, DebugControllerHolderId)> {
        let mut closed = Vec::new();
        self.relays.retain(|_, relay| {
            if relay.session == session {
                closed.push((relay.lease.clone(), relay.holder));
                false
            } else {
                true
            }
        });
        self.tombstones.retain(|_, relay| relay.session != session);
        closed
    }

    pub(crate) fn remove_stale(
        &mut self,
        session: SessionRef,
    ) -> Vec<(DebugControllerLease, DebugControllerHolderId)> {
        let now = relay_clock_now();
        let mut stale = Vec::new();
        self.relays.retain(|_, relay| {
            let expired = relay.session == session
                && now.saturating_duration_since(relay.last_activity) >= DEBUG_RELAY_STALE_AFTER;
            if expired {
                stale.push((relay.lease.clone(), relay.holder));
            }
            !expired
        });
        stale
    }

    fn checked_relay_mut(
        &mut self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        holder: DebugControllerHolderId,
    ) -> Result<&mut DebugRelay, DebugRelayError> {
        let relay = self.relays.get_mut(&id).ok_or(DebugRelayError::NotFound)?;
        if relay.session != session
            || relay.lease.client != *client
            || relay.lease.generation != generation
            || relay.holder != holder
        {
            return Err(DebugRelayError::StaleOrForeignLease);
        }
        Ok(relay)
    }
}

/// Errors returned by the daemon's stable GDB byte relay.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugRelayError {
    /// The actor returned an endpoint that was not a TCP socket address.
    #[error("debug gateway operator endpoint is not a TCP socket address")]
    InvalidGatewayEndpoint,
    /// The actor returned a non-loopback gateway endpoint.
    #[error("debug gateway operator endpoint must be loopback")]
    GatewayEndpointNotLoopback,
    /// The daemon could not connect to the stable local gateway.
    #[error("cannot connect to debug gateway: {message}")]
    Connect {
        /// Stable I/O diagnostic.
        message: String,
    },
    /// The daemon-local relay identifier space was exhausted.
    #[error("debug relay identifier space exhausted")]
    IdentifierExhausted,
    /// The session already owns its one permitted GDB relay.
    #[error("session already owns a debug relay connection")]
    CapacityExhausted,
    /// Connecting to the local gateway exceeded the bounded timeout.
    #[error("debug relay gateway connection timed out")]
    ConnectTimeout,
    /// The relay does not exist or has already closed.
    #[error("debug relay was not found")]
    NotFound,
    /// The request used another client's or an expired controller lease.
    #[error("debug relay controller lease is stale or foreign")]
    StaleOrForeignLease,
    /// One write exceeded the bounded relay chunk size.
    #[error("debug relay chunk length {length} exceeds the limit")]
    ChunkTooLarge {
        /// Rejected byte length.
        length: usize,
    },
    /// One read requested an invalid bounded size.
    #[error("debug relay read maximum {maximum} is invalid")]
    InvalidReadMaximum {
        /// Rejected maximum.
        maximum: usize,
    },
    /// The connected gateway stream failed.
    #[error("debug relay I/O failed: {message}")]
    Io {
        /// Stable I/O diagnostic.
        message: String,
    },
    /// A relay I/O operation exceeded the bounded timeout.
    #[error("debug relay I/O timed out")]
    IoTimeout,
    /// Another operation currently owns the relay stream.
    #[error("debug relay is busy")]
    Busy,
    /// A read-only relay received malformed GDB remote-protocol bytes.
    #[error("read-only debug relay received an invalid GDB packet")]
    InvalidReadOnlyPacket,
    /// A read-only relay received a command that can change target state.
    #[error("read-only debug relay rejected a state-changing GDB command")]
    ReadOnlyCommand,
}

impl ReadOnlyGdbFilter {
    fn accept(&mut self, bytes: &[u8]) -> Result<Vec<u8>, DebugRelayError> {
        let pending_length = self
            .pending
            .len()
            .checked_add(bytes.len())
            .ok_or(DebugRelayError::InvalidReadOnlyPacket)?;
        if pending_length > DEBUG_RELAY_CHUNK_MAX_BYTES {
            return Err(DebugRelayError::InvalidReadOnlyPacket);
        }
        self.pending.extend_from_slice(bytes);

        let mut forwarded = Vec::with_capacity(self.pending.len());
        let mut cursor = 0;
        while cursor < self.pending.len() {
            match self.pending[cursor] {
                b'+' | b'-' => {
                    forwarded.push(self.pending[cursor]);
                    cursor += 1;
                }
                b'$' => {
                    let Some(hash) = packet_checksum_offset(&self.pending, cursor + 1) else {
                        break;
                    };
                    let packet_end = hash
                        .checked_add(3)
                        .ok_or(DebugRelayError::InvalidReadOnlyPacket)?;
                    if packet_end > self.pending.len() {
                        break;
                    }
                    let encoded_payload = &self.pending[cursor + 1..hash];
                    authenticate_packet_checksum(
                        encoded_payload,
                        &self.pending[hash + 1..packet_end],
                    )?;
                    let payload = decode_packet_payload(encoded_payload)?;
                    if !read_only_gdb_command(&payload) {
                        return Err(DebugRelayError::ReadOnlyCommand);
                    }
                    forwarded.extend_from_slice(&self.pending[cursor..packet_end]);
                    cursor = packet_end;
                }
                _ => return Err(DebugRelayError::InvalidReadOnlyPacket),
            }
        }
        self.pending.drain(..cursor);
        Ok(forwarded)
    }
}

fn packet_checksum_offset(bytes: &[u8], start: usize) -> Option<usize> {
    let mut escaped = false;
    for (offset, byte) in bytes.get(start..)?.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if *byte == b'}' {
            escaped = true;
        } else if *byte == b'#' {
            return Some(start + offset);
        }
    }
    None
}

fn authenticate_packet_checksum(payload: &[u8], checksum: &[u8]) -> Result<(), DebugRelayError> {
    let [high, low] = checksum else {
        return Err(DebugRelayError::InvalidReadOnlyPacket);
    };
    let declared = hex_nibble(*high)
        .and_then(|high| hex_nibble(*low).map(|low| (high << 4) | low))
        .ok_or(DebugRelayError::InvalidReadOnlyPacket)?;
    let observed = payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    if observed != declared {
        return Err(DebugRelayError::InvalidReadOnlyPacket);
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_packet_payload(encoded: &[u8]) -> Result<Vec<u8>, DebugRelayError> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut cursor = 0;
    while cursor < encoded.len() {
        if encoded[cursor] == b'}' {
            let escaped = *encoded
                .get(cursor + 1)
                .ok_or(DebugRelayError::InvalidReadOnlyPacket)?;
            decoded.push(escaped ^ 0x20);
            cursor += 2;
        } else {
            decoded.push(encoded[cursor]);
            cursor += 1;
        }
    }
    Ok(decoded)
}

fn read_only_gdb_command(payload: &[u8]) -> bool {
    match payload.first().copied() {
        None | Some(b'?') | Some(b'g') | Some(b'p') | Some(b'm') | Some(b'x') | Some(b'H')
        | Some(b'T') => true,
        Some(b'q') => !payload.starts_with(b"qRcmd,") && !contains_bytes(payload, b":write:"),
        Some(b'Q') => payload == b"QStartNoAckMode",
        Some(b'v') => matches!(payload, b"vCont?" | b"vMustReplyEmpty" | b"vStopped"),
        _ => false,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
#[path = "debug_relay/tests.rs"]
mod tests;

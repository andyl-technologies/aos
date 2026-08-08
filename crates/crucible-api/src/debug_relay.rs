//! Lease-bound daemon relay for stable GDB byte streams.
//!
//! A relay connects only to a loopback endpoint reported by the session actor.
//! Every operation presents the authenticated client and controller generation;
//! reconnecting the HTTP/2 transport never transfers relay ownership. Each
//! relay retains one idempotent holder on the active controller lease. Other
//! commands from that principal use independent holders, while another
//! principal remains excluded until the final holder closes.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
// crucible-lint: allow host-monotonic-time -- relay expiry releases only daemon-local transport resources and never enters scenario, replay, or fingerprint state.
use std::time::{Duration, Instant as RelayInstant};

use crucible_session::{DebugClientId, DebugControllerLease};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
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
    stream: Arc<Mutex<TcpStream>>,
    last_activity: RelayInstant,
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

    pub(crate) async fn connect(endpoint: &str) -> Result<TcpStream, DebugRelayError> {
        let address: SocketAddr = endpoint
            .parse()
            .map_err(|_| DebugRelayError::InvalidGatewayEndpoint)?;
        if !address.ip().is_loopback() {
            return Err(DebugRelayError::GatewayEndpointNotLoopback);
        }
        tokio::time::timeout(DEBUG_RELAY_IO_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| DebugRelayError::ConnectTimeout)?
            .map_err(|error| DebugRelayError::Connect {
                message: error.to_string(),
            })
    }

    pub(crate) fn register(
        &mut self,
        stream: TcpStream,
        session: SessionRef,
        lease: DebugControllerLease,
        holder: DebugControllerHolderId,
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
                last_activity: relay_clock_now(),
            },
        );
        Ok(id)
    }

    pub(crate) async fn write_stream(
        stream: Arc<Mutex<TcpStream>>,
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

    pub(crate) fn stream(
        &mut self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        holder: DebugControllerHolderId,
    ) -> Result<Arc<Mutex<TcpStream>>, DebugRelayError> {
        let relay = self.checked_relay_mut(id, session, client, generation, holder)?;
        relay.last_activity = relay_clock_now();
        Ok(relay.stream.clone())
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
}

#[cfg(test)]
#[path = "debug_relay/tests.rs"]
mod tests;

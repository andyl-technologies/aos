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
use std::time::{Duration, Instant};

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
    last_activity: Instant,
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
                relay.last_activity = Instant::now();
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
                last_activity: Instant::now(),
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
        relay.last_activity = Instant::now();
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
            .last_activity = Instant::now();
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
        relay.last_activity = Instant::now();
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
        let now = Instant::now();
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
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn client(name: &str) -> DebugClientId {
        DebugClientId::new(name)
            .unwrap_or_else(|error| panic!("test client identity should be valid: {error}"))
    }

    fn session(id: u64, epoch: u64) -> SessionRef {
        SessionRef::new(
            crate::SessionId::new(id),
            epoch,
            crucible::Seed::from_u64(id),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_is_loopback_bounded_and_lease_owned() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("test gateway should bind: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test gateway should have address: {error}"));
        let gateway = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("relay should connect: {error}"));
            let mut bytes = [0_u8; 16];
            let length = stream
                .read(&mut bytes)
                .await
                .unwrap_or_else(|error| panic!("gateway should read: {error}"));
            stream
                .write_all(&bytes[..length])
                .await
                .unwrap_or_else(|error| panic!("gateway should echo: {error}"));
        });
        let owner = client("owner");
        let session_ref = session(3, 11);
        let lease = DebugControllerLease {
            client: owner.clone(),
            generation: 7,
        };
        let holder = uuid::Uuid::from_u128(7);
        let mut registry = DebugRelayRegistry::default();
        let stream = DebugRelayRegistry::connect(&address.to_string())
            .await
            .unwrap_or_else(|error| panic!("loopback relay should open: {error}"));
        let id = registry
            .register(stream, session_ref, lease, holder)
            .unwrap_or_else(|error| panic!("loopback relay should register: {error}"));
        assert_eq!(
            registry.existing(
                session_ref,
                &DebugControllerLease {
                    client: owner.clone(),
                    generation: 7,
                },
                holder,
            ),
            Some(id),
            "relay open retries must be idempotent"
        );
        assert!(registry.has_for_lease(
            session_ref,
            &DebugControllerLease {
                client: owner.clone(),
                generation: 7,
            }
        ));
        assert!(registry.has_holder(
            session_ref,
            &DebugControllerLease {
                client: owner.clone(),
                generation: 7,
            },
            holder,
        ));
        let stream = registry
            .stream(id, session_ref, &owner, 7, holder)
            .unwrap_or_else(|error| panic!("relay stream should be lease-owned: {error}"));
        assert_eq!(
            DebugRelayRegistry::write_stream(stream, b"gdb")
                .await
                .unwrap_or_else(|error| panic!("relay write should succeed: {error}")),
            3
        );
        assert_eq!(
            registry.read(id, session_ref, &client("foreign"), 7, holder, 16),
            Err(DebugRelayError::StaleOrForeignLease)
        );
        assert_eq!(
            registry.read(id, session(4, 11), &owner, 7, holder, 16),
            Err(DebugRelayError::StaleOrForeignLease),
            "the same lease generation on another session must not authorize"
        );
        let mut chunk = DebugRelayChunk {
            bytes: Vec::new(),
            eof: false,
        };
        for _ in 0..64 {
            chunk = registry
                .read(id, session_ref, &owner, 7, holder, 16)
                .unwrap_or_else(|error| panic!("relay read should succeed: {error}"));
            if !chunk.bytes.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(chunk.bytes, b"gdb");
        if let Some(relay) = registry.relays.get_mut(&id) {
            relay.last_activity = Instant::now() - DEBUG_RELAY_STALE_AFTER;
        } else {
            panic!("registered relay disappeared before stale cleanup");
        }
        assert_eq!(
            registry.remove_stale(session_ref),
            vec![(
                DebugControllerLease {
                    client: owner.clone(),
                    generation: 7,
                },
                holder,
            )]
        );
        assert!(!registry.has_for_lease(
            session_ref,
            &DebugControllerLease {
                client: owner.clone(),
                generation: 7,
            }
        ));

        let replacement_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("replacement gateway should bind: {error}"));
        let replacement_address = replacement_listener
            .local_addr()
            .unwrap_or_else(|error| panic!("replacement gateway should have address: {error}"));
        let replacement_gateway = tokio::spawn(async move {
            let (_stream, _) = replacement_listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("replacement relay should connect: {error}"));
        });
        let stream = DebugRelayRegistry::connect(&replacement_address.to_string())
            .await
            .unwrap_or_else(|error| panic!("replacement relay should open: {error}"));
        let replacement_holder = uuid::Uuid::from_u128(8);
        let id = registry
            .register(
                stream,
                session_ref,
                DebugControllerLease {
                    client: owner.clone(),
                    generation: 8,
                },
                replacement_holder,
            )
            .unwrap_or_else(|error| panic!("replacement relay should register: {error}"));
        let closed = registry
            .close(id, session_ref, &owner, 8, replacement_holder)
            .unwrap_or_else(|error| panic!("relay close should succeed: {error}"));
        assert_eq!(closed.holder, uuid::Uuid::from_u128(8));
        let retried = registry
            .close(id, session_ref, &owner, 8, replacement_holder)
            .unwrap_or_else(|error| panic!("relay close retry should succeed: {error}"));
        assert_eq!(retried.holder, closed.holder);
        assert!(!registry.has_for_lease(
            session_ref,
            &DebugControllerLease {
                client: owner.clone(),
                generation: 8,
            }
        ));
        assert_eq!(
            registry.read(id, session_ref, &owner, 8, replacement_holder, 16),
            Err(DebugRelayError::NotFound)
        );
        gateway
            .await
            .unwrap_or_else(|error| panic!("test gateway should join: {error}"));
        replacement_gateway
            .await
            .unwrap_or_else(|error| panic!("replacement gateway should join: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_rejects_non_loopback_and_oversized_requests() {
        let owner = client("owner");
        let mut registry = DebugRelayRegistry::default();
        assert!(matches!(
            DebugRelayRegistry::connect("192.0.2.1:1234").await,
            Err(DebugRelayError::GatewayEndpointNotLoopback)
        ));
        assert_eq!(
            registry.read(
                DebugRelayId(1),
                session(1, 1),
                &owner,
                1,
                uuid::Uuid::from_u128(1),
                0,
            ),
            Err(DebugRelayError::InvalidReadMaximum { maximum: 0 })
        );
    }
}

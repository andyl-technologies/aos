//! Lease-bound daemon relay for stable GDB byte streams.
//!
//! A relay connects only to a loopback endpoint reported by the session actor.
//! Every operation presents the authenticated client and controller generation;
//! reconnecting the HTTP/2 transport never transfers relay ownership.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crucible_session::{DebugClientId, DebugControllerLease};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::SessionRef;

/// Maximum GDB bytes read or written by one relay RPC.
pub const DEBUG_RELAY_CHUNK_MAX_BYTES: usize = 64 * 1024;

const DEBUG_RELAY_MAX_CONNECTIONS: usize = 64;
const DEBUG_RELAY_IO_TIMEOUT: Duration = Duration::from_secs(5);

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
}

struct DebugRelay {
    session: SessionRef,
    lease: DebugControllerLease,
    stream: Arc<Mutex<TcpStream>>,
}

impl DebugRelayRegistry {
    pub(crate) fn existing(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
    ) -> Option<DebugRelayId> {
        self.relays.iter().find_map(|(id, relay)| {
            (relay.session == session && relay.lease == *lease).then_some(*id)
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
    ) -> Result<DebugRelayId, DebugRelayError> {
        if let Some(id) = self.existing(session, &lease) {
            return Ok(id);
        }
        if self.relays.len() >= DEBUG_RELAY_MAX_CONNECTIONS {
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
                stream: Arc::new(Mutex::new(stream)),
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
        &self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
    ) -> Result<Arc<Mutex<TcpStream>>, DebugRelayError> {
        Ok(self
            .checked_relay(id, session, client, generation)?
            .stream
            .clone())
    }

    pub(crate) fn read(
        &self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
        maximum: usize,
    ) -> Result<DebugRelayChunk, DebugRelayError> {
        if maximum == 0 || maximum > DEBUG_RELAY_CHUNK_MAX_BYTES {
            return Err(DebugRelayError::InvalidReadMaximum { maximum });
        }
        let relay = self.checked_relay(id, session, client, generation)?;
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
    ) -> Result<(), DebugRelayError> {
        let _ = self.checked_relay(id, session, client, generation)?;
        self.relays.remove(&id);
        Ok(())
    }

    pub(crate) fn close_for_lease(&mut self, session: SessionRef, lease: &DebugControllerLease) {
        self.relays
            .retain(|_, relay| relay.session != session || relay.lease != *lease);
    }

    pub(crate) fn close_for_session(&mut self, session: SessionRef) {
        self.relays.retain(|_, relay| relay.session != session);
    }

    fn checked_relay(
        &self,
        id: DebugRelayId,
        session: SessionRef,
        client: &DebugClientId,
        generation: u64,
    ) -> Result<&DebugRelay, DebugRelayError> {
        let relay = self.relays.get(&id).ok_or(DebugRelayError::NotFound)?;
        if relay.session != session
            || relay.lease.client != *client
            || relay.lease.generation != generation
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
    /// The daemon already owns the configured maximum number of relays.
    #[error("debug relay connection capacity is exhausted")]
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
        let mut registry = DebugRelayRegistry::default();
        let stream = DebugRelayRegistry::connect(&address.to_string())
            .await
            .unwrap_or_else(|error| panic!("loopback relay should open: {error}"));
        let id = registry
            .register(stream, session_ref, lease)
            .unwrap_or_else(|error| panic!("loopback relay should register: {error}"));
        assert_eq!(
            registry.existing(
                session_ref,
                &DebugControllerLease {
                    client: owner.clone(),
                    generation: 7,
                },
            ),
            Some(id),
            "relay open retries must be idempotent"
        );
        let stream = registry
            .stream(id, session_ref, &owner, 7)
            .unwrap_or_else(|error| panic!("relay stream should be lease-owned: {error}"));
        assert_eq!(
            DebugRelayRegistry::write_stream(stream, b"gdb")
                .await
                .unwrap_or_else(|error| panic!("relay write should succeed: {error}")),
            3
        );
        assert_eq!(
            registry.read(id, session_ref, &client("foreign"), 7, 16),
            Err(DebugRelayError::StaleOrForeignLease)
        );
        assert_eq!(
            registry.read(id, session(4, 11), &owner, 7, 16),
            Err(DebugRelayError::StaleOrForeignLease),
            "the same lease generation on another session must not authorize"
        );
        let mut chunk = DebugRelayChunk {
            bytes: Vec::new(),
            eof: false,
        };
        for _ in 0..64 {
            chunk = registry
                .read(id, session_ref, &owner, 7, 16)
                .unwrap_or_else(|error| panic!("relay read should succeed: {error}"));
            if !chunk.bytes.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(chunk.bytes, b"gdb");
        registry.close_for_lease(
            session_ref,
            &DebugControllerLease {
                client: owner.clone(),
                generation: 7,
            },
        );
        assert_eq!(
            registry.read(id, session_ref, &owner, 7, 16),
            Err(DebugRelayError::NotFound)
        );
        gateway
            .await
            .unwrap_or_else(|error| panic!("test gateway should join: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_rejects_non_loopback_and_oversized_requests() {
        let owner = client("owner");
        let registry = DebugRelayRegistry::default();
        assert!(matches!(
            DebugRelayRegistry::connect("192.0.2.1:1234").await,
            Err(DebugRelayError::GatewayEndpointNotLoopback)
        ));
        assert_eq!(
            registry.read(DebugRelayId(1), session(1, 1), &owner, 1, 0),
            Err(DebugRelayError::InvalidReadMaximum { maximum: 0 })
        );
    }
}

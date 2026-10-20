//! Authenticates a concrete publisher and independently checks readonly receipts.
//!
//! A client retains one cache incarnation across reconnects. Lost replies never
//! trigger automatic retries: a new authenticated connection must explicitly
//! drain before another readonly operation. Drain acknowledges ordered publisher
//! custody; it does not prove cache reconciliation. Resume additionally requires
//! genuine completed recovery and the concrete physical owner's exclusive turn.

#[cfg(feature = "tokio")]
mod cache_lifecycle;
#[cfg(feature = "tokio")]
mod cleanup;
#[cfg(feature = "tokio")]
mod context;
#[cfg(feature = "tokio")]
mod manifest;
#[cfg(feature = "tokio")]
mod publication;
mod receipt;
#[cfg(feature = "tokio")]
mod recovery;
#[cfg(feature = "tokio")]
pub(crate) mod recovery_manifest;
#[cfg(feature = "tokio")]
mod running;
#[cfg(feature = "tokio")]
mod transfer;

#[cfg(feature = "tokio")]
pub(crate) use cache_lifecycle::{CacheBodyCompletion, PendingCacheBody};
#[cfg(feature = "tokio")]
pub(crate) use cleanup::AcknowledgedSourceRetirement;
#[cfg(feature = "tokio")]
pub(crate) use recovery::{BodyIncarnationObservation, RecoveryBody};

#[cfg(feature = "tokio")]
pub(crate) use context::PublisherRecoveryContext;
#[cfg(feature = "tokio")]
pub use manifest::PeerManifestPublishedObject;
#[cfg(feature = "tokio")]
pub(crate) use running::{PublisherRunningContext, ResumeFailureStage};

pub use receipt::{PeerPublishedObject, PeerSealProbe};

use std::{
    fs::File,
    io::Read,
    os::fd::BorrowedFd,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use terrane_format::identity::TERRANE_V1;
use terrane_sdk::host::{
    cache::{DomainHostLayout, HostReadLocation},
    publication::{PublicationClaim, PublicationRecipe},
};

use super::{
    Error,
    socket::{Connection, ReceivedPacket, RoleIdentities},
    validation::ValidationPolicy,
    wire::{BodyKey, BodyKind, Claim, Operation, Packet, ResultCode},
};
use crate::host_cache::NativeHostLayout;

/// Trusted configuration for one domain's authenticated readonly publisher client.
pub struct ClientConfig {
    /// The protected absolute publisher socket path.
    pub socket_path: PathBuf,
    /// The distinct configured cache and publisher kernel identities.
    pub identities: RoleIdentities,
    /// The configured registered chunk profile label.
    pub chunk_profile_name: String,
    /// The registered request budget, from 1 through 300000 milliseconds.
    pub wait_budget_ms: u64,
}

/// A serialized concrete client retaining actual domain-root custody.
///
/// Both repository-bound layouts and host-only locations use the sealed
/// location interface; host-only clients require no repository routing facts.
///
/// This client exposes readonly probe and inline adoption. Private manifest
/// adoption and Resume additionally require genuine durable cache-owner
/// receipts. Writable admission and running operations require their separate
/// concrete owner integration and are unavailable through this public API.
pub struct Client<L: HostReadLocation = DomainHostLayout> {
    config: ClientConfig,
    layout: Arc<NativeHostLayout<L>>,
    cache_incarnation: [u8; 16],
    state: Mutex<State>,
}

struct State {
    connection: Option<Connection>,
    next_request_id: u64,
    phase: Phase,
    recovery_epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Undrained,
    Recovery,
    #[cfg(feature = "tokio")]
    Running,
    Uncertain,
}

impl<L: HostReadLocation> Client<L> {
    /// Connects to the authenticated publisher while retaining the inspected root.
    ///
    /// No command is retried automatically. The caller must explicitly drain
    /// before probing or adopting, including after any uncertain exchange.
    ///
    /// # Errors
    ///
    /// Rejects invalid resource policy, stale layout custody, unavailable kernel
    /// randomness, unsafe socket ancestors, wrong role identities and connect
    /// failures. Each kernel socket wait has a finite configured timeout.
    pub fn connect(config: ClientConfig, layout: Arc<NativeHostLayout<L>>) -> Result<Self, Error> {
        if !(1..=300_000).contains(&config.wait_budget_ms) || config.chunk_profile_name.is_empty() {
            return Err(Error::Invalid("client configuration"));
        }
        layout.recheck()?;
        let mut cache_incarnation = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut cache_incarnation)?;
        let connection = connect(&config)?;

        Ok(Self {
            config,
            layout,
            cache_incarnation,
            state: Mutex::new(State {
                connection: Some(connection),
                next_request_id: 1,
                phase: Phase::Undrained,
                recovery_epoch: 0,
            }),
        })
    }

    /// Establishes the actual publisher's ordered recovery barrier.
    ///
    /// Reconnection preserves this client's private cache incarnation. A lost
    /// reply leaves recovery required; this method never retries the command.
    /// The acknowledgement does not prove reconciliation or permit resume.
    ///
    /// # Errors
    ///
    /// Returns errors for stale layout custody, poisoned client state, failed
    /// authentication, transport uncertainty or a registered publisher failure.
    pub fn drain(&self) -> Result<(), Error> {
        let mut state = self.lock()?;
        state.phase = Phase::Undrained;
        state.recovery_epoch = state
            .recovery_epoch
            .checked_add(1)
            .ok_or(Error::Invalid("publisher recovery epoch exhausted"))?;
        if state.connection.is_none() {
            state.connection = Some(connect(&self.config)?);
        }
        self.exchange(&mut state, Operation::Drain, None, None)?;
        state.phase = Phase::Recovery;
        Ok(())
    }

    /// Checks a publisher-issued empty sealed probe against the local kernel.
    ///
    /// The returned probe retains root custody and proves measured kernel seal
    /// support on that root's device; it is not canonical content authority.
    ///
    /// # Errors
    ///
    /// Rejects missing drain custody, transport or publisher failures, stale
    /// root identity, wrong inode ownership/device and mismatched kernel seals.
    pub fn probe(&self) -> Result<PeerSealProbe<L>, Error> {
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        let received = self.exchange(&mut state, Operation::Probe, None, None)?;
        let result = receipt::probe(
            received,
            self.layout.clone(),
            self.config.identities.publish_uid,
        );
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }

    /// Adopts inline canonical content after independent kernel and byte checks.
    ///
    /// The claim is revalidated against this retained layout's domain and actual
    /// chunk profile. The receipt keeps the root guard alive with the file.
    ///
    /// # Errors
    ///
    /// Rejects manifest claims, another domain, profile-ineligible inline data,
    /// missing drain custody, uncertain exchanges, publisher failures and any
    /// file ownership, device, seal, size or plaintext identity mismatch.
    pub fn adopt_inline(&self, claim: PublicationClaim) -> Result<PeerPublishedObject<L>, Error> {
        let claim = self.inline_claim(claim)?;
        let descriptor = claim.descriptor().encode();
        let wire_claim = Claim {
            descriptor: descriptor.clone(),
            chunk_profile: self.config.chunk_profile_name.clone(),
            plaintext_size: claim.plaintext_size(),
            ..Default::default()
        };
        let body = BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor,
            ..Default::default()
        };
        let mut state = self.lock()?;
        self.require_drained(&state)?;
        let received = self.exchange(&mut state, Operation::Adopt, Some(wire_claim), Some(body))?;
        let result = receipt::published(
            received,
            self.layout.clone(),
            self.config.identities.publish_uid,
            claim,
        );
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }

    /// Borrows this actual client's stable private-generated owner incarnation.
    #[cfg(feature = "tokio")]
    pub(crate) fn cache_incarnation(&self) -> &[u8; 16] {
        &self.cache_incarnation
    }

    fn inline_claim(&self, claim: PublicationClaim) -> Result<PublicationClaim, Error> {
        self.layout.recheck()?;
        if claim.domain() != self.layout.layout().domain() || claim.manifest().is_some() {
            return Err(Error::Invalid("inline claim domain or manifest"));
        }
        Ok(PublicationClaim::new(
            claim.domain().to_owned(),
            PublicationRecipe::Inline {
                chunk: claim.descriptor().clone(),
            },
            self.layout.layout().chunk_profile(),
        )?)
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.state
            .lock()
            .map_err(|_| Error::Invalid("poisoned publisher client"))
    }

    fn require_drained(&self, state: &State) -> Result<(), Error> {
        if state.phase != Phase::Recovery {
            return Err(Error::Invalid("publisher recovery drain required"));
        }
        Ok(())
    }

    fn exchange(
        &self,
        state: &mut State,
        operation: Operation,
        claim: Option<Claim>,
        body: Option<BodyKey>,
    ) -> Result<ReceivedPacket, Error> {
        self.exchange_payload(
            state,
            operation,
            RequestPayload {
                claim,
                body,
                ..Default::default()
            },
        )
    }

    fn exchange_payload(
        &self,
        state: &mut State,
        operation: Operation,
        payload: RequestPayload,
    ) -> Result<ReceivedPacket, Error> {
        self.exchange_payload_files(state, operation, payload, &[])
    }

    fn exchange_payload_files(
        &self,
        state: &mut State,
        operation: Operation,
        payload: RequestPayload,
        files: &[BorrowedFd<'_>],
    ) -> Result<ReceivedPacket, Error> {
        self.layout.recheck()?;
        let request_id = state.next_request_id;
        state.next_request_id = request_id
            .checked_add(1)
            .ok_or(Error::Invalid("publisher request identity exhausted"))?;
        let packet = Packet {
            version: 1,
            request_id,
            operation: operation as i32,
            domain: self.layout.layout().domain().to_owned(),
            cache_incarnation: self.cache_incarnation.to_vec(),
            wait_budget_ms: self.config.wait_budget_ms,
            claim: payload.claim,
            body: payload.body,
            inventory_cursor: payload.cursor,
            body_incarnation: payload.incarnation,
            ..Default::default()
        };
        let policy = ValidationPolicy {
            domain: &packet.domain,
            identity: &TERRANE_V1,
            chunk_profile: &self.config.chunk_profile_name,
        };
        let result = (|| {
            let connection = state
                .connection
                .as_ref()
                .ok_or(Error::Invalid("publisher disconnected"))?;
            connection.send(&packet, files, &policy)?;
            connection.receive(&policy)
        })();
        let received = match result {
            Ok(received) => received,
            Err(error) => {
                invalidate(state);
                return Err(error);
            }
        };
        let result = ResultCode::try_from(received.packet.result)
            .map_err(|_| Error::Invalid("publisher result"))?;
        if result != ResultCode::Ok {
            // Unavailable may mean an accepted physical operation is still
            // running. Never interpret a failed exchange as rollback custody.
            if result == ResultCode::Unavailable {
                invalidate(state);
            }
            return Err(Error::Remote(result));
        }
        Ok(received)
    }
}

#[derive(Default)]
struct RequestPayload {
    claim: Option<Claim>,
    body: Option<BodyKey>,
    cursor: Vec<u8>,
    incarnation: Vec<u8>,
}

fn connect(config: &ClientConfig) -> Result<Connection, Error> {
    // The grace permits the server to return its bounded Unavailable reply;
    // neither timeout cancels an operation already accepted by its owner.
    let timeout = Duration::from_millis(config.wait_budget_ms + 1_000);
    Connection::connect_timed(&config.socket_path, config.identities, timeout)
}

fn invalidate(state: &mut State) {
    state.connection = None;
    state.phase = Phase::Uncertain;
}

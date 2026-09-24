//! Fixed RootMount connection to the separate SourceProvider service.
//!
//! This connector retains the configured sequenced-packet carrier inside the
//! protected RootMount session owner. Establishing a session grants no source
//! operation or backend authority; the Mount source graph remains a separate
//! admission boundary.

use std::path::Path;
use std::time::Duration;

use aos_sandbox::MountSourceConsumptionJournalAuthorityV1;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_mount::MountError;
use aos_sandbox_mount::broker::MountBroker;
use aos_sandbox_mount::worker::MountWorker;
use aos_sandbox_source_provider_security::{
    AuthenticatedRootMountRecoveryUnavailableV1, RootMountSourceProviderHandshakeStatusV1,
    RootMountSourceProviderOwnerV1, SourceProviderSecurityError,
};

use crate::ProductionBrokerSessionActivationErrorV1;
use crate::production_activation::remaining_duration;

const FIXED_PROVIDER_SOCKET: &str = "/run/aos/source-provider/control.sock";

/// Reports failure before RootMount can retain an authenticated provider session.
#[derive(Debug, thiserror::Error)]
pub enum ProductionRootMountSourceProviderErrorV1 {
    /// The exact configured provider socket was unavailable or invalid.
    #[error("RootMount SourceProvider socket failed: {0}")]
    Socket(#[from] SeqpacketError),
    /// Fixed RootMount custody, peer, or handshake authentication failed.
    #[error("RootMount SourceProvider authentication failed: {0}")]
    Security(#[from] SourceProviderSecurityError),
    /// The configured handshake deadline elapsed or the kernel clock was invalid.
    #[error("RootMount SourceProvider handshake deadline failed: {0}")]
    Deadline(#[from] ProductionBrokerSessionActivationErrorV1),
    /// The sole protected Mount journal could not be lent or verified.
    #[error("RootMount SourceProvider recovery failed: {0}")]
    Mount(#[from] MountError),
}

/// Connects RootMount to the fixed SourceProvider socket and authenticates it.
///
/// The returned owner alone retains the carrier and current session. The
/// service's protected execution identity and signed hello are checked by the
/// owner; a successful filesystem connection is never treated as authority.
///
/// # Errors
///
/// Returns an error for an invalid fixed socket, missing protected custody,
/// peer or signed transcript mismatch, or an expired boot-time deadline.
pub fn connect_authenticated_fixed_source_provider(
    deadline_boottime_nanoseconds: u64,
) -> Result<RootMountSourceProviderOwnerV1, ProductionRootMountSourceProviderErrorV1> {
    let socket = DescriptorSubjectSocket::connect(Path::new(FIXED_PROVIDER_SOCKET))?;
    let mut owner = RootMountSourceProviderOwnerV1::open_fixed(socket)?;

    loop {
        let remaining = remaining_duration(deadline_boottime_nanoseconds)?;
        match owner.advance_handshake()? {
            RootMountSourceProviderHandshakeStatusV1::Current => {
                remaining_duration(deadline_boottime_nanoseconds)?;
                return Ok(owner);
            }
            RootMountSourceProviderHandshakeStatusV1::Pending => {
                std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000)));
            }
        }
    }
}

/// Advances the original pending Acquire query under Mount's sole journal claim.
///
/// The returned observation is only signed Unavailable. This function does
/// not update the pending row, create a successor, or grant a source descriptor.
/// `Ok(None)` means the handshake or nonblocking exchange is still pending.
///
/// # Errors
///
/// Rejects a stale journal, changed original attempt, retired peer, or
/// malformed/downgraded Provider answer.
pub fn advance_authenticated_pending_acquire_recovery(
    owner: &mut RootMountSourceProviderOwnerV1,
    journal: &MountSourceConsumptionJournalAuthorityV1<'_>,
    acquisition_id: ObjectDigest,
) -> Result<Option<AuthenticatedRootMountRecoveryUnavailableV1>, SourceProviderSecurityError> {
    match owner.with_current_session(|session| {
        session.advance_pending_acquire_recovery_v1(journal, acquisition_id)
    })? {
        Some(progress) => progress,
        None => Ok(None),
    }
}

/// Observes every original pending Acquire after a Mount broker restart.
///
/// The broker lends its sole protected journal for the entire scan and each
/// AOSSPR01 exchange. No response changes the graph: even authenticated
/// Unavailable leaves the original attempt pending for later explicit recovery.
/// The authenticated session remains owned by `owner` after this function.
///
/// # Errors
///
/// Fails closed for a changed protected graph, retired peer, invalid signed
/// answer, or expired boot-time deadline. The caller should restart rather
/// than create a successor attempt or serve a source through this state.
pub fn observe_original_pending_acquires<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<usize, ProductionRootMountSourceProviderErrorV1> {
    let observed = broker.with_fixed_source_acquisition_owner(|source| {
        source.with_consumption_authority(|table, journal| {
            let pending = table.original_pending_acquire_ids();
            for acquisition_id in &pending {
                loop {
                    let remaining = remaining_duration(deadline_boottime_nanoseconds)
                        .map_err(|error| MountError::State(error.to_string()))?;
                    match advance_authenticated_pending_acquire_recovery(
                        owner,
                        journal,
                        ObjectDigest::from_bytes(*acquisition_id),
                    )
                    .map_err(|error| MountError::State(error.to_string()))?
                    {
                        Some(_) => break,
                        None => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
                    }
                }
            }
            Ok(pending.len())
        })
    })?;
    Ok(observed)
}

/// Obtains one fresh Mount source inventory through the separate provider daemon.
///
/// The fixed Mount journal reserves the signed request before it reaches the
/// authenticated carrier. Only a descriptor-free, exact signed Inventory
/// reply can advance the source graph. An unanswered send leaves a Reserved
/// attempt for explicit cold recovery; it never authorizes retransmission as
/// a new request or a terminal inventory response.
///
/// # Errors
///
/// Rejects an unresolved source graph, stale session or journal, invalid
/// descriptor or signature, and any unanswered or ambiguous request at the
/// absolute boot-time deadline.
pub fn observe_remote_source_inventory<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, ProductionRootMountSourceProviderErrorV1> {
    let response = broker.with_fixed_source_acquisition_owner(|source| {
        if let Err(error) = source.prepare_and_send_remote_inventory(owner) {
            if !source.has_pending_provider_send() {
                return Err(error);
            }
        }
        while source.has_pending_provider_send() {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)
                .map_err(|error| MountError::State(error.to_string()))?;
            match source.retry_pending_provider_send(owner) {
                Ok(()) => break,
                Err(_) => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
            }
        }
        loop {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)
                .map_err(|error| MountError::State(error.to_string()))?;
            match source.advance_remote_inventory(owner)? {
                true => {
                    let inventory = source.encode_current_inventory()?;
                    remaining_duration(deadline_boottime_nanoseconds)
                        .map_err(|error| MountError::State(error.to_string()))?;
                    return Ok(inventory);
                }
                false => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
            }
        }
    })?;
    Ok(response)
}

/// Recovers one old Reserved Inventory from Provider's protected journal.
///
/// This is a non-effect recovery operation. It never resends the old signed
/// request, authorizes Acquire or Release, or activates source-method dispatch.
///
/// # Errors
///
/// Rejects signed Unavailable, changed protected history, ambiguous commit,
/// or a response not completed before the absolute boot-time deadline.
pub fn observe_remote_cold_source_inventory<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, ProductionRootMountSourceProviderErrorV1> {
    let response = broker.with_fixed_source_acquisition_owner(|source| {
        loop {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)
                .map_err(|error| MountError::State(error.to_string()))?;
            match source.advance_remote_cold_inventory_readback(owner)? {
                true => {
                    let inventory = source.encode_current_inventory()?;
                    remaining_duration(deadline_boottime_nanoseconds)
                        .map_err(|error| MountError::State(error.to_string()))?;
                    return Ok(inventory);
                }
                false => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
            }
        }
    })?;
    Ok(response)
}

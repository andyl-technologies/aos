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

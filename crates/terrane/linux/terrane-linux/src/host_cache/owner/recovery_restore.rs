//! Restores pending names needed by recovery of a populated native cache.
//!
//! Restore preserves the original inode and changes only publisher namespaces.
//! It supplies no verified content, reconstructed policy or serving authority.
//! The owner must inspect the resulting canonical namespace again before any
//! adoption, source closure or completed recovery can be accepted.

use super::{
    recovery, recovery_candidates, recovery_namespace::SharedNamespaceObservation,
    retention::NativeOwnerExecutor,
};
use crate::{
    host_cache::{NativeRecoveryCandidate, NativeRecoveryInspection, RecoveryIssue},
    publisher_local::{
        client::{BodyIncarnationObservation, Client, PublisherRecoveryContext},
        wire::BodyKind,
    },
};
use std::{io, sync::Arc};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::cache::HostDomainLocation;

/// Borrows original funded recovery custody for one namespace-only restoration.
pub(crate) struct PublisherRecoveryRestoreTurn<'turn> {
    executor: &'turn mut NativeOwnerExecutor,
    bootstrap_id: &'turn [u8; 16],
    context: &'turn PublisherRecoveryContext<HostDomainLocation>,
    observation: &'turn BodyIncarnationObservation<HostDomainLocation>,
}

impl PublisherRecoveryRestoreTurn<'_> {
    /// Rechecks the sole physical worker and its synchronized original funding.
    ///
    /// # Errors
    /// Refuses stale custody, another session or Drain, lost bootstrap funding,
    /// changed native configuration and actual project quota excess.
    pub(crate) fn observation(
        &self,
        session: &Arc<Client<HostDomainLocation>>,
        context: &PublisherRecoveryContext<HostDomainLocation>,
    ) -> io::Result<&BodyIncarnationObservation<HostDomainLocation>> {
        self.executor.check_physical_worker()?;
        if !std::ptr::eq(self.context, context) {
            return Err(unresolved(
                "pending restoration changed original Drain context",
            ));
        }
        let owner = self
            .executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_synchronized_bootstrap(self.bootstrap_id)?;
        if !owner.faulted
            || !owner.recovery_required
            || !Arc::ptr_eq(session, &owner.preparation.publisher_session())
        {
            return Err(unresolved(
                "pending restoration requires original recovery custody",
            ));
        }
        recovery::check_charge(&owner, 0)?;
        Ok(self.observation)
    }
}

/// Restores supported original pending bodies alongside existing cache content.
///
/// An otherwise empty, unpinned cache retains the separate expired-retirement
/// path for inline and encoded bodies. A sealed manifest instead requires
/// restoration of its pending body or reconstruction metadata, including when
/// the manifest itself is canonical and its complete metadata pair is pending.
/// Populated recovery also restores before reconstructing policy: deleting an
/// expired body first could destroy backing required by a surviving cold pin.
///
/// # Errors
/// Refuses incomplete inventories, unsupported or ambiguous pending candidates,
/// unsupported canonical candidates, changed custody and uncertain exchanges.
/// Successful restoration still requires a fresh exhaustive scan and adoption.
pub(super) fn run(
    executor: &mut NativeOwnerExecutor,
    inventory: &NativeRecoveryInspection,
    shared: &SharedNamespaceObservation,
    bootstrap_id: &[u8; 16],
    context: &PublisherRecoveryContext<HostDomainLocation>,
) -> io::Result<bool> {
    let manifest_present = has_manifest(inventory)?;
    let session = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        if shared.only_nonresident_entries()
            && !manifest_present
            && owner.state.pins.is_empty()
            && owner.state.leases.is_empty()
            && owner.state.residences.is_empty()
        {
            return Ok(false);
        }
        owner.preparation.publisher_session()
    };
    if !inventory
        .candidates()
        .iter()
        .any(|candidate| candidate.pending_observation().is_some())
    {
        return Ok(false);
    }
    if inventory.inventory_failure().is_some() || inventory.namespace_failure().is_some() {
        return Err(unresolved(
            "pending restoration requires exhaustive inventory",
        ));
    }
    for candidate in inventory.candidates() {
        if candidate.pending_observation().is_some() {
            check_candidate(candidate)?;
        } else {
            recovery_candidates::classify(candidate)?;
        }
    }
    inventory.check_current()?;
    shared.check_current()?;
    for candidate in inventory.candidates() {
        let Some(observation) = candidate.pending_observation() else {
            continue;
        };
        inventory.check_current()?;
        let mut turn = PublisherRecoveryRestoreTurn {
            executor,
            bootstrap_id,
            context,
            observation,
        };
        session
            .restore_recovery_body(context, &mut turn)
            .map_err(io::Error::other)?;
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
    }
    Ok(true)
}

/// Selects restoration without treating a descriptor as verified backing.
///
/// Full candidate validation still precedes every namespace effect. In
/// particular, canonical sealed names are outside the shared content namespace.
/// A canonical manifest with a pending metadata pair therefore cannot select
/// empty-cache retirement merely because no shared canonical names remain.
fn has_manifest(inventory: &NativeRecoveryInspection) -> io::Result<bool> {
    for candidate in inventory.candidates() {
        let key = candidate.key();
        if key.kind != BodyKind::Sealed as i32 {
            continue;
        }
        let descriptor =
            Descriptor::decode(&TERRANE_V1, &key.descriptor).map_err(io::Error::other)?;
        if TERRANE_V1
            .kind(descriptor.domain())
            .map_err(io::Error::other)?
            == IdentityKind::Manifest
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_candidate(candidate: &NativeRecoveryCandidate) -> io::Result<()> {
    let key = candidate.key();
    match BodyKind::try_from(key.kind) {
        Ok(BodyKind::Pack)
            if key.codec == 0
                && key.descriptor.is_empty()
                && key.pack_id.len() == 16
                && candidate.verified().is_none()
                && matches!(candidate.issues(), [RecoveryIssue::PendingOnly]) =>
        {
            return Ok(());
        }
        Ok(BodyKind::Sealed)
            if key.codec == 0
                && matches!(candidate.issues(), [RecoveryIssue::SealedWitnessRequired]) => {}
        Ok(BodyKind::Chunk)
            if key.codec <= 2 && candidate.pending_chunk_observation().is_some() => {}
        _ => return Err(unresolved("unsupported pending restoration candidate")),
    }
    if !key.pack_id.is_empty() {
        return Err(unresolved(
            "pending restoration has an unexpected pack identity",
        ));
    }
    let descriptor = Descriptor::decode(&TERRANE_V1, &key.descriptor).map_err(io::Error::other)?;
    match TERRANE_V1
        .kind(descriptor.domain())
        .map_err(io::Error::other)?
    {
        IdentityKind::Chunk => Ok(()),
        IdentityKind::Manifest if key.kind == BodyKind::Sealed as i32 => Ok(()),
        _ => Err(unresolved("unsupported pending restoration descriptor")),
    }
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

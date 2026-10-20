//! Finishes expired inline pending inodes under funded physical recovery custody.
//!
//! This phase handles only an otherwise empty shared namespace and no cold
//! pins, leases or residences. Old allocation holds survive unchanged.
//! Actual publisher inventory verifies the sealed chunk claim;
//! InspectPending retains its original inode and reconstructs any lost deadline.
//! The publisher alone checks that durable deadline before final removal. Any
//! refusal keeps the bootstrap and faulted owner; uncertain exchanges invalidate
//! the original Drain and require a new physical recovery. No deadline,
//! freed allocation, adoption or completed recovery is inferred here.

use super::{
    recovery, recovery_namespace::SharedNamespaceObservation, retention::NativeOwnerExecutor,
};
use crate::{
    host_cache::{NativeRecoveryInspection, RecoveryIssue},
    publisher_local::{
        client::{BodyIncarnationObservation, Client, PublisherRecoveryContext},
        wire::BodyKind,
    },
};
use std::{io, sync::Arc};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::cache::HostDomainLocation;

/// Borrows the sole physical worker, synchronized funding and original observation.
pub(crate) struct PublisherRecoveryRetirementTurn<'turn> {
    executor: &'turn mut NativeOwnerExecutor,
    bootstrap_id: &'turn [u8; 16],
    context: &'turn PublisherRecoveryContext<HostDomainLocation>,
    observation: &'turn BodyIncarnationObservation<HostDomainLocation>,
}

impl PublisherRecoveryRetirementTurn<'_> {
    /// Rechecks genuine exclusion and funding before the client acquires its lock.
    ///
    /// # Errors
    /// Refuses another physical worker, session or original context, unsynchronized
    /// funding, cold pins/leases/residences, stale native custody or quota excess.
    pub(crate) fn observation(
        &self,
        session: &Arc<Client<HostDomainLocation>>,
        context: &PublisherRecoveryContext<HostDomainLocation>,
    ) -> io::Result<&BodyIncarnationObservation<HostDomainLocation>> {
        self.executor.check_physical_worker()?;
        if !std::ptr::eq(self.context, context) {
            return Err(unresolved("pending cleanup changed original Drain context"));
        }
        let owner = self
            .executor
            .custody()
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_synchronized_bootstrap(self.bootstrap_id)?;
        if !owner.faulted
            || !owner.recovery_required
            || !owner.state.pins.is_empty()
            || !owner.state.leases.is_empty()
            || !owner.state.residences.is_empty()
            || !Arc::ptr_eq(session, &owner.preparation.publisher_session())
        {
            return Err(unresolved(
                "pending cleanup requires unpinned recovery custody",
            ));
        }
        recovery::check_charge(&owner, 0)?;
        Ok(self.observation)
    }
}

/// Reconciles supported pending candidates without changing any other recovery case.
///
/// # Errors
/// Refuses incomplete scans, mixed encoded/manifest custody, nonempty shared
/// namespaces, cold pins/leases/residences, active or unknown intervals and uncertain
/// native effects. A successful removal still requires fresh exhaustive recovery.
pub(super) fn run(
    executor: &mut NativeOwnerExecutor,
    inventory: &NativeRecoveryInspection,
    shared: &SharedNamespaceObservation,
    bootstrap_id: &[u8; 16],
    context: &PublisherRecoveryContext<HostDomainLocation>,
) -> io::Result<bool> {
    if !inventory
        .candidates()
        .iter()
        .any(|candidate| candidate.pending_observation().is_some())
    {
        return Ok(false);
    }
    if inventory.inventory_failure().is_some()
        || inventory.namespace_failure().is_some()
        || !shared.only_empty_scaffolds()
    {
        return Err(unresolved(
            "pending cleanup requires exhaustive inline custody",
        ));
    }
    // Validate the complete candidate set before the first namespace mutation.
    // Metadata and encoded sources need their separate retirement-unit protocol.
    for candidate in inventory.candidates() {
        let key = candidate.key();
        if key.kind != BodyKind::Sealed as i32
            || key.codec != 0
            || !key.pack_id.is_empty()
            || !matches!(candidate.issues(), [RecoveryIssue::SealedWitnessRequired])
        {
            return Err(unresolved("unsupported pending recovery candidate"));
        }
        let descriptor =
            Descriptor::decode(&TERRANE_V1, &key.descriptor).map_err(io::Error::other)?;
        if TERRANE_V1
            .kind(descriptor.domain())
            .map_err(io::Error::other)?
            != IdentityKind::Chunk
        {
            return Err(unresolved("pending manifest recovery remains unresolved"));
        }
    }
    let session = executor
        .custody()
        .lock()
        .map_err(|_| io::Error::other("recovery custody poisoned"))?
        .preparation
        .publisher_session();
    for candidate in inventory.candidates() {
        let Some(observation) = candidate.pending_observation() else {
            continue;
        };
        inventory.check_current()?;
        shared.check_current()?;
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
        let mut turn = PublisherRecoveryRetirementTurn {
            executor,
            bootstrap_id,
            context,
            observation,
        };
        session
            .finish_recovery_retirement(context, &mut turn)
            .map_err(io::Error::other)?;
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
    }
    Ok(true)
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

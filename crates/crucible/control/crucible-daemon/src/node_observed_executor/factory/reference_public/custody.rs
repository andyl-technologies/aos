//! Reserves actor-owned public-peer custody before any native process exists.
//!
//! The installation actor must poll this queue until every original peer has
//! authentic reclamation proof. Native handles, journals, original world scope
//! and publication uncertainty survive borrower drops and callback unwinding.
//! A positive process-group census permits transfer of the retained capsule;
//! it does not discharge semantic or durable-ledger obligations.

use std::{cell::RefCell, rc::Rc};

use crucible_engine::{
    node_adapters::cnp::{CnpPeerCustody, CnpProcessCustodySlot},
    node_contract::{ActivationRecord, OwnerIdentity, PreparedWorldPublication, PublicationStatus},
};
use crucible_node_format::{ContentRef, U64};
use crucible_node_transport::{ProviderError, connection::ConnectionIncident};

#[path = "custody_archive.rs"]
mod archive;

use archive::{OriginalArchiveAttempt, RetainedResolvedPeer};

/// Retains the actual host reservation and all original source commitments.
pub(super) struct PublicPeerScope {
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) implementation: ContentRef,
    pub(super) source_roots: Vec<ContentRef>,
    pub(super) source_custody: Option<Rc<super::package::OriginalPackageSourceCustody>>,
    pub(super) publication: Option<PublicationStatus>,
    pub(super) connection_incident: Rc<RefCell<Option<ConnectionIncident>>>,
    // These private originals may contain admission secrets and never become
    // public CAS roots or inert observation evidence.
    pub(super) private_launch: Vec<u8>,
    pub(super) original_hello: Vec<u8>,
    // Ordinary preparation retains actual negotiated originals in this SAME entry.
    pub(super) ordinary_negotiation:
        Option<Rc<RefCell<super::vendor_bridge::OriginalReferenceNegotiation>>>,
    pub(super) collecting_negotiation:
        Option<Rc<RefCell<super::vendor_bridge::OriginalReferenceTransport>>>,
}

struct Entry {
    identity: U64,
    scope: PublicPeerScope,
    custody: Option<CnpPeerCustody>,
    in_flight: bool,
    reclaimed: bool,
    archive: Option<OriginalArchiveAttempt>,
}

struct Registry {
    entries: Vec<Option<Rc<RefCell<Entry>>>>,
    next_identity: u64,
    resolved: Vec<RetainedResolvedPeer>,
    keep_alive: Option<Rc<RefCell<Self>>>,
}

/// Keeps finite native reservations on the actual installation's owning actor.
#[derive(Clone)]
pub(super) struct PublicReferenceCustodyQueue(Rc<RefCell<Registry>>);

/// Transfers an authentically reclaimed capsule without discarding its journal.
pub(super) struct ReclaimedPublicPeer {
    pub(super) scope: PublicPeerScope,
    pub(super) custody: CnpPeerCustody,
}

impl PublicReferenceCustodyQueue {
    pub(super) fn new(maximum_peers: usize) -> Result<Self, ProviderError> {
        if maximum_peers == 0 || maximum_peers > 1024 {
            return Err(ProviderError::ResourceExhausted(
                "invalid public peer reservation ceiling",
            ));
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(maximum_peers)
            .map_err(|_| ProviderError::ResourceExhausted("public peer reservation allocation"))?;
        entries.resize_with(maximum_peers, || None);
        let mut resolved = Vec::new();
        resolved.try_reserve_exact(maximum_peers).map_err(|_| {
            ProviderError::ResourceExhausted("resolved original peer custody reservation")
        })?;
        Ok(Self(Rc::new(RefCell::new(Registry {
            entries,
            next_identity: 1,
            resolved,
            keep_alive: None,
        }))))
    }

    pub(super) fn reserve(
        &self,
        scope: PublicPeerScope,
    ) -> Result<Box<dyn CnpProcessCustodySlot>, ProviderError> {
        if !scope.activation.owners.contains(&scope.owner)
            || scope.source_roots.len() > 64
            || scope.publication.is_some()
            || scope.connection_incident.borrow().is_some()
            || scope.private_launch.len() > 16 * 1024 * 1024
            || scope.original_hello.len() > 1024 * 1024
        {
            return Err(ProviderError::Correlation(
                "public peer reservation scope differs",
            ));
        }
        if (scope.ordinary_negotiation.is_some() || scope.collecting_negotiation.is_some())
            && scope.source_custody.is_none()
        {
            return Err(ProviderError::Correlation(
                "ordinary package source custody was not reserved",
            ));
        }
        if scope.ordinary_negotiation.is_some() && scope.collecting_negotiation.is_some() {
            return Err(ProviderError::Correlation(
                "ordinary and collecting originals cannot share a slot",
            ));
        }
        if let Some(original) = &scope.collecting_negotiation {
            let original = original
                .try_borrow()
                .map_err(|_| ProviderError::Correlation("collecting transport already borrowed"))?;
            if !original.is_unstarted() {
                return Err(ProviderError::Correlation(
                    "collecting transport already attempted",
                ));
            }
        }
        if let Some(original) = &scope.ordinary_negotiation {
            let original = original.try_borrow().map_err(|_| {
                ProviderError::Correlation("ordinary negotiation holder is already borrowed")
            })?;
            if !original.is_unstarted() {
                return Err(ProviderError::Correlation(
                    "ordinary negotiation holder was used before reservation",
                ));
            }
        }
        let mut registry = self.0.borrow_mut();
        if registry.resolved.len() + registry.entries.iter().flatten().count()
            >= registry.entries.len()
        {
            return Err(ProviderError::ResourceExhausted(
                "original peer lifetime custody credit",
            ));
        }
        let index = registry.entries.iter().position(Option::is_none).ok_or(
            ProviderError::ResourceExhausted("public peer reservation unavailable"),
        )?;
        let identity = U64::new(registry.next_identity);
        registry.next_identity =
            registry
                .next_identity
                .checked_add(1)
                .ok_or(ProviderError::ResourceExhausted(
                    "public peer reservation identity overflow",
                ))?;
        let entry = Rc::new(RefCell::new(Entry {
            identity,
            scope,
            custody: None,
            in_flight: false,
            reclaimed: false,
            archive: None,
        }));
        registry.entries[index] = Some(entry.clone());
        registry.keep_alive = Some(self.0.clone());
        Ok(Box::new(Slot {
            queue: self.clone(),
            entry,
            index,
            identity,
            retained: false,
        }))
    }

    /// Copies actual publisher knowledge while retaining the original world.
    ///
    /// Only the private forwarding durable publisher calls this hook. It first
    /// records Unknown before its storage callback, then copies the callback's
    /// actual result. Native journals therefore retain uncertainty on unwind.
    pub(super) fn record_publication(
        &self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
        status: PublicationStatus,
    ) -> Result<(), ProviderError> {
        if prepared.prepared_owners().len() != record.owners.len()
            || record.owners.iter().any(|owner| {
                prepared
                    .prepared_owners()
                    .iter()
                    .filter(|prepared| {
                        prepared.owner_id == owner.owner
                            && prepared.incarnation_id == owner.incarnation
                            && prepared.owner_generation == owner.generation
                    })
                    .count()
                    != 1
            })
        {
            return Err(ProviderError::Correlation(
                "original public preparation owner scope differs",
            ));
        }
        self.record_scope_publication(record, status)
    }

    pub(super) fn publication(
        &self,
        record: &ActivationRecord,
    ) -> Result<Option<PublicationStatus>, ProviderError> {
        self.authenticate_publication_scope(record)?;
        let registry = self.0.borrow();
        let mut statuses = registry
            .entries
            .iter()
            .flatten()
            .map(|entry| entry.borrow().scope.publication);
        let original = statuses.next().ok_or(ProviderError::Correlation(
            "original public publication owner absent",
        ))?;
        if statuses.any(|status| status != original) {
            return Err(ProviderError::Correlation(
                "original public publication owners disagree",
            ));
        }
        Ok(original)
    }

    pub(super) fn record_scope_publication(
        &self,
        record: &ActivationRecord,
        status: PublicationStatus,
    ) -> Result<(), ProviderError> {
        self.authenticate_publication_scope(record)?;
        for entry in self.0.borrow().entries.iter().flatten() {
            let mut entry = entry.borrow_mut();
            // A later outage cannot erase a positively committed original.
            if entry.scope.publication != Some(PublicationStatus::Committed) {
                entry.scope.publication = Some(status);
            }
        }
        Ok(())
    }

    fn authenticate_publication_scope(
        &self,
        record: &ActivationRecord,
    ) -> Result<(), ProviderError> {
        let registry = self.0.borrow();
        if record.owners.is_empty()
            || registry.entries.iter().flatten().count() != record.owners.len()
            || registry.entries.iter().flatten().any(|entry| {
                let entry = entry.borrow();
                entry.scope.activation != *record
                    || record
                        .owners
                        .iter()
                        .filter(|owner| **owner == entry.scope.owner)
                        .count()
                        != 1
            })
            || record.owners.iter().any(|owner| {
                registry
                    .entries
                    .iter()
                    .flatten()
                    .filter(|entry| {
                        let entry = entry.borrow();
                        entry.scope.activation == *record && entry.scope.owner == *owner
                    })
                    .count()
                    != 1
            })
        {
            return Err(ProviderError::Correlation(
                "original public publication scope differs",
            ));
        }
        Ok(())
    }

    pub(super) fn outstanding(&self) -> usize {
        self.0.borrow().entries.iter().flatten().count()
    }

    pub(super) fn source_roots(&self) -> Vec<ContentRef> {
        self.0
            .borrow()
            .entries
            .iter()
            .flatten()
            .flat_map(|entry| {
                let entry = entry.borrow();
                std::iter::once(entry.scope.implementation.clone())
                    .chain(entry.scope.source_roots.iter().cloned())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Polls at most one original capsule without holding a registry borrow.
    pub(super) fn poll_reclamation(&self) -> Result<bool, ProviderError> {
        let candidate = {
            let mut registry = self.0.borrow_mut();
            registry
                .entries
                .iter_mut()
                .enumerate()
                .find_map(|(index, entry)| {
                    let entry = entry.as_ref()?;
                    let mut state = entry.borrow_mut();
                    if state.in_flight || state.reclaimed {
                        return None;
                    }
                    let custody = state.custody.take()?;
                    state.in_flight = true;
                    Some((index, entry.clone(), custody))
                })
        };
        let Some((_index, entry, custody)) = candidate else {
            return Ok(self.outstanding() == 0);
        };
        let mut lease = PollLease {
            entry: entry.clone(),
            custody: Some(custody),
        };
        let native = lease.custody.as_mut().ok_or(ProviderError::Correlation(
            "original public peer lease absent",
        ))?;
        let reclaimed = native.poll_reclamation()?;
        if reclaimed {
            entry.borrow_mut().reclaimed = true;
        }
        // PollLease restores the exact original object on Pending, failure or
        // unwind; the installation's actor continues polling afterward.
        drop(lease);
        Ok(false)
    }

    /// Resolves one ordinary capsule only after its original semantic and durable seals.
    pub(super) fn resolve_ordinary_reclaimed(&self) -> Result<bool, ProviderError> {
        self.resolve_original_reclaimed()
    }

    /// Resolves the same ordinary or source-only collecting originals.
    ///
    /// Transport selection grants no class acceptance. The original semantic
    /// seal and same-attempt source-complete private archive remain mandatory.
    ///
    /// # Errors
    /// Retains every capsule on unresolved semantic or durable disposition.
    pub(super) fn resolve_original_reclaimed(&self) -> Result<bool, ProviderError> {
        let mut registry = self.0.borrow_mut();
        let candidate = registry.entries.iter().position(|entry| {
            entry.as_ref().is_some_and(|entry| {
                let state = entry.borrow();
                state.reclaimed
                    && !state.in_flight
                    && state.custody.is_some()
                    && (state.scope.ordinary_negotiation.is_some()
                        || state.scope.collecting_negotiation.is_some())
                    && Rc::strong_count(entry) == 1
            })
        });
        let Some(index) = candidate else {
            return Ok(registry.entries.iter().all(Option::is_none));
        };
        if let Some(entry) = &registry.entries[index] {
            let mut state = entry.borrow_mut();
            if state.archive.is_none() {
                state.archive = Some(OriginalArchiveAttempt::prepare(&state)?);
            }
            let identity = state.identity;
            let archive = state.archive.as_mut().ok_or(ProviderError::Correlation(
                "original archive attempt absent",
            ))?;
            archive.poll()?;
            if !archive.complete_for(identity) {
                return Err(ProviderError::Correlation(
                    "original archive acknowledgement differs",
                ));
            }
        }
        let original = registry.entries[index]
            .take()
            .ok_or(ProviderError::Correlation(
                "original resolution slot absent",
            ))?;
        let mut entry = match Rc::try_unwrap(original) {
            Ok(original) => original.into_inner(),
            Err(original) => {
                registry.entries[index] = Some(original);
                return Ok(false);
            }
        };
        // All private originals travel together after the SAME attempt's positive
        // acknowledgement. They stay actor-owned; the durable file survives exit.
        match (entry.archive.take(), entry.custody.take()) {
            (Some(archive), Some(custody)) => registry.resolved.push(archive.acknowledge(
                entry.identity,
                ReclaimedPublicPeer {
                    scope: entry.scope,
                    custody,
                },
            )),
            (archive, custody) => {
                entry.archive = archive;
                entry.custody = custody;
                registry.entries[index] = Some(Rc::new(RefCell::new(entry)));
                return Err(ProviderError::Correlation(
                    "sealed original capsule incomplete",
                ));
            }
        }
        if registry.entries.iter().all(Option::is_none) {
            registry.keep_alive = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Authenticates the actual retained archive acknowledgements for this world.
    ///
    /// # Errors
    /// Refuses remaining original slots, missing exact owners or changed original
    /// file/source bytes. An activation label cannot construct an acknowledgement.
    pub(super) fn authenticate_resolved(
        &self,
        record: &ActivationRecord,
    ) -> Result<(), ProviderError> {
        let mut registry = self.0.borrow_mut();
        if registry.entries.iter().any(Option::is_some)
            || registry.resolved.len() != record.owners.len()
            || record.owners.is_empty()
        {
            return Err(ProviderError::Correlation(
                "original world archives incomplete",
            ));
        }
        for owner in &record.owners {
            if registry
                .resolved
                .iter()
                .filter(|original| original.belongs_to(record, owner))
                .count()
                != 1
            {
                return Err(ProviderError::Correlation(
                    "original world archive owner differs",
                ));
            }
        }
        for original in &mut registry.resolved {
            original.confirm_original()?;
        }
        Ok(())
    }

    pub(super) fn take_reclaimed(&self) -> Option<ReclaimedPublicPeer> {
        let mut registry = self.0.borrow_mut();
        let index = registry.entries.iter().position(|entry| {
            entry.as_ref().is_some_and(|entry| {
                let state = entry.borrow();
                state.reclaimed
                    && !state.in_flight
                    && state.custody.is_some()
                    && state.archive.is_none()
            })
        })?;
        let original = registry.entries[index].take()?;
        let entry = match Rc::try_unwrap(original) {
            Ok(original) => original.into_inner(),
            Err(original) => {
                // A still-owned native reservation cannot be discharged by
                // removing its queue row; retain it for the next actor turn.
                registry.entries[index] = Some(original);
                return None;
            }
        };
        if registry.entries.iter().all(Option::is_none) {
            registry.keep_alive = None;
        }
        Some(ReclaimedPublicPeer {
            scope: entry.scope,
            custody: entry.custody?,
        })
    }
}

struct Slot {
    queue: PublicReferenceCustodyQueue,
    entry: Rc<RefCell<Entry>>,
    index: usize,
    identity: U64,
    retained: bool,
}

impl CnpProcessCustodySlot for Slot {
    fn identity(&self) -> U64 {
        self.identity
    }

    fn retain(&mut self, custody: CnpPeerCustody) {
        // The core guard consumes this private, non-cloneable slot and invokes
        // retain exactly once. No wire value can construct a native capsule.
        self.entry.borrow_mut().custody = Some(custody);
        self.retained = true;
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if !self.retained {
            let mut registry = self.queue.0.borrow_mut();
            let entry = self.entry.borrow();
            let unused =
                entry.identity == self.identity && entry.custody.is_none() && !entry.in_flight;
            if unused {
                registry.entries[self.index] = None;
            }
            if registry.entries.iter().all(Option::is_none) {
                registry.keep_alive = None;
            }
        }
    }
}

struct PollLease {
    entry: Rc<RefCell<Entry>>,
    custody: Option<CnpPeerCustody>,
}

impl Drop for PollLease {
    fn drop(&mut self) {
        let mut entry = self.entry.borrow_mut();
        entry.custody = self.custody.take();
        entry.in_flight = false;
    }
}

//! Reserves actor-owned public-peer custody before any native process exists.
//!
//! The installation actor must poll this queue until every original peer has
//! authentic reclamation proof. Native handles, journals, original world scope
//! and publication uncertainty survive borrower drops and callback unwinding.
//! A positive process-group census permits transfer of the retained capsule;
//! it does not discharge semantic or durable-ledger obligations.

use std::{cell::RefCell, rc::Rc};

use crucible::{
    node_adapters::cnp::{CnpPeerCustody, CnpProcessCustodySlot},
    node_contract::{ActivationRecord, OwnerIdentity, PreparedWorldPublication, PublicationStatus},
};
use crucible_node_contract::{ContentRef, U64};
use crucible_node_provider::{ProviderError, connection::ConnectionIncident};

/// Retains the actual host reservation and all original source commitments.
pub(super) struct PublicPeerScope {
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) implementation: ContentRef,
    pub(super) source_roots: Vec<ContentRef>,
    pub(super) publication: Option<PublicationStatus>,
    pub(super) connection_incident: Rc<RefCell<Option<ConnectionIncident>>>,
    // These private originals may contain admission secrets and never become
    // public CAS roots or inert observation evidence.
    pub(super) private_launch: Vec<u8>,
    pub(super) original_hello: Vec<u8>,
}

struct Entry {
    identity: U64,
    scope: PublicPeerScope,
    custody: Option<CnpPeerCustody>,
    in_flight: bool,
    reclaimed: bool,
}

struct Registry {
    entries: Vec<Option<Rc<RefCell<Entry>>>>,
    next_identity: u64,
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
        Ok(Self(Rc::new(RefCell::new(Registry {
            entries,
            next_identity: 1,
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
        let mut registry = self.0.borrow_mut();
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
        let registry = self.0.borrow();
        let entries = registry.entries.iter().flatten().collect::<Vec<_>>();
        if entries.len() != record.owners.len()
            || prepared.prepared_owners().len() != record.owners.len()
            || entries.iter().any(|entry| {
                let entry = entry.borrow();
                entry.scope.activation != *record || !record.owners.contains(&entry.scope.owner)
            })
        {
            return Err(ProviderError::Correlation(
                "original public publication scope differs",
            ));
        }
        for entry in entries {
            entry.borrow_mut().scope.publication = Some(status);
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

    pub(super) fn take_reclaimed(&self) -> Option<ReclaimedPublicPeer> {
        let mut registry = self.0.borrow_mut();
        let index = registry.entries.iter().position(|entry| {
            entry.as_ref().is_some_and(|entry| {
                let state = entry.borrow();
                state.reclaimed && !state.in_flight && state.custody.is_some()
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

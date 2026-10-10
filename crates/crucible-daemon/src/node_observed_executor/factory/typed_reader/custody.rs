//! Preallocates three source capsules, three reader capsules and one whole world.
//!
//! The owning runtime actor polls both queues. Native errors preserve complete
//! original custody; numeric process IDs or an empty mailbox never prove cleanup.

use crucible::node_adapters::cnp::{LineageRuntimeCustody, LineageRuntimeCustodySlot};
use crucible::node_contract::{
    ActivationRecord, RuntimeCustodyQueue, RuntimeCustodySlot, RuntimeCustodySupervisor,
    RuntimeLimits,
};
use crucible_node_contract::U64;
use crucible_node_provider::reference_lineage::{LineageSourceCustody, LineageSourceCustodySlot};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use super::super::{NodeObservedError, refused};
use super::TypedReaderAdoptionFailure;

struct Mailbox {
    source: RefCell<Option<LineageSourceCustody>>,
    runtime: RefCell<Option<LineageRuntimeCustody>>,
    source_outstanding: Cell<bool>,
    runtime_outstanding: Cell<bool>,
    polling: Cell<bool>,
}

struct Inner {
    mailboxes: Vec<Rc<Mailbox>>,
    cursor: Cell<usize>,
    waker: RefCell<Option<Waker>>,
    keepalive: RefCell<Option<Rc<Inner>>>,
    adoption: RefCell<Option<Box<TypedReaderAdoptionFailure>>>,
    adoption_reserved: Cell<bool>,
    adoption_outstanding: Cell<bool>,
    adoption_polling: Cell<bool>,
}

/// Retains pre-reserved typed source obligations on their original actor thread.
///
/// This owner has no execution or admission API. Its event loop must call
/// [`Self::poll_reclamation`] even after a policy or diagnostic refuses. Pending
/// slot handles and retained capsules keep storage alive across caller drop.
#[derive(Clone)]
pub struct TypedReaderCustodySupervisor {
    inner: Rc<Inner>,
    world: RuntimeCustodyQueue,
}

/// Owns all seven distinct custody reservations before provider Child allocation.
///
/// This cohort is fixed to two producers and one consumer. The world slot retains
/// the complete coordinator/runtime and does not substitute for the six separate
/// original source/reader capsules. No member is an activation or Ready permit.
pub struct TypedReaderCohortReservation {
    /// Retains the exact whole-world slot for eventual `NodeRuntime::new`.
    pub world: Box<dyn RuntimeCustodySlot>,
    /// Retains one source/runtime pair for each original logical node.
    pub readers: Vec<TypedReaderCustodyPair>,
}

/// Transfers one original source and complete reader reservation without cloning.
pub struct TypedReaderCustodyPair {
    /// Enters `LineageSourceGuard::new` immediately after the actual Child spawn.
    pub source: Box<dyn LineageSourceCustodySlot>,
    /// Enters `LineageControlledReference::from_negotiated_original` unchanged.
    pub runtime: Box<dyn LineageRuntimeCustodySlot>,
}

impl TypedReaderCustodySupervisor {
    /// Reserves all complete world/source/reader custody before the first Child.
    ///
    /// # Errors
    /// Refuses changed three-node/three-owner geometry, invalid limits or host
    /// allocation failure. All partial unused reservations are consumed by Drop.
    pub fn reserve(
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<(Self, TypedReaderCohortReservation), NodeObservedError> {
        if limits.maximum_nodes != 3
            || limits.maximum_owners != 3
            || activation.owners.len() != 3
            || limits.maximum_operations == 0
            || limits.maximum_operations > 192
            || limits.maximum_retained_outputs == 0
            || limits.maximum_retained_outputs > 192
        {
            return Err(refused(
                "typed cohort whole-world reservation geometry differs",
            ));
        }
        let world = RuntimeCustodyQueue::new(1)
            .map_err(|error| NodeObservedError::Native(error.to_string()))?;
        let world_slot = world
            .reserve_world(activation, limits)
            .map_err(|error| NodeObservedError::Native(error.to_string()))?;
        let mut mailboxes = Vec::new();
        mailboxes
            .try_reserve_exact(3)
            .map_err(|_| refused("typed custody mailbox credit"))?;
        let mut readers = Vec::new();
        readers
            .try_reserve_exact(3)
            .map_err(|_| refused("typed custody slot credit"))?;
        for _ in 0..3 {
            mailboxes.push(Rc::new(Mailbox {
                source: RefCell::new(None),
                runtime: RefCell::new(None),
                source_outstanding: Cell::new(true),
                runtime_outstanding: Cell::new(true),
                polling: Cell::new(false),
            }));
        }
        let inner = Rc::new(Inner {
            mailboxes,
            cursor: Cell::new(0),
            waker: RefCell::new(None),
            keepalive: RefCell::new(None),
            adoption: RefCell::new(None),
            adoption_reserved: Cell::new(false),
            adoption_outstanding: Cell::new(false),
            adoption_polling: Cell::new(false),
        });
        *inner.keepalive.borrow_mut() = Some(Rc::clone(&inner));
        for (index, mailbox) in inner.mailboxes.iter().enumerate() {
            readers.push(TypedReaderCustodyPair {
                source: Box::new(SourceSlot {
                    inner: Rc::clone(&inner),
                    mailbox: Rc::clone(mailbox),
                    identity: U64::new(index as u64 + 1),
                }),
                runtime: Box::new(ReaderSlot {
                    inner: Rc::clone(&inner),
                    mailbox: Rc::clone(mailbox),
                    identity: U64::new(index as u64 + 4),
                }),
            });
        }
        Ok((
            Self { inner, world },
            TypedReaderCohortReservation {
                world: world_slot,
                readers,
            },
        ))
    }

    /// Reserves the sole failed-adoption journal holder before any Child.
    ///
    /// The upper preparation stops at its first failure. This consuming slot
    /// therefore retains at most one complete returned attachment and never
    /// allocates another holder during failure transfer or cleanup.
    pub(super) fn reserve_adoption(&self) -> Result<TypedReaderAdoptionSlot, NodeObservedError> {
        if self.inner.adoption_reserved.replace(true) {
            return Err(refused("typed adoption cleanup slot already reserved"));
        }
        self.inner.adoption_outstanding.set(true);
        Ok(TypedReaderAdoptionSlot {
            inner: Rc::clone(&self.inner),
            transferred: false,
        })
    }

    fn poll_adoption(&self) {
        if !self.inner.adoption_polling.replace(true) {
            let original = self.inner.adoption.borrow_mut().take();
            let mut retained = AdoptionPolling {
                inner: Rc::clone(&self.inner),
                original,
            };
            if let Some(original) = retained.original.take() {
                match (*original).retain_for_cleanup() {
                    Ok(()) => self.inner.adoption_outstanding.set(false),
                    Err(original) => {
                        retained.original = Some(original);
                        // The original journals remain in the prior mailbox.
                        // No absent queue or failed transfer proves reclamation.
                    }
                }
            }
        }
    }

    /// Polls one complete typed capsule and the authentic world cleanup queue.
    ///
    /// No registry borrow is held across native callbacks. Callback unwind puts
    /// the same owning capsule back. Cleanup failures never release a claim or
    /// imply rollback; the caller continues authentic cleanup after refusal.
    ///
    /// # Errors
    /// Preserves original custody on provider or whole-runtime cleanup failure.
    pub fn poll_reclamation(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), NodeObservedError>> {
        *self.inner.waker.borrow_mut() = Some(context.waker().clone());
        // World refusal cannot gate the independently owning native capsules.
        // Service one original capsule before returning its retained failure.
        let world_failure = match self.world.poll_reclamation(context) {
            Poll::Ready(Err(error)) => Some(error),
            _ => None,
        };
        self.poll_adoption();
        let start = self.inner.cursor.get();
        for offset in 0..3 {
            let index = (start + offset) % 3;
            let mailbox = &self.inner.mailboxes[index];
            if mailbox.polling.get() {
                continue;
            }
            let selected = if let Some(runtime) = mailbox.runtime.borrow_mut().take() {
                Some(Capsule {
                    runtime: Some(runtime),
                    source: None,
                })
            } else {
                mailbox.source.borrow_mut().take().map(|source| Capsule {
                    source: Some(source),
                    runtime: None,
                })
            };
            let Some(capsule) = selected else {
                continue;
            };
            self.inner.cursor.set((index + 1) % 3);
            mailbox.polling.set(true);
            let mut original = Polling {
                mailbox: Rc::clone(mailbox),
                capsule: Some(capsule),
            };
            let result = match original.capsule.as_mut() {
                Some(capsule) => match (capsule.source.as_mut(), capsule.runtime.as_mut()) {
                    (Some(source), None) => source.poll_reclamation(),
                    (None, Some(runtime)) => runtime.poll_reclamation(),
                    _ => return Poll::Pending,
                },
                None => return Poll::Pending,
            };
            match result {
                Ok(true) => {
                    drop(original.capsule.take());
                }
                Ok(false) => {}
                Err(error) => {
                    return Poll::Ready(Err(NodeObservedError::Native(error.to_string())));
                }
            }
            break;
        }
        if let Some(error) = world_failure {
            return Poll::Ready(Err(NodeObservedError::Native(error.to_string())));
        }
        let unresolved = self.inner.adoption_outstanding.get()
            || self.inner.adoption_polling.get()
            || self.inner.adoption.borrow().is_some()
            || self.inner.mailboxes.iter().any(|mailbox| {
                mailbox.source_outstanding.get()
                    || mailbox.runtime_outstanding.get()
                    || mailbox.polling.get()
                    || mailbox.source.borrow().is_some()
                    || mailbox.runtime.borrow().is_some()
            });
        if self.world.reserved_worlds() == 0 && !unresolved {
            self.inner.keepalive.borrow_mut().take();
            Poll::Ready(Ok(()))
        } else {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Transfers one exact returned adoption into its prior private supervisor.
///
/// The slot is private, non-cloneable and issued once before Child. Its sole
/// consumer is the upper capsule's failure Drop, after native assembly stops.
pub(super) struct TypedReaderAdoptionSlot {
    inner: Rc<Inner>,
    transferred: bool,
}

impl TypedReaderAdoptionSlot {
    pub(super) fn retain(mut self, original: Box<TypedReaderAdoptionFailure>) {
        // No mailbox borrow escapes this module. The single consuming slot and
        // sticky upper failure ensure the holder is unused on this transfer.
        *self.inner.adoption.borrow_mut() = Some(original);
        self.transferred = true;
        wake(&self.inner);
    }
}

impl Drop for TypedReaderAdoptionSlot {
    fn drop(&mut self) {
        if !self.transferred {
            self.inner.adoption_outstanding.set(false);
            wake(&self.inner);
        }
    }
}

struct AdoptionPolling {
    inner: Rc<Inner>,
    original: Option<Box<TypedReaderAdoptionFailure>>,
}

impl Drop for AdoptionPolling {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            *self.inner.adoption.borrow_mut() = Some(original);
        }
        self.inner.adoption_polling.set(false);
    }
}

// A local move slot retains exactly one original capsule without allocating
// another heap holder during native reclamation. Constructors are private.
struct Capsule {
    source: Option<LineageSourceCustody>,
    runtime: Option<LineageRuntimeCustody>,
}

struct Polling {
    mailbox: Rc<Mailbox>,
    capsule: Option<Capsule>,
}

impl Drop for Polling {
    fn drop(&mut self) {
        if let Some(mut capsule) = self.capsule.take() {
            if let Some(source) = capsule.source.take() {
                *self.mailbox.source.borrow_mut() = Some(source);
            }
            if let Some(runtime) = capsule.runtime.take() {
                *self.mailbox.runtime.borrow_mut() = Some(runtime);
            }
        }
        self.mailbox.polling.set(false);
    }
}

struct SourceSlot {
    inner: Rc<Inner>,
    mailbox: Rc<Mailbox>,
    identity: U64,
}

struct ReaderSlot {
    inner: Rc<Inner>,
    mailbox: Rc<Mailbox>,
    identity: U64,
}

impl LineageSourceCustodySlot for SourceSlot {
    fn identity(&self) -> U64 {
        self.identity
    }
    fn retain(self: Box<Self>, custody: LineageSourceCustody) {
        *self.mailbox.source.borrow_mut() = Some(custody);
        let waker = self.inner.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl LineageRuntimeCustodySlot for ReaderSlot {
    fn identity(&self) -> U64 {
        self.identity
    }
    fn retain(self: Box<Self>, custody: LineageRuntimeCustody) {
        *self.mailbox.runtime.borrow_mut() = Some(custody);
        let waker = self.inner.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        self.mailbox.source_outstanding.set(false);
    }
}

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        self.mailbox.runtime_outstanding.set(false);
    }
}

fn wake(inner: &Inner) {
    let original = inner.waker.borrow_mut().take();
    if let Some(original) = original {
        original.wake();
    }
}

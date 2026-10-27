//! Finite actor-local owning custody slots with authentic bounded reclamation.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use super::*;

#[path = "supervisor/bounded_wake.rs"]
mod bounded_wake;
pub use bounded_wake::{RuntimeCustodyWakeReader, RuntimeCustodyWakeWait};

struct Mailbox {
    reserved: Cell<bool>,
    polling: Cell<bool>,
    custody: RefCell<Option<WholeRuntimeCustody>>,
}

struct QueueInner {
    process: u32,
    thread: std::thread::ThreadId,
    notifier: Option<std::sync::Arc<bounded_wake::CustodyNotifier>>,
    original_waker: Option<Waker>,
    mailboxes: Vec<Rc<Mailbox>>,
    cursor: Cell<usize>,
    waker: RefCell<Option<Waker>>,
    keepalive: RefCell<Option<Rc<QueueInner>>>,
}

struct PollingCustody {
    mailbox: Rc<Mailbox>,
    custody: Option<WholeRuntimeCustody>,
}

impl Drop for PollingCustody {
    fn drop(&mut self) {
        // A native callback can unwind. Preserve the whole coordinator ledger
        // alongside native handles rather than leaving a permanently empty slot.
        if let Some(custody) = self.custody.take() {
            *self.mailbox.custody.borrow_mut() = Some(custody);
        }
        self.mailbox.polling.set(false);
    }
}

/// Retains complete dropped runtimes in finite preallocated actor-local mailboxes.
///
/// The owning actor reserves a slot before native allocation and polls this queue
/// during its event loop. Slots and pending custody keep the queue alive even if
/// all borrower handles disappear. Only authenticated complete native reclamation
/// releases a mailbox; cleanup failure preserves the original whole-world ledger.
/// This type has no execution or output-publication interface and is not `Send`.
#[derive(Clone)]
pub struct RuntimeCustodyQueue {
    inner: Rc<QueueInner>,
}

impl RuntimeCustodyQueue {
    /// Preallocates a finite complete-world custody inventory on its owning thread.
    ///
    /// # Errors
    /// Rejects a zero/excessive capacity or unavailable host allocation.
    pub fn new(maximum_worlds: usize) -> Result<Self, RuntimeError> {
        if maximum_worlds == 0 || maximum_worlds > crucible_node_format::MAX_ARRAY_ELEMENTS {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut mailboxes = Vec::new();
        mailboxes
            .try_reserve_exact(maximum_worlds)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for _ in 0..maximum_worlds {
            mailboxes.push(Rc::new(Mailbox {
                reserved: Cell::new(false),
                polling: Cell::new(false),
                custody: RefCell::new(None),
            }));
        }
        Ok(Self {
            inner: Rc::new(QueueInner {
                process: std::process::id(),
                thread: std::thread::current().id(),
                notifier: None,
                original_waker: None,
                mailboxes,
                cursor: Cell::new(0),
                waker: RefCell::new(None),
                keepalive: RefCell::new(None),
            }),
        })
    }

    /// Counts reserved live worlds and retained complete cleanup obligations.
    pub fn reserved_worlds(&self) -> usize {
        self.inner
            .mailboxes
            .iter()
            .filter(|mailbox| mailbox.reserved.get())
            .count()
    }

    /// Counts complete worlds already transferred into supervised containment.
    pub fn retained_worlds(&self) -> usize {
        self.inner
            .mailboxes
            .iter()
            .filter(|mailbox| mailbox.polling.get() || mailbox.custody.borrow().is_some())
            .count()
    }

    /// Polls at most one world's one-owner authentic native reclamation.
    ///
    /// No queue borrow is held during native callbacks. Reentrant dropping of
    /// another runtime can therefore transfer its complete custody safely.
    ///
    /// # Errors
    /// Returns native cleanup or evidence failure while reinserting the complete
    /// original custody. Errors never free capacity or imply effect rollback.
    pub fn poll_reclamation(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), super::super::RuntimePollFailure>> {
        if self.inner.notifier.is_some() {
            if self.inner.process != std::process::id()
                || self.inner.thread != std::thread::current().id()
            {
                return Poll::Ready(Err(crate::node_contract::RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                )));
            }
            let Some(expected) = self.inner.original_waker.as_ref() else {
                return Poll::Ready(Err(crate::node_contract::RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                )));
            };
            let stored = self.inner.waker.borrow();
            if !context.waker().will_wake(expected)
                || stored
                    .as_ref()
                    .is_some_and(|held| !held.will_wake(expected))
            {
                // Never discard an unknown retained wake owner to obtain budget
                // credit. Ordinary queues keep their original arbitrary path.
                return Poll::Ready(Err(crate::node_contract::RuntimePollFailure::Admission(
                    RuntimeError::ForeignAuthority,
                )));
            }
        }
        *self.inner.waker.borrow_mut() = Some(context.waker().clone());
        let count = self.inner.mailboxes.len();
        let start = self.inner.cursor.get();
        let next = (0..count)
            .map(|offset| (start + offset) % count)
            .find(|index| {
                let mailbox = &self.inner.mailboxes[*index];
                !mailbox.polling.get() && mailbox.custody.borrow().is_some()
            });
        let Some(index) = next else {
            return if self.reserved_worlds() == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        };
        self.inner.cursor.set((index + 1) % count);
        let mailbox = &self.inner.mailboxes[index];
        let custody = mailbox.custody.borrow_mut().take();
        let Some(custody) = custody else {
            return Poll::Pending;
        };
        mailbox.polling.set(true);
        let mut guarded = PollingCustody {
            mailbox: Rc::clone(mailbox),
            custody: Some(custody),
        };

        let result = match guarded.custody.as_mut() {
            Some(custody) => custody.poll_reclamation(context),
            None => return Poll::Pending,
        };

        match result {
            Poll::Ready(Ok(())) => {
                if guarded
                    .custody
                    .as_ref()
                    .is_some_and(WholeRuntimeCustody::retirement_history_pending)
                {
                    // Guard Drop restores the same complete capsule. The
                    // original mailbox remains charged until durable release.
                    return Poll::Pending;
                }
                mailbox.reserved.set(false);
                drop(guarded.custody.take());
                drop(guarded);
                release_keepalive_if_empty(&self.inner);
                if self.reserved_worlds() == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            other => other,
        }
    }
}

impl RuntimeCustodySupervisor for RuntimeCustodyQueue {
    fn reserve_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Box<dyn RuntimeCustodySlot>, RuntimeError> {
        if self.inner.notifier.is_some()
            && (self.inner.process != std::process::id()
                || self.inner.thread != std::thread::current().id())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mailbox = self
            .inner
            .mailboxes
            .iter()
            .find(|mailbox| !mailbox.reserved.get())
            .ok_or(RuntimeError::ResourceLimit)?;
        mailbox.reserved.set(true);
        *self.inner.keepalive.borrow_mut() = Some(Rc::clone(&self.inner));
        Ok(Box::new(QueueSlot {
            process: std::process::id(),
            thread: std::thread::current().id(),
            inner: Rc::clone(&self.inner),
            mailbox: Rc::clone(mailbox),
            activation: activation.clone(),
            limits,
            transferred: false,
        }))
    }
}

struct QueueSlot {
    process: u32,
    thread: std::thread::ThreadId,
    inner: Rc<QueueInner>,
    mailbox: Rc<Mailbox>,
    activation: ActivationRecord,
    limits: RuntimeLimits,
    transferred: bool,
}

impl RuntimeCustodySlot for QueueSlot {
    fn retained_descriptor_views_precredit_data(&self) -> Result<Option<usize>, RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || self.inner.process != self.process
            || self.inner.thread != self.thread
            || self.transferred
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.original_queue_storage(usize::MAX)?
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let descriptors = match self.inner.notifier.as_ref() {
            Some(notifier) => bounded_wake::notifier_descriptor_count_data(notifier)?,
            None => 0,
        };
        Ok(Some(descriptors))
    }

    fn original_runtime_custody_queue(
        &self,
    ) -> Result<Option<RuntimeCustodyQueueWitness<'_>>, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.transferred
            || self.inner.process != self.process
            || self.inner.thread != self.thread
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(Some(RuntimeCustodyQueueWitness { inner: &self.inner }))
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        use crate::node_contract::runtime::RuntimeOwnedStorage;

        let Some(backing) = self.original_queue_storage(maximum)? else {
            return Ok(None);
        };
        let bytes = backing
            .checked_add(self.activation.owned_storage()?)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(Some(bytes))
    }

    fn retained_requested_storage_precredit_scratch_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || self.inner.process != self.process
            || self.inner.thread != self.thread
            || self.transferred
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        use std::{cell::Ref, mem::size_of};
        Ok(Some(
            size_of::<RetainedRuntimeCounter>()
                + size_of::<Ref<'_, Option<Waker>>>()
                + size_of::<Ref<'_, Option<Rc<QueueInner>>>>()
                + size_of::<Ref<'_, Option<WholeRuntimeCustody>>>(),
        ))
    }

    fn original_transferred(&self) -> bool {
        self.transferred
    }

    fn retain_borrowed(
        &mut self,
        original: &mut Option<WholeRuntimeCustody>,
    ) -> Result<(), RuntimeError> {
        if self.transferred {
            return Err(RuntimeError::OutstandingObligations);
        }
        let custody = original
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        self.validate_world(custody.activation(), custody.limits())?;
        let mut mailbox = self
            .mailbox
            .custody
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if mailbox.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let original = original
            .take()
            .ok_or(RuntimeError::OutstandingObligations)?;
        *mailbox = Some(original);
        self.transferred = true;
        drop(mailbox);
        // Wake is after complete custody; unwind cannot lose the native world.
        let waker = self.inner.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    fn validate_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<(), RuntimeError> {
        if activation != &self.activation || limits != self.limits {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn retain(mut self: Box<Self>, custody: WholeRuntimeCustody) {
        if self.transferred {
            // The borrowed handoff already retained the same complete world.
            // Dropping its inactive shell must not replace that original.
            return;
        }
        // A mailbox has exactly one non-cloneable reserved slot, consumed once.
        // It cannot contain another capsule while this slot remains outstanding.
        *self.mailbox.custody.borrow_mut() = Some(custody);
        self.transferred = true;
        let waker = self.inner.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Drop for QueueSlot {
    fn drop(&mut self) {
        if !self.transferred {
            self.mailbox.reserved.set(false);
            release_keepalive_if_empty(&self.inner);
        }
    }
}

fn release_keepalive_if_empty(inner: &Rc<QueueInner>) {
    if inner
        .mailboxes
        .iter()
        .all(|mailbox| !mailbox.reserved.get())
    {
        inner.keepalive.borrow_mut().take();
    }
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;

impl QueueSlot {
    fn original_queue_storage(&self, maximum: usize) -> Result<Option<usize>, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }

        if self.inner.process != std::process::id()
            || self.inner.thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.transferred {
            return Ok(None);
        }
        if !self
            .inner
            .mailboxes
            .iter()
            .any(|mailbox| Rc::ptr_eq(mailbox, &self.mailbox))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        queue_storage(&self.inner, maximum)
    }
}

impl RuntimeCustodyQueue {
    /// Counts the queue observer's compiled counter and overlapping borrow headers.
    ///
    /// This fixed local data window grants no cleanup or allocation authority.
    /// Compiler-generated frames, allocator residency and kernel resources are
    /// outside this requested-storage observation.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn retained_requested_storage_counter_scratch_data() -> Result<usize, RuntimeError> {
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        std::mem::size_of::<RetainedRuntimeCounter>()
            .checked_add(std::mem::size_of::<std::cell::Ref<'_, Option<Waker>>>())
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::Ref<'_, Option<Rc<QueueInner>>>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    std::cell::Ref<'_, Option<WholeRuntimeCustody>>,
                >())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<Result<Option<usize>, RuntimeError>>())
            })
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Reports actual retained queue backing without cleanup or native callbacks.
    ///
    /// # Errors
    /// Refuses foreign creator, conflicting borrow or exhausted requested credit.
    /// Unknown opaque wake/custody backing returns `None`, never zero.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        queue_storage(&self.inner, maximum)
    }
}

fn queue_storage(inner: &Rc<QueueInner>, maximum: usize) -> Result<Option<usize>, RuntimeError> {
    use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
    if inner.process != std::process::id() || inner.thread != std::thread::current().id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    let waker = inner
        .waker
        .try_borrow()
        .map_err(|_| RuntimeError::OutstandingObligations)?;
    if let Some(waker) = waker.as_ref() {
        let (Some(_), Some(expected)) = (&inner.notifier, &inner.original_waker) else {
            return Ok(None);
        };
        if !waker.will_wake(expected) {
            return Ok(None);
        }
    }
    let keepalive = inner
        .keepalive
        .try_borrow()
        .map_err(|_| RuntimeError::OutstandingObligations)?;
    if keepalive
        .as_ref()
        .is_some_and(|held| !Rc::ptr_eq(held, inner))
    {
        return Ok(None);
    }
    for mailbox in &inner.mailboxes {
        if mailbox.polling.get()
            || mailbox
                .custody
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
        {
            return Ok(None);
        }
    }
    let mut counter = RetainedRuntimeCounter::new(maximum);
    counter.rc(inner)?;
    counter.slots(&inner.mailboxes)?;
    for mailbox in &inner.mailboxes {
        counter.rc(mailbox)?;
    }
    if let Some(notifier) = &inner.notifier {
        counter.shared(
            std::sync::Arc::as_ptr(notifier).cast(),
            bounded_wake::notifier_requested(notifier, maximum)?,
        )?;
    }
    Ok(Some(counter.bytes()))
}

/// Borrows one actual Core queue allocation under both original owning handles.
///
/// There is no public constructor, Clone implementation or serialized identity.
/// This local correspondence grants no activation, source or native permission.
pub struct RuntimeCustodyQueueWitness<'a> {
    inner: &'a Rc<QueueInner>,
}

impl RuntimeCustodyQueue {
    /// Authenticates an actual slot against this same original queue allocation.
    ///
    /// # Errors
    /// Refuses foreign creator, generic unknown slots, transferred slots or a
    /// distinct queue, even when all public proposal data are byte-identical.
    pub fn authenticate_original_slot(
        &self,
        slot: &dyn RuntimeCustodySlot,
    ) -> Result<(), RuntimeError> {
        if self.inner.process != std::process::id()
            || self.inner.thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let witness = slot
            .original_runtime_custody_queue()?
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !Rc::ptr_eq(witness.inner, &self.inner) {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Reauthenticate while the slot and actual queue are both still borrowed.
        if witness.inner.process != std::process::id()
            || witness.inner.thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl RuntimeCustodyQueue {
    /// Quotes the requested storage of one original concrete queue reservation.
    ///
    /// This is data for an installed caller's preallocation check. It counts the
    /// actual QueueSlot Box and conservatively uses each retained activation
    /// capacity for its forthcoming derived Clone request. The actual queue,
    /// notifier are conservatively repeated by the forthcoming slot's own data
    /// observer. The original activation and fixed observation bank are separate.
    /// No runtime, activation or reclamation permission follows from this row.
    ///
    /// # Errors
    /// Refuses foreign creator custody, checked overflow or a row above maximum.
    pub fn quote_original_reservation_requested_storage_data(
        &self,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_contract::runtime::RuntimeOwnedStorage;
        if self.inner.process != std::process::id()
            || self.inner.thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let backing = queue_storage(&self.inner, maximum)?.ok_or(RuntimeError::UnsupportedFacet)?;
        let activation_bytes = activation.owned_storage()?;
        std::mem::size_of::<QueueSlot>()
            .checked_add(backing)
            .and_then(|bytes| bytes.checked_add(activation_bytes))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

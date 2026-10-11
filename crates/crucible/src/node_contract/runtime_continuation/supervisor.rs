//! Finite actor-local owning custody slots with authentic bounded reclamation.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    task::{Context, Poll, Waker},
};

use super::*;

struct Mailbox {
    reserved: Cell<bool>,
    polling: Cell<bool>,
    custody: RefCell<Option<WholeRuntimeCustody>>,
}

struct QueueInner {
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
        if maximum_worlds == 0 || maximum_worlds > crucible_node_contract::MAX_ARRAY_ELEMENTS {
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
        let mailbox = self
            .inner
            .mailboxes
            .iter()
            .find(|mailbox| !mailbox.reserved.get())
            .ok_or(RuntimeError::ResourceLimit)?;
        mailbox.reserved.set(true);
        *self.inner.keepalive.borrow_mut() = Some(Rc::clone(&self.inner));
        Ok(Box::new(QueueSlot {
            inner: Rc::clone(&self.inner),
            mailbox: Rc::clone(mailbox),
            activation: activation.clone(),
            limits,
            transferred: false,
        }))
    }
}

struct QueueSlot {
    inner: Rc<QueueInner>,
    mailbox: Rc<Mailbox>,
    activation: ActivationRecord,
    limits: RuntimeLimits,
    transferred: bool,
}

impl RuntimeCustodySlot for QueueSlot {
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

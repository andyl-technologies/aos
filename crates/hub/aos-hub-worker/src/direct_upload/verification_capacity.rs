//! Shares bounded verification object capacity across independently delivered queues.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    task::{Poll, Waker},
};

use anyhow::{ensure, Result};
use aos_hub_db::direct_upload::DirectDependencyPhase;
use serde::{Deserialize, Serialize};

thread_local! {
    static BULK_ACTIVE: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    static METADATA_ACTIVE: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    static OBJECT_ACTIVE: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    static WAITERS: RefCell<Vec<Waiter>> = const { RefCell::new(Vec::new()) };
    static NEXT_WAITER: Cell<u64> = const { Cell::new(0) };
    static LAST_BULK: Cell<Option<bool>> = const { Cell::new(None) };
}

struct Waiter {
    id: u64,
    bulk: bool,
    maximum: u32,
    waker: Waker,
}

fn available(bulk: bool, maximum: u32) -> bool {
    let active = object_observation();
    active.aggregate_active < maximum
        && if bulk {
            active.bulk_active < maximum - 1
        } else {
            active.metadata_active < maximum
        }
}

fn selected_waiter(id: u64, bulk: bool, maximum: u32) -> Option<u64> {
    WAITERS.with(|waiters| {
        waiters
            .borrow()
            .iter()
            .map(|waiter| (waiter.id, waiter.bulk, waiter.maximum))
            .chain(std::iter::once((id, bulk, maximum)))
            .filter(|(_, bulk, maximum)| available(*bulk, *maximum))
            .min_by_key(|(id, bulk, _)| {
                let same_class = LAST_BULK.with(|last| last.get() == Some(*bulk));
                (same_class, *id)
            })
            .map(|(id, _, _)| id)
    })
}

fn wake_waiters() {
    // Wasm waiters must resume in their own queue invocation's I/O context.
    // Their runtime ticks below observe released capacity without foreign wakes.
    #[cfg(not(target_arch = "wasm32"))]
    {
        let wakers = WAITERS.with(|waiters| {
            waiters
                .borrow()
                .iter()
                .map(|waiter| waiter.waker.clone())
                .collect::<Vec<_>>()
        });
        for waker in wakers {
            waker.wake();
        }
    }
}

struct Registration(u64);

impl Drop for Registration {
    fn drop(&mut self) {
        WAITERS.with(|waiters| waiters.borrow_mut().retain(|waiter| waiter.id != self.0));
        wake_waiters();
    }
}

/// Reports actual object occupancy in the current participating isolate.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObjectObservation {
    pub(crate) aggregate_active: u32,
    pub(crate) bulk_active: u32,
    pub(crate) metadata_active: u32,
}

/// Reads the shared and per-class object counters without changing admission.
pub(crate) fn object_observation() -> ObjectObservation {
    ObjectObservation {
        aggregate_active: OBJECT_ACTIVE.with(|n| n.get()),
        bulk_active: BULK_ACTIVE.with(|n| n.get()),
        metadata_active: METADATA_ACTIVE.with(|n| n.get()),
    }
}

/// Holds one actual verification slot until its operation settles.
pub(crate) struct Capacity {
    active: Rc<Cell<u32>>,
    aggregate: Rc<Cell<u32>>,
}

impl Capacity {
    /// Waits for a fair verification slot without retrying the queue delivery.
    ///
    /// # Errors
    /// Returns an error for an invalid capacity or exhausted bounded waiters.
    pub(crate) async fn acquire_waiting(
        phase: DirectDependencyPhase,
        maximum: u32,
    ) -> Result<Self> {
        ensure!(
            maximum >= 2,
            "direct verification requires reserved metadata capacity"
        );
        let bulk = phase == DirectDependencyPhase::Content;
        let id = NEXT_WAITER.with(|next| {
            let id = next
                .get()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("direct verification waiter identity exhausted"))?;
            next.set(id);
            Ok::<_, anyhow::Error>(id)
        })?;
        let _registration = Registration(id);
        let pending = futures_util::future::poll_fn(|context| {
            // Turn ordinary cross-queue contention into a fair local wait.
            // Queue retries consume finite delivery attempts and can strand an
            // original behind a continuing stream of fresh metadata batches.
            if selected_waiter(id, bulk, maximum) == Some(id) {
                return Poll::Ready(Self::acquire(phase, maximum));
            }

            WAITERS.with(|waiters| {
                let mut waiters = waiters.borrow_mut();
                if let Some(waiter) = waiters.iter_mut().find(|waiter| waiter.id == id) {
                    waiter.waker = context.waker().clone();
                } else {
                    if waiters.len() >= 256 {
                        return Poll::Ready(Err(anyhow::anyhow!(
                            "direct verification capacity wait bound reached"
                        )));
                    }
                    waiters.push(Waiter {
                        id,
                        bulk,
                        maximum,
                        waker: context.waker().clone(),
                    });
                }
                Poll::Pending
            })
        });

        #[cfg(not(target_arch = "wasm32"))]
        return pending.await;

        #[cfg(target_arch = "wasm32")]
        super::provider_capacity::poll_with_runtime_ticks(pending, worker::Delay::from).await
    }

    /// Reserves an object slot within both the shared and class limits.
    ///
    /// # Errors
    /// Returns an error when no slot fits or metadata capacity is not reserved.
    pub(crate) fn acquire(phase: DirectDependencyPhase, maximum: u32) -> Result<Self> {
        let active = if phase == DirectDependencyPhase::Content {
            BULK_ACTIVE.with(Rc::clone)
        } else {
            METADATA_ACTIVE.with(Rc::clone)
        };
        ensure!(
            maximum >= 2,
            "direct verification requires reserved metadata capacity"
        );
        let ceiling = if phase == DirectDependencyPhase::Content {
            maximum - 1
        } else {
            maximum
        };
        let aggregate = OBJECT_ACTIVE.with(Rc::clone);
        ensure!(
            active.get() < ceiling && aggregate.get() < maximum,
            "direct verification queue at accepted capacity"
        );
        active.set(active.get() + 1);
        aggregate.set(aggregate.get() + 1);
        LAST_BULK.with(|last| last.set(Some(phase == DirectDependencyPhase::Content)));
        Ok(Self { active, aggregate })
    }
}

impl Drop for Capacity {
    fn drop(&mut self) {
        self.active.set(self.active.get().saturating_sub(1));
        self.aggregate.set(self.aggregate.get().saturating_sub(1));
        wake_waiters();
    }
}

#[cfg(test)]
mod tests;

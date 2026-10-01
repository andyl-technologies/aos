//! Per-isolate admission for mirror part buffers and incremental decoders.
//!
//! A permit spans source consumption and upload settlement, including SDK
//! copies. Provider request permits alone do not bound retained vectors while
//! an upload waits for capacity. Verification shares this admission because
//! its zstd window contributes to the same whole-isolate memory budget.
//! Two separately bounded small metadata producers remain runnable while a
//! bulk verifier holds its window; metadata classification includes decoded size.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::task::{Poll, Waker};

use anyhow::{ensure, Result};

/// Maximum concurrently retained mirror parts or full decoder windows.
pub(crate) const MAXIMUM: usize =
    aos_hub_core::mirror_acceptance::MIRROR_BULK_BUFFERED_PRODUCERS as usize;
const METADATA_MAXIMUM: usize =
    aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFERED_PRODUCERS as usize;
const MAX_WAITERS: usize = 256;

#[derive(Default)]
struct Pool {
    active: usize,
    next: u64,
    waiting: VecDeque<(u64, Waker)>,
}

thread_local! {
    static BULK: Rc<RefCell<Pool>> = Rc::default();
    static METADATA: Rc<RefCell<Pool>> = Rc::default();
    static OBSERVERS: RefCell<Vec<std::rc::Weak<RefCell<Observation>>>> = RefCell::default();
}

pub(crate) struct Permit(Rc<RefCell<Pool>>);

/// Records actual admission peaks during a controlled invocation interval.
#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Observation {
    peak_bulk: usize,
    peak_metadata: usize,
    peak_metadata_while_bulk: usize,
    admissions: u64,
}

pub(crate) struct Interval(Rc<RefCell<Observation>>);

impl Interval {
    pub(crate) fn finish(self) -> Observation {
        let observed = self.0.borrow();
        Observation {
            peak_bulk: observed.peak_bulk,
            peak_metadata: observed.peak_metadata,
            peak_metadata_while_bulk: observed.peak_metadata_while_bulk,
            admissions: observed.admissions,
        }
    }
}

pub(crate) fn observe_interval() -> Interval {
    let observed = Rc::new(RefCell::new(Observation::default()));
    OBSERVERS.with(|observers| {
        let mut observers = observers.borrow_mut();
        observers.retain(|observer| observer.strong_count() > 0);
        observers.push(Rc::downgrade(&observed));
    });
    Interval(observed)
}

fn observe_admission() {
    let bulk = BULK.with(|pool| pool.borrow().active);
    let metadata = METADATA.with(|pool| pool.borrow().active);
    OBSERVERS.with(|observers| {
        observers.borrow_mut().retain(|observer| {
            let Some(observer) = observer.upgrade() else {
                return false;
            };
            let mut observer = observer.borrow_mut();
            observer.peak_bulk = observer.peak_bulk.max(bulk);
            observer.peak_metadata = observer.peak_metadata.max(metadata);
            if bulk > 0 {
                observer.peak_metadata_while_bulk = observer.peak_metadata_while_bulk.max(metadata);
            }
            observer.admissions = observer.admissions.saturating_add(1);
            true
        });
    });
}

impl Drop for Permit {
    fn drop(&mut self) {
        let wake = {
            let mut pool = self.0.borrow_mut();
            pool.active = pool.active.saturating_sub(1);
            pool.waiting.front().map(|(_, waker)| waker.clone())
        };
        wake_in_native_context(wake);
    }
}

struct Waiting {
    pool: Rc<RefCell<Pool>>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let wake = {
            let mut pool = self.pool.borrow_mut();
            pool.waiting.retain(|(id, _)| *id != self.id);
            pool.waiting.front().map(|(_, waker)| waker.clone())
        };
        wake_in_native_context(wake);
    }
}

fn wake_in_native_context(wake: Option<Waker>) {
    // A shared buffer can be released by another Durable Object. Wasm waits
    // use an invocation-owned runtime timer rather than that object's waker.
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(waker) = wake {
        waker.wake();
    }

    #[cfg(target_arch = "wasm32")]
    let _ = wake;
}

/// Acquires bounded buffer ownership and rechecks authority after the wait.
pub(crate) async fn acquire(metadata: bool, check: impl Fn() -> Result<()>) -> Result<Permit> {
    let pool = if metadata {
        METADATA.with(Rc::clone)
    } else {
        BULK.with(Rc::clone)
    };
    let maximum = if metadata { METADATA_MAXIMUM } else { MAXIMUM };
    let id = {
        let mut state = pool.borrow_mut();
        ensure!(
            state.waiting.len() < MAX_WAITERS,
            "mirror buffer wait queue is full"
        );
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("mirror buffer identity exhausted"))?;
        state.next
    };
    let waiting = Waiting {
        pool: Rc::clone(&pool),
        id,
    };
    let pending = futures_util::future::poll_fn(|cx| {
        if let Err(error) = check() {
            return Poll::Ready(Err(error));
        }
        let mut state = pool.borrow_mut();
        if let Some((_, waker)) = state.waiting.iter_mut().find(|(current, _)| *current == id) {
            *waker = cx.waker().clone();
        } else {
            state.waiting.push_back((id, cx.waker().clone()));
        }
        if state.active < maximum
            && state
                .waiting
                .front()
                .is_some_and(|(current, _)| *current == id)
        {
            state.waiting.pop_front();
            state.active += 1;
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    });
    wait_in_origin_context(pending).await?;
    let permit = Permit(pool);
    drop(waiting);
    check()?;
    observe_admission();
    Ok(permit)
}

async fn wait_in_origin_context(
    pending: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    return pending.await;

    #[cfg(target_arch = "wasm32")]
    {
        let mut pending = Box::pin(pending);
        loop {
            let tick = Box::pin(worker::Delay::from(std::time::Duration::from_millis(50)));
            match futures_util::future::select(pending, tick).await {
                futures_util::future::Either::Left((result, _)) => return result,
                futures_util::future::Either::Right((_, next)) => pending = next,
            }
        }
    }
}

#[cfg(test)]
mod tests;

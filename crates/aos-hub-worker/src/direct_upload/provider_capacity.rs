//! Shared bounded native SDK request capacity, including live response streams.
//!
//! A copy reserves both source and destination before starting its GET. This
//! prevents readers from occupying every slot while waiting for upload slots.

use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    task::{Poll, Waker},
};

use anyhow::{ensure, Result};

/// Distinguishes queue read capacity from bounded foreground SDK work.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Foreground,
    Bulk,
    Metadata,
}

impl Class {
    fn index(self) -> usize {
        match self {
            Self::Foreground => 0,
            Self::Bulk => 1,
            Self::Metadata => 2,
        }
    }
}

struct Waiter {
    id: u64,
    class: Class,
    waker: Waker,
}

struct Pool {
    maximum: u32,
    active: Cell<u32>,
    by_class: [Cell<u32>; 3],
    waiters: RefCell<Vec<Waiter>>,
    next_waiter: Cell<u64>,
    peak: Cell<u32>,
    metadata_under_bulk: Cell<u64>,
    dispatches: Cell<u64>,
    interval_peaks: RefCell<Vec<Weak<Cell<u32>>>>,
}

impl Pool {
    fn new(maximum: u32) -> Self {
        Self {
            maximum,
            active: Cell::new(0),
            by_class: std::array::from_fn(|_| Cell::new(0)),
            waiters: RefCell::new(Vec::new()),
            next_waiter: Cell::new(0),
            peak: Cell::new(0),
            metadata_under_bulk: Cell::new(0),
            dispatches: Cell::new(0),
            interval_peaks: RefCell::new(Vec::new()),
        }
    }

    fn wake(&self) {
        // Another Durable Object may release this isolate-wide pool. A Wasm
        // waker would resume its waiter in that object's I/O context. Each
        // Wasm waiter instead owns the runtime timer below; native executors
        // retain ordinary immediate wakeups.
        #[cfg(target_arch = "wasm32")]
        return;

        #[cfg(not(target_arch = "wasm32"))]
        {
            let wakers = self
                .waiters
                .borrow()
                .iter()
                .map(|waiter| waiter.waker.clone())
                .collect::<Vec<_>>();
            for waker in wakers {
                waker.wake();
            }
        }
    }
}

thread_local! {
    static POOL: RefCell<Rc<Pool>> = RefCell::new(Rc::new(Pool::new(2)));
    static ISOLATE: String = uuid::Uuid::new_v4().to_string();
}

/// Actual participating-isolate pool counters, without a global deployment claim.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation {
    pub(crate) isolate_id: String,
    pub(crate) maximum: u32,
    pub(crate) active: u32,
    pub(crate) bulk_active: u32,
    pub(crate) metadata_active: u32,
    pub(crate) peak_active: u32,
    pub(crate) metadata_admissions_during_bulk: u64,
    pub(crate) dispatches: u64,
}

pub(crate) fn observation() -> Observation {
    POOL.with(|current| {
        let pool = current.borrow();
        pool_observation(&pool)
    })
}

fn pool_observation(pool: &Pool) -> Observation {
    Observation {
        isolate_id: ISOLATE.with(Clone::clone),
        maximum: pool.maximum,
        active: pool.active.get(),
        bulk_active: pool.by_class[Class::Bulk.index()].get(),
        metadata_active: pool.by_class[Class::Metadata.index()].get(),
        peak_active: pool.peak.get(),
        metadata_admissions_during_bulk: pool.metadata_under_bulk.get(),
        dispatches: pool.dispatches.get(),
    }
}

/// Measures aggregate provider occupancy during one delivery's actual interval.
pub(crate) struct Interval {
    pool: Rc<Pool>,
    peak: Rc<Cell<u32>>,
}

impl Interval {
    pub(crate) fn finish(self) -> Observation {
        let mut observed = pool_observation(&self.pool);
        observed.peak_active = self.peak.get();
        observed
    }
}

pub(crate) fn observe_interval() -> Result<Interval> {
    let pool = POOL.with(|current| Rc::clone(&current.borrow()));
    let peak = Rc::new(Cell::new(pool.active.get()));
    {
        let mut intervals = pool.interval_peaks.borrow_mut();
        intervals.retain(|interval| interval.strong_count() > 0);
        ensure!(
            intervals.len() < 128,
            "provider observation interval bound reached"
        );
        intervals.push(Rc::downgrade(&peak));
    }
    Ok(Interval { pool, peak })
}

/// Counts actual provider SDK/Fetch invocation attempts before acknowledgement.
pub(crate) fn record_dispatch() {
    POOL.with(|current| {
        let pool = current.borrow();
        pool.dispatches.set(pool.dispatches.get().saturating_add(1));
    });
}

/// Keeps actual provider requests reserved until metadata or streams settle.
pub(crate) struct Permit {
    pool: Rc<Pool>,
    count: u32,
    class: Class,
}

pub(crate) fn configure(maximum: u32) -> Result<()> {
    ensure!(
        (1..=32).contains(&maximum),
        "direct provider capacity invalid"
    );
    POOL.with(|current| {
        let mut current = current.borrow_mut();
        if current.maximum == maximum {
            return Ok(());
        }
        ensure!(
            current.active.get() == 0
                && current.waiters.borrow().is_empty()
                && current
                    .interval_peaks
                    .borrow()
                    .iter()
                    .all(|peak| peak.strong_count() == 0),
            "direct accepted provider capacity changed during work"
        );
        *current = Rc::new(Pool::new(maximum));
        Ok(())
    })
}

pub(crate) async fn acquire(count: u32) -> Result<Permit> {
    acquire_checked(count, &|| Ok(())).await
}

pub(crate) async fn acquire_checked<F: Fn() -> Result<()>>(
    count: u32,
    check: &F,
) -> Result<Permit> {
    acquire_class_checked(count, Class::Foreground, check).await
}

pub(crate) async fn acquire_class(count: u32, class: Class) -> Result<Permit> {
    acquire_class_checked(count, class, &|| Ok(())).await
}

pub(crate) async fn acquire_class_checked<F: Fn() -> Result<()>>(
    count: u32,
    class: Class,
    check: &F,
) -> Result<Permit> {
    let pool = POOL.with(|current| Rc::clone(&current.borrow()));
    let class_limit = match class {
        Class::Foreground => pool.maximum,
        Class::Bulk => pool.maximum.saturating_sub(1),
        // Metadata keeps the reserved slot under bulk load and borrows unused
        // aggregate capacity when the isolate is processing only metadata.
        Class::Metadata => pool.maximum,
    };
    ensure!(
        count > 0 && count <= class_limit,
        "direct provider operation exceeds accepted capacity"
    );
    let id = pool
        .next_waiter
        .get()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("direct provider waiter identity exhausted"))?;
    pool.next_waiter.set(id);
    let _registration = Registration {
        pool: Rc::clone(&pool),
        id,
    };
    let pending = futures_util::future::poll_fn(|context| {
        if let Err(error) = check() {
            return Poll::Ready(Err(error));
        }
        let metadata_waiting = pool
            .waiters
            .borrow()
            .iter()
            .any(|waiter| waiter.class == Class::Metadata && waiter.id != id);
        if pool.active.get() <= pool.maximum - count
            && pool.by_class[class.index()].get() <= class_limit - count
            && !(class == Class::Foreground && metadata_waiting)
        {
            pool.active.set(pool.active.get() + count);
            pool.peak.set(pool.peak.get().max(pool.active.get()));
            for peak in pool
                .interval_peaks
                .borrow()
                .iter()
                .filter_map(Weak::upgrade)
            {
                peak.set(peak.get().max(pool.active.get()));
            }
            if class == Class::Metadata && pool.by_class[Class::Bulk.index()].get() > 0 {
                pool.metadata_under_bulk
                    .set(pool.metadata_under_bulk.get().saturating_add(1));
            }
            let active = &pool.by_class[class.index()];
            active.set(active.get() + count);
            return Poll::Ready(Ok(Permit {
                pool: Rc::clone(&pool),
                count,
                class,
            }));
        }

        let mut waiters = pool.waiters.borrow_mut();
        if let Some(waiter) = waiters.iter_mut().find(|waiter| waiter.id == id) {
            waiter.waker = context.waker().clone();
        } else {
            if waiters.len() >= 256 {
                return Poll::Ready(Err(anyhow::anyhow!(
                    "direct provider capacity wait bound reached"
                )));
            }
            waiters.push(Waiter {
                id,
                class,
                waker: context.waker().clone(),
            });
        }
        Poll::Pending
    });

    #[cfg(not(target_arch = "wasm32"))]
    return pending.await;

    #[cfg(target_arch = "wasm32")]
    {
        let mut pending = Box::pin(pending);
        loop {
            // Runtime I/O keeps a capacity-only waiter alive and checks its
            // original cutoff while an unrelated provider request is pending.
            let tick = Box::pin(worker::Delay::from(std::time::Duration::from_millis(50)));
            match futures_util::future::select(pending, tick).await {
                futures_util::future::Either::Left((result, _)) => return result,
                futures_util::future::Either::Right((_, next)) => pending = next,
            }
        }
    }
}

struct Registration {
    pool: Rc<Pool>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.pool
            .waiters
            .borrow_mut()
            .retain(|waiter| waiter.id != self.id);
        self.pool.wake();
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.pool
            .active
            .set(self.pool.active.get().saturating_sub(self.count));
        let active = &self.pool.by_class[self.class.index()];
        active.set(active.get().saturating_sub(self.count));
        self.pool.wake();
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future as _, task::Context};

    use super::*;

    #[tokio::test]
    async fn metadata_borrows_idle_capacity_without_exceeding_the_same_total() {
        configure(4).unwrap();
        let all_metadata = acquire_class(4, Class::Metadata).await.unwrap();
        let mut excess = Box::pin(acquire_class(1, Class::Metadata));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(excess.as_mut().poll(&mut context).is_pending());
        drop(all_metadata);
        drop(excess.await.unwrap());
        configure(2).unwrap();
    }

    #[tokio::test]
    async fn metadata_has_a_provider_slot_while_bulk_streams_hold_their_permits() {
        configure(3).unwrap();
        let bulk = acquire_class(2, Class::Bulk).await.unwrap();
        let mut excess_bulk = Box::pin(acquire_class(1, Class::Bulk));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(excess_bulk.as_mut().poll(&mut context).is_pending());
        let metadata = acquire_class(1, Class::Metadata).await.unwrap();
        assert!(excess_bulk.as_mut().poll(&mut context).is_pending());
        drop(metadata);
        assert!(excess_bulk.as_mut().poll(&mut context).is_pending());
        drop(bulk);
        drop(excess_bulk.await.unwrap());
        configure(2).unwrap();
    }

    #[tokio::test]
    async fn copy_reserves_source_and_upload_together_and_wakes_after_stream_drop() {
        configure(2).unwrap();
        let reader = acquire(1).await.unwrap();
        let mut copy = Box::pin(acquire(2));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(copy.as_mut().poll(&mut context).is_pending());
        assert!(configure(3).is_err());
        drop(reader);
        let copy = copy.await.unwrap();

        let mut extra = Box::pin(acquire(1));
        assert!(extra.as_mut().poll(&mut context).is_pending());
        drop(copy);
        let reader = extra.await.unwrap();
        drop(reader);
        configure(1).unwrap();
        assert!(acquire(2).await.is_err());
    }

    #[tokio::test]
    async fn delivery_peak_excludes_prior_work_and_includes_actual_overlap() {
        configure(3).unwrap();
        drop(acquire(3).await.unwrap());
        assert_eq!(observation().peak_active, 3);

        let first = observe_interval().unwrap();
        let one = acquire_class(1, Class::Metadata).await.unwrap();
        let second = observe_interval().unwrap();
        let two = acquire_class(1, Class::Metadata).await.unwrap();
        assert!(configure(4).is_err());
        drop(two);
        drop(one);

        assert_eq!(first.finish().peak_active, 2);
        assert_eq!(second.finish().peak_active, 2);
        assert_eq!(observe_interval().unwrap().finish().peak_active, 0);
        configure(2).unwrap();
    }
}

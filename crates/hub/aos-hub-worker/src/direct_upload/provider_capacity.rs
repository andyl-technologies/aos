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

/// One-use transfers of actual reserved source capacity within the same pool.
pub(crate) mod transfer;

/// Source-bound common capacity shared by independently authenticated roles.
pub(crate) mod policy;

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
    count: u32,
    waker: Rc<RefCell<Option<Waker>>>,
}

struct Pool {
    generation: String,
    maximum: u32,
    active: Cell<u32>,
    by_class: [Cell<u32>; 3],
    waiters: RefCell<Vec<Waiter>>,
    next_waiter: Cell<u64>,
    last_class: Cell<Option<usize>>,
    // The outer None invalidates the cache; an inner None means no waiter fits.
    selected: Cell<Option<Option<(u64, Class)>>>,
    peak: Cell<u32>,
    metadata_under_bulk: Cell<u64>,
    dispatches: Cell<u64>,
    interval_peaks: RefCell<Vec<Weak<Cell<u32>>>>,
}

impl Pool {
    fn new(maximum: u32) -> Self {
        Self {
            generation: uuid::Uuid::new_v4().to_string(),
            maximum,
            active: Cell::new(0),
            by_class: std::array::from_fn(|_| Cell::new(0)),
            waiters: RefCell::new(Vec::new()),
            next_waiter: Cell::new(0),
            last_class: Cell::new(None),
            selected: Cell::new(None),
            peak: Cell::new(0),
            metadata_under_bulk: Cell::new(0),
            dispatches: Cell::new(0),
            interval_peaks: RefCell::new(Vec::new()),
        }
    }

    fn class_limit(&self, class: Class) -> u32 {
        match class {
            Class::Bulk => self.maximum.saturating_sub(1),
            Class::Foreground | Class::Metadata => self.maximum,
        }
    }

    fn available(&self, class: Class) -> u32 {
        let aggregate = self.maximum.saturating_sub(self.active.get());
        let class = self
            .class_limit(class)
            .saturating_sub(self.by_class[class.index()].get());
        aggregate.min(class)
    }

    fn selected_waiter(&self, id: u64, class: Class, count: u32) -> Option<u64> {
        let priority = |id, class: Class| {
            let class_turn = self
                .last_class
                .get()
                .map_or(0, |last| (class.index() + 3 - last - 1) % 3);
            (class_turn, id)
        };
        // Every waiting invocation polls in its own runtime context. Occupancy,
        // class turn and membership change much less often than those polls;
        // retain their selection until one of those inputs changes.
        let selected = match self.selected.get() {
            Some(selected) => selected,
            None => {
                let selected = self
                    .waiters
                    .borrow()
                    .iter()
                    .filter(|waiter| self.available(waiter.class) >= waiter.count)
                    .min_by_key(|waiter| priority(waiter.id, waiter.class))
                    .map(|waiter| (waiter.id, waiter.class));
                self.selected.set(Some(selected));
                selected
            }
        };
        selected
            .into_iter()
            .chain((self.available(class) >= count).then_some((id, class)))
            .min_by_key(|(id, class)| priority(*id, *class))
            .map(|(id, _)| id)
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
                .filter_map(|waiter| waiter.waker.borrow().clone())
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
    // Bulk cannot consume the final slot. Metadata and short foreground work
    // share the remaining capacity without an unbounded class priority.
    let class_limit = pool.class_limit(class);
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
    let waker = Rc::new(RefCell::new(None::<Waker>));
    let registered = Cell::new(false);
    let pending = futures_util::future::poll_fn(|context| {
        if let Err(error) = check() {
            return Poll::Ready(Err(error));
        }
        // Rotate between eligible classes, then preserve FIFO within each one.
        // A large foreground fanout must not multiply each metadata delivery's
        // wait by the number of upload tasks. Skip requests that cannot fit so
        // a bulk pair cannot block the reserved single slot.
        if pool.selected_waiter(id, class, count) == Some(id) {
            pool.last_class.set(Some(class.index()));
            pool.selected.set(None);
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

        if !waker
            .borrow()
            .as_ref()
            .is_some_and(|waker| waker.will_wake(context.waker()))
        {
            *waker.borrow_mut() = Some(context.waker().clone());
        }
        if !registered.get() {
            let mut waiters = pool.waiters.borrow_mut();
            if waiters.len() >= 256 {
                return Poll::Ready(Err(anyhow::anyhow!(
                    "direct provider capacity wait bound reached"
                )));
            }
            waiters.push(Waiter {
                id,
                class,
                count,
                waker: Rc::clone(&waker),
            });
            registered.set(true);
            pool.selected.set(None);
        }
        Poll::Pending
    });

    #[cfg(not(target_arch = "wasm32"))]
    return pending.await;

    #[cfg(target_arch = "wasm32")]
    {
        let phase = match class {
            Class::Foreground => super::observation::TimingPhase::ProviderForegroundCapacity,
            Class::Bulk => super::observation::TimingPhase::ProviderBulkCapacity,
            Class::Metadata => super::observation::TimingPhase::ProviderMetadataCapacity,
        };
        super::observation::timed(phase, poll_with_runtime_ticks(pending, worker::Delay::from))
            .await
    }
}

#[cfg(any(target_arch = "wasm32", test))]
/// Re-polls pending work in its runtime context when a foreign wakeup is missed.
pub(crate) async fn poll_with_runtime_ticks<F, T>(
    pending: F,
    mut tick: impl FnMut(std::time::Duration) -> T,
) -> F::Output
where
    F: std::future::Future,
    T: std::future::Future<Output = ()>,
{
    let mut pending = Box::pin(pending);
    loop {
        // Runtime I/O keeps the wait in its original context. A missed foreign
        // wakeup must not leave capacity idle or an already completed response
        // holding its provider slot for tens of milliseconds.
        let timer = Box::pin(tick(std::time::Duration::from_millis(5)));
        match futures_util::future::select(pending, timer).await {
            futures_util::future::Either::Left((result, _)) => return result,
            futures_util::future::Either::Right((_, next)) => pending = next,
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
        self.pool.selected.set(None);
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
        self.pool.selected.set(None);
        self.pool.wake();
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future as _, task::Context};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn runtime_tick_reuses_released_capacity_without_a_foreign_context_wakeup() {
        use std::time::Duration;

        configure(3).unwrap();
        let occupied = acquire_class(3, Class::Foreground).await.unwrap();
        let mut acquisition = Box::pin(acquire_class(1, Class::Metadata));
        let without_foreign_wakeup = futures_util::future::poll_fn(|_| {
            let waker = futures_util::task::noop_waker();
            acquisition.as_mut().poll(&mut Context::from_waker(&waker))
        });
        let waiting = poll_with_runtime_ticks(without_foreign_wakeup, tokio::time::sleep);
        let release = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            drop(occupied);
        };

        // Only the waiter's own timer can resume it after the foreign release.
        // A short metadata operation should not lose its remaining request
        // window while the entire provider pool is already idle.
        let (permit, ()) = tokio::select! {
            biased;
            _ = tokio::time::sleep(Duration::from_millis(25)) => {
                panic!("idle capacity was not reused within the metadata request window");
            }
            result = futures_util::future::join(waiting, release) => result,
        };
        let permit = permit.unwrap();

        assert_eq!(observation().active, 1);
        assert_eq!(observation().peak_active, 3);
        drop(permit);
        assert_eq!(observation().active, 0);
        configure(2).unwrap();
    }

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
    async fn new_metadata_cannot_bypass_a_queued_stage_creation() {
        configure(3).unwrap();
        let occupied = acquire_class(3, Class::Metadata).await.unwrap();
        let mut creation = Box::pin(acquire_class(1, Class::Foreground));
        let mut metadata = Box::pin(acquire_class(1, Class::Metadata));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(creation.as_mut().poll(&mut context).is_pending());
        assert!(metadata.as_mut().poll(&mut context).is_pending());
        drop(occupied);

        assert!(metadata.as_mut().poll(&mut context).is_pending());
        let creation = creation.await.unwrap();
        let metadata = metadata.await.unwrap();
        assert_eq!(observation().active, 2);

        drop(metadata);
        drop(creation);
        configure(2).unwrap();
    }

    #[tokio::test]
    async fn metadata_keeps_its_place_ahead_of_new_foreground_work() {
        configure(3).unwrap();
        let occupied = acquire_class(3, Class::Foreground).await.unwrap();
        let mut metadata = Box::pin(acquire_class(1, Class::Metadata));
        let mut creation = Box::pin(acquire_class(1, Class::Foreground));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(metadata.as_mut().poll(&mut context).is_pending());
        assert!(creation.as_mut().poll(&mut context).is_pending());
        drop(occupied);

        assert!(creation.as_mut().poll(&mut context).is_pending());
        let metadata = metadata.await.unwrap();
        let creation = creation.await.unwrap();
        assert_eq!(observation().active, 2);

        drop(creation);
        drop(metadata);
        configure(2).unwrap();
    }

    #[tokio::test]
    async fn metadata_progress_is_bounded_under_a_foreground_fanout() {
        configure(3).unwrap();
        let occupied = acquire_class(3, Class::Foreground).await.unwrap();
        let mut foreground = (0..64)
            .map(|_| Box::pin(acquire_class(1, Class::Foreground)))
            .collect::<Vec<_>>();
        let mut metadata = Box::pin(acquire_class(1, Class::Metadata));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        for request in &mut foreground {
            assert!(request.as_mut().poll(&mut context).is_pending());
        }
        assert!(metadata.as_mut().poll(&mut context).is_pending());
        drop(occupied);

        // A queue consumer must receive a turn without waiting for all 64
        // independently admitted foreground uploads to cross the provider.
        let metadata = match metadata.as_mut().poll(&mut context) {
            Poll::Ready(Ok(permit)) => permit,
            _ => panic!("foreground fanout delayed the metadata class"),
        };
        assert_eq!(observation().active, 1);

        drop(metadata);
        drop(foreground);
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

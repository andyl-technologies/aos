//! Shares one actual admitted reactor and readonly connection across fixed reads.
//!
//! Each caller still retains its own query, comparison and independent posts.
//! This mechanical owner supplies no C/B admission, role or payment. Native
//! failure never replaces the connection or disposes its original raw prefix.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use super::{ControllerPropertyObserverAttemptV1 as Observer, FixedPid1PropertyValuesV1};
use crate::client::{ReadonlyPropertyManagerOriginalV2, ReadonlyPropertyReceiveScheduleV2};
use crate::{Error, Result};

/// Retains the actual Runtime and one bounded readonly manager as mechanics.
///
/// A genuine enclosing owner admits and pays this storage before construction.
/// The supplied Runtime must be its actual retained reactor. This type creates
/// no Runtime, scheduling permission, connection replacement or financial scope.
#[must_use = "retain this same reactor and native manager through every owed post"]
pub struct SharedFixedPid1PropertyProviderV1 {
    pub(super) runtime: Arc<tokio::runtime::Runtime>,
    initial: Mutex<Option<ReadonlyPropertyManagerOriginalV2>>,
    completed: OnceLock<ReadonlyPropertyManagerOriginalV2>,
    next_query: AtomicUsize,
    first_native_query: AtomicUsize,
    interval_started: AtomicBool,
    preserve_interval: AtomicBool,
    retirement_failure: OnceLock<Error>,
}

impl SharedFixedPid1PropertyProviderV1 {
    /// Constructs inert bounded receiver storage using the actual held reactor.
    ///
    /// No native connection, worker or IO starts here. The caller separately
    /// pays the maximum failed window and each reached cumulative wire extent.
    ///
    /// # Errors
    /// Refuses empty or overflowing finite query/materialization bounds.
    pub fn new(
        runtime: Arc<tokio::runtime::Runtime>,
        maximum_window_queries: usize,
        materialization_bytes: usize,
    ) -> Result<Self> {
        let total = materialization_bytes
            .checked_mul(maximum_window_queries)
            .ok_or_else(closed)?;
        let schedule = Self::schedule(maximum_window_queries, materialization_bytes, total)?;
        Ok(Self {
            runtime,
            initial: Mutex::new(Some(ReadonlyPropertyManagerOriginalV2::new(schedule))),
            completed: OnceLock::new(),
            next_query: AtomicUsize::new(0),
            first_native_query: AtomicUsize::new(usize::MAX),
            interval_started: AtomicBool::new(false),
            preserve_interval: AtomicBool::new(false),
            retirement_failure: OnceLock::new(),
        })
    }

    fn schedule(
        queries: usize,
        per_query: usize,
        total: usize,
    ) -> Result<ReadonlyPropertyReceiveScheduleV2> {
        if queries == 0 || per_query == 0 {
            return Err(closed());
        }

        let outgoing = Observer::OUTGOING_MESSAGES
            .checked_mul(queries)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(closed)?;
        let incoming = outgoing.checked_add(2).ok_or_else(closed)?;
        ReadonlyPropertyReceiveScheduleV2::new(
            outgoing,
            incoming,
            Observer::MESSAGE_BYTES,
            Observer::MESSAGE_BYTES,
            total,
        )
        .map_err(Error::Zbus)
    }

    /// Reports the actual shared manager and retained failed-window byte peak.
    ///
    /// Runtime/driver storage is already held and paid by the actual parent.
    /// Per-query decoder/carrier/worker peaks remain separately charged by the
    /// existing row supplier; no credit is taken for their conservative bytes.
    #[must_use]
    pub fn receiving_footprint_v1(queries: usize, per_query: usize) -> Option<(usize, usize)> {
        let total = per_query.checked_mul(queries)?;
        let schedule = Self::schedule(queries, per_query, total).ok()?;
        let bytes = ReadonlyPropertyManagerOriginalV2::receiving_memory_bytes_v2(schedule)?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(2 * std::mem::size_of::<usize>())?;
        Some((bytes, schedule.maximum_native_files_v2()))
    }

    pub(super) fn query_ordinal(&self) -> Result<usize> {
        self.next_query
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
            .map_err(|_| closed())
    }

    async fn connect_first_once(&self) -> Result<()> {
        if let Some(manager) = self.completed.get() {
            return if manager.client_v2().is_some() {
                Ok(())
            } else {
                Err(closed())
            };
        }
        // The actual caller holds the serial joined-worker slot. Keeping this
        // original in its mutex before await also retains it through unwind;
        // after completion the same whole owner moves to stable borrowed storage.
        let mut initial = self.initial.lock().map_err(|_| closed())?;
        let manager = initial.as_mut().ok_or_else(closed)?;
        let result = manager.connect_once().await;
        let manager = initial.take().ok_or_else(closed)?;
        if let Err(manager) = self.completed.set(manager) {
            *initial = Some(manager);
            return Err(closed());
        }
        result
    }

    pub(super) async fn read(
        &self,
        ordinal: usize,
        unit: &'static str,
        pid: u32,
        service: &'static [&'static str],
        properties: &'static [&'static str],
    ) -> Result<FixedPid1PropertyValuesV1> {
        let result = async {
            self.connect_first_once().await?;
            let manager = self.completed.get().ok_or_else(closed)?;
            let mut cancellation = manager.cancellation_fence_v1();
            if !self.interval_started.load(Ordering::Acquire) {
                manager.begin_readonly_interval_v2()?;
                self.interval_started.store(true, Ordering::Release);
            }
            // The entire finite failed window was prepaid before the first
            // native read. One query may consume more of that shared byte lane;
            // the shared supplier includes ALL window decoding, beside the
            // separately retained row carriers. Per-message wire bounds stay
            // unchanged and cumulative traffic is never retired or refunded.
            let client = manager.client_v2().ok_or_else(closed)?;
            let (service, unit) = client
                .observe_pid1_service_startup_properties(unit, pid, service, properties)
                .await?;
            cancellation.complete();
            Ok((Arc::new(service), Arc::new(unit)))
        }
        .await;

        if result.is_err() {
            self.mark_failed_query(ordinal);
        }
        result
    }

    pub(super) fn mark_failed_query(&self, ordinal: usize) {
        let _ = self.first_native_query.compare_exchange(
            usize::MAX, ordinal, Ordering::AcqRel, Ordering::Acquire,
        );
        self.preserve_interval.store(true, Ordering::Release);
        if let Some(manager) = self.completed.get() {
            manager.end_retaining_v1();
        }
    }

    /// Preserves a failed enclosing comparison's whole raw interval permanently.
    ///
    /// This one-way negative disposition grants no retry, readiness or native
    /// operation. Independently owed queries still use the same connection.
    pub fn preserve_failed_interval_v1(&self) {
        self.preserve_interval.store(true, Ordering::Release);
    }

    /// Disposes only the actual completed positive interval on the same manager.
    ///
    /// The genuine caller enters after the complete typed comparison and all
    /// independent posts. No connection, Runtime or message serial is replaced.
    ///
    /// # Errors
    /// Retains a failed, incomplete, borrowed or nonquiescent native interval.
    pub fn retire_completed_interval_v1(&self) -> Result<()> {
        if self.preserve_interval.load(Ordering::Acquire)
            || !self.interval_started.load(Ordering::Acquire)
        {
            return Err(closed());
        }

        let manager = self.completed.get().ok_or_else(closed)?;
        match manager.retire_readonly_interval_v2() {
            Ok(()) => {
                self.interval_started.store(false, Ordering::Release);
                Ok(())
            }
            Err(cause) => {
                // No earlier failed retirement can reach this native call:
                // the permanent negative fence is checked before entry.
                let _ = self.retirement_failure.set(cause);
                self.preserve_interval.store(true, Ordering::Release);
                Err(closed())
            }
        }
    }

    /// Borrows the actual first native positive-disposition refusal.
    ///
    /// This observes no IO, grants no retry and leaves the raw manager owned.
    #[must_use]
    pub fn retirement_failure_v1(&self) -> Option<&Error> {
        self.retirement_failure.get()
    }

    pub(super) fn failure_is_query(&self, ordinal: usize) -> bool {
        self.first_native_query.load(Ordering::Acquire) == ordinal
    }

    pub(super) fn completed_manager(&self) -> Option<&ReadonlyPropertyManagerOriginalV2> {
        self.completed.get()
    }

    pub(super) fn initial_failure_guard(
        &self,
    ) -> Option<MutexGuard<'_, Option<ReadonlyPropertyManagerOriginalV2>>> {
        if self.completed.get().is_some() {
            return None;
        }

        Some(match self.initial.lock() {
            Ok(original) => original,
            Err(poisoned) => poisoned.into_inner(),
        })
    }
}

fn closed() -> Error {
    Error::Zbus(zbus::Error::InvalidReply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn the_actual_held_reactor_is_driven_from_the_joined_worker_thread() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (mut receiving, sending) =
            runtime.block_on(async { tokio::net::UnixStream::pair().unwrap() });
        let mut sending = sending.into_std().unwrap();
        let worker_runtime = Arc::clone(&runtime);

        let worker = std::thread::spawn(move || {
            worker_runtime.block_on(async {
                let mut received = [0; 4];
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    receiving.read_exact(&mut received),
                )
                .await
                .unwrap()
                .unwrap();
                received
            })
        });
        sending.write_all(b"same").unwrap();
        let received = worker.join().unwrap();

        assert_eq!(&received, b"same");
        assert_eq!(Arc::strong_count(&runtime), 1);

        // There is no fresh Runtime or detached worker. The original remains
        // usable after its driver core returns from the actual worker's call.
        assert_eq!(runtime.block_on(async { 7 }), 7);
    }
}

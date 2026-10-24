//! Shared finite PID1 readonly workers, without role or financial authority.
//!
//! A caller prepays and retains this archive through its independent semantic
//! posts. Ordinary rows own their bounded transport and current-thread Runtime.
//! Selected shared rows borrow one actual retained Runtime/readonly manager;
//! each row still owns its timeout, native Result, joined worker and panic.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use super::{ControllerPropertyObserverAttemptV1, SystemdClient};
use zbus::zvariant::OwnedValue;

mod shared;
pub use shared::SharedFixedPid1PropertyProviderV1;

/// Reports a mechanically unavailable or unfinished finite readonly flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FixedPid1PropertyErrorV1 {
    /// The actual owner is closed, incomplete, failed, poisoned or out of rows.
    #[error("fixed PID1 property flight is closed")]
    Closed,
}

/// Preserves the original bounded archive allocation error for its caller.
#[derive(Debug, thiserror::Error)]
pub enum FixedPid1PropertyGrowthErrorV1 {
    /// The finite archive cannot enter the requested growth transition.
    #[error("fixed PID1 property archive growth is closed")]
    Closed,
    /// The actual row backing allocation failed.
    #[error("fixed PID1 property archive allocation failed: {0}")]
    Allocation(#[source] std::collections::TryReserveError),
}

/// Retains the whole timeout and returned native operation Result.
pub type FixedPid1PropertyActionOutcomeV1 = Result<
    Result<(), crate::Error>, tokio::time::error::Elapsed,
>;

/// Shares the actual immutable property DATA retained by its native attempt.
pub type FixedPid1PropertyValuesV1 = (Arc<Vec<OwnedValue>>, Arc<Vec<OwnedValue>>);

/// Reports passive receiving geometry, without admission or a payer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedPid1PropertyGeometryV1 {
    /// Logical resident/transient memory carrier extent, excluding exact allocator census.
    pub memory_bytes: u64,
    /// Fixed control and dynamic property carrier cell bound.
    pub metadata_entries: u64,
    /// Conservative native descriptor bound for one reached row.
    pub open_files: u64,
    /// Actual one-row worker thread count, supplied as DATA rather than payment.
    pub worker_threads: u64,
    /// Aggregate bounded AUTH plus incoming/outgoing wire extent.
    pub wire_io_bytes: u64,
    /// Maximum retained per-message diagnostic byte extent.
    pub maximum_log_bytes: u64,
}

// The process has one dedicated bounded observer task lane. This mutex
// schedules actual worker lifetime only; it carries no role, payment or
// semantic/currentness result.
static FIXED_PID1_PROPERTY_WORKER_SLOT: Mutex<()> = Mutex::new(());

/// Holds the process's single dedicated PID1 worker scheduling slot.
///
/// Acquisition waits for the preceding actual worker to join. A caller with
/// an absolute deadline checks that same deadline after acquisition and before
/// calling [`FixedPid1PropertyArchiveV1::read_under_slot`]. Holding this slot
/// neither admits IO nor establishes semantic or currentness success.
///
/// The slot stays on its acquiring thread. A poisoned scheduling lock remains
/// retained as its original Result; it is not a failed native observation or a
/// reason to grant or deny a role. The previous worker is joined before its
/// slot can be released, including when its caller unwinds.
#[must_use]
pub struct FixedPid1PropertyWorkerSlotV1 {
    _held: std::sync::LockResult<MutexGuard<'static, ()>>,
}

impl FixedPid1PropertyWorkerSlotV1 {
    /// Waits for exclusive physical scheduling of one dedicated PID1 worker.
    #[must_use]
    pub fn acquire() -> Self {
        Self { _held: FIXED_PID1_PROPERTY_WORKER_SLOT.lock() }
    }
}

#[derive(Clone, Copy)]
enum FixedPropertyReadRecipeV1 { Startup, Ownership { cutoff: u64 } }

struct FixedPid1PropertyOriginalV1 {
    attempt: Option<super::ControllerPropertyObserverAttemptV1>,
    runtime: Option<Result<tokio::runtime::Runtime, std::io::Error>>,
    operation: Option<FixedPid1PropertyActionOutcomeV1>,
    action: Option<Result<(), FixedPid1PropertyErrorV1>>,
    native_completion: Option<Result<(), FixedPid1PropertyErrorV1>>,
    shared_values: Option<FixedPid1PropertyValuesV1>,
    shared_ordinal: Option<usize>,
    shared_entry_clock: Option<rustix::time::Timespec>,
    ownership_exit_clock: Option<rustix::time::Timespec>,
    ownership_deadline: Option<Result<(), crate::Error>>,
}

impl FixedPid1PropertyOriginalV1 {
    fn completed_values(&self) -> Option<&FixedPid1PropertyValuesV1> {
        self.shared_values.as_ref().or_else(|| self.attempt.as_ref()?.property_result()?.as_ref().ok())
    }

    // This closes only this row's completed native IO phase, not its enclosing
    // semantic/currentness scope. Retire the execution Runtime on its OWN
    // fixed worker, after block_on returns; dropping it in an async caller
    // would panic. Only after that and all alias disposal can the completed
    // native socket close; raw/property/native Result originals stay resident.
    fn finish_native_runtime_once(&mut self) -> Result<(), FixedPid1PropertyErrorV1> {
        if self.native_completion.is_some() {
            return Err(FixedPid1PropertyErrorV1::Closed);
        }
        self.native_completion = Some((|| {
            let attempt = self.attempt.as_mut().ok_or(FixedPid1PropertyErrorV1::Closed)?;
            if !matches!(self.action, Some(Ok(())))
                || !matches!(attempt.property_result(), Some(Ok(_)))
                || !matches!(self.runtime, Some(Ok(_)))
            {
                return Err(FixedPid1PropertyErrorV1::Closed);
            }
            attempt.end();
            let (connected, rejected) = attempt.shutdown_outcomes();
            if !matches!(connected, Some(Ok(()))) || rejected.is_some()
                || !attempt.transport_ended_cleanly_v1()
            {
                return Err(FixedPid1PropertyErrorV1::Closed);
            }
            // Ended is a one-way fence and its whole shutdown outcomes are
            // retained. No future read can use this closed native connection.
            // Arc tables, raw frames and native/error outcomes stay resident.
            // Runtime destruction cancels its actual remaining task aliases;
            // the lower native check also requires unique custody/socket Arcs.
            drop(self.runtime.take());
            attempt.retire_positive_native_socket_once_v1()
                .map_err(|_| FixedPid1PropertyErrorV1::Closed)?;
            Ok(())
        })());
        if matches!(self.native_completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedPid1PropertyErrorV1::Closed)
        }
    }
}

// A thread panic payload is Send but need not be Sync. Keep the exact
// returned box behind its own Mutex rather than weakening the shared Root
// error/source contract or replacing the original payload with a marker.
/// Retains the exact possibly non-Sync thread panic box behind its own Mutex.
pub type FixedPid1PropertyJoinOutcomeV1 = Result<
    (),
    std::sync::Mutex<Box<dyn std::any::Any + Send + 'static>>,
>;

fn retain_join_v1(joined: std::thread::Result<()>) -> FixedPid1PropertyJoinOutcomeV1 {
    joined.map_err(std::sync::Mutex::new)
}

struct FixedPid1PropertyEntryV1 {
    original: std::sync::Arc<std::sync::Mutex<FixedPid1PropertyOriginalV1>>,
    spawn: Option<std::io::Result<Option<std::thread::JoinHandle<()>>>>,
    joined: Option<FixedPid1PropertyJoinOutcomeV1>,
}

// Install this before spawn. Its Drop joins the actual handle and retains
// the complete join/panic Result while the borrowed scheduling slot is still
// held. Unwinding cannot detach a worker and lend its live task slot onward.
struct FixedPid1PropertyWorkerJoinV1<'entry> {
    entry: &'entry mut FixedPid1PropertyEntryV1,
    _slot: &'entry mut FixedPid1PropertyWorkerSlotV1,
}

impl FixedPid1PropertyWorkerJoinV1<'_> {
    fn join_once(&mut self) {
        match self.entry.spawn.take() {
            Some(Ok(Some(worker))) => {
                self.entry.joined = Some(retain_join_v1(worker.join()));
                self.entry.spawn = Some(Ok(None));
            }
            Some(Ok(None)) => self.entry.spawn = Some(Ok(None)),
            Some(Err(error)) => self.entry.spawn = Some(Err(error)),
            None => {}
        }
    }
}

impl Drop for FixedPid1PropertyWorkerJoinV1<'_> {
    fn drop(&mut self) {
        self.join_once();
    }
}

/// Owns finite readonly PID1 flights and every reached native worker outcome.
///
/// This is passive receiving storage, not a role, payer, interval or authority.
/// Its caller funds all actual rows/geometry before construction or growth.
pub struct FixedPid1PropertyArchiveV1 {
    entries: Vec<FixedPid1PropertyEntryV1>,
    maximum: usize,
    materialization_limit: usize,
    settlement: Option<Result<(), FixedPid1PropertyErrorV1>>,
    growth_closed: bool,
    preparation: Option<Result<(), std::collections::TryReserveError>>,
    preparation_complete: Option<Result<(), FixedPid1PropertyErrorV1>>,
    shared: Option<Arc<SharedFixedPid1PropertyProviderV1>>,
    shared_entry_cutoff: Option<u64>,
}

impl FixedPid1PropertyArchiveV1 {
    /// Returns the existing decoder materialization ceiling as byte DATA.
    ///
    /// This does not admit an observation, fund a worker or change the limit.
    #[doc(hidden)]
    #[must_use]
    pub const fn materialization_limit_v1(&self) -> usize {
        self.materialization_limit
    }

    // The caller must hold its distinct genuine interval and prepay the same
    // materialized-byte demand. A smaller decoder ceiling restricts DATA; it
    // cannot pay for an archive or reconstruct a lifetime from a scalar.
    /// Constructs empty receiving DATA without reserving rows or creating IO.
    ///
    /// All actual allocations/worker/decoder work require caller admission first.
    #[must_use]
    pub fn with_materialization_limit(
        maximum: usize,
        materialization_limit: usize,
    ) -> Self {
        Self {
            entries: Vec::new(),
            maximum,
            materialization_limit,
            settlement: None,
            growth_closed: false,
            preparation: None,
            preparation_complete: None,
            shared: None,
            shared_entry_cutoff: None,
        }
    }

    /// Creates finite query destinations on the same externally held provider.
    ///
    /// The provider owns its real Runtime and native connection continuously.
    /// The enclosing genuine purpose prepays all row and shared-window storage;
    /// constructing this archive grants no role, funding or IO permission.
    #[must_use]
    pub fn with_shared_provider_v1(
        maximum: usize,
        materialization_limit: usize,
        provider: Arc<SharedFixedPid1PropertyProviderV1>,
    ) -> Self {
        let mut archive = Self::with_materialization_limit(maximum, materialization_limit);
        archive.shared = Some(provider);
        archive
    }

    /// Restricts a shared worker to the caller's unchanged absolute BOOTTIME cutoff.
    ///
    /// This mechanical DATA can only stop entry. It grants no role or IO and
    /// never replaces an absolute cutoff with a fresh relative duration. The
    /// actual joined worker samples after entering the held Runtime, before
    /// connecting or reading. Ordinary archives preserve their original route.
    ///
    /// # Errors
    /// Refuses invalid, late or increasing restrictions on a shared archive.
    pub fn restrict_shared_entry_boottime_v1(&mut self, cutoff: u64)
        -> Result<(), FixedPid1PropertyErrorV1>
    {
        if self.shared.is_none() { return Ok(()); }
        if cutoff == 0 || cutoff == u64::MAX || !self.entries.is_empty()
            || self.settlement.is_some()
            || self.shared_entry_cutoff.is_some_and(|old| cutoff > old)
        { return Err(FixedPid1PropertyErrorV1::Closed); }
        self.shared_entry_cutoff = Some(cutoff);
        Ok(())
    }

    /// Preserves a failed enclosing comparison's shared raw/native interval.
    ///
    /// This argument-free negative fence grants no replacement or retry.
    pub fn preserve_shared_interval_failure_v1(&self) {
        if let Some(provider) = &self.shared { provider.preserve_failed_interval_v1(); }
    }

    // Preparation reserves DATA only. Caller-owned purposes keep their own
    // admission and cannot obtain one from this mechanical allocation Result.
    /// Reserves exactly this finite archive's row slots once.
    ///
    /// # Errors
    /// Retains the original allocation error and rejects invalid or repeated entry.
    pub fn prepare_once(&mut self) -> Result<(), FixedPid1PropertyErrorV1> {
        if self.preparation_complete.is_some() {
            return Err(FixedPid1PropertyErrorV1::Closed);
        }
        self.preparation_complete = Some((|| {
            use super::ControllerPropertyObserverAttemptV1 as Observer;

            if self.preparation.is_some()
                || self.maximum == 0
                || self.materialization_limit > Observer::MESSAGE_BYTES * Observer::INCOMING_MESSAGES
            {
                return Err(FixedPid1PropertyErrorV1::Closed);
            }
            self.preparation = Some(self.entries.try_reserve_exact(self.maximum));
            if !matches!(self.preparation, Some(Ok(()))) || self.entries.capacity() > self.maximum {
                return Err(FixedPid1PropertyErrorV1::Closed);
            }
            Ok(())
        })());
        if matches!(self.preparation_complete, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedPid1PropertyErrorV1::Closed)
        }
    }

    // The caller retains its real admission and the returned allocation error.
    // This mechanism cannot decide which role or account paid for the growth.
    /// Grows finite row DATA after the caller's independent payment checks.
    ///
    /// # Errors
    /// Moves the original allocation error to the caller and closes failed growth.
    pub fn grow_rows(
        &mut self,
        maximum: usize,
    ) -> Result<(), FixedPid1PropertyGrowthErrorV1> {
        use FixedPid1PropertyGrowthErrorV1 as E;

        if self.growth_closed || self.settlement.is_some()
            || !matches!(self.preparation_complete, Some(Ok(())))
            || !matches!(self.preparation, Some(Ok(()))) || maximum <= self.maximum
        {
            return Err(E::Closed);
        }
        self.growth_closed = true;
        let additional = maximum.checked_sub(self.entries.len()).ok_or(E::Closed)?;
        self.entries.try_reserve_exact(additional).map_err(E::Allocation)?;
        if self.entries.capacity() > maximum { return Err(E::Closed); }
        self.maximum = maximum;
        self.growth_closed = false;
        Ok(())
    }

    // This settles only an actually successful finite observation reservoir.
    // The original attempt retains each one-shot native shutdown Result; a
    // failed or ambiguous outcome permanently prevents positive peak reuse.
    // Calling Drop first would perform an unobserved end and lose that debt.
    /// Checks complete joined/native-ended rows without authorizing semantic success.
    ///
    /// # Errors
    /// Rejects partial, failed, poisoned or already settled original storage.
    pub fn settle_positive_once(&mut self) -> Result<(), FixedPid1PropertyErrorV1> {
        if self.settlement.is_some() {
            return Err(FixedPid1PropertyErrorV1::Closed);
        }
        self.settlement = Some((|| {
            if self.growth_closed || !matches!(self.preparation_complete, Some(Ok(())))
                || !matches!(self.preparation, Some(Ok(()))) || self.entries.is_empty() {
                return Err(FixedPid1PropertyErrorV1::Closed);
            }
            let mut positive = true;
            for entry in &self.entries {
                let Ok(original) = entry.original.lock() else {
                    positive = false;
                    continue;
                };
                if !matches!(entry.joined, Some(Ok(())))
                    || !matches!(original.action, Some(Ok(())))
                    || original.completed_values().is_none()
                    || !matches!(original.native_completion, Some(Ok(())))
                    || original.runtime.is_some()
                {
                    positive = false;
                    continue;
                }
                if self.shared.is_some() {
                    // This row owns a completed RPC Result. The real external
                    // provider and ALL raw frames remain until the genuine
                    // enclosing comparison and its independent posts finish.
                    continue;
                }
                let Some(attempt) = original.attempt.as_ref() else {
                    positive = false;
                    continue;
                };
                attempt.end();
                let (connected, rejected) = attempt.shutdown_outcomes();
                let clean_end = attempt.transport_ended_cleanly_v1();
                if !matches!(connected, Some(Ok(()))) || rejected.is_some() || !clean_end {
                    positive = false;
                }
            }
            if positive { Ok(()) } else { Err(FixedPid1PropertyErrorV1::Closed) }
        })());
        if matches!(self.settlement, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedPid1PropertyErrorV1::Closed)
        }
    }

    /// Runs one fixed-stack, bounded readonly flight and returns shared DATA.
    ///
    /// The caller retains this archive through its own semantic/currentness posts.
    /// Neither names nor returned values identify a payer or prove role authority.
    ///
    /// # Errors
    /// Retains every reached constructor/native/action/join outcome on refusal.
    pub fn read(
        &mut self,
        unit_name: &'static str,
        pid: u32,
        properties: &'static [&'static str],
        unit_properties: &'static [&'static str],
    ) -> Result<FixedPid1PropertyValuesV1, FixedPid1PropertyErrorV1> {
        let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();
        self.read_under_slot(&mut slot, unit_name, pid, properties, unit_properties)
    }

    /// Runs the same bounded flight while borrowing an actual held worker slot.
    ///
    /// A deadline-bearing caller checks its original absolute deadline after
    /// acquiring this slot and before entry. The slot is scheduling only; the
    /// caller retains its genuine admission and all native/semantic posts.
    /// This method joins every spawned worker before releasing its borrow.
    ///
    /// # Errors
    /// Retains the same constructor/native/action/join outcomes as [`Self::read`].
    pub fn read_under_slot(
        &mut self,
        slot: &mut FixedPid1PropertyWorkerSlotV1,
        unit_name: &'static str,
        pid: u32,
        properties: &'static [&'static str],
        unit_properties: &'static [&'static str],
    ) -> Result<FixedPid1PropertyValuesV1, FixedPid1PropertyErrorV1> {
        self.read_recipe_under_slot_v1(slot, unit_name, pid, properties,
            unit_properties, FixedPropertyReadRecipeV1::Startup)
    }

    /// Reads only the fixed active local Ownership unit with discovered MainPID.
    ///
    /// The caller holds a real worker slot and checks its original absolute
    /// deadline before this entry. This returns shared DATA, not a service grant.
    /// The existing ordinary retained worker owns all actual native prefixes.
    ///
    /// # Errors
    /// Retains native/property/worker failure or refuses closed/shared archives.
    pub fn read_fixed_ownership_profile_under_slot_v1(&mut self,
        slot: &mut FixedPid1PropertyWorkerSlotV1, cutoff: u64,
    ) -> Result<FixedPid1PropertyValuesV1, FixedPid1PropertyErrorV1> {
        if self.shared.is_some() { return Err(FixedPid1PropertyErrorV1::Closed); }
        self.read_recipe_under_slot_v1(slot, "aos-sandbox-ownershipd.service", 0,
            super::service_properties::OWNERSHIP_PROFILE_PROPERTIES_V1,
            super::service_properties::OWNERSHIP_PROFILE_UNIT_PROPERTIES_V1,
            FixedPropertyReadRecipeV1::Ownership { cutoff })
    }

    fn read_recipe_under_slot_v1(&mut self, slot: &mut FixedPid1PropertyWorkerSlotV1,
        unit_name: &'static str, pid: u32, properties: &'static [&'static str],
        unit_properties: &'static [&'static str], recipe: FixedPropertyReadRecipeV1,
    ) -> Result<FixedPid1PropertyValuesV1, FixedPid1PropertyErrorV1> {
        if self.growth_closed
            || self.settlement.is_some()
            || !matches!(self.preparation_complete, Some(Ok(())))
            || !matches!(self.preparation, Some(Ok(())))
            || self.entries.len() >= self.maximum
            || self.entries.len() >= self.entries.capacity()
        {
            return Err(FixedPid1PropertyErrorV1::Closed);
        }

        let original = std::sync::Arc::new(std::sync::Mutex::new(FixedPid1PropertyOriginalV1 {
            // The selected shared branch uses only its real existing manager.
            // It never constructs an unused fresh transport/raw archive.
            attempt: self.shared.is_none().then(|| {
                super::ControllerPropertyObserverAttemptV1::with_materialization_limit(
                    self.materialization_limit,
                )
            }),
            runtime: None,
            operation: None,
            action: None,
            native_completion: None,
            shared_values: None,
            shared_ordinal: None,
            shared_entry_clock: None,
            ownership_exit_clock: None, ownership_deadline: None,
        }));
        self.entries.push(FixedPid1PropertyEntryV1 {
            original,
            spawn: None,
            joined: None,
        });
        let entry = self.entries.last_mut().ok_or(FixedPid1PropertyErrorV1::Closed)?;
        let worker_original = std::sync::Arc::clone(&entry.original);
        let shared = self.shared.as_ref().map(Arc::clone);
        let shared_entry_cutoff = self.shared_entry_cutoff;
        let mut worker_join = FixedPid1PropertyWorkerJoinV1 { entry, _slot: slot };
        worker_join.entry.spawn = Some(std::thread::Builder::new()
            .name("first-global-pid1-readback".to_owned())
            .stack_size(Self::WORKER_STACK_BYTES)
            .spawn(move || {
                let Ok(mut original) = worker_original.lock() else {
                    return;
                };
                if let Some(provider) = shared {
                    let ordinal = match provider.query_ordinal() {
                        Ok(ordinal) => ordinal,
                        Err(cause) => {
                            original.operation = Some(Ok(Err(cause)));
                            original.action = Some(Err(FixedPid1PropertyErrorV1::Closed));
                            return;
                        }
                    };
                    original.shared_ordinal = Some(ordinal);
                    let FixedPid1PropertyOriginalV1 {
                        operation, action, native_completion, shared_values, shared_entry_clock, ..
                    } = &mut *original;
                    *operation = Some(provider.runtime.block_on(async {
                        tokio::time::timeout(Duration::from_secs(5), async {
                            if let Some(cutoff) = shared_entry_cutoff {
                                let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
                                *shared_entry_clock = Some(now);
                                let current = u64::try_from(now.tv_sec).ok()
                                    .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                                    .and_then(|value| value.checked_add(u64::try_from(now.tv_nsec).ok()?));
                                if !current.is_some_and(|current| current < cutoff) {
                                    return Err(crate::Error::ExactUnitTimeout(
                                        "fixed PID1 original BOOTTIME entry",
                                    ));
                                }
                            }
                            *shared_values = Some(provider.read(
                                ordinal, unit_name, pid, properties, unit_properties,
                            ).await?);
                            Ok(())
                        }).await
                    }));
                    *action = Some(if matches!(operation.as_ref(), Some(Ok(Ok(())))) {
                        Ok(())
                    } else {
                        provider.mark_failed_query(ordinal);
                        Err(FixedPid1PropertyErrorV1::Closed)
                    });
                    // The RPC future has completed on the actual held reactor
                    // and this worker will join. No connection/Runtime End or
                    // drop is fabricated; full raw retirement belongs to the
                    // outer comparison's explicit positive interval boundary.
                    *native_completion = Some(if matches!(action.as_ref(), Some(Ok(()))) {
                        Ok(())
                    } else { Err(FixedPid1PropertyErrorV1::Closed) });
                    return;
                }
                original.runtime = Some(tokio::runtime::Builder::new_current_thread()
                    .enable_all().build());
                let FixedPid1PropertyOriginalV1 {
                    attempt,
                    runtime,
                    operation,
                    action,
                    native_completion: _,
                    shared_entry_clock, ownership_exit_clock, ownership_deadline,
                    ..
                } = &mut *original;

                let Some(attempt) = attempt.as_mut() else {
                    *action = Some(Err(FixedPid1PropertyErrorV1::Closed));
                    return;
                };
                let mut cancellation = attempt.cancellation_fence();
                *operation = match runtime.as_ref() {
                    Some(Ok(runtime)) => Some(runtime.block_on(async {
                        let duration = match recipe {
                            FixedPropertyReadRecipeV1::Startup => Duration::from_secs(5),
                            FixedPropertyReadRecipeV1::Ownership { cutoff } => {
                                *shared_entry_clock = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
                                let remaining = ownership_remaining_v1(shared_entry_clock.as_ref(), cutoff);
                                match remaining {
                                    Ok(remaining) => remaining,
                                    Err(cause) => return Ok(Err(cause)),
                                }
                            }
                        };
                        tokio::time::timeout(duration, async {
                            attempt.connect().await?;
                            match recipe {
                                FixedPropertyReadRecipeV1::Startup =>
                                    attempt.observe_pid1_service_startup_properties(
                                        unit_name, pid, properties, unit_properties,
                                    ).await,
                                FixedPropertyReadRecipeV1::Ownership { .. } =>
                                    attempt.observe_fixed_ownership_profile_v1().await,
                            }
                        }).await
                    })),
                    _ => None,
                };
                if let FixedPropertyReadRecipeV1::Ownership { cutoff } = recipe {
                    *ownership_exit_clock = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
                    *ownership_deadline = Some(ownership_remaining_v1(ownership_exit_clock.as_ref(), cutoff).map(|_| ()));
                }
                *action = Some(if matches!(operation.as_ref(), Some(Ok(Ok(()))))
                    && !matches!(ownership_deadline.as_ref(), Some(Err(_))) {
                    Ok(())
                } else {
                    Err(FixedPid1PropertyErrorV1::Closed)
                });
                if matches!(action.as_ref(), Some(Ok(()))) {
                    cancellation.complete();
                    // The completed guard owns a real custody Arc. Dispose it
                    // before testing mechanical native ownership exclusivity.
                    drop(cancellation);
                    // This executes outside runtime.block_on on the same
                    // original worker. A shutdown/drop panic is retained by
                    // join and cannot yield a completed caller projection.
                    let _native = original.finish_native_runtime_once();
                }
            }).map(Some));

        worker_join.join_once();
        drop(worker_join);

        if let Some(provider) = &self.shared {
            if matches!(entry.joined, Some(Err(_))) {
                // The original mutex remains poisoned. Borrowing its contents
                // retains the exact panic/native prefix and closes the SAME
                // provider before any independently owed query can follow.
                let original = match entry.original.lock() {
                    Ok(original) => original,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match original.shared_ordinal {
                    Some(ordinal) => provider.mark_failed_query(ordinal),
                    None => provider.preserve_failed_interval_v1(),
                }
            }
        }
        let original = entry.original.lock().map_err(|_| FixedPid1PropertyErrorV1::Closed)?;
        if !matches!(entry.joined, Some(Ok(()))) || !matches!(original.action, Some(Ok(())))
            || !matches!(original.native_completion, Some(Ok(()))) || original.runtime.is_some()
        {
            return Err(FixedPid1PropertyErrorV1::Closed);
        }
        let (service, unit) = original.completed_values()
            .ok_or(FixedPid1PropertyErrorV1::Closed)?;
        // The returned DATA views share exactly the native attempt's immutable
        // tables. No decoded tree is cloned while the original stays retained.
        Ok((Arc::clone(service), Arc::clone(unit)))
    }
}

impl FixedPid1PropertyArchiveV1 {
    /// Actual fixed native worker stack extent, shared by all callers.
    pub const WORKER_STACK_BYTES: usize = 512 * 1024;

    /// Returns the actual resident row layout, excluding its Arc pointee/heap.
    #[must_use]
    pub const fn entry_bytes_v1() -> usize { std::mem::size_of::<FixedPid1PropertyEntryV1>() }

    /// Returns the actual retained worker/native original layout.
    #[must_use]
    pub const fn original_bytes_v1() -> usize { std::mem::size_of::<FixedPid1PropertyOriginalV1>() }

    /// Returns this archive's actual inline layout without row backing.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize { std::mem::size_of::<Self>() }

    /// Supplies the existing conservative full/generic receiving geometry.
    ///
    /// # Errors
    /// Rejects arithmetic overflow or materialization outside the native ceiling.
    pub fn geometry_v1(materialized_bytes: usize) -> Result<FixedPid1PropertyGeometryV1, FixedPid1PropertyErrorV1> {
        materialization_geometry(materialized_bytes, false)
    }

    /// Supplies the same fixed catalog decoder's actual bounded receiving geometry.
    ///
    /// # Errors
    /// Rejects arithmetic overflow or materialization outside the native ceiling.
    pub fn fixed_property_geometry_v1(materialized_bytes: usize) -> Result<FixedPid1PropertyGeometryV1, FixedPid1PropertyErrorV1> {
        materialization_geometry(materialized_bytes, true)
    }

    /// Bounds retained immutable output tables from the same fixed typed decoder.
    ///
    /// This excludes transport, worker and constructor scratch. A caller may
    /// reuse those peaks only after its whole positive comparison and native
    /// settlement; every retained output table still needs this byte provision.
    /// Returns `None` outside the existing one-message selected lane or on
    /// overflow. This supplies no role, payment or semantic completion.
    #[must_use]
    pub fn fixed_property_retained_values_bytes_v1(materialized_bytes: usize) -> Option<usize> {
        let (decoded, _) = super::ControllerPropertyObserverAttemptV1::
            fixed_property_decoded_geometry_v1(materialized_bytes)?;
        decoded.checked_add(super::ControllerPropertyObserverAttemptV1::
            shared_property_owner_bytes_v1())
    }
}

fn materialization_geometry(materialized_bytes: usize, fixed_property_requests: bool)
    -> Result<FixedPid1PropertyGeometryV1, FixedPid1PropertyErrorV1>
{
    use super::ControllerPropertyObserverAttemptV1 as Observer;

    // Each encoded byte can nominate a decoded value cell. This intentionally
    // overprices malformed replies as well as the expected fixed property
    // lists; the selected receiver enforces these extents before resizing.
    let incoming = Observer::MESSAGE_BYTES.checked_mul(Observer::INCOMING_MESSAGES)
        .ok_or(FixedPid1PropertyErrorV1::Closed)?;
    let outgoing = Observer::MESSAGE_BYTES.checked_mul(Observer::OUTGOING_MESSAGES)
        .ok_or(FixedPid1PropertyErrorV1::Closed)?;
    if materialized_bytes > incoming {
        return Err(FixedPid1PropertyErrorV1::Closed);
    }
    // The SAME selected native constructor supplies these raw layout widths.
    // Small-M receives admit whole announced extents before body growth; AUTH
    // carryover and one refused primary-header prefix have their own storage.
    let (raw_prefix_bytes, retained_frame_bytes) =
        Observer::raw_receive_bytes_for_materialization(materialized_bytes);
    // Thirty-two cells per emitted request cover the fixed primary/header
    // fields, tuple operands, Message/Arc/frame owners and control links. Raw
    // output remains fully charged below, beside four transient encoded-frame
    // scratch widths; this does not assume an outgoing reply is well-formed.
    let outgoing_cells = if fixed_property_requests {
        Observer::OUTGOING_MESSAGES.checked_mul(32)
    } else {
        Some(outgoing)
    }.ok_or(FixedPid1PropertyErrorV1::Closed)?;
    let cells = materialized_bytes.checked_add(outgoing_cells)
        .ok_or(FixedPid1PropertyErrorV1::Closed)?;
    let request_copies = if fixed_property_requests {
        // Actual fixed property calls are sequential. Completed requests keep
        // one encoded Vec each in the aggregate outgoing term below; cloning
        // Message/Data for retention/send shares its Arc. Four single-frame
        // widths conservatively cover current/refused build/send scratch.
        Observer::MESSAGE_BYTES.checked_mul(4)
            .and_then(|bytes| bytes.checked_add(materialized_bytes.checked_mul(16)?))
            .ok_or(FixedPid1PropertyErrorV1::Closed)?
    } else {
        0
    };
    // Preserve the generic/default provision. Only the actual small selected
    // typed decoder uses its own concrete carrier/constructor supplier; the
    // independent runtime/queue/error envelope below remains unchanged.
    let value_cell = std::mem::size_of::<(OwnedValue, OwnedValue, [usize; 3])>();
    let typed_geometry = if fixed_property_requests && materialized_bytes <= Observer::MESSAGE_BYTES {
        Some(Observer::fixed_property_decoded_geometry_v1(materialized_bytes)
            .ok_or(FixedPid1PropertyErrorV1::Closed)?)
    } else {
        None
    };
    let decoded = match typed_geometry {
        Some((memory, _)) => memory,
        None => materialized_bytes.checked_mul(value_cell)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(FixedPid1PropertyErrorV1::Closed)?,
    };
    let memory = raw_prefix_bytes.checked_add(retained_frame_bytes)
        .and_then(|bytes| bytes.checked_add(outgoing))
        .and_then(|bytes| bytes.checked_add(decoded))
        .and_then(|bytes| bytes.checked_add(Observer::AUTH_BYTES.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<FixedPid1PropertyEntryV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<FixedPid1PropertyOriginalV1>()))
        // Exact scheduling carriers are byte provision, not namespace entries.
        // Charging the shared mutex per row conservatively covers its one
        // actual process-wide instance without amortization credit.
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Mutex<()>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<FixedPid1PropertyWorkerSlotV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<FixedPid1PropertyWorkerJoinV1<'_>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<tokio::runtime::Runtime>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SystemdClient>()))
        .and_then(|bytes| bytes.checked_add(Observer::inline_bytes()))
        .and_then(|bytes| bytes.checked_add(Observer::shared_property_owner_bytes_v1()))
        // Runtime/connection queues, fixed task frames, parser scratch and
        // owning native errors have separate provision from raw frame bytes.
        // The immutable selected service limits remain the physical backstop;
        // this row does not claim sizeof(Runtime) measures its heap.
        .and_then(|bytes| bytes.checked_add(cells.checked_mul(value_cell)?))
        .and_then(|bytes| bytes.checked_add(request_copies))
        .and_then(|bytes| bytes.checked_add(FixedPid1PropertyArchiveV1::WORKER_STACK_BYTES))
        .ok_or(FixedPid1PropertyErrorV1::Closed)?;
    let memory = u64::try_from(memory).map_err(|_| FixedPid1PropertyErrorV1::Closed)?;
    let cells = u64::try_from(cells).map_err(|_| FixedPid1PropertyErrorV1::Closed)?;
    // Fixed requests retain at most one requested method/property name per
    // emitted message, including the service bookends and initial Hello. The
    // existing outgoing-message ceiling bounds that actual request roster.
    // Each decoded dynamic property/map/record entry requires at least two
    // encoded bytes; malformed replies remain bounded before materialization.
    // Signature AST nodes, Arc owners and native controls are byte provision.
    // Preserve the separate generic receiver's existing namespace invoice.
    let metadata = if fixed_property_requests {
        u64::try_from(materialized_bytes.div_ceil(2))
            .ok().and_then(|entries| entries.checked_add(u64::try_from(Observer::OUTGOING_MESSAGES).ok()?))
    } else {
        cells.checked_add(2).and_then(|entries| entries.checked_add(16))
    }.ok_or(FixedPid1PropertyErrorV1::Closed)?;
    // The selected native AUTH reader admits at most AUTH_BYTES in aggregate.
    // Common::write_commands independently caps its retained AUTH send buffers
    // at the same aggregate 4096 bytes before sendmsg. Four retained lines are
    // representations within those totals, not four separate traffic budgets.
    let auth_traffic = Observer::AUTH_BYTES.checked_mul(2)
        .ok_or(FixedPid1PropertyErrorV1::Closed)?;
    let traffic = u64::try_from(incoming.checked_add(outgoing)
        .and_then(|bytes| bytes.checked_add(auth_traffic))
        .ok_or(FixedPid1PropertyErrorV1::Closed)?)
        .map_err(|_| FixedPid1PropertyErrorV1::Closed)?;
    Ok(FixedPid1PropertyGeometryV1 {
        memory_bytes: memory,
        metadata_entries: metadata,
        // Five Runtime driver FDs, one once-connected socket and one
        // conservative allowance. Controller recvmsg uses an EMPTY control
        // slice: hostile rights are rejected, not retained as installed FDs.
        open_files: 7,
        worker_threads: 1,
        wire_io_bytes: traffic,
        maximum_log_bytes: u64::try_from(Observer::MESSAGE_BYTES)
            .map_err(|_| FixedPid1PropertyErrorV1::Closed)?,
    })
}

#[cfg(test)]
mod property_observer_join_custody_tests {
    use std::cell::Cell;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    use super::*;

    struct PanicPayload {
        value: Cell<u8>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for PanicPayload {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn require_send_sync<T: Send + Sync>() {}

    #[test]
    fn caller_unwind_joins_actual_worker_before_slot_borrow_ends() {
        use std::sync::atomic::AtomicBool;

        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let original = FixedPid1PropertyOriginalV1 {
            attempt: Some(ControllerPropertyObserverAttemptV1::with_materialization_limit(0)),
            runtime: None,
            operation: None,
            action: None,
            native_completion: None,
            shared_values: None,
            shared_ordinal: None,
            shared_entry_clock: None,
            ownership_exit_clock: None, ownership_deadline: None,
        };
        let mut entry = FixedPid1PropertyEntryV1 {
            original: Arc::new(Mutex::new(original)),
            spawn: None,
            joined: None,
        };
        let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();

        let caller = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let worker_join = FixedPid1PropertyWorkerJoinV1 { entry: &mut entry, _slot: &mut slot };
            worker_join.entry.spawn = Some(std::thread::Builder::new().spawn(move || {
                worker_finished.store(true, Ordering::SeqCst);
            }).map(Some));
            panic!("fixture caller unwinds after actual worker spawn");
        }));

        assert!(caller.is_err());
        assert!(finished.load(Ordering::SeqCst));
        assert!(matches!(entry.joined, Some(Ok(()))));
        assert!(matches!(entry.spawn, Some(Ok(None))));
        assert!(matches!(
            FIXED_PID1_PROPERTY_WORKER_SLOT.try_lock(),
            Err(std::sync::TryLockError::WouldBlock),
        ));

        drop(slot);
        let _next = FixedPid1PropertyWorkerSlotV1::acquire();
        assert!(matches!(
            FIXED_PID1_PROPERTY_WORKER_SLOT.try_lock(),
            Err(std::sync::TryLockError::WouldBlock),
        ));
    }

    #[test]
    fn non_sync_thread_panic_keeps_exact_box_until_owner_disposal() {
        require_send_sync::<FixedPid1PropertyArchiveV1>();
        let drops = Arc::new(AtomicUsize::new(0));
        let worker_drops = Arc::clone(&drops);
        let joined = std::thread::spawn(move || {
            std::panic::panic_any(PanicPayload { value: Cell::new(7), drops: worker_drops });
        }).join();
        let original_pointer = match &joined {
            Err(payload) => std::ptr::from_ref(payload.as_ref()).cast::<()>(),
            Ok(()) => panic!("fixture worker did not return its panic payload"),
        };

        let retained = retain_join_v1(joined);
        let payload = match retained {
            Err(payload) => payload,
            Ok(()) => panic!("retained observer join lost its panic outcome"),
        };
        {
            let original = payload.lock().expect("fixture payload lock");
            assert_eq!(std::ptr::from_ref(original.as_ref()).cast::<()>(), original_pointer);
            let original = original.downcast_ref::<PanicPayload>().expect("same payload type");
            assert_eq!(original.value.get(), 7);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
        }

        drop(payload);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}


/// Borrows the actual selected failed row while retaining its native owner lock.
///
/// This guard is not Send and never grants admission or a positive observation.
/// A native transport loan returned by this view cannot outlive the view itself.
/// Untyped panic payloads are available separately from Error causes.
pub struct FixedPid1PropertyFailureViewV1<'owner> {
    archive: &'owner FixedPid1PropertyArchiveV1,
    entry: Option<&'owner FixedPid1PropertyEntryV1>,
    original: Option<MutexGuard<'owner, FixedPid1PropertyOriginalV1>>,
    poisoned: bool,
    shared_initial: Option<MutexGuard<'owner, Option<super::ReadonlyPropertyManagerOriginalV2>>>,
}

impl FixedPid1PropertyArchiveV1 {
    /// Borrows the earliest failed row's real native storage without cloning it.
    ///
    /// Poisoned mutex contents remain poisoned; this diagnostic borrow neither
    /// heals a slot nor performs IO, cancellation, settlement or a new read.
    /// The caller must drop this view before invoking further archive actions.
    #[must_use]
    pub fn failure_view(&self) -> Option<FixedPid1PropertyFailureViewV1<'_>> {
        if retained_error(&self.preparation).is_some()
            || retained_error(&self.preparation_complete).is_some()
        {
            return Some(FixedPid1PropertyFailureViewV1 {
                archive: self, entry: None, original: None, poisoned: false, shared_initial: None,
            });
        }
        for entry in &self.entries {
            let (original, poisoned) = match entry.original.lock() {
                Ok(original) => (original, false),
                Err(poisoned) => (poisoned.into_inner(), true),
            };
            let failed = poisoned || matches!(entry.spawn, Some(Err(_)))
                || matches!(entry.joined, Some(Err(_)))
                || matches!(original.runtime, Some(Err(_)))
                || matches!(original.action, Some(Err(_)))
                || matches!(original.native_completion, Some(Err(_)));
            if failed {
                return Some(FixedPid1PropertyFailureViewV1 {
                    archive: self, entry: Some(entry), original: Some(original), poisoned,
                    shared_initial: self.shared.as_ref().and_then(|provider| provider.initial_failure_guard()),
                });
            }
        }
        if retained_error(&self.settlement).is_some() {
            return Some(FixedPid1PropertyFailureViewV1 {
                archive: self, entry: None, original: None, poisoned: false, shared_initial: None,
            });
        }
        None
    }
}

impl FixedPid1PropertyFailureViewV1<'_> {
    /// Borrows an actual Error before its later coarse action/settlement marker.
    ///
    /// Untyped panics do not implement Error: use [`Self::panic_payload`] too.
    /// Raw native parser/transport causes remain available through the guarded
    /// [`Self::transport_failure`] loan alongside their constructor projection.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        if let Some(cause) = retained_error(&self.archive.preparation)
            .or_else(|| retained_error(&self.archive.preparation_complete))
        {
            return Some(cause);
        }
        if let Some(cause) = self.entry.and_then(|entry| retained_error(&entry.spawn)) {
            return Some(cause);
        }
        if let Some(original) = &self.original {
            if let Some(cause) = retained_error(&original.runtime) {
                return Some(cause);
            }
            if original.shared_ordinal == Some(0) {
                let manager = self.archive.shared.as_ref().and_then(|provider| provider.completed_manager())
                    .or_else(|| self.shared_initial.as_ref().and_then(|initial| initial.as_ref()));
                if let Some(cause) = manager.and_then(|manager| manager.constructor_failure_v2()) {
                    return Some(cause);
                }
            }
            if let Some(attempt) = &original.attempt {
                if let Some(Err(cause)) = attempt.constructor_result() {
                    return Some(cause);
                }
                if let Some(Err(cause)) = attempt.property_result() {
                    return Some(cause);
                }
            }
            match &original.operation {
                Some(Ok(Err(cause))) => return Some(cause),
                Some(Err(cause)) => return Some(cause),
                _ => {}
            }
            if let Some(attempt) = &original.attempt {
                let (connected, rejected) = attempt.shutdown_outcomes();
                if let Some(Err(cause)) = connected { return Some(cause); }
                if let Some(Err(cause)) = rejected { return Some(cause); }
                if let Some(Err(cause)) = attempt.native_socket_retirement_outcome_v1() {
                    return Some(cause);
                }
            }
            if let Some(cause) = retained_error(&original.native_completion)
                .or_else(|| retained_error(&original.ownership_deadline))
                .or_else(|| retained_error(&original.action))
            {
                return Some(cause);
            }
        }
        retained_error(&self.archive.settlement)
    }

    /// Borrows the exact whole timeout/native returned operation outcome.
    #[must_use]
    pub fn action_outcome(&self) -> Option<&FixedPid1PropertyActionOutcomeV1> {
        self.original.as_ref().and_then(|original| original.operation.as_ref())
    }

    /// Borrows the original join Result and its exact untyped panic box.
    #[must_use]
    pub fn join_outcome(&self) -> Option<&FixedPid1PropertyJoinOutcomeV1> {
        self.entry.and_then(|entry| entry.joined.as_ref())
    }

    /// Borrows the exact panic payload Mutex without moving or wrapping its box.
    #[must_use]
    pub fn panic_payload(&self) -> Option<&Mutex<Box<dyn std::any::Any + Send + 'static>>> {
        self.join_outcome().and_then(|result| result.as_ref().err())
    }

    /// Reports the original mutex poison state without clearing it.
    #[must_use]
    pub fn is_poisoned(&self) -> bool { self.poisoned }

    /// Borrows the original native cause under this same held row guard.
    ///
    /// # Errors
    /// Returns the existing native unavailable diagnostic on a borrowed/poisoned
    /// transport slot. A preparation-only view has no transport to borrow.
    pub fn transport_failure(&self) -> Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        if let Some(provider) = &self.archive.shared {
            let Some(ordinal) = self.original.as_ref().and_then(|original| original.shared_ordinal) else {
                return Ok(None);
            };
            if !provider.failure_is_query(ordinal) { return Ok(None); }
            let manager = provider.completed_manager()
                .or_else(|| self.shared_initial.as_ref().and_then(|initial| initial.as_ref()));
            return match manager {
                Some(manager) => manager.transport_failure_v2(),
                None => Ok(None),
            };
        }
        match &self.original {
            Some(original) => match &original.attempt {
                Some(attempt) => attempt.transport_failure(),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }
}

fn retained_error<T, E: std::error::Error + Send + Sync + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|cause| cause as &(dyn std::error::Error + Send + Sync + 'static))
}

#[cfg(test)]
mod failure_view_tests {
    use super::*;

    #[test]
    fn preparation_retains_the_actual_allocation_error_before_any_native_row() {
        let mut archive = FixedPid1PropertyArchiveV1::with_materialization_limit(
            usize::MAX, ControllerPropertyObserverAttemptV1::MESSAGE_BYTES,
        );

        assert!(archive.prepare_once().is_err());
        assert!(archive.entries.is_empty());
        let original = archive.preparation.as_ref().unwrap().as_ref().unwrap_err();
        let original_pointer = std::ptr::from_ref(original);
        let view = archive.failure_view().unwrap();
        let exposed = view.cause().unwrap()
            .downcast_ref::<std::collections::TryReserveError>().unwrap();

        assert_eq!(std::ptr::from_ref(exposed), original_pointer);
        assert!(view.action_outcome().is_none());
        assert!(view.transport_failure().unwrap().is_none());
        drop(view);

        assert!(archive.prepare_once().is_err());
        let view = archive.failure_view().unwrap();
        assert_eq!(std::ptr::from_ref(view.cause().unwrap()
            .downcast_ref::<std::collections::TryReserveError>().unwrap()), original_pointer);
    }

    #[test]
    fn the_actual_runtime_error_precedes_its_later_action_marker() {
        // A private DATA fixture checks cause borrowing, not PID1 provenance,
        // successful native settlement, a paid interval or role authority.
        let original = FixedPid1PropertyOriginalV1 {
            attempt: Some(ControllerPropertyObserverAttemptV1::with_materialization_limit(0)),
            runtime: Some(Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                "fixture runtime constructor"))),
            operation: None,
            action: Some(Err(FixedPid1PropertyErrorV1::Closed)),
            native_completion: None,
            shared_values: None,
            shared_ordinal: None,
            shared_entry_clock: None,
            ownership_exit_clock: None, ownership_deadline: None,
        };
        let mut archive = FixedPid1PropertyArchiveV1::with_materialization_limit(1, 0);
        archive.entries.push(FixedPid1PropertyEntryV1 {
            original: Arc::new(Mutex::new(original)),
            spawn: Some(Ok(None)),
            joined: Some(Ok(())),
        });
        // Moving an io::Error into its actual Arc pointee changes its address;
        // identify the real resident object after that final owner move.
        let resident_pointer = {
            let owner = archive.entries[0].original.lock().unwrap();
            std::ptr::from_ref(owner.runtime.as_ref().unwrap().as_ref().unwrap_err())
        };

        let view = archive.failure_view().unwrap();
        let cause = view.cause().unwrap().downcast_ref::<std::io::Error>().unwrap();

        assert_eq!(std::ptr::from_ref(cause), resident_pointer);
        assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!view.is_poisoned());
        assert!(view.panic_payload().is_none());
    }
}

impl std::fmt::Debug for FixedPid1PropertyFailureViewV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FixedPid1PropertyFailureViewV1")
            .field("poisoned", &self.poisoned)
            .field("panicked", &self.panic_payload().is_some())
            .field("cause", &self.cause())
            .finish()
    }
}

#[cfg(test)]
mod fixed_property_namespace_tests {
    use super::*;

    #[test]
    fn empty_or_refused_reply_still_funds_the_named_request_roster() {
        use super::super::ControllerPropertyObserverAttemptV1 as Observer;

        let empty = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(0).unwrap();
        let partial = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(3).unwrap();
        let whole = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(Observer::MESSAGE_BYTES).unwrap();

        assert_eq!(empty.metadata_entries, Observer::OUTGOING_MESSAGES as u64);
        assert_eq!(partial.metadata_entries - empty.metadata_entries, 2);
        assert_eq!(whole.metadata_entries - empty.metadata_entries,
            Observer::MESSAGE_BYTES.div_ceil(2) as u64);
        assert!(partial.memory_bytes > empty.memory_bytes);
        assert_eq!(empty.open_files, whole.open_files);
        assert_eq!(empty.worker_threads, whole.worker_threads);
        assert_eq!(empty.wire_io_bytes, whole.wire_io_bytes);
        assert_eq!(empty.maximum_log_bytes, whole.maximum_log_bytes);
    }
}

// The original BOOTTIME limit is checked before native connect and again
// before any positive runtime/socket retirement. No partial IO renews it.
fn ownership_remaining_v1(sample: Option<&rustix::time::Timespec>, cutoff: u64)
    -> Result<Duration, crate::Error> {
    let now = sample.and_then(|sample| {
        let nanos = u64::try_from(sample.tv_nsec).ok()?;
        if nanos >= 1_000_000_000 { return None; }
        u64::try_from(sample.tv_sec).ok()?.checked_mul(1_000_000_000)?.checked_add(nanos)
    });
    let remaining = now.and_then(|now| cutoff.checked_sub(now)).filter(|remaining| *remaining != 0)
        .ok_or(crate::Error::ExactUnitTimeout("fixed Ownership original BOOTTIME"))?;
    Ok(Duration::from_nanos(remaining).min(Duration::from_secs(5)))
}

#[cfg(test)]
mod ownership_deadline_tests {
    use super::*;

    #[test]
    fn fixed_ownership_never_renews_an_expired_or_equal_original_deadline() {
        let sample = rustix::time::Timespec { tv_sec: 1, tv_nsec: 2 };
        assert_eq!(ownership_remaining_v1(Some(&sample), 1_000_000_003).unwrap(), Duration::from_nanos(1));
        assert!(ownership_remaining_v1(Some(&sample), 1_000_000_002).is_err());
        assert!(ownership_remaining_v1(Some(&sample), 1_000_000_001).is_err());
        assert_eq!(ownership_remaining_v1(Some(&sample), u64::MAX).unwrap(), Duration::from_secs(5));
        assert!(ownership_remaining_v1(None, u64::MAX).is_err());
    }
}

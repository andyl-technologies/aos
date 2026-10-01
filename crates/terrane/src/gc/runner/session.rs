//! Keeps one genuine lease and permanently stops canceled or fenced sessions.

use super::{CollectionError, denied};
use crate::gc::lease::Collector;
use crate::store::{Clock, NativeEffectClock, StoreFailure};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, UNIX_EPOCH};
use terrane_core::gc::{GcError, GcLease};

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

/// Retains selected whole ownership, native clock continuity and permanent poison.
pub(crate) struct Session {
    lease: GcLease,
    duration: u64,
    checks: Shared<Checks>,
}

struct Checks {
    clock: NativeEffectClock,
    last: Mutex<(Duration, Duration)>,
    poisoned: AtomicBool,
}

/// Owns cancellation poisoning independently of the awaiting task's lifetime.
pub(crate) struct Operation {
    checks: Shared<Checks>,
    completed: bool,
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.completed {
            self.checks.poisoned.store(true, Ordering::Release);
        }
    }
}

impl Operation {
    /// Acknowledges a fully refreshed durable operation.
    pub(crate) fn complete(mut self) {
        self.completed = true;
    }
}

impl Session {
    /// Retains an acknowledged native lease and the same injected clock state.
    ///
    /// # Errors
    /// Rejects zero renewal duration, unavailable time or an already expired lease.
    pub(super) fn new(
        lease: GcLease,
        duration: u64,
        clock: NativeEffectClock,
    ) -> Result<Self, CollectionError> {
        let wall = clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?;
        let monotonic = clock.monotonic();
        if duration == 0 || wall.as_secs() >= lease.expiry {
            return Err(GcError::LeaseLost.into());
        }
        Ok(Self {
            lease,
            duration,
            checks: Shared::new(Checks {
                clock,
                last: Mutex::new((monotonic, wall)),
                poisoned: AtomicBool::new(false),
            }),
        })
    }

    /// Starts a bounded operation; cancellation poisons every retained final check.
    ///
    /// # Errors
    /// Rejects prior poison, expired ownership or discontinuous actual clock time.
    pub(crate) fn operation(&self) -> Result<Operation, StoreFailure> {
        self.recheck()?;
        Ok(Operation {
            checks: Shared::clone(&self.checks),
            completed: false,
        })
    }

    /// Borrows the exact whole lease most recently acknowledged by native selection.
    pub(crate) fn lease(&self) -> &GcLease {
        &self.lease
    }

    /// Rechecks the same retained clock before every observation and effect.
    ///
    /// # Errors
    /// Refuses canceled sessions, rollback, discontinuity or lease expiry.
    pub(crate) fn recheck(&self) -> Result<u64, StoreFailure> {
        self.checks.check(self.lease.expiry)
    }

    /// Retains the actual injected clock for the historical Guard adapter.
    ///
    /// # Errors
    /// Refuses poisoned sessions and unavailable native clock retention.
    pub(crate) fn clock(&self) -> Result<NativeEffectClock, StoreFailure> {
        self.recheck()?;
        self.checks
            .clock
            .retain_native_clock()
            .map_err(|_| denied())
    }

    /// Owns the clock, continuity and poison predicates through queued completion.
    pub(crate) fn owned_check(&self) -> impl Fn() -> Result<(), StoreFailure> + use<> {
        let checks = Shared::clone(&self.checks);
        let expiry = self.lease.expiry;
        move || checks.check(expiry).map(|_| ())
    }

    /// Renews the selected whole value before acquiring any checkpoint holder.
    ///
    /// # Errors
    /// Permanently refuses stale ownership, expiration, arithmetic exhaustion,
    /// changed trusted authority and failed actual native durability.
    pub(super) async fn renew<F, B, V, C>(
        &mut self,
        collector: &Collector<'_, F, B, V, C>,
    ) -> Result<(), CollectionError>
    where
        F: crate::store::LocalFs + crate::bucket::BucketBinding,
        B: Clock + crate::bucket::BucketBinding,
        V: crate::store::ContentValidator + crate::bucket::BucketBinding,
        C: Clock,
    {
        let now = self.recheck()?;
        let duration = self
            .lease
            .expiry
            .checked_sub(now)
            .and_then(|remaining| remaining.checked_add(self.duration))
            .ok_or(GcError::Exhausted)?;
        let result = collector.renew(&self.lease, duration).await;
        match result {
            Ok(receipt) => {
                self.lease = receipt.lease;
                self.recheck()?;
                Ok(())
            }
            Err(error) => {
                self.checks.poisoned.store(true, Ordering::Release);
                Err(error.into())
            }
        }
    }
}

impl Checks {
    fn check(&self, expiry: u64) -> Result<u64, StoreFailure> {
        let mono = self.clock.monotonic();
        let wall = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?;
        let mut last = self.last.lock().map_err(|_| denied())?;
        if self.poisoned.load(Ordering::Acquire)
            || mono < last.0
            || wall < last.1
            || wall.as_secs() >= expiry
        {
            self.poisoned.store(true, Ordering::Release);
            return Err(denied());
        }
        *last = (mono, wall);
        Ok(wall.as_secs())
    }
}

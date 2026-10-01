//! Supplies a genuinely retained injected clock for collector qualification.

use super::{Clock, NativeEffectClock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

/// Shares the exact wall and monotonic state chosen by the native test binding.
#[derive(Clone)]
pub(crate) struct TestClock {
    wall: Shared<AtomicU64>,
    ticks: Shared<AtomicU64>,
}

impl TestClock {
    /// Starts one independently injected clock instance.
    pub(crate) fn new(wall: u64) -> Self {
        Self {
            wall: Shared::new(AtomicU64::new(wall)),
            ticks: Shared::new(AtomicU64::new(0)),
        }
    }

    /// Changes the real shared clock state observed by owned worker checks.
    pub(crate) fn set(&self, wall: u64, ticks: u64) {
        self.wall.store(wall, Ordering::SeqCst);
        self.ticks.store(ticks, Ordering::SeqCst);
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.wall.load(Ordering::SeqCst))
    }

    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.ticks.load(Ordering::SeqCst))
    }

    fn retain_native_clock(&self) -> std::io::Result<NativeEffectClock> {
        Ok(NativeEffectClock::from_native_clock(self.clone()))
    }
}

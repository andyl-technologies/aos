//! Supplies a genuinely retained injected clock for collector qualification.

use super::{Clock, NativeEffectClock};
use std::sync::Mutex;
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
    timer: Shared<Mutex<Option<Duration>>>,
}

impl TestClock {
    /// Starts one independently injected clock instance.
    pub(crate) fn new(wall: u64) -> Self {
        Self {
            wall: Shared::new(AtomicU64::new(wall)),
            ticks: Shared::new(AtomicU64::new(0)),
            timer: Shared::new(Mutex::new(None)),
        }
    }

    /// Changes the real shared clock state observed by owned worker checks.
    pub(crate) fn set(&self, wall: u64, ticks: u64) {
        self.wall.store(wall, Ordering::SeqCst);
        self.ticks.store(ticks, Ordering::SeqCst);
        let mut timer = self
            .timer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if timer.is_some() {
            *timer = Self::native_ticks();
        }
    }

    /// Enables real timer progression on this same retained injected clock.
    ///
    /// Existing clocks remain manually sampled until this opt-in is called.
    #[cfg(feature = "tokio")]
    pub(crate) fn enable_timer(&self) {
        *self
            .timer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Self::native_ticks();
    }

    fn elapsed(&self) -> Option<Duration> {
        self.timer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .and_then(|origin| Self::native_ticks()?.checked_sub(origin))
    }

    fn native_ticks() -> Option<Duration> {
        #[cfg(feature = "tokio")]
        {
            // Host time enters only through the existing native Clock binding.
            Some(crate::store::TokioClock.monotonic())
        }
        #[cfg(not(feature = "tokio"))]
        {
            None
        }
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(self.wall.load(Ordering::SeqCst))
            + self.elapsed().unwrap_or_default()
    }

    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.ticks.load(Ordering::SeqCst)) + self.elapsed().unwrap_or_default()
    }

    async fn sleep(&self, duration: Duration) -> std::io::Result<()> {
        #[cfg(feature = "tokio")]
        if self.elapsed().is_some() {
            tokio::time::sleep(duration).await;
            return Ok(());
        }
        let _ = duration;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "test clock timer is disabled",
        ))
    }

    fn retain_native_clock(&self) -> std::io::Result<NativeEffectClock> {
        Ok(NativeEffectClock::from_native_clock(self.clone()))
    }
}

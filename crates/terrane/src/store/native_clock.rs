//! Retains an actual injected clock for privately checked queued native effects.
//!
//! This opaque adapter owns the same clock state chosen by a genuine binding.
//! It grants no actor, policy or physical authority. Generic clocks keep their
//! existing representation and may refuse this optional native operation.

/// Supplies a test clock that retains the same injected lease-clock state.
#[cfg(test)]
#[path = "../gc/lease/clock.rs"]
pub(crate) mod gc_test_clock;

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;
use std::time::{Duration, SystemTime};

use super::Clock;

#[cfg(feature = "send")]
type RetainedClock = dyn Clock + Send + Sync + 'static;
#[cfg(not(feature = "send"))]
type RetainedClock = dyn Clock + 'static;

/// Owns the exact injected native clock used for queued final checks.
///
/// Its state and constructor stay private. Only a genuine clock binding can
/// supply it through the optional [`Clock::retain_native_clock`] hook.
pub struct NativeEffectClock {
    clock: Shared<RetainedClock>,
}

impl NativeEffectClock {
    /// Owns this actual native binding without replacing its injected clock state.
    #[cfg(feature = "send")]
    pub(super) fn from_native_clock<C: Clock + Send + Sync + 'static>(clock: C) -> Self {
        Self {
            clock: Shared::new(clock),
        }
    }

    /// Owns this actual local binding without requiring thread transfer.
    #[cfg(not(feature = "send"))]
    pub(super) fn from_native_clock<C: Clock + 'static>(clock: C) -> Self {
        Self {
            clock: Shared::new(clock),
        }
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl Clock for NativeEffectClock {
    fn now(&self) -> SystemTime {
        self.clock.now()
    }

    fn monotonic(&self) -> Duration {
        self.clock.monotonic()
    }

    fn retain_native_clock(&self) -> std::io::Result<NativeEffectClock> {
        Ok(Self {
            clock: Shared::clone(&self.clock),
        })
    }

    async fn sleep(&self, duration: Duration) -> std::io::Result<()> {
        self.clock.sleep(duration).await
    }
}

#[cfg(test)]
#[path = "native_clock/tests.rs"]
mod tests;

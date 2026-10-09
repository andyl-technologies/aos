//! Checked capped controller time with explicit closed-window boundary steps.
//!
//! This arithmetic defines the host/kernel clock-domain contract. It does not
//! intercept native instructions by itself: a realized KVM profile must qualify
//! every native counter, timer and paravirtual extrapolation path against it.

use crucible_node_contract::{Id, U64};
use serde::{Deserialize, Serialize};

use super::KvmProfileError;

/// Defines an explicit paced-and-boundary-stepped controller clock policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmClockPolicy {
    /// Counts logical picoseconds per pacing-ratio numerator unit.
    pub logical_ps_numerator: U64,
    /// Counts elapsed host nanoseconds per pacing-ratio denominator unit.
    pub host_ns_denominator: U64,
}

impl KvmClockPolicy {
    /// Checks that pacing has a positive, representable ratio.
    ///
    /// # Errors
    /// Refuses a zero numerator or denominator before any clock transition.
    pub fn validate(self) -> Result<(), KvmProfileError> {
        if self.logical_ps_numerator.get() == 0 || self.host_ns_denominator.get() == 0 {
            return Err(KvmProfileError::ClockTransition {
                reason: "clock pacing ratio must be positive",
            });
        }
        Ok(())
    }
}

/// Preserves guest-visible controller time while no native window is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmFrozenClock {
    /// Binds the accepted pacing and boundary-step policy.
    pub policy: KvmClockPolicy,
    /// Records the frozen logical counter coordinate in picoseconds.
    pub current_ps: U64,
}

/// Records an explicit clock jump at an authorized next-window boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvmBoundaryClockStep {
    /// Records the previous frozen guest-visible counter coordinate.
    pub from_ps: U64,
    /// Records the new start boundary without claiming skipped guest execution.
    pub to_ps: U64,
}

struct ActiveWindow {
    id: Id,
    start_ps: U64,
    end_ps: U64,
    last_host_elapsed_ns: U64,
}

/// Applies one capped clock window at a time and freezes between grants.
///
/// The caller supplies trusted monotonic host elapsed measurements only while
/// active. No host epoch or `Instant` is serialized into guest continuation.
/// Values saturate at the admitted end boundary even if native stopping overruns.
/// This does not make CPU retirement or native event timing deterministic.
pub struct KvmControllerClock {
    frozen: KvmFrozenClock,
    active: Option<ActiveWindow>,
}

impl KvmControllerClock {
    /// Constructs a frozen clock from a declared accepted policy.
    ///
    /// # Errors
    /// Refuses an invalid pacing ratio before creating clock authority.
    pub fn new(policy: KvmClockPolicy, initial_ps: U64) -> Result<Self, KvmProfileError> {
        policy.validate()?;
        Ok(Self {
            frozen: KvmFrozenClock {
                policy,
                current_ps: initial_ps,
            },
            active: None,
        })
    }

    /// Restores frozen clock state without importing a host epoch or active VM.
    ///
    /// # Errors
    /// Refuses an invalid captured policy. Complete native CPU/device restoration
    /// and fresh kernel objects remain separate architectural capture obligations.
    pub fn from_capture(capture: KvmFrozenClock) -> Result<Self, KvmProfileError> {
        Self::new(capture.policy, capture.current_ps)
    }

    /// Returns the current guest-visible logical coordinate.
    pub const fn current_ps(&self) -> U64 {
        self.frozen.current_ps
    }

    /// Advances a stopped clock to an explicitly authorized boundary.
    ///
    /// This is a declared clock step, not idle skipping or executed guest work.
    /// The selected profile must expose this effect to scenario admission.
    ///
    /// # Errors
    /// Refuses backward time or a step while a native window remains active.
    pub fn step_boundary(
        &mut self,
        boundary_ps: U64,
    ) -> Result<KvmBoundaryClockStep, KvmProfileError> {
        if self.active.is_some() || boundary_ps < self.frozen.current_ps {
            return Err(KvmProfileError::ClockTransition {
                reason: "boundary step requires a stopped nondecreasing clock",
            });
        }
        let step = KvmBoundaryClockStep {
            from_ps: self.frozen.current_ps,
            to_ps: boundary_ps,
        };
        self.frozen.current_ps = boundary_ps;
        Ok(step)
    }

    /// Activates a window whose start equals the prepared frozen clock.
    ///
    /// # Errors
    /// Refuses overlapping native windows, a changed start, or nonpositive extent.
    pub fn activate(&mut self, id: Id, start_ps: U64, end_ps: U64) -> Result<(), KvmProfileError> {
        if self.active.is_some() || start_ps != self.frozen.current_ps || end_ps <= start_ps {
            return Err(KvmProfileError::ClockTransition {
                reason: "clock activation conflicts with the retained window or start",
            });
        }
        self.active = Some(ActiveWindow {
            id,
            start_ps,
            end_ps,
            last_host_elapsed_ns: U64::new(0),
        });
        Ok(())
    }

    /// Converts trusted elapsed host time without exceeding the original ceiling.
    ///
    /// All guest-visible counter views must derive from the same qualified domain.
    /// A saturated counter remains at the end while native stop acknowledgment
    /// is pending; it never grants another quantum or injects future input.
    ///
    /// # Errors
    /// Refuses unknown windows, changed identity or a backward host measurement.
    pub fn observe(&mut self, id: &Id, elapsed_host_ns: U64) -> Result<U64, KvmProfileError> {
        let active = self
            .active
            .as_mut()
            .ok_or(KvmProfileError::ClockTransition {
                reason: "no active native clock window",
            })?;
        if &active.id != id || elapsed_host_ns < active.last_host_elapsed_ns {
            return Err(KvmProfileError::ClockTransition {
                reason: "clock observation changed window identity or moved backward",
            });
        }
        let scaled = u128::from(elapsed_host_ns.get())
            * u128::from(self.frozen.policy.logical_ps_numerator.get())
            / u128::from(self.frozen.policy.host_ns_denominator.get());
        let extent = active.end_ps.get() - active.start_ps.get();
        let delta =
            u64::try_from(scaled.min(u128::from(extent))).map_err(|_| KvmProfileError::Overflow)?;
        self.frozen.current_ps = U64::new(
            active
                .start_ps
                .get()
                .checked_add(delta)
                .ok_or(KvmProfileError::Overflow)?,
        );
        active.last_host_elapsed_ns = elapsed_host_ns;
        Ok(self.frozen.current_ps)
    }

    /// Freezes the current coordinate after authentic native-owner pause.
    ///
    /// The enclosing native controller must obtain all-vCPU, timer and device
    /// closure evidence before invoking this clock operation as a receipt.
    ///
    /// # Errors
    /// Refuses an unknown or changed active window. This method cannot prove
    /// physical native pause or settle pending kernel/device timer effects.
    pub fn freeze(&mut self, id: &Id) -> Result<KvmFrozenClock, KvmProfileError> {
        if !self.active.as_ref().is_some_and(|window| &window.id == id) {
            return Err(KvmProfileError::ClockTransition {
                reason: "clock freeze lacks original active window",
            });
        }
        self.active = None;
        Ok(self.frozen)
    }

    /// Returns serializable frozen state only outside an active native window.
    ///
    /// # Errors
    /// Refuses an active cut rather than silently draining or advancing execution.
    pub fn capture(&self) -> Result<KvmFrozenClock, KvmProfileError> {
        if self.active.is_some() {
            return Err(KvmProfileError::ClockTransition {
                reason: "native clock capture requires acknowledged stopped ownership",
            });
        }
        Ok(self.frozen)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn policy() -> KvmClockPolicy {
        KvmClockPolicy {
            logical_ps_numerator: U64::new(50),
            host_ns_denominator: U64::new(3),
        }
    }

    #[test]
    fn stop_overshoot_caps_every_read_and_closed_wait_does_not_advance_time() {
        let id = Id::new("window/0").unwrap();
        let mut clock = KvmControllerClock::new(policy(), U64::new(0)).unwrap();
        clock
            .activate(id.clone(), U64::new(0), U64::new(1000))
            .unwrap();
        assert_eq!(clock.observe(&id, U64::new(3)).unwrap().get(), 50);
        assert_eq!(clock.observe(&id, U64::new(61)).unwrap().get(), 1000);
        assert_eq!(clock.observe(&id, U64::new(u64::MAX)).unwrap().get(), 1000);
        let frozen = clock.freeze(&id).unwrap();
        assert_eq!(clock.current_ps().get(), 1000);
        assert_eq!(clock.capture().unwrap(), frozen);
        assert!(clock.observe(&id, U64::new(u64::MAX)).is_err());
    }

    #[test]
    fn counter_at_timeline_limit_never_wraps_or_treats_saturation_as_new_work() {
        let id = Id::new("window/last").unwrap();
        let mut clock = KvmControllerClock::new(
            KvmClockPolicy {
                logical_ps_numerator: U64::new(u64::MAX),
                host_ns_denominator: U64::new(1),
            },
            U64::new(u64::MAX - 1),
        )
        .unwrap();
        clock
            .activate(id.clone(), U64::new(u64::MAX - 1), U64::new(u64::MAX))
            .unwrap();
        assert_eq!(
            clock.observe(&id, U64::new(u64::MAX)).unwrap().get(),
            u64::MAX
        );
        assert!(clock.capture().is_err());
        assert!(
            clock
                .activate(
                    Id::new("another").unwrap(),
                    U64::new(u64::MAX - 1),
                    U64::new(u64::MAX)
                )
                .is_err()
        );
    }

    #[test]
    fn a_new_boundary_step_is_explicit_and_does_not_claim_idle_skipping() {
        let id = Id::new("window/0").unwrap();
        let mut clock = KvmControllerClock::new(policy(), U64::new(0)).unwrap();
        clock
            .activate(id.clone(), U64::new(0), U64::new(1000))
            .unwrap();
        clock.observe(&id, U64::new(3)).unwrap();
        assert!(clock.step_boundary(U64::new(1000)).is_err());
        clock.freeze(&id).unwrap();
        assert!(
            clock
                .activate(Id::new("window/1").unwrap(), U64::new(1000), U64::new(2000))
                .is_err()
        );
        assert_eq!(
            clock.step_boundary(U64::new(1000)).unwrap(),
            KvmBoundaryClockStep {
                from_ps: U64::new(50),
                to_ps: U64::new(1000)
            }
        );
        clock
            .activate(Id::new("window/1").unwrap(), U64::new(1000), U64::new(2000))
            .unwrap();
    }

    #[test]
    fn clock_capture_refuses_changed_window_and_does_not_import_host_epoch() {
        let id = Id::new("original").unwrap();
        let mut clock = KvmControllerClock::new(policy(), U64::new(0)).unwrap();
        clock
            .activate(id.clone(), U64::new(0), U64::new(1000))
            .unwrap();
        clock.observe(&id, U64::new(6)).unwrap();
        assert!(clock.observe(&id, U64::new(5)).is_err());
        assert!(clock.freeze(&Id::new("changed").unwrap()).is_err());
        let frozen = clock.freeze(&id).unwrap();
        let restored = KvmControllerClock::from_capture(frozen).unwrap();
        assert_eq!(restored.current_ps(), U64::new(100));
        assert_eq!(restored.capture().unwrap(), frozen);
    }
}

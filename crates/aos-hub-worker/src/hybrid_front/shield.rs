//! Bounded admission for Native origin requests within one Worker isolate.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Selects a separate budget for expensive pages and batched controls.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum OriginClass {
    Browse,
    Control,
}

/// Bounds active origin calls and retained client counters.
#[derive(Clone, Copy)]
pub(crate) struct ShieldLimits {
    pub active: usize,
    pub clients: usize,
    pub browse_per_minute: u32,
    pub control_per_minute: u32,
}

impl Default for ShieldLimits {
    fn default() -> Self {
        Self {
            active: 16,
            clients: 4096,
            browse_per_minute: 120,
            control_per_minute: 2400,
        }
    }
}

#[derive(Default)]
struct State {
    active: usize,
    observed_time: i64,
    clients: BTreeMap<(OriginClass, String), (i64, u32)>,
}

/// Enforces local limits without queueing or making another network request.
#[derive(Clone)]
pub(crate) struct OriginShield {
    limits: ShieldLimits,
    state: Arc<Mutex<State>>,
}

/// Retains admission until the origin future finishes or is cancelled.
pub(crate) struct OriginPermit {
    state: Arc<Mutex<State>>,
}

/// Identifies overload without extending an unbounded queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Busy,
    RateLimited,
    Unavailable,
}

impl OriginShield {
    pub(crate) fn new(limits: ShieldLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Admits a call under a fixed minute window and an immediate capacity cap.
    ///
    /// A backwards clock step cannot renew a client budget. Exhausted client
    /// storage refuses new identities until expiry instead of evicting counters.
    pub(crate) fn enter(
        &self,
        class: OriginClass,
        client: &str,
        now: i64,
    ) -> Result<OriginPermit, Refusal> {
        let mut state = self.state.lock().map_err(|_| Refusal::Unavailable)?;
        if state.active >= self.limits.active {
            return Err(Refusal::Busy);
        }

        state.observed_time = state.observed_time.max(now);
        let now = state.observed_time;
        let window = now.div_euclid(60);
        state.clients.retain(|_, (retained, _)| *retained == window);
        let key = (class, client.to_owned());
        if !state.clients.contains_key(&key) && state.clients.len() >= self.limits.clients {
            return Err(Refusal::RateLimited);
        }
        let budget = match class {
            OriginClass::Browse => self.limits.browse_per_minute,
            OriginClass::Control => self.limits.control_per_minute,
        };
        let counter = state.clients.entry(key).or_insert((window, 0));
        if counter.1 >= budget {
            return Err(Refusal::RateLimited);
        }
        counter.1 += 1;
        state.active += 1;
        Ok(OriginPermit {
            state: Arc::clone(&self.state),
        })
    }
}

impl Drop for OriginPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active = state.active.saturating_sub(1);
        }
    }
}

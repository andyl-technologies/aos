//! Plans S3-FIFO eviction without confusing a plan with durable retirement.
//!
//! Callers hold future capacity before writing, durably retire victims, and
//! only then acknowledge their removal. Holds are policy budgets, not measured
//! allocation or kernel reservations. All deadlines are injected ticks.

use crate::store::{StoreErrorKind, StoreFailure};
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

/// Configures exact allocation and bounded eviction policy.
#[derive(Clone, Copy, Debug)]
pub struct PolicyConfig {
    /// Combined budget for measured allocation and future-capacity holds.
    pub capacity: u64,
    /// Allocation to target before retrying admission at the high watermark.
    pub low_watermark: u64,
    /// Maximum probationary allocation before unread entries are preferred.
    pub probation_bytes: u64,
    /// Protection interval following the final consumer release.
    pub release_grace: Duration,
    /// Maximum queue visits in one eviction planning call.
    pub scan_limit: usize,
}

/// Tracks one uniquely charged allocation unit, including whole packs.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// Stable allocation identity; hard links share this identity.
    pub key: String,
    /// Exact physical allocation charged once for this unit.
    pub bytes: u64,
    /// Owner charged for this physical allocation.
    pub owner: String,
    pins: u64,
    protected_until: Duration,
    referenced: bool,
    main: bool,
    retiring: bool,
}

impl CacheEntry {
    /// Constructs a new, initially unpinned allocation unit.
    pub fn new(key: String, bytes: u64, owner: String) -> Self {
        Self {
            key,
            bytes,
            owner,
            pins: 0,
            protected_until: Duration::ZERO,
            referenced: false,
            main: false,
            retiring: false,
        }
    }
}

/// Keeps reconstructible eviction queues and future-capacity hold accounting.
///
/// This is planning state, not durable pin authority. A caller must persist pin
/// increments before acknowledging them and rebuild this inventory on restart.
#[derive(Debug)]
pub struct CachePolicy {
    config: PolicyConfig,
    entries: BTreeMap<String, CacheEntry>,
    probation: VecDeque<String>,
    main: VecDeque<String>,
    reservations: BTreeMap<String, (String, u64)>,
    quotas: BTreeMap<String, u64>,
}

impl CachePolicy {
    /// Validates bounds and constructs an empty allocation inventory.
    ///
    /// # Errors
    /// Rejects inconsistent watermarks or an unbounded/empty scan budget.
    pub fn new(config: PolicyConfig) -> Result<Self, StoreFailure> {
        if config.low_watermark > config.capacity
            || config.probation_bytes > config.capacity
            || config.scan_limit == 0
        {
            return Err(capacity());
        }
        Ok(Self {
            config,
            entries: BTreeMap::new(),
            probation: VecDeque::new(),
            main: VecDeque::new(),
            reservations: BTreeMap::new(),
            quotas: BTreeMap::new(),
        })
    }

    /// Sets an owner's exact allocation ceiling for subsequent reservations.
    pub fn set_quota(&mut self, owner: String, bytes: u64) {
        self.quotas.insert(owner, bytes);
    }

    /// Returns charged resident allocation, including pending retirement.
    pub fn resident_bytes(&self) -> u64 {
        self.entries.values().map(|entry| entry.bytes).sum()
    }

    /// Returns resident allocation plus all outstanding reservations.
    pub fn charged_bytes(&self) -> u64 {
        self.resident_bytes().saturating_add(
            self.reservations
                .values()
                .map(|(_, bytes)| *bytes)
                .sum::<u64>(),
        )
    }

    /// Reserves allocation without acknowledging hypothetical eviction.
    ///
    /// # Errors
    /// Returns capacity when the owner quota or tier capacity would be exceeded,
    /// the reservation already exists, or arithmetic overflows.
    pub fn reserve(&mut self, id: String, owner: String, bytes: u64) -> Result<(), StoreFailure> {
        let total = self
            .charged_bytes()
            .checked_add(bytes)
            .ok_or_else(capacity)?;
        let owner_bytes = self
            .entries
            .values()
            .filter(|entry| entry.owner == owner)
            .map(|entry| entry.bytes)
            .chain(
                self.reservations
                    .values()
                    .filter(|(candidate, _)| candidate == &owner)
                    .map(|(_, size)| *size),
            )
            .try_fold(bytes, |total, size| total.checked_add(size))
            .ok_or_else(capacity)?;
        if self.reservations.contains_key(&id)
            || total > self.config.capacity
            || self
                .quotas
                .get(&owner)
                .is_some_and(|quota| owner_bytes > *quota)
        {
            return Err(capacity());
        }
        self.reservations.insert(id, (owner, bytes));
        Ok(())
    }

    /// Releases a failed or cancelled admission's reservation.
    pub fn cancel_reservation(&mut self, id: &str) {
        self.reservations.remove(id);
    }

    /// Converts a reservation into one verified, durably admitted allocation.
    ///
    /// # Errors
    /// Rejects absent reservations, duplicate allocations, ownership mismatch,
    /// and actual allocation exceeding the reservation.
    pub fn admit(&mut self, reservation: &str, entry: CacheEntry) -> Result<(), StoreFailure> {
        let (owner, bytes) = self.reservations.get(reservation).ok_or_else(capacity)?;
        if owner != &entry.owner || entry.bytes > *bytes || self.entries.contains_key(&entry.key) {
            return Err(capacity());
        }
        self.reservations.remove(reservation);
        self.probation.push_back(entry.key.clone());
        self.entries.insert(entry.key.clone(), entry);
        Ok(())
    }

    /// Records a read and restores a pending retirement to active inventory.
    ///
    /// The caller must restore the canonical name before returning actual bytes.
    pub fn touch(&mut self, key: &str) {
        if let Some(entry) = self.entries.get_mut(key) {
            if !entry.main {
                // Promotion occurs on the read, preserving actual promotion
                // order rather than the order of a later eviction scan.
                self.probation.retain(|candidate| candidate != key);
                self.main.push_back(key.to_owned());
                entry.main = true;
            } else if entry.retiring {
                self.main.push_back(key.to_owned());
            }
            entry.retiring = false;
            entry.referenced = true;
        }
    }

    /// Protects a durably acknowledged consumer pin.
    ///
    /// # Errors
    /// Rejects unknown allocations and overflowing consumer counts.
    pub fn pin(&mut self, key: &str) -> Result<(), StoreFailure> {
        let entry = self.entries.get_mut(key).ok_or_else(capacity)?;
        entry.pins = entry.pins.checked_add(1).ok_or_else(capacity)?;
        if entry.retiring {
            if entry.main {
                self.main.push_back(key.to_owned());
            } else {
                self.probation.push_back(key.to_owned());
            }
        }
        entry.retiring = false;
        Ok(())
    }

    /// Releases one pin and starts grace only after the final release.
    ///
    /// # Errors
    /// Rejects unknown allocations, unbalanced releases, and deadline overflow.
    pub fn release(&mut self, key: &str, now: Duration) -> Result<(), StoreFailure> {
        let entry = self.entries.get_mut(key).ok_or_else(capacity)?;
        if entry.pins == 0 {
            return Err(capacity());
        }
        let until = now
            .checked_add(self.config.release_grace)
            .ok_or_else(capacity)?;
        entry.pins -= 1;
        if entry.pins == 0 {
            entry.protected_until = until;
        }
        Ok(())
    }

    /// Selects bounded S3-FIFO victims without releasing their physical charge.
    ///
    /// Pinned and grace-protected entries remain charged and are never selected.
    /// Main-queue hits get a second pass; probationary hits promote to main.
    pub fn eviction_candidates(&mut self, now: Duration) -> Vec<String> {
        self.eviction_candidates_for(0, now)
    }

    /// Plans enough retirement for the low watermark and an incoming reservation.
    ///
    /// Outstanding reservations remain charged even when their writes have not
    /// started. An oversized incoming reservation cannot make pins evictable.
    pub fn eviction_candidates_for(&mut self, incoming: u64, now: Duration) -> Vec<String> {
        let target = self
            .config
            .low_watermark
            .min(self.config.capacity.saturating_sub(incoming));
        self.select_victims(self.charged_bytes(), target, now)
    }

    /// Plans bounded retirement for an externally measured reclamation deficit.
    ///
    /// Native owners derive this deficit from complete kernel quota usage and
    /// distinct future holds. Metadata, temporary files and open unlinked inodes
    /// can make that usage larger than this reconstructible body inventory.
    /// Selection keeps every allocation charged until actual retirement; its
    /// sum is a plan and never evidence that kernel usage has fallen.
    pub fn eviction_candidates_to_reclaim(&mut self, bytes: u64, now: Duration) -> Vec<String> {
        self.select_victims(bytes, 0, now)
    }

    fn select_victims(&mut self, mut projected: u64, target: u64, now: Duration) -> Vec<String> {
        let mut victims = Vec::new();
        for _ in 0..self.config.scan_limit {
            if projected <= target {
                break;
            }
            let probation_size: u64 = self
                .entries
                .values()
                .filter(|entry| !entry.main && !entry.retiring)
                .map(|entry| entry.bytes)
                .sum();
            let reclaimable = |key: &String| {
                self.entries.get(key).is_some_and(|entry| {
                    !entry.retiring && entry.pins == 0 && now >= entry.protected_until
                })
            };
            let probation_ready = self.probation.iter().any(reclaimable);
            let main_ready = self.main.iter().any(reclaimable);
            if !probation_ready && !main_ready {
                break;
            }
            // Protected content stays charged, but a queue consisting solely
            // of protected entries must not consume every visit while the
            // other queue still contains an eligible allocation.
            let probationary =
                probation_ready && (probation_size > self.config.probation_bytes || !main_ready);
            let queue = if probationary {
                &mut self.probation
            } else {
                &mut self.main
            };
            let Some(key) = queue.pop_front() else {
                break;
            };
            let Some(entry) = self.entries.get_mut(&key) else {
                continue;
            };
            if entry.retiring {
                continue;
            }
            if entry.pins != 0 || now < entry.protected_until {
                queue.push_back(key);
                continue;
            }
            if entry.referenced {
                entry.referenced = false;
                entry.main = true;
                self.main.push_back(key);
                continue;
            }
            entry.retiring = true;
            projected = projected.saturating_sub(entry.bytes);
            victims.push(key);
        }
        victims
    }

    /// Plans retirement of a specific unprotected allocation without FIFO pressure.
    ///
    /// This supports lifetimes such as private sealed content, which must end
    /// after final consumer release even when capacity remains. It changes only
    /// scheduling state; callers still require original native retirement and
    /// actual physical accounting. Subsequent reads or pins cancel this plan.
    ///
    /// # Errors
    /// Refuses unknown allocations, live pins and unelapsed release grace.
    pub fn plan_retirement(&mut self, key: &str, now: Duration) -> Result<(), StoreFailure> {
        let entry = self.entries.get_mut(key).ok_or_else(capacity)?;
        if entry.pins != 0 || now < entry.protected_until {
            return Err(capacity());
        }
        entry.retiring = true;
        self.probation.retain(|candidate| candidate != key);
        self.main.retain(|candidate| candidate != key);
        Ok(())
    }

    /// Removes charge only after durable retirement has completed.
    ///
    /// # Errors
    /// Refuses deletion if a read or pin cancelled the planned retirement.
    pub fn finish_retirement(&mut self, key: &str) -> Result<(), StoreFailure> {
        let entry = self.entries.get(key).ok_or_else(capacity)?;
        if !entry.retiring || entry.pins != 0 {
            return Err(capacity());
        }
        self.entries.remove(key);
        Ok(())
    }

    /// Forgets scheduling state for an allocation outside the managed inventory.
    ///
    /// This changes only the reconstructible model and preserves future holds.
    /// It neither removes native bytes nor acknowledges physical reclamation or
    /// durable pin release. A caller must independently account in-flight and
    /// transferred allocations before making admission decisions.
    pub fn forget_allocation(&mut self, key: &str) {
        self.entries.remove(key);
        self.probation.retain(|candidate| candidate != key);
        self.main.retain(|candidate| candidate != key);
    }
}

fn capacity() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
}

/// Tracks lower-tier failure thresholds and bounded probe scheduling.
#[derive(Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    failures: u32,
    interval: Duration,
    next_probe: Option<Duration>,
}

impl CircuitBreaker {
    /// Constructs a circuit with a positive threshold and probe interval.
    ///
    /// # Errors
    /// Rejects zero thresholds and zero intervals.
    pub fn new(threshold: u32, interval: Duration) -> Result<Self, StoreFailure> {
        if threshold == 0 || interval.is_zero() {
            return Err(capacity());
        }
        Ok(Self {
            threshold,
            failures: 0,
            interval,
            next_probe: None,
        })
    }

    /// Reports whether a normal request or one scheduled probe may proceed.
    pub fn allow(&mut self, now: Duration) -> bool {
        match self.next_probe {
            None => true,
            Some(deadline) if now >= deadline => {
                self.next_probe = Some(now.saturating_add(self.interval));
                true
            }
            Some(_) => false,
        }
    }

    /// Opens the circuit after the configured consecutive failure threshold.
    pub fn failure(&mut self, now: Duration) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= self.threshold {
            self.next_probe = Some(now.saturating_add(self.interval));
        }
    }

    /// Closes the circuit after a successful request or probe.
    pub fn success(&mut self) {
        self.failures = 0;
        self.next_probe = None;
    }
}

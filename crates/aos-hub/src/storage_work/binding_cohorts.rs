//! Bounded, process-local single flights for authenticated custody renewal.

use super::*;

pub(super) const CUSTODY_REFRESH_SECONDS: i64 = 10;
const MAX_CUSTODY_COHORTS: usize = 1024;

/// Retains only a verified remote reply and its original observation window.
pub(super) struct VerifiedCustody {
    pub snapshot: StorageBindingSnapshot,
    pub verified_at: Instant,
    pub observed_at: i64,
}

impl VerifiedCustody {
    /// Rejects expired, backward-clock or overly old acknowledgement reuse.
    pub fn fresh(&self, now: i64) -> bool {
        self.verified_at.elapsed() < Duration::from_secs(CUSTODY_REFRESH_SECONDS as u64)
            && now >= self.observed_at
            && now < self.observed_at.saturating_add(CUSTODY_REFRESH_SECONDS)
            && self.snapshot.expires_at > now.saturating_add(60)
    }
}

/// Serializes refresh and local revocation for one exact SQL binding.
#[derive(Default)]
pub(super) struct CustodyState {
    pub verified: Option<VerifiedCustody>,
    pub retry_after: Option<Instant>,
}

type CohortGate = Arc<Mutex<CustodyState>>;

struct Entry {
    gate: CohortGate,
    last_used: Instant,
}

/// Bounds local flights without serializing independent bindings over the WAN.
#[derive(Default)]
pub(super) struct BindingCustodyCohorts {
    entries: std::sync::Mutex<BTreeMap<i64, Entry>>,
}

impl BindingCustodyCohorts {
    /// Retains an active gate or evicts the least recently used idle entry.
    pub fn gate(&self, binding_id: i64) -> Result<CohortGate> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("binding custody cohorts poisoned"))?;
        if let Some(entry) = entries.get_mut(&binding_id) {
            entry.last_used = Instant::now();
            return Ok(Arc::clone(&entry.gate));
        }

        if entries.len() == MAX_CUSTODY_COHORTS {
            // A caller retains an Arc before releasing this map lock. Evicting
            // only unreferenced gates cannot split a binding's active flight.
            let idle = entries
                .iter()
                .filter(|(_, entry)| Arc::strong_count(&entry.gate) == 1)
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| *id)
                .context("all binding custody cohorts are busy")?;
            entries.remove(&idle);
        }

        let gate = Arc::new(Mutex::new(CustodyState::default()));
        entries.insert(
            binding_id,
            Entry {
                gate: Arc::clone(&gate),
                last_used: Instant::now(),
            },
        );
        Ok(gate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_cohorts_keep_active_gates_and_evict_only_idle_entries() {
        let cohorts = BindingCustodyCohorts::default();
        let active: Vec<_> = (0..MAX_CUSTODY_COHORTS as i64)
            .map(|id| cohorts.gate(id).unwrap())
            .collect();
        assert!(cohorts.gate(MAX_CUSTODY_COHORTS as i64).is_err());
        assert!(Arc::ptr_eq(&active[0], &cohorts.gate(0).unwrap()));
        drop(active);
        assert!(cohorts.gate(MAX_CUSTODY_COHORTS as i64).is_ok());
        assert_eq!(cohorts.entries.lock().unwrap().len(), MAX_CUSTODY_COHORTS);
    }
}

//! Records exposure liveness separately from retained physical pin obligations.
//!
//! ```toml
//! [[exposures]]
//! id = "0123456789abcdef0123456789abcdef"
//! generation = 1
//! commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//! root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
//! index_version = 2
//! deadline = 2000000000
//! phase = "active"
//! ```
//!
//! Object pins use `exposure:<id>` in the same snapshot. Their lease and pin
//! expiry are the largest TOML integer, independently of the exposure deadline.
//! Expiry changes liveness; only proven physical closure can discharge custody.

use super::{CacheState, LeaseRecord, PinRecord, StateLimits, capacity, digest};
use crate::store::StoreFailure;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const RETAINED: u64 = i64::MAX as u64;

/// Distinguishes an exposure accepting work from one retaining drain obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExposurePhase {
    /// Retains a live deadline; each actual disclosure still needs authorization.
    Active,
    /// Denies new work while preserving all pins through actual kernel closure.
    Draining,
}

/// Describes one immutable served root and its durable physical obligations.
///
/// These records are policy data, never worker credentials or read authority.
/// Replacing a worker requires a distinct exposure identity and connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureRecord {
    /// Unique lowercase hexadecimal 128-bit exposure identifier.
    pub id: String,
    /// Nonzero generation fencing requests from another worker incarnation.
    pub generation: u64,
    /// Exact signed commit selected for this exposure.
    pub commit: String,
    /// Canonical root of the retained sealed index.
    pub root: String,
    /// Nonzero derived index format version.
    pub index_version: u16,
    /// Absolute liveness deadline in Unix seconds.
    pub deadline: u64,
    /// Current disclosure and drain phase, independent of physical closure.
    pub phase: ExposurePhase,
}

impl ExposureRecord {
    /// Returns the distinct owner used by this exposure's durable object pins.
    pub fn pin_owner(&self) -> String {
        format!("exposure:{}", self.id)
    }

    /// Reports live policy context without granting any disclosure authority.
    pub fn accepts_work(&self, generation: u64, now: u64) -> bool {
        self.phase == ExposurePhase::Active && self.generation == generation && now < self.deadline
    }
}

impl CacheState {
    /// Adds exposure context and object pins as one bounded policy transition.
    ///
    /// The physical owner must verify original backing, fund and synchronize the
    /// resulting snapshot before acknowledgment. This method performs no IO,
    /// establishes no native custody and grants no serving capability.
    ///
    /// # Errors
    /// Refuses malformed or duplicate context, non-live deadlines, invalid object
    /// hashes and snapshot limits. Failure leaves the original state unchanged.
    pub fn retain_exposure(
        &mut self,
        exposure: ExposureRecord,
        objects: &[String],
        now: u64,
        limits: StateLimits,
    ) -> Result<(), StoreFailure> {
        self.validate(limits)?;
        if !exposure.accepts_work(exposure.generation, now) {
            return Err(capacity());
        }
        let count = self
            .pins
            .len()
            .checked_add(self.leases.len())
            .and_then(|count| count.checked_add(self.reservations.len()))
            .and_then(|count| count.checked_add(self.residences.len()))
            .and_then(|count| count.checked_add(self.exposures.len()))
            .and_then(|count| count.checked_add(objects.len()))
            .and_then(|count| count.checked_add(2))
            .ok_or_else(capacity)?;
        if count > limits.records || objects.iter().any(|hash| !digest(hash)) {
            return Err(capacity());
        }

        let mut next = self.clone();
        let owner = exposure.pin_owner();
        next.version = 2;
        next.leases.push(LeaseRecord {
            owner: owner.clone(),
            expires: RETAINED,
        });
        next.pins.extend(objects.iter().map(|hash| PinRecord {
            owner: owner.clone(),
            hash: hash.clone(),
            expires: RETAINED,
        }));
        next.exposures.push(exposure);
        next.encoded_len(limits)?;
        *self = next;
        Ok(())
    }

    /// Moves elapsed exposures to draining without releasing any physical pins.
    ///
    /// Returns the number of newly draining records. The owner must synchronize
    /// the change and separately stop new opens, bound in-flight work and abort
    /// its connection. Neither this transition nor abort proves kernel closure.
    pub fn drain_expired_exposures(&mut self, now: u64) -> usize {
        let mut changed = 0;
        for exposure in &mut self.exposures {
            if exposure.phase == ExposurePhase::Active && exposure.deadline <= now {
                exposure.phase = ExposurePhase::Draining;
                changed += 1;
            }
        }
        changed
    }

    pub(super) fn validate_exposures(&self) -> Result<(), StoreFailure> {
        let mut owners = BTreeSet::new();
        for exposure in &self.exposures {
            let owner = exposure.pin_owner();
            if exposure.id.len() != 32
                || !exposure
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || exposure.generation == 0
                || exposure.generation > RETAINED
                || exposure.index_version == 0
                || exposure.deadline == 0
                || exposure.deadline > RETAINED
                || !digest(&exposure.commit)
                || !digest(&exposure.root)
                || !owners.insert(owner.clone())
                || !self
                    .leases
                    .iter()
                    .any(|lease| lease.owner == owner && lease.expires == RETAINED)
                || self
                    .pins
                    .iter()
                    .any(|pin| pin.owner == owner && pin.expires != RETAINED)
            {
                return Err(capacity());
            }
        }
        // Reserved names cannot create immortal pins without their full context.
        if self.version == 2
            && (self.leases.iter().any(|lease| {
                lease.owner.starts_with("exposure:") && !owners.contains(&lease.owner)
            }) || self
                .pins
                .iter()
                .any(|pin| pin.owner.starts_with("exposure:") && !owners.contains(&pin.owner)))
        {
            return Err(capacity());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

//! Observes typed Node attempts and actual metadata-validator calls during carry.
//!
//! A public disclosure legitimately walks Nodes outside this measured phase.
//! These observations do not supply bytes, change predicates, configure trust
//! or confer authority. Fixtures attach and calibrate the actual validator first.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Captures a completed real carry attempt without changing its result.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CarryObservation {
    /// Typed Node gets, puts and actual MetadataValidator Node decoder calls.
    pub(crate) nodes: [usize; 3],
    /// Actual factory result before observational bookkeeping.
    pub(crate) qualified: bool,
    /// Complete Guard-install counters, present only after its real durable ACK.
    pub(crate) installed_nodes: Option<[usize; 3]>,
    /// Sources actually retained by the completed closed factory, never authority.
    pub(crate) sources: Vec<String>,
    before: [usize; 3],
}

static OBSERVATIONS: Mutex<BTreeMap<PathBuf, Vec<CarryObservation>>> = Mutex::new(BTreeMap::new());

/// Locks the observation table without recovering poisoned test synchronization.
///
/// # Panics
/// Panics if observational synchronization is poisoned.
fn lock_observations() -> MutexGuard<'static, BTreeMap<PathBuf, Vec<CarryObservation>>> {
    match OBSERVATIONS.lock() {
        Ok(recorded) => recorded,
        Err(_) => panic!("carry observer remains available"),
    }
}

/// Records actual qualification counts while preserving the original result.
///
/// # Panics
/// Panics on counter reset during the phase or poisoned test synchronization.
pub(super) fn record(
    root: &Path,
    before: [usize; 3],
    after: [usize; 3],
    qualified: bool,
    sources: Vec<String>,
) {
    let nodes = std::array::from_fn(|index| {
        let Some(delta) = after[index].checked_sub(before[index]) else {
            panic!("carry counters remain monotonic");
        };
        delta
    });
    lock_observations()
        .entry(root.to_owned())
        .or_default()
        .push(CarryObservation {
            nodes,
            qualified,
            installed_nodes: None,
            sources,
            before,
        });
}

/// Closes the recorded interval from the actual successful install dispatch.
///
/// # Panics
/// Panics on missing/duplicate phase, counter reset or poisoned synchronization.
pub(super) fn acknowledge(root: &Path, after: [usize; 3]) {
    let mut recorded = lock_observations();
    let Some(observation) = recorded
        .get_mut(root)
        .and_then(|records| records.last_mut())
    else {
        panic!("actual Guard installation follows its completed carry attempt");
    };
    assert!(observation.qualified && observation.installed_nodes.is_none());
    observation.installed_nodes = Some(std::array::from_fn(|index| {
        let Some(delta) = after[index].checked_sub(observation.before[index]) else {
            panic!("install counters remain monotonic");
        };
        delta
    }));
}

/// Consumes observations keyed by the real independently opened fixture root.
///
/// # Panics
/// Panics if observational synchronization is poisoned.
#[cfg(feature = "surface-sdk")]
pub(crate) fn take(root: &Path) -> Vec<CarryObservation> {
    lock_observations().remove(root).unwrap_or_default()
}

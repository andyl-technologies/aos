//! Keeps ordinary logical cache publication separate from native dirty retirement.
//!
//! The caller owns its cache work outside the global cache mutex. Native callbacks
//! inspect only immutable retained evidence and the stable operation holder, never
//! reacquire this work's cache. Dirty ACK and logical publication stay independent.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Retains only immutable baseline evidence, without issuing native authority.
#[derive(Clone)]
pub(crate) struct FingerprintBaseline {
    snapshot: Option<RamSnapshot>,
    topology: u64,
    publication: Option<u64>,
}

impl FingerprintBaseline {
    #[cfg(test)]
    pub(super) fn fixture(cache: &RootCache) -> Self {
        Self {
            snapshot: cache.view.as_ref().map(|view| view.snapshot.clone()),
            topology: cache
                .view
                .as_ref()
                .map_or(0, |view| view.topology_generation),
            publication: cache.held_publication,
        }
    }

    /// Checks retained historical lineage against this callback's actual loan.
    ///
    /// # Errors
    /// Refuses a different accepted publication or incompatible baseline topology.
    pub(crate) fn validate_publication(
        &self,
        generation: u64,
        topology: u64,
    ) -> Result<(), RamError> {
        if generation != 0 && (self.publication != Some(generation) || self.topology != topology) {
            return Err(RamError::Invariant("fingerprint accepted baseline changed"));
        }
        if self.snapshot.is_some() && self.topology != topology {
            return Err(RamError::Invariant("fingerprint baseline topology changed"));
        }
        Ok(())
    }

    /// Returns the immutable baseline's known region count, if one exists.
    pub(crate) fn region_count(&self) -> Option<usize> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.topology().regions().len())
    }

    /// Checks actual native interval geometry against the retained inventory.
    ///
    /// # Errors
    /// Refuses malformed extents or a different immutable region descriptor.
    pub(crate) fn validate_region(
        &self,
        index: usize,
        native: &CaptureRegion,
        start: u64,
        end: u64,
    ) -> Result<(), RamError> {
        let length = usize::try_from(native.id_length)
            .map_err(|_| "fingerprint range ID length overflow")?;
        if length == 0
            || length >= native.id.len()
            || native.reserved != 0
            || start > end
            || end > native.logical_length
        {
            return Err(RamError::Invariant("fingerprint native range is invalid"));
        }
        if let Some(snapshot) = self.snapshot.as_ref() {
            let region = snapshot
                .topology()
                .regions()
                .get(index)
                .ok_or("fingerprint native region absent")?;
            if &native.id[..length] != region.id().as_bytes()
                || native.class != region.class() as u32
                || native.mask != u32::from(region.coverage_mask())
                || native.logical_length != region.logical_length()
            {
                return Err(RamError::Invariant("fingerprint native region changed"));
            }
        }
        Ok(())
    }
}

/// Executes cache work with no cache guard held over native owner callbacks.
pub(super) fn observe_ordinary(
    observer: &Observer,
    scope: Scope,
) -> Result<(RamRootDigest, u64), RamError> {
    // Context and old physical return are authenticated before new clock or
    // cache admission, and with all actual RootCache/State/Slot guards released.
    let mut entry = crate::paged_ram::controller::prepare_fingerprint_entry()?;
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "ordinary fingerprint cache busy")?;
    if entry.returned_old_cache() {
        if !cache.ordinary_active
            || cache.held.is_some()
            || cache.held_accepted.is_some()
            || cache.pending.is_some()
            || cache.restore.is_some()
        {
            return Err(RamError::Invariant(
                "fingerprint returned borrower cache journal disagrees",
            ));
        }
        cache.ordinary_active = false;
    }
    // A consumed old borrower returns its cache journal even on negative
    // semantic history; this same attempt still reports the signed refusal.
    if let Some(error) = entry.take_return_failure() {
        return Err(error);
    }
    let observed_mode = entry.observation_only;
    if cache.frozen
        || cache.ordinary_active
        || cache.held.is_some()
        || cache.held_accepted.is_some()
        || cache.pending.is_some()
        || cache.restore.is_some()
    {
        return Err(RamError::Invariant(
            "ordinary fingerprint admission is occupied",
        ));
    }
    let evidence = FingerprintBaseline {
        snapshot: cache.view.as_ref().map(|view| view.snapshot.clone()),
        topology: cache
            .view
            .as_ref()
            .map_or(0, |view| view.topology_generation),
        publication: cache.held_publication,
    };
    let mut work = std::mem::take(&mut *cache);
    cache.ordinary_active = true;
    drop(cache);

    let mut call = match entry.enter(evidence) {
        Ok(call) => call,
        Err(error) => {
            // The same Main owner returns its immutable baseline even when
            // operation admission refuses before native begin. No handle dies.
            let mut cache = observer
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *cache = work;
            return Err(error);
        }
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call.check_before_begin()?;
        work.refresh(observer.apis, &mut call)?;
        call.check_observed_mode(observed_mode)?;
        call.finish()?;
        let view = work
            .view
            .as_ref()
            .ok_or("ordinary fingerprint baseline absent")?;
        let index = SCOPES
            .iter()
            .position(|candidate| *candidate == scope)
            .ok_or("ordinary fingerprint scope absent")?;
        Ok((view.roots[index], view.logical_bytes[index]))
    }))
    .unwrap_or_else(|_| Err(RamError::Invariant("ordinary fingerprint capture panicked")));
    let physical_returned = call.physically_returned();
    // No native callback runs under this lock. Return the real cache even after
    // poisoning rather than destroying its retained snapshots/source allocation.
    let mut cache = observer
        .cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let return_changed = !cache.ordinary_active || cache.view.is_some();
    work.ordinary_active = !physical_returned || return_changed;
    *cache = work;
    if return_changed {
        return Err(RamError::Invariant(
            "ordinary fingerprint cache return changed",
        ));
    }
    result
}

//! Keeps ordinary logical cache publication separate from native dirty retirement.
//!
//! The caller owns its cache work outside the global cache mutex. Native callbacks
//! inspect only immutable retained evidence and the stable operation holder, never
//! reacquire this work's cache. Dirty ACK and logical publication stay independent.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Corroborates the module's retained baseline before a semantic sample entry.
///
/// This observation reads no guest memory and issues no Root or operation. The
/// genuine native Main issuer independently checks its accepted baseline.
///
/// # Errors
/// Refuses an absent observer, lock contention, poison or any competing cache
/// transaction. A busy or staged cache cannot be treated as an absent baseline.
pub(crate) fn pending_sample_class() -> Result<u32, RamError> {
    let observer = OBSERVER.get().ok_or("RAM observer is absent")?;
    if observer.original.is_none() {
        return Err(RamError::Invariant("native Original owner is absent"));
    }
    let cache = observer
        .cache
        .try_lock()
        .map_err(|_| "RAM baseline is busy")?;
    if cache.frozen
        || cache.ordinary_active
        || cache.held_publication.is_some()
        || cache.pending.is_some()
        || cache.restore.is_some()
        || cache.held.is_some()
        || cache.held_accepted.is_some()
    {
        return Err(RamError::Invariant("RAM baseline has competing custody"));
    }
    Ok(if cache.view.is_some() { 5 } else { 4 })
}

/// Runs one actual native Root without issuing a module-local operation.
pub(super) fn observe_ordinary(
    observer: &Observer,
    scope: Scope,
) -> Result<(RamRootDigest, u64), RamError> {
    original::synchronize_root()?;
    let owner = observer
        .original
        .ok_or("native Original runtime owner absent")?
        .owner();
    let mut call = owner.borrow(scope)?;
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "ordinary fingerprint cache busy")?;
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
    let mut work = std::mem::take(&mut *cache);
    cache.ordinary_active = true;
    drop(cache);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        work.refresh(observer.apis, &mut call)?;
        let result = owner.staged_root(scope, work.view.as_ref())?;
        call.finish()?;
        Ok(result)
    }))
    .unwrap_or_else(|_| Err(RamError::Invariant("ordinary fingerprint capture panicked")));
    // Dropping the same view still attempts identity-only return after failure
    // or expiry. Its actual durable field survives every negative/refusal.
    drop(call);
    let pending = owner.has_retained_work();
    let mut cache = observer
        .cache
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let changed = !cache.ordinary_active || cache.view.is_some();
    work.ordinary_active = pending || changed;
    *cache = work;
    if changed {
        return Err(RamError::Invariant(
            "ordinary fingerprint cache return changed",
        ));
    }
    result
}

/// Shares the pure Merkle traversal with existing isolated capture fixtures.
///
/// Production implements this only with a genuine native-entered Original.
/// The private test adapter exercises tree bytes, never Source/native authority.
pub(super) trait RefreshAuthority {
    fn require_full(&self, missing_view: bool) -> Result<bool, RamError>;
    fn open(&mut self, apis: NativeApis, full: bool) -> Result<CaptureClaim, RamError>;
    fn restart(&mut self, claim: CaptureClaim) -> Result<CaptureClaim, RamError>;
    fn check_mode(&mut self, observation_only: bool) -> Result<(), RamError>;
    fn progress(&self, completed: u64) -> Result<(), RamError>;
    fn stage(
        &mut self,
        claim: CaptureClaim,
        view: Option<CachedView>,
    ) -> Result<Option<CachedView>, RamError>;
}

impl RefreshAuthority for original::Call<'_> {
    fn require_full(&self, missing_view: bool) -> Result<bool, RamError> {
        let full = self.require_full()?;
        if missing_view && !full {
            return Err(RamError::Invariant(
                "native accepted baseline lacks its module view",
            ));
        }
        Ok(full)
    }

    fn open(&mut self, apis: NativeApis, full: bool) -> Result<CaptureClaim, RamError> {
        CaptureClaim::open_logical(apis, self, full)
    }

    fn restart(&mut self, claim: CaptureClaim) -> Result<CaptureClaim, RamError> {
        claim.restart_logical(self)
    }

    fn check_mode(&mut self, observation_only: bool) -> Result<(), RamError> {
        if !observation_only {
            return Err(RamError::Invariant(
                "logical capture obtained physical ACK mode",
            ));
        }
        self.check()
    }

    fn progress(&self, completed: u64) -> Result<(), RamError> {
        if completed == 0 {
            return Err(RamError::Invariant("empty logical hash batch"));
        }
        // Successful native page output already consumed its actual witness.
        // Hash completion checks that SAME Original, never mints earlier credit.
        self.check()
    }

    fn stage(
        &mut self,
        claim: CaptureClaim,
        view: Option<CachedView>,
    ) -> Result<Option<CachedView>, RamError> {
        self.retain_stage(claim.header, view)?;
        claim.commit()?;
        Ok(None)
    }
}

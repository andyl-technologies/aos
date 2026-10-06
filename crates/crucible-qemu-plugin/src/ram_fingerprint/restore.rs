//! Stages authenticated lazy-restore identities without traversing guest RAM.
//!
//! A receipt exclusively owns observer admission until native mapping commit
//! or abort. Immutable source proofs hydrate only paths subsequently written.

// SPDX-License-Identifier: GPL-2.0-or-later

use crucible_ram::{PageProof, RootRecord};

use super::*;

/// Supplies proofs from the retained immutable restore source.
///
/// Implementations must use bounded, cancellable I/O and never enter the RAM
/// observer or plugin runtime. Source ownership outlives every derived view.
pub(crate) trait RamProofSource: Send + Sync {
    /// Returns the authenticated original inventory and scoped roots.
    fn source_record(&self) -> &RootRecord;

    /// Returns the independently admitted original root identity.
    fn source_root(&self) -> RamRootDigest;

    /// Fetches one bounded proof without inspecting live guest memory.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, deadline expiry or invalid authority.
    fn proof(&self, region_id: &str, page_index: u64) -> Result<PageProof, RamError>;
}

pub(super) struct PendingRestore {
    transaction: u64,
    view: CachedView,
}

/// Owns exclusive admission for a fully prepared restored identity.
pub(crate) struct PreparedRestoreCache {
    transaction: u64,
    completed: bool,
}

impl RootCache {
    pub(super) fn rebind_proof_source(
        &mut self,
        replacement: Arc<dyn RamProofSource>,
    ) -> Result<Arc<dyn RamProofSource>, RamError> {
        if !self.frozen || self.pending.is_some() || self.restore.is_some() {
            return Err(RamError::Invariant(
                "source rebind requires exclusive frozen child custody",
            ));
        }
        let view = self
            .view
            .as_mut()
            .ok_or("source rebind lacks a committed RAM view")?;
        let prior = view
            .source
            .as_mut()
            .ok_or("source rebind lacks an inherited immutable source")?;
        if replacement.source_root() != prior.source_root()
            || replacement.source_record() != prior.source_record()
            || replacement.source_record().scope() != Scope::Exact
            || replacement.source_record().topology() != view.snapshot.topology()
        {
            return Err(crucible_ram::RamError::DigestMismatch.into());
        }
        Ok(std::mem::replace(prior, replacement))
    }

    pub(super) fn metadata_budget(&mut self, admitted: u64) -> Result<MetadataBudget, RamError> {
        if admitted == 0 {
            return Err(RamError::Invariant(
                "RAM metadata allowance is not admitted",
            ));
        }
        if let Some(budget) = &self.budget {
            if budget.limit_bytes() != admitted {
                return Err(RamError::Invariant(
                    "RAM metadata allowance changed without re-admission",
                ));
            }
            return Ok(budget.clone());
        }
        let budget = self
            .view
            .as_ref()
            .map_or_else(|| MetadataBudget::new(admitted), |view| view.budget.clone());
        if budget.limit_bytes() != admitted {
            return Err(RamError::Invariant(
                "restored RAM metadata admission disagrees with live owner",
            ));
        }
        self.budget = Some(budget.clone());
        Ok(budget)
    }
}

/// Rebinds inherited immutable proof authority to a fresh child endpoint.
///
/// The cache remains frozen and retains its current trees, roots and records.
/// The replacement must authenticate the original base record, even when guest
/// writes have changed the current root. The returned prior-source receipt must
/// remain owned until the caller disarms inherited descriptor wrappers before
/// native descriptor reconstruction; this function never closes endpoints.
///
/// # Errors
///
/// Refuses nonexclusive custody, an absent source, or a different immutable
/// baseline or topology. It reads no guest pages and allocates no metadata.
pub(crate) fn rebind_proof_source(
    replacement: Arc<dyn RamProofSource>,
) -> Result<Arc<dyn RamProofSource>, RamError> {
    observer()?
        .cache
        .try_lock()
        .map_err(|_| RamError::Invariant("RAM source rebind observer unavailable"))?
        .rebind_proof_source(replacement)
}

/// Reads the actual native inventory under the caller's paused writer fence.
///
/// The bounded capture is aborted without reading pages or acknowledging dirty
/// obligations. Source descriptors are never substituted for native topology.
///
/// # Errors
///
/// Returns an error for missing authority, invalid native inventory or admission.
pub(crate) fn capture_restore_inventory() -> Result<
    (
        u64,
        Vec<RegionDescriptor>,
        MetadataBudget,
        MetadataReservation,
    ),
    RamError,
> {
    let observer = observer()?;
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "RAM observer has an active capture")?;
    if cache.frozen || cache.pending.is_some() || cache.restore.is_some() {
        return Err(RamError::Invariant(
            "RAM observer admission is owned by another transaction",
        ));
    }
    let claim = CaptureClaim::begin(observer.apis, false)?;
    let budget = cache.metadata_budget(claim.header.metadata_budget_bytes)?;
    let inventory_bytes = (claim.header.region_count as u64)
        .checked_mul((std::mem::size_of::<RegionDescriptor>() + 255 + 32) as u64)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("restore RAM inventory metadata overflow")?;
    let reservation = budget.reserve_bytes(inventory_bytes)?;
    let regions = read_regions(&claim)?;
    Topology::new(regions.clone(), Limits::default()).map_err(display_error)?;
    Ok((
        claim.header.topology_generation,
        regions,
        budget,
        reservation,
    ))
}

/// Prepares all restored roots and records before native mappings are discarded.
///
/// # Errors
///
/// Returns an error for mismatched source or native inventory, exhausted owner
/// metadata, or competing admission. The caller retains its writer fence through
/// commit or abort; publication performs no hashing or allocation.
pub(crate) fn prepare_restore(
    transaction: u64,
    topology_generation: u64,
    native_regions: &[RegionDescriptor],
    budget: MetadataBudget,
    snapshot: RamSnapshot,
    expected_exact: RamRootDigest,
    source: Arc<dyn RamProofSource>,
) -> Result<PreparedRestoreCache, RamError> {
    if transaction == 0 || topology_generation == 0 {
        return Err(RamError::Invariant(
            "RAM restore receipt has zero generation",
        ));
    }
    let observer = observer()?;
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "RAM observer has an active capture")?;
    if cache.frozen || cache.pending.is_some() || cache.restore.is_some() {
        return Err(RamError::Invariant(
            "RAM observer admission is already owned",
        ));
    }
    let admitted = cache.metadata_budget(budget.limit_bytes())?;
    // The constructor's budget must be the actual shared account: otherwise
    // two independent counters could each consume the same admitted bytes.
    if !admitted.shares_account_with(&budget)
        || !snapshot.metadata_budget().shares_account_with(&budget)
    {
        return Err(RamError::Invariant(
            "RAM restore uses an independent metadata account",
        ));
    }
    let topology =
        Topology::new(native_regions.to_vec(), Limits::default()).map_err(display_error)?;
    if snapshot.topology() != &topology
        || source.source_record().topology() != &topology
        || source.source_record().scope() != Scope::Exact
        || source.source_record().digest() != expected_exact
        || source.source_root() != expected_exact
        || snapshot.scoped_root(Scope::Exact).map_err(display_error)? != expected_exact
    {
        return Err(RamError::Invariant(
            "RAM restore source, root or native topology disagrees",
        ));
    }
    let roots = [
        snapshot
            .scoped_root(Scope::Execution)
            .map_err(display_error)?,
        snapshot.scoped_root(Scope::Exact).map_err(display_error)?,
        snapshot
            .scoped_root(Scope::Lifecycle)
            .map_err(display_error)?,
    ];
    let records = encode_records(&snapshot, &budget)?;
    let inventory_reservation = budget
        .reserve_bytes(
            (native_regions.len() as u64)
                .checked_mul((std::mem::size_of::<RegionDescriptor>() + 255 + 32) as u64)
                .ok_or("RAM inventory metadata overflow")?,
        )
        .map_err(display_error)?;
    let mut logical_bytes = [0_u64; 3];
    for (scope, bytes) in SCOPES.iter().zip(&mut logical_bytes) {
        for region in topology.regions() {
            if scope.includes(region.class()) {
                *bytes = bytes
                    .checked_add(region.logical_length())
                    .ok_or("RAM byte count overflow")?;
            }
        }
    }
    cache.restore = Some(PendingRestore {
        transaction,
        view: CachedView {
            topology_generation,
            budget,
            snapshot,
            roots,
            logical_bytes,
            native_regions: native_regions.to_vec(),
            records,
            source: Some(source),
            _inventory_reservation: inventory_reservation,
        },
    });
    Ok(PreparedRestoreCache {
        transaction,
        completed: false,
    })
}

impl PreparedRestoreCache {
    /// Publishes the fully prepared identity while native exclusion is retained.
    ///
    /// # Errors
    ///
    /// Returns an error if the native caller lost exclusion or this receipt is
    /// stale. After destructive mapping changes any such error invalidates the
    /// instance; execution must remain stopped.
    pub(crate) fn commit(mut self) -> Result<(), RamError> {
        // The mapping owner has crossed its irreversible boundary. Failure must
        // retain the globally staged view and source; Drop cannot abort it.
        self.completed = true;
        let observer = observer()?;
        let mut cache = observer
            .cache
            .try_lock()
            .map_err(|_| "RAM restore lost exclusive observer admission")?;
        if cache.restore.as_ref().map(|stage| stage.transaction) != Some(self.transaction) {
            return Err(RamError::Invariant("RAM restore receipt is stale"));
        }
        let stage = cache.restore.take().ok_or("RAM restore stage was lost")?;
        cache.view = Some(stage.view);
        Ok(())
    }

    /// Releases an uncommitted restore candidate without changing live identity.
    ///
    /// # Errors
    ///
    /// Returns the still-owned receipt if exclusion was lost. The caller must
    /// retain its source and registration resources while containing failure.
    pub(crate) fn abort(mut self) -> Result<(), Self> {
        if self.release().is_err() {
            return Err(self);
        }
        Ok(())
    }

    fn release(&mut self) -> Result<(), RamError> {
        if self.completed {
            return Ok(());
        }
        let observer = observer()?;
        let mut cache = observer
            .cache
            .try_lock()
            .map_err(|_| "RAM restore abort lost exclusive observer admission")?;
        if cache.restore.as_ref().map(|stage| stage.transaction) != Some(self.transaction) {
            return Err(RamError::Invariant("RAM restore abort receipt is stale"));
        }
        cache.restore = None;
        self.completed = true;
        Ok(())
    }
}

impl Drop for PreparedRestoreCache {
    fn drop(&mut self) {
        // A lost exclusion retains the staged view and source lease, preventing
        // an accidental successful abort or further guest admission.
        let _ = self.release();
    }
}

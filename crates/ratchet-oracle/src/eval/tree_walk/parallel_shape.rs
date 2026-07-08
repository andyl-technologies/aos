//! Shared hidden-class shape interning for parallel evaluation (L2-P4).
//!
//! Hidden-class attr projection stores dense [`ShapeId`]s in shared heap
//! attrs metadata. Under multi-worker parallel mode those ids are read by
//! workers that did not project them, so the P3b landing disabled projection
//! entirely at `K >= 2`. This module restores it with the same append-only
//! prefix-replica pattern the shared symbol and module logs use:
//!
//! - one authoritative [`ShapeTable`] lives in [`SharedShapeLog`] behind an
//!   `RwLock`, seeded from the main evaluator's table at pool spawn;
//! - every worker's local `shape_table` is a prefix replica seeded through
//!   [`ShapeTable::replica`], so record `Arc`s are shared and a `ShapeId` is
//!   the same shape on every worker;
//! - transitions that resolve from existing local state (existing keys and
//!   cached edges - the steady-state hot path) stay lock-free; a locally
//!   unknown edge resolves under the shared read lock, and only a globally
//!   new shape takes the write lock, interns into the authoritative table,
//!   and replays locally through the ordinary dedup path so the local edge
//!   cache warms up.
//!
//! Multi-worker projection stays **off by default**
//! ([`TreeWalkOptions::parallel_shape_projection`]): on the measured package
//! corpus the hidden-class projection plus transient shaped-select machinery
//! costs more than shaped lookups save (serial pays the same per-allocation
//! projection cost, and the gap widens with worker count). This module makes
//! projection *sound* at `K >= 2`; enabling it is a performance decision.
//!
//! # Replica freshness
//!
//! A foreign attrs value carrying a projected `ShapeId` can only become
//! visible after the projecting worker interned that shape into the shared
//! log (the shape mutex release happens-before the value-publishing edge), so
//! syncing the replica at the standard ingestion points - plus the lazy
//! [`TreeWalk::shaped_handle_for_projected_shape`] resync fallback - always
//! resolves foreign ids.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::*;

/// Recovers a read guard, ignoring poisoning (see `parallel_demand::recover`).
fn recover_read<T: ?Sized>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Recovers a write guard, ignoring poisoning (see `parallel_demand::recover`).
fn recover_write<T: ?Sized>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The authoritative shape table behind every worker's prefix replica.
///
/// The table sits behind an `RwLock` rather than a mutex because the
/// steady-state choke-point traffic is read-shaped: workers that miss a
/// transition in their local edge cache look the edge up in the authoritative
/// table (and replicate its record suffix) far more often than anyone interns
/// a genuinely new shape. Readers proceed concurrently; only new-shape
/// interning takes the write lock.
#[derive(Debug)]
pub(crate) struct SharedShapeLog {
    /// Published record count of `table`; release-stored after each append.
    version: AtomicUsize,
    table: RwLock<ShapeTable>,
}

impl SharedShapeLog {
    /// Seeds the log with a replica of the main evaluator's shape table.
    ///
    /// Returns `None` when the main evaluator runs without a shape table or
    /// replica storage cannot be reserved; parallel evaluation then keeps
    /// projection disabled exactly like the pre-P4 behavior.
    pub(super) fn seed(main: Option<&ShapeTable>) -> Option<Self> {
        let table = main?.replica().ok()?;
        Some(Self {
            version: AtomicUsize::new(table.len()),
            table: RwLock::new(table),
        })
    }

    /// Clones the authoritative table into a fresh worker replica.
    pub(super) fn replica(&self) -> Option<ShapeTable> {
        recover_read(&self.table).replica().ok()
    }

    /// Appends the log's unseen record suffix onto a worker's prefix replica.
    ///
    /// Cheap when already current: one acquire load. Returns `false` if the
    /// replica could not reserve storage, in which case the caller should
    /// disable local projection rather than continue with a stale prefix.
    fn sync_into(&self, local: &mut ShapeTable) -> bool {
        if self.version.load(Ordering::Acquire) <= local.len() {
            return true;
        }
        let table = recover_read(&self.table);
        table.replicate_suffix_into(local).is_ok()
    }
}

impl TreeWalk {
    /// Refreshes the local shape-table replica from the shared shape log.
    ///
    /// Called from [`TreeWalk::sync_shared_context`] at every foreign-value
    /// ingestion point. On replica-storage failure the local table is dropped,
    /// which disables further projection on this worker (readers fall back to
    /// flat lookups) instead of leaving a replica that could miss foreign ids.
    pub(super) fn sync_shared_shape_table(&mut self, shared: &parallel_demand::SharedEvalContext) {
        let Some(log) = shared.shapes.as_ref() else {
            return;
        };
        let Some(local) = self.shape_table.as_mut() else {
            return;
        };
        if !log.sync_into(local) {
            tracing::warn!(
                target: "aos_nix::eval::parallel",
                "shared shape log sync failed; disabling shape projection on this worker"
            );
            self.shape_table = None;
        }
    }

    /// Resolves one shape transition through the shared log when present.
    ///
    /// This is the single choke point for evaluator shape interning under
    /// parallel mode: transitions that resolve from existing local state stay
    /// lock-free, and a transition that must intern a new shape first interns
    /// it into the authoritative shared table (so its dense id is global),
    /// then replays locally through the ordinary dedup path to warm the local
    /// edge cache. Serial mode transitions directly on the local table.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError`] when the transition fails validation or table
    /// storage cannot be reserved; callers treat any error as "skip
    /// projection for this attrset", matching the serial telemetry policy.
    pub(super) fn shape_transition_insert_key_for_eval(
        &mut self,
        shape: &ShapeHandle,
        key: Symbol,
    ) -> Result<ShapeTableTransition, ShapeError> {
        let Some(local) = self.shape_table.as_mut() else {
            return Err(ShapeError::UnknownShapeId { id: shape.id() });
        };
        // Steady-state fast path for serial and parallel alike: existing keys
        // and cached edges resolve by symbol identity without the mutating
        // path's per-record symbol validation (the evaluator drives every
        // table from one symbol universe by construction).
        if let Some(transition) = local.transition_insert_key_cached(shape, key)? {
            return Ok(transition);
        }
        let shared = match self.shared.as_ref().and_then(|shared| shared.shapes.as_ref()) {
            None => return local.transition_insert_key(shape, key, &self.symbols),
            Some(shared) => shared,
        };
        // Read phase: another worker usually interned this edge already, so a
        // shared read lock (concurrent with other readers) resolving the edge
        // plus a record-suffix replication covers the common miss.
        let known_globally = {
            let table = recover_read(&shared.table);
            let known = table.transition_insert_key_cached(shape, key)?.is_some();
            if known {
                table.replicate_suffix_into(local)?;
            }
            known
        };
        // Write phase, only when the edge was unknown globally: intern the
        // (possibly new) child shape into the authoritative table under the
        // write lock, then bring the local replica to the tip.
        if !known_globally {
            let mut table = recover_write(&shared.table);
            table.transition_insert_key(shape, key, &self.symbols)?;
            table.replicate_suffix_into(local)?;
            shared.version.store(table.len(), Ordering::Release);
        }
        // The local replica now holds the child record, so the local replay
        // dedups onto the same global id while caching the parent edge for
        // future lock-free transitions.
        let transition = local.transition_insert_key(shape, key, &self.symbols)?;
        debug_assert!(
            (transition_child_id(&transition).unwrap_or(0) as usize) < local.len(),
            "local shape replay escaped the shared log tip"
        );
        Ok(transition)
    }

    /// Resolves a projected [`ShapeId`] read from attrs metadata to a handle.
    ///
    /// Under parallel mode a foreign id may postdate this worker's last
    /// ingestion sync, so an unknown id triggers one shape-replica resync
    /// before failing: the projecting worker interned the shape into the
    /// shared log before the attrs value could become visible here.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError::UnknownShapeId`] when the id is missing from the
    /// local table (and, under parallel mode, from the shared log), or the
    /// table is disabled.
    pub(super) fn shaped_handle_for_projected_shape(
        &mut self,
        projected_shape: ShapeId,
    ) -> Result<ShapeHandle, ShapeError> {
        if let Some(local) = self.shape_table.as_ref() {
            if let Ok(handle) = local.handle(projected_shape) {
                return Ok(handle);
            }
        }
        let shared = self.shared.clone();
        if let Some(shared) = shared {
            self.sync_shared_shape_table(&shared);
            if let Some(local) = self.shape_table.as_ref() {
                return local.handle(projected_shape);
            }
        }
        Err(ShapeError::UnknownShapeId {
            id: projected_shape,
        })
    }
}

/// Returns the child record id of an append transition, if any.
fn transition_child_id(transition: &ShapeTableTransition) -> Option<u32> {
    match transition {
        ShapeTableTransition::ExistingKey { .. } => None,
        ShapeTableTransition::AppendKey { child, .. } => Some(child.id().as_u32()),
    }
}

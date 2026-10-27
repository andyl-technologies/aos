//! Block snapshots, restore, checkpoint boundaries, and materialization.

use super::super::page_store::BlockPageStore;
use super::*;

impl BlockDevice {
    /// Snapshots the device half of a `MaterializedState` ([IO-11], [IO-23]).
    ///
    /// Captures the overlay as a frozen chunk image that shares the live page
    /// store (no page bytes are copied), the **dirty page set** (so a
    /// mid-epoch snapshot/restore preserves which pages changed since the last
    /// boundary, [IO-7]), the device RNG cursor, the active fault table, the
    /// latency model parameters (part of the `World`, [IO-10]), the in-flight
    /// responses with their delivery icounts, the base hash, and the device
    /// length -- **never** the base image bytes ([TEMP-9]). The dirty set is
    /// *not* cleared here; call [`BlockDevice::checkpoint_boundary`] after the
    /// snapshot to begin a disjoint successor dirty set.
    #[must_use]
    pub fn snapshot(&self) -> BlockSnapshot {
        BlockSnapshot {
            core: self.core.snapshot(),
            base_hash: self.base.hash(),
            device_length: self.base.len(),
            overlay: self.overlay.freeze(self.base.len()),
            storage_faults: self.storage_faults.clone(),
            latency: self.latency,
        }
    }

    /// Clears the overlay dirty set at a checkpoint boundary ([IO-7]).
    ///
    /// Call this *after* [`BlockDevice::snapshot`] so the next snapshot's
    /// dirty set holds only pages written afterward.
    pub fn checkpoint_boundary(&mut self) {
        self.overlay.clear_dirty();
    }

    /// Restores a device from a snapshot over `base`, writing new pages to `store`.
    ///
    /// The snapshot's overlay image is rebuilt: chunks frozen from a live
    /// overlay are shared without copying, and stored chunks are read one at
    /// a time from the snapshot's bound chunk source, authenticated, and
    /// written to `store`. The **dirty page set** is restored verbatim (so
    /// the next checkpoint sees the same dirty set an uninterrupted run would,
    /// [IO-7]), the RNG position and the snapshot's **latency model** are
    /// restored (the latency params are part of the `World`, [IO-10]), and
    /// the in-flight responses are re-armed via the core snapshot ([IO-11]).
    /// The base image is supplied separately (it is content-addressed and
    /// shared, never carried in the snapshot, [TEMP-9]); the restore verifies
    /// its hash matches.
    ///
    /// The restored state is byte-identical to an uninterrupted run ([IO-11],
    /// [IO-22], [IO-28]): the same overlay content, dirty bookkeeping,
    /// completion model, and in-flight queue, so post-restore
    /// `delivery_icount`s and payloads match exactly.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BaseMismatch`] when `base`'s hash differs from the
    /// snapshot's `base_hash`, [`DeviceError::BlockOverlayImage`] when a stored
    /// overlay chunk is missing or fails authentication,
    /// [`DeviceError::BlockPageStore`] when `store` fails, and any
    /// [`DeviceError`] [`IoCore::restore`] raises.
    pub fn restore(
        snapshot: &BlockSnapshot,
        base: BaseImage,
        store: &BlockPageStore,
    ) -> Result<Self, DeviceError> {
        Self::validate_restore_shape(snapshot, &base)?;
        let core = IoCore::restore(&snapshot.core)?;
        let overlay = snapshot.overlay.materialize_into(store)?;
        Ok(Self {
            core,
            base,
            overlay,
            storage_faults: snapshot.storage_faults.clone(),
            // Restore the snapshot's latency model so post-restore completion
            // icounts match an uninterrupted run ([IO-10], [IO-22]); never
            // substitute the default, which would silently diverge.
            latency: snapshot.latency,
        })
    }

    /// Checks that `snapshot` would restore over `base` without restoring it.
    ///
    /// This validates the base binding, geometry, nested continuations, and
    /// in-flight queue, and authenticates every stored overlay chunk through
    /// the bound source with at most one chunk resident. No page is written,
    /// so a prepare step can call it before an irreversible commit.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`BlockDevice::restore`] other than page-store
    /// write failures.
    pub fn validate_restore(snapshot: &BlockSnapshot, base: &BaseImage) -> Result<(), DeviceError> {
        Self::validate_restore_shape(snapshot, base)?;
        IoCore::restore(&snapshot.core)?;
        snapshot.overlay.verify()
    }

    fn validate_restore_shape(
        snapshot: &BlockSnapshot,
        base: &BaseImage,
    ) -> Result<(), DeviceError> {
        if base.hash() != snapshot.base_hash {
            return Err(DeviceError::BaseMismatch {
                expected: snapshot.base_hash,
                found: base.hash(),
            });
        }
        snapshot
            .storage_faults
            .validate_restore(snapshot.device_length)?;
        if snapshot.device_length != base.len() || snapshot.overlay.length() != base.len() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "snapshot storage length differs from the base image",
            });
        }
        Ok(())
    }

    /// Replaces this device with an authenticated snapshot over its current base image.
    ///
    /// This is the process-independent restore seam used by an already-instantiated
    /// scheduler: the immutable base and the page store remain owned by the
    /// admitted device, while every mutable core, overlay, durability, fault,
    /// and latency field comes from `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`BlockDevice::restore`] if the snapshot does
    /// not match the admitted base image or contains invalid device state.
    pub fn restore_snapshot(&mut self, snapshot: &BlockSnapshot) -> Result<(), DeviceError> {
        let store = self.overlay.store().clone();
        let restored = Self::restore(snapshot, self.base.clone(), &store)?;
        *self = restored;
        Ok(())
    }

    /// Streams the full current disk image to `output`: base with overlay applied.
    ///
    /// The hand-off for the real-time QEMU path ([IO-12]): a standalone raw image
    /// QEMU can mount. The base image is **not** mutated ([INV-5]) and no
    /// full-device buffer is allocated.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BlockPageStore`] when an overlay page cannot be
    /// read or `output` rejects a write.
    pub fn materialize_to(&self, output: &mut dyn std::io::Write) -> Result<(), DeviceError> {
        self.overlay.materialize_to(&self.base, output)
    }
}

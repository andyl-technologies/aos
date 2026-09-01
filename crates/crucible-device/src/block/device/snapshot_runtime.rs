//! Block snapshots, restore, checkpoint boundaries, and materialization.

use super::*;

impl BlockDevice {
    /// Snapshots the device half of a `MaterializedState` ([IO-11], [IO-23]).
    ///
    /// Captures the overlay **delta** (only pages dirtied since the last
    /// checkpoint boundary), the **dirty page set itself** (so a mid-epoch
    /// snapshot/restore preserves which pages still owe the next checkpoint a
    /// delta, [IO-7]), the device RNG cursor, the active fault table, the latency model
    /// parameters (part of the `World`, [IO-10]), the in-flight responses with
    /// their delivery icounts, the base hash, and the device length -- **never**
    /// the base image bytes ([TEMP-9]). The dirty set is *not* cleared here;
    /// call [`BlockDevice::checkpoint_boundary`] after taking the delta to begin
    /// a disjoint successor delta.
    #[must_use]
    pub fn snapshot(&self) -> BlockSnapshot {
        BlockSnapshot {
            core: self.core.snapshot(),
            base_hash: self.base.hash(),
            device_length: self.base.len(),
            overlay_delta: self.overlay.dirty_delta(),
            full_pages: self.overlay.all_pages().clone(),
            dirty: self.overlay.dirty_pages().clone(),
            storage_faults: self.storage_faults.clone(),
            latency: self.latency,
        }
    }

    /// Clears the overlay dirty set at a checkpoint boundary ([IO-7]).
    ///
    /// Call this *after* [`BlockDevice::snapshot`] captures the delta so the next
    /// snapshot captures only pages dirtied afterward, giving successive
    /// checkpoints disjoint deltas.
    pub fn checkpoint_boundary(&mut self) {
        self.overlay.clear_dirty();
    }

    /// Restores a device from a snapshot stacked over a parent overlay.
    ///
    /// The parent overlay (the materialized state up to the snapshot's parent) is
    /// passed in `parent`; the snapshot's delta is stacked on top, the **dirty
    /// page set** is restored verbatim (so the next checkpoint emits the same
    /// delta an uninterrupted run would, [IO-7]), the RNG position and the
    /// snapshot's **latency model** are restored (the latency params are part of
    /// the `World`, [IO-10]), and the in-flight responses are re-armed via the
    /// core snapshot ([IO-11]). The base image is supplied separately (it is
    /// content-addressed and shared, never carried in the snapshot, [TEMP-9]);
    /// the restore verifies its hash matches.
    ///
    /// The restored state is byte-identical to an uninterrupted run ([IO-11],
    /// [IO-22], [IO-28]): the same dirty bookkeeping, the same completion model,
    /// and the same in-flight queue, so post-restore `delivery_icount`s and
    /// payloads match exactly.
    ///
    /// Pass `parent = None` to restore a self-contained snapshot whose captured
    /// `full_pages` already hold the complete overlay (the common in-process case
    /// where there is no separate parent chain).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::BaseMismatch`] when `base`'s hash differs from the
    /// snapshot's `base_hash`, and any [`DeviceError`] [`IoCore::restore`] raises.
    pub fn restore(
        snapshot: &BlockSnapshot,
        base: BaseImage,
        parent: Option<&CowOverlay>,
    ) -> Result<Self, DeviceError> {
        if base.hash() != snapshot.base_hash {
            return Err(DeviceError::BaseMismatch {
                expected: snapshot.base_hash,
                found: base.hash(),
            });
        }
        snapshot
            .storage_faults
            .validate_restore(snapshot.device_length)?;
        if snapshot.device_length != base.len() {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "snapshot storage length differs from the base image",
            });
        }
        let core = IoCore::restore(&snapshot.core)?;
        let overlay = match parent {
            Some(parent) => {
                let mut overlay = parent.clone();
                overlay.apply_delta(&snapshot.overlay_delta);
                // Restore the dirty set the snapshot captured ([IO-7]); the
                // applied delta is not implicitly clean, and clearing it here
                // would lose pages the next checkpoint still owes.
                overlay.set_dirty(snapshot.dirty.clone());
                overlay
            }
            None => CowOverlay::from_parts(snapshot.full_pages.clone(), snapshot.dirty.clone()),
        };
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

    /// Replaces this device with an authenticated snapshot over its current base image.
    ///
    /// This is the process-independent restore seam used by an already-instantiated
    /// scheduler: the immutable base remains owned by the admitted `World`, while
    /// every mutable core, overlay, durability, fault, and latency field comes from
    /// `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`BlockDevice::restore`] if the snapshot does
    /// not match the admitted base image or contains invalid device state.
    pub fn restore_snapshot(&mut self, snapshot: &BlockSnapshot) -> Result<(), DeviceError> {
        let restored = Self::restore(snapshot, self.base.clone(), None)?;
        *self = restored;
        Ok(())
    }

    /// Restores while overriding the latency model from the `World`.
    ///
    /// Like [`BlockDevice::restore`] but takes the `latency` model explicitly.
    /// Plain [`BlockDevice::restore`] already restores the snapshot's recorded
    /// latency faithfully; use this only when the caller authoritatively re-binds
    /// the latency parameters from the live `World` ([IO-10]).
    ///
    /// # Errors
    ///
    /// Same as [`BlockDevice::restore`].
    pub fn restore_with_latency(
        snapshot: &BlockSnapshot,
        base: BaseImage,
        parent: Option<&CowOverlay>,
        latency: BlockLatency,
    ) -> Result<Self, DeviceError> {
        let mut device = Self::restore(snapshot, base, parent)?;
        device.latency = latency;
        Ok(device)
    }

    /// Materializes the full current disk image: base with overlay applied.
    ///
    /// The hand-off for the real-time QEMU path ([IO-12]): a standalone raw image
    /// QEMU can mount. The base image is **not** mutated ([INV-5]); a fresh `Vec`
    /// is produced.
    #[must_use]
    pub fn materialize(&self) -> Vec<u8> {
        self.overlay.materialize(&self.base)
    }
}

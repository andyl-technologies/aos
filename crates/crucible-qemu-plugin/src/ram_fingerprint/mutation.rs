//! Prepares complete fault-mutation identities before physical guest writes.
//!
//! Batch actions extend an unpublished immutable candidate. Commit only moves
//! admitted snapshots and encoded records; native resource and writer fences
//! remain prerequisites rather than responsibilities of this observer.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

pub(super) extern "C" fn observe_transaction(
    phase: u32,
    transaction: u64,
    topology_generation: u64,
    pages: *const PreparedPage,
    count: usize,
    root: *mut u8,
    logical_bytes: *mut u64,
) -> c_int {
    if transaction == 0
        || topology_generation == 0
        || phase > 2
        || root.is_null()
        || logical_bytes.is_null()
        || count > MAX_PREPARED_PAGES
        || (phase == 0 && (pages.is_null() || count == 0))
        || (phase != 0 && count != 0)
    {
        return -libc::EINVAL;
    }
    // SAFETY: QEMU lends these writable outputs until this call returns.
    unsafe {
        std::ptr::write_bytes(root, 0, 32);
        logical_bytes.write(0);
    }
    let result = std::panic::catch_unwind(|| -> Result<([u8; 32], u64), RamError> {
        let observer = observer()?;
        let mut cache = observer
            .cache
            .try_lock()
            .map_err(|_| "RAM observer has an active capture")?;
        if cache.frozen || cache.restore.is_some() {
            return Err(RamError::Invariant("RAM observer is frozen"));
        }
        if phase == 0 {
            // SAFETY: native preparation lends `count` complete page descriptors
            // and their owned afterimages under its retained writer fence.
            let pages = unsafe { std::slice::from_raw_parts(pages, count) };
            cache.prepare_mutation(transaction, topology_generation, pages)?;
        } else {
            cache.finish_mutation(transaction, topology_generation, phase == 1)?;
        }
        let view = cache.view.as_ref().ok_or("missing RAM mutation baseline")?;
        let digest = cache
            .pending
            .as_ref()
            .map_or(view.roots[0], |pending| pending.roots[0]);
        Ok((*digest.as_bytes(), view.logical_bytes[0]))
    });
    match result {
        Ok(Ok((digest, bytes))) => {
            // SAFETY: the same borrowed output storage remains valid.
            unsafe {
                std::ptr::copy_nonoverlapping(digest.as_ptr(), root, 32);
                logical_bytes.write(bytes);
            }
            0
        }
        Ok(Err(_)) | Err(_) => -libc::EIO,
    }
}

impl RootCache {
    pub(super) fn prepare_mutation(
        &mut self,
        transaction: u64,
        topology_generation: u64,
        pages: &[PreparedPage],
    ) -> Result<(), RamError> {
        if self.pending.as_ref().is_some_and(|pending| {
            pending.transaction != transaction || pending.topology_generation != topology_generation
        }) {
            return Err(RamError::Invariant("another RAM mutation is prepared"));
        }
        let view = self
            .view
            .as_ref()
            .ok_or("RAM mutation lacks a coherent baseline")?;
        if view.topology_generation != topology_generation {
            return Err(RamError::Invariant(
                "RAM mutation topology generation is stale",
            ));
        }
        // Batch actions may overlap. Extend their virtual afterimages without
        // publishing them until every action has prepared and committed.
        let mut snapshot = self
            .pending
            .as_ref()
            .map_or_else(|| view.snapshot.clone(), |pending| pending.snapshot.clone());
        let mut previous = None;
        let mut batch_region = None;
        let _batch_reservation = view
            .budget
            .reserve_bytes((UPDATE_BATCH * std::mem::size_of::<(u64, PageDigest)>()) as u64)
            .map_err(display_error)?;
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(UPDATE_BATCH)
            .map_err(display_error)?;
        for page in pages {
            let index = page.region_index as usize;
            let region = view
                .native_regions
                .get(index)
                .ok_or("absent RAM mutation region")?;
            let coordinate = (index, page.page_index);
            if previous.is_some_and(|last| coordinate <= last)
                || page.bytes.is_null()
                || page.page_version == 0
                || !matches!(
                    region.class(),
                    RegionClass::MutableMain | RegionClass::MutableDevice
                )
                || page.valid_length
                    != region
                        .geometry()
                        .valid_length(page.page_index)
                        .map_err(display_error)?
            {
                return Err(RamError::Invariant("invalid RAM mutation candidate page"));
            }
            if batch_region.is_some_and(|last| last != index) || batch.len() == UPDATE_BATCH {
                snapshot = apply_batch(
                    snapshot,
                    &view.native_regions,
                    batch_region,
                    &mut batch,
                    view.source.as_deref(),
                )?;
            }
            let valid_length = page.valid_length as usize;
            // SAFETY: native preparation lends this complete valid-length
            // afterimage until callback return. No address is retained.
            let bytes = unsafe { std::slice::from_raw_parts(page.bytes, valid_length) };
            batch.push((
                page.page_index,
                PageDigest::hash(bytes).map_err(display_error)?,
            ));
            batch_region = Some(index);
            previous = Some(coordinate);
        }
        snapshot = apply_batch(
            snapshot,
            &view.native_regions,
            batch_region,
            &mut batch,
            view.source.as_deref(),
        )?;
        let roots = [
            snapshot
                .scoped_root(Scope::Execution)
                .map_err(display_error)?,
            snapshot.scoped_root(Scope::Exact).map_err(display_error)?,
            snapshot
                .scoped_root(Scope::Lifecycle)
                .map_err(display_error)?,
        ];
        let records = encode_records(&snapshot, &view.budget)?;
        self.pending = Some(PendingMutation {
            transaction,
            topology_generation,
            snapshot,
            roots,
            records,
        });
        Ok(())
    }

    pub(super) fn finish_mutation(
        &mut self,
        transaction: u64,
        topology_generation: u64,
        commit: bool,
    ) -> Result<(), RamError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("RAM mutation was not prepared")?;
        if pending.transaction != transaction || pending.topology_generation != topology_generation
        {
            return Err(RamError::Invariant("RAM mutation receipt is stale"));
        }
        if self.view.is_none() {
            return Err(RamError::Invariant("RAM mutation baseline was lost"));
        }
        let pending = self
            .pending
            .take()
            .ok_or("RAM mutation candidate was lost")?;
        if commit {
            let view = self.view.as_mut().ok_or("RAM mutation baseline was lost")?;
            view.snapshot = pending.snapshot;
            view.roots = pending.roots;
            view.records = pending.records;
        }
        Ok(())
    }
}

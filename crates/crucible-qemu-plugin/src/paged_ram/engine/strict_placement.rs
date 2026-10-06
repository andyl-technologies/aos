//! Completes strict placement before publishing generation-bound policy evidence.
//!
//! Disk evidence records a coherent authenticated cut, not a promise that later
//! writes are synchronously persisted. Locked evidence remains live until the
//! exact retained spans are successfully unlocked. No queued command is evidence
//! of either guarantee.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::fs::File;

use crucible_protocol::ram_control::{RamControlMode, RamControlPlacementReceipt};

use super::locking::LockedMemory;
use super::placement::PhysicalPlacement;
use super::*;

pub(super) struct LockTransition {
    ownership: Arc<LockedMemory>,
    mappings: File,
}

impl PhysicalPlacement<'_> {
    pub(super) fn prepare_locks(&self) -> Result<Option<LockTransition>, RamError> {
        if self.activate {
            return Ok(None);
        }
        if !self.establish_guarantee && self.mode == RamControlMode::ResidentRequired {
            return Ok(None);
        }
        let existing = self
            .owner
            .locks
            .try_lock()
            .map_err(|_| "guest lock ownership unavailable")?
            .clone();
        let ownership = match existing {
            Some(ownership) => ownership,
            None if self.mode == RamControlMode::ResidentRequired => {
                let ownership = LockedMemory::prepare(&self.service)?;
                *self
                    .owner
                    .locks
                    .try_lock()
                    .map_err(|_| "guest lock ownership unavailable")? = Some(ownership.clone());
                ownership
            }
            None => return Ok(None),
        };
        // Descriptor membership is frozen by native physical exclusion. Open
        // verification before acquiring that certificate and close after release.
        let mappings = File::open("/proc/self/smaps")?;
        Ok(Some(LockTransition {
            ownership,
            mappings,
        }))
    }

    pub(super) fn apply_placement(
        &mut self,
        locks: &mut Option<LockTransition>,
    ) -> Result<(), RamError> {
        self.check_policy_generation()?;
        if !self.establish_guarantee && self.mode != RamControlMode::Managed {
            if self.mode == RamControlMode::DiskOriented {
                self.reclaim_pages()?;
            }
            return Ok(());
        }
        let operation = self
            .operation
            .as_ref()
            .ok_or("placement supervisor absent")?
            .clone();
        if self.mode != RamControlMode::ResidentRequired
            && let Some(locks) = locks
        {
            // Clear live lock evidence immediately before the first unlock,
            // retaining actual span custody until complete kernel verification.
            *self
                .owner
                .placement_receipt
                .try_lock()
                .map_err(|_| "placement evidence unavailable")? = None;
            locks
                .ownership
                .unlock(&mut locks.mappings, operation.as_ref(), || {
                    self.progress_work()
                })?;
            *self
                .owner
                .locks
                .try_lock()
                .map_err(|_| "guest lock ownership unavailable")? = None;
        }
        let (locked_bytes, disk_pages, disk_bytes, writer_generation) = match self.mode {
            RamControlMode::Managed => {
                self.reclaim_pages()?;
                return Ok(());
            }
            RamControlMode::ResidentRequired => {
                *self
                    .service
                    .placement_dependency
                    .try_lock()
                    .map_err(|_| "placement dependency unavailable")? = Some(operation.clone());
                let locks = locks.as_mut().ok_or("guest lock preparation absent")?;
                if locks.ownership.verified_bytes().is_some() {
                    locks
                        .ownership
                        .verify(&mut locks.mappings, operation.as_ref(), || {
                            self.progress_work()
                        })?;
                } else {
                    locks
                        .ownership
                        .lock(&mut locks.mappings, operation.as_ref(), || {
                            self.progress_work()
                        })?;
                }
                (
                    locks
                        .ownership
                        .verified_bytes()
                        .ok_or("guest locks unverified")?,
                    0,
                    0,
                    0,
                )
            }
            RamControlMode::DiskOriented => {
                let generation = self.writer_generation()?;
                let (pages, bytes) = self.preserve_complete_disk_cut(generation)?;
                if self.writer_generation()? != generation {
                    return Err(RamError::Invariant(
                        "RAM writer generation changed during disk cut",
                    ));
                }
                self.reclaim_pages()?;
                (0, pages, bytes, generation)
            }
        };
        self.check_policy_generation()?;
        let epoch = self
            .owner
            .placement_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| "placement epoch exhausted")?
            + 1;
        self.receipt = Some(RamControlPlacementReceipt {
            mode: self.mode,
            policy_revision: self.policy_revision,
            topology_generation: self.generation,
            placement_epoch: epoch,
            locked_bytes,
            disk_preserved_logical_pages: disk_pages,
            disk_preserved_logical_bytes: disk_bytes,
            ram_write_generation_at_cut: writer_generation,
        });
        Ok(())
    }

    pub(super) fn publish_placement(&mut self, completed: bool) -> Result<(), RamError> {
        self.check_policy_generation()?;
        if !self.establish_guarantee && self.mode != RamControlMode::Managed {
            return Ok(());
        }
        if self.mode == RamControlMode::ResidentRequired && completed {
            self.service
                .placement_dependency
                .try_lock()
                .map_err(|_| "placement dependency unavailable")?
                .take();
        }
        if self.mode == RamControlMode::Managed {
            *self
                .owner
                .placement_receipt
                .try_lock()
                .map_err(|_| "placement evidence unavailable")? = None;
        } else {
            let receipt = self
                .receipt
                .take()
                .ok_or("strict placement completion absent")?;
            if completed {
                *self
                    .owner
                    .placement_receipt
                    .try_lock()
                    .map_err(|_| "placement evidence unavailable")? = Some(receipt);
            } else {
                *self
                    .owner
                    .prepared_placement_receipt
                    .try_lock()
                    .map_err(|_| "placement evidence unavailable")? = Some(receipt);
            }
        }
        Ok(())
    }

    fn check_policy_generation(&self) -> Result<(), RamError> {
        if self.policy_revision == 0
            || self.owner.requested_policy_revision.load(Ordering::Acquire) != self.policy_revision
            || self.owner.policy_generation.load(Ordering::Acquire) != self.policy_generation
        {
            return Err(RamError::Invariant(
                "physical placement policy was superseded",
            ));
        }
        Ok(())
    }

    fn writer_generation(&self) -> Result<u64, RamError> {
        let mut generation = 0;
        let status =
            (self.service.native.write_generation)(self.token, self.generation, &mut generation);
        if status != 0 || generation == 0 {
            return Err(RamError::Native {
                operation: "coherent RAM writer generation",
                status,
            });
        }
        Ok(generation)
    }

    fn preserve_complete_disk_cut(&self, writer_generation: u64) -> Result<(u64, u64), RamError> {
        let mut scratch = [0_u8; PAGE_BYTES];
        let mut pages = 0_u64;
        let mut logical_bytes = 0_u64;
        for arena in &self.service.arenas {
            for page in 0..arena.native.logical_length.div_ceil(PAGE_BYTES as u64) {
                self.check_budget()?;
                let valid = (arena.native.logical_length - page * PAGE_BYTES as u64)
                    .min(PAGE_BYTES as u64) as u32;
                let coordinate = arena.page_start
                    + usize::try_from(page).map_err(|_| "disk cut coordinate overflow")?;
                let state = self
                    .service
                    .states
                    .try_lock()
                    .map_err(|_| "disk cut page state unavailable")?
                    .get(coordinate)
                    .ok_or("disk cut page absent")?
                    .clone();
                // Pinned device RAM can change through native authors without a
                // UFFD transition. Its coherent cut version is the native writer
                // generation, rather than the pager's page-local version.
                let version = if arena.placement == ArenaPlacement::Pageable {
                    state.version
                } else {
                    writer_generation
                };
                let current_record = state.preserved.as_ref().filter(|record| {
                    disk_record_is_current(
                        arena.placement == ArenaPlacement::Pageable,
                        state.writable,
                        version,
                        valid,
                        record.page_version(),
                        record.valid_length(),
                    )
                });
                if let Some(record) = current_record {
                    let operation = self
                        .service
                        .operations
                        .begin(SourceOperationClass::Writeback)?;
                    self.service
                        .spill
                        .try_lock()
                        .map_err(|_| "disk cut backing unavailable")?
                        .read(record, &mut scratch)
                        .map_err(|error| self.owner.writeback_failure(error.into()))?;
                    operation.complete()?;
                    count_completed(&self.service.counters.preserved_reads)?;
                } else {
                    if state.resident {
                        scratch.fill(0);
                        let address = arena.native.host_address + page * PAGE_BYTES as u64;
                        // SAFETY: retained complete physical exclusion owns this
                        // exact logical range, including partial pinned tails.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                address as *const u8,
                                scratch.as_mut_ptr(),
                                valid as usize,
                            )
                        };
                    } else if self
                        .service
                        .read_cold(arena, page, coordinate, true, &mut scratch)?
                        != valid
                    {
                        return Err(RamError::Invariant("disk cut source length changed"));
                    }
                    let operation = self
                        .service
                        .operations
                        .begin(SourceOperationClass::Writeback)?;
                    super::placement::pace_writeback(operation.as_ref(), self.writeback_rate)?;
                    let record = self
                        .service
                        .spill
                        .try_lock()
                        .map_err(|_| "disk cut backing unavailable")?
                        .preserve(&scratch, valid, version)
                        .map_err(|error| self.owner.writeback_failure(error.into()))?;
                    operation.complete()?;
                    count_completed(&self.service.counters.preserved_writes)?;
                    self.service
                        .states
                        .try_lock()
                        .map_err(|_| "disk cut state unavailable")?
                        .get_mut(coordinate)
                        .ok_or("disk cut coordinate absent")?
                        .preserved = Some(record);
                }
                if arena.placement == ArenaPlacement::Pageable && state.resident && state.writable {
                    // Keeping a resident page after this cut must not let a
                    // later store retain the version of its preserved bytes.
                    // Native exclusion still prevents every logical accessor.
                    self.check_budget()?;
                    self.service.registration.protect(
                        arena.native.host_address + page * PAGE_BYTES as u64,
                        PAGE_BYTES as u64,
                        true,
                    )?;
                    let mut states = self
                        .service
                        .states
                        .try_lock()
                        .map_err(|_| "disk cut write ownership unavailable")?;
                    let current = states.get_mut(coordinate).ok_or("disk cut page absent")?;
                    if current.version != state.version || !current.resident {
                        return Err(RamError::Invariant(
                            "disk cut page changed under physical exclusion",
                        ));
                    }
                    current.writable = false;
                }
                pages = pages.checked_add(1).ok_or("disk cut page count overflow")?;
                logical_bytes = logical_bytes
                    .checked_add(u64::from(valid))
                    .ok_or("disk cut byte count overflow")?;
                self.progress_work()?;
            }
        }
        if logical_bytes != self.owner.logical_bytes.load(Ordering::Acquire) {
            return Err(RamError::Invariant("disk cut does not cover complete RAM"));
        }
        Ok((pages, logical_bytes))
    }
}

fn disk_record_is_current(
    pageable: bool,
    writable: bool,
    version: u64,
    valid_length: u32,
    preserved_version: u64,
    preserved_length: u32,
) -> bool {
    pageable && !writable && version == preserved_version && valid_length == preserved_length
}

#[cfg(test)]
mod tests {
    use super::disk_record_is_current;

    #[test]
    fn preserved_versions_require_a_closed_write_epoch() {
        assert!(disk_record_is_current(true, false, 7, 4096, 7, 4096));
        // A writable page can have changed without another WP transition.
        assert!(!disk_record_is_current(true, true, 7, 4096, 7, 4096));
        // The first write after a cut rearm must invalidate its old version.
        assert!(!disk_record_is_current(true, false, 8, 4096, 7, 4096));
        assert!(!disk_record_is_current(false, false, 7, 4096, 7, 4096));
        assert!(!disk_record_is_current(true, false, 7, 4095, 7, 4096));
    }
}

impl PausedPagingOwner {
    /// Establishes new child locks after independent fault service is ready.
    ///
    /// The immediate child is the only guest accessor. This bootstrap deliberately
    /// avoids the copied mainloop coordinator and every native reconstruction lock.
    pub(super) fn lock_immediate_child(&self, service: &FaultService) -> Result<(), RamError> {
        let operation: Arc<dyn SourceOperation> =
            Arc::from(self.operations.begin(SourceOperationClass::ForkRearm)?);
        *service
            .placement_dependency
            .try_lock()
            .map_err(|_| "child placement dependency unavailable")? = Some(operation.clone());
        let ownership = LockedMemory::prepare(service)?;
        *self
            .locks
            .try_lock()
            .map_err(|_| "child lock ownership unavailable")? = Some(ownership.clone());
        let mut mappings = File::open("/proc/self/smaps")?;
        let mut completed = 0_u64;
        ownership.lock(&mut mappings, operation.as_ref(), || {
            completed = completed
                .checked_add(1)
                .ok_or("child lock work exhausted")?;
            operation.progress(completed)?;
            Ok(())
        })?;
        operation.complete()?;
        service
            .placement_dependency
            .try_lock()
            .map_err(|_| "child placement dependency unavailable")?
            .take();
        Ok(())
    }

    /// Installs the authenticated child's initial configuration before control admission.
    ///
    /// This bootstrap does not use the copied native coordinator. Managed
    /// placement converges at the first real before-resume boundary; a resident
    /// guarantee is published only from this child's completed kernel lock proof.
    ///
    /// # Errors
    /// Refuses unsupported initial cuts, incomplete child authority, missing
    /// verified locks, or a previously installed policy or placement receipt.
    pub(crate) fn install_staged_child_policy(
        &self,
        policy: &crucible_protocol::ram_control::RamControlPolicy,
        resources: &PluginRamResources,
    ) -> Result<(), RamError> {
        self.admit_resource_policy(policy, resources)?;
        if policy.mode == RamControlMode::DiskOriented {
            return Err(RamError::Invariant(
                "initial child disk cut requires a reconstructed boundary",
            ));
        }
        let snapshot = self.authority_snapshot()?;
        if !snapshot.activated || snapshot.failed {
            return Err(RamError::Invariant(
                "staged child arenas are not independently ready",
            ));
        }
        let locked = if policy.mode == RamControlMode::ResidentRequired {
            self.locks
                .try_lock()
                .map_err(|_| "child lock proof unavailable")?
                .as_ref()
                .and_then(|locks| locks.verified_bytes())
                .ok_or("staged child lacks its own verified locks")?
        } else {
            0
        };
        let mut current = self
            .policy
            .try_lock()
            .map_err(|_| "child policy unavailable")?;
        if current.is_some()
            || self.requested_policy_revision.load(Ordering::Acquire) != 0
            || self.policy_generation.load(Ordering::Acquire) != 0
            || self.placement_epoch.load(Ordering::Acquire) != 0
        {
            return Err(RamError::Invariant("staged child policy already installed"));
        }
        let mut receipt = self
            .placement_receipt
            .try_lock()
            .map_err(|_| "child placement proof unavailable")?;
        if receipt.is_some() {
            return Err(RamError::Invariant(
                "staged child inherited placement evidence",
            ));
        }
        if locked != 0 {
            *receipt = Some(RamControlPlacementReceipt {
                mode: RamControlMode::ResidentRequired,
                policy_revision: 1,
                topology_generation: snapshot.topology_generation,
                placement_epoch: 1,
                locked_bytes: locked,
                disk_preserved_logical_pages: 0,
                disk_preserved_logical_bytes: 0,
                ram_write_generation_at_cut: 0,
            });
            self.placement_epoch.store(1, Ordering::Release);
        }
        *current = Some(*policy);
        self.policy_generation.store(1, Ordering::Release);
        self.requested_policy_revision.store(1, Ordering::Release);
        Ok(())
    }

    pub(super) fn complete_placement_receipt(&self, generation: u64) -> Result<(), RamError> {
        if self.policy_generation.load(Ordering::Acquire) != generation {
            return Err(RamError::Invariant("completed placement was superseded"));
        }
        let receipt = self
            .prepared_placement_receipt
            .try_lock()
            .map_err(|_| "placement evidence unavailable")?
            .take();
        if let Some(receipt) = receipt {
            if receipt.policy_revision != self.requested_policy_revision.load(Ordering::Acquire) {
                return Err(RamError::Invariant("completed placement revision changed"));
            }
            *self
                .placement_receipt
                .try_lock()
                .map_err(|_| "placement evidence unavailable")? = Some(receipt);
            if let Some(service) = self
                .active
                .try_lock()
                .map_err(|_| "paging ownership unavailable")?
                .as_ref()
            {
                service
                    .placement_dependency
                    .try_lock()
                    .map_err(|_| "placement dependency unavailable")?
                    .take();
            }
        }
        Ok(())
    }
}

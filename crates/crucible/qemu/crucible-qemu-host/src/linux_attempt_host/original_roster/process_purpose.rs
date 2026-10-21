//! Assigns one complete contained process family from the original native slot.
//!
//! The physical family ceiling is also conservatively charged to TOTAL metadata.
//! This trades capacity for coverage of loader, allocator and creator histories;
//! it does not classify guest RAM as logical metadata. Host controls remain
//! disjoint, and no child receives another copy of the family reservation.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::sync::{Arc, Weak};

use crucible_host_resources::host_supervision::{HostOperationGuard, HostOperationSupervisor};

use crate::QemuChildProcessContract;
use crate::artifact_identity::InstallerControlIdentity;
use crate::spawn::{ConfiguredProcessEnvelope, ProcessEnvelopeRefinementError};

use super::{NativeAccountAttempt, NativeRoster, OriginalActorAccountError, OriginalNativeNodeBinding};

mod family;
use family::InstalledProcessFamily;

mod setup_mapping;
pub(crate) use setup_mapping::SetupMappingRequest;

mod incarnation;
use incarnation::IncarnationJournal;

pub(in crate::linux_attempt_host) mod source_admission;
pub(crate) use source_admission::{InstalledSourceAdmission, InstalledSourceSubject};

mod record;
mod target;

mod source_cleanup;
pub(crate) use source_cleanup::{SourceCleanupLender, SourceCleanupOriginal};

pub(super) use record::IssuedInstalledProcessRecord;
pub(super) use target::verify_subdivision_preparation;

/// Keeps both an initiating refusal and any changed containment in the slot.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InstalledProcessPurposeError {
    #[error("original process purpose refused: {0}")]
    Original(#[from] OriginalActorAccountError),
    #[error("configured process envelope refused: {0}")]
    Refinement(#[source] ProcessEnvelopeRefinementError),
    #[error("issued RAM endpoint kernel observation refused: {0}")]
    EndpointKernel(#[source] rustix::io::Errno),
    #[error("installed process identity or retirement is unavailable")]
    Identity,
    #[error("complete process and outside controls exceed the original purpose")]
    Capacity,
}

pub(super) struct InstalledProcessState {
    envelope: ConfiguredProcessEnvelope,
    family: Option<InstalledProcessFamily>,
    process_bytes: u64,
    pending_cleanup_bytes: u64,
    pending_workspace_bytes: u64,
    controls: Option<InstallerControlIdentity>,
    journal: IncarnationJournal,
    sound: bool,
    ready: bool,
}

impl InstalledProcessState {
    pub(super) fn matches_source_directory(&self, device: u64, inode: u64) -> bool {
        self.envelope.child_cgroup_device() == device && self.envelope.child_cgroup_inode() == inode
    }

    pub(super) fn matches_launch_contract(&self, contract: &QemuChildProcessContract) -> bool {
        self.ready && self.sound && self.envelope.matches_contract(contract)
    }

    pub(super) fn reserved_metadata_bytes(&self) -> u64 {
        // Construction checks this sum, and subsequent transitions only move
        // pending host bytes into the slot's already-assigned host ledger.
        self.process_bytes
            + self.pending_cleanup_bytes
            + self.pending_workspace_bytes
            + self.journal.pending_startup_bytes
            + self.journal.assigned_startup_bytes
    }

    pub(super) fn pending_cleanup_is(&self, extent: u64) -> bool {
        self.pending_cleanup_bytes == extent
    }

    pub(super) fn consume_cleanup(&mut self, extent: u64) -> bool {
        if self.pending_cleanup_bytes != extent {
            return false;
        }
        self.pending_cleanup_bytes = 0;
        true
    }

    /// Computes the next unissued Target generation from this real journal.
    pub(super) fn next_target_generation(
        &self,
        reserved: u64,
    ) -> Result<u64, OriginalActorAccountError> {
        self.journal
            .last_process_generation
            .max(reserved)
            .checked_add(1)
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(super) fn contains_incarnation(&self, process_generation: u64) -> bool {
        self.incarnation_subdivision(process_generation).is_some()
    }

    pub(super) fn incarnation_subdivision(&self, process_generation: u64) -> Option<u8> {
        if !self.ready || !self.sound {
            return None;
        }
        self.journal
            .incarnations
            .iter()
            .position(|allocation| {
                allocation.is_some_and(|allocation| {
                    allocation.process_generation == process_generation
                        && !allocation.borrower_closed
                })
            })
            .and_then(|index| u8::try_from(index).ok())
    }

    pub(super) fn pending_workspace_bytes(&self) -> u64 {
        self.pending_workspace_bytes
    }

    pub(super) fn consume_workspace(
        &mut self,
        bytes: u64,
    ) -> Result<(), OriginalActorAccountError> {
        self.pending_workspace_bytes = self
            .pending_workspace_bytes
            .checked_sub(bytes)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(())
    }

    pub(super) fn restore_workspace(
        &mut self,
        bytes: u64,
    ) -> Result<(), OriginalActorAccountError> {
        self.pending_workspace_bytes = self
            .pending_workspace_bytes
            .checked_add(bytes)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(())
    }

    pub(super) fn fork_target_geometry(
        &self,
        contract: &QemuChildProcessContract,
    ) -> Result<(u32, u64, u64, u64, (u32, u32)), InstalledProcessPurposeError> {
        if !self.ready || !self.sound || !self.envelope.matches_contract(contract) {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let source = self.journal.incarnations[0]
            .filter(|allocation| !allocation.borrower_closed && !allocation.physical_retired)
            .ok_or(InstalledProcessPurposeError::Identity)?;
        if self.journal.incarnations[1].is_some() || self.journal.loans != 1 {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        let controls = self
            .controls
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let local = self.envelope.maximum_resident_bytes();
        let minimum = source.setup_mapping.minimum_resident_bytes(
            source.guest_ram_bytes,
            controls.requested_bytes(),
            controls
                .native_preinit_requested_bytes()
                .map_err(|_| InstalledProcessPurposeError::Identity)?,
            crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES,
        )?;
        if minimum > local {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        family_extent_from_local_cap(local, self.process_bytes)?;
        Ok((
            self.envelope.maximum_vcpus(),
            local,
            self.envelope.maximum_writable_bytes(),
            self.envelope.maximum_file_descriptors(),
            self.envelope.child_credential_ids(),
        ))
    }

    pub(super) fn verify_fork_target_envelope(
        &self,
        target: &ConfiguredProcessEnvelope,
    ) -> Result<(), InstalledProcessPurposeError> {
        if !self.ready
            || !self.sound
            || (target.child_cgroup_device(), target.child_cgroup_inode())
                == (
                    self.envelope.child_cgroup_device(),
                    self.envelope.child_cgroup_inode(),
                )
            || target.child_credential_ids() != self.envelope.child_credential_ids()
            || target.maximum_resident_bytes() != self.envelope.maximum_resident_bytes()
            || target.maximum_file_descriptors() != self.envelope.maximum_file_descriptors()
            || target.maximum_tasks() != self.envelope.maximum_tasks()
            || target.maximum_vcpus() != self.envelope.maximum_vcpus()
            || target.maximum_writable_bytes() != self.envelope.maximum_writable_bytes()
            || target.maximum_locked_bytes() != self.envelope.maximum_locked_bytes()
        {
            return Err(InstalledProcessPurposeError::Identity);
        }
        self.family
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?
            .verify_envelope(1, target)?;
        family_extent_from_local_cap(target.maximum_resident_bytes(), self.process_bytes)?;
        Ok(())
    }

    pub(super) fn can_retire(&self) -> bool {
        self.journal.loans == 0
            && self.journal.incarnations.iter().all(Option::is_none)
            && self.sound
    }
}

/// Borrows the one retained family assignment for an actual native incarnation.
///
/// The borrowing node and final launch cleanup must both close before its
/// fixed share can be reused. The complete family assignment and artifact
/// vector remain retained until real process/group retirement. Failed spawn,
/// thread join and dropping a facade never refund a live or uncertain share.
#[must_use = "retain the loan in the actual node through physical containment"]
pub(crate) struct InstalledProcessPurposeLoan {
    roster: Weak<std::sync::Mutex<NativeRoster>>,
    index: usize,
    generation: u64,
    process_generation: u64,
    subdivision_index: u8,
}

/// Retains the exact share until the final physical launch owner closes.
///
/// Only the actual binding can produce this token. The private launch cleanup
/// owner consumes it after real reap, all worker/import borrowers and successful
/// registry retirement; no caller-supplied disposition can release a share.
pub(crate) struct InstalledIncarnationRetirement {
    roster: Weak<std::sync::Mutex<NativeRoster>>,
    index: usize,
    generation: u64,
    process_generation: u64,
    subdivision_index: u8,
}

impl InstalledProcessState {
    fn close_incarnation(&mut self, index: usize) {
        if self.journal.close_incarnation(index).is_err() {
            self.sound = false;
            self.ready = false;
        }
    }
}

impl InstalledIncarnationRetirement {
    pub(crate) fn retire_after_physical_cleanup(self) {
        let Some(roster) = self.roster.upgrade() else {
            return;
        };
        let Ok(mut state) = roster.lock() else {
            return;
        };
        let Some(purpose) = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.installed_process.as_mut())
        else {
            return;
        };
        let Some(allocation) = purpose
            .journal
            .incarnations
            .get_mut(usize::from(self.subdivision_index))
            .and_then(Option::as_mut)
            .filter(|allocation| allocation.process_generation == self.process_generation)
        else {
            return;
        };
        allocation.physical_retired = true;
        purpose.close_incarnation(usize::from(self.subdivision_index));
    }
}

/// Borrows issued transport material while its real containing owner is locked.
///
/// The descriptor is not a capability: a native receiver must authenticate the
/// once-consumed physical carrier and retain its same original Source owner.
/// No constructor accepts these values, and this borrow cannot outlive the
/// keeper whose original, contract and artifact were checked.
pub(crate) struct IssuedInstalledProcessMaterial<'a> {
    /// Immutable containing-operation coordinates, sampled from its real guard.
    /// They confer no authority outside the retained authenticated carrier.
    pub(crate) containing_original_basis: [u8; 80],
    /// Borrows the fixed reservation owner; it contains no execution generation.
    pub(crate) family: &'a InstalledProcessFamily,
    /// Actual parent device/inode, aggregate CPU quota/period, and task readback.
    pub(crate) native_parent_fields: [u64; 5],
    pub(crate) original_total_metadata_bytes: u64,
    pub(crate) original_full_resident_bytes: u64,
    pub(crate) effective_process_bytes: u64,
    /// Fixed disjoint share; it is never the complete copied family allowance.
    pub(crate) native_incarnation_bytes: u64,
    pub(crate) maximum_incarnations: u8,
    pub(crate) subdivision_index: u8,
    pub(crate) assigned_host_metadata_bytes: u64,
    pub(crate) pending_cleanup_bytes: u64,
    pub(crate) pending_workspace_bytes: u64,
    pub(crate) pending_startup_bytes: u64,
    pub(crate) assigned_startup_bytes: u64,
    pub(crate) live_guest_ram_bytes: u64,
    /// Guest debit belonging to this occupied incarnation, not all borrowers.
    pub(crate) current_guest_ram_bytes: u64,
    pub(crate) live_incarnations: u8,
    pub(crate) account_generation: u64,
    pub(crate) process_generation: u64,
    pub(crate) envelope: &'a ConfiguredProcessEnvelope,
    pub(crate) controls: &'a InstallerControlIdentity,
}

/// Returns the same-slot constructor peak, excluding its prepaid roster body.
///
/// # Errors
/// Refuses an unrepresentable fixed constructor overlap.
pub(super) fn family_constructor_extent() -> Result<u64, OriginalActorAccountError> {
    family::constructor_extent()
}

/// Computes the gross retained family assignment from real local readback.
fn family_extent_from_local_cap(
    local_cap: u64,
    admitted_family: u64,
) -> Result<u64, InstalledProcessPurposeError> {
    local_cap
        .checked_mul(u64::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS))
        .filter(|bytes| local_cap != 0 && *bytes <= admitted_family)
        .ok_or(InstalledProcessPurposeError::Capacity)
}

impl NativeAccountAttempt {
    /// Checks the factory's real workload root before host worker birth.
    pub(crate) fn verify_actor_family(
        &self,
        process: &crate::linux_attempt_process::LinuxQemuAttemptProcessFactory,
    ) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.credit.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?
            .verify_actor_family(process)
    }

    /// Installs the family assignment before any image tool or VM can execute.
    ///
    /// The actual host owner is the only caller. It lends its just-sealed
    /// contract and retains that owner before this operation or its postcut can
    /// refuse. Reservation precedes the real monotonic kernel refinement.
    pub(in crate::linux_attempt_host) fn bind_configured_process_family(
        &self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), InstalledProcessPurposeError> {
        self.require_original()?;
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let mut state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.installed_process.is_none()
                    && slot.unsettled.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let envelope = contract
            .configured_process_envelope()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        slot.reserve_family_constructor()?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let local_descriptors = credit.local_descriptor_ceiling()?;
        credit.require_vcpu_ceiling(envelope.maximum_vcpus())?;
        if envelope.maximum_vcpus() != 1
            || u64::from(envelope.maximum_tasks()) > credit.task_ceiling()
            || envelope.maximum_file_descriptors() > credit.descriptor_ceiling()
            || envelope.maximum_writable_bytes() > credit.full_backing_bytes()
            || envelope.maximum_resident_bytes() > credit.full_resident_bytes()
        {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        let cleanup = if slot.cleanup.is_none() {
            super::cleanup_control_extent()?
        } else {
            0
        };
        let workspace = crate::spawn::OriginalDeviceDigestWorkspace::host_allocation_extent()
            .map_err(|_| InstalledProcessPurposeError::Capacity)?
            .checked_mul(u64::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS))
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let startup = startup_and_transport_extent()?
            .checked_mul(u64::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS))
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let outside = slot
            .assigned_metadata_bytes()?
            .checked_add(cleanup)
            .and_then(|bytes| bytes.checked_add(workspace))
            .and_then(|bytes| bytes.checked_add(startup))
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let available = credit
            .total_metadata_bytes()
            .checked_sub(outside)
            .filter(|bytes| *bytes != 0)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let requested = envelope.maximum_resident_bytes().min(available);
        let local_requested = requested
            .checked_div(u64::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS))
            .filter(|bytes| *bytes != 0)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        slot.installed_process = Some(InstalledProcessState {
            envelope,
            family: None,
            process_bytes: requested,
            pending_cleanup_bytes: cleanup,
            pending_workspace_bytes: workspace,
            controls: None,
            journal: IncarnationJournal::new(startup),
            sound: true,
            ready: false,
        });

        let purpose = slot
            .installed_process
            .as_mut()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let descriptor_refined = contract
            .refine_configured_descriptor_limit(&purpose.envelope, local_descriptors)
            .map_err(InstalledProcessPurposeError::Refinement)?;
        // Both monotonic refinements use this same binding. No stale witness
        // can become the final material after an effective descriptor change.
        purpose.envelope = descriptor_refined;
        let refined = contract
            .refine_configured_process_envelope(&purpose.envelope, local_requested)
            .map_err(InstalledProcessPurposeError::Refinement)?;
        // A partial or refused refinement leaves the provisional assignment
        // here. Only the actual refreshed witness can become ready.
        // Each distinct child group enforces only its own disjoint ceiling.
        // The complete family assignment remains the sum of those ceilings,
        // so moving a fork child to a different group cannot expose a second W.
        purpose.process_bytes =
            family_extent_from_local_cap(refined.maximum_resident_bytes(), requested)?;
        purpose.envelope = refined;
        purpose.family = Some(InstalledProcessFamily::retain(
            credit,
            self.index,
            self.generation,
            purpose.process_bytes,
            &purpose.envelope,
        )?);
        purpose.ready = true;
        drop(state);
        contract
            .bind_helper_receiver(self.helper_cleanup_lender())
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        self.require_original()?;
        Ok(())
    }

    /// Binds configured installer geometry and lends the existing family once.
    ///
    /// This does not read an ELF, allocate, send a frame or spawn. The artifact
    /// operation authenticates the final installed plugin before supplying the
    /// opaque vector. Known compulsory RAM/control terms must fit the family;
    /// native constructors still consume their subdivisions through Source.
    pub(crate) fn prepare_installed_process_purpose(
        &self,
        original: &Arc<HostOperationGuard>,
        contract: &QemuChildProcessContract,
        qemu: &Path,
        plugin: &Path,
        controls: InstallerControlIdentity,
        guest_ram_bytes: u64,
        setup_mapping: SetupMappingRequest,
        process_generation: u64,
    ) -> Result<InstalledProcessPurposeLoan, InstalledProcessPurposeError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let mut state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get_mut(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.launch_in_flight
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        slot.credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?
            .verify_preparation(original)?;
        let purpose = slot
            .installed_process
            .as_mut()
            .filter(|purpose| {
                purpose.ready
                    && purpose.envelope.matches_contract(contract)
                    && purpose.journal.loans == 0
                    && purpose.journal.incarnations.iter().all(Option::is_none)
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        purpose
            .family
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?
            .verify_envelope(0, &purpose.envelope)?;
        if !controls.belongs_to_paths(qemu, plugin)
            || process_generation <= purpose.journal.last_process_generation
        {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let live_guest_ram_bytes = purpose
            .journal
            .live_guest_ram_bytes
            .checked_add(guest_ram_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let next_loans = purpose
            .journal
            .loans
            .checked_add(1)
            .filter(|loans| *loans <= super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let native_incarnation_bytes =
            purpose.process_bytes / u64::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS);
        let minimum = setup_mapping.minimum_resident_bytes(
            guest_ram_bytes,
            controls.requested_bytes(),
            controls
                .native_preinit_requested_bytes()
                .map_err(|_| InstalledProcessPurposeError::Identity)?,
            crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES,
        )?;
        if guest_ram_bytes == 0 || minimum > native_incarnation_bytes {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        live_guest_ram_bytes
            .checked_add(
                controls
                    .requested_bytes()
                    .checked_add(
                        controls
                            .native_preinit_requested_bytes()
                            .map_err(|_| InstalledProcessPurposeError::Identity)?,
                    )
                    .ok_or(InstalledProcessPurposeError::Capacity)?
                    .checked_mul(u64::from(next_loans))
                    .ok_or(InstalledProcessPurposeError::Capacity)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES
                        .checked_mul(u64::from(next_loans))?,
                )
            })
            .and_then(|bytes| bytes.checked_add(purpose.journal.live_setup_mapping_bytes().ok()?))
            .and_then(|bytes| bytes.checked_add(setup_mapping.backing_bytes()))
            .filter(|bytes| guest_ram_bytes != 0 && *bytes <= purpose.process_bytes)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let startup = startup_and_transport_extent()?;
        if let Some(existing) = purpose.controls.as_ref() {
            if existing != &controls {
                return Err(InstalledProcessPurposeError::Identity);
            }
        } else {
            purpose.controls = Some(controls);
        }
        let subdivision_index =
            purpose
                .journal
                .issue(process_generation, guest_ram_bytes, startup, setup_mapping)?;
        let loan = InstalledProcessPurposeLoan {
            roster: Weak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            process_generation,
            subdivision_index: subdivision_index as u8,
        };
        drop(state);
        self.require_original()?;
        Ok(loan)
    }
}

fn envelope_for_subdivision(
    slot: &super::NativeSlot,
    index: u8,
) -> Option<&ConfiguredProcessEnvelope> {
    match index {
        0 => slot
            .installed_process
            .as_ref()
            .map(|purpose| &purpose.envelope),
        1 => slot.fork_target.active_envelope(),
        _ => None,
    }
}

impl InstalledProcessPurposeLoan {
    /// Lends only this owner's verified material to the funded frame encoder.
    ///
    /// The caller must retain the loan before allocation or transport. The
    /// closure runs under the same slot lock, so host assignments cannot race
    /// serialization. It must not reenter the issuer or original account.
    /// Its typed initiating result and independent original post belong in the
    /// caller's already-paid failure body; this method starts no deadline.
    pub(crate) fn with_issued_material<T>(
        &self,
        original: &Arc<HostOperationGuard>,
        contract: &QemuChildProcessContract,
        qemu: &Path,
        plugin: &Path,
        process_generation: u64,
        encode: impl FnOnce(IssuedInstalledProcessMaterial<'_>) -> T,
    ) -> Result<T, InstalledProcessPurposeError> {
        self.verify(original, contract, qemu, plugin, process_generation)?;
        self.with_retained_material(original, contract, process_generation, encode)
    }

    fn with_retained_material<T>(
        &self,
        original: &Arc<HostOperationGuard>,
        contract: &QemuChildProcessContract,
        process_generation: u64,
        encode: impl FnOnce(IssuedInstalledProcessMaterial<'_>) -> T,
    ) -> Result<T, InstalledProcessPurposeError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        target::verify_subdivision_preparation(slot, original, self.subdivision_index)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| {
                purpose.ready
                    && purpose.sound
                    && purpose.journal.loans != 0
                    && self.process_generation == process_generation
                    && envelope_for_subdivision(slot, self.subdivision_index)
                        .is_some_and(|envelope| envelope.matches_contract(contract))
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let controls = purpose
            .controls
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let containing_original_basis = original
            .serialize_original_preparation_basis()
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        let family = purpose
            .family
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        family.verify_incarnation(
            self.generation,
            &containing_original_basis,
            self.subdivision_index,
            purpose.process_bytes,
            envelope_for_subdivision(slot, self.subdivision_index)
                .ok_or(InstalledProcessPurposeError::Identity)?,
        )?;
        let allocation = purpose
            .journal
            .incarnations
            .get(usize::from(self.subdivision_index))
            .and_then(Option::as_ref)
            .filter(|allocation| {
                allocation.process_generation == self.process_generation
                    && !allocation.borrower_closed
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        Ok(encode(IssuedInstalledProcessMaterial {
            containing_original_basis,
            family,
            native_parent_fields: credit.native_parent_readback()?,
            original_total_metadata_bytes: credit.total_metadata_bytes(),
            original_full_resident_bytes: credit.full_resident_bytes(),
            effective_process_bytes: purpose.process_bytes,
            native_incarnation_bytes: purpose.process_bytes
                / u64::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS),
            maximum_incarnations: super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS,
            subdivision_index: self.subdivision_index,
            assigned_host_metadata_bytes: slot.assigned_metadata_bytes()?,
            pending_cleanup_bytes: purpose.pending_cleanup_bytes,
            pending_workspace_bytes: purpose.pending_workspace_bytes,
            pending_startup_bytes: purpose.journal.pending_startup_bytes,
            assigned_startup_bytes: purpose.journal.assigned_startup_bytes,
            live_guest_ram_bytes: purpose.journal.live_guest_ram_bytes,
            current_guest_ram_bytes: allocation.guest_ram_bytes,
            live_incarnations: purpose.journal.loans,
            account_generation: self.generation,
            process_generation: self.process_generation,
            envelope: envelope_for_subdivision(slot, self.subdivision_index)
                .ok_or(InstalledProcessPurposeError::Identity)?,
            controls,
        }))
    }

    /// Corroborates actual setup-role geometry under this retained incarnation.
    ///
    /// # Errors
    /// Refuses missing, retired or foreign custody, changed role extent or page
    /// geometry. Caller must also retain its genuine operation/admission check.
    fn verify_setup_mapping_extent(
        &self,
        region_bytes: u64,
    ) -> Result<(), InstalledProcessPurposeError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let allocation = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.installed_process.as_ref())
            .and_then(|purpose| {
                purpose
                    .journal
                    .incarnations
                    .get(usize::from(self.subdivision_index))
            })
            .and_then(Option::as_ref)
            .filter(|allocation| {
                allocation.process_generation == self.process_generation
                    && !allocation.borrower_closed
                    && !allocation.physical_retired
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        allocation.setup_mapping.verify_extent(region_bytes)
    }

    /// Checks the actual family, selected artifact and still-live original.
    pub(crate) fn verify(
        &self,
        original: &Arc<HostOperationGuard>,
        contract: &QemuChildProcessContract,
        qemu: &Path,
        plugin: &Path,
        process_generation: u64,
    ) -> Result<(), InstalledProcessPurposeError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        target::verify_subdivision_preparation(slot, original, self.subdivision_index)?;
        slot.installed_process
            .as_ref()
            .filter(|purpose| {
                purpose.ready
                    && purpose.sound
                    && purpose.journal.loans != 0
                    && self.process_generation == process_generation
                    && envelope_for_subdivision(slot, self.subdivision_index)
                        .is_some_and(|envelope| envelope.matches_contract(contract))
                    && purpose
                        .controls
                        .as_ref()
                        .is_some_and(|controls| controls.belongs_to_paths(qemu, plugin))
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        Ok(())
    }
}

impl OriginalNativeNodeBinding {
    /// Borrows only this first-bound Target's saved physical cleanup origin.
    ///
    /// # Errors
    /// Refuses foreign, retired or unavailable Target incarnation custody.
    pub(crate) fn target_cleanup_lender(
        &self,
    ) -> Result<super::TargetCleanupLoan, OriginalActorAccountError> {
        let loan = self
            .installed_process
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if loan.subdivision_index != 1
            || loan.index != self.index
            || loan.generation != self.generation
            || !Weak::ptr_eq(&loan.roster, &self.roster)
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| purpose.ready && purpose.sound)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        purpose.journal.incarnations[1]
            .as_ref()
            .filter(|allocation| {
                allocation.process_generation == loan.process_generation
                    && !allocation.physical_retired
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        slot.fork_target
            .cleanup_for_process_generation(loan.process_generation)
    }

    /// Binds final physical retirement before any launch resource is created.
    pub(crate) fn retain_launch_cleanup(
        &self,
        cleanup: &crate::launch_cleanup::LaunchCleanup,
    ) -> Result<(), OriginalActorAccountError> {
        let loan = self
            .installed_process
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        cleanup
            .retain_installed_incarnation(InstalledIncarnationRetirement {
                roster: Weak::clone(&loan.roster),
                index: loan.index,
                generation: loan.generation,
                process_generation: loan.process_generation,
                subdivision_index: loan.subdivision_index,
            })
            .map_err(|_| OriginalActorAccountError::Unavailable)
    }

    /// Checks startup against the loan's actual retained Preparation lineage.
    ///
    /// The selected artifact was authenticated before this loan was issued.
    /// This borrow checks the still-retained issuer, effective contract and
    /// incarnation; it neither clones authority nor creates a Setup operation.
    pub(crate) fn verify_installed_process_purpose(
        &self,
        contract: &QemuChildProcessContract,
        supervisor: &HostOperationSupervisor,
        registration: &crate::ram_control::RamControlRegistration,
        process_generation: u64,
    ) -> Result<(), InstalledProcessPurposeError> {
        let loan = self
            .installed_process
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let roster = loan
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = roster
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(loan.index)
            .filter(|slot| slot.active == Some(loan.generation))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        credit.verify_capture_supervisor(supervisor)?;
        if registration.resources.metadata_bytes != credit.total_metadata_bytes()
            || registration.resources.resident_peak_bytes > credit.full_resident_bytes()
        {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        slot.installed_process
            .as_ref()
            .filter(|purpose| {
                purpose.ready
                    && purpose.sound
                    && purpose.journal.loans != 0
                    && loan.process_generation == process_generation
                    && envelope_for_subdivision(slot, loan.subdivision_index)
                        .is_some_and(|envelope| envelope.matches_contract(contract))
                    && purpose.controls.is_some()
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        Ok(())
    }

    /// Moves the issued borrower into the actual node's existing keeper.
    pub(crate) fn retain_installed_process_purpose(
        &mut self,
        loan: InstalledProcessPurposeLoan,
        record: IssuedInstalledProcessRecord,
    ) -> Result<(), InstalledProcessPurposeError> {
        if self.installed_process.is_some()
            || !Weak::ptr_eq(&self.roster, &loan.roster)
            || self.index != loan.index
            || self.generation != loan.generation
        {
            return Err(InstalledProcessPurposeError::Identity);
        }
        self.installed_process = Some(loan);
        self.issued_process_record = Some(record);
        Ok(())
    }

    /// Lends this issuer's one record after checking the actual Setup consumer.
    pub(crate) fn with_issued_process_record<T>(
        &self,
        contract: &QemuChildProcessContract,
        supervisor: &HostOperationSupervisor,
        registration: Option<&crate::ram_control::RamControlRegistration>,
        admission: &InstalledSourceAdmission,
        standing: &crate::spawn::source_supervision::OriginalSourceSupervision,
        process_generation: u64,
        setup_region_bytes: u64,
        ram_endpoint: Option<&crate::spawn::ram_endpoint_binding::IssuedRamControlEndpoint<'_>>,
        borrow: impl FnOnce(&[u8; record::ISSUED_PROCESS_RECORD_BYTES]) -> T,
    ) -> Result<T, crate::spawn::source_supervision::SourceEmissionError> {
        // Initial preexec has only Source custody. Target's historical prefix
        // remains private until its distinct native creator is implemented.
        self.installed_process
            .as_ref()
            .filter(|loan| loan.subdivision_index == 0)
            .ok_or(InstalledProcessPurposeError::Identity)?;
        self.verify_source_admission(contract, supervisor, admission, process_generation)?;
        if let Some(registration) = registration {
            self.verify_installed_process_purpose(
                contract,
                supervisor,
                registration,
                process_generation,
            )?;
        }
        self.installed_process
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?
            .verify_setup_mapping_extent(setup_region_bytes)?;
        let record = self
            .issued_process_record
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        if let Some(endpoint) = ram_endpoint {
            endpoint.verify_for(
                self,
                supervisor,
                registration.ok_or(InstalledProcessPurposeError::Identity)?,
                process_generation,
            )?;
        }
        if !standing.belongs_to(admission) {
            return Err(InstalledProcessPurposeError::Identity.into());
        }
        let corroboration = standing.corroboration()?;
        let bytes = record.with_ram_endpoint(ram_endpoint, &corroboration);
        Ok(borrow(&bytes))
    }
}

impl Drop for InstalledProcessPurposeLoan {
    fn drop(&mut self) {
        let Some(roster) = self.roster.upgrade() else {
            return;
        };
        let Ok(mut state) = roster.lock() else {
            return;
        };
        let Some(purpose) = state
            .slots
            .get_mut(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.installed_process.as_mut())
        else {
            return;
        };
        let Some(allocation) = purpose
            .journal
            .incarnations
            .get_mut(usize::from(self.subdivision_index))
            .and_then(Option::as_mut)
            .filter(|allocation| allocation.process_generation == self.process_generation)
        else {
            return;
        };
        allocation.borrower_closed = true;
        purpose.close_incarnation(usize::from(self.subdivision_index));
    }
}

fn startup_and_transport_extent() -> Result<u64, InstalledProcessPurposeError> {
    let qmp_extent = crate::QemuQmpExactSnapshotControlChannel::<
        std::os::unix::net::UnixStream,
    >::host_allocation_extent()
    .ok_or(InstalledProcessPurposeError::Capacity)?;

    crate::spawn::OriginalPluginStartup::host_allocation_extent()
        .map_err(|_| InstalledProcessPurposeError::Capacity)?
        .checked_add(
            crate::spawn::preexec_setup::PreparedPreexecSetup::host_allocation_extent()
                .ok_or(InstalledProcessPurposeError::Capacity)?,
        )
        .and_then(|bytes| {
            bytes.checked_add(crate::launch_cleanup::LaunchCleanup::retained_control_bytes()?)
        })
        .and_then(|bytes| bytes.checked_add(qmp_extent))
        .and_then(|bytes| {
            bytes.checked_add(u64::try_from(std::mem::size_of::<crate::QemuNodeChild>()).ok()?)
        })
        .and_then(|bytes| bytes.checked_add(crate::node::child_shutdown_control_extent()?))
        .ok_or(InstalledProcessPurposeError::Capacity)
}

pub(super) fn fresh_launch_control_extent() -> Result<u64, OriginalActorAccountError> {
    let (error_layout, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<
        crate::linux_attempt_host::original_node::OriginalNativeFreshLaunchError,
    >())
    .map_err(|_| OriginalActorAccountError::Unavailable)?;
    let helper_error_bytes =
        crucible_engine::SharedOperationalCause::<crate::QemuSpawnError>::allocation_bytes()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
    let bytes = error_layout
        .pad_to_align()
        .size()
        .checked_add(helper_error_bytes)
        // A single probe owns these two disjoint capacities through its same
        // Source journal; reserve the full floor before process-family sizing.
        .and_then(|bytes| {
            bytes.checked_add(
                crate::spawn::helper_receiver::MAXIMUM_PROBE_OUTPUT_BYTES.checked_mul(2)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                usize::from(super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS)
                    * std::mem::size_of::<Option<OriginalNativeNodeBinding>>(),
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                crate::linux_attempt_host::original_node::OriginalNativeFreshPreparation,
            >())
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                Arc<crate::linux_attempt_host::original_node::OriginalNativeFreshLaunchError>,
            >())
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(OriginalActorAccountError::Unavailable)?;
    Ok(bytes)
}

pub(super) fn cleanup_control_extent() -> Result<u64, OriginalActorAccountError> {
    let (layout, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<HostOperationGuard>())
    .map_err(|_| OriginalActorAccountError::Unavailable)?;
    let extent = u64::try_from(layout.pad_to_align().size())
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
    Ok(extent)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn distinct_child_caps_conserve_the_retained_family_assignment()
    -> Result<(), InstalledProcessPurposeError> {
        let admitted_family = 17 * 4096;
        let local_cap = (admitted_family / 2 / 4096) * 4096;

        assert_eq!(
            family_extent_from_local_cap(local_cap, admitted_family)?,
            16 * 4096
        );
        assert!(family_extent_from_local_cap(admitted_family, admitted_family).is_err());
        assert!(family_extent_from_local_cap(0, admitted_family).is_err());
        assert!(family_extent_from_local_cap(u64::MAX, u64::MAX).is_err());
        Ok(())
    }

    #[test]
    fn retained_source_reuses_two_concurrent_shares_for_three_successors()
    -> Result<(), InstalledProcessPurposeError> {
        let mapping =
            SetupMappingRequest::for_config(crucible_qemu_shmem::RegionConfig::new(1, 64))?;
        let mut journal = IncarnationJournal::new(18);
        let source = journal.issue(1, 8, 9, mapping)?;
        assert_eq!(source, 0);

        for generation in 2..=4 {
            let successor = journal.issue(generation, 8, 9, mapping)?;
            assert_eq!(successor, 1);
            assert_eq!(journal.loans, 2);
            assert_eq!(journal.live_guest_ram_bytes, 16);
            assert_eq!(journal.pending_startup_bytes, 0);
            assert!(journal.issue(generation + 1, 8, 9, mapping).is_err());

            journal.incarnations[successor]
                .as_mut()
                .unwrap()
                .borrower_closed = true;
            journal.close_incarnation(successor)?;
            assert_eq!(journal.loans, 2);
            assert!(journal.incarnations[successor].is_some());

            journal.incarnations[successor]
                .as_mut()
                .unwrap()
                .physical_retired = true;
            journal.close_incarnation(successor)?;
            assert_eq!(journal.loans, 1);
            assert_eq!(journal.live_guest_ram_bytes, 8);
            assert_eq!(journal.live_setup_mapping_bytes()?, mapping.backing_bytes());
            assert_eq!(journal.pending_startup_bytes, 9);
            assert_eq!(journal.assigned_startup_bytes, 9);
            assert_eq!(journal.incarnations[source].unwrap().process_generation, 1);
            assert!(journal.issue(generation, 8, 9, mapping).is_err());
        }
        Ok(())
    }

    #[test]
    fn neither_facade_drop_nor_physical_retirement_alone_releases_a_share()
    -> Result<(), InstalledProcessPurposeError> {
        for (borrower_closed, physical_retired) in [(false, false), (true, false), (false, true)] {
            let mapping =
                SetupMappingRequest::for_config(crucible_qemu_shmem::RegionConfig::new(1, 64))?;
            let mut journal = IncarnationJournal::new(18);
            let index = journal.issue(7, 8, 9, mapping)?;
            let allocation = journal.incarnations[index].as_mut().unwrap();
            allocation.borrower_closed = borrower_closed;
            allocation.physical_retired = physical_retired;

            journal.close_incarnation(index)?;
            assert_eq!(journal.loans, 1);
            assert_eq!(journal.live_guest_ram_bytes, 8);
            assert_eq!(journal.live_setup_mapping_bytes()?, mapping.backing_bytes());
            assert_eq!(journal.pending_startup_bytes, 9);
            assert_eq!(journal.assigned_startup_bytes, 9);
            assert!(journal.incarnations[index].is_some());
        }
        Ok(())
    }

    #[test]
    fn failed_retirement_accounting_keeps_the_entire_assigned_share()
    -> Result<(), InstalledProcessPurposeError> {
        let mapping =
            SetupMappingRequest::for_config(crucible_qemu_shmem::RegionConfig::new(1, 64))?;
        let mut journal = IncarnationJournal::new(18);
        let index = journal.issue(7, 8, 9, mapping)?;
        let allocation = journal.incarnations[index].as_mut().unwrap();
        allocation.borrower_closed = true;
        allocation.physical_retired = true;
        journal.pending_startup_bytes = u64::MAX;

        assert!(journal.close_incarnation(index).is_err());
        assert_eq!(journal.loans, 1);
        assert_eq!(journal.live_guest_ram_bytes, 8);
        assert_eq!(journal.live_setup_mapping_bytes()?, mapping.backing_bytes());
        assert_eq!(journal.assigned_startup_bytes, 9);
        assert!(journal.incarnations[index].is_some());
        Ok(())
    }
}

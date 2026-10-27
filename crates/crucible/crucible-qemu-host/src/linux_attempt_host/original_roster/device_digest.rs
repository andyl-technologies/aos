//! Retains a fixed workspace purpose inside the original native slot.
//!
//! The external holder must free its descriptor and unique shared body before
//! retiring this keeper. An entered refusal retains the slot's assignment.
//! The retained enclosing host envelope covers host histories, and the actual
//! native family purpose pays the single workspace backing inside its local share.
//! The allocation-only record never claims the retired precise source proof.

use std::sync::Arc;

use crucible_host_resources::host_supervision::HostOperationGuard;

use super::{NativeAccountAttempt, OriginalAccountCheckError, RosterWeak};

#[derive(Clone, Copy, Default)]
pub(super) struct DigestPurposeState {
    generation: Option<u64>,
    process_generation: u64,
    metadata_bytes: u64,
    resident_bytes: u64,
    entered: bool,
}

impl DigestPurposeState {
    pub(super) fn is_live(&self) -> bool {
        self.generation.is_some()
    }

    pub(super) fn belongs_to_process(&self, generation: u64) -> bool {
        self.is_live() && self.process_generation == generation
    }

    pub(super) fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }
}

struct MatchedFootprint {
    containing_cap: [u8; 32],
    metadata_bytes: u64,
    resident_bytes: u64,
}

/// Describes the one allocation already issued beneath the conservative envelope.
///
/// This is allocation-purpose version 2. It makes no legacy source-proof,
/// creator census or per-worker metadata claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocationWorkspaceRecord {
    fields: AllocationWorkspaceFields,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocationWorkspaceFields {
    pub(crate) containing_cap: [u8; 32],
    pub(crate) original_total_metadata_bytes: u64,
    pub(crate) metadata_purpose_bytes: u64,
    pub(crate) resident_purpose_bytes: u64,
    pub(crate) process_generation: u64,
    pub(crate) account_generation: u64,
    pub(crate) workspace_generation: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl AllocationWorkspaceRecord {
    pub(crate) fn fields(&self) -> AllocationWorkspaceFields {
        self.fields
    }

    pub(crate) fn encode(&self) -> [u8; 128] {
        let fields = self.fields;
        let mut bytes = [0; 128];
        bytes[..8].copy_from_slice(b"CRUCWSP2");
        bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&1_u32.to_be_bytes());
        bytes[16..48].copy_from_slice(&fields.containing_cap);
        for (offset, value) in [
            (48, fields.original_total_metadata_bytes),
            (56, fields.metadata_purpose_bytes),
            (64, fields.resident_purpose_bytes),
            (72, fields.process_generation),
            (80, fields.account_generation),
            (88, fields.workspace_generation),
            (96, fields.device),
            (104, fields.inode),
            // This is the same allocation at offset64, not a second grant.
            (120, fields.resident_purpose_bytes),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }
}

/// Keeps one process-bound purpose outside its funded allocation.
#[must_use = "retain outside the body until its actual descriptor and allocation free"]
pub(crate) struct OriginalDeviceDigestWorkspacePurpose {
    account: NativeAccountAttempt,
    index: usize,
    generation: u64,
    process_generation: u64,
    subdivision_index: u8,
    original: Arc<HostOperationGuard>,
    original_total_metadata_bytes: u64,
    footprint: MatchedFootprint,
    retired: bool,
}

impl std::fmt::Debug for OriginalDeviceDigestWorkspacePurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalDeviceDigestWorkspacePurpose")
            .finish_non_exhaustive()
    }
}

impl NativeAccountAttempt {
    /// Issues one workspace from its actual incarnation and exact active guard.
    ///
    /// # Errors
    /// Refuses foreign originals, lost generation custody or exhausted terms.
    pub(crate) fn prepare_device_digest_workspace(
        &self,
        original: &Arc<HostOperationGuard>,
        process_generation: u64,
    ) -> Result<OriginalDeviceDigestWorkspacePurpose, OriginalAccountCheckError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        credit.require_original()?;
        let host_bytes = crate::spawn::OriginalDeviceDigestWorkspace::host_allocation_extent()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        let installed = slot
            .installed_process
            .as_ref()
            .filter(|purpose| purpose.contains_incarnation(process_generation))
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let subdivision_index = installed
            .incarnation_subdivision(process_generation)
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        super::process_purpose::verify_subdivision_preparation(slot, original, subdivision_index)?;
        if installed.pending_workspace_bytes() < host_bytes {
            return Err(OriginalAccountCheckError::Unavailable);
        }
        let basis = original.serialize_original_preparation_basis()?;
        let mut containing_cap = [0; 32];
        containing_cap.copy_from_slice(&basis[16..48]);
        let footprint = MatchedFootprint {
            containing_cap,
            metadata_bytes: host_bytes,
            resident_bytes: crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES,
        };
        if process_generation == 0
            || slot.digest_purposes.iter().any(|purpose| {
                purpose.is_live() && purpose.process_generation == process_generation
            })
        {
            return Err(OriginalAccountCheckError::Unavailable);
        }
        let index = slot
            .digest_purposes
            .iter()
            .position(|purpose| !purpose.is_live())
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        // This body was reserved outside W before family refinement. Move that
        // exact reservation into the digest row, rather than debit it again.

        let resident = slot
            .digest_purposes
            .iter()
            .try_fold(0_u64, |used, purpose| {
                used.checked_add(purpose.resident_bytes)
            })
            .and_then(|used| used.checked_add(footprint.resident_bytes))
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        if resident > credit.full_resident_bytes() {
            return Err(OriginalAccountCheckError::Unavailable);
        }
        let original_total_metadata_bytes = credit.total_metadata_bytes();
        let generation = state.next_workspace_generation;
        state.next_workspace_generation = generation
            .checked_add(1)
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        state.slots[self.index]
            .installed_process
            .as_mut()
            .ok_or(OriginalAccountCheckError::Unavailable)?
            .consume_workspace(footprint.metadata_bytes)?;
        state.slots[self.index].digest_purposes[index] = DigestPurposeState {
            generation: Some(generation),
            process_generation,
            metadata_bytes: footprint.metadata_bytes,
            resident_bytes: footprint.resident_bytes,
            entered: false,
        };
        Ok(OriginalDeviceDigestWorkspacePurpose {
            account: NativeAccountAttempt {
                roster: RosterWeak::clone(&self.roster),
                index: self.index,
                generation: self.generation,
            },
            index,
            generation,
            process_generation,
            subdivision_index,
            original: Arc::clone(original),
            original_total_metadata_bytes,
            footprint,
            retired: false,
        })
    }
}

impl OriginalDeviceDigestWorkspacePurpose {
    pub(crate) fn check_original(&self) -> Result<(), OriginalAccountCheckError> {
        self.account.require_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        let slot = state
            .slots
            .get(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        slot.digest_purposes
            .get(self.index)
            .filter(|purpose| {
                purpose.generation == Some(self.generation)
                    && purpose.process_generation == self.process_generation
                    && !self.retired
            })
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let retained = credit
            .original
            .as_ref()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let original = match self.subdivision_index {
            0 => Some(&retained.preparation),
            1 => slot.fork_target.retained_preparation(),
            _ => None,
        }
        .ok_or(OriginalAccountCheckError::Unavailable)?;
        if !Arc::ptr_eq(original, &self.original) {
            return Err(OriginalAccountCheckError::Unavailable);
        }
        if let Some(normal) = retained.normal.as_ref() {
            normal.verify_retained_native_preparation(original)?;
        } else {
            original.wait_slice()?;
        }
        Ok(())
    }

    pub(crate) fn enter_workspace_birth(&mut self) -> Result<(), OriginalAccountCheckError> {
        self.check_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        let purpose = state
            .slots
            .get_mut(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get_mut(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation) && !purpose.entered)
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        purpose.entered = true;
        Ok(())
    }

    // Only the closed holder calls this after inspecting its own newly created
    // descriptor. These identities are evidence, never allocation authority.
    pub(crate) fn record_for_descriptor(
        &self,
        device: u64,
        inode: u64,
    ) -> Result<AllocationWorkspaceRecord, OriginalAccountCheckError> {
        self.check_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        state
            .slots
            .get(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation) && purpose.entered)
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        drop(state);
        if device == 0 || inode == 0 {
            return Err(OriginalAccountCheckError::Unavailable);
        }
        Ok(AllocationWorkspaceRecord {
            fields: AllocationWorkspaceFields {
                containing_cap: self.footprint.containing_cap,
                original_total_metadata_bytes: self.original_total_metadata_bytes,
                metadata_purpose_bytes: self.footprint.metadata_bytes,
                resident_purpose_bytes: self.footprint.resident_bytes,
                process_generation: self.process_generation,
                account_generation: self.account.generation,
                workspace_generation: self.generation,
                device,
                inode,
            },
        })
    }

    // The fixed external holder calls this only after real unique-body free.
    // A refusal keeps the same keeper; it does not manufacture a replacement.
    pub(crate) fn retire_after_body_free(&mut self) -> Result<(), OriginalAccountCheckError> {
        self.check_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        let purpose = state
            .slots
            .get_mut(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get_mut(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation))
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let bytes = purpose.metadata_bytes;
        // A failed restoration keeps the original assigned row. Clear it only
        // after the complete inverse transition has accepted the same extent.
        state.slots[self.account.index]
            .installed_process
            .as_mut()
            .ok_or(OriginalAccountCheckError::Unavailable)?
            .restore_workspace(bytes)?;
        state.slots[self.account.index].digest_purposes[self.index] = DigestPurposeState::default();
        self.retired = true;
        Ok(())
    }

    fn release_before_entry(&self) -> Result<(), OriginalAccountCheckError> {
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalAccountCheckError::Unavailable)?;
        let purpose = state
            .slots
            .get_mut(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get_mut(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation) && !purpose.entered)
            .ok_or(OriginalAccountCheckError::Unavailable)?;
        let bytes = purpose.metadata_bytes;
        // A failed restoration keeps the original assigned row. Clear it only
        // after the complete inverse transition has accepted the same extent.
        state.slots[self.account.index]
            .installed_process
            .as_mut()
            .ok_or(OriginalAccountCheckError::Unavailable)?
            .restore_workspace(bytes)?;
        state.slots[self.account.index].digest_purposes[self.index] = DigestPurposeState::default();
        Ok(())
    }
}

impl Drop for OriginalDeviceDigestWorkspacePurpose {
    fn drop(&mut self) {
        if !self.retired {
            // Before entry there is no funded body. Entry, panic or uncertainty
            // leaves the slot charged and prevents native control retirement.
            let _ = self.release_before_entry();
        }
    }
}

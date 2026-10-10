//! Retains a fixed workspace purpose inside the original native slot.
//!
//! The external holder must free its descriptor and unique shared body before
//! retiring this keeper. An entered refusal retains the slot's assignment.
//! The current source has no qualified worker/thread/TLS footprint, so normal
//! issuance refuses before any descriptor or workspace allocation.

use std::sync::{Arc, Weak};

use crucible_linux_resource::host_supervision::HostOperationGuard;
use crucible_protocol::plugin_setup_plan::{
    DeviceDigestPurpose, DeviceDigestPurposeFields, DeviceDigestPurposeScope,
};

use super::{NativeAccountAttempt, OriginalActorAccountError};

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
}

struct MatchedFootprint {
    source_proof_digest: [u8; 32],
    metadata_bytes: u64,
    resident_bytes: u64,
    descriptor_peak: u32,
    mapping_peak: u32,
}

impl MatchedFootprint {
    fn current() -> Result<Self, OriginalActorAccountError> {
        let original_stack = crate::spawn::GuardedWorkerStackProfile::for_environment(&[])
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let _original_request = original_stack.original_request_bytes();
        let _host_body = crate::spawn::OriginalDeviceDigestWorkspace::host_allocation_extent()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        // A target layout alone cannot supply the allocator, worker stack/TLS,
        // panic, inherited-child, and native control terms. Only a genuinely
        // matched source qualification may replace this closed admission.
        Err(OriginalActorAccountError::Unavailable)
    }
}

/// Keeps one process-bound purpose outside its funded allocation.
#[must_use = "retain outside the body until its actual descriptor and allocation free"]
pub(crate) struct OriginalDeviceDigestWorkspacePurpose {
    account: NativeAccountAttempt,
    index: usize,
    generation: u64,
    process_generation: u64,
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
    pub(crate) fn prepare_device_digest_workspace(
        &self,
        original: &Arc<HostOperationGuard>,
        process_generation: u64,
    ) -> Result<OriginalDeviceDigestWorkspacePurpose, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| {
                slot.active == Some(self.generation)
                    && slot.unsettled.is_none()
                    && slot.launch_refusal.is_none()
                    && !slot.launch_abandoned
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        credit.verify_preparation(original)?;
        let footprint = MatchedFootprint::current()?;
        if process_generation == 0
            || slot.digest_purposes.iter().any(|purpose| {
                purpose.is_live() && purpose.process_generation == process_generation
            })
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let index = slot
            .digest_purposes
            .iter()
            .position(|purpose| !purpose.is_live())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let metadata = slot
            .digest_purposes
            .iter()
            .try_fold(slot.launch_controls_bytes, |used, purpose| {
                used.checked_add(purpose.metadata_bytes)
            })
            .and_then(|used| used.checked_add(footprint.metadata_bytes))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let resident = slot
            .digest_purposes
            .iter()
            .try_fold(0_u64, |used, purpose| {
                used.checked_add(purpose.resident_bytes)
            })
            .and_then(|used| used.checked_add(footprint.resident_bytes))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if metadata > credit.total_metadata_bytes() || resident > credit.full_resident_bytes() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let original_total_metadata_bytes = credit.total_metadata_bytes();
        let generation = state.next_workspace_generation;
        state.next_workspace_generation = generation
            .checked_add(1)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        state.slots[self.index].digest_purposes[index] = DigestPurposeState {
            generation: Some(generation),
            process_generation,
            metadata_bytes: footprint.metadata_bytes,
            resident_bytes: footprint.resident_bytes,
            entered: false,
        };
        Ok(OriginalDeviceDigestWorkspacePurpose {
            account: NativeAccountAttempt {
                roster: Weak::clone(&self.roster),
                index: self.index,
                generation: self.generation,
            },
            index,
            generation,
            process_generation,
            original_total_metadata_bytes,
            footprint,
            retired: false,
        })
    }
}

impl OriginalDeviceDigestWorkspacePurpose {
    pub(crate) fn check_original(&self) -> Result<(), OriginalActorAccountError> {
        self.account.require_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        state
            .slots
            .get(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get(self.index))
            .filter(|purpose| {
                purpose.generation == Some(self.generation)
                    && purpose.process_generation == self.process_generation
                    && !self.retired
            })
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(())
    }

    pub(crate) fn enter_workspace_birth(&mut self) -> Result<(), OriginalActorAccountError> {
        self.check_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let purpose = state
            .slots
            .get_mut(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get_mut(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation) && !purpose.entered)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        purpose.entered = true;
        Ok(())
    }

    // Only the closed holder calls this after inspecting its own newly created
    // descriptor. These identities are evidence, never allocation authority.
    pub(crate) fn record_for_descriptor(
        &self,
        device: u64,
        inode: u64,
    ) -> Result<DeviceDigestPurpose, OriginalActorAccountError> {
        self.check_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        state
            .slots
            .get(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation) && purpose.entered)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        drop(state);
        DeviceDigestPurpose::new(DeviceDigestPurposeFields {
            scope: DeviceDigestPurposeScope::Initial,
            source_proof_digest: self.footprint.source_proof_digest,
            original_total_metadata_bytes: self.original_total_metadata_bytes,
            metadata_purpose_bytes: self.footprint.metadata_bytes,
            resident_purpose_bytes: self.footprint.resident_bytes,
            process_generation: self.process_generation,
            account_generation: self.account.generation,
            workspace_generation: self.generation,
            device,
            inode,
            native_descriptor_peak: self.footprint.descriptor_peak,
            native_mapping_peak: self.footprint.mapping_peak,
        })
        .map_err(|_| OriginalActorAccountError::Unavailable)
    }

    // The fixed external holder calls this only after real unique-body free.
    // A refusal keeps the same keeper; it does not manufacture a replacement.
    pub(crate) fn retire_after_body_free(&mut self) -> Result<(), OriginalActorAccountError> {
        self.check_original()?;
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let purpose = state
            .slots
            .get_mut(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get_mut(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        *purpose = DigestPurposeState::default();
        self.retired = true;
        Ok(())
    }

    fn release_before_entry(&self) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .account
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let mut state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let purpose = state
            .slots
            .get_mut(self.account.index)
            .filter(|slot| slot.active == Some(self.account.generation))
            .and_then(|slot| slot.digest_purposes.get_mut(self.index))
            .filter(|purpose| purpose.generation == Some(self.generation) && !purpose.entered)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        *purpose = DigestPurposeState::default();
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

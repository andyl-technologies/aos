//! Issues only the separately contained second incarnation from its real loan.
//!
//! Target keeps the immutable installer identity of the running Source. This
//! path never rereads artifact geometry or reuses Source's initial carrier.

use super::*;

/// Checks the exact active issuer operation of one already-issued incarnation.
///
/// Source and Target have different retained guards. Sharing Main or copying
/// the same class cannot replace the nominal second slot's actual operation.
pub(in crate::linux_attempt_host::original_roster) fn verify_subdivision_preparation(
    slot: &super::super::NativeSlot,
    original: &Arc<HostOperationGuard>,
    subdivision: u8,
) -> Result<(), OriginalActorAccountError> {
    let credit = slot
        .credit
        .as_ref()
        .ok_or(OriginalActorAccountError::Unavailable)?;
    match subdivision {
        0 => credit.verify_preparation(original),
        1 => {
            let (_, target) = slot
                .fork_target
                .watcher_preparation()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            if !Arc::ptr_eq(target, original) {
                return Err(OriginalActorAccountError::Unavailable);
            }
            credit
                .original
                .as_ref()
                .and_then(|held| held.normal.as_ref())
                .ok_or(OriginalActorAccountError::Unavailable)?
                .verify_native_preparation(original)?;
            credit.require_original()
        }
        _ => Err(OriginalActorAccountError::Unavailable),
    }
}

impl InstalledProcessState {
    pub(in crate::linux_attempt_host::original_roster) fn fork_target_incarnation_is_retained(
        &self,
    ) -> bool {
        self.journal.incarnations[1].is_some()
    }
}

impl NativeAccountAttempt {
    pub(in crate::linux_attempt_host) fn prepare_fork_target_binding(
        &self,
        contract: &QemuChildProcessContract,
        supervisor: &HostOperationSupervisor,
        registration: &crate::ram_control::RamControlRegistration,
        guest_ram_bytes: u64,
    ) -> Result<OriginalNativeNodeBinding, InstalledProcessPurposeError> {
        self.verify_fork_target_contract(contract)?;
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
                    && slot.node_bindings_live == 1
                    && !slot.launch_in_flight
                    && !slot.launch_abandoned
                    && slot.launch_refusal.is_none()
            })
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let credit = slot
            .credit
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        credit.verify_capture_supervisor(supervisor)?;
        let (_, original) = slot
            .fork_target
            .watcher_preparation()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        verify_subdivision_preparation(slot, original, 1)?;
        if !original.shares_outer_cap(supervisor) {
            return Err(InstalledProcessPurposeError::Identity);
        }
        if registration.target.retained_template
            || registration.resources.metadata_bytes != credit.total_metadata_bytes()
            || registration.resources.resident_peak_bytes > credit.full_resident_bytes()
        {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        let purpose = slot
            .installed_process
            .as_mut()
            .filter(|purpose| purpose.ready && purpose.sound && purpose.journal.loans == 1)
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let source = purpose.journal.incarnations[0]
            .filter(|allocation| !allocation.borrower_closed && !allocation.physical_retired)
            .ok_or(InstalledProcessPurposeError::Identity)?;
        if guest_ram_bytes == 0 || guest_ram_bytes != source.guest_ram_bytes {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let controls = purpose
            .controls
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let local =
            purpose.process_bytes / u64::from(super::super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS);
        let minimum = source.setup_mapping.minimum_resident_bytes(
            guest_ram_bytes,
            controls.requested_bytes(),
            controls
                .native_preinit_requested_bytes()
                .map_err(|_| InstalledProcessPurposeError::Identity)?,
            crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES,
        )?;
        let combined = minimum
            .checked_mul(2)
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        if minimum > local || combined > purpose.process_bytes {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        let generation = registration.target.owner_generation;
        let subdivision_index = purpose.journal.issue(
            generation,
            guest_ram_bytes,
            startup_and_transport_extent()?,
            source.setup_mapping,
        )?;
        if subdivision_index != 1 {
            purpose.sound = false;
            return Err(InstalledProcessPurposeError::Identity);
        }
        slot.fork_target.retain_process_generation(generation)?;
        slot.node_bindings_live += 1;
        let loan = InstalledProcessPurposeLoan {
            roster: Weak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            process_generation: generation,
            subdivision_index: 1,
        };
        let mut binding = OriginalNativeNodeBinding {
            roster: Weak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            installed_process: None,
            issued_process_record: None,
            source_host: None,
        };
        drop(state);
        binding.installed_process = Some(loan);
        Ok(binding)
    }
}

impl OriginalNativeNodeBinding {
    /// Issues the Target workspace beneath its already reserved second share.
    ///
    /// # Errors
    /// Refuses a Source borrower, reused prefix, retired Target or missing original.
    pub(in crate::linux_attempt_host) fn prepare_fork_target_workspace(
        &self,
    ) -> Result<
        super::super::device_digest::OriginalDeviceDigestWorkspacePurpose,
        InstalledProcessPurposeError,
    > {
        if self.issued_process_record.is_some() {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let loan = self
            .installed_process
            .as_ref()
            .filter(|loan| loan.subdivision_index == 1)
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let held = self
            .roster
            .upgrade()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let state = held
            .lock()
            .map_err(|_| InstalledProcessPurposeError::Identity)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let (_, original) = slot
            .fork_target
            .watcher_preparation()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        verify_subdivision_preparation(slot, original, 1)?;
        let original = Arc::clone(original);
        drop(state);
        NativeAccountAttempt {
            roster: Weak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
        }
        .prepare_device_digest_workspace(&original, loan.process_generation)
        .map_err(Into::into)
    }

    pub(in crate::linux_attempt_host) fn seal_fork_target_prefix(
        &mut self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), InstalledProcessPurposeError> {
        if self.issued_process_record.is_some() {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let loan = self
            .installed_process
            .as_ref()
            .filter(|loan| loan.subdivision_index == 1)
            .ok_or(InstalledProcessPurposeError::Identity)?;
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
        let (_, original) = slot
            .fork_target
            .watcher_preparation()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        verify_subdivision_preparation(slot, original, 1)?;
        let original = Arc::clone(original);
        drop(state);
        let record = loan.with_retained_material(
            &original,
            contract,
            loan.process_generation,
            |material| material.encode_record(),
        )??;
        self.issued_process_record = Some(record);
        Ok(())
    }
}

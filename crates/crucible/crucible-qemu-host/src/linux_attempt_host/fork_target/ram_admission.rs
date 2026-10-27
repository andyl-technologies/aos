//! Borrows the saved Target role before its second RAM registration is created.
//!
//! This in-process witness never crosses QMP or shared memory. It borrows the
//! real reservation and contract; copied generations and resource limits cannot
//! construct it. Checks revalidate the same saved epoch on every registry cut.

use super::*;

/// Borrows one actual Target's fixed RAM-registration request.
///
/// The backend retains the Target host while a concrete registration companion
/// uses this borrow. The matching Source controller identifies its registry
/// owner and node; no caller-supplied node scalar can substitute for that match.
pub struct QemuForkTargetRamAdmission<'a> {
    custody: &'a ForkTargetCustody,
    contract: &'a QemuChildProcessContract,
    generation: u64,
}

impl LinuxQemuAttemptHostOwner {
    /// Borrows the existing Target role for its exact planned RAM generation.
    ///
    /// The first request binds that generation in the saved reservation before
    /// registration effects. Retrying the same request borrows the same state.
    ///
    /// # Errors
    /// Refuses Source-only owners, foreign contracts, closed/uncertain Targets,
    /// changed generations, or a noncurrent saved Target Preparation.
    pub fn borrow_fork_target_ram_admission<'a>(
        &'a self,
        contract: &'a QemuChildProcessContract,
    ) -> Result<QemuForkTargetRamAdmission<'a>, QemuVmRealizationError> {
        let custody = self
            .fork_target
            .as_ref()
            .ok_or_else(|| missing_authority("borrow actual Target RAM admission"))?;
        self.process_contract()?
            .verify_process_stage_binding(&contract.retain_process_stage_binding())
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        let process_generation = custody
            .reservation
            .bind_ram_registration(contract)
            .map_err(original_roster::original_error)?;
        Ok(QemuForkTargetRamAdmission {
            custody,
            contract,
            generation: process_generation,
        })
    }
}

impl QemuForkTargetRamAdmission<'_> {
    /// Executes registration under the same Target precheck and independent postcheck.
    ///
    /// # Errors
    /// Preserves the initiating callback error and any independent role refusal.
    pub fn with_registration(
        &self,
        prepare: &mut dyn FnMut(
            &Self,
        ) -> Result<
            crate::ram_control::RamControlRegistration,
            QemuVmRealizationError,
        >,
    ) -> Result<crate::ram_control::RamControlRegistration, QemuVmRealizationError> {
        let result = self.check_preparation().and_then(|()| prepare(self));
        original_roster::after_boundary(
            result,
            self.custody
                .reservation
                .check_ram_registration(self.contract, self.generation, false),
        )
    }

    /// Returns the generation already bound in this actual Target reservation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Checks the same saved role, epoch, contract and Target Preparation.
    ///
    /// # Errors
    /// Refuses stale/closed/uncertain ownership or a canceled/expired operation.
    pub fn check_preparation(&self) -> Result<(), QemuVmRealizationError> {
        self.custody
            .reservation
            .check_ram_registration(self.contract, self.generation, false)
            .map_err(original_roster::original_error)
    }

    /// Matches the genuine retained Source controller for this Target's node.
    ///
    /// Registry owner/node identity must be selected by this exact match. The
    /// method does not accept a copied identifier as proof of membership.
    ///
    /// # Errors
    /// Refuses a changed Target operation, foreign controller or retired Source.
    pub fn matches_source_controller(
        &self,
        controller: &LinuxQemuNativeResourceController,
    ) -> Result<bool, QemuVmRealizationError> {
        self.check_preparation()?;
        Ok(self.custody.source.upgrade().is_some_and(|source| {
            NativeResourceState::available(&source)
                && native_resources::controller_matches(&source, controller)
        }))
    }

    /// Checks a Cleanup already entered by this exact retained Target owner.
    ///
    /// This observation cannot enter or renew Cleanup. Registry physical
    /// retirement still needs the actual owning cleanup/physical receipt.
    ///
    /// # Errors
    /// Refuses missing, failed, canceled, expired or foreign saved Cleanup.
    pub fn check_retained_cleanup(&self) -> Result<(), QemuVmRealizationError> {
        self.custody
            .reservation
            .check_ram_registration(self.contract, self.generation, true)
            .map_err(original_roster::original_error)
    }
}

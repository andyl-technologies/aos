//! Prepays the fixed TPM helper's parent-side descriptor copy and libc stack.
//!
//! The shared configured-kernel supplier owns the sole private-layout formula
//! and this publisher proves its own kernel-notes affinity. Source's real hard
//! memory and PID cgroup remain the backstop for allocator and kernel overhead.
//! The permit covers dominant requested storage rather than all global caches,
//! slab/RCU residency, exact physical usage or a completed child/NV session.

use aos_sandbox_linux::kernel_clone::{
    ConfiguredKernelCloneOriginalV1, configured_notes_bytes_data_v1, dominant_birth_bytes_data_v1,
};

use super::*;

pub(super) struct HelperBirthOriginal {
    kernel: ConfiguredKernelCloneOriginalV1,
    returned: Option<aos_sandbox_linux::Result<()>>,
    complete: bool,
}

impl HelperBirthOriginal {
    fn new() -> Self {
        Self {
            kernel: ConfiguredKernelCloneOriginalV1::new(),
            returned: None,
            complete: false,
        }
    }

    fn demand(table_bound: u64) -> Option<ResourceVector> {
        let (notes, files, names) = ConfiguredKernelCloneOriginalV1::receiving_obligations_v1()?;
        let highest = table_bound.checked_sub(1)?;
        // The fixed common055 helper command has only argv[0], no arguments,
        // and an empty environment. Its stdio preparation and CLOEXEC entries
        // still lie below the genuine transfer's complete parent-table bound.
        let birth = dominant_birth_bytes_data_v1(highest, 1)?;
        let memory = notes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?;
        Some(
            ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(memory).ok()?.checked_add(birth)?,
                )
                .with(D::Pids, 1)
                .with(
                    D::OpenFiles,
                    u64::try_from(files).ok()?.checked_add(table_bound)?,
                )
                .with(
                    D::OutputBytes,
                    configured_notes_bytes_data_v1()?.checked_add(1)?,
                )
                .with(D::MetadataEntries, u64::try_from(names).ok()?),
        )
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.kernel
            .failure()
            .or_else(|| result_failure(&self.returned))
    }
}

impl RuntimeBootPreparationStartupOriginalV1 {
    pub(in crate::runtime_deployment) fn prepare_tpm_helper_birth_once_v1(
        &self,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        self.require_current_v1()?;
        let mut birth = self
            .helper_birth
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        if birth.is_some() {
            return Err(self.fail(First::Order));
        }
        let table_bound = self
            .source
            .try_borrow()
            .map_err(|_| self.fail(First::Order))?
            .helper_table_bound_data_v1()
            .map_err(|_| self.fail(First::Source))?;
        self.fund_additional(HelperBirthOriginal::demand(table_bound))?;

        *birth = Some(HelperBirthOriginal::new());
        let original = birth.as_mut().ok_or(self.closed)?;
        original.returned = Some(original.kernel.capture_once_v1());
        if !matches!(original.returned, Some(Ok(()))) || !original.kernel.completed_v1() {
            return Err(self.fail(First::HelperBirth));
        }
        original.complete = true;
        Ok(())
    }
}

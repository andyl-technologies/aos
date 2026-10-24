//! Borrows exact direct or nominal Target cleanup without creating authority.

use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};

/// Borrows one saved Cleanup from its actual issuer for a bounded return step.
///
/// Direct cleanup retains its exact supervisor. A Target borrow is created only
/// from the genuine first-bound Target cleanup object, independently of the
/// ordinary child service supervisor. This view issues no operation or return.
#[derive(Clone, Copy)]
pub struct RamCleanupOriginal<'a> {
    origin: CleanupOrigin<'a>,
}

#[derive(Clone, Copy)]
enum CleanupOrigin<'a> {
    Direct(&'a HostOperationGuard, &'a HostOperationSupervisor),
    #[cfg(target_os = "linux")]
    Target(&'a crate::linux_attempt_host::TargetCleanupOriginal),
    #[cfg(target_os = "linux")]
    Source(&'a crate::linux_attempt_host::SourceCleanupOriginal),
}

impl<'a> RamCleanupOriginal<'a> {
    /// Borrows a saved guard with the exact supervisor that entered it.
    ///
    /// Each operation still verifies roster identity and live Cleanup status;
    /// constructing this inert borrow grants no effect or waiting permission.
    #[must_use]
    pub const fn direct(
        original: &'a HostOperationGuard,
        supervisor: &'a HostOperationSupervisor,
    ) -> Self {
        Self {
            origin: CleanupOrigin::Direct(original, supervisor),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn target(
        original: &'a crate::linux_attempt_host::TargetCleanupOriginal,
    ) -> Self {
        Self {
            origin: CleanupOrigin::Target(original),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn source(
        original: &'a crate::linux_attempt_host::SourceCleanupOriginal,
    ) -> Self {
        Self {
            origin: CleanupOrigin::Source(original),
        }
    }

    fn original(self) -> Result<&'a HostOperationGuard, HostSupervisionError> {
        match self.origin {
            CleanupOrigin::Direct(original, supervisor) => {
                if !original.belongs_to_supervisor(supervisor) {
                    return Err(HostSupervisionError::InvalidBudget);
                }
                Ok(original)
            }
            #[cfg(target_os = "linux")]
            CleanupOrigin::Target(original) => original.checked_original(),
            #[cfg(target_os = "linux")]
            CleanupOrigin::Source(original) => original.checked_original(),
        }
    }

    pub(crate) fn verify(self) -> Result<(), HostSupervisionError> {
        self.original()?
            .verify_operation_class(HostOperationClass::Cleanup)
    }

    pub(crate) fn wait_slice(self) -> Result<std::time::Duration, HostSupervisionError> {
        let original = self.original()?;
        original.verify_operation_class(HostOperationClass::Cleanup)?;
        original.wait_slice()
    }
}

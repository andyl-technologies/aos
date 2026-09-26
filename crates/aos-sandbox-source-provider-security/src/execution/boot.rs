//! Opaque current-kernel-boot evidence.

use aos_sandbox_linux::boot::KernelBootId;

use crate::SourceProviderSecurityError;

/// Proves a boot ID was read from the running kernel at an authority boundary.
pub struct CurrentKernelBootV1 {
    pub(super) boot_id: [u8; 16],
}

impl core::fmt::Debug for CurrentKernelBootV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentKernelBootV1([redacted])")
    }
}

impl CurrentKernelBootV1 {
    pub(crate) fn capture() -> Result<Self, SourceProviderSecurityError> {
        let boot_id = KernelBootId::current()
            .map_err(|_| SourceProviderSecurityError::ExecutionChanged)?
            .into_bytes();
        if boot_id == [0; 16] {
            return Err(SourceProviderSecurityError::ExecutionChanged);
        }
        Ok(Self { boot_id })
    }

    pub(crate) const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        if Self::capture()?.boot_id == self.boot_id {
            Ok(())
        } else {
            Err(SourceProviderSecurityError::ExecutionChanged)
        }
    }
}

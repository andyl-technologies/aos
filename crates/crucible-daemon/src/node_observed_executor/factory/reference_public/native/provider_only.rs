//! Measures the original provider-only cohort before native realization.
//!
//! A singleton private process group and empty direct-child census establish
//! only that no companion currently exists under this original supervision.
//! They do not establish general absence of kernel or filesystem effects.

use super::{
    InstalledPublicReferencePackage, NativeProcess, ProviderError, ResourceLimits, U64, children,
    group_members, package_error,
};
use serde::Serialize;
use std::collections::BTreeSet;

/// Retains an independently measured original pre-realization process scope.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub(in super::super) struct ProviderOnlyEnrollment {
    provider: NativeProcess,
    supervision: U64,
    package: crucible_node_contract::ContentRef,
}

impl ProviderOnlyEnrollment {
    /// Measures the actual provider under its already-reserved native slot.
    ///
    /// The caller retains the real Child and slot throughout measurement.
    /// PID lifetime, executable and loaded ELF objects, resource limits, parent
    /// and the complete private process group are checked independently.
    ///
    /// # Errors
    /// Refuses missing or foreign supervision, changed executable/runtime,
    /// resource limits, PID lifetime, ancestry, or any companion/group member.
    pub(in super::super) fn enroll(
        provider: u32,
        supervision: U64,
        package: &InstalledPublicReferencePackage,
        limits: &ResourceLimits,
    ) -> Result<Self, ProviderError> {
        if provider == 0 || supervision.get() == 0 {
            return Err(ProviderError::Correlation(
                "invalid original provider-only supervision",
            ));
        }
        let process = NativeProcess::measure(
            provider,
            package
                .artifact_content("provider")
                .map_err(package_error)?,
            package,
            limits,
        )?;
        if process.group != U64::new(u64::from(provider))
            || process.parent != U64::new(u64::from(std::process::id()))
            || !children(provider)?.is_empty()
            || group_members(provider)? != BTreeSet::from([provider])
        {
            return Err(ProviderError::Correlation(
                "original provider-only native scope contains another process",
            ));
        }
        Ok(Self {
            provider: process,
            supervision,
            package: package.identity().clone(),
        })
    }

    /// Re-measures the original provider without accepting a replacement PID.
    ///
    /// # Errors
    /// Refuses loss or change of the original native lifetime, source scope,
    /// limits, supervision, private group or absence of a companion.
    pub(in super::super) fn authenticate(
        &self,
        package: &InstalledPublicReferencePackage,
        limits: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        let provider = u32::try_from(self.provider.pid.get())
            .map_err(|_| ProviderError::Correlation("original provider-only PID overflow"))?;
        let current = Self::enroll(provider, self.supervision, package, limits)?;
        if current != *self {
            return Err(ProviderError::Correlation(
                "original provider-only native scope changed",
            ));
        }
        Ok(())
    }
}

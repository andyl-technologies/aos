//! Adapts closed host capabilities without adding a production issuer.

use super::*;
use crucible_linux_resource::host_supervision::HostOperationClass;
use crucible_qemu::{OriginalActorCatalogPurpose, OriginalCatalogPhysicalAudit};

pub(super) enum CatalogAccounts {
    Original(OriginalActorCatalogAccounts),
    #[cfg(test)]
    Fixture(tests::FixtureAccounts),
}

impl CatalogAccounts {
    pub(super) fn check(&self) -> Result<(), HostSupervisionError> {
        match self {
            Self::Original(accounts) => accounts.check(),
            #[cfg(test)]
            Self::Fixture(accounts) => accounts.original.wait_slice().map(|_| ()),
        }
    }

    pub(super) fn begin_read(&self) -> Result<HostOperationGuard, HostSupervisionError> {
        match self {
            Self::Original(accounts) => accounts.begin_read(),
            #[cfg(test)]
            Self::Fixture(accounts) => accounts.supervisor.begin(HostOperationClass::PageIn),
        }
    }

    pub(super) fn begin_write(&self) -> Result<HostOperationGuard, HostSupervisionError> {
        match self {
            Self::Original(accounts) => accounts.begin_write(),
            #[cfg(test)]
            Self::Fixture(accounts) => accounts.supervisor.begin(HostOperationClass::Writeback),
        }
    }

    pub(super) fn begin_provider(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        self.check()?;
        match self {
            Self::Original(accounts) => match class {
                HostOperationClass::Preparation => accounts.begin_preparation(),
                HostOperationClass::Cleanup => accounts.begin_cleanup(),
                HostOperationClass::PageIn => accounts.begin_read(),
                HostOperationClass::Writeback => accounts.begin_write(),
                _ => Err(HostSupervisionError::Unavailable),
            },
            #[cfg(test)]
            Self::Fixture(accounts) => accounts.supervisor.begin(class),
        }
    }

    pub(super) fn prepare_audit(
        &self,
        purpose: OriginalActorCatalogPurpose,
    ) -> Result<OriginalCatalogPhysicalAudit, OriginalActorAccountError> {
        match self {
            Self::Original(accounts) => accounts.prepare_physical_audit(purpose),
            // Local graph controls do not construct a physical workflow grant.
            #[cfg(test)]
            Self::Fixture(_) => Err(OriginalActorAccountError::Unavailable),
        }
    }
}

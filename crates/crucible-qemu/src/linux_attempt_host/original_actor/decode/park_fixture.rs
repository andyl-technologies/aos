//! Creates fixed host originals for negative parent-park custody controls.
//!
//! The fixture has no authenticated parent invocation, process, native slot,
//! Source or family stage. It exercises host ownership and refusal only.

use std::sync::Arc;

use crucible_linux_resource::host_services::HostServiceAllocator;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

use super::{OriginalActorAccountError, OriginalActorDecodeOwner};

/// Keeps one controlled original and its decoder accounts for negative tests.
pub struct ControlledOriginalActorParkFixture {
    /// The exact Preparation retained by this fixture's decoder.
    pub original: Arc<HostOperationGuard>,
    /// The issuer of that Preparation, without an authenticated actor role.
    pub supervisor: HostOperationSupervisor,
    /// The host-only decoder whose authority names the same Preparation.
    pub decoder: OriginalActorDecodeOwner,
    /// The fixture's resident bank retained through decoder closure.
    pub resident: HostServiceAllocator,
    /// The fixture's metadata bank retained through decoder closure.
    pub metadata: HostServiceAllocator,
}

impl ControlledOriginalActorParkFixture {
    /// Creates the fixed original and accounts used by negative custody tests.
    ///
    /// No caller-supplied guard or account can replace these fixture owners.
    /// This does not admit a native operation or process.
    ///
    /// # Errors
    /// Returns the original supervisor, account or decoder admission refusal.
    pub fn prepare() -> Result<Self, OriginalActorAccountError> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let resident = HostServiceAllocator::new(1, 64, 1 << 20)?;
        let metadata = HostServiceAllocator::new(1, 64, 1 << 20)?;
        let decoder = OriginalActorDecodeOwner::prepare(&original, &resident, &metadata, 1 << 20)?;

        Ok(Self {
            original,
            supervisor,
            decoder,
            resident,
            metadata,
        })
    }
}

//! CAS project-quota composition for the local campaign store.
//!
//! The raw Linux resource crate owns pinned filesystem verification. This
//! daemon adapter is the first layer that knows both that kernel capability
//! and the content-store quota traits, keeping lower host integration free of
//! storage policy dependencies.

use std::path::Path;
use std::sync::Arc;

use crucible_cas::content_store::{StoreError, StorePhysicalQuotaBinder, StorePhysicalQuotaGuard};
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaError};

/// Binds an operator-installed Linux project quota to one CAS graph leaf.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxProjectQuotaBinder;

#[derive(Debug)]
struct BoundLinuxProjectQuota(LinuxProjectQuotaBinding);

impl LinuxProjectQuotaBinder {
    /// Constructs the stateless daemon-side quota adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl StorePhysicalQuotaBinder for LinuxProjectQuotaBinder {
    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        let binding = LinuxProjectQuotaBinding::bind_existing(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
        )
        .map_err(store_error)?;
        Ok(Arc::new(BoundLinuxProjectQuota(binding)))
    }
}

impl StorePhysicalQuotaGuard for BoundLinuxProjectQuota {
    fn verify(&self) -> Result<(), StoreError> {
        self.0.verify().map_err(store_error)
    }
}

fn store_error(error: LinuxProjectQuotaError) -> StoreError {
    match error {
        LinuxProjectQuotaError::Io {
            operation,
            path,
            source,
        } => StoreError::Io {
            operation,
            path,
            source,
        },
        _ => StoreError::Quota,
    }
}

//! Pins each handle to writable layout two or explicit read-only layout one.

use super::{BucketBinding, FileBucket, files};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_core::bucket::{BucketCapabilities, BucketKey};

/// Selects locations without upgrading an existing namespace.
#[derive(Clone, Copy)]
pub(super) enum Access {
    /// Permits effects only while the persisted namespace remains layout two.
    Writable,
    /// Reads original layout-one locations without probes, locks, or mutations.
    LegacyReadOnly,
}

impl Access {
    /// Returns the exact version selected when this handle opened.
    pub(super) const fn version(self) -> u64 {
        match self {
            Self::Writable => 2,
            Self::LegacyReadOnly => 1,
        }
    }

    /// Reports whether the handle permits only legacy reads.
    pub(super) const fn read_only(self) -> bool {
        matches!(self, Self::LegacyReadOnly)
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Rejects incompatible profiles and changes to the selected layout.
    ///
    /// # Errors
    /// Returns `Unsupported` when the persisted profile or version differs.
    pub(super) fn validate_layout(
        &self,
        capabilities: &BucketCapabilities,
    ) -> Result<(), StoreFailure> {
        if capabilities.layout_version != self.inner.access.version()
            || capabilities.profile != self.profile()
            || capabilities.publication_protocol.is_some()
        {
            // Registered state requires the selected-chain resolver, including
            // for already-open handles. Legacy caches and probes cannot select it.
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        Ok(())
    }

    /// Rejects a changed layout without inferring freshness or performing effects.
    ///
    /// # Errors
    /// Refuses absent, corrupt, incompatible, changed, or unavailable records.
    pub(super) async fn ensure_layout(&self) -> Result<BucketCapabilities, StoreFailure> {
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let bytes = self
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let capabilities =
            BucketCapabilities::decode(&bytes).map_err(|_| files::layout_corrupt())?;
        self.validate_layout(&capabilities)?;
        Ok(capabilities)
    }

    /// Checks layout two while the effect's caller retains the root exclusion.
    ///
    /// # Errors
    /// Refuses read-only access and invalid or changed capability records.
    pub(super) async fn write_layout_locked(&self) -> Result<(), StoreFailure> {
        if self.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        self.ensure_layout().await?;
        Ok(())
    }

    /// Reads legacy state without creating or syncing coordination files.
    ///
    /// # Errors
    /// Refuses unavailable exclusion or invalid and changed capability records.
    pub(super) async fn read_exclusion(&self) -> Result<Option<F::Lock>, StoreFailure> {
        let guard = if self.inner.access.read_only() {
            None
        } else {
            Some(self.exclusive().await?)
        };
        self.ensure_layout().await?;
        Ok(guard)
    }
}

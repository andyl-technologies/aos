//! Performs the terminal direct read of the original collecting native owners.

use super::{InstalledTypedReaderSourceFixture, invalid};
use crucible::node_admission::AdmissionRequest;
use crucible_node_provider::ProviderError;

impl InstalledTypedReaderSourceFixture {
    /// Reads the exact configured world and every original registrar/capsule.
    ///
    /// This is the final trusted source read, not a vendor callback or a cached
    /// runtime validation result. Each handle was issued by the actual guard
    /// after source-authenticated realization and cannot be replaced on resume.
    /// No native or installed callback may follow this read before dispatch.
    ///
    /// # Errors
    /// Refuses changed plan/world/bindings/owners, unavailable original handles,
    /// transferred or uncertain source custody, revoked registration or changed
    /// actual original kernel identities and measured executables.
    pub(in super::super) fn authenticate_current_collection_scope(
        &self,
        request: AdmissionRequest<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_collection_world(request)?;
        self.authenticate_current_native_owners()
    }

    /// Reads every retained original native owner without invoking callbacks.
    ///
    /// The terminal world predicate and durable publisher use the same direct
    /// private gate/epoch and capsule reads. Each caller must authenticate its
    /// complete current plan/world/source request before this final read; this
    /// method supplies neither admission nor publication permission by itself.
    ///
    /// # Errors
    /// Refuses missing, busy, stale, transferred or uncertain original custody,
    /// changed native groups or changed measured original executables.
    pub(in super::super) fn authenticate_current_native_owners(&self) -> Result<(), ProviderError> {
        for source in &self.sources {
            let retained = source.read_handle.try_borrow().map_err(|_| invalid())?;
            retained.as_ref().ok_or_else(invalid)?.ensure_current()?;
        }
        Ok(())
    }
}

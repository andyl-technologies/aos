//! Selects the actual native schema-first Connection writer and complete walk.

use super::*;

impl Connection<crate::client::DeadlineStream> {
    /// Borrows the native Connection's actual complete field writer.
    ///
    /// # Errors
    /// Refuses another process/thread or role, absent codec/frame owners, changed
    /// erased-verifier identity or borrowed actual literal backing.
    pub(crate) fn borrowed_native_settled17_data(
        &self,
    ) -> Result<impl serde::Serialize + '_, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.role != EndpointRole::Provider {
            return Err(invalid());
        }
        self.borrowed_settled_history_data()
    }

    /// Appends every actual native field and repeated shared-view capacity row.
    ///
    /// # Errors
    /// Refuses wrong origin/role, unavailable actual loans or finite bank limits.
    pub(crate) fn observe_native_settled17_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.role != EndpointRole::Provider {
            return Err(invalid());
        }
        self.observe_settled_history_metadata_data(observer)
    }
}

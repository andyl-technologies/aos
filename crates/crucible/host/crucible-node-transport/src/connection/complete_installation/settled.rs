//! Borrows complete native Connection child history without reviving rights.
//!
//! Actual shared payloads are encoded once by the enclosing native17 graph.
//! This view preserves all raw/typed/partial fields and records their real alias
//! edges. Deadline labels are historical roles; host clock coordinates are
//! deliberately unencoded and no fresh deadline or issuer is reconstructed.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct ChildHistory<'a>(&'a InstalledNativeCompleteRestoration);

impl InstalledNativeCompleteRestoration {
    /// Borrows the same installed mapping after checking its retained token edge.
    ///
    /// # Errors
    /// Refuses foreign or borrowed token roots or a changed mapping association.
    pub(in crate::connection) fn borrowed_settled_mapping17_data(
        &self,
    ) -> Result<&Rc<RefCell<PreparedArchivedNativeProtocolMapping>>, ProviderError> {
        self.token
            .authenticate_settled_history_mapping_data(&self.mapping)?;
        Ok(&self.mapping)
    }

    /// Borrows every actual field under its original native owner relation.
    ///
    /// # Errors
    /// Refuses foreign originating roots, borrowed token relations or a changed
    /// installed mapping. This grants no Capture, continuation or installation.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.token
            .authenticate_settled_history_mapping_data(&self.mapping)?;
        Ok(ChildHistory(self))
    }

    /// Appends complete actual child capacities and shared edges without reset.
    ///
    /// # Errors
    /// Refuses foreign/borrowed roots, exhausted admitted banks or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.token
            .authenticate_settled_history_mapping_data(&self.mapping)?;
        let Self { token, mapping } = self;
        token.observe_settled_history_metadata_data(observer)?;
        observer.shared_original(MetadataSharedKind::ArchivedMapping, mapping.as_ref())?;
        Ok(())
    }

    /// Names the defining borrowed field, serializer, option and error headers.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<ChildHistory<'static>>()
            + size_of::<Result<ChildHistory<'static>, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + VerifiedCompleteRestoration::settled_history_counter_scratch_data()
            + field_view_bytes(|value: &'static InstalledNativeCompleteRestoration| {
                let InstalledNativeCompleteRestoration { token, mapping } = value;
                (token, mapping)
            })
    }
}

impl Serialize for ChildHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .token
            .authenticate_settled_history_mapping_data(&self.0.mapping)
            .map_err(serde::ser::Error::custom)?;
        let InstalledNativeCompleteRestoration { token, mapping } = self.0;
        let mut state = serializer.serialize_struct("NativeConnectionChildHistory17", 3)?;
        state.serialize_field("schema", "source-private.complete-installation-history/17")?;
        state.serialize_field(
            "token",
            &token
                .borrowed_settled_history_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        let _ = mapping;
        state.serialize_field("mapping_role", "native-archived-protocol-mapping")?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}

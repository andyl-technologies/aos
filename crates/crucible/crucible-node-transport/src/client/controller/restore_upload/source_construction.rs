//! Lends concrete receive and mapping construction DATA to the Source signer.
//!
//! No mapping, request, index, cut or transport action is constructed. A whole
//! installed policy must precredit the fixed counter/formatter window and all
//! independently retained owners before invoking these bounded visitors.

use super::*;
use crate::handshake::ConnectionAuthority;
use std::mem::size_of;

impl CnpController {
    /// Returns the real full negotiated raw receive/parser/error storage row.
    ///
    /// This is the same generic raw geometry used by initial lifecycle receive,
    /// not a byte-to-heap conversion. Typed transfer DTOs, assigned originals,
    /// correlation/cache growth and Source work remain separate obligations.
    ///
    /// # Errors
    /// Refuses foreign/revoked authority, unsupported frame extent or overflow.
    pub fn original_complete_restore_transfer_raw_receive_storage_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        crate::connection::original_host_initial_raw_receive_storage_data(self.maximum_frame()?)
    }

    /// Borrows a closed ceiling for the two selected mapping normalizations.
    ///
    /// The real historical authority and both full references are borrowed.
    /// The invocation format labels dominate the shorter startup labels, and
    /// the fixed nonce ceiling dominates each byte of either actual nonce. This
    /// DATA view grants no class selection, mapping or request permission.
    ///
    /// # Errors
    /// Refuses foreign/revoked registration or checked data refusal.
    pub fn original_selected_archived_mapping_normalization_projection_data<'a>(
        &'a self,
        archive_protocol: &'a ContentRef,
        native_protocol: &'a ContentRef,
    ) -> Result<impl serde::Serialize + 'a, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        use crate::protocol_snapshot::owned11::{native::outer as native, outer};
        Ok((
            "source-private.archived-protocol-mapping/12",
            archive_protocol,
            native_protocol,
            outer::COMPLETE_CONTROLLER_FORMAT,
            outer::COMPLETE_CONNECTION_FORMAT,
            native::COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
            native::COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT,
            self.authority().historical_owned_view(),
            [255u8; 32],
            "original-fresh-request-cut-retained",
        ))
    }

    /// Names exact borrowed normalization, result, counter and formatter views.
    ///
    /// The generic helper measures the actual opaque historical-view type via
    /// its method signature, without constructing authority or a view. Actual
    /// U64 serialization's one live decimal bank is independently named below.
    pub fn original_restore_transfer_source_projection_counter_scratch_data() -> usize {
        fn layouts<A>(_: fn(&'static ConnectionAuthority) -> A) -> usize {
            size_of::<(
                &str,
                &ContentRef,
                &ContentRef,
                &str,
                &str,
                &str,
                &str,
                A,
                [u8; 32],
                &str,
            )>() + size_of::<
                Result<
                    (
                        &str,
                        &ContentRef,
                        &ContentRef,
                        &str,
                        &str,
                        &str,
                        &str,
                        A,
                        [u8; 32],
                        &str,
                    ),
                    ProviderError,
                >,
            >()
        }
        layouts(ConnectionAuthority::historical_owned_view)
            + size_of::<(&CnpController, &ContentRef, &ContentRef)>()
            + size_of::<Result<usize, ProviderError>>()
            + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
            + 20
    }
}

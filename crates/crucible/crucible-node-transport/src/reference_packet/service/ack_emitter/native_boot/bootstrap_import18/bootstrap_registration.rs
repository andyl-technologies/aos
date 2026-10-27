//! Lends actual native registration DATA from the original live SDK authority.
//!
//! Complete policy, Source/launch, literal Hello and SDK guards surround the
//! callback. No registration graph is copied and no role or connection is issued.

use super::*;
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18CurrentRegistrationView, native_import18_current_registration_view_data,
};

impl OriginalImport18RawBootstrap {
    /// Lends the complete native registration under original policy and SDK guards.
    ///
    /// The native connection ID comes from the same actual authority. No caller
    /// can substitute a controller ID through this loan. Inspection and its Copy
    /// result are independently funded; no view becomes an ACK or phase grant.
    ///
    /// # Errors
    /// Refuses incomplete policy/publication, stale original custody or SDK,
    /// absent typed negotiation, callback refusal or any failed terminal guard.
    pub(in super::super) fn with_bootstrap_native_registration_wire_data<R: Copy>(
        &self,
        inspect: impl FnOnce(
            &PacketNativeImport18CurrentRegistrationView<'_>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_bootstrap_policy_wire_data(|_| {
            self.with_hello_authority_data(|authority| {
                let view = native_import18_current_registration_view_data(authority, None)?;
                inspect(&view)
            })
        })
    }

    /// Quotes actual nested loans and native registration controls for a Copy result.
    ///
    /// Dynamic projection and allocating callback work remain separate.
    ///
    /// # Errors
    /// Refuses checked layout accumulation overflow for the concrete result.
    pub(in super::super) fn bootstrap_native_registration_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            Self::hello_authority_loan_counter_scratch_data::<R>(),
            PacketNativeImport18CurrentRegistrationView::native_counter_scratch_data(),
            size_of::<Result<R, ProviderError>>(),
        ]
        .into_iter()
        .try_fold(
            Self::bootstrap_policy_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(refused),
        )
    }
}

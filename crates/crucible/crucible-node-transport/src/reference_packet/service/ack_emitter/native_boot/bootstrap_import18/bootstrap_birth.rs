//! Lends the original complete typed birth preimage under bootstrap guards.
//!
//! The original private body and Source bank stay owned through either callback
//! outcome. This loan neither copies a bank nor constructs a DOM, private Birth,
//! ACK, Initial, Recipe or native phase permission.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18DecodedBodyLoans, PacketNativeImport18BootstrapTypedBirthView,
};

impl OriginalImport18RawBootstrap {
    /// Lends every birth-association field under the same policy and SDK guards.
    ///
    /// The enclosing policy loan checks original inputs, cut, launch, actual
    /// completed Hello publication and live SDK on both callback outcomes.
    /// The caller separately funds projection and allocating normalization.
    ///
    /// # Errors
    /// Refuses incomplete policy, stale original custody/SDK, malformed birth
    /// DATA, callback refusal or any failed terminal guard.
    pub(in super::super) fn with_bootstrap_birth_wire_data<R: Copy>(
        &self,
        inspect: impl FnOnce(
            &PacketNativeImport18BootstrapTypedBirthView<'_>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_bootstrap_policy_wire_data(|_| {
            let bodies = self.typed_bodies_data()?;
            let view = bodies.boot.bootstrap_birth_wire_data()?;
            inspect(&view)
        })
    }

    /// Quotes actual nested guards and fixed birth-view controls for a Copy result.
    ///
    /// Dynamic inspection, serialization and retained outputs remain separate.
    /// This allocation-free quote supplies no original funding or authority.
    ///
    /// # Errors
    /// Refuses checked layout accumulation overflow for the concrete result.
    pub(in super::super) fn bootstrap_birth_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            PacketNativeImport18BootstrapTypedBirthView::counter_scratch_data(),
            size_of::<OriginalImport18DecodedBodyLoans<'static>>(),
            size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
        ]
        .into_iter()
        .try_fold(
            Self::bootstrap_policy_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(refused),
        )
    }
}

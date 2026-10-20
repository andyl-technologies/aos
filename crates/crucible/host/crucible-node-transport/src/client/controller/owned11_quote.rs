//! Counts the same complete host tuple used by original protocol capture.
//!
//! The source supplies actual precharged banks and the supported supervisor
//! witness. Quoting changes only those metadata banks; no bytes are published,
//! issuer is installed, operational cut is renewed or live authority is issued.

use super::*;
use crate::connection::{OriginalProtocolSupervisor, OriginalSupervisorProtocolView};
use crate::protocol_snapshot::{
    OriginalOwned11StateQuote, ProtocolCaptureCut, ProtocolSnapshotReservation,
};

impl CnpController {
    /// Counts the exact current complete host view in its precharged metadata banks.
    ///
    /// The same tuple and borrowed supervisor state feed actual capture. This
    /// data quote leaves the encoded bank empty and unbound. It does not predict
    /// later request/reply growth or establish eligibility at a Capture cut.
    /// Existing literal, encoded, metadata and alias capacities remain separate
    /// actual allocations in the returned facts.
    ///
    /// # Errors
    /// Refuses foreign/revoked actors, unresolved restore owners, unsupported or
    /// active supervisor callbacks, incomplete profile coverage, conflicting
    /// loans, insufficient original banks, or checked traversal/encoding limits.
    /// Partial metadata rows remain in the supplied reservation on refusal.
    pub fn quote_original_owned11_state_with_supervisor(
        &self,
        reservation: &mut ProtocolSnapshotReservation,
        witness: &OriginalProtocolSupervisor,
    ) -> Result<OriginalOwned11StateQuote, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.ensure_no_pending_original_complete_restore()?;
        if self
            .original_native5_fresh_restore_allocation_selection()?
            .is_some()
        {
            return Err(ProviderError::Correlation(
                "fresh query owner requires extended host complete class",
            ));
        }
        if self.fenced || !reservation.uses_owned11_encoding() {
            return Err(ProviderError::Correlation(
                "complete host quote class absent",
            ));
        }
        self.session
            .authenticate_original_protocol_supervisor(witness)?;
        self.session.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(
            self.session.original_native5_codec_owner(),
            ProtocolCaptureCut::HostSettled,
            true,
        )?;
        let original_storage = self.original_native5_storage_facts()?;
        let mut quote = None;
        witness.with_original_state(&mut |supervisor| {
            let data = self.complete_owned11_protocol_data(&supervisor)?;
            quote = Some(reservation.quote_original_host_owned11(
                &data,
                original_storage,
                |observer| {
                    self.observe_owned11_metadata(observer)?;
                    witness.observe_original_header(observer)?;
                    supervisor.observe_owned11_metadata(observer)
                },
            )?);
            Ok(())
        })?;
        self.session
            .authenticate_original_protocol_supervisor(witness)?;
        self.authenticate_native5_source_codec()?;
        quote.ok_or(ProviderError::Correlation(
            "complete host state quote absent",
        ))
    }

    pub(super) fn complete_owned11_protocol_data<'a>(
        &'a self,
        supervisor: &'a OriginalSupervisorProtocolView<'_>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        if self
            .original_native5_fresh_restore_allocation_selection()?
            .is_some()
        {
            return Err(ProviderError::Correlation(
                "fresh query owner requires extended host complete class",
            ));
        }
        Ok((
            crate::protocol_snapshot::owned11::outer::COMPLETE_CONTROLLER_FORMAT,
            &self.route.node,
            &self.route.execution_owner,
            U64::new(self.budget.as_secs()),
            self.budget.subsec_nanos(),
            self.fenced,
            self.session.original_native5_capture_profile()?,
            self.session.owned_protocol_view(),
            self.custody.owned_protocol_view(),
            self.original_ack_admit
                .as_ref()
                .map(assigned_admit::AssignedOriginalCanonicalAckAdmit::owned_protocol_view),
            supervisor,
            self.original_complete_restore
                .as_ref()
                .map(assigned_restore::AssignedOriginalCompleteRestore::owned_protocol_view),
        ))
    }
}

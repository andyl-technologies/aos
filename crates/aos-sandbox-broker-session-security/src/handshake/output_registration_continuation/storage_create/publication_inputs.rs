//! Borrows completed Prepare originals for the separate publication producer.
//!
//! The original flight retains the proposal, signed plan, authenticated terminal
//! and complete Ready input. This view creates no Apply grant, signed plan,
//! currentness loan or resource reservation. The installed caller separately
//! requires its same-operation terminal seal before lending the view.

use aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1;
use aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1;

use super::*;

/// Borrows the actual completed Prepare and its original publication inputs.
///
/// These are comparison DATA. A later issuer must independently authorize the
/// exact Apply action and its broker-minted catalog, and pay before decoding,
/// signing, retaining or sending anything. No owner or backing is extracted.
#[doc(hidden)]
pub struct CreateStorageCompletedPreparationDataV1<'held> {
    proposed: &'held ProtectedStorageCreatePreparationV1,
    outcome: &'held AuthenticatedBrokerMethodOutcomeV1,
    response: &'held PrepareStorageCatalogResponse,
    bundle: ReadyBundleDataV1<'held>,
}

impl<'held> CreateStorageCompletedPreparationDataV1<'held> {
    /// Borrows the original nonmutating Create proposal.
    #[must_use]
    pub const fn proposed(&self) -> &'held ProtectedStorageCreatePreparationV1 {
        self.proposed
    }

    /// Borrows the original authenticated, durably committed Prepare outcome.
    #[must_use]
    pub const fn outcome(&self) -> &'held AuthenticatedBrokerMethodOutcomeV1 {
        self.outcome
    }

    /// Borrows the already decoded and checked broker-minted catalog response.
    #[must_use]
    pub const fn response(&self) -> &'held PrepareStorageCatalogResponse {
        self.response
    }

    /// Borrows the same completed Ready framing without copying nested inputs.
    #[must_use]
    pub const fn bundle(&self) -> ReadyBundleDataV1<'held> {
        self.bundle
    }
}

impl OriginalStorageCreatePreparationFlightV1 {
    /// Starts the separate Root Apply opening from these same completed inputs.
    ///
    /// The Native loan independently compares the full Ready and actual C9
    /// packet commitments and pays every native receiving destination first.
    /// The returned owner retains native failures and the unfinished socket;
    /// callers retain it before inspecting failure or entering later signing.
    ///
    /// # Errors
    /// Refuses an incomplete preparation/bundle or actual C23 preconstruction
    /// admission. The existing flight and receiver retain their original causes.
    #[doc(hidden)]
    pub fn begin_original_storage_apply_root_once_v1(
        &self,
        original_bundle: &OriginalStorageReadyBundleFlightV1,
        loan: &mut aos_sandbox::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
        co_resident: aos_sandbox_core::ResourceVector,
    ) -> Result<aos_sandbox::normal_root::RootStorageApplyClientOriginalV1,
        aos_sandbox::ResourceReservationErrorV1>
    {
        let completed = self.completed_preparation_data_v1(original_bundle)
            .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        let ready = original_bundle.encoded_bundle_v1()
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        loan.begin_storage_apply_root_once_v1(controller, ready, completed.outcome(), co_resident)
    }

    /// Borrows completed originals after their actual C9 and Root exchange.
    ///
    /// No native operation, allocation or semantic acceptance occurs here. The
    /// previously checked immutable Ready framing is borrowed from the same
    /// bundle owner. A foreign bundle is rejected using the actual retained
    /// request and signed plan; this does not turn historical data into a grant.
    ///
    /// # Errors
    /// Rejects an incomplete or refused flight, missing retained response,
    /// incomplete bundle, or a proposal that differs from the sent request.
    #[doc(hidden)]
    pub fn completed_preparation_data_v1<'held>(
        &'held self,
        original_bundle: &'held OriginalStorageReadyBundleFlightV1,
    ) -> Result<CreateStorageCompletedPreparationDataV1<'held>, OutputPreparationClosedV1> {
        if !matches!(self.recorded_outcome, Some(Ok(())))
            || !matches!(self.outcome_exchanged, Some(Ok(())))
        {
            return Err(OutputPreparationClosedV1);
        }
        let outcome = self.committed_prepare_outcome_v1()?;
        let proposed = original_bundle.proposed_for_create_use_v1()
            .ok_or(OutputPreparationClosedV1)?;
        // The authenticated request already owns the sole semantic decode.
        // Join the complete proposal to that same retained meaning before
        // lending any historical inputs to the separately admitted Apply.
        let decoded = outcome.request().storage_create_preparation_data_v1()
            .ok_or(OutputPreparationClosedV1)?;
        if !proposed.matches_decoded(decoded) {
            return Err(OutputPreparationClosedV1);
        }
        let signed = self.signed_plan.as_ref().ok_or(OutputPreparationClosedV1)?;
        let request = self.request_header.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(OutputPreparationClosedV1)?;
        let response = self.io.response.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(OutputPreparationClosedV1)?;
        let [grant] = signed.plan().grants() else {
            return Err(OutputPreparationClosedV1);
        };
        if grant.verb() != aos_sandbox_core::BrokerVerb::StoragePrepareCatalog
            || grant.target() != aos_sandbox_core::BrokerGrantTarget::Assignment
            || grant.argument_commitment() != proposed.argument_commitment()
        {
            return Err(OutputPreparationClosedV1);
        }
        let assignment = proposed.assignment();
        let fence = request.fence.as_option().ok_or(OutputPreparationClosedV1)?;
        let header = request.header.as_option().ok_or(OutputPreparationClosedV1)?;
        if request.operation_id.as_slice() != proposed.operation_id().as_bytes()
            || response.operation_id != request.operation_id
            || signed.plan().assignment() != assignment
            || header.request_id.as_slice() != proposed.signed_request_id_v1(
                signed.digest(), signed.canonical_signature(),
            )
            || outcome.request().request_id().as_slice() != header.request_id.as_slice()
            || fence.sandbox_id.as_slice() != assignment.sandbox().as_bytes()
            || fence.incarnation_id.as_slice() != assignment.incarnation().as_bytes()
            || fence.assignment_epoch != assignment.epoch().get()
            || fence.desired_generation != assignment.desired_generation().get()
            || fence.assignment_digest.as_slice() != assignment.digest().as_bytes()
        {
            return Err(OutputPreparationClosedV1);
        }

        let bytes = original_bundle.encoded_bundle_v1().ok_or(OutputPreparationClosedV1)?;
        let bundle = ReadyBundleDataV1::borrow_field_framing_data_v1(bytes)
            .map_err(|_| OutputPreparationClosedV1)?;
        if bundle.proposed_storage != proposed.canonical_bytes() {
            return Err(OutputPreparationClosedV1);
        }
        Ok(CreateStorageCompletedPreparationDataV1 { proposed, outcome, response, bundle })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_flight_cannot_lend_a_preparation_or_publication_input() {
        let flight = OriginalStorageCreatePreparationFlightV1::empty();
        let bundle = OriginalStorageReadyBundleFlightV1::empty();

        assert!(flight.completed_preparation_data_v1(&bundle).is_err());
        assert!(flight.completed_preparation_data_v1(&bundle).is_err());
        assert!(flight.shared.inner.committed.is_none());
        assert!(flight.io.response.is_none());
    }
}

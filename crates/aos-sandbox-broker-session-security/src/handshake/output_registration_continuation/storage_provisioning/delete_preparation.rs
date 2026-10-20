//! Retains signed Delete26 on the same protected Session flight.
//!
//! The actual upper loan owns C17 and Root posts. This adapter lends only the
//! completed Session result and retains every SDK/native prefix through those posts.

use super::delete_session::{
    DeleteStorageLoanV3, DeleteStoragePredecessorV3, DeleteStorageSessionFlightOriginalV3,
};
use super::*;

/// Returns the protocol ceiling checked before native Delete26 receive.
#[must_use]
pub const fn delete_storage_preparation_response_maximum_v3() -> usize {
    aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
}

/// Describes the actual negotiated Session flight without granting admission.
#[must_use]
pub fn delete_storage_preparation_security_shape_v3(
    negotiated_maximum: usize,
    request_bytes: usize,
) -> Option<aos_sandbox::StorageProvisioningSessionIoShapeDataV1> {
    super::delete_session::delete_security_shape_v3(negotiated_maximum, request_bytes)
}

/// Retains one authenticated Delete26 request, receipt and independent posts.
///
/// Construction is inert. The same completed Inventory owner and genuine upper
/// loan must qualify the held Session before any request or native stage enters.
#[doc(hidden)]
#[must_use = "retain the whole flight through the upper C and Root posts"]
pub struct DeleteStoragePreparationSessionIoOriginalV3 {
    inner: DeleteStorageSessionFlightOriginalV3,
}

impl DeleteStoragePreparationSessionIoOriginalV3 {
    /// Constructs empty destinations without allocation, IO or permission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DeleteStorageSessionFlightOriginalV3::new(ProvisioningKindV4::DeletePreparation),
        }
    }

    /// Executes the actual signed request under the same genuine upper loan.
    ///
    /// # Errors
    /// Retains entry, association, request, receipt and native post failures. The
    /// caller must finish its already-entered upper C and Root posts on failure.
    pub fn prepare_once_v3(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'_>,
        predecessor: &super::super::delete_inventory::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        session.run_delete_storage_preparation_once_v3(self, original, predecessor)
    }

    pub(crate) fn run_inner_once_v3(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'_>,
        predecessor: &super::super::delete_inventory::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.inner.run_once_v3(
            session,
            DeleteStorageLoanV3::Preparation(original),
            DeleteStoragePredecessorV3::Inventory(predecessor),
        )
    }

    /// Retires the finite append helper after the upper C and Root posts.
    ///
    /// # Errors
    /// Refuses incomplete SDK/upper posts, reentry or actual native disposal failure.
    pub fn retire_completed_native_window_once_v3(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.require_completed_v3()?;
        if self.inner.retirement.is_some() {
            return Err(OutputPreparationClosedV1);
        }
        session.retire_delete_storage_preparation_window_once_v3(self, original)
    }

    pub(crate) fn retire_inner_once_v3(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.inner
            .retire_once_v3(session, DeleteStorageLoanV3::Preparation(original))
    }

    /// Borrows only the completed actual outcome and native boundary as historical DATA.
    ///
    /// # Errors
    /// Refuses incomplete entry, association, receipt, native posts or failed retirement.
    pub fn require_completed_v3(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &[u8; 64]), OutputPreparationClosedV1> {
        self.inner.require_completed_v3()
    }

    /// Borrows the canonical successful response after the actual Session posts.
    ///
    /// # Errors
    /// Refuses incomplete native completion or a missing canonical success response.
    pub fn completed_preparation_response_data_v3(
        &self,
    ) -> Result<
        &aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse,
        OutputPreparationClosedV1,
    > {
        self.require_completed_v3()?;
        self.inner
            .flight
            .outcome
            .as_ref()
            .ok_or(OutputPreparationClosedV1)?
            .retained_storage_preparation_response_data_v3()
            .ok_or(OutputPreparationClosedV1)
    }

    /// Borrows the actual outcome only after every Session post succeeded.
    #[must_use]
    pub fn completed_outcome_v3(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.require_completed_v3().ok().map(|(outcome, _)| outcome)
    }

    /// Borrows the first actual error while its owning prefixes remain resident.
    #[must_use]
    pub fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.failure_v3()
    }

    /// Identifies the selected lower original without replacing an earlier SDK cause.
    #[must_use]
    pub fn original_failure_selected_v3(&self) -> bool {
        self.inner.original_failure_selected_v3()
    }
}

impl Default for DeleteStoragePreparationSessionIoOriginalV3 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_or_raw_native_position_cannot_complete_delete26() {
        let mut flight = DeleteStoragePreparationSessionIoOriginalV3::new();
        assert!(flight.require_completed_v3().is_err());

        flight.inner.native = Some(Ok([7; 64]));
        flight.inner.entry = Some(Ok(()));
        flight.inner.association = Some(Ok(()));
        assert!(flight.require_completed_v3().is_err());
        assert!(flight.completed_outcome_v3().is_none());
    }

    #[test]
    fn shape_uses_actual_negotiated_receive_and_exact_single_flight_layout() {
        let shape = delete_storage_preparation_security_shape_v3(4096, 1024).unwrap();
        let negotiated = delete_storage_preparation_security_shape_v3(8192, 1024).unwrap();
        assert_eq!(shape.response_bytes, 4096);
        assert_eq!(negotiated.response_bytes, 8192);
        assert!(negotiated.receiving_bytes >= shape.receiving_bytes);
        assert_eq!(shape.request_bytes, 1024);
        assert_eq!(shape.namespace_entries, 0);
        assert!(delete_storage_preparation_security_shape_v3(0, 1024).is_none());
        assert!(delete_storage_preparation_security_shape_v3(4096, 0).is_none());
    }
}

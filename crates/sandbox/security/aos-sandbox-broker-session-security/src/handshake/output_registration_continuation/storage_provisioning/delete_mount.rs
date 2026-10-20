//! Retains signed MountReap62 on the same protected Session flight.
//!
//! The actual upper loan owns C17 and Root posts. This adapter lends only the
//! completed Session result and retains every SDK/native prefix through those posts.

use super::delete_session::{
    DeleteStorageLoanV3, DeleteStoragePredecessorV3, DeleteStorageSessionFlightOriginalV3,
};
use super::*;

/// Returns the protocol ceiling checked before native MountReap62 receive.
#[must_use]
pub const fn delete_mount_reap_response_maximum_v4() -> usize {
    aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES
}

/// Describes the actual negotiated Session flight without granting admission.
#[must_use]
pub fn delete_mount_reap_security_shape_v4(
    negotiated_maximum: usize,
    request_bytes: usize,
) -> Option<aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1> {
    StorageProvisioningSessionIoOriginalV1::shape_data_v4(
        negotiated_maximum,
        request_bytes,
        inline_bytes_v4()?,
        0,
    )
}

pub(super) fn inline_bytes_v4() -> Option<usize> {
    let additional = size_of::<DeleteMountReapSessionIoOriginalV4>()
        .checked_sub(size_of::<DeleteStorageSessionFlightOriginalV3>())?;
    super::delete_session::inline_bytes_v3()?.checked_add(additional.checked_mul(2)?)
}

#[derive(Debug, thiserror::Error)]
enum ReapResultErrorV4 {
    #[error("completed Mount62 has no retained canonical namespace result")]
    Missing,
    #[error("completed Mount62 namespace has lifecycle {0:?}, expected Released")]
    Lifecycle(aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorLifecycleV1),
}

/// Retains one authenticated MountReap62 request, receipt and independent posts.
///
/// Construction is inert. The same completed Mount16 owner and genuine upper
/// loan must qualify the held Session before any request or native stage enters.
#[doc(hidden)]
#[must_use = "retain the whole flight through the upper C and Root posts"]
pub struct DeleteMountReapSessionIoOriginalV4 {
    inner: DeleteStorageSessionFlightOriginalV3,
    released: Option<Result<(), ReapResultErrorV4>>,
}

impl DeleteMountReapSessionIoOriginalV4 {
    /// Constructs empty destinations without allocation, IO or permission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DeleteStorageSessionFlightOriginalV3::new(ProvisioningKindV4::DeleteMount),
            released: None,
        }
    }

    /// Executes the actual signed request under the same genuine upper loan.
    ///
    /// # Errors
    /// Retains entry, association, request, receipt and native post failures. The
    /// caller must finish its already-entered upper C and Root posts on failure.
    pub fn apply_once_v4(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::OriginalDeleteMountReapLoanV4<'_>,
        predecessor: &super::super::delete_inventory::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        session.run_delete_mount_reap_once_v4(self, original, predecessor)
    }

    pub(crate) fn run_inner_once_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::OriginalDeleteMountReapLoanV4<'_>,
        predecessor: &super::super::delete_inventory::DeleteInventoryAnswerOriginalsV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.released.is_some() {
            return Err(OutputPreparationClosedV1);
        }
        self.inner.run_once_v3(
            session,
            DeleteStorageLoanV3::Mount(original),
            DeleteStoragePredecessorV3::Inventory(predecessor),
        )?;
        // Retain this actual semantic refusal before returning to the upper
        // borrower, whose independently prepaid C/Root posts remain owed.
        self.released = Some(match self.inner.flight.outcome.as_ref().and_then(|capture| capture.retained_mount_namespace_result_data_v2()) {
            Some(resource) if resource.lifecycle() == aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorLifecycleV1::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED => Ok(()),
            Some(resource) => Err(ReapResultErrorV4::Lifecycle(resource.lifecycle())),
            None => Err(ReapResultErrorV4::Missing),
        });
        if matches!(self.released, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Retires the finite append helper after the upper C and Root posts.
    ///
    /// # Errors
    /// Refuses incomplete SDK/upper posts, reentry or actual native disposal failure.
    pub fn retire_completed_native_window_once_v4(
        &mut self,
        session: &mut crate::DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::OriginalDeleteMountReapLoanV4<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.require_completed_v4()?;
        if self.inner.retirement.is_some() {
            return Err(OutputPreparationClosedV1);
        }
        session.retire_delete_mount_reap_window_once_v4(self, original)
    }

    pub(crate) fn retire_inner_once_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox_controller_domain::OriginalDeleteMountReapLoanV4<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.inner
            .retire_once_v3(session, DeleteStorageLoanV3::Mount(original))
    }

    /// Borrows only the completed actual outcome and native boundary as historical DATA.
    ///
    /// # Errors
    /// Refuses incomplete entry, association, receipt, native posts or failed retirement.
    pub fn require_completed_v4(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &[u8; 64]), OutputPreparationClosedV1> {
        let completed = self.inner.require_completed_v3()?;
        if !matches!(self.released, Some(Ok(()))) {
            return Err(OutputPreparationClosedV1);
        }
        Ok(completed)
    }

    /// Borrows the canonical successful response after the actual Session posts.
    ///
    /// # Errors
    /// Refuses incomplete native completion or a missing canonical success response.
    pub fn completed_reap_response_data_v4(
        &self,
    ) -> Result<
        &aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1,
        OutputPreparationClosedV1,
    > {
        self.require_completed_v4()?;
        self.inner
            .flight
            .outcome
            .as_ref()
            .ok_or(OutputPreparationClosedV1)?
            .retained_mount_namespace_result_data_v2()
            .ok_or(OutputPreparationClosedV1)
    }

    /// Borrows the actual outcome only after every Session post succeeded.
    #[must_use]
    pub fn completed_outcome_v4(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.require_completed_v4().ok().map(|(outcome, _)| outcome)
    }

    /// Borrows the first actual error while its owning prefixes remain resident.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.failure_v3().or_else(|| {
            self.released
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as &(dyn Error + 'static))
        })
    }

    /// Identifies the selected lower original without replacing an earlier SDK cause.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        self.inner.original_failure_selected_v3()
    }
}

impl Default for DeleteMountReapSessionIoOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copied_native_boundary_cannot_adopt_a_released_namespace() {
        let mut original = DeleteMountReapSessionIoOriginalV4::new();
        original.inner.native = Some(Ok([9; 64]));
        original.inner.entry = Some(Ok(()));
        original.inner.association = Some(Ok(()));

        assert!(original.require_completed_v4().is_err());
        assert!(original.completed_reap_response_data_v4().is_err());
    }
}

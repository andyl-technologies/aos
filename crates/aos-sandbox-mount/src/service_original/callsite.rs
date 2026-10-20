//! Lends only the same Mount state/Store authority to its two closed methods.

use super::*;
use aos_sandbox_broker::receiving::{FixedServiceOperationOriginalV4,
    MountAttachmentAnchorReceivingLoanV4};

/// Borrows a response produced only by the actual closed Mount domain recipe.
///
/// Private construction binds these bytes to the same authenticated request.
/// This is a domain observation; Session commit/send and independent native
/// after obligations remain with their actual protected Security receiver.
pub struct MountServiceObservationV4<'held> {
    pub(super) body: &'held [u8],
    pub(super) request_id: [u8; 16],
    pub(super) method: u32,
    pub(super) signed_request_digest: [u8; 32],
}

impl MountServiceObservationV4<'_> {
    /// Borrows the exact successful domain response still held by its original.
    #[must_use]
    pub const fn body_v4(&self) -> &[u8] { self.body }

    /// Returns the same authenticated request's identifier.
    #[must_use]
    pub const fn request_id_v4(&self) -> [u8; 16] { self.request_id }

    /// Returns the exact closed method that produced this response.
    #[must_use]
    pub const fn method_v4(&self) -> u32 { self.method }

    /// Returns the signed packet commitment of that same authenticated request.
    #[must_use]
    pub const fn signed_request_digest_v4(&self) -> [u8; 32] { self.signed_request_digest }
}

/// Borrows the actual held Mount authority, writer and native Store together.
///
/// It exposes no Journal, descriptor, authority-adoption port or arbitrary
/// callback. Only the real service can construct this view alongside its
/// independently purpose-checked image-enrolled receiving loan.
pub struct MountServiceDomainCallsiteV4<'held> {
    pub(super) state: &'held mut Journal,
    pub(super) state_opening: &'held MountStateCapturedJournalOpenV4,
    pub(super) authority: &'held MountAuthorityV1,
    pub(super) store: &'held mut DestinationSlotStoreV1,
    pub(super) method: u32,
}

impl MountAttachmentAnchorServiceOriginalV4 {
    /// Borrows the native cause from the same captured cold Session opener.
    ///
    /// The actual SDK caller selects this diagnostic only when that original
    /// Journal prefix was its first refusal. This comparison lends no Journal,
    /// descriptor, replay result or completion authority.
    #[must_use]
    pub fn captured_session_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.session_opening.failure()
    }

    /// Borrows the exact same operation's first original receiving refusal.
    ///
    /// The lower getter joins the actual enrolled invocation and role before
    /// exposing a ledger cause. It performs no observation or admission and
    /// cannot replace an earlier operation/native error with a late post.
    #[must_use]
    pub fn operation_failure_v4<'held>(
        &'held self, operation: &'held FixedServiceOperationOriginalV4,
    ) -> Option<&'held (dyn Error + 'static)> {
        operation.failure_with_common_v4(&self.common).or_else(|| self.failure())
    }

    /// Borrows the genuine Mount62 loan and same state/Store callsite together.
    ///
    /// # Errors
    /// Refuses incomplete startup, missing held objects or the original F debit.
    pub fn begin_attachment_anchor_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(MountAttachmentAnchorReceivingLoanV4<'held>, MountServiceDomainCallsiteV4<'held>)> {
        self.require_service_ready()?;
        let fixed = self.admit_callsite_header(fixed)?;
        let state = self.state.as_mut().ok_or_else(|| closed("Mount state original is absent"))?;
        let authority = self.authority.as_ref().ok_or_else(|| closed("Mount authority original is absent"))?;
        let store = self.store.as_mut().ok_or_else(|| closed("Mount Store original is absent"))?;
        let loan = self.common.begin_mount_attachment_anchor_once_v4(operation, fixed)
            .map_err(|_| closed("Mount62 original receiving refused"))?;
        Ok((loan, MountServiceDomainCallsiteV4 { state, state_opening: &self.state_opening, authority, store, method: 62 }))
    }

    /// Borrows the distinct Mount16 inventory loan and same physical Store.
    ///
    /// # Errors
    /// Refuses incomplete startup, missing held objects or the original F debit.
    pub fn begin_attachment_inventory_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(MountAttachmentAnchorReceivingLoanV4<'held>, MountServiceDomainCallsiteV4<'held>)> {
        self.require_service_ready()?;
        let fixed = self.admit_callsite_header(fixed)?;
        let state = self.state.as_mut().ok_or_else(|| closed("Mount state original is absent"))?;
        let authority = self.authority.as_ref().ok_or_else(|| closed("Mount authority original is absent"))?;
        let store = self.store.as_mut().ok_or_else(|| closed("Mount Store original is absent"))?;
        let loan = self.common.begin_mount_attachment_anchor_inventory_once_v4(operation, fixed)
            .map_err(|_| closed("Mount16 original receiving refused"))?;
        Ok((loan, MountServiceDomainCallsiteV4 { state, state_opening: &self.state_opening, authority, store, method: 16 }))
    }

    pub(super) fn require_service_ready(&self) -> Result<()> {
        if !self.ready || self.first.is_some() || !matches!(self.startup, Some(Ok(()))) {
            return Err(closed("Mount original service startup remains closed"));
        }
        Ok(())
    }

    fn admit_callsite_header(&mut self, fixed: ResourceVector) -> Result<ResourceVector> {
        // A completed prior interval may have left successful geometry DATA.
        // Refusal is sticky on the actual service and cannot be replaced.
        self.callsite_geometry = Some(add_callsite_header(fixed));
        match self.callsite_geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(fixed) => Ok(fixed),
            None => {
                self.first.get_or_insert(Failure::Geometry);
                Err(closed("Mount callsite geometry remains closed"))
            }
        }
    }
}

fn add_callsite_header(fixed: ResourceVector) -> std::result::Result<ResourceVector, AccountingError> {
    use aos_sandbox_core::ResourceDimension as D;
    let bytes = std::mem::size_of::<MountServiceDomainCallsiteV4<'_>>().checked_mul(2)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
    fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

//! Retains the same Mount16 physical census and complete response encoder.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use crate::destination_slot::{AttachmentAnchorInventoryV1,
    MountAttachmentAnchorInventoryOriginalV4, MountAttachmentAnchorInventoryShapeDataV4};
use super::*;

mod absence;
use absence::MountNativeAbsenceOriginalV2;

/// Retains one genuine fresh Mount inventory and every native read prefix.
///
/// Construction performs no IO. The same distinct Mount16 loan pays the
/// complete current census before the sole Store collector enters native work.
#[derive(Default)]
pub struct MountServiceInventoryOriginalV4 {
    entered: bool,
    shape: Option<Result<MountAttachmentAnchorInventoryShapeDataV4>>,
    header: Option<std::result::Result<ResourceVector, AccountingError>>,
    representation: Option<std::result::Result<ResourceVector, AccountingError>>,
    admitted: Option<std::result::Result<(), Closed>>,
    native: MountAttachmentAnchorInventoryOriginalV4,
    absence: MountNativeAbsenceOriginalV2,
    absence_before: Option<Result<()>>,
    absence_after: Option<Result<()>>,
    absence_selected: bool,
    collected: Option<Result<()>>,
    anchors: Option<Vec<AttachmentAnchorInventoryV1>>,
    response: Option<Result<Vec<u8>>>,
    identity: Option<([u8; 16], [u8; 32])>,
    result: Option<Result<()>>,
    native_selected: bool,
    closed: Option<MountError>,
}

impl MountServiceInventoryOriginalV4 {
    /// Constructs an empty physical inventory destination.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Physically retires a successful Mount16 census after actual F posts.
    ///
    /// # Errors
    /// Refuses another request, failed body or unfinished native interval.
    pub fn dispose_completed_inventory_once_v5(&mut self,
        loan: &MountAttachmentAnchorReceivingLoanV4<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        loan.require_completed_inventory_interval_v5(16)
            .map_err(|_| closed("Mount inventory native interval is unfinished"))?;
        if !self.entered || !matches!(self.result, Some(Ok(())))
            || !matches!(self.response, Some(Ok(_)))
            || self.identity != Some((request.request_id(), request.signed_request_digest()))
            || request.method() != BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS {
            return Err(closed("Mount inventory positive disposal refused"));
        }
        // Entered failed owners still abort on Drop. Only this actual positive
        // body and its posted F interval may release their native File owners.
        self.entered = false;
        drop(std::mem::replace(self, Self::new()));
        Ok(())
    }

    /// Borrows the actual receiving, native or encoding refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.shape.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.header.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.representation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.admitted.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| if self.absence_selected { self.absence.failure_v2() } else { None })
            .or_else(|| self.native.failure())
            .or_else(|| self.response.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Identifies a source-native or financial refusal held by the actual loan.
    #[must_use]
    pub const fn original_failure_selected_v4(&self) -> bool {
        self.native_selected
    }
}

impl Drop for MountServiceInventoryOriginalV4 {
    fn drop(&mut self) {
        if self.entered {
            std::process::abort();
        }
    }
}

impl MountServiceDomainCallsiteV4<'_> {
    /// Produces only the full current Mount16 inventory under its own interval.
    ///
    /// # Errors
    /// Retains exact purpose/currentness, complete geometry, native census and
    /// full schema-encoding failures. No partial census is published.
    pub fn inventory_once_v4<'held>(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        original: &'held mut MountServiceInventoryOriginalV4,
    ) -> Result<MountServiceObservationV4<'held>> {
        if original.entered {
            original.closed.get_or_insert_with(|| closed("Mount inventory cannot reenter"));
            return Err(closed("Mount inventory original remains closed"));
        }
        original.entered = true;
        original.identity = Some((request.request_id(), request.signed_request_digest()));
        original.result = Some(self.inventory_inner(request, loan, original));
        if !matches!(original.result, Some(Ok(()))) {
            return Err(closed("Mount inventory original retained a refusal"));
        }
        let body = original.response.as_ref().and_then(|value| value.as_ref().ok())
            .map(Vec::as_slice).ok_or_else(|| closed("Mount full inventory response is absent"))?;
        Ok(MountServiceObservationV4 {
            body, request_id: request.request_id(), method: 16,
            signed_request_digest: request.signed_request_digest(),
        })
    }

    fn inventory_inner(&mut self, request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        original: &mut MountServiceInventoryOriginalV4,
    ) -> Result<()> {
        if self.method != 16 || request.method() != BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS {
            return Err(closed("Mount inventory does not match the authenticated method"));
        }
        self.state.ensure_healthy()?;
        if loan.require_inventory_current_v4().is_err() {
            original.native_selected = true;
            return Err(closed("Mount inventory native interval is not current"));
        }
        original.shape = Some(MountAttachmentAnchorInventoryShapeDataV4::for_current_v4(self.store));
        let shape = original.shape.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| closed("Mount inventory shape refused"))?.receiving_demand_v4()?;
        original.header = Some((|| {
            use aos_sandbox_model::ResourceDimension as D;
            let bytes = std::mem::size_of::<MountServiceInventoryOriginalV4>().checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let header = original.header.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| closed("Mount inventory header geometry refused"))?;
        original.representation = Some(shape.checked_add(header));
        let complete = original.representation.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| closed("Mount inventory complete geometry refused"))?;
        original.admitted = Some(loan.require_additional_representation_v4(complete));
        if !matches!(original.admitted, Some(Ok(()))) {
            original.native_selected = true;
            return Err(closed("Mount inventory whole representation refused"));
        }
        let empty = self.state.all_records().next().is_none() && self.store.inventory_custody_empty_v2();
        if empty {
            original.absence_before = Some(original.absence.before_once_v2(loan, self.store, self.state, self.state_opening));
            if !matches!(original.absence_before, Some(Ok(()))) { original.absence_selected = true; }
        }
        if !original.absence_selected {
            original.collected = Some(original.native.collect_once_v4(self.store));
            if matches!(original.collected, Some(Ok(()))) {
                original.anchors = original.native.take_completed_once_v4();
            }
        }
        if empty {
            original.absence_after = Some(original.absence.finish_after_once_v2(loan, self.store, self.state, self.state_opening,
                request.request_id()));
            // An earlier ordinary census failure remains ahead of later owed
            // root/FDStore/clock failures. Every native original stays resident.
            if !matches!(original.absence_after, Some(Ok(())))
                && (original.absence_selected || matches!(original.collected, Some(Ok(())))) {
                original.absence_selected = true;
            }
            if original.absence_selected {
                original.native_selected = original.absence.original_failure_selected_v2();
                return Err(closed("Mount complete native absence retained refusal"));
            }
        }
        if !matches!(original.collected, Some(Ok(()))) {
            return Err(closed("Mount inventory native prefix refused"));
        }
        let anchors = original.anchors.as_deref().ok_or_else(|| closed("Mount physical census is absent"))?;
        let invocation = loan.actual_invocation_data_v4().map_err(|_| {
            original.native_selected = true;
            closed("Mount inventory original invocation is absent")
        })?;
        original.response = Some(crate::broker::encode_held_destination_inventory_with_absence_v2(
            self.store, self.store.retained_kernel_boot_id_v4(), self.state.snapshot_sequence(), invocation,
            anchors.iter().copied(), if empty { original.absence.encoded_v2() } else { None }));
        let bytes = original.response.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| closed("Mount inventory schema refused"))?;
        if bytes.len() > request.maximum_response_bytes() as usize {
            return Err(closed("Mount inventory exceeds the authenticated response maximum"));
        }
        Ok(())
    }
}

//! Retains the fixed Session post invoice before Core lends its C23 owner.
//!
//! The genuine installed caller obtains this named representation DATA from
//! Security's compiled post/floor supplier. It supplies only Memory and native
//! descriptor demand, never a payer, account, arbitrary vector or permission.

use super::*;

/// Names the compiled independently owed Session post's fixed representation.
///
/// The sole installed caller obtains both fields from Security's complete
/// retained-post supplier. Rust field storage is Memory, not namespace entries.
/// This inert DATA cannot create an original or grant IO/append authority.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageProvisioningSessionPostShapeDataV1 {
    /// Actual post/carrier/native/floor backing, including construction overlap.
    pub receiving_bytes: usize,
    /// Actual simultaneously retained native descriptors, outside raw recvmsg.
    pub open_files: usize,
}

impl StorageProvisioningSessionPostShapeDataV1 {
    pub(super) fn checked_demand_v1(self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        use aos_sandbox_linux::self_execution::SelfExecutionObservationV1;
        // Every retained post includes the same actual native execution
        // sampler. This is only a canonical lower validation; the full private
        // endpoint/peer/floor sum comes from the reviewed Security supplier.
        let minimum_memory = std::mem::size_of::<SelfExecutionObservationV1>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(SelfExecutionObservationV1::receiving_heap_bytes_v1()))
            .and_then(|bytes| bytes.checked_add(super::storage_io::StorageProvisioningSessionIoShapeDataV1::native_post_carrier_bytes_v1()?))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if self.receiving_bytes < minimum_memory
            || self.open_files < SelfExecutionObservationV1::opened_file_bound_v1() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, u64::try_from(self.receiving_bytes)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .with(ResourceDimension::OpenFiles, u64::try_from(self.open_files)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?))
    }
}

#[derive(Default)]
pub(super) struct StoragePostPreparationV1 {
    shape: Option<StorageProvisioningSessionPostShapeDataV1>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    paid: Option<Result<(), ResourceReservationErrorV1>>,
    reentry: Option<ResourceReservationErrorV1>,
}

impl StoragePostPreparationV1 {
    pub(super) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        match self.geometry.as_ref() {
            Some(Ok(demand)) => Ok(*demand),
            Some(Err(_)) => Err(ResourceReservationErrorV1::Conflict),
            None => Ok(ResourceVector::ZERO),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.paid.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl CreateProvisioningOriginalsV1 {
    pub(crate) fn prepay_storage_io_post_v1(&mut self, controller: &Journal,
        complete: ResourceVector, shape: StorageProvisioningSessionPostShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        if let Some(previous) = self.storage_post.shape {
            if previous != shape || !matches!(self.storage_post.paid, Some(Ok(()))) {
                self.storage_post.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // The same fixed destination remains resident; require_complete
            // adds its invoice automatically with the reached Core base.
            return self.require_complete_v1(controller, complete);
        }
        self.storage_post.shape = Some(shape);
        self.storage_post.geometry = Some(shape.checked_demand_v1());
        if !matches!(self.storage_post.geometry, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let paid = self.require_complete_v1(controller, complete);
        self.storage_post.paid = Some(paid);
        if matches!(self.storage_post.paid, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_native_post_bound_is_a_retained_sticky_refusal() {
        let shape = StorageProvisioningSessionPostShapeDataV1 { receiving_bytes: 0, open_files: 0 };
        let mut original = StoragePostPreparationV1::default();
        original.shape = Some(shape);
        original.geometry = Some(shape.checked_demand_v1());

        assert!(original.receiving_demand_v1().is_err());
        let retained = original.geometry.as_ref().unwrap().as_ref().unwrap_err();
        let selected = original.failure().unwrap()
            .downcast_ref::<ResourceReservationErrorV1>().unwrap();
        assert!(std::ptr::eq(retained, selected));
        assert!(original.paid.is_none());
    }

    #[test]
    fn a_fixed_post_has_only_memory_and_native_descriptors() {
        let shape = StorageProvisioningSessionPostShapeDataV1 {
            receiving_bytes: 1 << 20,
            open_files: 256,
        };
        let demand = shape.checked_demand_v1().unwrap();

        assert_eq!(demand, ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, 1 << 20)
            .with(ResourceDimension::OpenFiles, 256));
    }
}

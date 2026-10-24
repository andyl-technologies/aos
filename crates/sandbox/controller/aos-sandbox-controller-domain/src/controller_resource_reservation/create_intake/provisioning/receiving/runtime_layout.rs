//! Binds the installed Runtime header's memory to its genuine C23 parent.
//!
//! This private layout is accounting DATA. Only the completed-intake constructor
//! creates it, before the first native entry. It introduces no resource account,
//! namespace, traffic, permission, or reusable receiving factory.

use aos_sandbox_model::{OperationId, ResourceDimension, ResourceVector};

use crate::controller_resource_reservation::ResourceReservationErrorV1;

#[derive(Debug, thiserror::Error)]
pub(super) enum RuntimeLayoutErrorV1 {
    #[error("the compiled Runtime header memory bound overflowed")]
    Overflow,
    #[error(transparent)]
    Length(#[from] std::num::TryFromIntError),
}

pub(super) struct RuntimeLayoutV1 {
    parent: OperationId,
    memory_bytes: u64,
}

impl RuntimeLayoutV1 {
    pub(super) fn from_runtime_header_v1<T: Sized>(
        parent: OperationId,
        runtime_header: &T,
    ) -> Result<Self, RuntimeLayoutErrorV1> {
        // The second plane includes the moved inline destinations while the
        // complete installed owner remains resident. No graph field fee is used.
        let bytes = std::mem::size_of_val(runtime_header)
            .checked_mul(2)
            .ok_or(RuntimeLayoutErrorV1::Overflow)?;
        let memory_bytes = u64::try_from(bytes)?;
        Ok(Self { parent, memory_bytes })
    }

    pub(super) fn require_parent_v1(
        &self,
        parent: OperationId,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.parent != parent {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn receiving_demand_v1(
        &self,
        parent: OperationId,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.require_parent_v1(parent)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, self.memory_bytes))
    }
}

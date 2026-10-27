//! Measures retained completed C23 storage before another purpose pays.
//!
//! The distinct live custody borrower establishes only the stored predecessor
//! association. This passive sum performs no graph parse, IO, native entry or
//! financial debit. Full fresh historical validation remains the new purpose's
//! responsibility after its actual receiving owner has paid for that work.

use super::*;
use crate::CreateStoppedTerminalCustodyV1;

impl CreateProvisioningOriginalsV1 {
    /// Bounds this completed receiver's storage beside a fresh native purpose.
    ///
    /// The completed IO and fixed-post invoices include the external SDK's
    /// dynamic representation; callers must not add that same backing twice.
    /// Their descriptor and namespace bounds stay conservative. This does not
    /// assert physical disposal from a historical price or create capacity.
    /// Runtime fixed layout, the Action, Root client, completion Attempt and
    /// shared original journals/baseline remain separate receiving owners.
    ///
    /// # Errors
    /// Refuses a different custody association, unfinished native disposal,
    /// failed retained stage, missing representation plane or arithmetic overflow.
    #[doc(hidden)]
    pub fn completed_resident_receiving_demand_v1(
        &self, custody: &CreateStoppedTerminalCustodyV1<'_>, controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let association = custody.association_v1()?;
        custody.require_same_complete_v1(&association, self, controller)?;
        self.require_completed_original_v1(controller)?;
        let native = self.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?
            .original_v1();
        let source_bytes = self.source.completed_resident_backing_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(source_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes)
            .checked_add(native.completed_resident_receiving_demand_v1()
                .map_err(ResourceReservationErrorV1::ControllerBankLaunch)?)?
            .checked_add(self.client_session.completed_resident_receiving_demand_v1()?)?
            .checked_add(self.storage_post.receiving_demand_v1()?)?
            .checked_add(self.storage_io.completed_resident_receiving_demand_v1()?)
            .map_err(Into::into)
    }
}

//! Selects the genuine Recover original for the sole retained Inventory kernel.
//!
//! The native loan is created only by the already-authorized Recover owner and
//! actual completed cold Session. No role, request, method or budget factory is
//! supplied by this mechanical alias.

pub(crate) type OperatorRecoverInventoryClientKernelV1<'query, 'owner, 'controller> =
    super::delete_inventory::ControllerInventoryClientKernelV1<
        aos_sandbox::OperatorRecoverInventoryLoanV1<'query, 'owner, 'controller>>;

/// Keeps an exact SDK association cause separate from its native admission marker.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OperatorRecoverInventoryBorrowFailureV1 {
    #[error(transparent)]
    Protected(#[from] crate::BrokerSessionSecurityError),
    #[error(transparent)]
    Native(#[from] aos_sandbox::ResourceReservationErrorV1),
}

impl<'query, 'owner, 'controller>
    OperatorRecoverInventoryClientKernelV1<'query, 'owner, 'controller>
{
    pub(crate) fn borrow_native_once_v1(
        source: &'query mut aos_sandbox::OperatorCreateRecoveryLoanV1<'owner, 'controller>,
        receiving: &aos_sandbox::ControllerInitialBrokerSessionReceivingV1,
        session: &super::DormantAuthenticatedBrokerSessionV1,
        shape: aos_sandbox::DeleteInventorySecurityShapeDataV1,
    ) -> Result<aos_sandbox::OperatorRecoverInventoryLoanV1<'query, 'owner, 'controller>,
        OperatorRecoverInventoryBorrowFailureV1>
    {
        // Private Session fields are inspected only in their owning module.
        let journal = match session.owner.operator_recover_inventory_journal_v1() {
            Ok(journal) => journal,
            Err(cause) => {
                source.retain_storage_sdk_refusal_once_v1();
                return Err(OperatorRecoverInventoryBorrowFailureV1::Protected(cause));
            }
        };
        source.borrow_storage_inventory_once_v1(receiving, journal, shape)
            .map_err(OperatorRecoverInventoryBorrowFailureV1::Native)
    }
}

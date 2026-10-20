//! Delegates the normal Apply final comparison to the shared C finality engine.

use super::{lifecycle::RootApplyFinalLifecycleOriginalV1, session::RootApplyFinalSessionOriginalV1};
use crate::journal::{Journal, JournalError};
use crate::policy_compiler::provisioning_current::create_finality::controller::CreateFinalityControllerOriginalV1;
use aos_sandbox_core::OperationId;
use aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedLifecycleReceiptDataV1;

type Cause = Box<dyn std::error::Error>;

// The one-field wrapper preserves the exact old paid layout and keeps the
// ordinary consumer's Source/Session type requirements closed.
pub(super) struct RootApplyFinalControllerOriginalV1 {
    original: CreateFinalityControllerOriginalV1,
}

impl RootApplyFinalControllerOriginalV1 {
    pub(super) fn new() -> Self {
        Self { original: CreateFinalityControllerOriginalV1::new() }
    }

    pub(super) fn observe_once_v1(&mut self, controller: &mut Journal,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>, expected_parent: OperationId,
        final_receipt: &[u8],
    ) -> Result<(), JournalError> {
        self.original.observe_once_v1(controller, receipt, expected_parent, final_receipt)
    }

    pub(super) fn compare_once_v1(&self, controller: &Journal,
        lifecycle: &RootApplyFinalLifecycleOriginalV1, session: &RootApplyFinalSessionOriginalV1,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>,
        root: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
        admitted_plan: &[u8], lane: [u8; 16],
    ) -> Result<(), Cause> {
        self.original.require_complete_v1()?;
        let (source, source_record) = lifecycle.operation_v1()?;
        self.original.compare_data_v1(controller, source, source_record,
            session.apply_v1()?, session.apply_response_v1()?,
            session.inventory_v1()?, session.inventory_model_v1()?,
            receipt, root, admitted_plan, lane)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}

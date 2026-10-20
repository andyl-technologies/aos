//! Keeps closed Controller intake mechanics beside the actual Bank owner.
//!
//! These crate-private aliases introduce no new account, Native constructor or
//! writer projection. Only the Bank's named Delete/Execution claim methods
//! invoke the lower paired-C factories. Specific semantic wrappers must bind
//! their real accepted/authorized operation before any effect or protected
//! graph admission. No decoded plan, request ID or historical view grants it.
//!
//! The existing Journal remains the semantic writer throughout each loan.
//! Bank methods reborrow its SAME sealed native coordinator with the privately
//! retained confirmed Launch; neither raw owner escapes through this module.
//! Initial intake and independently owed completion use distinct method paths.

pub(crate) use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerOperationIntakeOriginalV1, ControllerOperationIntakeReceivingLoanV1,
    ControllerOperationIntakeDisposalV1, ControllerOperationIntakeDemandDataV1,
    ControllerOperationIntakeFailureViewV1,
};

// Actual same-Source coordinator and C loan, with the private Journal selection
// retained below the semantic compiler. These aliases add no constructor.
pub(crate) type ControllerDeleteSourceScopeV1<'scope, 'original> =
    aos_sandbox_broker::source_receiving::SourceDeleteScopeV1<
        'scope, 'original, crate::journal::ControllerCoordinatorSelectionV1,
    >;
pub(crate) type ControllerDeleteSourceDisposalV1<'disposal> =
    aos_sandbox_broker::source_receiving::SourceDeleteScopeDisposalV1<
        'disposal, crate::journal::ControllerCoordinatorSelectionV1,
    >;

// Same sole native scope engine, selected only by the actual X18 loan.
pub(crate) type ControllerExecutionSourceScopeV1<'scope, 'original> =
    crate::journal::SourceExecutionSemanticScopeV1<'scope, 'original>;
pub(crate) type ControllerExecutionSourceDisposalV1<'disposal> =
    aos_sandbox_broker::source_receiving::SourceExecutionScopeDisposalV1<
        'disposal, crate::journal::ControllerCoordinatorSelectionV1,
    >;

pub(crate) type ControllerExecutionSourceCompleteBorrowV1<'read, 'original> =
    aos_sandbox_broker::source_receiving::SourceExecutionCompleteBorrowV1<
        'read, 'original, crate::journal::ControllerCoordinatorSelectionV1,
    >;

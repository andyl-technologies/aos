//! Dispatches only actual initial or new Start Client native receiving loans.
//!
//! Shared endpoint and cold machinery borrows one of these whole genuine
//! originals. The closed enum has no tuple, profile, amount or DTO constructor;
//! its Start arm never constructs or borrows an initial-B role claim.

use aos_sandbox::{ControllerInitialBrokerSessionReceivingLoanV1, ControllerInitialBrokerSessionClosedV1,
    ControllerInitialBrokerSessionRoleV1 as Role, StartResourceSessionOpeningLoanV2, ResourceReservationErrorV1};
use aos_sandbox_broker::endpoint_native_files::{ControllerEndpointExecutionOriginalV1,
    ControllerEndpointExecutionCaptureErrorV1, ControllerEndpointNativeCustodyCaptureV1,
    EndpointNativeFileOpenOriginalV1, EndpointNativeFileV1};
use aos_sandbox_linux::self_execution::SelfExecutionObservationV1;

pub(crate) enum ControllerClientReceivingV4<'loan, 'turn> {
    Initial(&'loan mut ControllerInitialBrokerSessionReceivingLoanV1<'turn>),
    StartResource(&'loan mut StartResourceSessionOpeningLoanV2<'turn>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControllerClientReceivingErrorV4 {
    #[error(transparent)]
    Initial(#[from] ControllerInitialBrokerSessionClosedV1),
    #[error(transparent)]
    StartResource(#[from] ResourceReservationErrorV1),
}

impl ControllerClientReceivingV4<'_, '_> {
    pub(crate) fn role(&self) -> Role {
        match self { Self::Initial(loan) => loan.role_v1(), Self::StartResource(loan) => loan.actual_role_v2() }
    }

    pub(crate) fn require_current(&mut self) -> Result<(), ControllerClientReceivingErrorV4> {
        match self {
            Self::Initial(loan) => loan.require_fixed_capture_current_v1(loan.role_v1()).map_err(Into::into),
            Self::StartResource(loan) => loan.require_fixed_capture_current_v2().map_err(Into::into),
        }
    }

    pub(crate) fn expected_node(&mut self) -> Result<[u8; 16], ControllerClientReceivingErrorV4> {
        match self {
            Self::Initial(loan) => loan.expected_node_v1().map_err(Into::into),
            Self::StartResource(loan) => loan.expected_node_v2().map_err(Into::into),
        }
    }

    pub(crate) fn capture_execution_once(&mut self)
        -> Result<ControllerEndpointExecutionOriginalV1, ControllerEndpointExecutionCaptureErrorV1>
    {
        match self {
            Self::Initial(loan) => loan.capture_endpoint_execution_once_v1(),
            Self::StartResource(loan) => loan.capture_endpoint_execution_once_v2(),
        }
    }

    pub(crate) fn capture_directory_once(&mut self, destination: &mut EndpointNativeFileOpenOriginalV1)
        -> Result<(), ControllerClientReceivingErrorV4>
    {
        match self {
            Self::Initial(loan) => loan.capture_endpoint_directory_once_v1(destination).map_err(Into::into),
            Self::StartResource(loan) => loan.capture_endpoint_directory_once_v2(destination).map_err(Into::into),
        }
    }

    pub(crate) fn capture_custody_once(&mut self, destination: &mut ControllerEndpointNativeCustodyCaptureV1,
        execution: &mut Option<ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<SelfExecutionObservationV1>, files: [&EndpointNativeFileV1; 4],
    ) -> Result<(), ControllerClientReceivingErrorV4> {
        match self {
            Self::Initial(loan) => loan.capture_endpoint_custody_once_v1(destination, execution, post, files).map_err(Into::into),
            Self::StartResource(loan) => loan.capture_endpoint_custody_once_v2(destination, execution, post, files).map_err(Into::into),
        }
    }
}

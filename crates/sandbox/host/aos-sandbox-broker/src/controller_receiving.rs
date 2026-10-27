//! Retains genuine Controller receiving originals below protected role crates.
//!
//! Original first-table files, the same sole residual ledger and private
//! complete native/profile control scopes stay together. Domain keeps bank,
//! launch, Runtime, Root and Q04/J orchestration above these fixed mechanisms.
//! Passive structural DATA never construct an original or supply admission.
//!
//! `initial_delivery` and `startup_opening` preserve the linked first table.
//! The private original, budget and operation modules retain the residual C
//! ledger and native scopes. `profile` owns measured self-observation; Runtime
//! admission and construction loans invoke only its fixed private recipes.

pub mod bank_launch;
mod budget;
mod construction;
mod initial_delivery;
mod launch_shape;
mod observation;
mod original;
mod operation_intake;
mod initial_session;
mod publisher_schedule;
mod publisher_operation;
mod shapes;
mod source_prebank;
mod runtime_startup;
mod startup_envelope;
mod startup_credentials;
mod startup_opening;
pub mod profile;

pub use initial_delivery::capture_ordinary as capture_ordinary_controller_initial_delivery_v1;

pub use initial_delivery::{
    ControllerEnrollmentDeliveryV1, ControllerInitialDeliveryCaptureV1,
    ControllerInitialDeliveryFailureRefV1, ControllerInitialDeliveryPartsV1,
    ControllerNixDeliveryDataV1, ControllerLaunchImageDeliveryOriginalV1,
};
pub use original::ControllerReceivingOriginalV1;
pub use source_prebank::{ControllerSourcePreBankConstructionLoanV1, ControllerSourceOriginalRefV1};
pub use observation::ControllerOriginalObservationV1;
pub use initial_session::{ControllerInitialBrokerSessionRoleV1, ControllerInitialSessionReceivingOriginalV1};
pub use construction::{ControllerSourceConstructionReceivingV1, ControllerCacheConstructionReceivingV1};
pub use startup_opening::{ControllerStartupOpeningV1, ControllerStartupFailureRefV1, ControllerBankOpeningFailureV1};
pub use runtime_startup::ControllerRuntimeStartupAdmissionV1;
pub use startup_credentials::ControllerStartupCredentialReceivingV1;
pub use publisher_operation::ControllerPublisherOperationReceivingV1;
pub use publisher_schedule::ControllerPublisherStartupDataV1;
pub use launch_shape::ControllerLaunchReceivingShapeV1;
pub use shapes::{
    ControllerRuntimeStartupShapeV1, ControllerRuntimeCredentialShapeV1, ControllerRuntimeTaskEnvelopeV1,
    ControllerRuntimeRequestedCountsV1, CONTROLLER_RUNTIME_TASKS_V1,
    CONTROLLER_RUNTIME_ROLE_TASKS_V1, CONTROLLER_RUNTIME_BLOCKING_THREADS_V1,
    CONTROLLER_RUNTIME_STACK_BYTES_V1,
};

/// Preserves original fixed receiving/accounting causes without Domain owners.
#[derive(Debug, thiserror::Error)]
pub enum ControllerReceivingErrorV1 {
    /// The same original is missing, incomplete or unavailable.
    #[error("shared Controller receiving original is unavailable")]
    EnrollmentUnavailable,
    /// A once-only stage, original identity or complete observation differs.
    #[error("shared Controller receiving original conflicts")]
    Conflict,
    /// The existing Core arithmetic or capacity check failed.
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_model::AccountingError),
    /// Original canonical bank subdivision DATA failed validation.
    #[error(transparent)]
    Data(#[from] aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError),
}

mod cache_prebank;
pub use cache_prebank::ControllerCachePreBankImportLoanV1;

pub use initial_session::ControllerStorageFloorRepresentationV1;

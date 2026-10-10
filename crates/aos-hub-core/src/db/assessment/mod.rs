//! Durable assessment storage, generations, provider claims and atomic attention/event commits.
//!
//! Shared database methods operate through the same checked-batch backend on
//! Native SQL and HubDb. Source HTTP never runs inside a database transaction.
//! Raw source bodies stay on the admitted evidence path, including in Hybrid.

mod acquisition_progress;
mod alerts;
mod authority;
mod budgets;
mod cache;
mod clock;
mod evaluation;
mod inventory;
mod job_authority;
mod objects;
mod provider_index;
mod provider_state;
mod publication;
mod reconcile;
mod scans;
mod schedules;
mod status;

pub use budgets::{AssessmentProviderReservation, AssessmentProviderWork, AssessmentSourceBudget};
pub use inventory::{AssessmentInventoryAdmission, AssessmentResource};
pub use job_authority::assessment_actor_ref;
pub use publication::AssessmentPublicationRefresh;
pub use objects::AssessmentObjectKind;
pub use provider_state::AssessmentProviderReplay;
pub use scans::AssessmentScanRecord;
pub use status::{
    AssessmentProfileStatus, AssessmentScanSummary, AssessmentStatusPage, AssessmentSubjectStatus,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod objects_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod scans_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod reconcile_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod budgets_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod evaluation_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod execution_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod provider_state_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod status_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod alerts_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod authority_tests;

#[cfg(all(test, not(target_arch = "wasm32"), feature = "postgres"))]
mod postgres_tests;

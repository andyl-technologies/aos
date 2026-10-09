//! Durable assessment storage, generations, provider claims and atomic attention/event commits.
//!
//! Shared database methods operate through the same checked-batch backend on
//! Native SQL and HubDb. Source HTTP never runs inside a database transaction.
//! Raw source bodies stay on the admitted evidence path, including in Hybrid.

mod alerts;
mod budgets;
mod clock;
mod evaluation;
mod inventory;
mod objects;
mod provider_index;
mod provider_state;
mod scans;
mod status;

pub use budgets::{AssessmentProviderReservation, AssessmentProviderWork, AssessmentSourceBudget};
pub use inventory::{AssessmentInventoryAdmission, AssessmentResource};
pub use objects::AssessmentObjectKind;
pub use scans::AssessmentScanRecord;
pub use status::{
    AssessmentProfileStatus, AssessmentScanSummary, AssessmentStatusPage, AssessmentSubjectStatus,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod objects_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod scans_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod budgets_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod evaluation_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod provider_state_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod status_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod alerts_tests;

#[cfg(all(test, not(target_arch = "wasm32"), feature = "postgres"))]
mod postgres_tests;

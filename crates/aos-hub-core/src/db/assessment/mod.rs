//! Durable assessment storage, generations, provider claims and atomic attention/event commits.
//!
//! Shared database methods operate through the same checked-batch backend on
//! Native SQL and HubDb. Source HTTP never runs inside a database transaction.
//! Raw source bodies stay on the admitted evidence path, including in Hybrid.

mod acquisition_progress;
mod advisories;
mod advisory_snapshot;
mod alerts;
mod alert_snapshot;
mod authority;
mod budgets;
mod cache;
mod clock;
mod delivery_snapshot;
mod evaluation;
mod inventory;
mod job_authority;
mod notifications;
mod notification_journal;
mod notification_work;
mod objects;
mod provider_failure;
mod provider_index;
mod provider_state;
mod publication;
mod reconcile;
mod read_snapshot;
mod subscription_snapshot;
mod reviews;
mod scans;
mod schedules;
mod service_authority;
mod schedule_snapshot;
mod source_health;
pub(super) mod source_status;
mod status;

pub(crate) use reviews::AssessmentReviewCompletion;

pub use budgets::{AssessmentProviderReservation, AssessmentProviderWork, AssessmentSourceBudget};
pub use inventory::{AssessmentInventoryAdmission, AssessmentResource};
pub use job_authority::assessment_actor_ref;
pub use notification_work::{AssessmentNotificationPlacement, AssessmentNotificationWork};
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
mod provider_failure_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod conditional_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod status_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod read_snapshot_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod alerts_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod authority_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod notifications_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod notification_work_tests;

#[cfg(all(test, not(target_arch = "wasm32"), feature = "postgres"))]
mod postgres_tests;

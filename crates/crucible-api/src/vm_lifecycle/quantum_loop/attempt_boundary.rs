//! Attempt-authority checks around scheduler quantum execution.

use super::*;

pub(super) fn combine_attempt_quantum_boundary<T>(
    operation: Result<T, SchedulerError>,
    boundary: Result<(), LifecycleApiError>,
) -> Result<T, SchedulerError> {
    match (operation, boundary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(boundary)) => Err(attempt_boundary_scheduler_error(
            "check production attempt after scheduler quantum",
            boundary,
        )),
        (Err(error), Err(boundary)) => Err(attempt_boundary_scheduler_error(
            &format!(
                "production scheduler quantum failed ({error}); post-quantum attempt boundary"
            ),
            boundary,
        )),
    }
}

pub(super) fn attempt_boundary_scheduler_error(
    context: &str,
    error: LifecycleApiError,
) -> SchedulerError {
    match error {
        LifecycleApiError::AttemptOperational { class, message } => {
            SchedulerError::OperationalBoundary {
                class,
                message: format!("{context} failed: {message}"),
            }
        }
        error => SchedulerError::BoundaryViolation {
            message: format!("{context} failed: {error}"),
        },
    }
}

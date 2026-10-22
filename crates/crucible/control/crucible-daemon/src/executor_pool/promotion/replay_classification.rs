//! Classifies actual replay leaves without following recursive Main reports.
//!
//! These diagnostic projections retain the existing raw cleanup policy. An
//! unavailable or recursive protected cause is terminal and grants no new
//! attempt, Original, native ownership or cleanup permission.

use super::*;

pub(super) fn classify_native_replay_cleanup(
    report: &crate::QemuAttemptResourceGuardCleanupFailure,
) -> PromotionFailureClass {
    if report.reports_terminal_quarantine() {
        PromotionFailureClass::Terminal
    } else {
        classify_realization_failure(report.error())
    }
}

fn classify_replay_lifecycle(
    first: &crate::QemuAttemptProductionVmLifecycleError,
) -> PromotionFailureClass {
    match crate::qemu_campaign_lifecycle::production_lifecycle_failure_class(first) {
        crucible_engine::SchedulerOperationalFailureClass::Retryable => PromotionFailureClass::Retryable,
        crucible_engine::SchedulerOperationalFailureClass::Canceled => PromotionFailureClass::Canceled,
        crucible_engine::SchedulerOperationalFailureClass::Terminal => PromotionFailureClass::Terminal,
    }
}

fn classify_raw_replay_first(first: crate::LifecycleFailureRef<'_>) -> PromotionFailureClass {
    use crate::LifecycleFailureRef as Failure;

    match first {
        Failure::Lifecycle(first) => {
            // Reentering the same protected Main report cannot establish a class.
            if matches!(
                first,
                crate::QemuAttemptProductionVmLifecycleError::PreparedSource(_)
            ) {
                PromotionFailureClass::Terminal
            } else {
                classify_replay_lifecycle(first)
            }
        }
        Failure::Realization(first) => classify_realization_failure(first),
        Failure::GuardCleanup(first) => classify_native_replay_cleanup(first),
        _ => PromotionFailureClass::Terminal,
    }
}

pub(super) fn classify_replay_cleanup(
    first: &crate::paused_checkpoint_promotion::ProductionReplayCleanup,
) -> PromotionFailureClass {
    use crate::paused_checkpoint_promotion::ProductionReplayCleanup;
    match first {
        ProductionReplayCleanup::Native(first) => classify_native_replay_cleanup(first),
        ProductionReplayCleanup::Prepared { failure, .. } => failure
            .with_first_error(classify_raw_replay_first)
            .unwrap_or(PromotionFailureClass::Terminal),
        ProductionReplayCleanup::Returned { body, post } => {
            if let Some(first) = body.first_failure() {
                classify_raw_replay_first(first)
            } else if post.is_some() {
                // The previous Restore completion adapter reported this same
                // actual operation's refusal as operational unavailability.
                PromotionFailureClass::Retryable
            } else {
                PromotionFailureClass::Terminal
            }
        }
    }
}

pub(super) fn classify_replay_failure(
    first: &crate::paused_checkpoint_promotion::ProductionReplayError,
) -> PromotionFailureClass {
    use crate::paused_checkpoint_promotion::ProductionReplayError;
    match first {
        ProductionReplayError::Realization(first)
        | ProductionReplayError::Admission { first, .. } => classify_realization_failure(first),
        ProductionReplayError::Preparation(first) => classify_replay_lifecycle(first),
        ProductionReplayError::Prepared(first)
        | ProductionReplayError::Transport { failure: first, .. } => first
            .with_first_error(classify_raw_replay_first)
            .unwrap_or(PromotionFailureClass::Terminal),
        ProductionReplayError::Launch(_) | ProductionReplayError::OriginalAdmission { .. } => {
            // These retain the unchanged issuer/Restore admission refusals that
            // the previous replay adapter exposed as operational unavailability.
            PromotionFailureClass::Retryable
        }
        ProductionReplayError::OriginalBoundary {
            comparison,
            node_cleanup,
            ..
        } => {
            if node_cleanup.is_some() {
                PromotionFailureClass::Terminal
            } else {
                comparison
                    .as_ref()
                    .map(classify_realization_failure)
                    .unwrap_or(PromotionFailureClass::Retryable)
            }
        }
        ProductionReplayError::Execution { first, cleanup } => match cleanup {
            Some(cleanup) => classify_replay_cleanup(cleanup),
            None => match first {
                AttemptWorkerFailure::Retryable(_) => PromotionFailureClass::Retryable,
                AttemptWorkerFailure::Canceled(_) => PromotionFailureClass::Canceled,
                AttemptWorkerFailure::Terminal(_) => PromotionFailureClass::Terminal,
            },
        },
        ProductionReplayError::Cleanup(first) => classify_replay_cleanup(first),
    }
}

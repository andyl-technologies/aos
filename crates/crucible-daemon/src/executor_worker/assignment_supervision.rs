//! Original assignment supervision shared by guest execution and journal recovery.

use crucible_campaign::{AttemptRetentionPolicyDisposition, CampaignExecutorStore};
use thiserror::Error;

use crate::QueuedAttempt;
use crate::supervision::AssignmentHostWatchdog;

#[derive(Debug, Error)]
pub(crate) enum AssignmentSupervisionError {
    #[error("authenticate assignment timeout policy: {0}")]
    Repository(#[from] crucible_campaign::CampaignRepositoryError),
    #[error("start original assignment watchdog: {0}")]
    Watchdog(#[from] std::io::Error),
    #[error("register original assignment cap: {0}")]
    Registry(#[from] crucible_api::host_operational::HostOperationalError),
}

/// Starts the first watcher once; subsequent phases borrow its original cap.
pub(crate) fn start_original_assignment(
    queued: &QueuedAttempt,
    store: &CampaignExecutorStore,
) -> Result<(AssignmentHostWatchdog, Option<u64>), AssignmentSupervisionError> {
    let milliseconds = match queued.request().retention_policy() {
        AttemptRetentionPolicyDisposition::Required(basis) => store
            .load_attempt_timeout_policy(
                queued.request().lineage(),
                queued.request().attempt(),
                basis,
            )?
            .and_then(|policy| policy.host_completion_watchdog_ms()),
        AttemptRetentionPolicyDisposition::Disabled => None,
    };
    let budgets = queued
        .host_operation_budgets()
        .ok_or_else(|| std::io::Error::other("missing authored host operation budgets"))?;
    let (watchdog, first_start) =
        queued.start_host_watchdog(milliseconds, queued.cancellation().clone(), budgets)?;
    if first_start {
        use crucible_api::host_operational::{
            HostOuterCapClass, HostOuterCapOwner, HostOuterCapTarget,
        };
        queued.host_operational_registry().register_cap(
            HostOuterCapTarget {
                daemon_epoch: queued.host_daemon_epoch(),
                owner: HostOuterCapOwner::Execution(
                    crate::host_operational_registry::operational_identity(
                        queued.execution().as_bytes(),
                    ),
                ),
                owner_generation: 1,
                cap_id: watchdog.supervisor().cap_id(),
            },
            HostOuterCapClass::Assignment,
            watchdog.supervisor().clone(),
        )?;
    }
    Ok((watchdog, milliseconds))
}

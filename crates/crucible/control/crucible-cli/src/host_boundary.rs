//! Operational host observations that remain outside deterministic state.

use std::future::Future;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

/// Identifies which host operation completed first.
pub(super) enum HostRaceOutcome<F, S> {
    First(F),
    Second(S),
}

/// Waits for either host operation using a stable first-operation priority.
pub(super) async fn first_completed<F, S>(
    first: F,
    second: S,
) -> HostRaceOutcome<F::Output, S::Output>
where
    F: Future,
    S: Future,
{
    tokio::pin!(first);
    tokio::pin!(second);

    tokio::select! {
        biased;
        output = &mut first => HostRaceOutcome::First(output),
        output = &mut second => HostRaceOutcome::Second(output),
    }
}

/// Reads Unix wall time for deployment credential admission.
///
/// The caller uses this observation only to reject expired credentials before
/// constructing a campaign. It never enters a campaign object, graph identity,
/// or deterministic execution result.
pub(super) fn operational_wall_clock_seconds() -> Result<u64, SystemTimeError> {
    UNIX_EPOCH.elapsed().map(|elapsed| elapsed.as_secs())
}

/// Converts authored Unix seconds for an operational credential provider.
pub(super) fn system_time_from_unix_seconds(seconds: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

//! Route diagnostics the Envoy flight attaches to hot-fork and replay failures.
//!
//! A branch attempt that should hot-fork can decline, anchor, or replay thin,
//! and a fresh replay can diverge from the decisions its parent recorded. The
//! service writes one row per routing decision and, when asked, traces every
//! retained attempt log. These helpers gather those rows and the traced log
//! entries around a divergence into the failure the flight reports.

use super::*;

/// Requires a hot-fork materialization, naming the route rows when it is absent.
pub(super) fn assert_hot_fork_tier(
    service: &CampaignServiceChild,
    materialization: &[String],
    attempt: impl std::fmt::Display,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = guest_choice::assert_materialization_tier(materialization, attempt, "HotFork")
    else {
        return Ok(());
    };
    let mut rows = Vec::new();
    for prefix in [
        ANCHOR_DIAGNOSTIC_PREFIX,
        ANCESTOR_DIAGNOSTIC_PREFIX,
        "CRUCIBLE-HOT-FORK-DECLINE-V1 ",
        "CRUCIBLE-HOT-FORK-RETENTION-V1 ",
        "CRUCIBLE-HOT-FORK-SOURCE-PREPARATION-V1 ",
        "CRUCIBLE-REPLAY-DIVERGENCE-V1 ",
    ] {
        rows.extend(service.stderr_lines_with_prefix(prefix, 32, 4096)?);
    }
    Err(format!("{error}; route_rows={rows:?}").into())
}

/// Names the directory where the service traces each retained attempt log.
pub(super) fn attempt_log_trace_directory(fixture: &FlightFixture) -> PathBuf {
    fixture._temporary.path().join("attempt-log-trace")
}

/// Prints every traced attempt log's entries around a replay divergence.
///
/// The first delivery time in the divergence row centers the window, so the
/// original and replayed logs show which publication moved.
pub(super) fn attempt_log_trace_window(fixture: &FlightFixture, rows: &str) -> String {
    const HALF_WINDOW_PS: u64 = 40_000_000;
    const LINES_PER_LOG: usize = 160;

    let Some(center) = rows
        .split("order@")
        .nth(1)
        .and_then(|tail| tail.split(':').next())
        .and_then(|ticks| ticks.parse::<u64>().ok())
    else {
        return String::new();
    };
    let Ok(directory) = fs::read_dir(attempt_log_trace_directory(fixture)) else {
        return String::new();
    };
    let mut paths = directory
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    paths.sort();

    let mut window = Vec::new();
    for path in paths {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let lines = text
            .lines()
            .filter(|line| {
                line.split(' ')
                    .nth(1)
                    .and_then(|ticks| ticks.parse::<u64>().ok())
                    .is_some_and(|at| at.abs_diff(center) <= HALF_WINDOW_PS)
            })
            .take(LINES_PER_LOG)
            .collect::<Vec<_>>();
        if lines.is_empty() {
            continue;
        }
        window.push(format!(
            "CRUCIBLE-ATTEMPT-LOG-TRACE-V1 log={} center_ps={center} lines={}",
            path.file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
            lines.len()
        ));
        window.extend(lines.into_iter().map(|line| format!("  {line}")));
    }
    window.join("\n")
}

/// Collects the service rows that explain a branch attempt's replay route.
pub(super) fn service_failure_rows(service: &CampaignServiceChild) -> String {
    service
        .stderr_tail()
        .lines()
        .filter(|line| {
            line.starts_with("CRUCIBLE-HOT-FORK-DECLINE-V1 ")
                || line.starts_with("CRUCIBLE-REPLAY-DIVERGENCE-V1 ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

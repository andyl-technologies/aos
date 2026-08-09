//! Canonical labels for event, logging, readiness, and white-box policies.

use super::*;

pub(in super::super) fn reachable_disposition_label(
    disposition: ReachableDisposition,
) -> &'static str {
    match disposition {
        ReachableDisposition::Warn => "warn",
        ReachableDisposition::Fail => "fail",
    }
}

pub(in super::super) fn fire_policy_label(policy: FirePolicy) -> &'static str {
    match policy {
        FirePolicy::Once => "once",
        FirePolicy::Repeatable => "repeatable",
    }
}

pub(in super::super) fn log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

pub(in super::super) fn ready_point_material(ready_point: &ReadyPoint) -> String {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => {
            format!("ready_point=fixed-icount\nready_icount={}", icount.retired)
        }
        ReadyPoint::NetworkIdle { window } => {
            format!("ready_point=network-idle\nidle_window_ns={}", window.nanos)
        }
        ReadyPoint::ConsoleMarker { marker } => format!(
            "ready_point=console-marker\nmarker_len={}\nmarker={marker}",
            marker.len()
        ),
        ReadyPoint::AgentSignal => String::from("ready_point=agent-signal"),
    }
}

pub(in super::super) fn white_box_material(policy: WhiteBoxPolicy) -> &'static str {
    match policy {
        WhiteBoxPolicy::Disabled => "disabled",
        WhiteBoxPolicy::Enabled => "enabled",
    }
}

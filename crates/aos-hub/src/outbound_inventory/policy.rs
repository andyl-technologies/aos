//! Closed policy parsing and one-time wall-clock to monotonic selection.
//!
//! ```text
//! Policy = {version:1, runId:<64 hex>, windowId:<32 hex>,
//!           startUnixMillis:<decimal>, endUnixMillis:<decimal>}
//! ```

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::window::Window;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Policy {
    pub(super) version: u8,
    pub(super) run_id: String,
    pub(super) window_id: String,
    pub(super) start_unix_millis: String,
    pub(super) end_unix_millis: String,
}

/// Validates the finite observation policy and anchors its monotonic interval.
///
/// # Errors
///
/// Returns an error for malformed identity/time, a past or excessive interval,
/// an unavailable clock or an unavailable process epoch.
pub(super) fn select(raw: &str) -> anyhow::Result<Arc<Window>> {
    anyhow::ensure!(
        raw.len() <= 1024,
        "outbound observation policy exceeds bound"
    );
    let policy: Policy = serde_json::from_str(raw)
        .map_err(|_| anyhow::anyhow!("outbound observation policy is invalid"))?;
    let hex = |value: &str, size: usize| {
        value.len() == size
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    anyhow::ensure!(
        policy.version == 1 && hex(&policy.run_id, 64) && hex(&policy.window_id, 32),
        "outbound observation identity differs"
    );
    let decimal = |value: &str| -> anyhow::Result<u64> {
        let parsed = value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("outbound observation time is invalid"))?;
        anyhow::ensure!(
            parsed.to_string() == value,
            "outbound observation time is not canonical"
        );
        Ok(parsed)
    };
    let start = decimal(&policy.start_unix_millis)?;
    let end = decimal(&policy.end_unix_millis)?;
    let clock = Instant::now();
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    anyhow::ensure!(
        start >= now && end > start && end - now <= 3_600_000,
        "outbound observation window is past or exceeds bound"
    );
    Window::new(
        policy,
        clock + Duration::from_millis(start - now),
        clock + Duration::from_millis(end - now),
    )
}

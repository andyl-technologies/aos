//! Authored storage-history limits carried across the plugin launch boundary.

use super::{ParsedPluginArgs, PluginArgsParseError};

/// Required completed block-history epoch-limit argument key.
pub const PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS: &str = "storage_completed_history_epochs";
/// Required completed block-history gap-limit argument key.
pub const PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS: &str = "storage_completed_history_gaps";

/// Immutable compiled ceiling for retained completed-request epochs.
pub const HARD_STORAGE_COMPLETED_HISTORY_EPOCHS: u64 = 1_048_576;
/// Immutable compiled ceiling for retained out-of-order completed identities.
pub const HARD_STORAGE_COMPLETED_HISTORY_GAPS: u64 = 1_048_576;

/// Authored completed-request history limits for one plugin process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginStorageHistoryLimits {
    epochs: u64,
    gaps: u64,
}

impl PluginStorageHistoryLimits {
    /// Returns the compiled maximum used by internal test fixtures.
    #[must_use]
    #[cfg(test)]
    pub const fn compiled_maximum() -> Self {
        Self {
            epochs: HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
            gaps: HARD_STORAGE_COMPLETED_HISTORY_GAPS,
        }
    }

    /// Returns the configured retained-epoch ceiling.
    #[must_use]
    pub const fn epochs(self) -> u64 {
        self.epochs
    }

    /// Returns the configured retained-gap ceiling.
    #[must_use]
    pub const fn gaps(self) -> u64 {
        self.gaps
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<PluginStorageHistoryLimits, PluginArgsParseError> {
    Ok(PluginStorageHistoryLimits {
        epochs: parse_required_limit(
            parsed,
            PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS,
            HARD_STORAGE_COMPLETED_HISTORY_EPOCHS,
        )?,
        gaps: parse_required_limit(
            parsed,
            PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS,
            HARD_STORAGE_COMPLETED_HISTORY_GAPS,
        )?,
    })
}

pub(super) fn is_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS | PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS
    )
}

fn parse_required_limit(
    parsed: &ParsedPluginArgs<'_>,
    key: &'static str,
    hard: u64,
) -> Result<u64, PluginArgsParseError> {
    let Some(value) = parsed.value(key) else {
        return Err(PluginArgsParseError::MissingRequiredKey { key });
    };
    match value.parse::<u64>() {
        Ok(configured) if configured != 0 && configured <= hard => Ok(configured),
        _ => Err(PluginArgsParseError::InvalidResourceLimit {
            key,
            value: value.to_owned(),
            hard,
        }),
    }
}

//! Exact-boundary raw-state dump launch arguments.

use std::path::{Path, PathBuf};

use super::{ParsedPluginArgs, PluginArgsParseError, PluginSwitch};

/// Optional terminal raw-state dump target-icount argument key.
pub const PLUGIN_ARG_STATE_DUMP_TARGET: &str = "state_dump_target";
/// Optional terminal raw-state dump output-path argument key.
pub const PLUGIN_ARG_STATE_DUMP_PATH: &str = "state_dump_path";

/// A terminal raw-state dump requested at one exact fingerprint boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginStateDumpConfig {
    target_icount: u64,
    output_path: PathBuf,
}

impl PluginStateDumpConfig {
    /// Returns the exact aggregate icount at which QEMU must pause and dump.
    #[must_use]
    pub const fn target_icount(&self) -> u64 {
        self.target_icount
    }

    /// Returns the absolute output path for the atomic dump artifact.
    #[must_use]
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
    fingerprint: PluginSwitch,
) -> Result<Option<PluginStateDumpConfig>, PluginArgsParseError> {
    match (
        parsed.value(PLUGIN_ARG_STATE_DUMP_TARGET),
        parsed.value(PLUGIN_ARG_STATE_DUMP_PATH),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(PluginArgsParseError::IncompleteStateDump),
        (Some(target), Some(path)) => {
            if !fingerprint.is_on() {
                return Err(PluginArgsParseError::StateDumpWithoutFingerprint);
            }
            let target_icount = target.parse::<u64>().map_err(|_source| {
                PluginArgsParseError::InvalidStateDumpTarget {
                    value: target.to_owned(),
                }
            })?;
            if target_icount == 0 {
                return Err(PluginArgsParseError::InvalidStateDumpTarget {
                    value: target.to_owned(),
                });
            }
            let output_path = PathBuf::from(path);
            if !output_path.is_absolute() || path.contains(',') || path.contains('=') {
                return Err(PluginArgsParseError::InvalidStateDumpPath {
                    value: path.to_owned(),
                });
            }
            Ok(Some(PluginStateDumpConfig {
                target_icount,
                output_path,
            }))
        }
    }
}

pub(super) fn is_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_STATE_DUMP_TARGET | PLUGIN_ARG_STATE_DUMP_PATH
    )
}

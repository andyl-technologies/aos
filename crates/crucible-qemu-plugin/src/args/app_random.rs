//! Parsing and typed configuration for the live app-random argument group.

use thiserror::Error;

use super::{ParsedPluginArgs, PluginArgsParseError, PluginSwitch};

/// Optional scenario root seed for the live app-random doorbell.
pub const PLUGIN_ARG_APP_RANDOM_SEED: &str = "app_random_seed";
/// Optional scenario draw cap for the live app-random doorbell.
pub const PLUGIN_ARG_APP_RANDOM_CAP: &str = "app_random_cap";
/// Optional canonical node name for the live app-random doorbell.
pub const PLUGIN_ARG_APP_RANDOM_NODE: &str = "app_random_node";

/// Seeded decision-source inputs for the live app-random doorbell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginAppRandomConfig {
    root_seed: u64,
    draw_cap: u64,
    node_name: String,
}

impl PluginAppRandomConfig {
    /// Returns the scenario root seed.
    #[must_use]
    pub const fn root_seed(&self) -> u64 {
        self.root_seed
    }

    /// Returns the scenario-wide app-random draw cap.
    #[must_use]
    pub const fn draw_cap(&self) -> u64 {
        self.draw_cap
    }

    /// Returns the canonical scheduler node name.
    #[must_use]
    pub fn node_name(&self) -> &str {
        &self.node_name
    }
}

/// Reports malformed live app-random plugin arguments.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRandomArgsParseError {
    /// Only part of the app-random argument group was supplied.
    #[error(
        "live app-random requires all of `app_random_seed`, `app_random_cap`, and `app_random_node`"
    )]
    Incomplete,
    /// Inputs were supplied while white-box mode was disabled.
    #[error("live app-random arguments are forbidden while white-box mode is off")]
    WhiteboxDisabled,
    /// A numeric argument was not a valid unsigned integer.
    #[error("plugin argument `{key}` has invalid u64 value `{value}`")]
    InvalidInteger {
        /// Rejected argument key.
        key: &'static str,
        /// Rejected value.
        value: String,
    },
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
    whitebox: PluginSwitch,
) -> Result<Option<PluginAppRandomConfig>, PluginArgsParseError> {
    let seed = parsed.value(PLUGIN_ARG_APP_RANDOM_SEED);
    let cap = parsed.value(PLUGIN_ARG_APP_RANDOM_CAP);
    let node = parsed.value(PLUGIN_ARG_APP_RANDOM_NODE);
    match (seed, cap, node) {
        (None, None, None) => Ok(None),
        (Some(_), Some(_), Some(_)) if !whitebox.is_on() => {
            Err(AppRandomArgsParseError::WhiteboxDisabled.into())
        }
        (Some(seed), Some(cap), Some(node_name)) => Ok(Some(PluginAppRandomConfig {
            root_seed: parse_u64(PLUGIN_ARG_APP_RANDOM_SEED, seed)?,
            draw_cap: parse_u64(PLUGIN_ARG_APP_RANDOM_CAP, cap)?,
            node_name: node_name.to_owned(),
        })),
        _ => Err(AppRandomArgsParseError::Incomplete.into()),
    }
}

pub(super) fn is_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_APP_RANDOM_SEED | PLUGIN_ARG_APP_RANDOM_CAP | PLUGIN_ARG_APP_RANDOM_NODE
    )
}

fn parse_u64(key: &'static str, value: &str) -> Result<u64, PluginArgsParseError> {
    value
        .parse::<u64>()
        .map_err(|_source| AppRandomArgsParseError::InvalidInteger {
            key,
            value: value.to_owned(),
        })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PluginArgs;

    #[test]
    fn complete_group_parses() {
        let args = PluginArgs::parse(
            "simfd=4,slot=1,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=1048598,app_random_cap=2,app_random_node=node-a",
        )
        .unwrap_or_else(|error| panic!("app-random args should parse: {error}"));
        let config = args
            .app_random()
            .unwrap_or_else(|| panic!("app-random config should be present"));
        assert_eq!(config.root_seed(), 1_048_598);
        assert_eq!(config.draw_cap(), 2);
        assert_eq!(config.node_name(), "node-a");
    }

    #[test]
    fn partial_or_disabled_group_is_rejected() {
        assert_eq!(
            PluginArgs::parse(
                "simfd=3,slot=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=7"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::Incomplete
            ))
        );
        assert_eq!(
            PluginArgs::parse(
                "simfd=3,slot=0,app_random_seed=7,app_random_cap=1,app_random_node=node-a"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::WhiteboxDisabled
            ))
        );
    }
}

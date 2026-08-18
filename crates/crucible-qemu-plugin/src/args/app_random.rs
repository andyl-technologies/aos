//! Parsing and typed configuration for the live app-random argument group.

use std::collections::BTreeMap;
use thiserror::Error;

use super::{ParsedPluginArgs, PluginArgsParseError, PluginSwitch};

/// Optional scenario root seed for the live app-random doorbell.
pub const PLUGIN_ARG_APP_RANDOM_SEED: &str = "app_random_seed";
/// Optional scenario draw cap for the live app-random doorbell.
pub const PLUGIN_ARG_APP_RANDOM_CAP: &str = "app_random_cap";
/// Optional canonical node name for the live app-random doorbell.
pub const PLUGIN_ARG_APP_RANDOM_NODE: &str = "app_random_node";
/// Optional fork seed for requests after an exact node-local prefix.
pub const PLUGIN_ARG_APP_RANDOM_BRANCH_SEED: &str = "app_random_branch_seed";
/// Optional number of node-local prefix requests served before re-seeding.
pub const PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER: &str = "app_random_branch_after";
/// Optional node-local draw count already consumed before process launch.
pub const PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET: &str = "app_random_draw_offset";
/// Optional hex-name/per-stream cursor map for process continuation.
pub const PLUGIN_ARG_APP_RANDOM_POSITIONS: &str = "app_random_positions";

/// Seeded decision-source inputs for the live app-random doorbell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginAppRandomConfig {
    root_seed: u64,
    draw_cap: u64,
    node_name: String,
    branch_seed: Option<u64>,
    branch_after_draws: Option<u64>,
    draw_offset: u64,
    stream_positions: BTreeMap<String, u64>,
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

    /// Returns the optional decision-RNG root for the forked future.
    #[must_use]
    pub const fn branch_seed(&self) -> Option<u64> {
        self.branch_seed
    }

    /// Returns the node-local prefix draw count before the forked future.
    #[must_use]
    pub const fn branch_after_draws(&self) -> Option<u64> {
        self.branch_after_draws
    }

    /// Returns the node-local draws consumed before process launch.
    #[must_use]
    pub const fn draw_offset(&self) -> u64 {
        self.draw_offset
    }

    /// Returns per-stream cursors consumed before process launch.
    #[must_use]
    pub const fn stream_positions(&self) -> &BTreeMap<String, u64> {
        &self.stream_positions
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
    /// Only part of the optional branch group was supplied.
    #[error(
        "live app-random branching requires both `app_random_branch_seed` and `app_random_branch_after`"
    )]
    IncompleteBranch,
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
    /// The branch boundary lies beyond the scenario draw budget.
    #[error("live app-random branch boundary {branch_after} exceeds draw cap {draw_cap}")]
    BranchAfterExceedsCap {
        /// Requested node-local prefix draw count.
        branch_after: u64,
        /// Scenario app-random draw cap.
        draw_cap: u64,
    },
    /// The continuation offset lies beyond the scenario draw budget.
    #[error("live app-random draw offset {draw_offset} exceeds draw cap {draw_cap}")]
    DrawOffsetExceedsCap {
        /// Already-consumed node-local draw count.
        draw_offset: u64,
        /// Scenario app-random draw cap.
        draw_cap: u64,
    },
    /// The per-stream continuation map was malformed.
    #[error("plugin argument `app_random_positions` has malformed value `{value}`")]
    MalformedPositions {
        /// Rejected encoded cursor map.
        value: String,
    },
    /// Node-local stream positions do not match the declared continuation count.
    #[error(
        "live app-random stream positions total {position_draws} does not match draw offset {draw_offset}"
    )]
    PositionsMismatchOffset {
        /// Sum of node-local per-stream positions.
        position_draws: u64,
        /// Node-local already-consumed draw count.
        draw_offset: u64,
    },
    /// A pending branch boundary lies behind the continuation point.
    #[error("live app-random branch boundary {branch_after} is behind draw offset {draw_offset}")]
    BranchBeforeOffset {
        /// Pending node-local branch boundary.
        branch_after: u64,
        /// Already-consumed node-local draw count.
        draw_offset: u64,
    },
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
    whitebox: PluginSwitch,
) -> Result<Option<PluginAppRandomConfig>, PluginArgsParseError> {
    let seed = parsed.value(PLUGIN_ARG_APP_RANDOM_SEED);
    let cap = parsed.value(PLUGIN_ARG_APP_RANDOM_CAP);
    let node = parsed.value(PLUGIN_ARG_APP_RANDOM_NODE);
    let branch_seed = parsed.value(PLUGIN_ARG_APP_RANDOM_BRANCH_SEED);
    let branch_after = parsed.value(PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER);
    let draw_offset_arg = parsed.value(PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET);
    let positions_arg = parsed.value(PLUGIN_ARG_APP_RANDOM_POSITIONS);
    let draw_offset = draw_offset_arg
        .map(|value| parse_u64(PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET, value))
        .transpose()?
        .unwrap_or_default();
    let stream_positions = positions_arg
        .map(parse_stream_positions)
        .transpose()?
        .unwrap_or_default();
    let branch = match (branch_seed, branch_after) {
        (None, None) => (None, None),
        (Some(seed), Some(after)) => (
            Some(parse_u64(PLUGIN_ARG_APP_RANDOM_BRANCH_SEED, seed)?),
            Some(parse_u64(PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER, after)?),
        ),
        _ => return Err(AppRandomArgsParseError::IncompleteBranch.into()),
    };
    match (seed, cap, node) {
        (None, None, None)
            if branch == (None, None) && draw_offset_arg.is_none() && positions_arg.is_none() =>
        {
            Ok(None)
        }
        (Some(_), Some(_), Some(_)) if !whitebox.is_on() => {
            Err(AppRandomArgsParseError::WhiteboxDisabled.into())
        }
        (Some(seed), Some(cap), Some(node_name)) => {
            let draw_cap = parse_u64(PLUGIN_ARG_APP_RANDOM_CAP, cap)?;
            if branch.1.is_some_and(|after| after > draw_cap) {
                return Err(AppRandomArgsParseError::BranchAfterExceedsCap {
                    branch_after: branch.1.unwrap_or_default(),
                    draw_cap,
                }
                .into());
            }
            if draw_offset > draw_cap {
                return Err(AppRandomArgsParseError::DrawOffsetExceedsCap {
                    draw_offset,
                    draw_cap,
                }
                .into());
            }
            let position_draws = stream_positions
                .values()
                .try_fold(0_u64, |sum, draws| sum.checked_add(*draws))
                .ok_or(AppRandomArgsParseError::PositionsMismatchOffset {
                    position_draws: u64::MAX,
                    draw_offset,
                })?;
            if position_draws != draw_offset {
                return Err(AppRandomArgsParseError::PositionsMismatchOffset {
                    position_draws,
                    draw_offset,
                }
                .into());
            }
            if let Some(branch_after) = branch.1
                && branch_after < draw_offset
            {
                return Err(AppRandomArgsParseError::BranchBeforeOffset {
                    branch_after,
                    draw_offset,
                }
                .into());
            }
            Ok(Some(PluginAppRandomConfig {
                root_seed: parse_u64(PLUGIN_ARG_APP_RANDOM_SEED, seed)?,
                draw_cap,
                node_name: node_name.to_owned(),
                branch_seed: branch.0,
                branch_after_draws: branch.1,
                draw_offset,
                stream_positions,
            }))
        }
        _ => Err(AppRandomArgsParseError::Incomplete.into()),
    }
}

pub(super) fn is_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_APP_RANDOM_SEED
            | PLUGIN_ARG_APP_RANDOM_CAP
            | PLUGIN_ARG_APP_RANDOM_NODE
            | PLUGIN_ARG_APP_RANDOM_BRANCH_SEED
            | PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER
            | PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET
            | PLUGIN_ARG_APP_RANDOM_POSITIONS
    )
}

fn parse_stream_positions(value: &str) -> Result<BTreeMap<String, u64>, PluginArgsParseError> {
    if value.is_empty() {
        return Err(AppRandomArgsParseError::MalformedPositions {
            value: value.to_owned(),
        }
        .into());
    }
    let mut positions = BTreeMap::new();
    for entry in value.split(';') {
        let Some((encoded_name, draws)) = entry.split_once(':') else {
            return Err(AppRandomArgsParseError::MalformedPositions {
                value: value.to_owned(),
            }
            .into());
        };
        let name = decode_hex_name(encoded_name).ok_or_else(|| {
            AppRandomArgsParseError::MalformedPositions {
                value: value.to_owned(),
            }
        })?;
        let draws = draws.parse::<u64>().map_err(|_source| {
            AppRandomArgsParseError::MalformedPositions {
                value: value.to_owned(),
            }
        })?;
        if name.is_empty() || positions.insert(name, draws).is_some() {
            return Err(AppRandomArgsParseError::MalformedPositions {
                value: value.to_owned(),
            }
            .into());
        }
    }
    Ok(positions)
}

fn decode_hex_name(value: &str) -> Option<String> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    String::from_utf8(decoded).ok()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=1048598,app_random_cap=2,app_random_node=node-a",
        )
        .unwrap_or_else(|error| panic!("app-random args should parse: {error}"));
        let config = args
            .app_random()
            .unwrap_or_else(|| panic!("app-random config should be present"));
        assert_eq!(config.root_seed(), 1_048_598);
        assert_eq!(config.draw_cap(), 2);
        assert_eq!(config.node_name(), "node-a");
        assert_eq!(config.branch_seed(), None);
        assert_eq!(config.branch_after_draws(), None);
        assert_eq!(config.draw_offset(), 0);
        assert!(config.stream_positions().is_empty());
    }

    #[test]
    fn continuation_positions_parse() {
        let args = PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=11,app_random_cap=8,app_random_node=node-a,app_random_draw_offset=3,app_random_positions=616c706861:2;62657461:1",
        )
        .unwrap_or_else(|error| panic!("continuation configuration should parse: {error}"));
        let config = args
            .app_random()
            .unwrap_or_else(|| panic!("continuation should include app-random"));
        assert_eq!(config.draw_offset(), 3);
        assert_eq!(config.stream_positions().get("alpha"), Some(&2));
        assert_eq!(config.stream_positions().get("beta"), Some(&1));
    }

    #[test]
    fn complete_branch_group_parses() {
        let args = PluginArgs::parse(
            "simfd=4,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=1048598,app_random_cap=9,app_random_node=node-a,app_random_branch_seed=77,app_random_branch_after=2",
        )
        .unwrap_or_else(|error| panic!("app-random branch args should parse: {error}"));
        let config = args
            .app_random()
            .unwrap_or_else(|| panic!("app-random config should be present"));
        assert_eq!(config.branch_seed(), Some(77));
        assert_eq!(config.branch_after_draws(), Some(2));
    }

    #[test]
    fn partial_or_disabled_group_is_rejected() {
        assert_eq!(
            PluginArgs::parse(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=7"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::Incomplete
            ))
        );
        assert_eq!(
            PluginArgs::parse(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,app_random_seed=7,app_random_cap=1,app_random_node=node-a"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::WhiteboxDisabled
            ))
        );
        assert_eq!(
            PluginArgs::parse(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=7,app_random_cap=1,app_random_node=node-a,app_random_branch_seed=9"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::IncompleteBranch
            ))
        );
        assert_eq!(
            PluginArgs::parse(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_draw_offset=1"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::Incomplete
            ))
        );
        assert!(matches!(
            PluginArgs::parse(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=7,app_random_cap=4,app_random_node=node-a,app_random_draw_offset=2,app_random_positions=616c706861:1"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::PositionsMismatchOffset {
                    position_draws: 1,
                    draw_offset: 2
                }
            ))
        ));
        assert!(matches!(
            PluginArgs::parse(
                "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,app_random_seed=7,app_random_cap=4,app_random_node=node-a,app_random_branch_seed=9,app_random_branch_after=1,app_random_draw_offset=2,app_random_positions=616c706861:2"
            ),
            Err(PluginArgsParseError::AppRandom(
                AppRandomArgsParseError::BranchBeforeOffset {
                    branch_after: 1,
                    draw_offset: 2
                }
            ))
        ));
    }
}

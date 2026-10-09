//! Separately pinned original construction authorization in native launch arguments.

use super::{ParsedPluginArgs, PluginArgsParseError, parse_required_hash, parse_required_u32};

const COMMITMENT: &str = "node_initialization_commitment";
const REALIZE: &str = "node_initialization_realize_digest";
const POLICY: &str = "node_initialization_policy_digest";
const CLASSES: &str = "node_initialization_class_mask";
const BUDGET: &str = "node_initialization_max_callbacks";
const KEYS: [&str; 5] = [COMMITMENT, REALIZE, POLICY, CLASSES, BUDGET];

/// Pins every original construction field before native callback registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeInitializationConfig {
    /// Commits to the complete original initialization preparation.
    pub commitment: [u8; 32],
    /// Commits to the original accepted CNP Realize envelope.
    pub realize_request_digest: [u8; 32],
    /// Commits to the installed construction policy.
    pub policy_digest: [u8; 32],
    /// Selects the installed typed callback classes, never a generic poll loop.
    pub class_mask: u32,
    /// Bounds enrolled original administrative callbacks.
    pub maximum_callbacks: u32,
}

impl NativeInitializationConfig {
    pub(crate) fn matches(
        self,
        preparation: &crucible_protocol::node_control::NativeInitializationPreparation,
    ) -> Result<bool, crucible_protocol::node_control::NativeCommandError> {
        Ok(self.commitment == preparation.identity_digest()?
            && self.realize_request_digest == preparation.realize_request_digest
            && self.policy_digest == preparation.policy_digest
            && self.class_mask == preparation.class_mask
            && self.maximum_callbacks == preparation.maximum_callbacks)
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<NativeInitializationConfig>, PluginArgsParseError> {
    if KEYS.iter().all(|key| parsed.value(key).is_none()) {
        return Ok(None);
    }
    for key in KEYS {
        if parsed.value(key).is_none() {
            return Err(PluginArgsParseError::MissingRequiredKey { key });
        }
    }
    let config = NativeInitializationConfig {
        commitment: parse_required_hash(parsed, COMMITMENT)?,
        realize_request_digest: parse_required_hash(parsed, REALIZE)?,
        policy_digest: parse_required_hash(parsed, POLICY)?,
        class_mask: parse_required_u32(parsed, CLASSES)?,
        maximum_callbacks: parse_required_u32(parsed, BUDGET)?,
    };
    if config.commitment == [0; 32]
        || config.realize_request_digest == [0; 32]
        || config.policy_digest == [0; 32]
        || config.class_mask == 0
        || config.class_mask & !7 != 0
        || !(1..=64).contains(&config.maximum_callbacks)
    {
        return Err(PluginArgsParseError::InvalidNativeNodeControl);
    }
    Ok(Some(config))
}

pub(super) fn is_key(key: &str) -> bool {
    KEYS.contains(&key)
}

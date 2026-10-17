//! Original reader enrollment commitments pinned before native construction.

use super::{ParsedPluginArgs, PluginArgsParseError, parse_required_hash};

const COMMITMENT: &str = "node_administration_commitment";
const POLICY: &str = "node_administration_policy_digest";
const KEYS: [&str; 2] = [COMMITMENT, POLICY];

/// Pins a source-observed reader role without granting modeled-source coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAdministrationConfig {
    /// Commits to the complete original endpoint and companion preparation.
    pub commitment: [u8; 32],
    /// Commits to the independently selected reader enrollment policy.
    pub policy_digest: [u8; 32],
}

impl NativeAdministrationConfig {
    pub(crate) fn matches(
        self,
        preparation: &crucible_protocol::node_control::NativeAdministrativePreparation,
    ) -> Result<bool, crucible_protocol::node_control::NativeCommandError> {
        preparation.validate()?;
        Ok(self.commitment == preparation.identity_digest()?
            && self.policy_digest == preparation.policy_digest)
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<NativeAdministrationConfig>, PluginArgsParseError> {
    if KEYS.iter().all(|key| parsed.value(key).is_none()) {
        return Ok(None);
    }
    for key in KEYS {
        if parsed.value(key).is_none() {
            return Err(PluginArgsParseError::MissingRequiredKey { key });
        }
    }
    let config = NativeAdministrationConfig {
        commitment: parse_required_hash(parsed, COMMITMENT)?,
        policy_digest: parse_required_hash(parsed, POLICY)?,
    };
    if config.commitment == [0; 32] || config.policy_digest == [0; 32] {
        return Err(PluginArgsParseError::InvalidNativeNodeControl);
    }
    Ok(Some(config))
}

pub(super) fn is_key(key: &str) -> bool {
    KEYS.contains(&key)
}

#[cfg(test)]
#[path = "native_administration_tests.rs"]
mod tests;

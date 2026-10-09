//! Original source-defined phase policy pinned beside the construction companion.
//!
//! A closed launch pin is a compatibility commitment, never permission to execute
//! a callback. The source independently checks every field against its early
//! pre-construction authorization and actual resource manifest.

use super::{ParsedPluginArgs, PluginArgsParseError, parse_required_hash, parse_required_u32};

const COMMITMENT: &str = "node_phase_commitment";
const POLICY: &str = "node_phase_policy_digest";
const MAPPING: &str = "node_phase_mapping";
const BUDGET: &str = "node_phase_max_microsteps";
const KEYS: [&str; 4] = [COMMITMENT, POLICY, MAPPING, BUDGET];

/// Pins the exact source phase projection before construction and registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePhaseConfig {
    /// Commits to the complete original phase and construction preparation bytes.
    pub commitment: [u8; 32],
    /// Commits to the installed instruction projection policy.
    pub policy_digest: [u8; 32],
    /// Selects the closed source mapping, currently instruction reaction only.
    pub mapping: u32,
    /// Bounds the exclusive microstep count; this grants no settlement permission.
    pub maximum_microsteps: u64,
}

impl NativePhaseConfig {
    pub(crate) fn matches(
        self,
        preparation: &crucible_protocol::node_control::NativePhasePreparation,
    ) -> Result<bool, crucible_protocol::node_control::NativeCommandError> {
        preparation.validate()?;
        Ok(self.commitment == preparation.identity_digest()?
            && self.policy_digest == preparation.policy_digest
            && self.mapping == preparation.mapping as u32
            && self.maximum_microsteps == preparation.maximum_microstep.get())
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<NativePhaseConfig>, PluginArgsParseError> {
    if KEYS.iter().all(|key| parsed.value(key).is_none()) {
        return Ok(None);
    }
    for key in KEYS {
        if parsed.value(key).is_none() {
            return Err(PluginArgsParseError::MissingRequiredKey { key });
        }
    }
    let config = NativePhaseConfig {
        commitment: parse_required_hash(parsed, COMMITMENT)?,
        policy_digest: parse_required_hash(parsed, POLICY)?,
        mapping: parse_required_u32(parsed, MAPPING)?,
        maximum_microsteps: u64::from(parse_required_u32(parsed, BUDGET)?),
    };
    if config.commitment == [0; 32]
        || config.policy_digest == [0; 32]
        || config.mapping != 1
        || !(1..=1_000_000).contains(&config.maximum_microsteps)
    {
        return Err(PluginArgsParseError::InvalidNativeNodeControl);
    }
    Ok(Some(config))
}

pub(super) fn is_key(key: &str) -> bool {
    KEYS.contains(&key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::args::PluginArgs;

    fn fields() -> Vec<String> {
        vec![
            format!("node_phase_commitment={}", "06".repeat(32)),
            format!("node_phase_policy_digest={}", "07".repeat(32)),
            "node_phase_mapping=1".into(),
            "node_phase_max_microsteps=16".into(),
        ]
    }

    fn arguments(fields: &[String], edition: u32, construction: bool) -> String {
        let companion = if construction {
            format!(
                ",node_initialization_commitment={},node_initialization_realize_digest={},node_initialization_policy_digest={},node_initialization_class_mask=7,node_initialization_max_callbacks=64",
                "03".repeat(32),
                "04".repeat(32),
                "05".repeat(32),
            )
        } else {
            String::new()
        };
        format!(
            "simfd=3,slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,node_control_fd=9,node_control_scope_hash={},node_control_version={edition}{companion},{}",
            "01".repeat(32),
            "02".repeat(32),
            fields.join(","),
        )
    }

    #[test]
    fn phase_requires_complete_companion_and_pinned_wire_edition() {
        let fields = fields();
        let parsed = PluginArgs::parse(&arguments(&fields, 3, true)).unwrap();
        let native = parsed.native_node_control().unwrap();
        assert!(native.initialization().is_some());
        let phase = native.phase().unwrap();
        assert_eq!(phase.commitment, [6; 32]);
        assert_eq!(phase.policy_digest, [7; 32]);
        assert_eq!(phase.mapping, 1);
        assert_eq!(phase.maximum_microsteps, 16);

        assert!(PluginArgs::parse(&arguments(&fields, 3, false)).is_err());
        for edition in [1, 2] {
            assert!(PluginArgs::parse(&arguments(&fields, edition, true)).is_err());
        }
        for missing in 0..fields.len() {
            let partial: Vec<_> = fields
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != missing)
                .map(|(_, value)| value.clone())
                .collect();
            assert!(PluginArgs::parse(&arguments(&partial, 3, true)).is_err());
        }
    }

    #[test]
    fn phase_rejects_open_mapping_budget_zero_commitment_and_duplicate_pin() {
        for (index, replacement) in [
            (0, format!("node_phase_commitment={}", "00".repeat(32))),
            (1, format!("node_phase_policy_digest={}", "00".repeat(32))),
            (2, "node_phase_mapping=0".into()),
            (2, "node_phase_mapping=2".into()),
            (3, "node_phase_max_microsteps=0".into()),
            (3, "node_phase_max_microsteps=1000001".into()),
        ] {
            let mut changed = fields();
            changed[index] = replacement;
            assert!(PluginArgs::parse(&arguments(&changed, 3, true)).is_err());
        }
        let mut duplicate = fields();
        duplicate.push(duplicate[0].clone());
        assert!(PluginArgs::parse(&arguments(&duplicate, 3, true)).is_err());
    }
}

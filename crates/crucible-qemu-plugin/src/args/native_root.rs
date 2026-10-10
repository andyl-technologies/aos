//! Original full-root commitment pinned before source constructor enrollment.
//!
//! The portable record includes every construction, phase and reader companion.
//! Matching this launch pin is correlation only. The native source independently
//! compares its complete original Root328 policy and never derives Ready or
//! effect permission from these arguments.

use super::{ParsedPluginArgs, PluginArgsParseError, parse_required_hash};

const COMMITMENT: &str = "node_fixed_microvm_commitment";
const POLICY: &str = "node_fixed_microvm_policy_digest";
const KEYS: [&str; 2] = [COMMITMENT, POLICY];

/// Pins the complete original preparation before source-root policy registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFixedMicrovmConfig {
    /// Commits to the whole original preparation, including all unchanged companions.
    pub commitment: [u8; 32],
    /// Names the separately installed native root and finite ordering policy.
    pub policy_digest: [u8; 32],
}

impl NativeFixedMicrovmConfig {
    pub(crate) fn matches(
        self,
        preparation: &crucible_protocol::node_control::NativeFixedMicrovmPreparation,
    ) -> Result<bool, crucible_protocol::node_control::NativeCommandError> {
        preparation.validate()?;
        Ok(self.commitment == preparation.identity_digest()?
            && self.policy_digest == preparation.policy_digest)
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<NativeFixedMicrovmConfig>, PluginArgsParseError> {
    if KEYS.iter().all(|key| parsed.value(key).is_none()) {
        return Ok(None);
    }
    for key in KEYS {
        if parsed.value(key).is_none() {
            return Err(PluginArgsParseError::MissingRequiredKey { key });
        }
    }
    let config = NativeFixedMicrovmConfig {
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
// crucible-lint: allow panic-shortcut -- Test-only assertions panic on an unmet original preparation invariant.
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::args::PluginArgs;

    fn fields() -> Vec<String> {
        vec![
            "simfd=3".into(),
            "slot=0".into(),
            format!("fault_node_hash={}", "01".repeat(32)),
            "process_generation=1".into(),
            "network_tx_next_seq=0".into(),
            "storage_completed_history_epochs=1048576".into(),
            "storage_completed_history_gaps=1048576".into(),
            "node_control_fd=9".into(),
            format!("node_control_scope_hash={}", "02".repeat(32)),
            "node_control_version=7".into(),
            format!("node_initialization_commitment={}", "03".repeat(32)),
            format!("node_initialization_realize_digest={}", "04".repeat(32)),
            format!("node_initialization_policy_digest={}", "05".repeat(32)),
            "node_initialization_class_mask=7".into(),
            "node_initialization_max_callbacks=64".into(),
            format!("node_phase_commitment={}", "06".repeat(32)),
            format!("node_phase_policy_digest={}", "07".repeat(32)),
            "node_phase_mapping=1".into(),
            "node_phase_max_microsteps=1024".into(),
            format!("node_administration_commitment={}", "08".repeat(32)),
            format!("node_administration_policy_digest={}", "09".repeat(32)),
            format!("node_fixed_microvm_commitment={}", "0a".repeat(32)),
            format!("node_fixed_microvm_policy_digest={}", "0b".repeat(32)),
        ]
    }

    #[test]
    fn root_selector_requires_each_companion_and_refuses_other_editions() {
        let fields = fields();
        let parsed = PluginArgs::parse(&fields.join(",")).unwrap();
        let config = parsed.native_node_control().unwrap();
        assert_eq!(config.edition().version(), 7);
        let root = config.fixed_microvm().unwrap();
        assert_eq!(root.commitment, [10; 32]);
        assert_eq!(root.policy_digest, [11; 32]);
        for index in 7..fields.len() {
            let mut partial = fields.clone();
            partial.remove(index);
            assert!(PluginArgs::parse(&partial.join(",")).is_err());
        }
        for edition in ["1", "2", "3", "4", "5", "6", "07", "8"] {
            let arguments = fields.join(",").replace(
                "node_control_version=7",
                &format!("node_control_version={edition}"),
            );
            assert!(PluginArgs::parse(&arguments).is_err());
        }
        for key in [
            "node_fixed_microvm_commitment",
            "node_fixed_microvm_policy_digest",
        ] {
            let mut invalid = fields.clone();
            let index = invalid
                .iter()
                .position(|field| field.starts_with(key))
                .unwrap();
            invalid[index] = format!("{key}={}", "00".repeat(32));
            assert!(PluginArgs::parse(&invalid.join(",")).is_err());
            invalid[index] = format!("{key}={}", "0a".repeat(31));
            assert!(PluginArgs::parse(&invalid.join(",")).is_err());
        }
    }
    #[test]
    fn dormant_epoch_selector_requires_original_root_and_preserves_default() {
        let original = fields().join(",");
        assert_eq!(
            PluginArgs::parse(&original)
                .unwrap()
                .native_node_control()
                .unwrap()
                .root_epoch_version(),
            None
        );
        let selected = format!("{original},node_root_epoch_version=1");
        assert_eq!(
            PluginArgs::parse(&selected)
                .unwrap()
                .native_node_control()
                .unwrap()
                .root_epoch_version(),
            Some(1)
        );
        for version in ["0", "2", "01", "", "true"] {
            assert!(
                PluginArgs::parse(&format!("{original},node_root_epoch_version={version}"))
                    .is_err()
            );
        }
        assert!(PluginArgs::parse(&format!("{selected},node_root_epoch_version=1")).is_err());
        assert!(PluginArgs::parse("node_root_epoch_version=1").is_err());
        let without_root = fields()
            .into_iter()
            .filter(|field| !field.starts_with("node_fixed_microvm_"))
            .collect::<Vec<_>>()
            .join(",")
            .replace("node_control_version=7", "node_control_version=6");
        assert!(PluginArgs::parse(&format!("{without_root},node_root_epoch_version=1")).is_err());
    }
    #[test]
    fn prefix_selector_requires_its_own_commitment_and_every_original_companion() {
        let mut complete = fields();
        complete[9] = "node_control_version=9".into();
        complete.extend([
            "node_root_epoch_version=1".into(),
            "node_endpoint_owner_version=1".into(),
            "node_bounded_teardown_version=1".into(),
            format!("node_effect_commitment={}", "0c".repeat(32)),
            format!("node_prefix_commitment={}", "0d".repeat(32)),
        ]);

        let selected = PluginArgs::parse(&complete.join(",")).unwrap();
        let configuration = selected.native_node_control().unwrap();
        assert_eq!(configuration.edition().version(), 9);
        assert_eq!(configuration.effect_commitment(), Some([12; 32]));
        assert_eq!(configuration.prefix_commitment(), Some([13; 32]));
        assert_eq!(configuration.prefix_preparation_contract(), None);
        let explicit = format!(
            "{},node_prefix_preparation_contract_version=1",
            complete.join(",")
        );
        assert_eq!(
            PluginArgs::parse(&explicit)
                .unwrap()
                .native_node_control()
                .unwrap()
                .prefix_preparation_contract(),
            Some(1)
        );
        for version in ["0", "2", "01", "", "future"] {
            assert!(
                PluginArgs::parse(&format!(
                    "{},node_prefix_preparation_contract_version={version}",
                    complete.join(",")
                ))
                .is_err()
            );
        }
        assert!(
            PluginArgs::parse(&format!(
                "{explicit},node_prefix_preparation_contract_version=1"
            ))
            .is_err()
        );
        assert!(PluginArgs::parse("node_prefix_preparation_contract_version=1").is_err());
        assert_eq!(configuration.bounded_teardown_version(), Some(1));
        for index in 7..complete.len() {
            let mut missing = complete.clone();
            missing.remove(index);
            assert!(PluginArgs::parse(&missing.join(",")).is_err());
        }
        for edition in 1..=8 {
            let arguments = complete.join(",").replace(
                "node_control_version=9",
                &format!("node_control_version={edition}"),
            );
            assert!(PluginArgs::parse(&arguments).is_err());
        }
        for digest in ["00".repeat(32), "0d".repeat(31)] {
            let arguments = complete.join(",").replace(
                &format!("node_prefix_commitment={}", "0d".repeat(32)),
                &format!("node_prefix_commitment={digest}"),
            );
            assert!(PluginArgs::parse(&arguments).is_err());
        }
        let stray = format!(
            "{},node_prefix_commitment={}",
            fields().join(","),
            "0d".repeat(32)
        );
        assert!(PluginArgs::parse(&stray).is_err());
    }
}

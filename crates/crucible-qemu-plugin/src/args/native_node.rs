//! Closed independently versioned native node-controller preparation arguments.

use super::{ParsedPluginArgs, PluginArgsParseError, parse_required_fd, parse_required_hash};

/// Names the separately inherited private native command datagram descriptor.
pub const PLUGIN_ARG_NODE_CONTROL_FD: &str = "node_control_fd";
/// Pins the complete prepared owner scope rather than a feature switch.
pub const PLUGIN_ARG_NODE_CONTROL_SCOPE_HASH: &str = "node_control_scope_hash";
/// Negotiates the exact independent native command edition.
pub const PLUGIN_ARG_NODE_CONTROL_VERSION: &str = "node_control_version";

/// Pins independently prepared native channel custody and exact codec edition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeNodeControlConfig {
    descriptor: i32,
    scope_digest: [u8; 32],
    edition: crucible_protocol::node_control::NativeControlEdition,
    initialization: Option<super::NativeInitializationConfig>,
    phase: Option<super::NativePhaseConfig>,
    administration: Option<super::NativeAdministrationConfig>,
    fixed_microvm: Option<super::NativeFixedMicrovmConfig>,
    fingerprint_worker: bool,
    root_epoch_version: Option<u32>,
    endpoint_owner_version: Option<u32>,
    bounded_teardown_version: Option<u32>,
    effect_commitment: Option<[u8; 32]>,
    prefix_commitment: Option<[u8; 32]>,
    prefix_preparation_contract: Option<u32>,
}

impl NativeNodeControlConfig {
    /// Returns the separately installed initial observation and consumed-ACK contract.
    pub const fn prefix_preparation_contract(self) -> Option<u32> {
        self.prefix_preparation_contract
    }

    /// Returns the distinct complete controller-nine preparation commitment.
    pub const fn prefix_commitment(self) -> Option<[u8; 32]> {
        self.prefix_commitment
    }

    /// Returns the separately pinned complete original effect preparation.
    pub const fn effect_commitment(self) -> Option<[u8; 32]> {
        self.effect_commitment
    }

    /// Returns the separately selected finite producer mechanism, never epoch authority.
    pub const fn bounded_teardown_version(self) -> Option<u32> {
        self.bounded_teardown_version
    }

    /// Returns the explicitly selected local original-owner observation ABI.
    pub const fn endpoint_owner_version(self) -> Option<u32> {
        self.endpoint_owner_version
    }

    /// Returns the explicitly selected dormant native callback ABI.
    pub const fn root_epoch_version(self) -> Option<u32> {
        self.root_epoch_version
    }

    /// Returns the complete original root-policy commitment, if explicitly selected.
    pub const fn fixed_microvm(self) -> Option<super::NativeFixedMicrovmConfig> {
        self.fixed_microvm
    }

    pub(crate) const fn fingerprint_worker(self) -> bool {
        self.fingerprint_worker
    }
    /// Returns the separately pinned original reader enrollment, if present.
    pub const fn administration(self) -> Option<super::NativeAdministrationConfig> {
        self.administration
    }
    /// Returns the separately pinned original source projection, if present.
    pub const fn phase(self) -> Option<super::NativePhaseConfig> {
        self.phase
    }
    /// Returns the separately pinned original construction authorization, if present.
    pub const fn initialization(self) -> Option<super::NativeInitializationConfig> {
        self.initialization
    }
    /// Returns the immutable launch-selected public channel edition.
    pub const fn edition(self) -> crucible_protocol::node_control::NativeControlEdition {
        self.edition
    }
    /// Returns the independently inherited supervisor-owned native socket.
    pub const fn descriptor(self) -> i32 {
        self.descriptor
    }

    /// Returns the complete prepared owner scope commitment.
    pub const fn scope_digest(self) -> [u8; 32] {
        self.scope_digest
    }
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<NativeNodeControlConfig>, PluginArgsParseError> {
    let keys = [
        PLUGIN_ARG_NODE_CONTROL_FD,
        PLUGIN_ARG_NODE_CONTROL_SCOPE_HASH,
        PLUGIN_ARG_NODE_CONTROL_VERSION,
    ];
    let initialization = super::native_initialization::parse(parsed)?;
    let phase = super::native_phase::parse(parsed)?;
    let administration = super::native_administration::parse(parsed)?;
    let fixed_microvm = super::native_root::parse(parsed)?;
    let root_epoch_version = match parsed.value("node_root_epoch_version") {
        None => None,
        Some("1") if fixed_microvm.is_some() => Some(1),
        _ => return Err(PluginArgsParseError::InvalidNativeNodeControl),
    };
    let endpoint_owner_version = match parsed.value("node_endpoint_owner_version") {
        None => None,
        Some("1") if root_epoch_version == Some(1) => Some(1),
        _ => return Err(PluginArgsParseError::InvalidNativeNodeControl),
    };
    let bounded_teardown_version = match parsed.value("node_bounded_teardown_version") {
        None => None,
        Some("1") if endpoint_owner_version == Some(1) => Some(1),
        _ => return Err(PluginArgsParseError::InvalidNativeNodeControl),
    };
    let effect_commitment = if parsed.value("node_effect_commitment").is_some() {
        Some(parse_required_hash(parsed, "node_effect_commitment")?)
    } else {
        None
    };
    let prefix_commitment = if parsed.value("node_prefix_commitment").is_some() {
        Some(parse_required_hash(parsed, "node_prefix_commitment")?)
    } else {
        None
    };
    if keys.iter().all(|key| parsed.value(key).is_none())
        && initialization.is_none()
        && phase.is_none()
        && administration.is_none()
        && fixed_microvm.is_none()
        && prefix_commitment.is_none()
        && parsed
            .value("node_prefix_preparation_contract_version")
            .is_none()
    {
        return Ok(None);
    }
    for key in keys {
        if parsed.value(key).is_none() {
            return Err(PluginArgsParseError::MissingRequiredKey { key });
        }
    }
    let edition = match parsed.value(PLUGIN_ARG_NODE_CONTROL_VERSION) {
        Some("1") => crucible_protocol::node_control::NativeControlEdition::Original,
        Some("2") => crucible_protocol::node_control::NativeControlEdition::OwnedCustody,
        Some("3") if phase.is_some() => {
            crucible_protocol::node_control::NativeControlEdition::PhaseProjection
        }
        Some("4") if phase.is_some() => {
            crucible_protocol::node_control::NativeControlEdition::PreparationSuccessor
        }
        Some("9")
            if phase.is_some()
                && administration.is_some()
                && fixed_microvm.is_some()
                && bounded_teardown_version == Some(1)
                && effect_commitment.is_some_and(|value| value != [0; 32])
                && prefix_commitment.is_some_and(|value| value != [0; 32]) =>
        {
            crucible_protocol::node_control::NativeControlEdition::PrefixEffect
        }
        Some("8")
            if phase.is_some()
                && administration.is_some()
                && fixed_microvm.is_some()
                && bounded_teardown_version == Some(1)
                && effect_commitment.is_some_and(|value| value != [0; 32]) =>
        {
            crucible_protocol::node_control::NativeControlEdition::FiniteEffect
        }
        Some("7") if phase.is_some() && administration.is_some() && fixed_microvm.is_some() => {
            crucible_protocol::node_control::NativeControlEdition::FixedMicrovm
        }
        Some("6") if phase.is_some() && administration.is_some() => {
            crucible_protocol::node_control::NativeControlEdition::Construction
        }
        Some("5") if phase.is_some() && administration.is_some() => {
            crucible_protocol::node_control::NativeControlEdition::Administration
        }
        _ => return Err(PluginArgsParseError::InvalidNativeNodeControl),
    };
    if (initialization.is_some()
        && edition == crucible_protocol::node_control::NativeControlEdition::Original)
        || (phase.is_some()
            && (initialization.is_none()
                || !matches!(edition, crucible_protocol::node_control::NativeControlEdition::PhaseProjection
                    | crucible_protocol::node_control::NativeControlEdition::PreparationSuccessor
                    | crucible_protocol::node_control::NativeControlEdition::Administration
                    | crucible_protocol::node_control::NativeControlEdition::Construction
                    | crucible_protocol::node_control::NativeControlEdition::FiniteEffect
                    | crucible_protocol::node_control::NativeControlEdition::PrefixEffect
                    | crucible_protocol::node_control::NativeControlEdition::FixedMicrovm)))
        || (administration.is_some()
            && !matches!(edition, crucible_protocol::node_control::NativeControlEdition::Administration
                | crucible_protocol::node_control::NativeControlEdition::Construction
                | crucible_protocol::node_control::NativeControlEdition::FiniteEffect
                    | crucible_protocol::node_control::NativeControlEdition::PrefixEffect
                    | crucible_protocol::node_control::NativeControlEdition::FixedMicrovm))
        || (fixed_microvm.is_some()
            && !matches!(edition, crucible_protocol::node_control::NativeControlEdition::FixedMicrovm | crucible_protocol::node_control::NativeControlEdition::FiniteEffect
                    | crucible_protocol::node_control::NativeControlEdition::PrefixEffect))
    {
        return Err(PluginArgsParseError::InvalidNativeNodeControl);
    }
    if effect_commitment.is_some()
        && !matches!(
            edition,
            crucible_protocol::node_control::NativeControlEdition::FiniteEffect
                | crucible_protocol::node_control::NativeControlEdition::PrefixEffect
        )
    {
        return Err(PluginArgsParseError::InvalidNativeNodeControl);
    }
    let prefix_preparation_contract = match parsed.value("node_prefix_preparation_contract_version")
    {
        None => None,
        Some("1")
            if edition == crucible_protocol::node_control::NativeControlEdition::PrefixEffect =>
        {
            Some(1)
        }
        _ => return Err(PluginArgsParseError::InvalidNativeNodeControl),
    };
    if prefix_commitment.is_some()
        && edition != crucible_protocol::node_control::NativeControlEdition::PrefixEffect
    {
        return Err(PluginArgsParseError::InvalidNativeNodeControl);
    }
    Ok(Some(NativeNodeControlConfig {
        descriptor: parse_required_fd(parsed, PLUGIN_ARG_NODE_CONTROL_FD)?,
        scope_digest: parse_required_hash(parsed, PLUGIN_ARG_NODE_CONTROL_SCOPE_HASH)?,
        edition,
        initialization,
        phase,
        administration,
        fixed_microvm,
        root_epoch_version,
        endpoint_owner_version,
        bounded_teardown_version,
        effect_commitment,
        prefix_commitment,
        prefix_preparation_contract,
        fingerprint_worker: parsed.value(super::PLUGIN_ARG_FINGERPRINT) == Some("on"),
    }))
}

pub(super) fn is_key(key: &str) -> bool {
    super::native_root::is_key(key)
        || super::native_administration::is_key(key)
        || super::native_phase::is_key(key)
        || super::native_initialization::is_key(key)
        || matches!(
            key,
            "node_prefix_preparation_contract_version"
                | "node_prefix_commitment"
                | "node_effect_commitment"
                | "node_root_epoch_version"
                | "node_endpoint_owner_version"
                | "node_bounded_teardown_version"
                | PLUGIN_ARG_NODE_CONTROL_FD
                | PLUGIN_ARG_NODE_CONTROL_SCOPE_HASH
                | PLUGIN_ARG_NODE_CONTROL_VERSION
        )
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These native node tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::args::PluginArgs;

    fn base() -> String {
        format!(
            "simfd=3,slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576",
            "01".repeat(32)
        )
    }

    #[test]
    fn finite_teardown_selector_requires_the_same_original_endpoint_owner() {
        for selection in ["0", "1", "2", "future"] {
            assert!(
                PluginArgs::parse(&format!(
                    "{},node_bounded_teardown_version={selection}",
                    base()
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn local_endpoint_owner_requires_the_original_root_and_dormant_epoch_selection() {
        for selection in ["0", "1", "2", "future"] {
            let args = format!("{},node_endpoint_owner_version={selection}", base());
            assert!(matches!(
                PluginArgs::parse(&args),
                Err(super::PluginArgsParseError::InvalidNativeNodeControl)
            ));
        }
        let args = format!(
            "{},node_root_epoch_version=1,node_endpoint_owner_version=1",
            base()
        );
        assert!(PluginArgs::parse(&args).is_err());
    }

    #[test]
    fn legacy_launch_has_no_native_controller_preparation() {
        assert!(
            PluginArgs::parse(&base())
                .unwrap()
                .native_node_control()
                .is_none()
        );
    }

    #[test]
    fn independent_native_preparation_requires_all_fields_and_exact_version() {
        for partial in [
            "node_control_fd=9",
            "node_control_version=1",
            "node_control_version=2,node_control_fd=9",
        ] {
            assert!(PluginArgs::parse(&format!("{},{}", base(), partial)).is_err());
        }
        let fields = format!(
            "node_control_fd=9,node_control_scope_hash={},node_control_version=1",
            "02".repeat(32)
        );
        let parsed = PluginArgs::parse(&format!("{},{}", base(), fields)).unwrap();
        let native = parsed.native_node_control().unwrap();
        assert_eq!(native.descriptor(), 9);
        assert_eq!(native.scope_digest(), [2; 32]);
        let owned = PluginArgs::parse(&format!(
            "{},{}",
            base(),
            fields.replace("version=1", "version=2")
        ))
        .unwrap();
        assert_eq!(
            owned.native_node_control().unwrap().edition(),
            crucible_protocol::node_control::NativeControlEdition::OwnedCustody
        );
        assert!(
            PluginArgs::parse(&format!(
                "{},{}",
                base(),
                fields.replace("version=1", "version=3")
            ))
            .is_err()
        );
        assert!(
            PluginArgs::parse(&format!(
                "{},{}",
                base(),
                fields.replace("version=1", "version=01")
            ))
            .is_err()
        );
    }

    #[test]
    fn native_descriptor_cannot_alias_existing_control_or_shared_descriptors() {
        let fields = format!(
            "node_control_fd=3,node_control_scope_hash={},node_control_version=1",
            "02".repeat(32)
        );
        assert!(PluginArgs::parse(&format!("{},{}", base(), fields)).is_err());
        let fields = fields.replace("fd=3", "fd=4");
        assert!(PluginArgs::parse(&format!("{},shmemfd=4,wakefd=5,{}", base(), fields)).is_err());
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These native node tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod initialization_tests {
    use crate::args::PluginArgs;

    fn fields() -> Vec<String> {
        vec![
            format!("node_initialization_commitment={}", "03".repeat(32)),
            format!("node_initialization_realize_digest={}", "04".repeat(32)),
            format!("node_initialization_policy_digest={}", "05".repeat(32)),
            "node_initialization_class_mask=7".into(),
            "node_initialization_max_callbacks=64".into(),
        ]
    }

    fn arguments(fields: &[String], edition: u32) -> String {
        format!(
            "simfd=3,slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,node_control_fd=9,node_control_scope_hash={},node_control_version={edition},{}",
            "01".repeat(32),
            "02".repeat(32),
            fields.join(",")
        )
    }

    #[test]
    fn construction_requires_every_pinned_field_and_owned_wire_edition() {
        let fields = fields();
        let parsed = PluginArgs::parse(&arguments(&fields, 2)).unwrap();
        let initialization = parsed
            .native_node_control()
            .unwrap()
            .initialization()
            .unwrap();
        assert_eq!(initialization.commitment, [3; 32]);
        assert_eq!(initialization.realize_request_digest, [4; 32]);
        assert_eq!(initialization.policy_digest, [5; 32]);
        assert_eq!(initialization.class_mask, 7);
        assert_eq!(initialization.maximum_callbacks, 64);
        assert!(PluginArgs::parse(&arguments(&fields, 1)).is_err());

        for missing in 0..fields.len() {
            let partial: Vec<_> = fields
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != missing)
                .map(|(_, value)| value.clone())
                .collect();
            assert!(PluginArgs::parse(&arguments(&partial, 2)).is_err());
        }
    }

    #[test]
    fn construction_rejects_open_budget_classes_and_missing_identities() {
        for (index, replacement) in [
            (
                0,
                format!("node_initialization_commitment={}", "00".repeat(32)),
            ),
            (
                1,
                format!("node_initialization_realize_digest={}", "00".repeat(32)),
            ),
            (
                2,
                format!("node_initialization_policy_digest={}", "00".repeat(32)),
            ),
            (3, "node_initialization_class_mask=0".into()),
            (3, "node_initialization_class_mask=8".into()),
            (4, "node_initialization_max_callbacks=0".into()),
            (4, "node_initialization_max_callbacks=65".into()),
        ] {
            let mut changed = fields();
            changed[index] = replacement;
            assert!(PluginArgs::parse(&arguments(&changed, 2)).is_err());
        }
        let mut duplicate = fields();
        duplicate.push(duplicate[0].clone());
        assert!(PluginArgs::parse(&arguments(&duplicate, 2)).is_err());
    }
}

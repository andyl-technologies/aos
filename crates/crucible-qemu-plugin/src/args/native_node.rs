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
}

impl NativeNodeControlConfig {
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
    if keys.iter().all(|key| parsed.value(key).is_none()) {
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
        _ => return Err(PluginArgsParseError::InvalidNativeNodeControl),
    };
    Ok(Some(NativeNodeControlConfig {
        descriptor: parse_required_fd(parsed, PLUGIN_ARG_NODE_CONTROL_FD)?,
        scope_digest: parse_required_hash(parsed, PLUGIN_ARG_NODE_CONTROL_SCOPE_HASH)?,
        edition,
    }))
}

pub(super) fn is_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_NODE_CONTROL_FD
            | PLUGIN_ARG_NODE_CONTROL_SCOPE_HASH
            | PLUGIN_ARG_NODE_CONTROL_VERSION
    )
}

#[cfg(test)]
mod tests {
    use crate::args::PluginArgs;

    fn base() -> String {
        format!(
            "simfd=3,slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576",
            "01".repeat(32)
        )
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

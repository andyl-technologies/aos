//! White-box setup attestation arguments.

use super::{PLUGIN_ARG_WHITEBOX_SETUP, ParsedPluginArgs, PluginArgsParseError, PluginSwitch};

/// The only accepted x86 setup attestation for the frozen doorbell ABI.
pub const WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1: &str = "x86-port-00e7-unclaimed-v1";
/// The accepted aarch64 setup attestation for the frozen inert HINT immediate.
pub const WHITEBOX_SETUP_AARCH64_HINT_INERT_V1: &str = "aarch64-hint-4c-inert-v1";

/// A host-produced setup validation consumed before white-box registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxSetupAttestation {
    /// The observed x86 QEMU I/O map leaves reserved port `0x00e7` unclaimed.
    X86Port00e7UnclaimedV1,
    /// The aarch64 guest/platform contract reserves inert `hint #0x4c` for Crucible.
    Aarch64Hint4cInertV1,
}

pub(super) fn parse(
    parsed: &ParsedPluginArgs<'_>,
    whitebox: PluginSwitch,
) -> Result<Option<WhiteboxSetupAttestation>, PluginArgsParseError> {
    match (whitebox, parsed.value(PLUGIN_ARG_WHITEBOX_SETUP)) {
        (PluginSwitch::Off, None) => Ok(None),
        (PluginSwitch::Off, Some(_)) => Err(PluginArgsParseError::WhiteboxSetupWhileDisabled {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
        }),
        (PluginSwitch::On, None) => Err(PluginArgsParseError::MissingWhiteboxSetup {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
        }),
        (PluginSwitch::On, Some(WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1)) => {
            Ok(Some(WhiteboxSetupAttestation::X86Port00e7UnclaimedV1))
        }
        (PluginSwitch::On, Some(WHITEBOX_SETUP_AARCH64_HINT_INERT_V1)) => {
            Ok(Some(WhiteboxSetupAttestation::Aarch64Hint4cInertV1))
        }
        (PluginSwitch::On, Some(value)) => Err(PluginArgsParseError::InvalidWhiteboxSetup {
            key: PLUGIN_ARG_WHITEBOX_SETUP,
            value: value.to_owned(),
        }),
    }
}

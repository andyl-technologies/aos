//! Fail-closed parsing for QEMU plugin launch arguments.
//!
//! QEMU passes plugin options as comma-separated `key=value` tokens after the
//! `-plugin` shared-object path:
//!
//! ```text
//! -plugin /nix/store/.../crucible-qemu-plugin.so,simfd=3,slot=0,whitebox=off,coverage=off
//! ```
//!
//! This module owns only the safe, typed parsing contract. The FFI registration
//! entry point will call it before opening the control fd or touching QEMU state.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

mod app_random;
mod whitebox;
pub use app_random::{
    AppRandomArgsParseError, PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER, PLUGIN_ARG_APP_RANDOM_BRANCH_SEED,
    PLUGIN_ARG_APP_RANDOM_CAP, PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET, PLUGIN_ARG_APP_RANDOM_NODE,
    PLUGIN_ARG_APP_RANDOM_POSITIONS, PLUGIN_ARG_APP_RANDOM_SEED, PluginAppRandomConfig,
};
pub use whitebox::{
    WHITEBOX_SETUP_AARCH64_HLT_UNCLAIMED_V1, WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1,
    WhiteboxSetupAttestation,
};
/// The required host-to-plugin control-socket argument key.
pub const PLUGIN_ARG_SIMFD: &str = "simfd";
/// The required shared-memory node-slot argument key.
pub const PLUGIN_ARG_SLOT: &str = "slot";
/// The optional pre-inherited shared-memory fd argument key.
pub const PLUGIN_ARG_SHMEMFD: &str = "shmemfd";
/// The optional pre-inherited wake fd argument key.
pub const PLUGIN_ARG_WAKEFD: &str = "wakefd";
/// The optional white-box hook switch argument key.
pub const PLUGIN_ARG_WHITEBOX: &str = "whitebox";
/// The setup-time white-box collision-validation attestation argument key.
pub const PLUGIN_ARG_WHITEBOX_SETUP: &str = "whitebox_setup";
/// The optional coverage hook switch argument key.
pub const PLUGIN_ARG_COVERAGE: &str = "coverage";
/// The optional single-VM fingerprint sampling switch argument key.
pub const PLUGIN_ARG_FINGERPRINT: &str = "fingerprint";
/// The optional gate-only synchronous fingerprint-oracle switch argument key.
pub const PLUGIN_ARG_FINGERPRINT_ORACLE: &str = "fingerprint_oracle";
/// The optional terminal raw-state dump target-icount argument key.
pub const PLUGIN_ARG_STATE_DUMP_TARGET: &str = "state_dump_target";
/// The optional terminal raw-state dump output-path argument key.
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

/// Parsed QEMU plugin launch arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginArgs {
    sim_fd: i32,
    slot: u32,
    inherited_fds: Option<PluginInheritedFds>,
    whitebox: PluginSwitch,
    whitebox_setup: Option<WhiteboxSetupAttestation>,
    app_random: Option<PluginAppRandomConfig>,
    coverage: PluginSwitch,
    fingerprint: PluginSwitch,
    fingerprint_oracle: PluginSwitch,
    state_dump: Option<PluginStateDumpConfig>,
}

impl PluginArgs {
    /// Parses comma-separated QEMU plugin arguments.
    ///
    /// # Errors
    ///
    /// Returns [`PluginArgsParseError`] when a required key is missing, an
    /// argument is malformed, a key appears more than once, a value is
    /// unparseable, an unknown key is present, or only one inherited descriptor
    /// of the `shmemfd`/`wakefd` pair is supplied.
    pub fn parse(raw: &str) -> Result<Self, PluginArgsParseError> {
        let parsed = ParsedPluginArgs::parse(raw)?;

        let sim_fd = parse_required_fd(&parsed, PLUGIN_ARG_SIMFD)?;
        let slot = parse_required_u32(&parsed, PLUGIN_ARG_SLOT)?;
        let whitebox = parse_optional_switch(&parsed, PLUGIN_ARG_WHITEBOX)?;
        let whitebox_setup = whitebox::parse(&parsed, whitebox)?;
        let app_random = app_random::parse(&parsed, whitebox)?;
        let coverage = parse_optional_switch(&parsed, PLUGIN_ARG_COVERAGE)?;
        let fingerprint = parse_optional_switch(&parsed, PLUGIN_ARG_FINGERPRINT)?;
        let fingerprint_oracle = parse_optional_switch(&parsed, PLUGIN_ARG_FINGERPRINT_ORACLE)?;
        if fingerprint_oracle.is_on() && !fingerprint.is_on() {
            return Err(PluginArgsParseError::FingerprintOracleWithoutFingerprint);
        }
        let state_dump = parse_state_dump(&parsed, fingerprint)?;
        let inherited_fds = parse_inherited_fds(&parsed)?;

        Ok(Self {
            sim_fd,
            slot,
            inherited_fds,
            whitebox,
            whitebox_setup,
            app_random,
            coverage,
            fingerprint,
            fingerprint_oracle,
            state_dump,
        })
    }

    /// Returns the host-to-plugin control socket fd.
    #[must_use]
    pub const fn sim_fd(&self) -> i32 {
        self.sim_fd
    }

    /// Returns the launch-argument slot index.
    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    /// Returns optional pre-inherited setup descriptors.
    #[must_use]
    pub const fn inherited_fds(&self) -> Option<PluginInheritedFds> {
        self.inherited_fds
    }

    /// Returns whether white-box hooks are enabled.
    #[must_use]
    pub const fn whitebox(&self) -> PluginSwitch {
        self.whitebox
    }

    /// Returns the setup-time collision-validation attestation.
    #[must_use]
    pub const fn whitebox_setup(&self) -> Option<WhiteboxSetupAttestation> {
        self.whitebox_setup
    }

    /// Returns the optional seeded live app-random configuration.
    #[must_use]
    pub const fn app_random(&self) -> Option<&PluginAppRandomConfig> {
        self.app_random.as_ref()
    }

    /// Returns whether coverage hooks are enabled.
    #[must_use]
    pub const fn coverage(&self) -> PluginSwitch {
        self.coverage
    }

    /// Returns whether single-VM fingerprint sampling is enabled.
    #[must_use]
    pub const fn fingerprint(&self) -> PluginSwitch {
        self.fingerprint
    }

    /// Returns whether gate-only synchronous fingerprint comparison is enabled.
    #[must_use]
    pub const fn fingerprint_oracle(&self) -> PluginSwitch {
        self.fingerprint_oracle
    }

    /// Returns the optional exact-boundary terminal raw-state dump request.
    #[must_use]
    pub const fn state_dump(&self) -> Option<&PluginStateDumpConfig> {
        self.state_dump.as_ref()
    }

    /// Validates the slot against the host-advertised node count.
    ///
    /// # Errors
    ///
    /// Returns [`PluginArgsParseError::SlotOutOfRange`] when `node_count` is
    /// zero or this argument's slot is not in `0..node_count`.
    pub fn validate_slot_index(&self, node_count: u32) -> Result<(), PluginArgsParseError> {
        if self.slot < node_count {
            Ok(())
        } else {
            Err(PluginArgsParseError::SlotOutOfRange {
                slot: self.slot,
                node_count,
            })
        }
    }
}

/// Optional pre-inherited setup descriptors from the plugin command line.
///
/// The canonical production path receives these descriptors through the
/// `Setup` frame's `SCM_RIGHTS` payload. This pair exists for explicit test and
/// bootstrap paths and must be supplied all-or-nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginInheritedFds {
    /// Pre-inherited shared-memory descriptor.
    pub shmem_fd: i32,
    /// Pre-inherited wake descriptor.
    pub wake_fd: i32,
}

/// A boolean plugin feature switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginSwitch {
    /// The feature is disabled.
    Off,
    /// The feature is enabled.
    On,
}

impl PluginSwitch {
    /// Returns `true` when the feature is enabled.
    #[must_use]
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }
}

/// An error produced while parsing QEMU plugin launch arguments.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginArgsParseError {
    /// A required key was absent.
    #[error("missing required plugin argument `{key}`")]
    MissingRequiredKey {
        /// Missing key.
        key: &'static str,
    },
    /// A key appeared more than once.
    #[error("duplicate plugin argument `{key}`")]
    DuplicateKey {
        /// Duplicated key.
        key: String,
    },
    /// An argument was not `key=value`.
    #[error("malformed plugin argument `{argument}`")]
    MalformedArgument {
        /// Rejected argument text.
        argument: String,
    },
    /// An unrecognized key was supplied.
    #[error("unknown plugin argument key `{key}`")]
    UnknownKey {
        /// Rejected key.
        key: String,
    },
    /// A file descriptor value was invalid.
    #[error("plugin argument `{key}` has invalid fd value `{value}`")]
    InvalidFd {
        /// Key whose value was rejected.
        key: &'static str,
        /// Rejected value.
        value: String,
    },
    /// A slot value was invalid.
    #[error("plugin argument `{key}` has invalid slot value `{value}`")]
    InvalidSlot {
        /// Key whose value was rejected.
        key: &'static str,
        /// Rejected value.
        value: String,
    },
    /// A feature switch was not `on` or `off`.
    #[error("plugin argument `{key}` must be `on` or `off`, got `{value}`")]
    InvalidSwitch {
        /// Key whose value was rejected.
        key: &'static str,
        /// Rejected value.
        value: String,
    },
    /// White-box mode was enabled without a setup collision attestation.
    #[error("white-box mode requires plugin argument `{key}`")]
    MissingWhiteboxSetup {
        /// Missing setup-attestation key.
        key: &'static str,
    },
    /// A setup attestation was supplied while white-box mode was disabled.
    #[error("plugin argument `{key}` is forbidden while white-box mode is off")]
    WhiteboxSetupWhileDisabled {
        /// Unexpected setup-attestation key.
        key: &'static str,
    },
    /// The setup attestation did not match a supported frozen doorbell ABI.
    #[error("plugin argument `{key}` has unsupported value `{value}`")]
    InvalidWhiteboxSetup {
        /// Setup-attestation key.
        key: &'static str,
        /// Rejected attestation.
        value: String,
    },
    /// The app-random argument group was malformed.
    #[error(transparent)]
    AppRandom(#[from] AppRandomArgsParseError),
    /// Only one of the inherited descriptor keys was supplied.
    #[error("plugin inherited descriptors require both `shmemfd` and `wakefd`")]
    IncompleteInheritedDescriptors,
    /// Only one member of the terminal state-dump argument pair was supplied.
    #[error("plugin terminal state dump requires both target and output path")]
    IncompleteStateDump,
    /// A terminal state dump was requested without fingerprint boundary sampling.
    #[error("plugin terminal state dump requires `fingerprint=on`")]
    StateDumpWithoutFingerprint,
    /// The synchronous oracle was requested without fingerprint boundary sampling.
    #[error("plugin fingerprint oracle requires `fingerprint=on`")]
    FingerprintOracleWithoutFingerprint,
    /// The terminal state-dump target was not a nonzero instruction count.
    #[error("plugin state-dump target is invalid: `{value}`")]
    InvalidStateDumpTarget {
        /// Rejected target text.
        value: String,
    },
    /// The terminal state-dump path was not an absolute comma-free path.
    #[error("plugin state-dump path is invalid: `{value}`")]
    InvalidStateDumpPath {
        /// Rejected path text.
        value: String,
    },
    /// The slot was not within `0..node_count`.
    #[error("plugin slot {slot} is outside 0..{node_count}")]
    SlotOutOfRange {
        /// Rejected slot.
        slot: u32,
        /// Host-advertised node count.
        node_count: u32,
    },
}

struct ParsedPluginArgs<'a> {
    entries: Vec<(&'a str, &'a str)>,
}

impl<'a> ParsedPluginArgs<'a> {
    fn parse(raw: &'a str) -> Result<Self, PluginArgsParseError> {
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();

        for argument in raw.split(',') {
            let Some((key, value)) = argument.split_once('=') else {
                return Err(PluginArgsParseError::MalformedArgument {
                    argument: argument.to_owned(),
                });
            };
            if key.is_empty() || value.is_empty() {
                return Err(PluginArgsParseError::MalformedArgument {
                    argument: argument.to_owned(),
                });
            }
            if !is_known_key(key) {
                return Err(PluginArgsParseError::UnknownKey {
                    key: key.to_owned(),
                });
            }
            if !seen.insert(key) {
                return Err(PluginArgsParseError::DuplicateKey {
                    key: key.to_owned(),
                });
            }
            entries.push((key, value));
        }

        Ok(Self { entries })
    }

    fn value(&self, key: &'static str) -> Option<&'a str> {
        self.entries
            .iter()
            .find_map(|(candidate, value)| (*candidate == key).then_some(*value))
    }
}

fn parse_required_fd(
    parsed: &ParsedPluginArgs<'_>,
    key: &'static str,
) -> Result<i32, PluginArgsParseError> {
    let Some(value) = parsed.value(key) else {
        return Err(PluginArgsParseError::MissingRequiredKey { key });
    };
    parse_fd(key, value)
}

fn parse_optional_fd(
    parsed: &ParsedPluginArgs<'_>,
    key: &'static str,
) -> Result<Option<i32>, PluginArgsParseError> {
    parsed
        .value(key)
        .map(|value| parse_fd(key, value))
        .transpose()
}

fn parse_fd(key: &'static str, value: &str) -> Result<i32, PluginArgsParseError> {
    match value.parse::<i32>() {
        Ok(fd) if fd >= 0 => Ok(fd),
        _ => Err(PluginArgsParseError::InvalidFd {
            key,
            value: value.to_owned(),
        }),
    }
}

fn parse_required_u32(
    parsed: &ParsedPluginArgs<'_>,
    key: &'static str,
) -> Result<u32, PluginArgsParseError> {
    let Some(value) = parsed.value(key) else {
        return Err(PluginArgsParseError::MissingRequiredKey { key });
    };
    value
        .parse::<u32>()
        .map_err(|_source| PluginArgsParseError::InvalidSlot {
            key,
            value: value.to_owned(),
        })
}

fn parse_optional_switch(
    parsed: &ParsedPluginArgs<'_>,
    key: &'static str,
) -> Result<PluginSwitch, PluginArgsParseError> {
    match parsed.value(key) {
        Some("on") => Ok(PluginSwitch::On),
        Some("off") | None => Ok(PluginSwitch::Off),
        Some(value) => Err(PluginArgsParseError::InvalidSwitch {
            key,
            value: value.to_owned(),
        }),
    }
}

fn parse_inherited_fds(
    parsed: &ParsedPluginArgs<'_>,
) -> Result<Option<PluginInheritedFds>, PluginArgsParseError> {
    match (
        parse_optional_fd(parsed, PLUGIN_ARG_SHMEMFD)?,
        parse_optional_fd(parsed, PLUGIN_ARG_WAKEFD)?,
    ) {
        (Some(shmem_fd), Some(wake_fd)) => Ok(Some(PluginInheritedFds { shmem_fd, wake_fd })),
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            Err(PluginArgsParseError::IncompleteInheritedDescriptors)
        }
    }
}

fn parse_state_dump(
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

fn is_known_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_SIMFD
            | PLUGIN_ARG_SLOT
            | PLUGIN_ARG_SHMEMFD
            | PLUGIN_ARG_WAKEFD
            | PLUGIN_ARG_WHITEBOX
            | PLUGIN_ARG_WHITEBOX_SETUP
            | PLUGIN_ARG_COVERAGE
            | PLUGIN_ARG_FINGERPRINT
            | PLUGIN_ARG_FINGERPRINT_ORACLE
            | PLUGIN_ARG_STATE_DUMP_TARGET
            | PLUGIN_ARG_STATE_DUMP_PATH
    ) || app_random::is_key(key)
}

#[cfg(test)]
mod tests;

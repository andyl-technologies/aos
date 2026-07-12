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

use thiserror::Error;

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
/// The optional coverage hook switch argument key.
pub const PLUGIN_ARG_COVERAGE: &str = "coverage";
/// The optional single-VM fingerprint sampling switch argument key.
pub const PLUGIN_ARG_FINGERPRINT: &str = "fingerprint";

/// Parsed QEMU plugin launch arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginArgs {
    sim_fd: i32,
    slot: u32,
    inherited_fds: Option<PluginInheritedFds>,
    whitebox: PluginSwitch,
    coverage: PluginSwitch,
    fingerprint: PluginSwitch,
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
        let coverage = parse_optional_switch(&parsed, PLUGIN_ARG_COVERAGE)?;
        let fingerprint = parse_optional_switch(&parsed, PLUGIN_ARG_FINGERPRINT)?;
        let inherited_fds = parse_inherited_fds(&parsed)?;

        Ok(Self {
            sim_fd,
            slot,
            inherited_fds,
            whitebox,
            coverage,
            fingerprint,
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
    /// Only one of the inherited descriptor keys was supplied.
    #[error("plugin inherited descriptors require both `shmemfd` and `wakefd`")]
    IncompleteInheritedDescriptors,
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

fn is_known_key(key: &str) -> bool {
    matches!(
        key,
        PLUGIN_ARG_SIMFD
            | PLUGIN_ARG_SLOT
            | PLUGIN_ARG_SHMEMFD
            | PLUGIN_ARG_WAKEFD
            | PLUGIN_ARG_WHITEBOX
            | PLUGIN_ARG_COVERAGE
            | PLUGIN_ARG_FINGERPRINT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_args_parse_required_simfd_and_slot() {
        let args = PluginArgs::parse("simfd=3,slot=2")
            .unwrap_or_else(|error| panic!("minimal args should parse: {error}"));

        assert_eq!(args.sim_fd(), 3);
        assert_eq!(args.slot(), 2);
        assert_eq!(args.inherited_fds(), None);
        assert_eq!(args.whitebox(), PluginSwitch::Off);
        assert_eq!(args.coverage(), PluginSwitch::Off);
        assert_eq!(args.fingerprint(), PluginSwitch::Off);
        assert_eq!(args.validate_slot_index(3), Ok(()));
    }

    #[test]
    fn plugin_args_parse_optional_fds_and_switches() {
        let args = PluginArgs::parse(
            "simfd=4,slot=1,shmemfd=5,wakefd=6,whitebox=on,coverage=off,fingerprint=on",
        )
        .unwrap_or_else(|error| panic!("complete args should parse: {error}"));

        assert_eq!(args.sim_fd(), 4);
        assert_eq!(args.slot(), 1);
        assert_eq!(
            args.inherited_fds(),
            Some(PluginInheritedFds {
                shmem_fd: 5,
                wake_fd: 6,
            })
        );
        assert!(args.whitebox().is_on());
        assert!(!args.coverage().is_on());
        assert!(args.fingerprint().is_on());
    }

    #[test]
    fn plugin_args_reject_missing_required_keys() {
        assert_eq!(
            PluginArgs::parse("slot=0"),
            Err(PluginArgsParseError::MissingRequiredKey { key: "simfd" })
        );
        assert_eq!(
            PluginArgs::parse("simfd=3"),
            Err(PluginArgsParseError::MissingRequiredKey { key: "slot" })
        );
    }

    #[test]
    fn plugin_args_reject_malformed_unknown_and_duplicate_keys() {
        assert_eq!(
            PluginArgs::parse("simfd=3,slot"),
            Err(PluginArgsParseError::MalformedArgument {
                argument: String::from("slot"),
            })
        );
        assert_eq!(
            PluginArgs::parse("simfd=3,slot=0,mode=on"),
            Err(PluginArgsParseError::UnknownKey {
                key: String::from("mode"),
            })
        );
        assert_eq!(
            PluginArgs::parse("simfd=3,slot=0,slot=1"),
            Err(PluginArgsParseError::DuplicateKey {
                key: String::from("slot"),
            })
        );
    }

    #[test]
    fn plugin_args_reject_bad_fd_slot_and_switch_values() {
        assert_eq!(
            PluginArgs::parse("simfd=-1,slot=0"),
            Err(PluginArgsParseError::InvalidFd {
                key: "simfd",
                value: String::from("-1"),
            })
        );
        assert_eq!(
            PluginArgs::parse("simfd=control,slot=0"),
            Err(PluginArgsParseError::InvalidFd {
                key: "simfd",
                value: String::from("control"),
            })
        );
        assert_eq!(
            PluginArgs::parse("simfd=3,slot=guest"),
            Err(PluginArgsParseError::InvalidSlot {
                key: "slot",
                value: String::from("guest"),
            })
        );
        assert_eq!(
            PluginArgs::parse("simfd=3,slot=0,coverage=true"),
            Err(PluginArgsParseError::InvalidSwitch {
                key: "coverage",
                value: String::from("true"),
            })
        );
    }

    #[test]
    fn plugin_args_reject_partial_inherited_descriptor_pair() {
        assert_eq!(
            PluginArgs::parse("simfd=3,slot=0,shmemfd=4"),
            Err(PluginArgsParseError::IncompleteInheritedDescriptors)
        );
        assert_eq!(
            PluginArgs::parse("simfd=3,slot=0,wakefd=5"),
            Err(PluginArgsParseError::IncompleteInheritedDescriptors)
        );
    }

    #[test]
    fn plugin_args_validate_slot_against_node_count() {
        let args = PluginArgs::parse("simfd=3,slot=2")
            .unwrap_or_else(|error| panic!("args should parse: {error}"));

        assert_eq!(args.validate_slot_index(3), Ok(()));
        assert_eq!(
            args.validate_slot_index(2),
            Err(PluginArgsParseError::SlotOutOfRange {
                slot: 2,
                node_count: 2,
            })
        );
        assert_eq!(
            args.validate_slot_index(0),
            Err(PluginArgsParseError::SlotOutOfRange {
                slot: 2,
                node_count: 0,
            })
        );
    }
}

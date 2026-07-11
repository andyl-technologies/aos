//! Canonical identities for observation control, raw Unix argv, and invocation paths.
//!
//! Every digest in this module uses SHA-256 with explicit domain separation,
//! field labels, big-endian counts and indexes, and length-framed byte strings.
//! Consequently, concatenation, empty-argument, ordering, and path-boundary
//! ambiguities cannot collapse to the same encoded hash input.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::SingleVmFingerprintRunOrdinal;

const MODE_DOMAIN: &str = "crucible.qemu.live-observation-mode.v1";
const CONTROL_DOMAIN: &str = "crucible.qemu.live-observation-control.v1";
const RAW_ARGV_DOMAIN: &str = "crucible.qemu.raw-unix-argv.v2";
const INVOCATION_DOMAIN: &str = "crucible.qemu.live-invocation-identity.v1";
const MODE_FLAGS_VERSION: u16 = 1;

/// Tagged observation purpose for one QEMU launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveObservationMode {
    /// Captures a definition-only preflight before guest execution.
    DefinitionPreflight,
    /// Captures periodic observations through the configured horizon.
    ObservationHorizon {
        /// Periodic fingerprint cadence.
        cadence_icount: u64,
        /// Fixed-run ordinal being observed.
        ordinal: SingleVmFingerprintRunOrdinal,
    },
    /// Captures or refines one exact instruction-count target.
    ExactTarget {
        /// Definition-pinned periodic fingerprint cadence.
        cadence_icount: u64,
        /// Exact aggregate instruction target; zero selects paused genesis.
        target_icount: u64,
        /// Fixed-run ordinal being replayed.
        ordinal: SingleVmFingerprintRunOrdinal,
    },
}

impl LiveObservationMode {
    /// Returns the stable mode tag hashed into identities.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::DefinitionPreflight => "definition-preflight",
            Self::ObservationHorizon { .. } => "observation-horizon",
            Self::ExactTarget { .. } => "exact-target",
        }
    }

    /// Returns the versioned flags implied by this mode.
    #[must_use]
    pub const fn flags(self) -> LiveObservationModeFlags {
        match self {
            Self::DefinitionPreflight => LiveObservationModeFlags {
                version: MODE_FLAGS_VERSION,
                definition_only: true,
                periodic_sampling: false,
                stop_at_target: false,
                exact_target: false,
            },
            Self::ObservationHorizon { .. } => LiveObservationModeFlags {
                version: MODE_FLAGS_VERSION,
                definition_only: false,
                periodic_sampling: true,
                stop_at_target: true,
                exact_target: false,
            },
            Self::ExactTarget {
                target_icount: 0, ..
            } => LiveObservationModeFlags {
                version: MODE_FLAGS_VERSION,
                definition_only: true,
                periodic_sampling: false,
                stop_at_target: false,
                exact_target: true,
            },
            Self::ExactTarget { .. } => LiveObservationModeFlags {
                version: MODE_FLAGS_VERSION,
                definition_only: false,
                periodic_sampling: true,
                stop_at_target: true,
                exact_target: true,
            },
        }
    }

    /// Returns the canonical SHA-256 digest of the tagged mode and flags.
    #[must_use]
    pub fn canonical_digest(self) -> [u8; 32] {
        let flags = self.flags();
        let mut hasher = DomainHasher::new(MODE_DOMAIN);
        hasher.segment("tag", self.tag().as_bytes());
        hasher.segment("flags-version", &flags.version.to_be_bytes());
        hasher.segment("definition-only", bool_byte(flags.definition_only));
        hasher.segment("periodic-sampling", bool_byte(flags.periodic_sampling));
        hasher.segment("stop-at-target", bool_byte(flags.stop_at_target));
        hasher.segment("exact-target", bool_byte(flags.exact_target));
        if let Some(cadence) = self.cadence_icount() {
            hasher.u64("cadence-icount", cadence);
        }
        if let Some(target) = self.explicit_target_icount() {
            hasher.u64("target-icount", target);
        }
        if let Some(ordinal) = self.ordinal() {
            hasher.segment("ordinal", ordinal_bytes(ordinal));
        }
        hasher.finish()
    }

    /// Returns the definition-bound cadence carried by observation and exact modes.
    #[must_use]
    pub const fn cadence_icount(self) -> Option<u64> {
        match self {
            Self::DefinitionPreflight => None,
            Self::ObservationHorizon { cadence_icount, .. }
            | Self::ExactTarget { cadence_icount, .. } => Some(cadence_icount),
        }
    }

    /// Returns an explicit target for exact mode.
    ///
    /// Horizon observation derives its target from the control horizon.
    #[must_use]
    pub const fn explicit_target_icount(self) -> Option<u64> {
        match self {
            Self::ExactTarget { target_icount, .. } => Some(target_icount),
            Self::DefinitionPreflight | Self::ObservationHorizon { .. } => None,
        }
    }

    /// Returns the fixed-run ordinal when this mode executes the guest.
    #[must_use]
    pub const fn ordinal(self) -> Option<SingleVmFingerprintRunOrdinal> {
        match self {
            Self::DefinitionPreflight => None,
            Self::ObservationHorizon { ordinal, .. } | Self::ExactTarget { ordinal, .. } => {
                Some(ordinal)
            }
        }
    }
}

/// Versioned behavior flags derived solely from [`LiveObservationMode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveObservationModeFlags {
    /// Encoding version for this flag set.
    pub version: u16,
    /// Whether the plugin must emit only the preflight definition.
    pub definition_only: bool,
    /// Whether periodic cadence samples are enabled.
    pub periodic_sampling: bool,
    /// Whether QEMU must stop at the control target.
    pub stop_at_target: bool,
    /// Whether the target represents an exact refinement point.
    pub exact_target: bool,
}

/// Fields bound by one observation-control identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveObservationControlFields {
    /// Digest of the immutable base QEMU launch.
    pub base_launch_digest: [u8; 32],
    /// Digest of the config-derived fixed run inputs.
    pub fixed_run_digest: [u8; 32],
    /// Digest of the canonical fingerprint definition, absent during its preflight.
    pub definition_digest: Option<[u8; 32]>,
    /// Maximum run horizon in retired instructions.
    pub horizon_icount: u64,
    /// Stable scenario node name.
    pub node: String,
    /// Fresh attempt number under the run ordinal.
    pub attempt: u32,
    /// Digest of the exact raw process argv bytes, including `argv[0]`.
    pub actual_argv_digest: [u8; 32],
    /// Tagged observation purpose.
    pub mode: LiveObservationMode,
}

/// Validated control-plane identity for one observation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveObservationControl {
    fields: LiveObservationControlFields,
    digest: [u8; 32],
}

impl LiveObservationControl {
    /// Validates and hashes all observation-control fields.
    ///
    /// # Errors
    ///
    /// Returns [`LiveIdentityError`] for zero placeholder digests, invalid
    /// node text, a zero horizon, missing or premature definition identity, or
    /// cadence/target values inconsistent with the selected mode.
    pub fn new(fields: LiveObservationControlFields) -> Result<Self, LiveIdentityError> {
        validate_digest("base_launch_digest", fields.base_launch_digest)?;
        validate_digest("fixed_run_digest", fields.fixed_run_digest)?;
        validate_digest("actual_argv_digest", fields.actual_argv_digest)?;
        validate_text("node", fields.node.as_bytes())?;
        if fields.horizon_icount == 0 {
            return Err(LiveIdentityError::ZeroControlField {
                field: "horizon_icount",
            });
        }
        let (cadence, target, ordinal) = match fields.mode {
            LiveObservationMode::DefinitionPreflight => {
                if fields.definition_digest.is_some() {
                    return Err(LiveIdentityError::DefinitionPresenceMismatch {
                        mode: fields.mode,
                    });
                }
                (None, 0, None)
            }
            LiveObservationMode::ObservationHorizon {
                cadence_icount,
                ordinal,
            } => {
                validate_executing_mode(cadence_icount, fields.horizon_icount)?;
                require_definition_digest(fields.definition_digest, fields.mode)?;
                (Some(cadence_icount), fields.horizon_icount, Some(ordinal))
            }
            LiveObservationMode::ExactTarget {
                cadence_icount,
                target_icount,
                ordinal,
            } => {
                validate_executing_mode(cadence_icount, fields.horizon_icount)?;
                require_definition_digest(fields.definition_digest, fields.mode)?;
                if target_icount > fields.horizon_icount {
                    return Err(LiveIdentityError::InvalidModeTarget {
                        mode: fields.mode,
                        target: target_icount,
                        horizon: fields.horizon_icount,
                    });
                }
                (Some(cadence_icount), target_icount, Some(ordinal))
            }
        };

        let flags = fields.mode.flags();
        let mut hasher = DomainHasher::new(CONTROL_DOMAIN);
        hasher.segment("base-launch-digest", &fields.base_launch_digest);
        hasher.segment("fixed-run-digest", &fields.fixed_run_digest);
        hasher.segment(
            "definition-present",
            bool_byte(fields.definition_digest.is_some()),
        );
        if let Some(definition_digest) = fields.definition_digest {
            hasher.segment("definition-digest", &definition_digest);
        }
        hasher.segment("cadence-present", bool_byte(cadence.is_some()));
        if let Some(cadence) = cadence {
            hasher.u64("cadence-icount", cadence);
        }
        hasher.u64("target-icount", target);
        hasher.u64("horizon-icount", fields.horizon_icount);
        hasher.segment("ordinal-present", bool_byte(ordinal.is_some()));
        if let Some(ordinal) = ordinal {
            hasher.segment("ordinal", ordinal_bytes(ordinal));
        }
        hasher.segment("node", fields.node.as_bytes());
        hasher.segment("attempt", &fields.attempt.to_be_bytes());
        hasher.segment("actual-argv-digest", &fields.actual_argv_digest);
        hasher.segment("mode-tag", fields.mode.tag().as_bytes());
        hasher.segment("mode-flags-version", &flags.version.to_be_bytes());
        hasher.segment("definition-only", bool_byte(flags.definition_only));
        hasher.segment("periodic-sampling", bool_byte(flags.periodic_sampling));
        hasher.segment("stop-at-target", bool_byte(flags.stop_at_target));
        hasher.segment("exact-target", bool_byte(flags.exact_target));
        let digest = hasher.finish();
        Ok(Self { fields, digest })
    }

    /// Returns all validated control fields.
    #[must_use]
    pub fn fields(&self) -> &LiveObservationControlFields {
        &self.fields
    }

    /// Returns the canonical observation-control digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Canonical identity of one raw Unix process argument vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawUnixArgvIdentity {
    argv0: OsString,
    argv: Vec<OsString>,
    argc: u64,
    raw_byte_count: u64,
    digest: [u8; 32],
}

impl RawUnixArgvIdentity {
    /// Hashes raw Unix process argument bytes without Unicode conversion.
    ///
    /// Empty `argv[0]` and tail arguments are valid and remain distinct from
    /// omitted arguments. This identity describes the argument vector visible
    /// to the process; it does not claim that `argv[0]` is the `execve` path.
    ///
    /// # Errors
    ///
    /// Returns [`LiveIdentityError`] when any element contains NUL, the raw
    /// byte count overflows, or the argument count/index cannot fit the
    /// canonical `u64`.
    pub fn new(argv0: &OsStr, argv: &[OsString]) -> Result<Self, LiveIdentityError> {
        let argv0_bytes = argv0.as_bytes();
        validate_no_nul("argv", Some(0), argv0_bytes)?;
        let argc_tail = u64::try_from(argv.len())
            .map_err(|_| LiveIdentityError::CountOverflow { field: "argc" })?;
        let argc = argc_tail
            .checked_add(1)
            .ok_or(LiveIdentityError::CountOverflow { field: "argc" })?;
        let mut raw_byte_count = u64::try_from(argv0_bytes.len())
            .map_err(|_| LiveIdentityError::RawArgvByteCountOverflow)?;
        let mut hasher = DomainHasher::new(RAW_ARGV_DOMAIN);
        hasher.u64("argc", argc);
        hasher.u64("argv-index", 0);
        hasher.segment("argv-value", argv0_bytes);
        for (index, argument) in argv.iter().enumerate() {
            let index = u64::try_from(index).map_err(|_| LiveIdentityError::CountOverflow {
                field: "argv-index",
            })?;
            let index = index
                .checked_add(1)
                .ok_or(LiveIdentityError::CountOverflow {
                    field: "argv-index",
                })?;
            let bytes = argument.as_bytes();
            validate_no_nul("argv", Some(index), bytes)?;
            let byte_count = u64::try_from(bytes.len())
                .map_err(|_| LiveIdentityError::RawArgvByteCountOverflow)?;
            raw_byte_count = raw_byte_count
                .checked_add(byte_count)
                .ok_or(LiveIdentityError::RawArgvByteCountOverflow)?;
            hasher.u64("argv-index", index);
            hasher.segment("argv-value", bytes);
        }
        Ok(Self {
            argv0: argv0.to_owned(),
            argv: argv.to_vec(),
            argc,
            raw_byte_count,
            digest: hasher.finish(),
        })
    }

    /// Returns the exact raw `argv[0]` value.
    #[must_use]
    pub fn argv0(&self) -> &OsStr {
        &self.argv0
    }

    /// Returns the exact ordered argv tail, including empty arguments.
    #[must_use]
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }

    /// Returns the actual process `argc`, including forced `argv[0]`.
    #[must_use]
    pub const fn argc(&self) -> u64 {
        self.argc
    }

    /// Returns the sum of raw bytes across all actual `argv[i]` values.
    #[must_use]
    pub const fn raw_byte_count(&self) -> u64 {
        self.raw_byte_count
    }

    /// Returns the canonical raw argv digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Absolute host paths bound by one process invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveInvocationPaths {
    /// Process working directory.
    pub cwd: PathBuf,
    /// QMP Unix socket.
    pub qmp_socket: PathBuf,
    /// Captured standard output.
    pub stdout: PathBuf,
    /// Captured standard error.
    pub stderr: PathBuf,
}

/// Canonical identity of argv and host-visible invocation boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveInvocationIdentity {
    argv_digest: [u8; 32],
    paths: LiveInvocationPaths,
    digest: [u8; 32],
}

impl LiveInvocationIdentity {
    /// Binds raw argv, absolute paths, null stdin, and an empty environment.
    ///
    /// # Errors
    ///
    /// Returns [`LiveIdentityError`] when a path is relative, contains NUL, or
    /// any two QMP/stdout/stderr endpoints alias one another.
    pub fn new(
        argv: &RawUnixArgvIdentity,
        paths: LiveInvocationPaths,
    ) -> Result<Self, LiveIdentityError> {
        for (field, path) in [
            ("cwd", &paths.cwd),
            ("qmp_socket", &paths.qmp_socket),
            ("stdout", &paths.stdout),
            ("stderr", &paths.stderr),
        ] {
            if !path.is_absolute() {
                return Err(LiveIdentityError::RelativeInvocationPath {
                    field,
                    path: path.to_owned(),
                });
            }
            validate_no_nul(field, None, path.as_os_str().as_bytes())?;
        }
        if paths.qmp_socket == paths.stdout
            || paths.qmp_socket == paths.stderr
            || paths.stdout == paths.stderr
        {
            return Err(LiveIdentityError::AliasedInvocationEndpoints);
        }
        let digest = hash_segments(
            INVOCATION_DOMAIN,
            &[
                ("argv-digest", &argv.digest),
                ("cwd", paths.cwd.as_os_str().as_bytes()),
                ("qmp-socket", paths.qmp_socket.as_os_str().as_bytes()),
                ("stdout", paths.stdout.as_os_str().as_bytes()),
                ("stderr", paths.stderr.as_os_str().as_bytes()),
                ("stdin-null", bool_byte(true)),
                ("environment-cleared", bool_byte(true)),
                ("stdout-mode", b"create-new-write"),
                ("stderr-mode", b"create-new-write"),
            ],
        );
        Ok(Self {
            argv_digest: argv.digest,
            paths,
            digest,
        })
    }

    /// Returns the bound argv digest.
    #[must_use]
    pub const fn argv_digest(&self) -> [u8; 32] {
        self.argv_digest
    }

    /// Returns all absolute invocation paths.
    #[must_use]
    pub fn paths(&self) -> &LiveInvocationPaths {
        &self.paths
    }

    /// Returns true because stdin is always bound to the null device.
    #[must_use]
    pub const fn stdin_is_null(&self) -> bool {
        true
    }

    /// Returns true because the inherited process environment is always cleared.
    #[must_use]
    pub const fn environment_is_cleared(&self) -> bool {
        true
    }

    /// Returns the canonical invocation digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Invalid canonical live identity input.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LiveIdentityError {
    /// A digest used the all-zero sentinel.
    #[error("{field} must not use the all-zero SHA-256 sentinel")]
    ZeroDigest {
        /// Rejected field.
        field: &'static str,
    },
    /// Required numeric control field was zero.
    #[error("{field} must be non-zero")]
    ZeroControlField {
        /// Rejected field.
        field: &'static str,
    },
    /// Cadence exceeded the run horizon.
    #[error("cadence icount must not exceed horizon icount")]
    CadenceBeyondHorizon,
    /// Target did not match mode semantics.
    #[error("target {target} is invalid for {mode:?} with horizon {horizon}")]
    InvalidModeTarget {
        /// Selected mode.
        mode: LiveObservationMode,
        /// Rejected target.
        target: u64,
        /// Configured horizon.
        horizon: u64,
    },
    /// Definition identity presence did not match preflight/execution semantics.
    #[error("definition digest presence is invalid for {mode:?}")]
    DefinitionPresenceMismatch {
        /// Selected observation mode.
        mode: LiveObservationMode,
    },
    /// Text field was empty or contained a forbidden byte.
    #[error("{field} must be non-empty and contain no NUL or newline")]
    InvalidText {
        /// Rejected field.
        field: &'static str,
    },
    /// Raw Unix element contained NUL.
    #[error("{field} element {index:?} contains NUL")]
    InteriorNul {
        /// Rejected field.
        field: &'static str,
        /// Argument index, when applicable.
        index: Option<u64>,
    },
    /// Collection count could not fit the canonical integer width.
    #[error("{field} does not fit canonical u64 encoding")]
    CountOverflow {
        /// Rejected field.
        field: &'static str,
    },
    /// Raw process argument bytes exceeded canonical `u64` accounting.
    #[error("raw Unix argv byte count exceeds canonical u64 accounting")]
    RawArgvByteCountOverflow,
    /// Invocation path was relative.
    #[error("{field} invocation path must be absolute: {path}", path = path.display())]
    RelativeInvocationPath {
        /// Rejected field.
        field: &'static str,
        /// Relative path.
        path: PathBuf,
    },
    /// QMP and log endpoints aliased.
    #[error("QMP, stdout, and stderr invocation paths must be distinct")]
    AliasedInvocationEndpoints,
}

struct DomainHasher {
    hasher: Sha256,
}

impl DomainHasher {
    fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hash_framed(&mut hasher, domain.as_bytes());
        Self { hasher }
    }

    fn segment(&mut self, label: &str, value: &[u8]) {
        hash_framed(&mut self.hasher, label.as_bytes());
        hash_framed(&mut self.hasher, value);
    }

    fn u64(&mut self, label: &str, value: u64) {
        self.segment(label, &value.to_be_bytes());
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

fn hash_segments(domain: &str, segments: &[(&str, &[u8])]) -> [u8; 32] {
    let mut hasher = DomainHasher::new(domain);
    hasher.u64("segment-count", segments.len() as u64);
    for (label, value) in segments {
        hasher.segment(label, value);
    }
    hasher.finish()
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

const fn bool_byte(value: bool) -> &'static [u8] {
    if value { &[1] } else { &[0] }
}

fn validate_digest(field: &'static str, digest: [u8; 32]) -> Result<(), LiveIdentityError> {
    if digest == [0; 32] {
        Err(LiveIdentityError::ZeroDigest { field })
    } else {
        Ok(())
    }
}

fn require_definition_digest(
    digest: Option<[u8; 32]>,
    mode: LiveObservationMode,
) -> Result<(), LiveIdentityError> {
    match digest {
        Some(digest) => validate_digest("definition_digest", digest),
        None => Err(LiveIdentityError::DefinitionPresenceMismatch { mode }),
    }
}

fn validate_executing_mode(cadence: u64, horizon: u64) -> Result<(), LiveIdentityError> {
    if cadence == 0 {
        return Err(LiveIdentityError::ZeroControlField {
            field: "cadence_icount",
        });
    }
    if cadence > horizon {
        return Err(LiveIdentityError::CadenceBeyondHorizon);
    }
    Ok(())
}

const fn ordinal_bytes(ordinal: SingleVmFingerprintRunOrdinal) -> &'static [u8] {
    match ordinal {
        SingleVmFingerprintRunOrdinal::First => b"first",
        SingleVmFingerprintRunOrdinal::Second => b"second",
    }
}

fn validate_text(field: &'static str, bytes: &[u8]) -> Result<(), LiveIdentityError> {
    if bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
        Err(LiveIdentityError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_no_nul(
    field: &'static str,
    index: Option<u64>,
    bytes: &[u8],
) -> Result<(), LiveIdentityError> {
    if bytes.contains(&0) {
        Err(LiveIdentityError::InteriorNul { field, index })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    fn exact_fields() -> LiveObservationControlFields {
        LiveObservationControlFields {
            base_launch_digest: [1; 32],
            fixed_run_digest: [2; 32],
            definition_digest: Some([3; 32]),
            horizon_icount: 1_000,
            node: "node-0".to_owned(),
            attempt: 1,
            actual_argv_digest: [4; 32],
            mode: LiveObservationMode::ExactTarget {
                cadence_icount: 100,
                target_icount: 500,
                ordinal: SingleVmFingerprintRunOrdinal::First,
            },
        }
    }

    fn control(fields: LiveObservationControlFields) -> Result<[u8; 32], LiveIdentityError> {
        LiveObservationControl::new(fields).map(|control| control.digest())
    }

    #[test]
    fn every_control_field_changes_identity() -> Result<(), Box<dyn Error>> {
        let baseline = control(exact_fields())?;
        let mutations = [
            LiveObservationControlFields {
                base_launch_digest: [3; 32],
                ..exact_fields()
            },
            LiveObservationControlFields {
                fixed_run_digest: [3; 32],
                ..exact_fields()
            },
            LiveObservationControlFields {
                definition_digest: Some([5; 32]),
                ..exact_fields()
            },
            LiveObservationControlFields {
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: 101,
                    target_icount: 500,
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                ..exact_fields()
            },
            LiveObservationControlFields {
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: 100,
                    target_icount: 501,
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                ..exact_fields()
            },
            LiveObservationControlFields {
                horizon_icount: 1_001,
                ..exact_fields()
            },
            LiveObservationControlFields {
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: 100,
                    target_icount: 500,
                    ordinal: SingleVmFingerprintRunOrdinal::Second,
                },
                ..exact_fields()
            },
            LiveObservationControlFields {
                node: "node-1".to_owned(),
                ..exact_fields()
            },
            LiveObservationControlFields {
                attempt: 2,
                ..exact_fields()
            },
            LiveObservationControlFields {
                actual_argv_digest: [6; 32],
                ..exact_fields()
            },
            LiveObservationControlFields {
                mode: LiveObservationMode::ObservationHorizon {
                    cadence_icount: 100,
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                ..exact_fields()
            },
        ];
        for mutation in mutations {
            assert_ne!(baseline, control(mutation)?);
        }
        Ok(())
    }

    #[test]
    fn mode_target_rules_are_typed() {
        assert!(matches!(
            LiveObservationControl::new(LiveObservationControlFields {
                mode: LiveObservationMode::DefinitionPreflight,
                ..exact_fields()
            }),
            Err(LiveIdentityError::DefinitionPresenceMismatch { .. })
        ));
        assert!(matches!(
            LiveObservationControl::new(LiveObservationControlFields {
                mode: LiveObservationMode::ExactTarget {
                    cadence_icount: 100,
                    target_icount: 1_001,
                    ordinal: SingleVmFingerprintRunOrdinal::First,
                },
                ..exact_fields()
            }),
            Err(LiveIdentityError::InvalidModeTarget { .. })
        ));
        assert!(
            LiveObservationControl::new(LiveObservationControlFields {
                definition_digest: None,
                mode: LiveObservationMode::DefinitionPreflight,
                ..exact_fields()
            })
            .is_ok()
        );
        let genesis = LiveObservationMode::ExactTarget {
            cadence_icount: 100,
            target_icount: 0,
            ordinal: SingleVmFingerprintRunOrdinal::Second,
        };
        assert!(
            LiveObservationControl::new(LiveObservationControlFields {
                mode: genesis,
                ..exact_fields()
            })
            .is_ok()
        );
        assert_eq!(
            genesis.flags(),
            LiveObservationModeFlags {
                version: MODE_FLAGS_VERSION,
                definition_only: true,
                periodic_sampling: false,
                stop_at_target: false,
                exact_target: true,
            }
        );
    }

    #[test]
    fn argv_length_framing_defeats_concatenation_and_empty_ambiguity() -> Result<(), Box<dyn Error>>
    {
        let argv0 = OsStr::new("/nix/store/qemu");
        let split_left =
            RawUnixArgvIdentity::new(argv0, &[OsString::from("ab"), OsString::from("c")])?;
        let split_right =
            RawUnixArgvIdentity::new(argv0, &[OsString::from("a"), OsString::from("bc")])?;
        let with_empty = RawUnixArgvIdentity::new(
            argv0,
            &[OsString::from("ab"), OsString::new(), OsString::from("c")],
        )?;
        let reordered =
            RawUnixArgvIdentity::new(argv0, &[OsString::from("c"), OsString::from("ab")])?;
        assert_ne!(split_left.digest(), split_right.digest());
        assert_ne!(split_left.digest(), with_empty.digest());
        assert_ne!(split_left.digest(), reordered.digest());
        assert_eq!(with_empty.argv().len(), 3);
        assert!(with_empty.argv()[1].is_empty());
        Ok(())
    }

    #[test]
    fn raw_non_utf8_and_argv0_bytes_are_bound() -> Result<(), Box<dyn Error>> {
        let non_utf8 = OsString::from_vec(vec![0xff]);
        let first = RawUnixArgvIdentity::new(OsStr::new("/qemu-a"), &[non_utf8.clone()])?;
        let second = RawUnixArgvIdentity::new(OsStr::new("/qemu-b"), &[non_utf8])?;
        assert_ne!(first.digest(), second.digest());
        assert_eq!(first.argv0(), OsStr::new("/qemu-a"));
        assert_eq!(first.argv()[0].as_bytes(), &[0xff]);
        Ok(())
    }

    #[test]
    fn raw_argv_v2_matches_cross_language_known_answer() -> Result<(), Box<dyn Error>> {
        let argv0 = OsString::from_vec(vec![b'q', b'e', b'm', b'u', b'-', 0xff]);
        let identity = RawUnixArgvIdentity::new(
            &argv0,
            &[
                OsString::from("-S"),
                OsString::new(),
                OsString::from("ab"),
                OsString::from("c"),
            ],
        )?;
        assert_eq!(identity.argc(), 5);
        assert_eq!(identity.raw_byte_count(), 11);
        assert_eq!(
            identity.digest(),
            [
                0x6e, 0x59, 0x13, 0xd0, 0x07, 0xf3, 0x62, 0x00, 0x25, 0x52, 0xd3, 0xda, 0xb7, 0xa3,
                0x85, 0x15, 0xc4, 0xd7, 0x3f, 0x8f, 0xbc, 0xd6, 0x05, 0x0a, 0xed, 0xec, 0xae, 0x8a,
                0xd9, 0xb5, 0xfe, 0xa2,
            ]
        );
        Ok(())
    }

    fn paths() -> LiveInvocationPaths {
        LiveInvocationPaths {
            cwd: "/tmp/run".into(),
            qmp_socket: "/tmp/run/qmp.sock".into(),
            stdout: "/tmp/run/stdout.log".into(),
            stderr: "/tmp/run/stderr.log".into(),
        }
    }

    #[test]
    fn every_invocation_boundary_changes_identity() -> Result<(), Box<dyn Error>> {
        let argv = RawUnixArgvIdentity::new(OsStr::new("/qemu"), &["-S".into()])?;
        let baseline = LiveInvocationIdentity::new(&argv, paths())?.digest();
        let argv_changed = RawUnixArgvIdentity::new(OsStr::new("/qemu"), &["-s".into()])?;
        assert_ne!(
            baseline,
            LiveInvocationIdentity::new(&argv_changed, paths())?.digest()
        );
        for changed in [
            LiveInvocationPaths {
                cwd: "/tmp/run-2".into(),
                ..paths()
            },
            LiveInvocationPaths {
                qmp_socket: "/tmp/run/qmp-2.sock".into(),
                ..paths()
            },
            LiveInvocationPaths {
                stdout: "/tmp/run/stdout-2.log".into(),
                ..paths()
            },
            LiveInvocationPaths {
                stderr: "/tmp/run/stderr-2.log".into(),
                ..paths()
            },
        ] {
            assert_ne!(
                baseline,
                LiveInvocationIdentity::new(&argv, changed)?.digest()
            );
        }
        let identity = LiveInvocationIdentity::new(&argv, paths())?;
        assert!(identity.stdin_is_null());
        assert!(identity.environment_is_cleared());
        Ok(())
    }

    #[test]
    fn invalid_raw_and_path_inputs_fail_closed() -> Result<(), Box<dyn Error>> {
        let empty_argv0 = RawUnixArgvIdentity::new(OsStr::new(""), &[])?;
        assert_eq!(empty_argv0.argc(), 1);
        assert_eq!(empty_argv0.raw_byte_count(), 0);
        let argv = RawUnixArgvIdentity::new(OsStr::new("/qemu"), &[])?;
        assert!(matches!(
            LiveInvocationIdentity::new(
                &argv,
                LiveInvocationPaths {
                    cwd: "relative".into(),
                    ..paths()
                }
            ),
            Err(LiveIdentityError::RelativeInvocationPath { .. })
        ));
        Ok(())
    }
}

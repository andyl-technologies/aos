//! The fixed E0 helper's bounded 120-byte inspection plan encoder.
//!
//! This is mechanical DATA, not a Git packet parser or an admission record.
//! The only emitted verbs inspect an existing directory without publishing it.
//!
//! ```text
//! 0..8 magic AOSGHP01; 8 verb; 9 object format; 10..16 reserved zero
//! 16..56 five big-endian u64 limits: input, output, expanded, objects, seconds
//! 56..88 Git kernel SHA256 fs-verity; 88..120 helper kernel SHA256 fs-verity
//! ```

use std::time::Duration;

use crate::git::GitObjectFormatV1;

pub(super) const PLAN_BYTES: usize = 120;
pub(super) const MAXIMUM_STREAM_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_STDERR_BYTES: usize = 64 * 1024;
const MAXIMUM_OBJECTS: u64 = 262_144;

/// Selects one of the helper's four read-only builtins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::git) enum GitHelperInspectionV1 {
    /// Checks connectivity and object integrity without repairing the ODB.
    Fsck = 3,
    /// Enumerates physical objects through the fixed batch-check builtin.
    Enumerate = 4,
    /// Lists references using the helper's literal format.
    References = 5,
    /// Reports ancestry through the canonical two-OID E0 input grammar.
    IsAncestor = 10,
}

/// Carries finite mechanical budgets, never a hard aggregate ODB reservation.
#[derive(Clone, Copy, Debug)]
pub(in crate::git) struct GitHelperLimitsV1 {
    /// Caps the exact sealed stdin bytes before dispatch.
    pub maximum_input_bytes: u64,
    /// Caps retained standard output independently of standard error.
    pub maximum_output_bytes: usize,
    /// Caps retained standard error, including the original E0 denial record.
    pub maximum_stderr_bytes: usize,
    /// Selects E0's per-file RLIMIT_FSIZE, not aggregate expanded ODB usage.
    pub maximum_expanded_file_bytes: u64,
    /// Carries E0's finite object budget without claiming graph completeness.
    pub maximum_objects: u64,
    /// Selects an integral 1..300-second supervisor/CPU-limit budget.
    pub timeout: Duration,
}

/// Reports fixed-plan admission without exposing command bytes.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(in crate::git) enum GitHelperPlanErrorV1 {
    #[error("Git helper mechanical limit is invalid")]
    Limit,
    #[error("Git helper inspection input is invalid")]
    Input,
    #[error("Git helper kernel measurement is invalid")]
    Measurement,
}

/// Encodes only the existing E0 plan after bounded mechanical admission.
///
/// # Errors
/// Rejects invalid finite limits, unexpected stdin or zero kernel measurements.
pub(super) fn encode(
    verb: GitHelperInspectionV1,
    format: GitObjectFormatV1,
    limits: GitHelperLimitsV1,
    input_bytes: usize,
    git_verity: [u8; 32],
    helper_verity: [u8; 32],
) -> Result<[u8; PLAN_BYTES], GitHelperPlanErrorV1> {
    let input_bytes = u64::try_from(input_bytes).map_err(|_| GitHelperPlanErrorV1::Limit)?;
    let output_bytes = u64::try_from(limits.maximum_output_bytes)
        .map_err(|_| GitHelperPlanErrorV1::Limit)?;
    let seconds = limits.timeout.as_secs();

    if limits.maximum_input_bytes > MAXIMUM_STREAM_BYTES
        || input_bytes > limits.maximum_input_bytes
        || output_bytes == 0
        || output_bytes > MAXIMUM_STREAM_BYTES
        || limits.maximum_stderr_bytes == 0
        || limits.maximum_stderr_bytes > MAXIMUM_STDERR_BYTES
        || limits.maximum_expanded_file_bytes == 0
        || limits.maximum_expanded_file_bytes == u64::MAX
        || limits.maximum_objects == 0
        || limits.maximum_objects > MAXIMUM_OBJECTS
        || !(1..=300).contains(&seconds)
        || limits.timeout.subsec_nanos() != 0
    {
        return Err(GitHelperPlanErrorV1::Limit);
    }

    // E0 owns the canonical two-OID parser for IsAncestor; no second parser is
    // introduced here. All other inspection verbs have literal empty stdin.
    if verb != GitHelperInspectionV1::IsAncestor && input_bytes != 0 {
        return Err(GitHelperPlanErrorV1::Input);
    }
    if git_verity == [0; 32] || helper_verity == [0; 32] {
        return Err(GitHelperPlanErrorV1::Measurement);
    }

    let mut bytes = [0; PLAN_BYTES];
    bytes[..8].copy_from_slice(b"AOSGHP01");
    bytes[8] = verb as u8;
    bytes[9] = format as u8;

    for (offset, value) in [
        (16, input_bytes),
        (24, output_bytes),
        (32, limits.maximum_expanded_file_bytes),
        (40, limits.maximum_objects),
        (48, seconds),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes[56..88].copy_from_slice(&git_verity);
    bytes[88..120].copy_from_slice(&helper_verity);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> GitHelperLimitsV1 {
        GitHelperLimitsV1 {
            maximum_input_bytes: 1024,
            maximum_output_bytes: 4096,
            maximum_stderr_bytes: 1024,
            maximum_expanded_file_bytes: 8192,
            maximum_objects: 16,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn golden_plan_preserves_e0_offsets_and_digest_domains() {
        let bytes = encode(
            GitHelperInspectionV1::IsAncestor,
            GitObjectFormatV1::Sha256,
            limits(),
            130,
            [0x31; 32],
            [0x72; 32],
        )
        .unwrap();

        assert_eq!(&bytes[..8], b"AOSGHP01");
        assert_eq!(&bytes[8..16], &[10, 2, 0, 0, 0, 0, 0, 0]);
        for (offset, value) in [
            (16, 130_u64),
            (24, 4096),
            (32, 8192),
            (40, 16),
            (48, 5),
        ] {
            assert_eq!(&bytes[offset..offset + 8], &value.to_be_bytes());
        }
        assert_eq!(&bytes[56..88], &[0x31; 32]);
        assert_eq!(&bytes[88..120], &[0x72; 32]);
    }

    #[test]
    fn only_four_inspection_verbs_are_emitted() {
        for (verb, code) in [
            (GitHelperInspectionV1::Fsck, 3),
            (GitHelperInspectionV1::Enumerate, 4),
            (GitHelperInspectionV1::References, 5),
            (GitHelperInspectionV1::IsAncestor, 10),
        ] {
            let bytes = encode(
                verb,
                GitObjectFormatV1::Sha1,
                limits(),
                0,
                [1; 32],
                [2; 32],
            )
            .unwrap();

            assert_eq!(bytes[8], code);
            assert_eq!(bytes[9], 1);
        }
    }

    #[test]
    fn invalid_limits_never_round_or_expand_the_budget() {
        for timeout in [
            Duration::ZERO,
            Duration::from_millis(1500),
            Duration::from_secs(301),
        ] {
            let mut selected = limits();
            selected.timeout = timeout;

            let encoded = encode(
                GitHelperInspectionV1::Fsck,
                GitObjectFormatV1::Sha1,
                selected,
                0,
                [1; 32],
                [2; 32],
            );

            assert!(encoded.is_err());
        }

        let mut selected = limits();
        selected.maximum_expanded_file_bytes = u64::MAX;
        let encoded = encode(
            GitHelperInspectionV1::Fsck,
            GitObjectFormatV1::Sha1,
            selected,
            0,
            [1; 32],
            [2; 32],
        );

        assert!(encoded.is_err());
    }

    #[test]
    fn stdin_and_kernel_measurements_are_not_inferred() {
        for (verb, input_bytes, git_verity) in [
            (GitHelperInspectionV1::References, 1, [1; 32]),
            (GitHelperInspectionV1::Fsck, 0, [0; 32]),
            (GitHelperInspectionV1::IsAncestor, 1025, [1; 32]),
        ] {
            let encoded = encode(
                verb,
                GitObjectFormatV1::Sha1,
                limits(),
                input_bytes,
                git_verity,
                [2; 32],
            );

            assert!(encoded.is_err());
        }
    }

    #[test]
    fn finite_boundary_limits_remain_data() {
        for seconds in [1, 300] {
            let selected = GitHelperLimitsV1 {
                maximum_input_bytes: MAXIMUM_STREAM_BYTES,
                maximum_output_bytes: MAXIMUM_STREAM_BYTES as usize,
                maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
                maximum_expanded_file_bytes: u64::MAX - 1,
                maximum_objects: MAXIMUM_OBJECTS,
                timeout: Duration::from_secs(seconds),
            };

            let encoded = encode(
                GitHelperInspectionV1::Fsck,
                GitObjectFormatV1::Sha1,
                selected,
                0,
                [1; 32],
                [2; 32],
            );

            assert!(encoded.is_ok());
        }
    }
}

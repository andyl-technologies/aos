//! Canonical `AOSMMSTA1` policy and `AOSMMCAP1` capture envelopes.
//!
//! Both formats use a fixed binary envelope around canonical serde JSON:
//!
//! ```text
//! magic[9] | version:u16be | flags:u16be=0 | json-length:u32be |
//! canonical-json[json-length] | sha256[32]
//! ```

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{
    ExpectedStartupDescriptorV1, MAXIMUM_STARTUP_ABSENCE_SUBJECTS_V1,
    MAXIMUM_STARTUP_CAPTURE_BYTES_V1, MAXIMUM_STARTUP_CAPTURE_HISTORY_BYTES_V1,
    MAXIMUM_STARTUP_CAPTURE_HISTORY_RECORDS_V1, MAXIMUM_STARTUP_DESCRIPTOR_NUMBER_V1,
    MAXIMUM_STARTUP_DESCRIPTORS_V1, MAXIMUM_STARTUP_LOCATOR_BYTES_V1,
    MAXIMUM_STARTUP_NAME_BYTES_V1, MAXIMUM_STARTUP_NAMES_BYTES_V1, MAXIMUM_STARTUP_POLICY_BYTES_V1,
    MountManagerStartupCaptureV1, MountManagerStartupPolicyV1, StartupActivationLabelV1,
    StartupDescriptorObservationV1, StartupDescriptorPresenceV1, StartupDescriptorRoleV1,
    StartupExecutableIdentityV1, StartupSourceSubjectV1,
};

const POLICY_MAGIC: &[u8; 9] = b"AOSMMSTA1";
const CAPTURE_MAGIC: &[u8; 9] = b"AOSMMCAP1";
const FORMAT_VERSION: u16 = 1;
const ENVELOPE_PREFIX_BYTES: usize = 9 + 2 + 2 + 4;
const DIGEST_BYTES: usize = 32;
const POLICY_KEY: &[u8] = b"aos.mount-manager-startup.policy.v1\0";
const POLICY_HISTORY_KEY_PREFIX: &[u8] = b"aos.mount-manager-startup.policy-history.v1\0";
const CAPTURE_KEY_PREFIX: &[u8] = b"aos.mount-manager-startup.capture.v1\0";
const LINUX_AF_UNIX: u32 = 1;
const LINUX_SOCK_SEQPACKET: u32 = 5;
const LINUX_O_PATH: u32 = 0o10000000;
const LINUX_O_ACCMODE: u32 = 0o3;

/// Reports malformed or noncanonical startup policy and capture records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountManagerStartupFormatError {
    /// A key does not use the exact namespace-45 key form.
    #[error("invalid Mount-manager startup record key")]
    InvalidKey,
    /// An envelope is empty, truncated, or exceeds its fixed bound.
    #[error("invalid Mount-manager startup record size")]
    InvalidSize,
    /// A record violates its closed canonical schema or self-digest.
    #[error("invalid Mount-manager startup record")]
    InvalidRecord,
}

/// Returns the singleton policy-head key.
#[must_use]
pub fn mount_manager_startup_policy_key_v1() -> Vec<u8> {
    POLICY_KEY.to_vec()
}

/// Returns one immutable historical policy key.
///
/// # Errors
///
/// Returns an error for generation zero.
pub fn mount_manager_startup_policy_history_key_v1(
    generation: u64,
) -> Result<Vec<u8>, MountManagerStartupFormatError> {
    if generation == 0 {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }
    let mut key = Vec::with_capacity(POLICY_HISTORY_KEY_PREFIX.len() + 8);
    key.extend_from_slice(POLICY_HISTORY_KEY_PREFIX);
    key.extend_from_slice(&generation.to_be_bytes());
    Ok(key)
}

/// Reports whether a key has the exact immutable policy-history shape.
#[must_use]
pub fn is_mount_manager_startup_policy_history_key_v1(key: &[u8]) -> bool {
    key.len() == POLICY_HISTORY_KEY_PREFIX.len() + 8
        && key.starts_with(POLICY_HISTORY_KEY_PREFIX)
        && key[POLICY_HISTORY_KEY_PREFIX.len()..] != [0; 8]
}

/// Reports whether a key has the exact immutable capture-row shape.
#[must_use]
pub fn is_mount_manager_startup_capture_key_v1(key: &[u8]) -> bool {
    key.len() == CAPTURE_KEY_PREFIX.len() + 8
        && key.starts_with(CAPTURE_KEY_PREFIX)
        && key[CAPTURE_KEY_PREFIX.len()..] != [0; 8]
}

/// Validates the exact singleton policy-head key.
///
/// # Errors
///
/// Returns [`MountManagerStartupFormatError::InvalidKey`] for any other key.
pub fn validate_mount_manager_startup_policy_key_v1(
    key: &[u8],
) -> Result<(), MountManagerStartupFormatError> {
    if key != POLICY_KEY {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }
    Ok(())
}

/// Returns one immutable capture-row key.
///
/// # Errors
///
/// Returns [`MountManagerStartupFormatError::InvalidKey`] for sequence zero.
pub fn mount_manager_startup_capture_key_v1(
    sequence: u64,
) -> Result<Vec<u8>, MountManagerStartupFormatError> {
    if sequence == 0 {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }
    let mut key = Vec::with_capacity(CAPTURE_KEY_PREFIX.len() + 8);
    key.extend_from_slice(CAPTURE_KEY_PREFIX);
    key.extend_from_slice(&sequence.to_be_bytes());
    Ok(key)
}

/// Decodes an exact immutable capture-row key.
///
/// # Errors
///
/// Returns [`MountManagerStartupFormatError::InvalidKey`] for any other key.
pub fn decode_mount_manager_startup_capture_key_v1(
    key: &[u8],
) -> Result<u64, MountManagerStartupFormatError> {
    if key.len() != CAPTURE_KEY_PREFIX.len() + 8 || !key.starts_with(CAPTURE_KEY_PREFIX) {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }
    let sequence = u64::from_be_bytes(
        key[CAPTURE_KEY_PREFIX.len()..]
            .try_into()
            .map_err(|_| MountManagerStartupFormatError::InvalidKey)?,
    );
    if sequence == 0 {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }
    Ok(sequence)
}

/// Seals a policy with its canonical self-digest.
///
/// # Errors
///
/// Returns an error when the policy violates a closed field invariant or its
/// canonical representation exceeds the fixed policy bound.
pub fn seal_mount_manager_startup_policy_v1(
    mut policy: MountManagerStartupPolicyV1,
) -> Result<MountManagerStartupPolicyV1, MountManagerStartupFormatError> {
    policy.record_digest = [0; 32];
    validate_policy(&policy, false)?;
    let (_, digest) = encode_envelope(POLICY_MAGIC, &policy, MAXIMUM_STARTUP_POLICY_BYTES_V1)?;
    policy.record_digest = digest;
    Ok(policy)
}

/// Encodes one sealed canonical policy record.
///
/// # Errors
///
/// Returns an error for an invalid, unsealed, or oversized policy.
pub fn encode_mount_manager_startup_policy_v1(
    policy: &MountManagerStartupPolicyV1,
) -> Result<Vec<u8>, MountManagerStartupFormatError> {
    validate_policy(policy, true)?;
    let (bytes, digest) = encode_envelope(POLICY_MAGIC, policy, MAXIMUM_STARTUP_POLICY_BYTES_V1)?;
    if digest != policy.record_digest {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(bytes)
}

/// Decodes and canonical-reencodes one policy record.
///
/// # Errors
///
/// Returns an error for a malformed, unsupported, noncanonical, oversized, or
/// incorrectly digested record.
pub fn decode_mount_manager_startup_policy_v1(
    bytes: &[u8],
) -> Result<MountManagerStartupPolicyV1, MountManagerStartupFormatError> {
    let (payload, digest) = decode_envelope(POLICY_MAGIC, bytes, MAXIMUM_STARTUP_POLICY_BYTES_V1)?;
    let mut policy: MountManagerStartupPolicyV1 = serde_json::from_slice(payload)
        .map_err(|_| MountManagerStartupFormatError::InvalidRecord)?;
    policy.record_digest = digest;
    validate_policy(&policy, true)?;
    if encode_mount_manager_startup_policy_v1(&policy)? != bytes {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(policy)
}

/// Seals all derived commitments and the canonical capture self-digest.
///
/// # Errors
///
/// Returns an error if any list or field violates its closed invariant or the
/// encoded record exceeds the policy-independent hard capture bound.
pub fn seal_mount_manager_startup_capture_v1(
    mut capture: MountManagerStartupCaptureV1,
) -> Result<MountManagerStartupCaptureV1, MountManagerStartupFormatError> {
    capture.descriptor_table.sort_by_key(|entry| entry.number);
    capture.activation_labels.sort_by_key(|entry| entry.number);
    capture.expected_descriptors.sort();
    capture.source_subjects.sort();

    for observation in &mut capture.descriptor_table {
        observation.physical_commitment = startup_descriptor_physical_commitment_v1(observation)?;
    }
    capture.descriptor_count = exact_count(capture.descriptor_table.len())?;
    capture.activation_count = exact_count(capture.activation_labels.len())?;
    capture.expected_descriptor_count = exact_count(capture.expected_descriptors.len())?;
    capture.source_subject_count = exact_count(capture.source_subjects.len())?;
    capture.cleanup_subject_count = exact_count(
        capture
            .source_subjects
            .iter()
            .filter(|subject| matches!(subject, StartupSourceSubjectV1::Cleanup(_)))
            .count(),
    )?;
    capture.terminal_subject_count = exact_count(
        capture
            .source_subjects
            .iter()
            .filter(|subject| matches!(subject, StartupSourceSubjectV1::Terminal(_)))
            .count(),
    )?;
    let (listener_number, listener_commitment) = listener_physical_identity(&capture)?;
    capture.listener_descriptor_number = listener_number;
    capture.listener_physical_commitment = listener_commitment;
    capture.descriptor_table_digest =
        startup_descriptor_table_digest_v1(&capture.descriptor_table)?;
    capture.activation_table_digest =
        startup_activation_table_digest_v1(&capture.activation_labels)?;
    capture.expected_table_digest =
        startup_expected_table_digest_v1(&capture.expected_descriptors)?;
    capture.source_subjects_digest = startup_source_subjects_digest_v1(&capture.source_subjects)?;
    capture.capture_id = startup_capture_id_v1(&capture)?;
    capture.record_digest = [0; 32];
    validate_capture(&capture, false)?;
    let (_, digest) = encode_envelope(CAPTURE_MAGIC, &capture, MAXIMUM_STARTUP_CAPTURE_BYTES_V1)?;
    capture.record_digest = digest;
    Ok(capture)
}

/// Encodes one sealed canonical immutable capture record.
///
/// # Errors
///
/// Returns an error for invalid derived commitments, ordering, bounds, or
/// self-digest.
pub fn encode_mount_manager_startup_capture_v1(
    capture: &MountManagerStartupCaptureV1,
) -> Result<Vec<u8>, MountManagerStartupFormatError> {
    validate_capture(capture, true)?;
    let (bytes, digest) =
        encode_envelope(CAPTURE_MAGIC, capture, MAXIMUM_STARTUP_CAPTURE_BYTES_V1)?;
    if digest != capture.record_digest {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(bytes)
}

/// Decodes and canonical-reencodes one immutable capture record.
///
/// # Errors
///
/// Returns an error for a malformed, unsupported, noncanonical, oversized, or
/// incorrectly digested record.
pub fn decode_mount_manager_startup_capture_v1(
    bytes: &[u8],
) -> Result<MountManagerStartupCaptureV1, MountManagerStartupFormatError> {
    let (payload, digest) =
        decode_envelope(CAPTURE_MAGIC, bytes, MAXIMUM_STARTUP_CAPTURE_BYTES_V1)?;
    let mut capture: MountManagerStartupCaptureV1 = serde_json::from_slice(payload)
        .map_err(|_| MountManagerStartupFormatError::InvalidRecord)?;
    capture.record_digest = digest;
    validate_capture(&capture, true)?;
    if encode_mount_manager_startup_capture_v1(&capture)? != bytes {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(capture)
}

/// Validates one exact monotone policy-head replacement.
///
/// `None` admits only the canonical generation-one genesis. A successor must
/// name the immediately preceding generation and exact sealed record digest,
/// retain the deployment identity, and advance its configuration generation.
///
/// # Errors
///
/// Returns an error if either policy is noncanonical or the replacement is
/// not the exact next protected head.
pub fn validate_mount_manager_startup_policy_successor_v1(
    previous: Option<&MountManagerStartupPolicyV1>,
    next: &MountManagerStartupPolicyV1,
) -> Result<(), MountManagerStartupFormatError> {
    encode_mount_manager_startup_policy_v1(next)?;
    match previous {
        None if next.generation == 1 => Ok(()),
        None => Err(MountManagerStartupFormatError::InvalidRecord),
        Some(previous) => {
            encode_mount_manager_startup_policy_v1(previous)?;
            let control_key_is_exact =
                if next.manager_control_key_generation == previous.manager_control_key_generation {
                    next.manager_control_key_id == previous.manager_control_key_id
                        && next.manager_control_public_key == previous.manager_control_public_key
                } else {
                    next.manager_control_key_generation
                        == previous
                            .manager_control_key_generation
                            .checked_add(1)
                            .ok_or(MountManagerStartupFormatError::InvalidRecord)?
                        && next.manager_control_key_id != previous.manager_control_key_id
                        && next.manager_control_public_key != previous.manager_control_public_key
                };
            if next.generation
                != previous
                    .generation
                    .checked_add(1)
                    .ok_or(MountManagerStartupFormatError::InvalidRecord)?
                || next.predecessor_generation != previous.generation
                || next.predecessor_digest != previous.record_digest
                || next.deployment_id != previous.deployment_id
                || next.configuration_generation <= previous.configuration_generation
                || !control_key_is_exact
            {
                return Err(MountManagerStartupFormatError::InvalidRecord);
            }
            Ok(())
        }
    }
}

/// Validates one exact immutable capture successor.
///
/// # Errors
///
/// Returns an error if either capture is noncanonical, sequence or predecessor
/// linkage is not gap-free, protected state regresses, or a reused policy
/// generation changes digest.
pub fn validate_mount_manager_startup_capture_successor_v1(
    previous: Option<&MountManagerStartupCaptureV1>,
    next: &MountManagerStartupCaptureV1,
) -> Result<(), MountManagerStartupFormatError> {
    encode_mount_manager_startup_capture_v1(next)?;
    match previous {
        None if next.capture_sequence == 1 => Ok(()),
        None => Err(MountManagerStartupFormatError::InvalidRecord),
        Some(previous) => {
            encode_mount_manager_startup_capture_v1(previous)?;
            let same_policy_is_exact = next.policy_generation != previous.policy_generation
                || next.policy_digest == previous.policy_digest;
            if next.capture_sequence
                != previous
                    .capture_sequence
                    .checked_add(1)
                    .ok_or(MountManagerStartupFormatError::InvalidRecord)?
                || next.predecessor_capture_digest != previous.record_digest
                || next.policy_generation < previous.policy_generation
                || !same_policy_is_exact
                || next.derivation.journal_sequence <= previous.derivation.journal_sequence
            {
                return Err(MountManagerStartupFormatError::InvalidRecord);
            }
            Ok(())
        }
    }
}

/// Validates a canonical capture against its exact sealed policy head.
///
/// This closes the policy-to-capture binding for credentials, unit/cgroup and
/// executable identity, descriptor/name/count bounds, listener identity, and
/// capture duration. Protected-state expected-table equality remains the
/// caller's responsibility because it requires the three source namespaces.
///
/// # Errors
///
/// Returns an error if either record is noncanonical or any capture field
/// violates the referenced policy.
pub fn validate_mount_manager_startup_capture_policy_v1(
    policy: &MountManagerStartupPolicyV1,
    capture: &MountManagerStartupCaptureV1,
) -> Result<(), MountManagerStartupFormatError> {
    let policy_bytes = encode_mount_manager_startup_policy_v1(policy)?;
    let capture_bytes = encode_mount_manager_startup_capture_v1(capture)?;
    let duration = capture
        .boot_time_after_ns
        .checked_sub(capture.boot_time_before_ns)
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    let standard_bitmap = capture
        .expected_descriptors
        .iter()
        .fold(0_u8, |bitmap, expected| match expected.role {
            StartupDescriptorRoleV1::StandardInput => bitmap | 0b001,
            StartupDescriptorRoleV1::StandardOutput => bitmap | 0b010,
            StartupDescriptorRoleV1::StandardError => bitmap | 0b100,
            _ => bitmap,
        });
    let listener = capture
        .expected_descriptors
        .iter()
        .find(|expected| expected.role == StartupDescriptorRoleV1::Listener)
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    let expected_name_bytes = capture
        .expected_descriptors
        .iter()
        .filter_map(|expected| expected.name.as_ref())
        .try_fold(0usize, |total, name| total.checked_add(name.len()))
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    let activation_name_bytes = capture
        .activation_labels
        .iter()
        .try_fold(0usize, |total, label| total.checked_add(label.name.len()))
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    let source_count = capture
        .expected_descriptors
        .iter()
        .filter(|expected| expected.role == StartupDescriptorRoleV1::SourceRoot)
        .count();
    let mount_count = capture
        .expected_descriptors
        .iter()
        .filter(|expected| expected.role == StartupDescriptorRoleV1::RetainedMount)
        .count();
    let policy_listener = super::StartupSocketObservationV1 {
        domain: policy.listener_domain,
        socket_type: policy.listener_socket_type,
        accepting: policy.listener_accepting,
        local_address: policy.listener_local_address.clone(),
    };

    if policy_bytes.len() > MAXIMUM_STARTUP_POLICY_BYTES_V1
        || capture_bytes.len() > policy.maximum_capture_bytes as usize
        || capture.policy_generation != policy.generation
        || capture.policy_digest != policy.record_digest
        || !credentials_are_exact(
            &capture.execution.credentials,
            policy.service_uid,
            policy.service_gid,
        )
        || capture.execution.unit != policy.service_unit
        || capture.execution.cgroup_path != policy.service_cgroup
        || capture.execution.executable != policy.service_executable
        || !credentials_are_exact(
            &capture.launcher.credentials,
            policy.launcher_uid,
            policy.launcher_gid,
        )
        || capture.launcher.unit != policy.launcher_unit
        || capture.launcher.cgroup_path != policy.launcher_cgroup
        || capture.launcher.executable != policy.launcher_executable
        || duration > policy.maximum_capture_duration_ns
        || capture.descriptor_count > policy.maximum_descriptor_count
        || capture.activation_count > policy.maximum_activation_count
        || capture
            .descriptor_table
            .last()
            .is_some_and(|descriptor| descriptor.number > policy.maximum_descriptor_number)
        || source_count > policy.maximum_source_count as usize
        || mount_count > policy.maximum_mount_count as usize
        || standard_bitmap != policy.standard_descriptor_bitmap
        || listener.name.as_ref() != Some(&policy.listener_name)
        || listener.logical_identity
            != mount_manager_startup_listener_identity_v1(&policy.listener_name)
        || listener.socket.as_ref() != Some(&policy_listener)
        || capture
            .expected_descriptors
            .iter()
            .filter_map(|expected| expected.name.as_ref())
            .any(|name| name.len() > policy.maximum_name_bytes as usize)
        || capture
            .activation_labels
            .iter()
            .any(|label| label.name.len() > policy.maximum_name_bytes as usize)
        || expected_name_bytes > policy.maximum_names_bytes as usize
        || activation_name_bytes > policy.maximum_names_bytes as usize
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(())
}

/// Validates immutable archived policies against the exact current head.
///
/// Archives may arrive in any order but must contain every predecessor from
/// generation one through the generation immediately before `current`.
///
/// # Errors
///
/// Returns an error for malformed keys or policies, gaps, duplicates, broken
/// predecessor links, or an archive that does not terminate at `current`.
pub fn validate_mount_manager_startup_policy_history_v1<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    current: &MountManagerStartupPolicyV1,
) -> Result<Vec<MountManagerStartupPolicyV1>, MountManagerStartupFormatError> {
    encode_mount_manager_startup_policy_v1(current)?;
    let mut materialized = records
        .into_iter()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    if materialized.len() >= MAXIMUM_STARTUP_CAPTURE_HISTORY_RECORDS_V1 {
        return Err(MountManagerStartupFormatError::InvalidSize);
    }
    materialized.sort_by(|left, right| left.0.cmp(&right.0));
    if materialized.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }

    let mut policies = Vec::with_capacity(materialized.len());
    for (key, value) in materialized {
        if !is_mount_manager_startup_policy_history_key_v1(&key) {
            return Err(MountManagerStartupFormatError::InvalidKey);
        }
        let generation = u64::from_be_bytes(
            key[POLICY_HISTORY_KEY_PREFIX.len()..]
                .try_into()
                .map_err(|_| MountManagerStartupFormatError::InvalidKey)?,
        );
        let policy = decode_mount_manager_startup_policy_v1(&value)?;
        if generation != policy.generation {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
        validate_mount_manager_startup_policy_successor_v1(policies.last(), &policy)?;
        policies.push(policy);
    }
    if let Some(previous) = policies.last() {
        validate_mount_manager_startup_policy_successor_v1(Some(previous), current)?;
    } else if current.generation != 1 {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    if policies.len() as u64 != current.generation.saturating_sub(1) {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(policies)
}

/// Decodes and validates the complete gap-free immutable capture history.
///
/// Records may arrive in any order. Keys are bytewise sorted and must encode
/// exactly the capture sequence stored in their canonical values. Empty
/// history is valid.
///
/// # Errors
///
/// Returns an error for duplicate/malformed keys, an exceeded aggregate bound,
/// a key/value sequence mismatch, or any predecessor/history discontinuity.
pub fn validate_mount_manager_startup_capture_history_v1<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Vec<MountManagerStartupCaptureV1>, MountManagerStartupFormatError> {
    let mut aggregate_bytes = 0usize;
    let mut materialized = Vec::new();
    for (key, value) in records {
        if materialized.len() >= MAXIMUM_STARTUP_CAPTURE_HISTORY_RECORDS_V1 {
            return Err(MountManagerStartupFormatError::InvalidSize);
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(MountManagerStartupFormatError::InvalidSize)?;
        if aggregate_bytes > MAXIMUM_STARTUP_CAPTURE_HISTORY_BYTES_V1 {
            return Err(MountManagerStartupFormatError::InvalidSize);
        }
        materialized.push((key.to_vec(), value.to_vec()));
    }
    materialized.sort_by(|left, right| left.0.cmp(&right.0));
    if materialized.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(MountManagerStartupFormatError::InvalidKey);
    }

    let mut captures = Vec::with_capacity(materialized.len());
    for (key, value) in materialized {
        let sequence = decode_mount_manager_startup_capture_key_v1(&key)?;
        let capture = decode_mount_manager_startup_capture_v1(&value)?;
        if sequence != capture.capture_sequence {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
        validate_mount_manager_startup_capture_successor_v1(captures.last(), &capture)?;
        captures.push(capture);
    }
    Ok(captures)
}

/// Derives a physical-observation commitment independent of its stored digest.
///
/// # Errors
///
/// Returns an error if canonical serialization fails or a socket address is
/// outside its fixed bound.
pub fn startup_descriptor_physical_commitment_v1(
    observation: &StartupDescriptorObservationV1,
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    if observation
        .socket
        .as_ref()
        .is_some_and(|socket| socket.local_address.len() > 256)
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    let mut value = observation.clone();
    value.physical_commitment = [0; 32];
    digest_serialized(b"aos.sandbox.mount-manager.startup-descriptor.v1\0", &value)
}

/// Derives a commitment to one complete pinned manager execution identity.
///
/// # Errors
///
/// Returns an error when canonical serialization fails.
pub fn startup_execution_identity_commitment_v1(
    execution: &super::StartupExecutionIdentityV1,
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    digest_serialized(
        b"aos.sandbox.mount-manager.execution-identity.v1\0",
        execution,
    )
}

/// Derives a commitment to the complete sorted descriptor table.
///
/// # Errors
///
/// Returns an error when canonical serialization fails.
pub fn startup_descriptor_table_digest_v1(
    table: &[StartupDescriptorObservationV1],
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    digest_serialized(b"aos.sandbox.mount-manager.startup-fd-table.v1\0", table)
}

/// Derives a commitment to the complete sorted activation-label table.
///
/// # Errors
///
/// Returns an error when canonical serialization fails.
pub fn startup_activation_table_digest_v1(
    table: &[StartupActivationLabelV1],
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    digest_serialized(
        b"aos.sandbox.mount-manager.startup-activation-table.v1\0",
        table,
    )
}

/// Derives a commitment to the protected-state expected table.
///
/// # Errors
///
/// Returns an error when canonical serialization fails.
pub fn startup_expected_table_digest_v1(
    table: &[ExpectedStartupDescriptorV1],
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    digest_serialized(
        b"aos.sandbox.mount-manager.startup-expected-table.v1\0",
        table,
    )
}

/// Derives a commitment to the exact sorted terminal-absence batch.
///
/// # Errors
///
/// Returns an error when canonical serialization fails.
pub fn startup_source_subjects_digest_v1(
    subjects: &[StartupSourceSubjectV1],
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    digest_serialized(
        b"aos.sandbox.mount-manager.startup-source-subjects.v1\0",
        subjects,
    )
}

/// Commits one optional bounded activation-environment value and its length.
///
/// The `field` selector is closed to `LISTEN_PID`, `LISTEN_FDS`, and
/// `LISTEN_FDNAMES`; these values remain diagnostic and never authorize a
/// descriptor role.
///
/// # Errors
///
/// Returns an error for another field or a value beyond the aggregate hint
/// ceiling.
pub fn startup_environment_hint_commitment_v1(
    field: &str,
    value: Option<&[u8]>,
) -> Result<([u8; 32], Option<u32>), MountManagerStartupFormatError> {
    let field_tag = match field {
        "LISTEN_PID" => 1_u8,
        "LISTEN_FDS" => 2,
        "LISTEN_FDNAMES" => 3,
        _ => return Err(MountManagerStartupFormatError::InvalidRecord),
    };
    let length = value
        .map(|bytes| {
            if bytes.len() > MAXIMUM_STARTUP_NAMES_BYTES_V1 {
                return Err(MountManagerStartupFormatError::InvalidSize);
            }
            u32::try_from(bytes.len()).map_err(|_| MountManagerStartupFormatError::InvalidSize)
        })
        .transpose()?;
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.startup-environment-hint.v1\0");
    hasher.update([field_tag, u8::from(value.is_some())]);
    hasher.update(length.unwrap_or(0).to_be_bytes());
    if let Some(bytes) = value {
        hasher.update(bytes);
    }
    Ok((hasher.finalize().into(), length))
}

/// Commits exact sorted scanner-owned descriptor numbers.
///
/// # Errors
///
/// Returns an error for an empty, unsorted, duplicate, or oversized set.
pub fn startup_scanner_descriptor_digest_v1(
    numbers: &[u32],
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    if numbers.is_empty() || numbers.len() > 32 || numbers.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.startup-scanner-fds.v1\0");
    hasher.update((numbers.len() as u64).to_be_bytes());
    for number in numbers {
        hasher.update(number.to_be_bytes());
    }
    Ok(hasher.finalize().into())
}

/// Derives the protected logical identity of the configured listener name.
#[must_use]
pub fn mount_manager_startup_listener_identity_v1(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.listener.v1\0");
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// Reproduces the commitment to one protected-state derivation head.
#[must_use]
pub fn mount_manager_startup_derivation_digest_v1(
    head: &super::MountManagerStartupDerivationHeadV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.startup-derivation.v1\0");
    hasher.update(head.journal_sequence.to_be_bytes());
    hasher.update(head.acquisition_record_count.to_be_bytes());
    hasher.update(head.acquisition_state_digest);
    hasher.update(head.source_pin_record_count.to_be_bytes());
    hasher.update(head.source_pin_state_digest);
    hasher.update(head.mount_resource_record_count.to_be_bytes());
    hasher.update(head.mount_resource_state_digest);
    hasher.finalize().into()
}

fn validate_policy(
    policy: &MountManagerStartupPolicyV1,
    require_digest: bool,
) -> Result<(), MountManagerStartupFormatError> {
    let predecessor_valid = if policy.generation == 1 {
        policy.predecessor_generation == 0 && policy.predecessor_digest == [0; 32]
    } else {
        policy.generation > 1
            && policy.predecessor_generation == policy.generation - 1
            && policy.predecessor_digest != [0; 32]
    };
    if !predecessor_valid
        || policy.deployment_id == [0; 16]
        || policy.configuration_generation == 0
        || policy.configuration_digest == [0; 32]
        || policy.manager_control_key_id == [0; 16]
        || policy.manager_control_key_generation == 0
        || VerifyingKey::from_bytes(&policy.manager_control_public_key).is_err()
        || !valid_locator(&policy.service_unit)
        || !valid_locator(&policy.service_cgroup)
        || !valid_locator(&policy.launcher_unit)
        || !valid_locator(&policy.launcher_cgroup)
        || !policy.service_cgroup.ends_with(&policy.service_unit)
        || !policy.launcher_cgroup.ends_with(&policy.launcher_unit)
        || !valid_executable(&policy.service_executable)
        || !valid_executable(&policy.launcher_executable)
        || policy.service_executable == policy.launcher_executable
        || policy.standard_descriptor_bitmap & !0b111 != 0
        || policy.maximum_descriptor_count == 0
        || usize::try_from(policy.maximum_descriptor_count)
            .map_or(true, |count| count > MAXIMUM_STARTUP_DESCRIPTORS_V1)
        || policy.maximum_descriptor_number < 3
        || policy.maximum_descriptor_number > MAXIMUM_STARTUP_DESCRIPTOR_NUMBER_V1
        || policy.maximum_activation_count == 0
        || policy.maximum_activation_count > policy.maximum_descriptor_count
        || policy.maximum_mount_count > policy.maximum_activation_count
        || policy.maximum_source_count > policy.maximum_activation_count
        || policy
            .maximum_mount_count
            .saturating_add(policy.maximum_source_count)
            > policy.maximum_activation_count.saturating_sub(1)
        || policy.maximum_name_bytes == 0
        || usize::try_from(policy.maximum_name_bytes)
            .map_or(true, |count| count > MAXIMUM_STARTUP_NAME_BYTES_V1)
        || policy.maximum_names_bytes == 0
        || usize::try_from(policy.maximum_names_bytes)
            .map_or(true, |count| count > MAXIMUM_STARTUP_NAMES_BYTES_V1)
        || usize::try_from(policy.maximum_capture_bytes).map_or(true, |count| {
            count == 0 || count > MAXIMUM_STARTUP_CAPTURE_BYTES_V1
        })
        || policy.maximum_capture_duration_ns == 0
        || !valid_name(&policy.listener_name, policy.maximum_name_bytes as usize)
        || policy.listener_domain != LINUX_AF_UNIX
        || policy.listener_socket_type != LINUX_SOCK_SEQPACKET
        || !policy.listener_accepting
        || policy.listener_local_address.is_empty()
        || policy.listener_local_address.len() > 256
        || (require_digest && policy.record_digest == [0; 32])
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(())
}

fn validate_capture(
    capture: &MountManagerStartupCaptureV1,
    require_digest: bool,
) -> Result<(), MountManagerStartupFormatError> {
    let predecessor_valid = if capture.capture_sequence == 1 {
        capture.predecessor_capture_digest == [0; 32]
    } else {
        capture.capture_sequence > 1 && capture.predecessor_capture_digest != [0; 32]
    };
    if !predecessor_valid
        || capture.capture_id == [0; 32]
        || capture.policy_generation == 0
        || capture.policy_digest == [0; 32]
        || capture.derivation.journal_sequence == 0
        || capture.derivation.acquisition_state_digest == [0; 32]
        || capture.derivation.source_pin_state_digest == [0; 32]
        || capture.derivation.mount_resource_state_digest == [0; 32]
        || capture.derivation.derivation_digest == [0; 32]
        || mount_manager_startup_derivation_digest_v1(&capture.derivation)
            != capture.derivation.derivation_digest
        || capture.execution.kernel_boot_id != capture.launcher.kernel_boot_id
        || capture.execution.pid == 0
        || capture.execution.pid != capture.execution.tgid
        || capture.execution.ppid != capture.launcher.pid
        || capture.launcher.pid == 0
        || capture.launcher.pid != capture.launcher.tgid
        || capture.boot_time_before_ns > capture.boot_time_after_ns
        || capture.realtime_before_ns > capture.realtime_after_ns
        || capture.descriptor_table.len() > MAXIMUM_STARTUP_DESCRIPTORS_V1
        || capture.expected_descriptors.len() > MAXIMUM_STARTUP_DESCRIPTORS_V1
        || capture.activation_labels.len() > MAXIMUM_STARTUP_DESCRIPTORS_V1
        || capture.source_subjects.len() > MAXIMUM_STARTUP_ABSENCE_SUBJECTS_V1
        || usize::try_from(capture.descriptor_count).ok() != Some(capture.descriptor_table.len())
        || usize::try_from(capture.activation_count).ok() != Some(capture.activation_labels.len())
        || usize::try_from(capture.expected_descriptor_count).ok()
            != Some(capture.expected_descriptors.len())
        || usize::try_from(capture.source_subject_count).ok() != Some(capture.source_subjects.len())
        || usize::try_from(capture.cleanup_subject_count).ok()
            != Some(
                capture
                    .source_subjects
                    .iter()
                    .filter(|subject| matches!(subject, StartupSourceSubjectV1::Cleanup(_)))
                    .count(),
            )
        || usize::try_from(capture.terminal_subject_count).ok()
            != Some(
                capture
                    .source_subjects
                    .iter()
                    .filter(|subject| matches!(subject, StartupSourceSubjectV1::Terminal(_)))
                    .count(),
            )
        || capture.scanner_descriptor_count == 0
        || capture.scanner_descriptor_digest == [0; 32]
        || capture.listen_pid_hint_digest == [0; 32]
        || capture.listen_fds_hint_digest == [0; 32]
        || capture.listen_fdnames_hint_digest == [0; 32]
        || capture
            .listen_pid_hint_length
            .is_some_and(|length| length as usize > MAXIMUM_STARTUP_NAMES_BYTES_V1)
        || capture
            .listen_fds_hint_length
            .is_some_and(|length| length as usize > MAXIMUM_STARTUP_NAMES_BYTES_V1)
        || capture
            .listen_fdnames_hint_length
            .is_some_and(|length| length as usize > MAXIMUM_STARTUP_NAMES_BYTES_V1)
        || [
            capture.listen_pid_hint_length,
            capture.listen_fds_hint_length,
            capture.listen_fdnames_hint_length,
        ]
        .into_iter()
        .flatten()
        .try_fold(0usize, |total, length| total.checked_add(length as usize))
        .is_none_or(|total| total > MAXIMUM_STARTUP_NAMES_BYTES_V1)
        || (require_digest && capture.record_digest == [0; 32])
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    validate_execution(&capture.execution)?;
    validate_execution(&capture.launcher)?;
    validate_sorted_capture_lists(capture)?;
    let (listener_number, listener_commitment) = listener_physical_identity(capture)?;

    if capture.listener_descriptor_number != listener_number
        || capture.listener_physical_commitment != listener_commitment
        || startup_descriptor_table_digest_v1(&capture.descriptor_table)?
            != capture.descriptor_table_digest
        || startup_activation_table_digest_v1(&capture.activation_labels)?
            != capture.activation_table_digest
        || startup_expected_table_digest_v1(&capture.expected_descriptors)?
            != capture.expected_table_digest
        || startup_source_subjects_digest_v1(&capture.source_subjects)?
            != capture.source_subjects_digest
        || startup_capture_id_v1(capture)? != capture.capture_id
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(())
}

fn validate_sorted_capture_lists(
    capture: &MountManagerStartupCaptureV1,
) -> Result<(), MountManagerStartupFormatError> {
    if capture
        .descriptor_table
        .windows(2)
        .any(|pair| pair[0].number >= pair[1].number)
        || capture
            .activation_labels
            .windows(2)
            .any(|pair| pair[0].number >= pair[1].number)
        || capture
            .expected_descriptors
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || capture
            .source_subjects
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    let descriptor_numbers: BTreeSet<_> = capture
        .descriptor_table
        .iter()
        .map(|entry| entry.number)
        .collect();
    let mut activation_names = BTreeSet::new();
    let aggregate_name_bytes = capture
        .activation_labels
        .iter()
        .try_fold(0usize, |total, label| total.checked_add(label.name.len()))
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    if aggregate_name_bytes > MAXIMUM_STARTUP_NAMES_BYTES_V1 {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    if capture.activation_labels.iter().any(|label| {
        !descriptor_numbers.contains(&label.number)
            || !valid_name(&label.name, MAXIMUM_STARTUP_NAME_BYTES_V1)
            || !activation_names.insert(label.name.as_str())
            || matches!(
                label.role,
                StartupDescriptorRoleV1::StandardInput
                    | StartupDescriptorRoleV1::StandardOutput
                    | StartupDescriptorRoleV1::StandardError
            )
    }) {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    if capture
        .activation_labels
        .iter()
        .enumerate()
        .any(|(index, label)| {
            u32::try_from(index)
                .ok()
                .and_then(|offset| offset.checked_add(3))
                != Some(label.number)
        })
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    for observation in &capture.descriptor_table {
        if observation.device == 0
            || observation.inode == 0
            || observation.number > MAXIMUM_STARTUP_DESCRIPTOR_NUMBER_V1
            || observation.physical_commitment
                != startup_descriptor_physical_commitment_v1(observation)?
            || observation
                .socket
                .as_ref()
                .is_some_and(|socket| socket.local_address.len() > 256)
            || (observation.object_kind == super::StartupDescriptorObjectKindV1::Socket)
                != observation.socket.is_some()
        {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
    }
    for expected in &capture.expected_descriptors {
        if let Some(name) = &expected.name {
            if !valid_name(name, MAXIMUM_STARTUP_NAME_BYTES_V1) {
                return Err(MountManagerStartupFormatError::InvalidRecord);
            }
        }
        validate_expected_descriptor(expected)?;
        if matches!(
            expected.role,
            StartupDescriptorRoleV1::StandardInput
                | StartupDescriptorRoleV1::StandardOutput
                | StartupDescriptorRoleV1::StandardError
                | StartupDescriptorRoleV1::Listener
        ) && expected.presence != StartupDescriptorPresenceV1::Required
        {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
    }
    if capture.source_subjects.iter().any(|subject| match subject {
        StartupSourceSubjectV1::Cleanup(subject) => {
            subject.acquisition_id == [0; 32]
                || subject.acquisition_revision == 0
                || subject.acquisition_record_digest == [0; 32]
                || subject.acquire_attempt_id == [0; 32]
                || subject.acquire_attempt_revision == 0
                || subject.acquire_attempt_record_digest == [0; 32]
                || subject.evidence.is_some_and(|evidence| {
                    evidence.source_realization_handle == [0; 32]
                        || evidence.descriptor_commitment == [0; 32]
                        || evidence.source_kernel_boot_id == [0; 16]
                        || evidence.source_device == 0
                        || evidence.source_inode == 0
                        || evidence.source_unique_mount_id == 0
                })
                || subject.last_custody_owner.is_some_and(|owner| {
                    owner.attempt_id == [0; 32]
                        || owner.attempt_revision == 0
                        || owner.attempt_record_digest == [0; 32]
                        || owner.session_id == [0; 32]
                        || owner.session_record_digest == [0; 32]
                        || owner.kernel_boot_id == [0; 16]
                        || owner.tgid == 0
                        || owner.start_time_ticks == 0
                        || owner.cgroup_digest == [0; 32]
                })
                || subject.evidence.is_none()
                || subject.last_custody_owner.is_none()
        }
        StartupSourceSubjectV1::Terminal(subject) => {
            subject.acquisition_id == [0; 32]
                || subject.acquisition_revision == 0
                || subject.acquisition_record_digest == [0; 32]
                || subject.provider_acquisition_id == [0; 32]
                || subject.provider_acquisition_sequence == 0
                || subject.source_realization_handle == [0; 32]
                || subject.descriptor_commitment == [0; 32]
                || subject.source_kernel_boot_id == [0; 16]
                || subject.source_device == 0
                || subject.source_inode == 0
                || subject.source_unique_mount_id == 0
                || subject.lease_id == [0; 16]
                || subject.lease_digest == [0; 32]
                || subject.terminal_attempt_id == [0; 32]
                || subject.terminal_attempt_revision == 0
                || subject.terminal_attempt_digest == [0; 32]
        }
    }) {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    validate_exact_descriptor_allocation(capture)?;
    Ok(())
}

fn validate_expected_descriptor(
    expected: &ExpectedStartupDescriptorV1,
) -> Result<(), MountManagerStartupFormatError> {
    let no_physical = expected.kernel_boot_id.is_none()
        && expected.device.is_none()
        && expected.inode.is_none()
        && expected.unique_mount_id.is_none()
        && expected.descriptor_commitment.is_none();
    let no_acquisition = expected.source_acquisition_id.is_none()
        && expected.source_acquisition_revision.is_none()
        && expected.source_acquisition_record_digest.is_none();
    let valid = match expected.role {
        StartupDescriptorRoleV1::StandardInput
        | StartupDescriptorRoleV1::StandardOutput
        | StartupDescriptorRoleV1::StandardError => {
            expected.name.is_none()
                && expected.logical_identity == [0; 32]
                && no_physical
                && no_acquisition
                && expected.socket.is_none()
        }
        StartupDescriptorRoleV1::Listener => {
            expected.name.is_some()
                && expected.logical_identity != [0; 32]
                && no_physical
                && no_acquisition
                && expected.socket.as_ref().is_some_and(valid_listener_socket)
        }
        StartupDescriptorRoleV1::RetainedMount => {
            expected.name.is_some()
                && expected.logical_identity != [0; 32]
                && expected.kernel_boot_id.is_some_and(|boot| boot != [0; 16])
                && expected.device.is_none()
                && expected.inode.is_none()
                && expected.unique_mount_id.is_some_and(|mount| mount != 0)
                && expected.descriptor_commitment.is_none()
                && no_acquisition
                && expected.socket.is_none()
        }
        StartupDescriptorRoleV1::SourceRoot => {
            expected.name.is_some()
                && expected.logical_identity != [0; 32]
                && expected.kernel_boot_id.is_some_and(|boot| boot != [0; 16])
                && expected.device.is_some_and(|device| device != 0)
                && expected.inode.is_some_and(|inode| inode != 0)
                && expected.unique_mount_id.is_some_and(|mount| mount != 0)
                && expected
                    .descriptor_commitment
                    .is_some_and(|commitment| commitment != [0; 32])
                && expected
                    .source_acquisition_id
                    .is_some_and(|identity| identity != [0; 32])
                && expected
                    .source_acquisition_revision
                    .is_some_and(|revision| revision != 0)
                && expected
                    .source_acquisition_record_digest
                    .is_some_and(|digest| digest != [0; 32])
                && expected.socket.is_none()
        }
    };
    if !valid {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(())
}

fn validate_exact_descriptor_allocation(
    capture: &MountManagerStartupCaptureV1,
) -> Result<(), MountManagerStartupFormatError> {
    let expected_standard_numbers = capture
        .expected_descriptors
        .iter()
        .filter_map(|expected| match expected.role {
            StartupDescriptorRoleV1::StandardInput => Some(0),
            StartupDescriptorRoleV1::StandardOutput => Some(1),
            StartupDescriptorRoleV1::StandardError => Some(2),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let actual_numbers = capture
        .descriptor_table
        .iter()
        .map(|descriptor| descriptor.number)
        .collect::<BTreeSet<_>>();
    let admitted_numbers = expected_standard_numbers
        .into_iter()
        .chain(capture.activation_labels.iter().map(|label| label.number))
        .collect::<BTreeSet<_>>();
    if actual_numbers != admitted_numbers {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }

    for label in &capture.activation_labels {
        let matching = capture.expected_descriptors.iter().filter(|expected| {
            expected.name.as_ref() == Some(&label.name)
                && expected.role == label.role
                && expected.logical_identity == label.logical_identity
        });
        if matching.count() != 1 {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
        let expected = capture
            .expected_descriptors
            .iter()
            .find(|expected| {
                expected.name.as_ref() == Some(&label.name)
                    && expected.role == label.role
                    && expected.logical_identity == label.logical_identity
            })
            .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
        let descriptor = capture
            .descriptor_table
            .iter()
            .find(|descriptor| descriptor.number == label.number)
            .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
        let physical_match = match label.role {
            StartupDescriptorRoleV1::Listener => {
                descriptor.object_kind == super::StartupDescriptorObjectKindV1::Socket
                    && descriptor.socket == expected.socket
            }
            StartupDescriptorRoleV1::RetainedMount => {
                descriptor.object_kind == super::StartupDescriptorObjectKindV1::Directory
                    && descriptor.unique_mount_id == expected.unique_mount_id
            }
            StartupDescriptorRoleV1::SourceRoot => {
                descriptor.object_kind == super::StartupDescriptorObjectKindV1::Directory
                    && descriptor.status_flags & LINUX_O_PATH == LINUX_O_PATH
                    && descriptor.status_flags & LINUX_O_ACCMODE == 0
                    && descriptor.mount_read_only == Some(true)
                    && Some(descriptor.device) == expected.device
                    && Some(descriptor.inode) == expected.inode
                    && descriptor.unique_mount_id == expected.unique_mount_id
            }
            StartupDescriptorRoleV1::StandardInput
            | StartupDescriptorRoleV1::StandardOutput
            | StartupDescriptorRoleV1::StandardError => false,
        };
        if !physical_match {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
    }
    for expected in &capture.expected_descriptors {
        if expected.name.is_some()
            && expected.presence == StartupDescriptorPresenceV1::Required
            && !capture.activation_labels.iter().any(|label| {
                expected.name.as_ref() == Some(&label.name)
                    && expected.role == label.role
                    && expected.logical_identity == label.logical_identity
            })
        {
            return Err(MountManagerStartupFormatError::InvalidRecord);
        }
    }
    Ok(())
}

fn listener_physical_identity(
    capture: &MountManagerStartupCaptureV1,
) -> Result<(u32, [u8; 32]), MountManagerStartupFormatError> {
    let mut listeners = capture
        .activation_labels
        .iter()
        .filter(|label| label.role == StartupDescriptorRoleV1::Listener);
    let listener = listeners
        .next()
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    if listeners.next().is_some() {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    let descriptor = capture
        .descriptor_table
        .iter()
        .find(|descriptor| descriptor.number == listener.number)
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    let expected_socket = capture
        .expected_descriptors
        .iter()
        .find(|expected| {
            expected.role == StartupDescriptorRoleV1::Listener
                && expected.name.as_ref() == Some(&listener.name)
                && expected.logical_identity == listener.logical_identity
        })
        .and_then(|expected| expected.socket.as_ref())
        .ok_or(MountManagerStartupFormatError::InvalidRecord)?;
    if descriptor.object_kind != super::StartupDescriptorObjectKindV1::Socket
        || descriptor.socket.as_ref() != Some(expected_socket)
        || descriptor.physical_commitment == [0; 32]
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok((descriptor.number, descriptor.physical_commitment))
}

fn valid_listener_socket(socket: &super::StartupSocketObservationV1) -> bool {
    socket.domain == LINUX_AF_UNIX
        && socket.socket_type == LINUX_SOCK_SEQPACKET
        && socket.accepting
        && !socket.local_address.is_empty()
        && socket.local_address.len() <= 256
}

fn credentials_are_exact(credentials: &super::StartupCredentialsV1, uid: u32, gid: u32) -> bool {
    credentials.real_uid == uid
        && credentials.effective_uid == uid
        && credentials.saved_uid == uid
        && credentials.filesystem_uid == uid
        && credentials.real_gid == gid
        && credentials.effective_gid == gid
        && credentials.saved_gid == gid
        && credentials.filesystem_gid == gid
}

fn exact_count(length: usize) -> Result<u32, MountManagerStartupFormatError> {
    u32::try_from(length).map_err(|_| MountManagerStartupFormatError::InvalidSize)
}

fn validate_execution(
    execution: &super::StartupExecutionIdentityV1,
) -> Result<(), MountManagerStartupFormatError> {
    if execution.kernel_boot_id == [0; 16]
        || execution.pid == 0
        || execution.tgid == 0
        || execution.start_time_ticks == 0
        || execution.cgroup_id == 0
        || !valid_locator(&execution.cgroup_path)
        || !valid_locator(&execution.unit)
        || !execution.cgroup_path.ends_with(&execution.unit)
        || !valid_executable(&execution.executable)
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok(())
}

fn valid_executable(executable: &StartupExecutableIdentityV1) -> bool {
    executable.device != 0
        && executable.inode != 0
        && executable.size != 0
        && executable.mode & libc_mode_type_mask() == libc_regular_mode()
        && executable.fs_verity_sha256 != [0; 32]
        && executable.build_identity_digest != [0; 32]
}

const fn libc_mode_type_mask() -> u32 {
    0o170000
}

const fn libc_regular_mode() -> u32 {
    0o100000
}

fn valid_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_STARTUP_LOCATOR_BYTES_V1
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        && !value.split('/').any(|component| component == "..")
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .bytes()
            .any(|byte| matches!(byte, b':' | b'\0' | b'\n' | b'\r'))
}

fn startup_capture_id_v1(
    capture: &MountManagerStartupCaptureV1,
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    let mut identity = capture.clone();
    identity.capture_id = [0; 32];
    identity.record_digest = [0; 32];
    digest_serialized(
        b"aos.sandbox.mount-manager.startup-capture-id.v1\0",
        &identity,
    )
}

fn encode_envelope<T: Serialize>(
    magic: &[u8; 9],
    value: &T,
    maximum: usize,
) -> Result<(Vec<u8>, [u8; 32]), MountManagerStartupFormatError> {
    let payload =
        serde_json::to_vec(value).map_err(|_| MountManagerStartupFormatError::InvalidRecord)?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| MountManagerStartupFormatError::InvalidSize)?;
    let total = ENVELOPE_PREFIX_BYTES
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(DIGEST_BYTES))
        .ok_or(MountManagerStartupFormatError::InvalidSize)?;
    if total > maximum {
        return Err(MountManagerStartupFormatError::InvalidSize);
    }

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(&payload);
    let digest = envelope_digest(magic, &bytes);
    bytes.extend_from_slice(&digest);
    Ok((bytes, digest))
}

fn decode_envelope<'a>(
    magic: &[u8; 9],
    bytes: &'a [u8],
    maximum: usize,
) -> Result<(&'a [u8], [u8; 32]), MountManagerStartupFormatError> {
    if bytes.len() < ENVELOPE_PREFIX_BYTES + DIGEST_BYTES || bytes.len() > maximum {
        return Err(MountManagerStartupFormatError::InvalidSize);
    }
    if &bytes[..9] != magic
        || u16::from_be_bytes(
            bytes[9..11]
                .try_into()
                .map_err(|_| MountManagerStartupFormatError::InvalidRecord)?,
        ) != FORMAT_VERSION
        || bytes[11..13] != [0, 0]
    {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    let payload_length = usize::try_from(u32::from_be_bytes(
        bytes[13..17]
            .try_into()
            .map_err(|_| MountManagerStartupFormatError::InvalidRecord)?,
    ))
    .map_err(|_| MountManagerStartupFormatError::InvalidSize)?;
    let payload_end = ENVELOPE_PREFIX_BYTES
        .checked_add(payload_length)
        .ok_or(MountManagerStartupFormatError::InvalidSize)?;
    if payload_end + DIGEST_BYTES != bytes.len() {
        return Err(MountManagerStartupFormatError::InvalidSize);
    }
    let digest: [u8; 32] = bytes[payload_end..]
        .try_into()
        .map_err(|_| MountManagerStartupFormatError::InvalidRecord)?;
    if envelope_digest(magic, &bytes[..payload_end]) != digest {
        return Err(MountManagerStartupFormatError::InvalidRecord);
    }
    Ok((&bytes[ENVELOPE_PREFIX_BYTES..payload_end], digest))
}

fn envelope_digest(magic: &[u8; 9], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.startup-envelope.v1\0");
    hasher.update(magic);
    hasher.update(body);
    hasher.finalize().into()
}

fn digest_serialized<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], MountManagerStartupFormatError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| MountManagerStartupFormatError::InvalidRecord)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

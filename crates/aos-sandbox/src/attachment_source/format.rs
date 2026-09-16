//! Canonical codecs for attachment-source attempt and completion custody.
//!
//! ```text
//! AOSASA01 | kind:1 | flags:1 | reserved:2 | operation-id:16 |
//! request-digest:32 | attachment-id:16 | desired-generation:8 |
//! desired-digest:32 | acquisition-id:32 | predecessor:32 |
//! mount-completion:32 | plan-digest:32 | request-len:4 | plan-len:4 |
//! exact-request | canonical-plan | digest:32
//!
//! AOSASC01 | kind:1 | flags:1 | reserved:2 | operation-id:16 |
//! attempt-digest:32 | predecessor:32 | attachment-id:16 |
//! desired-generation:8 | acquisition-id:32 | acquisition-revision:8 |
//! acquisition-record-digest:32 | acquisition-phase:1 |
//! resource-snapshot-digest:32 | source-snapshot-digest:32 |
//! mount-handle:32 | resource-revision:8 | resource-lifecycle:1 |
//! mount-completion:32 | verification:32 | digest:32
//! ```
//!
//! Integers are big endian. Optional 32-byte fields are all zero when their
//! flag is clear. The trailing SHA-256 digest covers a format-specific domain
//! and every preceding byte. A terminal rowless-Acquire cancellation uses zero
//! acquisition revision/digest and the unspecified phase while retaining the
//! exact acquisition ID and source/resource snapshot digests.

use buffa::Enumeration as _;
use sha2::{Digest as _, Sha256};

use aos_proto::aos::sandbox::local::v1::{MountLifecycle, MountSourceAcquisitionPhase};

use super::custody::{AttachmentSourceAttemptKindV1, AttemptRecord, CompletionRecord};
use super::planning::AttachmentSourceError;

const ATTEMPT_MAGIC: &[u8; 8] = b"AOSASA01";
const COMPLETION_MAGIC: &[u8; 8] = b"AOSASC01";
const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.attachment-source-attempt.v1\0";
const COMPLETION_DOMAIN: &[u8] = b"aos.sandbox.attachment-source-completion.v1\0";
const FLAG_PREDECESSOR: u8 = 1;
const FLAG_MOUNT_COMPLETION: u8 = 2;
const FLAG_VERIFICATION: u8 = 4;
const FLAG_RESOURCE: u8 = 8;
const ATTEMPT_PREFIX_BYTES: usize = 252;
const ATTEMPT_FIXED_BYTES: usize = ATTEMPT_PREFIX_BYTES + 32;
const COMPLETION_FIXED_BYTES: usize = 390;
pub(super) const PLAN_BYTES: usize = 637;
const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
const MAXIMUM_ATTEMPT_BYTES: usize = MAXIMUM_REQUEST_BYTES + PLAN_BYTES + ATTEMPT_FIXED_BYTES;

impl AttemptRecord {
    pub(super) fn encoded_len(&self) -> usize {
        ATTEMPT_FIXED_BYTES
            .saturating_add(self.request_body.len())
            .saturating_add(self.plan_bytes.len())
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(ATTEMPT_MAGIC);
        bytes.push(self.kind as u8);
        bytes.push(
            u8::from(self.predecessor.is_some()) * FLAG_PREDECESSOR
                | u8::from(self.mount_completion_digest.is_some()) * FLAG_MOUNT_COMPLETION,
        );
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.operation_id);
        bytes.extend_from_slice(&self.request_digest);
        bytes.extend_from_slice(&self.attachment_id);
        bytes.extend_from_slice(&self.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.desired_digest);
        bytes.extend_from_slice(&self.acquisition_id);
        bytes.extend_from_slice(&self.predecessor.unwrap_or([0; 32]));
        bytes.extend_from_slice(&self.mount_completion_digest.unwrap_or([0; 32]));
        bytes.extend_from_slice(&self.plan_digest);
        bytes.extend_from_slice(&u32_len(self.request_body.len()).to_be_bytes());
        bytes.extend_from_slice(&u32_len(self.plan_bytes.len()).to_be_bytes());
        bytes.extend_from_slice(&self.request_body);
        bytes.extend_from_slice(&self.plan_bytes);
        bytes
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(ATTEMPT_DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    pub(super) fn validate(&self) -> Result<(), AttachmentSourceError> {
        if self.operation_id == [0; 16]
            || self.request_digest == [0; 32]
            || self.attachment_id == [0; 16]
            || self.desired_generation == 0
            || self.desired_digest == [0; 32]
            || self.acquisition_id == [0; 32]
            || self.plan_digest == [0; 32]
            || self.predecessor == Some([0; 32])
            || self.mount_completion_digest == Some([0; 32])
            || self.request_body.len() > MAXIMUM_REQUEST_BYTES
            || self.plan_bytes.len() != PLAN_BYTES
            || self.encoded_len() > MAXIMUM_ATTEMPT_BYTES
            || self.digest == [0; 32]
            || self.compute_digest() != self.digest
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        match self.kind {
            AttachmentSourceAttemptKindV1::Acquire | AttachmentSourceAttemptKindV1::Release
                if self.request_body.is_empty() || self.mount_completion_digest.is_some() =>
            {
                Err(AttachmentSourceError::CorruptState)
            }
            AttachmentSourceAttemptKindV1::Consume
                if !self.request_body.is_empty() || self.mount_completion_digest.is_none() =>
            {
                Err(AttachmentSourceError::CorruptState)
            }
            _ => Ok(()),
        }
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, AttachmentSourceError> {
        if bytes.len() < ATTEMPT_FIXED_BYTES
            || bytes.len() > MAXIMUM_ATTEMPT_BYTES
            || take::<8>(&mut bytes)? != *ATTEMPT_MAGIC
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        let kind = AttachmentSourceAttemptKindV1::from_byte(take::<1>(&mut bytes)?[0])?;
        let flags = take::<1>(&mut bytes)?[0];
        if flags & !(FLAG_PREDECESSOR | FLAG_MOUNT_COMPLETION) != 0
            || take::<2>(&mut bytes)? != [0; 2]
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        let operation_id = take(&mut bytes)?;
        let request_digest = take(&mut bytes)?;
        let attachment_id = take(&mut bytes)?;
        let desired_generation = u64::from_be_bytes(take(&mut bytes)?);
        let desired_digest = take(&mut bytes)?;
        let acquisition_id = take(&mut bytes)?;
        let predecessor = optional_digest(flags, FLAG_PREDECESSOR, take(&mut bytes)?)?;
        let mount_completion_digest =
            optional_digest(flags, FLAG_MOUNT_COMPLETION, take(&mut bytes)?)?;
        let plan_digest = take(&mut bytes)?;
        let request_len = usize_len(take(&mut bytes)?)?;
        let plan_len = usize_len(take(&mut bytes)?)?;
        if plan_len != PLAN_BYTES
            || bytes.len() != request_len.saturating_add(plan_len).saturating_add(32)
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        let request_body = take_vec(&mut bytes, request_len)?;
        let plan_bytes = take_vec(&mut bytes, plan_len)?;
        let digest = take(&mut bytes)?;
        let record = Self {
            kind,
            operation_id,
            request_digest,
            attachment_id,
            desired_generation,
            desired_digest,
            acquisition_id,
            predecessor,
            mount_completion_digest,
            plan_digest,
            request_body,
            plan_bytes,
            digest,
        };
        if !bytes.is_empty() {
            return Err(AttachmentSourceError::CorruptState);
        }
        record.validate()?;
        Ok(record)
    }
}

impl CompletionRecord {
    pub(super) const fn encoded_len(&self) -> usize {
        COMPLETION_FIXED_BYTES
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(COMPLETION_FIXED_BYTES);
        bytes.extend_from_slice(COMPLETION_MAGIC);
        bytes.push(self.kind as u8);
        bytes.push(
            u8::from(self.predecessor.is_some()) * FLAG_PREDECESSOR
                | u8::from(self.mount_completion_digest.is_some()) * FLAG_MOUNT_COMPLETION
                | u8::from(self.verification_digest.is_some()) * FLAG_VERIFICATION
                | u8::from(self.mount_handle.is_some()) * FLAG_RESOURCE,
        );
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.operation_id);
        bytes.extend_from_slice(&self.attempt_digest);
        bytes.extend_from_slice(&self.predecessor.unwrap_or([0; 32]));
        bytes.extend_from_slice(&self.attachment_id);
        bytes.extend_from_slice(&self.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.acquisition_id);
        bytes.extend_from_slice(&self.acquisition_revision.to_be_bytes());
        bytes.extend_from_slice(&self.acquisition_record_digest);
        bytes.push(self.acquisition_phase as i32 as u8);
        bytes.extend_from_slice(&self.resource_snapshot_digest);
        bytes.extend_from_slice(&self.source_snapshot_digest);
        bytes.extend_from_slice(&self.mount_handle.unwrap_or([0; 32]));
        bytes.extend_from_slice(&self.resource_revision.unwrap_or(0).to_be_bytes());
        bytes.push(
            self.resource_lifecycle
                .map_or(0, |value| value as i32 as u8),
        );
        bytes.extend_from_slice(&self.mount_completion_digest.unwrap_or([0; 32]));
        bytes.extend_from_slice(&self.verification_digest.unwrap_or([0; 32]));
        bytes
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(COMPLETION_DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    pub(super) fn validate(&self) -> Result<(), AttachmentSourceError> {
        let cancelled_acquire = self.kind == AttachmentSourceAttemptKindV1::Acquire
            && self.acquisition_revision == 0
            && self.acquisition_record_digest == [0; 32]
            && self.acquisition_phase
                == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED
            && self.mount_handle.is_none();
        if self.operation_id == [0; 16]
            || self.attempt_digest == [0; 32]
            || self.attachment_id == [0; 16]
            || self.desired_generation == 0
            || self.acquisition_id == [0; 32]
            || (!cancelled_acquire
                && (self.acquisition_revision == 0
                    || self.acquisition_record_digest == [0; 32]
                    || self.acquisition_phase
                        == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED))
            || self.resource_snapshot_digest == [0; 32]
            || self.source_snapshot_digest == [0; 32]
            || self.mount_handle == Some([0; 32])
            || self.resource_revision == Some(0)
            || self.resource_lifecycle == Some(MountLifecycle::MOUNT_LIFECYCLE_UNSPECIFIED)
            || self.mount_handle.is_some() != self.resource_revision.is_some()
            || self.mount_handle.is_some() != self.resource_lifecycle.is_some()
            || self.predecessor == Some([0; 32])
            || self.mount_completion_digest == Some([0; 32])
            || self.verification_digest == Some([0; 32])
            || self.digest == [0; 32]
            || self.compute_digest() != self.digest
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        match self.kind {
            AttachmentSourceAttemptKindV1::Acquire => {
                let active = self.acquisition_phase
                    == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
                    && self.mount_handle.is_none();
                let preactive_or_faulted = matches!(
                    self.acquisition_phase,
                    MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
                        | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
                        | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                ) && self.mount_handle.is_none();
                let resource_bearing = matches!(
                    self.acquisition_phase,
                    MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                        | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                ) && self.mount_handle.is_some();
                if (!cancelled_acquire && !active && !preactive_or_faulted && !resource_bearing)
                    || self.mount_completion_digest.is_some()
                    || self.verification_digest.is_some()
                {
                    Err(AttachmentSourceError::CorruptState)
                } else {
                    Ok(())
                }
            }
            AttachmentSourceAttemptKindV1::Consume => {
                let installed = self.acquisition_phase
                    == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                    && self.resource_lifecycle == Some(MountLifecycle::MOUNT_LIFECYCLE_INSTALLED)
                    && self.verification_digest.is_some();
                let released = matches!(
                    self.acquisition_phase,
                    MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                        | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
                ) && self.resource_lifecycle
                    == Some(MountLifecycle::MOUNT_LIFECYCLE_RELEASED)
                    && self.verification_digest.is_none();
                if self.mount_handle.is_none()
                    || self.mount_completion_digest.is_none()
                    || !(installed || released)
                {
                    Err(AttachmentSourceError::CorruptState)
                } else {
                    Ok(())
                }
            }
            AttachmentSourceAttemptKindV1::Release
                if self.mount_completion_digest.is_some() || self.verification_digest.is_some() =>
            {
                Err(AttachmentSourceError::CorruptState)
            }
            AttachmentSourceAttemptKindV1::Release
                if self.acquisition_phase
                    != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    || self.resource_lifecycle.is_some_and(|lifecycle| {
                        lifecycle != MountLifecycle::MOUNT_LIFECYCLE_RELEASED
                    }) =>
            {
                Err(AttachmentSourceError::CorruptState)
            }
            _ => Ok(()),
        }
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, AttachmentSourceError> {
        if bytes.len() != COMPLETION_FIXED_BYTES || take::<8>(&mut bytes)? != *COMPLETION_MAGIC {
            return Err(AttachmentSourceError::CorruptState);
        }
        let kind = AttachmentSourceAttemptKindV1::from_byte(take::<1>(&mut bytes)?[0])?;
        let flags = take::<1>(&mut bytes)?[0];
        if flags & !(FLAG_PREDECESSOR | FLAG_MOUNT_COMPLETION | FLAG_VERIFICATION | FLAG_RESOURCE)
            != 0
            || take::<2>(&mut bytes)? != [0; 2]
        {
            return Err(AttachmentSourceError::CorruptState);
        }
        let operation_id = take(&mut bytes)?;
        let attempt_digest = take(&mut bytes)?;
        let predecessor = optional_digest(flags, FLAG_PREDECESSOR, take(&mut bytes)?)?;
        let attachment_id = take(&mut bytes)?;
        let desired_generation = u64::from_be_bytes(take(&mut bytes)?);
        let acquisition_id = take(&mut bytes)?;
        let acquisition_revision = u64::from_be_bytes(take(&mut bytes)?);
        let acquisition_record_digest = take(&mut bytes)?;
        let acquisition_phase =
            MountSourceAcquisitionPhase::from_i32(i32::from(take::<1>(&mut bytes)?[0]))
                .ok_or(AttachmentSourceError::CorruptState)?;
        let resource_snapshot_digest = take(&mut bytes)?;
        let source_snapshot_digest = take(&mut bytes)?;
        let mount_handle = optional_digest(flags, FLAG_RESOURCE, take(&mut bytes)?)?;
        let raw_resource_revision = u64::from_be_bytes(take(&mut bytes)?);
        let raw_resource_lifecycle = take::<1>(&mut bytes)?[0];
        let (resource_revision, resource_lifecycle) = if flags & FLAG_RESOURCE != 0 {
            (
                Some(raw_resource_revision),
                Some(
                    MountLifecycle::from_i32(i32::from(raw_resource_lifecycle))
                        .ok_or(AttachmentSourceError::CorruptState)?,
                ),
            )
        } else if raw_resource_revision == 0 && raw_resource_lifecycle == 0 {
            (None, None)
        } else {
            return Err(AttachmentSourceError::CorruptState);
        };
        let record = Self {
            kind,
            operation_id,
            attempt_digest,
            predecessor,
            attachment_id,
            desired_generation,
            acquisition_id,
            acquisition_revision,
            acquisition_record_digest,
            acquisition_phase,
            resource_snapshot_digest,
            source_snapshot_digest,
            mount_handle,
            resource_revision,
            resource_lifecycle,
            mount_completion_digest: optional_digest(
                flags,
                FLAG_MOUNT_COMPLETION,
                take(&mut bytes)?,
            )?,
            verification_digest: optional_digest(flags, FLAG_VERIFICATION, take(&mut bytes)?)?,
            digest: take(&mut bytes)?,
        };
        if !bytes.is_empty() {
            return Err(AttachmentSourceError::CorruptState);
        }
        record.validate()?;
        Ok(record)
    }
}

fn optional_digest(
    flags: u8,
    bit: u8,
    value: [u8; 32],
) -> Result<Option<[u8; 32]>, AttachmentSourceError> {
    match flags & bit != 0 {
        false if value == [0; 32] => Ok(None),
        true if value != [0; 32] => Ok(Some(value)),
        _ => Err(AttachmentSourceError::CorruptState),
    }
}

fn u32_len(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn usize_len(value: [u8; 4]) -> Result<usize, AttachmentSourceError> {
    usize::try_from(u32::from_be_bytes(value)).map_err(|_| AttachmentSourceError::CorruptState)
}

fn take_vec(bytes: &mut &[u8], length: usize) -> Result<Vec<u8>, AttachmentSourceError> {
    let (value, remaining) = bytes
        .split_at_checked(length)
        .ok_or(AttachmentSourceError::CorruptState)?;
    *bytes = remaining;
    Ok(value.to_vec())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], AttachmentSourceError> {
    let (value, remaining) = bytes
        .split_at_checked(N)
        .ok_or(AttachmentSourceError::CorruptState)?;
    *bytes = remaining;
    let value = value
        .try_into()
        .map_err(|_| AttachmentSourceError::CorruptState)?;
    Ok(value)
}

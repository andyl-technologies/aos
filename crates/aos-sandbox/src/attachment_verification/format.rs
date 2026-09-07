//! Length-delimited codec for durable attachment verification evidence.
//!
//! ```text
//! AOSATV01 | state:1 | flags:1 | reserved:2 | attachment-id:16 |
//! desired-generation:8 | desired-record:32 | namespace-target:112 |
//! assignment-epoch:8 | assignment-generation:8 | assignment-digest:32 |
//! inventory-snapshot:32 | inventory-request-id:16 | mount-handle:32 |
//! resource-revision:8 | resource-kernel-boot-id:16 | recipe-digest:32 |
//! resource-digest:32 | kernel-observation:92 | root-bytes:4 | mount-point-bytes:4 |
//! root | mount-point | digest:32
//! ```
//!
//! Integers and lengths are big endian. The final digest covers a domain
//! separator and every preceding byte, including both raw kernel paths.

use aos_sandbox_core::{AttachmentId, IncarnationId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{AttachmentVerificationError, ObservationRecord, Record};
use crate::runtime_scope::DurableNamespaceTargetReferenceV1;

const MAGIC: &[u8; 8] = b"AOSATV01";
const DOMAIN: &[u8] = b"aos.sandbox.attachment-verification.v1\0";
const STATE_VERIFIED: u8 = 1;
const PREFIX_BYTES: usize = 496;
const DIGEST_BYTES: usize = 32;
pub(super) const FIXED_RECORD_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;

impl Record {
    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(STATE_VERIFIED);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(self.attachment_id.as_bytes());
        bytes.extend_from_slice(&self.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.desired_record_digest);
        bytes.extend_from_slice(self.namespace_target.sandbox().as_bytes());
        bytes.extend_from_slice(self.namespace_target.incarnation().as_bytes());
        bytes.extend_from_slice(&self.namespace_target.observed_generation().to_be_bytes());
        bytes.extend_from_slice(&self.namespace_target.observed_audit_digest());
        bytes.extend_from_slice(&self.namespace_target.target_generation().to_be_bytes());
        bytes.extend_from_slice(&self.namespace_target.allocation_digest());
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_generation.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_digest);
        bytes.extend_from_slice(&self.inventory_snapshot_digest);
        bytes.extend_from_slice(&self.inventory_request_id);
        bytes.extend_from_slice(&self.mount_handle);
        bytes.extend_from_slice(&self.resource_revision.to_be_bytes());
        bytes.extend_from_slice(&self.resource_kernel_boot_id);
        bytes.extend_from_slice(&self.recipe_digest);
        bytes.extend_from_slice(&self.resource_digest);
        bytes.extend_from_slice(&self.observation.unique_mount_id.to_be_bytes());
        bytes.extend_from_slice(&self.observation.parent_mount_id.to_be_bytes());
        bytes.extend_from_slice(&self.observation.mount_namespace_id.to_be_bytes());
        bytes.extend_from_slice(&self.observation.device_major.to_be_bytes());
        bytes.extend_from_slice(&self.observation.device_minor.to_be_bytes());
        bytes.extend_from_slice(&self.observation.superblock_magic.to_be_bytes());
        bytes.extend_from_slice(&self.observation.superblock_flags.to_be_bytes());
        bytes.extend_from_slice(&self.observation.mount_attributes.to_be_bytes());
        bytes.extend_from_slice(&self.observation.propagation.to_be_bytes());
        bytes.extend_from_slice(&self.observation.identity_map_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.observation.root.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.observation.mount_point.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.observation.root);
        bytes.extend_from_slice(&self.observation.mount_point);
        bytes
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, AttachmentVerificationError> {
        if bytes.len() < FIXED_RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(AttachmentVerificationError::CorruptState);
        }
        if take::<1>(&mut bytes)? != [STATE_VERIFIED]
            || take::<1>(&mut bytes)? != [0]
            || take::<2>(&mut bytes)? != [0; 2]
        {
            return Err(AttachmentVerificationError::CorruptState);
        }

        let attachment_id = AttachmentId::from_bytes(take(&mut bytes)?);
        let desired_generation = u64::from_be_bytes(take(&mut bytes)?);
        let desired_record_digest = take(&mut bytes)?;
        let namespace_target = DurableNamespaceTargetReferenceV1::from_parts(
            SandboxId::from_bytes(take(&mut bytes)?),
            IncarnationId::from_bytes(take(&mut bytes)?),
            u64::from_be_bytes(take(&mut bytes)?),
            take(&mut bytes)?,
            u64::from_be_bytes(take(&mut bytes)?),
            take(&mut bytes)?,
        );
        let assignment_epoch = u64::from_be_bytes(take(&mut bytes)?);
        let assignment_generation = u64::from_be_bytes(take(&mut bytes)?);
        let assignment_digest = take(&mut bytes)?;
        let inventory_snapshot_digest = take(&mut bytes)?;
        let inventory_request_id = take(&mut bytes)?;
        let mount_handle = take(&mut bytes)?;
        let resource_revision = u64::from_be_bytes(take(&mut bytes)?);
        let resource_kernel_boot_id = take(&mut bytes)?;
        let recipe_digest = take(&mut bytes)?;
        let resource_digest = take(&mut bytes)?;
        let observation = ObservationRecord {
            unique_mount_id: u64::from_be_bytes(take(&mut bytes)?),
            parent_mount_id: u64::from_be_bytes(take(&mut bytes)?),
            mount_namespace_id: u64::from_be_bytes(take(&mut bytes)?),
            device_major: u32::from_be_bytes(take(&mut bytes)?),
            device_minor: u32::from_be_bytes(take(&mut bytes)?),
            superblock_magic: u64::from_be_bytes(take(&mut bytes)?),
            superblock_flags: u32::from_be_bytes(take(&mut bytes)?),
            mount_attributes: u64::from_be_bytes(take(&mut bytes)?),
            propagation: u64::from_be_bytes(take(&mut bytes)?),
            identity_map_digest: take(&mut bytes)?,
            root: Vec::new(),
            mount_point: Vec::new(),
        };
        let root_bytes = length(&mut bytes)?;
        let mount_point_bytes = length(&mut bytes)?;
        let variable_bytes = root_bytes
            .checked_add(mount_point_bytes)
            .ok_or(AttachmentVerificationError::CorruptState)?;
        if bytes.len() != variable_bytes.saturating_add(DIGEST_BYTES) {
            return Err(AttachmentVerificationError::CorruptState);
        }
        let mut observation = observation;
        observation.root = take_vec(&mut bytes, root_bytes)?;
        observation.mount_point = take_vec(&mut bytes, mount_point_bytes)?;
        let digest = take(&mut bytes)?;
        let record = Self {
            attachment_id,
            desired_generation,
            desired_record_digest,
            namespace_target,
            assignment_epoch,
            assignment_generation,
            assignment_digest,
            inventory_snapshot_digest,
            inventory_request_id,
            mount_handle,
            resource_revision,
            resource_kernel_boot_id,
            recipe_digest,
            resource_digest,
            observation,
            digest,
        };
        if !bytes.is_empty() || record.compute_digest() != record.digest {
            return Err(AttachmentVerificationError::CorruptState);
        }
        Ok(record)
    }
}

fn length(bytes: &mut &[u8]) -> Result<usize, AttachmentVerificationError> {
    usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| AttachmentVerificationError::CorruptState)
}

fn take_vec(bytes: &mut &[u8], length: usize) -> Result<Vec<u8>, AttachmentVerificationError> {
    let (prefix, remaining) = bytes
        .split_at_checked(length)
        .ok_or(AttachmentVerificationError::CorruptState)?;
    *bytes = remaining;
    Ok(prefix.to_vec())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], AttachmentVerificationError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(AttachmentVerificationError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| AttachmentVerificationError::CorruptState)?;
    *bytes = remaining;
    Ok(value)
}

//! Length-delimited codec for durable controller Mount attempts.
//!
//! ```text
//! AOSMTA02 | state:1 | flags:1 | reserved:2 | request-id:16 |
//! namespace-target-reference:112 | assignment-epoch:8 |
//! desired-generation:8 | assignment-digest:32 | catalog:32 |
//! semantics:32 | plan:32 | template:32 | lease:32 |
//! lease-generation:8 | deadline:8 | template-body-bytes:4 |
//! body-bytes:4 | packet-bytes:4 | template-body | body | packet | digest:32
//! ```
//!
//! Integers and lengths are big endian. Flag bit zero states that the catalog
//! field is present; release clears it and requires 32 zero bytes. The final
//! SHA-256 digest covers a domain separator and every preceding byte, including
//! all variable bytes.

use sha2::{Digest as _, Sha256};

use super::{DurableNamespaceTargetReferenceV1, MountAttemptError, Record};
use aos_sandbox_core::{IncarnationId, SandboxId};

const MAGIC: &[u8; 8] = b"AOSMTA02";
const DOMAIN: &[u8] = b"aos.sandbox.mount-attempt.v2\0";
const STATE_ADMITTED: u8 = 1;
const HAS_CATALOG: u8 = 1 << 0;
const PREFIX_BYTES: usize = 376;
const DIGEST_BYTES: usize = 32;
pub(super) const FIXED_RECORD_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;

impl Record {
    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(STATE_ADMITTED);
        bytes.push(self.catalog_commitment.map_or(0, |_| HAS_CATALOG));
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(self.namespace_target.sandbox().as_bytes());
        bytes.extend_from_slice(self.namespace_target.incarnation().as_bytes());
        bytes.extend_from_slice(&self.namespace_target.observed_generation().to_be_bytes());
        bytes.extend_from_slice(&self.namespace_target.observed_audit_digest());
        bytes.extend_from_slice(&self.namespace_target.target_generation().to_be_bytes());
        bytes.extend_from_slice(&self.namespace_target.allocation_digest());
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.desired_generation.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_digest);
        bytes.extend_from_slice(&self.catalog_commitment.unwrap_or([0; 32]));
        bytes.extend_from_slice(&self.semantic_digest);
        bytes.extend_from_slice(&self.plan_digest);
        bytes.extend_from_slice(&self.template_digest);
        bytes.extend_from_slice(&self.lease_digest);
        bytes.extend_from_slice(&self.lease_generation.to_be_bytes());
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.template_body.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.body.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.packet.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.template_body);
        bytes.extend_from_slice(&self.body);
        bytes.extend_from_slice(&self.packet);
        bytes
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.body_bytes());
        digest.finalize().into()
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, MountAttemptError> {
        if bytes.len() < FIXED_RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(MountAttemptError::CorruptState);
        }
        if take::<1>(&mut bytes)? != [STATE_ADMITTED] {
            return Err(MountAttemptError::CorruptState);
        }
        let flags = take::<1>(&mut bytes)?[0];
        if flags & !HAS_CATALOG != 0 || take::<2>(&mut bytes)? != [0; 2] {
            return Err(MountAttemptError::CorruptState);
        }

        let request_id = take(&mut bytes)?;
        let namespace_target = DurableNamespaceTargetReferenceV1::from_parts(
            SandboxId::from_bytes(take(&mut bytes)?),
            IncarnationId::from_bytes(take(&mut bytes)?),
            u64::from_be_bytes(take(&mut bytes)?),
            take(&mut bytes)?,
            u64::from_be_bytes(take(&mut bytes)?),
            take(&mut bytes)?,
        );
        let assignment_epoch = u64::from_be_bytes(take(&mut bytes)?);
        let desired_generation = u64::from_be_bytes(take(&mut bytes)?);
        let assignment_digest = take(&mut bytes)?;
        let catalog_bytes = take(&mut bytes)?;
        let catalog_commitment = if flags & HAS_CATALOG != 0 {
            Some(catalog_bytes)
        } else if catalog_bytes == [0; 32] {
            None
        } else {
            return Err(MountAttemptError::CorruptState);
        };
        let semantic_digest = take(&mut bytes)?;
        let plan_digest = take(&mut bytes)?;
        let template_digest = take(&mut bytes)?;
        let lease_digest = take(&mut bytes)?;
        let lease_generation = u64::from_be_bytes(take(&mut bytes)?);
        let deadline_boottime_nanoseconds = u64::from_be_bytes(take(&mut bytes)?);
        let template_body_bytes = length(&mut bytes)?;
        let body_bytes = length(&mut bytes)?;
        let packet_bytes = length(&mut bytes)?;
        let variable_bytes = template_body_bytes
            .checked_add(body_bytes)
            .and_then(|size| size.checked_add(packet_bytes))
            .ok_or(MountAttemptError::CorruptState)?;
        if bytes.len() != variable_bytes.saturating_add(DIGEST_BYTES) {
            return Err(MountAttemptError::CorruptState);
        }

        let template_body = take_vec(&mut bytes, template_body_bytes)?;
        let body = take_vec(&mut bytes, body_bytes)?;
        let packet = take_vec(&mut bytes, packet_bytes)?;
        let digest = take(&mut bytes)?;
        let record = Self {
            request_id,
            namespace_target,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            catalog_commitment,
            semantic_digest,
            plan_digest,
            template_digest,
            lease_digest,
            lease_generation,
            deadline_boottime_nanoseconds,
            template_body,
            body,
            packet,
            digest,
        };
        if !bytes.is_empty() || record.compute_digest() != record.digest {
            return Err(MountAttemptError::CorruptState);
        }
        Ok(record)
    }
}

fn length(bytes: &mut &[u8]) -> Result<usize, MountAttemptError> {
    usize::try_from(u32::from_be_bytes(take(bytes)?)).map_err(|_| MountAttemptError::CorruptState)
}

fn take_vec(bytes: &mut &[u8], length: usize) -> Result<Vec<u8>, MountAttemptError> {
    let (prefix, remaining) = bytes
        .split_at_checked(length)
        .ok_or(MountAttemptError::CorruptState)?;
    *bytes = remaining;
    Ok(prefix.to_vec())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], MountAttemptError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(MountAttemptError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| MountAttemptError::CorruptState)?;
    *bytes = remaining;
    Ok(value)
}

//! Length-delimited codec for durable controller Mount attempts.
//!
//! ```text
//! AOSMTA01 | state:1 | flags:1 | reserved:2 | request-id:16 |
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

use aos_sandbox_core::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};

use super::{DurableNamespaceTargetReferenceV1, MountAttemptError, Record};
use aos_sandbox_core::{IncarnationId, SandboxId};

const MAGIC: &[u8; 8] = b"AOSMTA01";
const DOMAIN: &[u8] = b"aos.sandbox.mount-attempt.v1\0";
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

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, MountAttemptError> {
        let mut reader = BoundedReader::new(bytes, |_| MountAttemptError::CorruptState);

        if bytes.len() < FIXED_RECORD_BYTES || reader.array::<8>()? != *MAGIC {
            return Err(MountAttemptError::CorruptState);
        }
        if reader.array::<1>()? != [STATE_ADMITTED] {
            return Err(MountAttemptError::CorruptState);
        }
        let flags = reader.array::<1>()?[0];
        if flags & !HAS_CATALOG != 0 || reader.array::<2>()? != [0; 2] {
            return Err(MountAttemptError::CorruptState);
        }

        let request_id = reader.array()?;
        let namespace_target = DurableNamespaceTargetReferenceV1::from_parts(
            SandboxId::from_bytes(reader.array()?),
            IncarnationId::from_bytes(reader.array()?),
            u64::from_be_bytes(reader.array()?),
            reader.array()?,
            u64::from_be_bytes(reader.array()?),
            reader.array()?,
        );
        let assignment_epoch = u64::from_be_bytes(reader.array()?);
        let desired_generation = u64::from_be_bytes(reader.array()?);
        let assignment_digest = reader.array()?;
        let catalog_bytes = reader.array()?;
        let catalog_commitment = if flags & HAS_CATALOG != 0 {
            Some(catalog_bytes)
        } else if catalog_bytes == [0; 32] {
            None
        } else {
            return Err(MountAttemptError::CorruptState);
        };
        let semantic_digest = reader.array()?;
        let plan_digest = reader.array()?;
        let template_digest = reader.array()?;
        let lease_digest = reader.array()?;
        let lease_generation = u64::from_be_bytes(reader.array()?);
        let deadline_boottime_nanoseconds = u64::from_be_bytes(reader.array()?);
        let template_body_bytes = length(&mut reader)?;
        let body_bytes = length(&mut reader)?;
        let packet_bytes = length(&mut reader)?;
        let variable_bytes = template_body_bytes
            .checked_add(body_bytes)
            .and_then(|size| size.checked_add(packet_bytes))
            .ok_or(MountAttemptError::CorruptState)?;
        if reader.remaining() != variable_bytes.saturating_add(DIGEST_BYTES) {
            return Err(MountAttemptError::CorruptState);
        }

        let template_body = reader.bytes(template_body_bytes)?.to_vec();
        let body = reader.bytes(body_bytes)?.to_vec();
        let packet = reader.bytes(packet_bytes)?.to_vec();
        let digest = reader.array()?;
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
        if !reader.is_empty() || record.compute_digest() != record.digest {
            return Err(MountAttemptError::CorruptState);
        }
        Ok(record)
    }
}

fn length(reader: &mut BoundedReader<'_, MountAttemptError>) -> Result<usize, MountAttemptError> {
    usize::try_from(u32::from_be_bytes(reader.array()?))
        .map_err(|_| MountAttemptError::CorruptState)
}

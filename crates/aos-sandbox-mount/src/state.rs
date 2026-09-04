//! Bounded mount-broker records stored in the common checksummed journal.

use aos_sandbox::journal::{Journal, RecordNamespace};
use aos_sandbox_protocol::ValidatedAssignmentFence;

use crate::{MountError, Result};

const FENCE_BYTES: usize = 16 + 8 + 8 + 32;
const EFFECT_FIXED_BYTES: usize = 1 + 1 + 32 + 4;
const MAXIMUM_RECEIPT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectStatus {
    Pending,
    Complete,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EffectRecord {
    pub(crate) status: EffectStatus,
    pub(crate) action: u8,
    pub(crate) request_digest: [u8; 32],
    pub(crate) receipt: Vec<u8>,
}

pub(crate) fn validate_fence(journal: &Journal, proposed: &ValidatedAssignmentFence) -> Result<()> {
    let Some(bytes) = journal.get(RecordNamespace::DesiredState, proposed.sandbox_id()) else {
        return Ok(());
    };
    let current = decode_fence(bytes)?;
    if proposed.assignment_epoch() < current.assignment_epoch
        || (proposed.assignment_epoch() == current.assignment_epoch
            && proposed.desired_generation() < current.desired_generation)
    {
        return Err(MountError::Fence("assignment generation is stale"));
    }
    if proposed.assignment_epoch() == current.assignment_epoch {
        if proposed.incarnation_id() != &current.incarnation_id {
            return Err(MountError::Fence(
                "equal assignment epoch changed incarnation",
            ));
        }
        if proposed.desired_generation() == current.desired_generation
            && proposed.assignment_digest() != &current.assignment_digest
        {
            return Err(MountError::Fence(
                "equal assignment generation changed semantic digest",
            ));
        }
    }
    Ok(())
}

pub(crate) fn encode_fence(fence: &ValidatedAssignmentFence) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FENCE_BYTES);
    bytes.extend_from_slice(fence.incarnation_id());
    bytes.extend_from_slice(&fence.assignment_epoch().to_le_bytes());
    bytes.extend_from_slice(&fence.desired_generation().to_le_bytes());
    bytes.extend_from_slice(fence.assignment_digest());
    bytes
}

pub(crate) fn encode_effect(
    status: EffectStatus,
    action: u8,
    request_digest: [u8; 32],
    receipt: &[u8],
) -> Result<Vec<u8>> {
    if action == 0
        || (status == EffectStatus::Pending && !receipt.is_empty())
        || (status == EffectStatus::Complete
            && (receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES))
    {
        return Err(MountError::State(
            "invalid durable mount effect record".to_owned(),
        ));
    }
    let length = u32::try_from(receipt.len())
        .map_err(|_| MountError::State("mount receipt length exceeds u32".to_owned()))?;
    let mut bytes = Vec::with_capacity(EFFECT_FIXED_BYTES + receipt.len());
    bytes.push(match status {
        EffectStatus::Pending => 0,
        EffectStatus::Complete => 1,
    });
    bytes.push(action);
    bytes.extend_from_slice(&request_digest);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(receipt);
    Ok(bytes)
}

pub(crate) fn decode_effect(bytes: &[u8]) -> Result<EffectRecord> {
    if bytes.len() < EFFECT_FIXED_BYTES {
        return Err(MountError::State(
            "durable mount effect record is truncated".to_owned(),
        ));
    }
    let status = match bytes[0] {
        0 => EffectStatus::Pending,
        1 => EffectStatus::Complete,
        _ => {
            return Err(MountError::State(
                "durable mount effect status is unknown".to_owned(),
            ));
        }
    };
    let action = bytes[1];
    let request_digest = bytes[2..34]
        .try_into()
        .map_err(|_| MountError::State("mount request digest is truncated".to_owned()))?;
    let length = u32::from_le_bytes(
        bytes[34..38]
            .try_into()
            .map_err(|_| MountError::State("mount receipt length is truncated".to_owned()))?,
    ) as usize;
    if action == 0
        || length > MAXIMUM_RECEIPT_BYTES
        || bytes.len() != EFFECT_FIXED_BYTES + length
        || (status == EffectStatus::Pending && length != 0)
        || (status == EffectStatus::Complete && length == 0)
    {
        return Err(MountError::State(
            "durable mount effect record is noncanonical".to_owned(),
        ));
    }
    Ok(EffectRecord {
        status,
        action,
        request_digest,
        receipt: bytes[EFFECT_FIXED_BYTES..].to_vec(),
    })
}

struct StoredFence {
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

fn decode_fence(bytes: &[u8]) -> Result<StoredFence> {
    if bytes.len() != FENCE_BYTES {
        return Err(MountError::State(
            "durable mount fence has an invalid length".to_owned(),
        ));
    }
    let fence = StoredFence {
        incarnation_id: bytes[0..16]
            .try_into()
            .map_err(|_| MountError::State("mount incarnation is truncated".to_owned()))?,
        assignment_epoch: u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| MountError::State("mount epoch is truncated".to_owned()))?,
        ),
        desired_generation: u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| MountError::State("mount generation is truncated".to_owned()))?,
        ),
        assignment_digest: bytes[32..64]
            .try_into()
            .map_err(|_| MountError::State("mount assignment digest is truncated".to_owned()))?,
    };
    if fence.incarnation_id == [0; 16]
        || fence.assignment_epoch == 0
        || fence.desired_generation == 0
        || fence.assignment_digest == [0; 32]
    {
        return Err(MountError::State(
            "durable mount fence contains a sentinel".to_owned(),
        ));
    }
    Ok(fence)
}

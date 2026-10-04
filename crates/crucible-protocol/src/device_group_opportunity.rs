//! Pointer-free publication of one original sorted Device backend subgroup.
//!
//! ```text
//! publication:u64 | pid:u64 | process_generation:u64 | node:u64 | mapping:u64
//! paired_grid:u32 | count:u32 | actor112 | member144[32]
//! ```
//!
//! Unused member slots are zero. Publication identifies a retained descriptor;
//! it creates no Source, member, backend, or execution permission.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Semantic version of the fixed Group descriptor body.
pub const DEVICE_GROUP_OPPORTUNITY_VERSION: u16 = 1;

/// Size of a canonical Group opportunity payload, excluding frame tag/prefix.
pub const DEVICE_GROUP_OPPORTUNITY_BYTES: usize = 4_768;

/// Maximum number of sorted members carried by one Group opportunity.
pub const DEVICE_GROUP_OPPORTUNITY_MAX_MEMBERS: usize = 32;

/// Refuses malformed public descriptor geometry or original correlation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("invalid Device Group opportunity field: {field}")]
pub struct DeviceGroupOpportunityError {
    /// Names the malformed field without exposing a process-private object.
    pub field: &'static str,
}

/// Retains a validated public description for exact Host selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceGroupOpportunity {
    publication_sequence: u64,
    physical_identity: [u64; 4],
    grid_publish_generation: u32,
    actor: [u8; 112],
    members: Vec<[u8; 144]>,
}

impl DeviceGroupOpportunity {
    /// Checks and retains the original public bytes of a sorted subgroup.
    ///
    /// # Errors
    ///
    /// Refuses missing identity/publication, unpaired GRID, oversized membership,
    /// mismatched actor count/digest, unknown member tags, or nonzero padding.
    pub fn new(
        publication_sequence: u64,
        physical_identity: [u64; 4],
        grid_publish_generation: u32,
        actor: [u8; 112],
        members: Vec<[u8; 144]>,
    ) -> Result<Self, DeviceGroupOpportunityError> {
        let refusal = |field| DeviceGroupOpportunityError { field };

        if publication_sequence == 0 || physical_identity.contains(&0) {
            return Err(refusal("original identity"));
        }
        if grid_publish_generation == 0 || grid_publish_generation & 1 != 0 {
            return Err(refusal("paired GRID"));
        }
        if !(1..=DEVICE_GROUP_OPPORTUNITY_MAX_MEMBERS).contains(&members.len())
            || scalar(&actor, 24) != members.len() as u64
        {
            return Err(refusal("member count"));
        }

        let mut digest = Sha256::new();
        digest.update(b"qemu.virtio-blk.presubmit-group.members.v1");
        digest.update((members.len() as u32).to_le_bytes());
        for member in &members {
            let tag = u32::from_le_bytes(member[..4].try_into().map_err(|_| refusal("tag"))?);
            let length =
                u32::from_le_bytes(member[4..8].try_into().map_err(|_| refusal("length"))?);
            match (tag, length) {
                (1, 112) if member[120..].iter().all(|byte| *byte == 0) => {}
                (2, 136) => {}
                _ => return Err(refusal("canonical member")),
            }
            digest.update(member);
        }
        if digest.finalize().as_slice() != &actor[32..64] {
            return Err(refusal("membership digest"));
        }

        Ok(Self {
            publication_sequence,
            physical_identity,
            grid_publish_generation,
            actor,
            members,
        })
    }

    /// Returns the original descriptor issuance, independent of command counters.
    #[must_use]
    pub const fn publication_sequence(&self) -> u64 {
        self.publication_sequence
    }

    /// Returns PID, process generation, node incarnation, and clock mapping.
    #[must_use]
    pub const fn physical_identity(&self) -> [u64; 4] {
        self.physical_identity
    }

    /// Returns the independent stable-even paired GRID publication generation.
    #[must_use]
    pub const fn grid_publish_generation(&self) -> u32 {
        self.grid_publish_generation
    }

    /// Returns the exact native-published actor bytes for semantic validation.
    #[must_use]
    pub const fn actor(&self) -> &[u8; 112] {
        &self.actor
    }

    /// Returns the exact ordered member bytes without choosing or reordering them.
    #[must_use]
    pub fn members(&self) -> &[[u8; 144]] {
        &self.members
    }

    /// Encodes the checked descriptor with zero unused roster slots.
    #[must_use]
    pub fn encode(&self) -> [u8; DEVICE_GROUP_OPPORTUNITY_BYTES] {
        let mut bytes = [0; DEVICE_GROUP_OPPORTUNITY_BYTES];
        for (index, value) in core::iter::once(self.publication_sequence)
            .chain(self.physical_identity)
            .enumerate()
        {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[40..44].copy_from_slice(&self.grid_publish_generation.to_le_bytes());
        bytes[44..48].copy_from_slice(&(self.members.len() as u32).to_le_bytes());
        bytes[48..160].copy_from_slice(&self.actor);
        for (target, member) in bytes[160..].chunks_mut(144).zip(&self.members) {
            target.copy_from_slice(member);
        }
        bytes
    }

    /// Decodes the exact bounded descriptor without allocating from a copied count.
    ///
    /// # Errors
    ///
    /// Refuses truncated/trailing payload, count outside one through thirty-two,
    /// nonzero unused slots, or any invalid original descriptor field.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeviceGroupOpportunityError> {
        let refusal = |field| DeviceGroupOpportunityError { field };
        if bytes.len() != DEVICE_GROUP_OPPORTUNITY_BYTES {
            return Err(refusal("payload length"));
        }
        let count =
            u32::from_le_bytes(bytes[44..48].try_into().map_err(|_| refusal("count"))?) as usize;
        if !(1..=DEVICE_GROUP_OPPORTUNITY_MAX_MEMBERS).contains(&count) {
            return Err(refusal("member count"));
        }
        let end = 160 + count * 144;
        if bytes[end..].iter().any(|byte| *byte != 0) {
            return Err(refusal("unused member slots"));
        }
        let mut members = Vec::with_capacity(count);
        for member in bytes[160..end].chunks(144) {
            members.push(member.try_into().map_err(|_| refusal("member length"))?);
        }
        Self::new(
            scalar(bytes, 0),
            core::array::from_fn(|index| scalar(bytes, 8 + index * 8)),
            u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| refusal("GRID"))?),
            bytes[48..160]
                .try_into()
                .map_err(|_| refusal("actor length"))?,
            members,
        )
    }
}

fn scalar(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(count: usize) -> DeviceGroupOpportunity {
        let mut actor = [0; 112];
        actor[24..32].copy_from_slice(&(count as u64).to_le_bytes());
        let mut members = vec![[0; 144]; count];
        let mut digest = Sha256::new();
        digest.update(b"qemu.virtio-blk.presubmit-group.members.v1");
        digest.update((count as u32).to_le_bytes());

        for (index, member) in members.iter_mut().enumerate() {
            member[..4].copy_from_slice(&1_u32.to_le_bytes());
            member[4..8].copy_from_slice(&112_u32.to_le_bytes());
            member[8..16].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            digest.update(member);
        }
        actor[32..64].copy_from_slice(&digest.finalize());
        DeviceGroupOpportunity::new(19, [101, 7, 11, 13], 6, actor, members)
            .unwrap_or_else(|error| panic!("valid original descriptor: {error}"))
    }

    #[test]
    fn bounded_public_roundtrip_preserves_exact_original_bytes() {
        for count in [1, 2, DEVICE_GROUP_OPPORTUNITY_MAX_MEMBERS] {
            let original = descriptor(count);
            let payload = original.encode();
            assert_eq!(DeviceGroupOpportunity::decode(&payload), Ok(original.clone()));
            assert_eq!(&payload[48..160], original.actor());
            assert_eq!(payload[40..44], 6_u32.to_le_bytes());
            assert!(payload[160 + count * 144..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn copied_count_digest_padding_and_unpaired_grid_refuse() {
        let original = descriptor(2).encode();
        for count in [0_u32, 33, u32::MAX] {
            let mut changed = original;
            changed[44..48].copy_from_slice(&count.to_le_bytes());
            assert!(DeviceGroupOpportunity::decode(&changed).is_err());
        }
        for offset in [0, 8, 16, 24, 32, 40, 72, 80, 160, 160 + 2 * 144] {
            let mut changed = original;
            if offset <= 40 {
                changed[offset..offset + 8].fill(0);
            } else {
                changed[offset] ^= 1;
            }
            assert!(
                DeviceGroupOpportunity::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut odd = original;
        odd[40..44].copy_from_slice(&5_u32.to_le_bytes());
        assert!(DeviceGroupOpportunity::decode(&odd).is_err());
        assert!(DeviceGroupOpportunity::decode(&original[..original.len() - 1]).is_err());
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert!(DeviceGroupOpportunity::decode(&trailing).is_err());
    }
}

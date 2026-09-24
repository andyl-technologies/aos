//! Canonical AOSKGH01 deny-stage bytes and nonauthorizing physical snapshots.
//!
//! ```text
//! AOSKGH01[344] = header[16] | handoff-id[32] | Provider/plan/journal/
//! clone/holder/cgroup/expiry tuple[296]
//! SCM_RIGHTS = [detached clone O_PATH, exact consumer cgroup-v2 O_PATH]
//! ```
//!
//! Storage's handoff ID is a digest, not a signature. The receiver must also
//! authenticate the live Storage process and validate both FD roles. Even a
//! completely validated frame does not authorize a map mutation or FD release.

use sha2::{Digest as _, Sha256};

use crate::OwnerPeerError;

/// Exact Storage deny-stage frame length.
pub const HANDOFF_BYTES: usize = 344;
const HANDOFF_DOMAIN: &[u8] = b"aos.sandbox.storage.kernel-export-deny-handoff.v1\0";

/// Owns one canonical, nonauthorizing Storage deny-stage frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyStageHandoff {
    bytes: [u8; HANDOFF_BYTES],
}

impl DenyStageHandoff {
    /// Parses the exact Storage frame and recomputes its unkeyed commitment.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, phase, reserved bytes, zero identities,
    /// a nonzero pre-grant epoch, missing expiry, or a mismatched handoff ID.
    pub fn parse(input: &[u8]) -> Result<Self, OwnerPeerError> {
        let bytes: [u8; HANDOFF_BYTES] =
            input.try_into().map_err(|_| OwnerPeerError::Noncanonical)?;
        let id: [u8; 32] = Sha256::new()
            .chain_update(HANDOFF_DOMAIN)
            .chain_update(&bytes[48..])
            .finalize()
            .into();

        if &bytes[..8] != b"AOSKGH01"
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
            || bytes[16..48] != id
            || [
                &bytes[48..64],
                &bytes[64..72],
                &bytes[72..88],
                &bytes[88..120],
                &bytes[120..152],
                &bytes[152..184],
                &bytes[184..192],
                &bytes[192..224],
                &bytes[224..240],
                &bytes[240..248],
                &bytes[248..256],
                &bytes[256..264],
                &bytes[264..280],
                &bytes[280..288],
                &bytes[288..320],
                &bytes[320..328],
            ]
            .iter()
            .any(|field| field.iter().all(|byte| *byte == 0))
            || bytes[328..336] != [0; 8]
            || i64::from_be_bytes(
                bytes[336..344]
                    .try_into()
                    .map_err(|_| OwnerPeerError::Noncanonical)?,
            ) <= 0
        {
            return Err(OwnerPeerError::Noncanonical);
        }

        Ok(Self { bytes })
    }

    /// Returns the exact canonical wire bytes without granting authority.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HANDOFF_BYTES] {
        &self.bytes
    }

    /// Returns the unkeyed handoff commitment, not a signed identity.
    #[must_use]
    pub fn handoff_id(&self) -> [u8; 32] {
        self.bytes[16..48].try_into().unwrap_or([0; 32])
    }

    /// Returns the boot UUID bound by Storage's handoff commitment.
    #[must_use]
    pub fn boot_id(&self) -> [u8; 16] {
        self.bytes[224..240].try_into().unwrap_or([0; 16])
    }

    /// Returns the detached clone's unique mount ID.
    #[must_use]
    pub fn clone_mount_id(&self) -> u64 {
        u64::from_be_bytes(self.bytes[240..248].try_into().unwrap_or([0; 8]))
    }

    /// Returns the detached clone's root device and inode.
    #[must_use]
    pub fn clone_root(&self) -> (u64, u64) {
        (
            u64::from_be_bytes(self.bytes[248..256].try_into().unwrap_or([0; 8])),
            u64::from_be_bytes(self.bytes[256..264].try_into().unwrap_or([0; 8])),
        )
    }

    /// Returns the exact consumer cgroup kernfs ID expected on the second FD.
    #[must_use]
    pub fn cgroup_id(&self) -> u64 {
        u64::from_be_bytes(self.bytes[320..328].try_into().unwrap_or([0; 8]))
    }

    /// Returns the exclusive wall-clock expiry, not a currentness proof.
    #[must_use]
    pub fn exclusive_expiry_seconds(&self) -> i64 {
        i64::from_be_bytes(self.bytes[336..344].try_into().unwrap_or([0; 8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> [u8; HANDOFF_BYTES] {
        let mut bytes = [0_u8; HANDOFF_BYTES];
        bytes[..8].copy_from_slice(b"AOSKGH01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        for (start, end, value) in [
            (48, 64, 1),
            (72, 88, 2),
            (88, 120, 3),
            (120, 152, 4),
            (152, 184, 5),
            (192, 224, 6),
            (224, 240, 7),
            (264, 280, 8),
            (288, 320, 9),
        ] {
            bytes[start..end].fill(value);
        }
        for (offset, value) in [
            (64, 1_u64),
            (184, 2),
            (240, 3),
            (248, 4),
            (256, 5),
            (280, 6),
            (320, 7),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[336..344].copy_from_slice(&100_i64.to_be_bytes());
        let id: [u8; 32] = Sha256::new()
            .chain_update(HANDOFF_DOMAIN)
            .chain_update(&bytes[48..])
            .finalize()
            .into();
        bytes[16..48].copy_from_slice(&id);
        bytes
    }

    #[test]
    fn exact_handoff_rejects_wrong_length_epoch_hash_and_reserved_bytes() {
        let bytes = frame();
        assert!(DenyStageHandoff::parse(&bytes).is_ok());
        assert!(DenyStageHandoff::parse(&bytes[..343]).is_err());

        let mut changed = bytes;
        changed[328..336].copy_from_slice(&1_u64.to_be_bytes());
        assert!(DenyStageHandoff::parse(&changed).is_err());

        let mut changed = bytes;
        changed[11] = 1;
        assert!(DenyStageHandoff::parse(&changed).is_err());

        let mut changed = bytes;
        changed[320] ^= 1;
        assert!(DenyStageHandoff::parse(&changed).is_err());
    }
}

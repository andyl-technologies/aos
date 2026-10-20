//! Encodes the complete fixed preimage of a Root planning observation.
//!
//! ```text
//! native784 = AOSDPO02/version2/reserved | open32/challenge32/clock48 |
//!   namespace-commitment32/Ownership-commitment32 |
//!   namespace500 | active-Ownership92
//! namespace500 = rooted-before52/rooted-after52 |
//!   three-local-named-before132/three-held132/three-local-named-after132
//! file44 = device8/inode8/uid4/gid4/mode4/nlink8/size8
//! active-Ownership92 = PID4/invocation16/cgroup8/unit-digest32/exec-name-digest32
//! ```
//!
//! The fixed namespace names and their order are part of the versioned domain:
//! the root is `/var/lib/aos/sandbox/multi-node`; the three local names are
//! `coordinator-ownership-bootstrap-v1.bin`, `coordinator-ownership-v1.journal`
//! and `coordinator-ownership-v1.journal.lock`. A genuine Root producer also
//! observed ENOENT for each fixed Transfer journal, lock and compact temporary.
//! DATA decoding cannot establish that native fact, an active process, default
//! local configuration, or any authorization. Only the actual whole exchange
//! can lend its retained comparison result to a genuine Runtime collector.

use super::super::transport::{
    DeleteRootWireErrorV2, array, decode_clock, encode_clock, encode_header_v2, header_v2,
};
use super::{
    DeleteRootPlanningDataErrorV3,
};
use aos_sandbox_core::RawPairedClockSample;
use sha2::{Digest as _, Sha256};

/// Gives the exact full-preimage planning observation extent.
pub const DELETE_ROOT_PLANNING_NATIVE_BYTES_V2: usize = 784;
const MAGIC: &[u8; 8] = b"AOSDPO02";
const NAMESPACE_DOMAIN: &[u8] = b"aos.sandbox.delete-root.planning-namespace.v1\0";
const OWNERSHIP_DOMAIN: &[u8] = b"aos.sandbox.delete-root.planning-ownership.v1\0";

/// Records all native file coordinates used by the fixed planning comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningFileDataV1 {
    /// Gives the actual native device identifier.
    pub device: u64,
    /// Gives the actual native inode identifier.
    pub inode: u64,
    /// Gives the actual numeric owner.
    pub uid: u32,
    /// Gives the actual numeric group.
    pub gid: u32,
    /// Gives the complete native file type and permission bits.
    pub mode: u32,
    /// Gives the actual native link count.
    pub links: u64,
    /// Gives the independently sampled byte extent at this frontier.
    pub bytes: u64,
}

impl DeleteRootPlanningFileDataV1 {
    fn encode_into(self, bytes: &mut [u8]) {
        bytes[..8].copy_from_slice(&self.device.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.inode.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.uid.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.gid.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.mode.to_be_bytes());
        bytes[28..36].copy_from_slice(&self.links.to_be_bytes());
        bytes[36..44].copy_from_slice(&self.bytes.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        Ok(Self {
            device: u64::from_be_bytes(array(bytes, 0)?),
            inode: u64::from_be_bytes(array(bytes, 8)?),
            uid: u32::from_be_bytes(array(bytes, 16)?),
            gid: u32::from_be_bytes(array(bytes, 20)?),
            mode: u32::from_be_bytes(array(bytes, 24)?),
            links: u64::from_be_bytes(array(bytes, 28)?),
            bytes: u64::from_be_bytes(array(bytes, 36)?),
        })
    }

    fn identity(self) -> (u64, u64, u32, u32, u32, u64) {
        (
            self.device,
            self.inode,
            self.uid,
            self.gid,
            self.mode,
            self.links,
        )
    }
}

/// Records the actual rooted directory and unique kernel mount identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningDirectoryDataV1 {
    /// Records the actual rooted directory's native metadata.
    pub file: DeleteRootPlanningFileDataV1,
    /// Gives the kernel's unique nonreused mount identifier.
    pub mount: u64,
}

/// Records every retained rooted/local name boundary in its fixed order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningNamespaceDataV1 {
    /// Records the independent before and after rooted traversals.
    pub directories: [DeleteRootPlanningDirectoryDataV1; 2],
    /// Records the three names before entry, the same held FDs, and names after.
    pub local: [[DeleteRootPlanningFileDataV1; 3]; 3],
}

impl DeleteRootPlanningNamespaceDataV1 {
    fn encode(self) -> [u8; 500] {
        let mut bytes = [0; 500];
        for (index, directory) in self.directories.into_iter().enumerate() {
            let offset = index * 52;
            directory.file.encode_into(&mut bytes[offset..offset + 44]);
            bytes[offset + 44..offset + 52].copy_from_slice(&directory.mount.to_be_bytes());
        }
        for (index, file) in self.local.into_iter().flatten().enumerate() {
            let offset = 104 + index * 44;
            file.encode_into(&mut bytes[offset..offset + 44]);
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        let directory = |offset| -> Result<_, DeleteRootWireErrorV2> {
            Ok(DeleteRootPlanningDirectoryDataV1 {
                file: DeleteRootPlanningFileDataV1::decode(&bytes[offset..offset + 44])?,
                mount: u64::from_be_bytes(array(bytes, offset + 44)?),
            })
        };
        let group = |offset| -> Result<_, DeleteRootWireErrorV2> {
            Ok([
                DeleteRootPlanningFileDataV1::decode(&bytes[offset..offset + 44])?,
                DeleteRootPlanningFileDataV1::decode(&bytes[offset + 44..offset + 88])?,
                DeleteRootPlanningFileDataV1::decode(&bytes[offset + 88..offset + 132])?,
            ])
        };
        Ok(Self {
            directories: [directory(0)?, directory(52)?],
            local: [group(104)?, group(236)?, group(368)?],
        })
    }

    pub(super) fn require_canonical(self) -> Result<(), DeleteRootWireErrorV2> {
        for directory in self.directories {
            if directory.file.uid != 0
                || directory.file.mode != 0o40700
                || directory.file.device == 0
                || directory.file.inode == 0
                || directory.mount == 0
            {
                return Err(DeleteRootWireErrorV2::Association);
            }
        }
        if self.directories[0].file.identity() != self.directories[1].file.identity()
            || self.directories[0].mount != self.directories[1].mount
        {
            return Err(DeleteRootWireErrorV2::Association);
        }
        for index in 0..3 {
            let first = self.local[0][index];
            for group in self.local {
                let file = group[index];
                if file.uid != 0
                    || file.mode != 0o100600
                    || file.links != 1
                    || file.identity() != first.identity()
                {
                    return Err(DeleteRootWireErrorV2::Association);
                }
            }
        }
        Ok(())
    }

    /// Commits the complete fixed native preimage after comparing its DATA.
    ///
    /// # Errors
    /// Rejects changed local identities or a noncanonical rooted namespace.
    pub fn commitment_v1(self) -> Result<[u8; 32], DeleteRootPlanningDataErrorV3> {
        self.require_canonical()?;
        Ok(Sha256::new()
            .chain_update(NAMESPACE_DOMAIN)
            .chain_update(self.encode())
            .finalize()
            .into())
    }
}

/// Records the independently observed active local Ownership process generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningOwnershipDataV1 {
    /// Gives the genuine retained PID1 MainPID and same pidfd process.
    pub pid: u32,
    /// Gives the actual PID1 service invocation identifier.
    pub invocation: [u8; 16],
    /// Gives the exact kernel cgroup identifier from the same pidfd membership.
    pub cgroup: u64,
    /// Commits the actual immutable unit fragment measured and revalidated.
    pub unit: [u8; 32],
    /// Commits the actual singleton immutable executable locator.
    pub executable: [u8; 32],
}

impl DeleteRootPlanningOwnershipDataV1 {
    fn encode(self) -> [u8; 92] {
        let mut bytes = [0; 92];
        bytes[..4].copy_from_slice(&self.pid.to_be_bytes());
        bytes[4..20].copy_from_slice(&self.invocation);
        bytes[20..28].copy_from_slice(&self.cgroup.to_be_bytes());
        bytes[28..60].copy_from_slice(&self.unit);
        bytes[60..].copy_from_slice(&self.executable);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        Ok(Self {
            pid: u32::from_be_bytes(array(bytes, 0)?),
            invocation: array(bytes, 4)?,
            cgroup: u64::from_be_bytes(array(bytes, 20)?),
            unit: array(bytes, 28)?,
            executable: array(bytes, 60)?,
        })
    }

    /// Commits the complete observed generation preimage without granting it.
    ///
    /// # Errors
    /// Rejects absent process, invocation or kernel membership identifiers.
    pub fn commitment_v1(self) -> Result<[u8; 32], DeleteRootPlanningDataErrorV3> {
        if self.pid == 0 || self.invocation == [0; 16] || self.cgroup == 0 {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(Sha256::new()
            .chain_update(OWNERSHIP_DOMAIN)
            .chain_update(self.encode())
            .finalize()
            .into())
    }
}

/// Carries the complete canonical preimage alongside both named commitments.
///
/// The actual receiving owner retains the authenticated whole Root exchange.
/// This native submodel has no constructor for that private receiving owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPlanningNativeDataV2 {
    /// Commits the entire original authorized opening.
    pub open: [u8; 32],
    /// Commits the actual fresh Root challenge.
    pub challenge: [u8; 32],
    /// Gives the actual final Root paired sample after independent native posts.
    pub clock: RawPairedClockSample,
    /// Contains both rooted traversals and all three local file boundaries.
    pub namespace: DeleteRootPlanningNamespaceDataV1,
    /// Contains actual active Ownership process-generation coordinates.
    pub ownership: DeleteRootPlanningOwnershipDataV1,
}

impl DeleteRootPlanningNativeDataV2 {

    /// Encodes the native component of the complete trust-bearing V2 frame.
    ///
    /// # Errors
    /// Refuses malformed fixed namespace/process comparison fields.
    pub(super) fn encode_v2(self)
        -> Result<[u8; DELETE_ROOT_PLANNING_NATIVE_BYTES_V2], DeleteRootPlanningDataErrorV3> {
        self.require_canonical()?;
        let mut bytes = [0; DELETE_ROOT_PLANNING_NATIVE_BYTES_V2];
        encode_header_v2(&mut bytes, MAGIC);
        bytes[16..48].copy_from_slice(&self.open);
        bytes[48..80].copy_from_slice(&self.challenge);
        encode_clock(&mut bytes, 80, self.clock);
        bytes[128..160].copy_from_slice(&self.namespace.commitment_v1()?);
        bytes[160..192].copy_from_slice(&self.ownership.commitment_v1()?);
        bytes[192..692].copy_from_slice(&self.namespace.encode());
        bytes[692..].copy_from_slice(&self.ownership.encode());
        Ok(bytes)
    }

    /// Decodes only the V2 native component within the full trust frame.
    ///
    /// # Errors
    /// Refuses another header, malformed fields or changed commitments.
    pub(super) fn decode_v2(bytes: &[u8]) -> Result<Self, DeleteRootPlanningDataErrorV3> {
        header_v2(bytes, DELETE_ROOT_PLANNING_NATIVE_BYTES_V2, MAGIC)?;
        let value = Self {
            open: array(bytes, 16)?,
            challenge: array(bytes, 48)?,
            clock: decode_clock(bytes, 80)?,
            namespace: DeleteRootPlanningNamespaceDataV1::decode(&bytes[192..692])?,
            ownership: DeleteRootPlanningOwnershipDataV1::decode(&bytes[692..])?,
        };
        value.require_canonical()?;
        if bytes[128..160] != value.namespace.commitment_v1()?
            || bytes[160..192] != value.ownership.commitment_v1()?
        {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(value)
    }

    pub(super) fn require_canonical(self) -> Result<(), DeleteRootPlanningDataErrorV3> {
        if self.open == [0; 32] || self.challenge == [0; 32] {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        self.namespace.require_canonical()?;
        self.ownership.commitment_v1()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn observation() -> DeleteRootPlanningNativeDataV2 {
        let file = DeleteRootPlanningFileDataV1 {
            device: 1,
            inode: 2,
            uid: 0,
            gid: 0,
            mode: 0o100600,
            links: 1,
            bytes: 128,
        };
        let directory = DeleteRootPlanningDirectoryDataV1 {
            file: DeleteRootPlanningFileDataV1 {
                inode: 3,
                mode: 0o40700,
                links: 2,
                ..file
            },
            mount: 9,
        };
        DeleteRootPlanningNativeDataV2 {
            open: [3; 32],
            challenge: [4; 32],
            clock: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted([1; 16]).unwrap(),
                [2; 16],
                100,
                10_000_000_000,
            )
            .unwrap(),
            namespace: DeleteRootPlanningNamespaceDataV1 {
                directories: [directory; 2],
                local: [[file; 3]; 3],
            },
            ownership: DeleteRootPlanningOwnershipDataV1 {
                pid: 42,
                invocation: [5; 16],
                cgroup: 6,
                unit: [7; 32],
                executable: [8; 32],
            },
        }
    }

    #[test]
    fn every_observed_preimage_byte_is_bound_by_its_named_commitment() {
        let original = observation();
        let bytes = original.encode_v2().unwrap();
        assert_eq!(
            DeleteRootPlanningNativeDataV2::decode_v2(&bytes).unwrap(),
            original
        );

        for index in 128..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                DeleteRootPlanningNativeDataV2::decode_v2(&changed).is_err(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn active_local_append_is_preserved_as_a_distinct_observed_boundary() {
        let mut changed = observation();
        changed.namespace.local[2][1].bytes += 128;
        let original = observation().namespace.commitment_v1().unwrap();
        let appended = changed.namespace.commitment_v1().unwrap();

        assert_ne!(original, appended);
        assert!(changed.encode_v2().is_ok());
        changed.namespace.local[2][1].inode += 1;
        assert!(changed.encode_v2().is_err());
    }

    #[test]
    fn missing_process_or_changed_mount_cannot_replace_the_observed_generation() {
        let mut changed = observation();
        changed.ownership.pid = 0;
        assert!(changed.encode_v2().is_err());
        changed = observation();
        changed.ownership.invocation = [0; 16];
        assert!(changed.encode_v2().is_err());
        changed = observation();
        changed.namespace.directories[1].mount += 1;
        assert!(changed.encode_v2().is_err());
    }

    #[test]
    fn old_purpose_and_noncanonical_framing_are_refused() {
        let original = observation().encode_v2().unwrap();
        let mut changed = original;
        changed[..8].copy_from_slice(b"AOSDRQ01");
        assert!(DeleteRootPlanningNativeDataV2::decode_v2(&changed).is_err());
        for index in [8, 10, 15] {
            changed = original;
            changed[index] ^= 1;
            assert!(DeleteRootPlanningNativeDataV2::decode_v2(&changed).is_err());
        }
        assert!(DeleteRootPlanningNativeDataV2::decode_v2(&original[..783]).is_err());
    }
}

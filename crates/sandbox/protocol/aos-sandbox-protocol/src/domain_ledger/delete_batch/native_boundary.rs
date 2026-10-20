//! Names V2 journal-prefix and actual Root namespace-absence boundaries.
//!
//! ```text
//! owner48 = role:u8 | boundary:u8 | reserved:2 | coordinate:u64be |
//!           complete-count:u32be | full-preimage-digest:32
//! boundary = journal-NEXT:1 | Root-namespace-directory-inode:2
//! ```
//!
//! These are passive comparison coordinates. Only genuine native owners can
//! supply the complete current preimages; a digest or count creates no proof.
//! Historical V1 retains its zero reserved bytes and sequence interpretation.

use super::*;

/// Distinguishes a real journal prefix from a real default-local absence sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteBatchNativeBoundaryDataV2 {
    /// Records the actual next sequence of the held native journal prefix.
    JournalPrefix {
        /// Gives the checked native next sequence, never an inventory row count.
        next_sequence: u64,
    },
    /// Records the real rooted directory from a complete Transfer absence cut.
    ///
    /// The complete dev/mount/name/trust preimage and nine native ENOENTs, plus
    /// genuine default-off/never-opened Runtime conjunction, remain required.
    /// The inode is not a journal sequence or a cgroup identifier.
    RootNamespaceAbsence {
        /// Gives the actual retained rooted directory inode.
        directory_inode: u64,
    },
}

/// Commits one complete owner inventory and its explicitly typed native boundary.
///
/// This DATA has no effect, native currentness or six-owner constructor. A
/// production cut must derive/recompute it from the same retained original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteBatchOwnerCutDataV2 {
    /// Names the native coordinate's exact interpretation.
    pub boundary: DeleteBatchNativeBoundaryDataV2,
    /// Counts the complete selected inventory; typed absence requires zero.
    pub count: u32,
    /// Commits its full canonical inventory, endpoint, generation and native preimage.
    pub digest: [u8; 32],
}

impl DeleteBatchOwnerCutDataV2 {
    /// Encodes this role's comparison descriptor through the sole V2 codec.
    ///
    /// The result is passive canonical DATA; it supplies no native or six proof.
    ///
    /// # Errors
    /// Refuses the established invalid role/boundary/count/digest combination.
    pub fn canonical_descriptor_data_v2(self, role: u8) -> Result<[u8; 48], LifecycleModelError> {
        self.require_role_v2(role)?;
        let mut bytes = [0; 48];
        self.write_descriptor_v2(role, &mut bytes);
        Ok(bytes)
    }

    pub(super) fn require_role_v2(self, role: u8) -> Result<(), LifecycleModelError> {
        if !(1..=6).contains(&role) || self.count as usize > MAXIMUM_ROWS || zero(&self.digest) {
            return Err(corrupt());
        }
        match self.boundary {
            DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence }
                if next_sequence != 0 && next_sequence != u64::MAX => Ok(()),
            DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode }
                if role == 6 && self.count == 0
                    && directory_inode != 0 && directory_inode != u64::MAX => Ok(()),
            _ => Err(corrupt()),
        }
    }

    pub(super) fn write_descriptor_v2(self, role: u8, bytes: &mut [u8]) {
        bytes[0] = role;
        let (kind, coordinate) = match self.boundary {
            DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence } => (1, next_sequence),
            DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode } => (2, directory_inode),
        };
        bytes[1] = kind;
        bytes[2..4].fill(0);
        bytes[4..12].copy_from_slice(&coordinate.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.count.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.digest);
    }

    pub(crate) fn decode_descriptor_v2(role: u8, bytes: &[u8]) -> Result<Self, LifecycleModelError> {
        if bytes.len() != 48 || bytes[0] != role || !zero(&bytes[2..4]) {
            return Err(corrupt());
        }
        let coordinate = number64(&bytes[4..12])?;
        let boundary = match bytes[1] {
            1 => DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: coordinate },
            2 => DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: coordinate },
            _ => return Err(corrupt()),
        };
        let value = Self { boundary, count: number32(&bytes[12..16])?, digest: array32(&bytes[16..48]) };
        value.require_role_v2(role)?;
        Ok(value)
    }
}

impl DeleteBatchViewV1<'_> {
    /// Borrows one checked V2 owner's exact native-boundary interpretation.
    ///
    /// This is historical DATA, never a live native observation or grant.
    ///
    /// # Errors
    /// Refuses historical V1, a role outside 1..=6, or malformed V2 coordinates.
    pub fn native_owner_cut_v2(self, role: u8) -> Result<DeleteBatchOwnerCutDataV2, LifecycleModelError> {
        if self.version() != 2 || !(1..=6).contains(&role) { return Err(corrupt()); }
        let start = 320 + (usize::from(role) - 1) * 48;
        DeleteBatchOwnerCutDataV2::decode_descriptor_v2(role, &self.bytes[start..start + 48])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_coordinate_is_explicit_and_only_the_real_transfer_slot_can_use_it() {
        let cut = DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: 73 },
            count: 0, digest: [9; 32],
        };
        let mut bytes = [0; 48];
        cut.write_descriptor_v2(6, &mut bytes);

        assert_eq!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(6, &bytes).unwrap(), cut);
        assert_eq!(bytes[1], 2);
        for role in 1..=5 {
            cut.write_descriptor_v2(role, &mut bytes);
            assert!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(role, &bytes).is_err());
        }
        cut.write_descriptor_v2(6, &mut bytes);
        bytes[15] = 1;
        assert!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(6, &bytes).is_err());
    }

    #[test]
    fn unknown_boundary_zero_coordinate_and_reserved_mutations_refuse() {
        let cut = DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: 17 },
            count: 0, digest: [7; 32],
        };
        let mut bytes = [0; 48];
        cut.write_descriptor_v2(1, &mut bytes);
        assert_eq!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(1, &bytes).unwrap(), cut);

        for kind in [0, 3, 255] {
            bytes[1] = kind;
            assert!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(1, &bytes).is_err());
        }
        cut.write_descriptor_v2(1, &mut bytes);
        bytes[4..12].fill(0);
        assert!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(1, &bytes).is_err());
        cut.write_descriptor_v2(1, &mut bytes);
        bytes[2] = 1;
        assert!(DeleteBatchOwnerCutDataV2::decode_descriptor_v2(1, &bytes).is_err());
    }
}

//! Observes the mount actually retained by an open descriptor.
//!
//! Inherited files can refer to mounts outside the receiver's private mount
//! namespace. Their per-mount attributes must come from that retained mount,
//! rather than a namespace lookup or superblock-only read-only observation.

use std::os::fd::BorrowedFd;

use aos_linux_descriptors::{Error, Result};

use super::MountId;
use crate::uapi::{self, MOUNT_ATTR_RDONLY, RawStatMount, STATMOUNT_MNT_BASIC};

/// Records identity and per-mount attributes from the original descriptor.
///
/// This observation supplies no namespace-membership or immutability proof.
/// The caller retains the descriptor and repeats its own currentness checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorMountObservation {
    /// Identifies the mount retained by the descriptor for this kernel lifetime.
    pub mount_id: MountId,
    /// Records the kernel's per-mount `MOUNT_ATTR_*` flags.
    pub mount_attributes: u64,
}

impl DescriptorMountObservation {
    /// Observes the held mount without resolving it in the caller's namespace.
    ///
    /// Uses `statx(AT_EMPTY_PATH)` and `statmount(STATMOUNT_BY_FD)` on the same
    /// borrowed descriptor. Only fixed-width mount basics are requested; no
    /// topology, string buffer, descriptor duplication or path lookup is used.
    ///
    /// # Errors
    /// Refuses syscall or access failures, unsupported descriptor-based mount
    /// observation, malformed output, missing basics or a changed mount ID.
    pub fn capture(descriptor: BorrowedFd<'_>) -> Result<Self> {
        let expected = MountId::from_fd(descriptor)?;
        let observed = uapi::statmount_fd_basic(descriptor)?;
        Self::decode(expected, &observed)
    }

    /// Reports the held mount's `MOUNT_ATTR_RDONLY` flag.
    ///
    /// This preserves the per-mount check independently of superblock flags.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        self.mount_attributes & MOUNT_ATTR_RDONLY != 0
    }

    fn decode(expected: MountId, observed: &RawStatMount) -> Result<Self> {
        if observed.size as usize != std::mem::size_of::<RawStatMount>()
            || observed.mask & STATMOUNT_MNT_BASIC == 0
            || observed.mount_id != expected.get()
        {
            return Err(Error::MalformedKernelResponse {
                object: "descriptor statmount",
                message: "missing fixed mount basics or inconsistent mount identity".to_owned(),
            });
        }

        Ok(Self {
            mount_id: expected,
            mount_attributes: observed.mount_attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_basics_require_complete_output_and_the_original_identity() {
        let expected = MountId::new(17).unwrap();
        let mut observed = RawStatMount::default();
        observed.size = std::mem::size_of::<RawStatMount>() as u32;
        observed.mask = STATMOUNT_MNT_BASIC;
        observed.mount_id = expected.get();
        observed.mount_attributes = MOUNT_ATTR_RDONLY;

        assert!(
            DescriptorMountObservation::decode(expected, &observed)
                .unwrap()
                .is_read_only()
        );

        observed.mount_attributes = 0;
        observed.superblock_flags = 1;
        assert!(
            !DescriptorMountObservation::decode(expected, &observed)
                .unwrap()
                .is_read_only()
        );

        observed.mount_id += 1;
        assert!(DescriptorMountObservation::decode(expected, &observed).is_err());
        observed.mount_id = expected.get();
        observed.mask = 0;
        assert!(DescriptorMountObservation::decode(expected, &observed).is_err());
        observed.mask = STATMOUNT_MNT_BASIC;
        observed.size -= 1;
        assert!(DescriptorMountObservation::decode(expected, &observed).is_err());
    }
}

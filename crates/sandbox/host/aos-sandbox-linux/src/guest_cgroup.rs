//! Existing nspawn-to-Guest payload-cgroup descriptor custody.
//!
//! ```text
//! FD6 = existing mounted payload cgroup2 directory
//! FD7 = sealed AOSGCG01 | FD4.dev:u64 | FD4.ino:u64 | FD4.size:u64
//!                       | FD6.dev:u64 | FD6.ino:u64 (all big endian)
//! ```
//!
//! This bounded record carries no key, copied credential, grant, path, or
//! signing domain. The two live descriptor pins and original FD4 parser are
//! joined independently. A directory FD is not a read-only delegation.

use std::os::fd::OwnedFd;

use crate::cgroup::RetainedCgroupAnchor;
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

mod control;
mod directory;
mod topology;
mod inherited;
mod handoff;
mod completion;
mod agent_completion;
mod agent_parent;
mod ssh;
pub use ssh::{GuestSshScopeOriginalV1, GuestSshStandingOriginalV1};
pub use topology::{GuestRuntimeTopologyClosedV1, GuestRuntimeTopologyOriginalV1,
    GUEST_PID1_STARTUP_CONTROL_BYTES_V1};
pub use ssh::source::GuestSshBirthSourceOriginalV1;
pub(crate) use ssh::source::GuestSshBirthSourceDataV1;

fn require_owner_retaining(slot: &mut Option<Box<crate::guest_confinement::GuestOwnerOriginalV2>>)
    -> Result<()>
{
    if slot.is_some() {
        return Err(Error::invalid("Guest Owner original", "native predicate already entered"));
    }
    *slot = Some(Box::new(crate::guest_confinement::GuestOwnerOriginalV2::new()));
    let original = slot.as_mut().ok_or_else(|| Error::invalid("Guest Owner original", "missing destination"))?;
    original.capture_once_v2()?;
    original.dispose_positive_once_v2()?;
    drop(slot.take());
    Ok(())
}

/// Names the fixed inherited directory role, reserved before startup duplicates.
pub const GUEST_PAYLOAD_CGROUP_FD: i32 = 6;
/// Names the fixed sealed descriptor-identity join, never an authorizer.
pub const GUEST_CGROUP_CUSTODY_FD: i32 = 7;
/// Bounds the complete version-one custody carrier.
pub const GUEST_CGROUP_CUSTODY_BYTES: usize = 48;

/// Retains only the existing mounted payload cgroup chosen by nspawn.
#[derive(Debug)]
pub struct GuestPayloadCgroupCustodyV1 {
    payload: RetainedCgroupAnchor,
    provisioning: OwnedFd,
}

impl GuestPayloadCgroupCustodyV1 {
    /// Adopts fixed FD6/7 before any FD3/4/5 duplication can reuse those slots.
    ///
    /// The original numeric entries remain unowned for the fixed bootstrap's
    /// agent spawn. Fresh duplicates are CLOEXEC; callers must separately close
    /// originals before systemd or any Tenant exec. Original FD4 parsing and
    /// runtime/trust matching remain with their existing protected owner.
    ///
    /// # Errors
    ///
    /// Rejects a foreign subject, unsealed/partial carrier, changed descriptor
    /// identity, non-cgroup2 root, wrong live self membership, or kernel error.
    pub fn from_inherited() -> Result<Self> {
        inherited::GuestPayloadCgroupCustodyOriginalV2::ordinary()
    }

    /// Duplicates the same retained original provisioning inode for its existing parser.
    ///
    /// # Errors
    ///
    /// Returns an error when the kernel cannot make a close-on-exec duplicate.
    pub fn original_provisioning(&self) -> Result<OwnedFd> {
        rustix::io::fcntl_dupfd_cloexec(&self.provisioning, 64)
            .map_err(io("duplicate retained original Guest provisioning"))
    }

    /// Creates or reopens only the fixed Owner-private execution-root descendant.
    ///
    /// Existing execution children are never adopted here. This directory is
    /// merely a retained creation scope beneath the original payload root.
    ///
    /// # Errors
    ///
    /// Rejects an inaccessible/deactivated payload root, unsafe descendant,
    /// unavailable write delegation, or kernel error.
    pub fn execution_root(&self) -> Result<RetainedCgroupAnchor> {
        directory::DirectoryOriginalV1::ordinary_execution_root(&self.payload)
    }
}

fn require_carrier(bytes: &[u8], expected: [u64; 5]) -> Result<()> {
    if bytes.len() != GUEST_CGROUP_CUSTODY_BYTES || bytes.get(..8) != Some(b"AOSGCG01") {
        return Err(Error::invalid(
            "Guest cgroup carrier",
            "version or exact length differs",
        ));
    }
    for (index, value) in expected.into_iter().enumerate() {
        if bytes[8 + index * 8..16 + index * 8] != value.to_be_bytes() {
            return Err(Error::invalid(
                "Guest cgroup carrier",
                "retained descriptor join differs",
            ));
        }
    }
    Ok(())
}

fn io(operation: &'static str) -> impl FnOnce(rustix::io::Errno) -> Error {
    move |source| Error::Syscall {
        operation,
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    //! Carrier shape tests do not substitute for actual delegated-cgroup VM checks.
    use super::*;

    #[test]
    fn carrier_rejects_partial_foreign_and_substituted_originals() {
        let fields = [1, 2, 258, 3, 4];
        let mut bytes = b"AOSGCG01".to_vec();
        for field in fields {
            bytes.extend_from_slice(&u64::to_be_bytes(field));
        }
        require_carrier(&bytes, fields).unwrap();
        assert!(require_carrier(&bytes[..47], fields).is_err());
        assert!(require_carrier(&bytes, [1, 5, 258, 3, 4]).is_err());
        assert!(require_carrier(&bytes, [1, 2, 258, 3, 5]).is_err());
        bytes[7] = b'2';
        assert!(require_carrier(&bytes, fields).is_err());
    }
}

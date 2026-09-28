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

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use rustix::fs::{FileType, Mode, SealFlags, fcntl_get_seals, fstat, mkdirat};

use crate::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use crate::guest_confinement::{require_guest_cgroup_object, require_guest_owner};
use crate::immutable_file::SealedMemfdMapping;
use crate::inherited_fd::duplicate_inherited_descriptor;
use crate::pidfd::PidFd;
use crate::{Error, Result};

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
        require_guest_owner()?;
        let payload = duplicate_inherited_descriptor(GUEST_PAYLOAD_CGROUP_FD)?;
        let carrier = duplicate_inherited_descriptor(GUEST_CGROUP_CUSTODY_FD)?;
        let provisioning = duplicate_inherited_descriptor(4)?;
        let seals =
            fcntl_get_seals(&provisioning).map_err(io("read original Guest provisioning seals"))?;
        if !seals.contains(SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE)
        {
            return Err(Error::invalid(
                "Guest cgroup custody",
                "original provisioning is not fully sealed",
            ));
        }
        let credential = fstat(&provisioning).map_err(io("stat original Guest provisioning"))?;
        let directory = fstat(&payload).map_err(io("stat Guest payload cgroup"))?;
        let expected = [
            credential.st_dev,
            credential.st_ino,
            credential.st_size as u64,
            directory.st_dev,
            directory.st_ino,
        ];
        SealedMemfdMapping::run(
            carrier,
            GUEST_CGROUP_CUSTODY_BYTES as u64,
            GUEST_CGROUP_CUSTODY_BYTES as u64,
            |bytes, _identity| require_carrier(bytes, expected),
        )
        .map_err(|_| Error::invalid("Guest cgroup carrier", "sealed carrier is unavailable"))??;
        if FileType::from_raw_mode(credential.st_mode) != FileType::RegularFile
            || credential.st_size != 258
            || directory.st_uid != 0
            || directory.st_mode & 0o022 != 0
        {
            return Err(Error::invalid(
                "Guest cgroup custody",
                "original descriptor profile differs",
            ));
        }
        let payload = CgroupV2Root::from_owned(payload)?.resolve(Path::new("."))?;
        require_guest_cgroup_object(payload.as_fd())?;
        let pid = NonZeroU32::new(std::process::id())
            .ok_or_else(|| Error::invalid("Guest owner", "PID is zero"))?;
        payload.verify_exact_membership(&PidFd::open(pid)?)?;
        Ok(Self {
            payload,
            provisioning,
        })
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
        require_guest_owner()?;
        self.payload.validate_active()?;
        match mkdirat(
            self.payload.as_fd(),
            "aos-executions-v1",
            Mode::from_raw_mode(0o700),
        ) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(source) => return Err(io("create private Guest execution root")(source)),
        }
        let root = self
            .payload
            .resolve_descendant(Path::new("aos-executions-v1"))?;
        let stat = fstat(root.as_fd()).map_err(io("stat private Guest execution root"))?;
        require_guest_cgroup_object(root.as_fd())?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o777 != 0o700 {
            return Err(Error::invalid(
                "Guest execution root",
                "private directory profile differs",
            ));
        }
        Ok(root)
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

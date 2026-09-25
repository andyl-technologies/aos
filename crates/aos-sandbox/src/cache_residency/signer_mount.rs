//! Exact read-only idmapped Cache mount checks for a separate signer UID.
//!
//! The signer sees only the two Cache roots, remapped from Controller UID to
//! its own UID. The on-disk roots are siblings below a root-owned parent so
//! the signer can re-resolve each original fixed name without traversing it.

use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::{AtFlags, CWD, StatVfsMountFlags, StatxAttributes, StatxFlags, statvfs, statx};

/// Identifies the mounted inode and its mount across one bounded readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SignerMountWitness {
    mount_id: u64,
    device: u64,
    inode: u64,
    source_uid: u32,
}

impl SignerMountWitness {
    /// Returns the exact mounted root inode expected from an opened descriptor.
    pub(super) const fn root_identity(self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Returns the original Cache owner UID, before the signer-only idmap.
    pub(super) const fn source_uid(self) -> u32 {
        self.source_uid
    }

    /// Rejects a descriptor opened through a transient replacement mount.
    pub(super) fn matches_opened_root(self, device: u64, inode: u64) -> bool {
        (device, inode) == self.root_identity()
    }
}

/// Checks a fixed signer mount and the original Controller-owned root name.
pub(super) fn require_signer_mount(
    view: &str,
    source: &str,
    signer_uid: u32,
) -> io::Result<SignerMountWitness> {
    let signer_gid = rustix::process::getegid().as_raw();
    if signer_uid == 0 || signer_gid == 0 {
        return Err(invalid_mount());
    }

    for parent in [
        "/var",
        "/var/lib",
        "/var/lib/aos",
        "/var/lib/aos/sandbox",
        "/run",
        "/run/aos",
    ] {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid_mount());
        }
    }

    let original = fs::symlink_metadata(source)?;
    let mapped = fs::symlink_metadata(view)?;
    if !original.file_type().is_dir()
        || !mapped.file_type().is_dir()
        || original.uid() == 0
        || original.uid() == signer_uid
        || original.gid() == 0
        || original.gid() == signer_gid
        || original.mode() & 0o7777 != 0o700
        || mapped.uid() != signer_uid
        || mapped.gid() != signer_gid
        || mapped.mode() & 0o7777 != 0o700
        || (original.dev(), original.ino()) != (mapped.dev(), mapped.ino())
    {
        return Err(invalid_mount());
    }

    let mounted = statx(
        CWD,
        view,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )?;
    let parent = statx(
        CWD,
        "/run/aos",
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )?;
    let flags = statvfs(view)?.f_flag;
    let required = StatVfsMountFlags::RDONLY
        | StatVfsMountFlags::NOSUID
        | StatVfsMountFlags::NODEV
        | StatVfsMountFlags::NOEXEC;
    if mounted.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || parent.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || mounted.stx_mnt_id == parent.stx_mnt_id
        || !mounted
            .stx_attributes_mask
            .contains(StatxAttributes::MOUNT_ROOT)
        || !mounted.stx_attributes.contains(StatxAttributes::MOUNT_ROOT)
        || !flags.contains(required)
    {
        return Err(invalid_mount());
    }

    let mut mountinfo = String::new();
    fs::File::open("/proc/self/mountinfo")?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut mountinfo)?;
    if mountinfo.len() > 1024 * 1024 || !has_exact_mount(&mountinfo, mounted.stx_mnt_id, view) {
        return Err(invalid_mount());
    }

    Ok(SignerMountWitness {
        mount_id: mounted.stx_mnt_id,
        device: mapped.dev(),
        inode: mapped.ino(),
        source_uid: original.uid(),
    })
}

fn has_exact_mount(mountinfo: &str, mount_id: u64, view: &str) -> bool {
    mountinfo
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let id = fields.next().and_then(|value| value.parse::<u64>().ok());
            let _parent = fields.next();
            let _device = fields.next();
            let _root = fields.next();
            let path = fields.next();
            let options = fields.next();
            id == Some(mount_id)
                && path == Some(view)
                && options.is_some_and(|options| {
                    ["ro", "nosuid", "nodev", "noexec", "nosymfollow"]
                        .into_iter()
                        .all(|required| options.split(',').any(|option| option == required))
                })
        })
        .count()
        == 1
}

fn invalid_mount() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe Cache signer view")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_mount_requires_one_exact_read_only_name() {
        let view = "/run/aos/sandbox-cache-signer-objects";
        let valid =
            format!("42 1 0:2 / {view} ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/test rw");
        assert!(has_exact_mount(&valid, 42, view));
        assert!(!has_exact_mount(&valid, 43, view));
        assert!(!has_exact_mount(
            &valid.replace("nosymfollow", "symfollow"),
            42,
            view
        ));
        assert!(!has_exact_mount(&format!("{valid}\n{valid}"), 42, view));
    }

    #[test]
    fn opened_inode_must_match_mount_witness() {
        let mount = SignerMountWitness {
            mount_id: 42,
            device: 7,
            inode: 11,
            source_uid: 811,
        };

        assert!(mount.matches_opened_root(7, 11));
        assert!(!mount.matches_opened_root(7, 12));
        assert!(!mount.matches_opened_root(8, 11));
    }
}

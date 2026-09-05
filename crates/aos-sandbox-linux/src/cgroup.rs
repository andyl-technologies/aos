//! Retained kernel cgroup-v2 directory identity and exact membership snapshots.
//!
//! The supported profile is a 64-bit Linux kernel/process. Linux 6.18.33
//! `include/linux/cgroup.h:cgroup_id` returns `cgrp->kn->id`, while
//! `include/linux/kernfs.h:kernfs_id_ino` preserves that complete ID only on
//! 64-bit kernels. Admission checks the descriptor's cgroup2 filesystem before
//! interpreting its inode number; an ordinary filesystem inode is never a
//! cgroup identifier. A retained inode pins its kernfs node against ID reuse.
//!
//! Directory link counts do not establish liveness: kernfs refreshes them even
//! for removed directories. Instead, a fresh read-only open of `cgroup.procs`
//! observes an active kernfs file (`fs/kernfs/file.c:kernfs_fop_open`). This is
//! available on the hierarchy root too, unlike `cgroup.events`. No task list is
//! read and no cgroup is modified. None of these observations fence migration,
//! removal, process exit, or a subsequent effect.

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Component, Path};

use crate::path::{BeneathRoot, ResolveOptions};
use crate::pidfd::{PidFd, PidFdInfo};
use crate::{Error, Result, uapi};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAXIMUM_DESCENDANT_HINT_BYTES: usize = 4096;

/// Retains a kernel cgroup-v2 directory as a strict descendant-resolution root.
///
/// The caller chooses its trusted scope; this type proves neither that the
/// root is the global hierarchy root nor that a particular principal owns it.
#[derive(Debug)]
pub struct CgroupV2Root {
    anchor: RetainedCgroupAnchor,
}

impl CgroupV2Root {
    /// Adopts an owned cgroup-v2 directory after kernel identity and active-file checks.
    ///
    /// # Errors
    ///
    /// Rejects unsupported word size, non-directory or non-cgroup2 descriptors,
    /// zero identity, inaccessible/deactivated `cgroup.procs`, and kernel errors.
    pub fn from_owned(fd: OwnedFd) -> Result<Self> {
        Self::try_from(BeneathRoot::from_owned(fd)?)
    }

    /// Resolves and retains one exact cgroup beneath this root.
    ///
    /// `.` selects the root itself. Resolution rejects symlinks, magic links,
    /// mount crossings, absolute paths and parent traversal using `openat2`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed strict resolution, a stale
    /// root or target, unsupported filesystem identity, or kernel failures.
    pub fn resolve(&self, relative: &Path) -> Result<RetainedCgroupAnchor> {
        self.anchor.resolve_child(relative)
    }

    /// Borrows the retained resolution-root descriptor.
    ///
    /// Subsequent descriptor-relative operations retain ordinary kernel access
    /// checks; this borrow is not a read-only restriction on the subtree.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.anchor.as_fd()
    }
}

impl TryFrom<BeneathRoot> for CgroupV2Root {
    type Error = Error;

    /// Validates and consumes an existing descriptor-relative root as cgroup-v2 scope.
    ///
    /// # Errors
    ///
    /// Returns the same filesystem, active-file and platform errors as
    /// [`Self::from_owned`], without replacing the retained descriptor.
    fn try_from(root: BeneathRoot) -> Result<Self> {
        Ok(Self {
            anchor: RetainedCgroupAnchor::new(root)?,
        })
    }
}

/// Pins one exact cgroup-v2 object and its complete kernel identifier.
///
/// Exact and explicitly hinted descendant checks remain distinct. The retained
/// FD prevents reuse of this object's kernfs identity, but does not prevent
/// cgroup removal or movement of processes. Neither the ID nor a snapshot grants an
/// application principal, service provenance, or filesystem/effect authority.
#[derive(Debug)]
pub struct RetainedCgroupAnchor {
    root: BeneathRoot,
    kernel_id: u64,
}

impl RetainedCgroupAnchor {
    /// Reobserves the retained cgroup's filesystem identity and active kernfs file.
    ///
    /// This does not authenticate a member or fence later removal. It allows
    /// trusted provisioning to reject a stale anchor before exposing a channel.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained identity is invalid or a fresh
    /// `cgroup.procs` open cannot obtain an active kernel reference.
    pub fn validate_current(&self) -> Result<()> {
        self.validate_active()
    }

    fn new(root: BeneathRoot) -> Result<Self> {
        if !cfg!(target_pointer_width = "64") {
            return Err(Error::invalid(
                "cgroup identity profile",
                "requires a 64-bit kernel/process",
            ));
        }
        let anchor = Self {
            kernel_id: root.identity().inode,
            root,
        };
        anchor.validate_active()?;
        Ok(anchor)
    }

    /// Returns the retained object's full kernel cgroup ID, not an authorization token.
    #[must_use]
    pub const fn kernel_id(&self) -> u64 {
        self.kernel_id
    }

    /// Borrows the descriptor that keeps the exact kernfs identity pinned.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// Observes exact cgroup membership of a retained live process.
    ///
    /// Checks active-file availability, reads fresh pidfd information, compares
    /// the complete cgroup ID, checks active-file availability again, and rereads
    /// pidfd information before final liveness. Both observations must agree on
    /// PID, thread group and cgroup. The freshest information is returned; it is
    /// not a migration lock, subtree proof, or authority for a later effect.
    /// Migration away and back between observations is not detected.
    ///
    /// # Errors
    ///
    /// Rejects an inaccessible/deactivated anchor, omitted cgroup information,
    /// different exact membership, process exit, or any kernel failure.
    pub fn verify_exact_membership(&self, process: &PidFd) -> Result<PidFdInfo> {
        self.validate_active()?;
        let info = process.info()?;
        if info.cgroup_id() != Some(self.kernel_id) {
            return Err(Error::invalid(
                "exact cgroup membership",
                "pidfd does not name this cgroup",
            ));
        }
        self.validate_active()?;
        recheck_process(process, info)
    }

    /// Observes membership in a strictly resolved proper descendant cgroup.
    ///
    /// The relative hint locates a candidate; it is not trusted membership
    /// evidence. Strict bounded resolution beneath this retained anchor and
    /// fresh pidfd cgroup-ID equality establish the observed relationship.
    /// Cgroup-v2 does not permit reparenting a cgroup, so retaining the resolved
    /// object preserves its ancestry. No alternate candidate is tried after a
    /// mismatch. Use [`Self::verify_exact_membership`] for the anchor itself.
    ///
    /// The process information is rechecked after the outer anchor's final
    /// active-file check. This detects observed migration, not a move away and
    /// back between observations. It neither discovers an arbitrary process's
    /// path nor fences migration or cgroup removal after its observations.
    ///
    /// # Errors
    ///
    /// Rejects oversized, empty or dot-only hints, invalid/traversing paths,
    /// failed strict resolution, inaccessible/deactivated anchors, mismatched
    /// membership, process exit, and kernel errors.
    pub fn verify_descendant_membership(
        &self,
        process: &PidFd,
        relative_hint: &Path,
    ) -> Result<PidFdInfo> {
        // Match BeneathRoot's byte ceiling before even scanning components,
        // including attacker-controlled dot-only inputs that name no child.
        if relative_hint.as_os_str().len() > MAXIMUM_DESCENDANT_HINT_BYTES
            || !relative_hint
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
        {
            return Err(Error::invalid(
                "descendant cgroup hint",
                "must name a proper descendant within the 4096-byte limit",
            ));
        }
        let child = self.resolve_child(relative_hint)?;
        let info = child.verify_exact_membership(process)?;
        self.validate_active()?;
        recheck_process(process, info)
    }

    fn resolve_child(&self, relative: &Path) -> Result<Self> {
        self.validate_active()?;
        let resolved = self.root.resolve(relative, ResolveOptions::directory())?;
        let child = Self::new(BeneathRoot::from_resolved(resolved)?)?;
        self.validate_active()?;
        Ok(child)
    }

    fn validate_active(&self) -> Result<()> {
        if uapi::filesystem_type(self.root.as_fd())? != CGROUP2_SUPER_MAGIC {
            return Err(Error::WrongDescriptorType {
                expected: "kernel cgroup-v2 directory",
            });
        }
        let stat = uapi::fstat(self.root.as_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || self.kernel_id == 0
            || stat.st_ino != self.kernel_id
            || stat.st_dev != self.root.identity().device
        {
            return Err(Error::invalid(
                "cgroup anchor",
                "kernel directory identity changed or is unspecified",
            ));
        }
        // A retained removed directory may still report a positive nlink.
        // Opening this fixed regular kernfs file checks an active reference;
        // all lookup constraints remain enforced by BeneathRoot.
        let _active = self.root.open_regular(Path::new("cgroup.procs"))?;
        Ok(())
    }
}

fn recheck_process(process: &PidFd, before: PidFdInfo) -> Result<PidFdInfo> {
    let after = process.info()?;
    if after.pid() != before.pid()
        || after.thread_group_id() != before.thread_group_id()
        || after.cgroup_id() != before.cgroup_id()
    {
        return Err(Error::invalid(
            "cgroup membership observation",
            "process identity or membership changed during observation",
        ));
    }
    if !process.is_alive()? {
        return Err(Error::invalid(
            "cgroup membership observation",
            "pinned process exited",
        ));
    }
    Ok(after)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Read-only kernel fixture failures intentionally panic."
)]
mod tests {
    use super::*;
    use std::fs::File;
    #[cfg(feature = "kernel-tests")]
    use std::num::NonZeroU32;

    #[test]
    fn ordinary_directory_with_matching_file_names_is_not_a_cgroup() {
        let temporary = tempfile::tempdir().expect("test directory");
        File::create(temporary.path().join("cgroup.procs")).expect("fake cgroup file");
        let fd = File::open(temporary.path())
            .expect("open ordinary directory")
            .into();
        assert!(matches!(
            CgroupV2Root::from_owned(fd),
            Err(Error::WrongDescriptorType { .. })
        ));
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn real_readonly_hierarchy_resolves_exact_current_membership() {
        let root = CgroupV2Root::try_from(
            BeneathRoot::from_owned(
                File::open("/sys/fs/cgroup")
                    .expect("open cgroup-v2 hierarchy")
                    .into(),
            )
            .expect("pin cgroup root"),
        )
        .expect("admit real cgroup root");
        let process =
            PidFd::open(NonZeroU32::new(std::process::id()).expect("test PID")).expect("pin self");
        let membership = std::fs::read_to_string("/proc/self/cgroup").expect("read own membership");
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .expect("unified membership");
        let relative = if relative.is_empty() { "." } else { relative };
        let anchor = root
            .resolve(Path::new(relative))
            .expect("resolve current cgroup");
        let info = anchor
            .verify_exact_membership(&process)
            .expect("exact self membership");
        assert_eq!(info.cgroup_id(), Some(anchor.kernel_id()));
        let hierarchy = root.resolve(Path::new(".")).expect("pin hierarchy root");
        if hierarchy.kernel_id() != anchor.kernel_id() {
            assert!(matches!(
                hierarchy.verify_exact_membership(&process),
                Err(Error::InvalidInput {
                    field: "exact cgroup membership",
                    ..
                })
            ));
            assert_eq!(
                hierarchy
                    .verify_descendant_membership(&process, Path::new(relative))
                    .expect("hinted descendant membership")
                    .cgroup_id(),
                Some(anchor.kernel_id())
            );
        }
        for invalid in ["", ".", "./.", "../outside", "/sys/fs/cgroup"] {
            assert!(
                hierarchy
                    .verify_descendant_membership(&process, Path::new(invalid))
                    .is_err()
            );
        }
        let oversized = "./".repeat(MAXIMUM_DESCENDANT_HINT_BYTES / 2 + 1);
        assert!(matches!(
            hierarchy.verify_descendant_membership(&process, Path::new(&oversized)),
            Err(Error::InvalidInput {
                field: "descendant cgroup hint",
                ..
            })
        ));
        for invalid in ["", "/", "..", "../cgroup", "cgroup.procs"] {
            assert!(
                root.resolve(Path::new(invalid)).is_err(),
                "accepted {invalid:?}"
            );
        }
    }
}

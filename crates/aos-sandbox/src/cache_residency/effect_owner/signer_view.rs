//! Nonauthorizing physical Cache readback from the signer-only idmapped view.
//!
//! This opener never takes or transfers the Controller's physical flock. It
//! proves fixed names and a replayed manifest at two local observations; a
//! separate adopted writer protocol must keep them current during Q04.

use std::os::fd::OwnedFd;

use rustix::fs::{Mode, OFlags};

use crate::cache_residency::signer_mount::require_signer_mount;

use super::{
    CacheOwnerCurrentnessV1, CacheOwnerErrorV1, CacheOwnerLimitsV1, FIXED_CACHE_ROOT, inspect_lock,
    inspect_manifest_identity, inspect_root, reject_legacy_object_root, replayed_manifest_head,
};

pub(crate) const SIGNER_OBJECT_VIEW: &str = "/run/aos/sandbox-cache-signer-objects";

/// Reports one replayed physical head and exact signer-visible fixed names.
///
/// The value carries no flock or effect capability. Its identities are useful
/// only while an independent holder retains the corresponding writer cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheSignerObjectReadbackV1 {
    root: (u64, u64),
    owner_uid: u32,
    lock: (u64, u64),
    manifest: Option<(u64, u64)>,
    current: CacheOwnerCurrentnessV1,
}

impl CacheSignerObjectReadbackV1 {
    /// Returns the fixed object-root device and inode.
    #[must_use]
    pub const fn root_identity(self) -> (u64, u64) {
        self.root
    }

    /// Returns the original Controller-owned source UID before idmapping.
    #[must_use]
    pub const fn owner_uid(self) -> u32 {
        self.owner_uid
    }

    /// Returns the fixed physical lock device and inode.
    #[must_use]
    pub const fn lock_identity(self) -> (u64, u64) {
        self.lock
    }

    /// Returns the named manifest identity, or none for a fresh owner.
    #[must_use]
    pub const fn manifest_identity(self) -> Option<(u64, u64)> {
        self.manifest
    }

    /// Returns the complete replayed manifest generation and digest.
    #[must_use]
    pub const fn currentness(self) -> CacheOwnerCurrentnessV1 {
        self.current
    }
}

/// Replays physical Cache fixed names through only the signer object view.
///
/// The source root is a Controller-owned sibling under a root-owned parent.
/// This read-only opener re-resolves that original name and both fixed child
/// names after replay. It cannot establish ownership of the Controller flock.
///
/// # Errors
///
/// Rejects a missing or writable mount, wrong idmap or signer UID, replaced
/// source, lock, or manifest name, malformed manifest, or invalid limits.
pub(crate) fn read_fixed_signer_cache_object_view_v1(
    limits: CacheOwnerLimitsV1,
) -> Result<CacheSignerObjectReadbackV1, CacheOwnerErrorV1> {
    let limits = limits.validate()?;
    reject_legacy_object_root()?;
    let signer_uid = rustix::process::geteuid().as_raw();
    let mount = require_signer_mount(SIGNER_OBJECT_VIEW, FIXED_CACHE_ROOT, signer_uid)?;
    let root: OwnedFd = rustix::fs::open(
        SIGNER_OBJECT_VIEW,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let root_identity = inspect_root(&root)?;
    if !mount.matches_opened_root(root_identity.device, root_identity.inode) {
        return Err(CacheOwnerErrorV1::RootChanged);
    }
    let lock: OwnedFd = rustix::fs::openat(
        &root,
        ".owner.lock",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let lock_identity = inspect_lock(&root, &lock)?;
    let manifest_identity = inspect_manifest_identity(&root)?;
    let current = replayed_manifest_head(&root, limits)?;
    reject_legacy_object_root()?;

    if inspect_root(&root)? != root_identity
        || inspect_lock(&root, &lock)? != lock_identity
        || inspect_manifest_identity(&root)? != manifest_identity
        || replayed_manifest_head(&root, limits)? != current
        || require_signer_mount(SIGNER_OBJECT_VIEW, FIXED_CACHE_ROOT, signer_uid)? != mount
    {
        return Err(CacheOwnerErrorV1::Stale);
    }

    Ok(CacheSignerObjectReadbackV1 {
        root: (root_identity.device, root_identity.inode),
        owner_uid: mount.source_uid(),
        lock: (lock_identity.device, lock_identity.inode),
        manifest: manifest_identity.map(|identity| (identity.device, identity.inode)),
        current,
    })
}

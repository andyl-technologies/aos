//! Retains the existing physical readback recipe for the selected Cache lane.
//!
//! The actual original owner, flock and immutable maps remain borrowed. Fresh
//! native readers, independent-lock probe and both rooted reopens survive every
//! negative result; complete positive checks dispose those actual descriptors
//! before their peak is reused. No decoded DATA constructs a physical owner.

use super::*;
use aos_sandbox_linux::immutable_file::PublicationRootRecheckOriginalsV1;

#[derive(Default)]
pub(super) struct PhysicalRootOriginalsV1 {
    publication: PublicationRootRecheckOriginalsV1,
    result: Option<Result<(), CacheOwnerErrorV1>>,
}

impl PhysicalRootOriginalsV1 {
    pub(super) fn capture_once(&mut self, owner: &DormantCacheOwnerV1) -> Result<(), CacheOwnerErrorV1> {
        if self.result.is_some() { return Err(CacheOwnerErrorV1::Stale); }
        self.result = Some((|| {
            if inspect_root(&owner.root)? != owner.root_identity { return Err(CacheOwnerErrorV1::RootChanged); }
            inspect_lock(&owner.root, &owner._owner_lock)?;
            owner.publication_root.recheck_protected_path_into(&mut self.publication)?;
            Ok(())
        })());
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(CacheOwnerErrorV1::Stale) }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.publication.failure().or_else(|| self.result.as_ref()
            .and_then(|result| result.as_ref().err()).map(|error| error as _))
    }
}

/// Retains the two actual flock observations and fresh independent descriptor.
#[derive(Default)]
pub(super) struct HeldLockOriginalsV1 {
    inspected: Option<Result<LockIdentity, CacheOwnerErrorV1>>,
    original_flock: Option<Result<(), rustix::io::Errno>>,
    independent: Option<Result<OwnedFd, rustix::io::Errno>>,
    independent_flock: Option<Result<(), rustix::io::Errno>>,
    result: Option<Result<(), CacheOwnerErrorV1>>,
}

impl HeldLockOriginalsV1 {
    pub(super) fn capture_once(
        &mut self,
        root: &OwnedFd,
        lock: &OwnedFd,
    ) -> Result<(), CacheOwnerErrorV1> {
        if self.result.is_some() {
            return Err(CacheOwnerErrorV1::OwnerLockNotHeld);
        }
        self.result = Some(self.capture_inner(root, lock));
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CacheOwnerErrorV1::OwnerLockNotHeld)
        }
    }

    fn capture_inner(&mut self, root: &OwnedFd, lock: &OwnedFd) -> Result<(), CacheOwnerErrorV1> {
        self.inspected = Some(inspect_lock(root, lock));
        if !matches!(self.inspected, Some(Ok(_))) {
            return Err(CacheOwnerErrorV1::OwnerLockNotHeld);
        }
        self.original_flock = Some(rustix::fs::flock(lock, FlockOperation::NonBlockingLockExclusive));
        if !matches!(self.original_flock, Some(Ok(()))) {
            return Err(CacheOwnerErrorV1::OwnerLockNotHeld);
        }
        self.independent = Some(rustix::fs::openat(root, ".owner.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
        let independent = self.independent.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheOwnerErrorV1::OwnerLockNotHeld)?;
        self.independent_flock = Some(rustix::fs::flock(independent,
            FlockOperation::NonBlockingLockExclusive));
        match self.independent_flock {
            Some(Err(rustix::io::Errno::WOULDBLOCK)) => Ok(()),
            _ => Err(CacheOwnerErrorV1::OwnerLockNotHeld),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inspected.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.original_flock.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.independent.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.independent_flock.as_ref().and_then(|result| result.as_ref().err())
                .filter(|cause| **cause != rustix::io::Errno::WOULDBLOCK).map(|cause| cause as _))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    // The ordinary path returns its original variants, not selected projections.
    // An expected WOULDBLOCK probe is a positive observation, never failure debt.
    pub(super) fn into_result(mut self) -> Result<(), CacheOwnerErrorV1> {
        if let Some(Err(cause)) = self.inspected.take() {
            return Err(cause);
        }
        if matches!(self.original_flock, Some(Err(_))) {
            return Err(CacheOwnerErrorV1::OwnerLockNotHeld);
        }
        if self.independent.as_ref().is_some_and(Result::is_err) {
            if let Some(Err(cause)) = self.independent.take() {
                return Err(cause.into());
            }
        }
        if let Some(Err(cause)) = self.independent_flock.take() {
            if cause != rustix::io::Errno::WOULDBLOCK {
                return Err(cause.into());
            }
        }
        self.result.take().ok_or(CacheOwnerErrorV1::OwnerLockNotHeld)?
    }
}

/// Owns one selected check's complete physical native/streaming custody.
#[derive(Default)]
pub(crate) struct CachePhysicalReadbackOriginalsV1 {
    identity: Option<CacheOwnerHeldIdentityV1>,
    lock: Option<Result<LockIdentity, CacheOwnerErrorV1>>,
    manifest: Option<Result<Option<ManifestIdentity>, CacheOwnerErrorV1>>,
    pub(super) before_root: PhysicalRootOriginalsV1,
    pub(super) held_lock: HeldLockOriginalsV1,
    pub(super) streams: [held_manifest::ManifestStreamOriginalsV1; 2],
    pub(super) after_root: PhysicalRootOriginalsV1,
    result: Option<Result<(), CacheOwnerErrorV1>>,
}

impl CachePhysicalReadbackOriginalsV1 {
    // Counts actual fields and reached fixed construction controls, rather
    // than using the seven-descriptor peak as an allocator-metadata proxy.
    pub(crate) const fn receiving_metadata_cells_v1() -> usize {
        // Owner8; two Root2/Publication4/AbsoluteDirectory4; HeldLock5;
        // two ManifestOriginal7/ManifestStream8; fixed identity/snapshot16;
        // and eight current native reference/flag/comparison controls.
        8 + 2 * (2 + 4 + 4) + 5 + 2 * (7 + 8) + 16 + 8
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.lock.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
            .or_else(|| self.manifest.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.before_root.failure())
            .or_else(|| self.held_lock.failure())
            .or_else(|| self.streams[0].failure())
            .or_else(|| self.after_root.failure())
            .or_else(|| self.streams[1].failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
    }

    pub(crate) fn identity(&self) -> Result<CacheOwnerHeldIdentityV1, CacheOwnerErrorV1> {
        if !matches!(self.result, Some(Ok(()))) { return Err(CacheOwnerErrorV1::Stale); }
        self.identity.ok_or(CacheOwnerErrorV1::Stale)
    }

    // Every required physical post is complete. Dispose the real positive
    // readers/rooted probes now; failed/incomplete destinations never enter.
    fn dispose_success(&mut self) {
        self.held_lock = Default::default();
        self.streams = Default::default();
        self.before_root = Default::default();
        self.after_root = Default::default();
    }
}

impl DormantCacheOwnerV1 {
    pub(crate) fn capture_create_storage_physical_once<'owner>(
        &'owner self,
        destination: &mut CachePhysicalReadbackOriginalsV1,
        expected: Option<CacheOwnerHeldIdentityV1>,
    ) -> Result<CacheOwnerHeldSnapshotV1<'owner>, CacheOwnerErrorV1> {
        if destination.result.is_some() { return Err(CacheOwnerErrorV1::Stale); }
        destination.result = Some((|| {
            let current = self.currentness();
            destination.lock = Some(inspect_lock(&self.root, &self._owner_lock));
            let lock = destination.lock.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(CacheOwnerErrorV1::Stale)?;
            destination.manifest = Some(inspect_manifest_identity(&self.root));
            let manifest = destination.manifest.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(CacheOwnerErrorV1::Stale)?;
            let identity = CacheOwnerHeldIdentityV1 { root: self.root_identity, lock, manifest, current };
            if expected.is_some_and(|expected| expected != identity) { return Err(CacheOwnerErrorV1::Stale); }
            destination.identity = Some(identity);
            self.validate_held_snapshot_with(identity.root, identity.lock, identity.manifest,
                identity.current, Some(destination))
        })());
        if !matches!(destination.result, Some(Ok(()))) { return Err(CacheOwnerErrorV1::Stale); }
        let identity = destination.identity()?;
        destination.dispose_success();
        Ok(CacheOwnerHeldSnapshotV1 {
            owner: self, root_identity: identity.root, lock_identity: identity.lock,
            manifest_identity: identity.manifest, current: identity.current,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture() -> (tempfile::TempDir, OwnedFd, OwnedFd) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        let lock = open_owner_lock(&root).unwrap();
        (directory, root, lock)
    }

    #[test]
    fn selected_lock_keeps_actual_success_and_expected_blocking_probe() {
        let (_directory, root, lock) = fixture();
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        let mut original = HeldLockOriginalsV1::default();

        original.capture_once(&root, &lock).unwrap();

        assert!(matches!(original.original_flock, Some(Ok(()))));
        assert!(matches!(original.independent, Some(Ok(_))));
        assert!(matches!(original.independent_flock,
            Some(Err(rustix::io::Errno::WOULDBLOCK))));
        assert!(original.failure().is_none());
        original.into_result().unwrap();
        ensure_held_lock(&root, &lock).unwrap();
    }

    #[test]
    fn original_flock_failure_remains_the_actual_native_cause_through_reentry() {
        let (_directory, root, lock) = fixture();
        rustix::fs::flock(&lock, FlockOperation::Unlock).unwrap();
        let competing = rustix::fs::openat(&root, ".owner.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).unwrap();
        rustix::fs::flock(&competing, FlockOperation::NonBlockingLockExclusive).unwrap();
        let mut original = HeldLockOriginalsV1::default();

        assert!(matches!(original.capture_once(&root, &lock),
            Err(CacheOwnerErrorV1::OwnerLockNotHeld)));

        let native = original.original_flock.as_ref().unwrap().as_ref().unwrap_err()
            as *const rustix::io::Errno;
        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap(), native));
        assert!(original.independent.is_none());
        rustix::fs::flock(&competing, FlockOperation::Unlock).unwrap();
        assert!(original.capture_once(&root, &lock).is_err());
        assert!(std::ptr::eq(original.failure().unwrap()
            .downcast_ref::<rustix::io::Errno>().unwrap(), native));
        assert!(matches!(original.into_result(), Err(CacheOwnerErrorV1::OwnerLockNotHeld)));
    }
}

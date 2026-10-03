//! Passive original specimen-root custody before any resource-creation effect.
//!
//! This uses the existing complete Agent tree algorithm and safe descriptor-
//! relative resolver. It never calls a mount/namespace effect or labels an
//! attached store descriptor detached. Actual DetachedMount cloning and the
//! fixed network child still require the genuine floor-issued Prepared permit,
//! which is unavailable until the separately reviewed Host055 physical join.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox_agent::guest_root_tree::compare_guest_root_template_v1;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions, ResolvedPath};
use rustix::fs::{Mode, OFlags, StatVfsMountFlags, fstat, fstatvfs, open};

use crate::immutable_image::RetainedImmutableFileV1;

use super::InstalledCollectorStartupErrorV1 as Error;
use super::startup::ProductionInstalledCollectorStartupV1;

pub(super) struct RetainedSpecimenTemplateV1<'collector> {
    startup: &'collector ProductionInstalledCollectorStartupV1,
    store: BeneathRoot,
    root: ResolvedPath,
    mount: MountId,
    digest_pin: RetainedImmutableFileV1,
    digest: [u8; 32],
}

impl<'collector> RetainedSpecimenTemplateV1<'collector> {
    // Original startup alone admits this passive observation, not a mount
    // clone/start effect. There is deliberately no arbitrary root/FD factory.
    pub(super) fn retain(
        startup: &'collector ProductionInstalledCollectorStartupV1,
    ) -> Result<Self, Error> {
        startup.recheck()?;
        let store = BeneathRoot::from_owned(
            open(
                "/nix/store",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::SpecimenRoot)?,
        )
        .map_err(|_| Error::SpecimenRoot)?;
        let relative = Path::new(&startup.profile.specimen_root)
            .strip_prefix("/nix/store")
            .map_err(|_| Error::SpecimenRoot)?;
        let root = store
            .resolve(relative, ResolveOptions::directory())
            .map_err(|_| Error::SpecimenRoot)?;
        let mount = MountId::from_fd(root.as_fd()).map_err(|_| Error::SpecimenRoot)?;
        let pin = &startup.profile.specimen_root_digest_pin;
        let digest_pin = RetainedImmutableFileV1::open_with_profile(
            pin.path.clone().into(),
            Some(pin.sha256),
            65,
            false,
        )
        .map_err(|_| Error::SpecimenRoot)?;

        let retained = Self {
            startup,
            store,
            root,
            mount,
            digest_pin,
            digest: startup.profile.specimen_root_sha256,
        };
        retained.recheck()?;
        Ok(retained)
    }

    pub(super) fn recheck(&self) -> Result<(), Error> {
        self.startup.recheck()?;
        self.digest_pin.revalidate().map_err(|_| Error::SpecimenRoot)?;
        self.require_original_root()?;
        if self.digest_pin.read_bounded().map_err(|_| Error::SpecimenRoot)?
            != canonical_digest_pin(self.digest)
        {
            return Err(Error::SpecimenRoot);
        }

        let path = Path::new(&self.startup.profile.specimen_root);
        // The immutable template is independently protected by original
        // profile/name/readonly-store custody. No empty mounted guest is used
        // as a shortcut or compared-entry omission.
        let observed =
            compare_guest_root_template_v1(path, path).map_err(|_| Error::SpecimenRoot)?;
        if observed != self.digest {
            return Err(Error::SpecimenRoot);
        }

        self.require_original_root()?;
        self.digest_pin.revalidate().map_err(|_| Error::SpecimenRoot)?;
        self.startup.profile_file().revalidate().map_err(|_| Error::Profile)?;
        self.startup.recheck()
    }

    fn require_original_root(&self) -> Result<(), Error> {
        let path = Path::new(&self.startup.profile.specimen_root);
        if std::fs::canonicalize(path).map_err(|_| Error::SpecimenRoot)? != path {
            return Err(Error::SpecimenRoot);
        }
        let relative = path.strip_prefix("/nix/store").map_err(|_| Error::SpecimenRoot)?;
        let current = self
            .store
            .resolve(relative, ResolveOptions::directory())
            .map_err(|_| Error::SpecimenRoot)?;
        let held = fstat(self.root.as_fd()).map_err(|_| Error::SpecimenRoot)?;
        let named = std::fs::symlink_metadata(path).map_err(|_| Error::SpecimenRoot)?;
        let flags = fstatvfs(self.root.as_fd()).map_err(|_| Error::SpecimenRoot)?;
        if current.identity() != self.root.identity()
            || MountId::from_fd(current.as_fd()).map_err(|_| Error::SpecimenRoot)? != self.mount
            || MountId::from_fd(self.root.as_fd()).map_err(|_| Error::SpecimenRoot)? != self.mount
            || held.st_uid != 0
            || held.st_gid != 0
            || held.st_mode & 0o7222 != 0
            || held.st_dev != named.dev()
            || held.st_ino != named.ino()
            || !named.is_dir()
            || !flags.f_flag.contains(StatVfsMountFlags::RDONLY)
        {
            return Err(Error::SpecimenRoot);
        }

        Ok(())
    }

    /// Returns physical complete-tree comparison DATA, never a Prepared permit.
    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn canonical_digest_pin(digest: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(65);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        bytes.push(HEX[usize::from(byte >> 4)]);
        bytes.push(HEX[usize::from(byte & 0x0f)]);
    }
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests;

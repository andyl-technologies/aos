//! Observes complete empty selected-Mount custody beneath its original root.
//!
//! Every non-dot child refuses. Both retained directory prefixes, pathname
//! comparisons and MountId results remain held through the service interval.

use super::*;
use aos_sandbox_linux::path::RetainedEmptyDirectoryOriginalV2;

pub(crate) const SELECTED_CATALOG_V2: &str = "/run/aos/sandbox-mount-catalog";

#[derive(Default)]
pub(crate) struct MountInventoryRootAbsenceOriginalV2 {
    entered: bool,
    directory: RetainedEmptyDirectoryOriginalV2,
    directory_result: Option<std::result::Result<(), aos_sandbox_linux::path::EmptyDirectoryClosedV2>>,
    path_open: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    path: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    path_mount: Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
    mount: Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
    comparison: Option<Result<()>>,
    first: Option<First>,
}

#[derive(Clone, Copy)]
enum First { Directory, PathOpen, Path, PathMount, Mount, Comparison }

impl DestinationSlotStoreV1 {
    pub(crate) fn inventory_custody_empty_v2(&self) -> bool {
        self.records.is_empty() && self.pins.is_empty()
            && self.namespace_anchors.inventory_custody_empty_v2()
            // An abandoned coverage observation may still retain a descriptor.
            && self.git_coverage_census.is_none()
    }
}

impl MountInventoryRootAbsenceOriginalV2 {
    pub(crate) fn receiving_demand_v2() -> Result<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (bytes, files, names) = RetainedEmptyDirectoryOriginalV2::receiving_shape_v2()
            .ok_or_else(|| invalid("Mount absence directory geometry overflow"))?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid("Mount absence memory overflow"))?)
            .with(D::OpenFiles, u64::try_from(files.checked_add(1)
                .ok_or_else(|| invalid("Mount absence file overflow"))?)
                .map_err(|_| invalid("Mount absence file overflow"))?)
            .with(D::MetadataEntries, u64::try_from(names.checked_add(1)
                .ok_or_else(|| invalid("Mount absence namespace overflow"))?)
                .map_err(|_| invalid("Mount absence namespace overflow"))?))
    }

    pub(crate) fn observe_once_v2(&mut self, store: &DestinationSlotStoreV1) -> Result<()> {
        if self.entered { return Err(conflict("Mount absence root cannot reenter")); }
        self.entered = true;
        self.directory_result = Some(self.directory.capture_once_v2(store.root.as_fd()));
        if !matches!(self.directory_result, Some(Ok(()))) { self.first = Some(First::Directory); }
        // These independently owed observations follow even a rejected child.
        self.path_open = Some(rustix::fs::open(SELECTED_CATALOG_V2, rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::empty()));
        if matches!(self.path_open, Some(Err(_))) { self.first.get_or_insert(First::PathOpen); }
        if let Some(Ok(path)) = self.path_open.as_ref() {
            self.path = Some(rustix::fs::fstat(path.as_fd()));
            if matches!(self.path, Some(Err(_))) { self.first.get_or_insert(First::Path); }
            self.path_mount = Some(MountId::from_fd(path.as_fd()));
            if matches!(self.path_mount, Some(Err(_))) { self.first.get_or_insert(First::PathMount); }
        }
        self.mount = Some(MountId::from_fd(store.root.as_fd()));
        if matches!(self.mount, Some(Err(_))) { self.first.get_or_insert(First::Mount); }
        self.comparison = Some((|| {
            if !store.inventory_custody_empty_v2() { return Err(conflict("Mount retains native resource custody")); }
            let stat = self.directory.root_metadata_v2()
                .ok_or_else(|| conflict("Mount root directory observation refused"))?;
            let path = self.path.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| conflict("Mount root pathname observation refused"))?;
            let mount = self.mount.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| conflict("Mount root MountId observation refused"))?;
            let identity = store.root.identity();
            if stat.st_uid != store.root_owner || stat.st_mode & 0o7777 != PARENT_DIRECTORY_MODE
                || stat.st_dev as u64 != identity.device || stat.st_ino as u64 != identity.inode
                || *mount != store.anchor_mount_id
                || self.path_mount.as_ref().and_then(|result| result.as_ref().ok()) != Some(mount)
                || path.st_dev != stat.st_dev || path.st_ino != stat.st_ino
                || path.st_uid != stat.st_uid || path.st_gid != stat.st_gid || path.st_mode != stat.st_mode {
                return Err(conflict("Mount retained root or selected pathname changed"));
            }
            Ok(())
        })());
        if !matches!(self.comparison, Some(Ok(()))) { self.first.get_or_insert(First::Comparison); }
        if self.first.is_none() { Ok(()) } else { Err(conflict("Mount absence root retained refusal")) }
    }

    pub(crate) fn root_identity_v2(&self) -> Option<(u64, u64, u64)> {
        if self.first.is_some() || !matches!(self.comparison, Some(Ok(()))) { return None; }
        let stat = self.directory.root_metadata_v2()?;
        Some((stat.st_dev as u64, stat.st_ino as u64, self.mount.as_ref()?.as_ref().ok()?.get()))
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Directory => self.directory.failure_v2(),
            First::PathOpen => self.path_open.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Path => self.path.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PathMount => self.path_mount.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Mount => self.mount.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Comparison => self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

//! Separates public wire access from the GPL Native whole-mapping owner.
// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::BorrowedFd;

use crucible_qemu_shmem::{MappedSetupView, SetupRegionBackingIdentity};

use crate::{PluginSetupError, StartupSourceError, startup_source::InstallerStartupSource};

pub(super) struct SetupMappingView {
    view: MappedSetupView,
    // Declaration order drops the wire view before its standalone fixture owner.
    // Production has no Rust physical owner; Source retains that native custody.
    #[cfg(test)]
    fixture_owner: Option<crucible_qemu_shmem::MappedSetupRegion>,
}

impl SetupMappingView {
    pub(super) fn view(&self) -> &MappedSetupView {
        &self.view
    }

    pub(super) fn view_mut(&mut self) -> &mut MappedSetupView {
        // This private view never escapes the GPL fixture/native holder as an
        // owned value. Public ordinary owners provide only bounded wire borrows.
        &mut self.view
    }

    pub(super) fn is_owned_fixture(&self) -> bool {
        #[cfg(test)]
        {
            self.fixture_owner.is_some()
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    pub(super) fn exclude_from_child(
        &self,
        source: Option<&InstallerStartupSource>,
    ) -> Result<(), i32> {
        #[cfg(test)]
        if let Some(owner) = self.fixture_owner.as_ref() {
            return owner
                .exclude_from_hot_fork_child()
                .map_err(hot_fork_mapping_disposition_status);
        }
        current(source)
    }

    pub(super) fn restore_parent(
        &self,
        source: Option<&InstallerStartupSource>,
    ) -> Result<(), i32> {
        #[cfg(test)]
        if let Some(owner) = self.fixture_owner.as_ref() {
            return owner
                .restore_hot_fork_parent_inheritance()
                .map_err(hot_fork_mapping_disposition_status);
        }
        // Native's creating owner stays permanently DONTFORK. A logical parent
        // release never creates child inheritance or a replacement view.
        current(source)
    }
}

pub(super) fn prepare(
    source: Option<&InstallerStartupSource>,
    fd: BorrowedFd<'_>,
    region_len: u64,
) -> Result<SetupMappingView, PluginSetupError> {
    #[cfg(test)]
    if source.is_none_or(InstallerStartupSource::has_setup_model) {
        let owner = crucible_qemu_shmem::mmap_setup_region(fd, region_len)
            .map_err(|source| PluginSetupError::MapRegion { source })?;
        // SAFETY: this explicit component fixture retains the actual standalone
        // owner in the same private holder before any view/role escapes. Its
        // wire view drops first; no mutable owner metadata is exposed publicly.
        let view = unsafe {
            MappedSetupView::from_retained_mapping(
                owner.mapping_start() as *mut u8,
                region_len,
                owner.backing_identity(),
            )
        }
        .map_err(|source| PluginSetupError::MapRegion { source })?;
        return Ok(SetupMappingView {
            view,
            fixture_owner: Some(owner),
        });
    }
    let source = source.ok_or(PluginSetupError::StartupSource {
        source: StartupSourceError::Ownership {
            reason: "native mapping has no retained installing Source",
        },
    })?;
    // Backing facts only corroborate the actual authenticated role consumed by
    // the native constructor; neither FD nor length is an input to that creator.
    let (device, inode) = super::shared_memory_identity(fd)
        .map_err(|errno| PluginSetupError::InspectSharedMemory { errno })?;
    let identity = SetupRegionBackingIdentity::from_parts(device, inode, region_len).ok_or(
        PluginSetupError::StartupSource {
            source: StartupSourceError::Ownership {
                reason: "setup mapping backing identity is empty",
            },
        },
    )?;
    source
        .create_setup_mapping(identity)
        .map(|view| SetupMappingView {
            view,
            #[cfg(test)]
            fixture_owner: None,
        })
}

fn current(source: Option<&InstallerStartupSource>) -> Result<(), i32> {
    let source = source.ok_or(-libc::EPROTO)?;
    source.check_setup_mapping().map_err(|error| match error {
        StartupSourceError::NativeStatus { status } => status,
        StartupSourceError::Unavailable { .. } => -libc::ENOSYS,
        StartupSourceError::Ownership { .. } => -libc::EPROTO,
    })
}

#[cfg(test)]
fn hot_fork_mapping_disposition_status(
    error: crucible_qemu_shmem::HotForkMappingDispositionError,
) -> std::os::raw::c_int {
    match error {
        crucible_qemu_shmem::HotForkMappingDispositionError::Unsupported => -libc::ENOTSUP,
        crucible_qemu_shmem::HotForkMappingDispositionError::Madvise { source, .. } => source
            .raw_os_error()
            .filter(|errno| *errno > 0)
            .map_or(-libc::EIO, |errno| -errno),
    }
}

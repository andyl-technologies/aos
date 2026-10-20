//! Shared physical FD facts and separate attached-namespace evidence.

use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_linux::inventory::{MountNamespace, MountObservation, ReadOnlyDirectorySnapshot};
use aos_sandbox_linux::pidfd::NamespaceFd;

use crate::{CurrentKernelBootV1, SourceProviderSecurityError};

/// Selected only by a verified native graph or a fully verified signed outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceRootObservationProfileV1 {
    Attached,
    NativeDetached,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceRootSnapshotV1 {
    pub(crate) physical: ReadOnlyDirectorySnapshot,
    pub(crate) namespace: Option<MountObservation>,
}

pub(crate) fn observe_source_root_snapshot(
    descriptor: &OwnedFd,
    profile: SourceRootObservationProfileV1,
    namespace: Option<&NamespaceFd>,
) -> Result<SourceRootSnapshotV1, SourceProviderSecurityError> {
    let boot = CurrentKernelBootV1::capture()?;
    let physical = ReadOnlyDirectorySnapshot::capture(descriptor.as_fd())
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
    let namespace = match profile {
        SourceRootObservationProfileV1::NativeDetached => None,
        SourceRootObservationProfileV1::Attached => {
            let namespace = match namespace {
                Some(pin) => MountNamespace::pinned(pin)
                    .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?,
                None => MountNamespace::current(),
            };
            let mount = namespace
                .observe(physical.mount_id)
                .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;
            if mount.mount_id != physical.mount_id
                || mount.device_major != rustix::fs::major(physical.device)
                || mount.device_minor != rustix::fs::minor(physical.device)
                || !mount.is_read_only()
            {
                return Err(SourceProviderSecurityError::DescriptorObservation);
            }
            Some(mount)
        }
    };
    boot.revalidate()?;
    if physical.boot_id != boot.boot_id() {
        return Err(SourceProviderSecurityError::DescriptorObservation);
    }
    Ok(SourceRootSnapshotV1 {
        physical,
        namespace,
    })
}

#[cfg(test)]
mod tests {
    use aos_sandbox_linux::mount::{FileSystemContext, MountAttributes};

    use super::*;

    #[test]
    #[ignore = "requires the explicit AOS kernel VM mount fixture"]
    fn detached_physical_facts_do_not_fabricate_namespace_evidence() {
        let mount = FileSystemContext::open("tmpfs")
            .unwrap()
            .create()
            .unwrap()
            .mount()
            .unwrap();
        mount
            .set_attributes(false, MountAttributes::secure_read_only(), None)
            .unwrap();
        let descriptor = rustix::io::fcntl_dupfd_cloexec(mount.as_fd(), 0).unwrap();

        // Private observer exercise only, not an authenticated receive profile
        // or a production detached-root constructor.
        let first = observe_source_root_snapshot(
            &descriptor,
            SourceRootObservationProfileV1::NativeDetached,
            None,
        )
        .unwrap();
        let second = observe_source_root_snapshot(
            &descriptor,
            SourceRootObservationProfileV1::NativeDetached,
            None,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.physical.mount_id, mount.mount_id());
        assert!(first.namespace.is_none());
        assert!(
            observe_source_root_snapshot(
                &descriptor,
                SourceRootObservationProfileV1::Attached,
                None
            )
            .is_err()
        );

        mount
            .set_attributes(false, MountAttributes::secure_writable(), None)
            .unwrap();
        assert!(
            observe_source_root_snapshot(
                &descriptor,
                SourceRootObservationProfileV1::NativeDetached,
                None
            )
            .is_err()
        );
    }
}

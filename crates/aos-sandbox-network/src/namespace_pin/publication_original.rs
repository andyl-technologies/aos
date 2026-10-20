//! Retains the sole canonical namespace-pin publication and rollback prefix.
//!
//! The actual role supplies the prepaid destination and independently owns
//! Source/D bookends. This native owner grants no namespace or effect authority.

use super::*;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::path::{
    BeneathDirectoryOpenOriginalV2, BeneathNamespaceOpenOriginalV4, BeneathRootOpenOriginalV2,
};
use std::error::Error;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};

#[derive(Clone, Copy)]
enum First {
    Order,
    Slash,
    Filesystem,
    Directory,
    Root,
    Metadata,
    Policy,
    Handle,
    Placeholder,
    Mount,
    Readback,
    Identity,
}

/// Parks every reached native pin and owed rollback result without retrying.
pub(crate) struct NetworkNamespacePublicationOriginalV2 {
    entered: bool,
    slash: Option<Result<OwnedFd, rustix::io::Errno>>,
    filesystem: BeneathRootOpenOriginalV2,
    filesystem_result: Option<Result<(), aos_sandbox_linux::Error>>,
    directory: BeneathDirectoryOpenOriginalV2,
    directory_result: Option<Result<(), aos_sandbox_linux::Error>>,
    root: Option<BeneathRoot>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    policy: Option<Result<(), NetworkNamespacePinMutationError>>,
    component: Option<Result<String, NetworkNamespacePinMutationError>>,
    destination: Option<PathBuf>,
    source: Option<PathBuf>,
    placeholder: Option<Result<OwnedFd, rustix::io::Errno>>,
    mounted: Option<Result<(), rustix::io::Errno>>,
    readback: BeneathNamespaceOpenOriginalV4,
    readback_result: Option<Result<(), aos_sandbox_linux::Error>>,
    identity: Option<Result<(), NetworkNamespacePinMutationError>>,
    rollback_unmount: Option<Result<(), rustix::io::Errno>>,
    rollback_unlink: Option<Result<(), rustix::io::Errno>>,
    first: Option<First>,
    closed: NetworkNamespacePinMutationError,
}

impl NetworkNamespacePublicationOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            slash: None,
            filesystem: BeneathRootOpenOriginalV2::new(),
            filesystem_result: None,
            directory: BeneathDirectoryOpenOriginalV2::new(),
            directory_result: None,
            root: None,
            metadata: None,
            policy: None,
            component: None,
            destination: None,
            source: None,
            placeholder: None,
            mounted: None,
            readback: BeneathNamespaceOpenOriginalV4::new(),
            readback_result: None,
            identity: None,
            rollback_unmount: None,
            rollback_unlink: None,
            first: None,
            closed: NetworkNamespacePinMutationError::Identity,
        }
    }

    /// Prices the fixed root/pin/source paths and actual five-FD native peak.
    pub(crate) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        let component = 32usize.checked_mul(2)?;
        let destination = PIN_ROOT.len().checked_add(1)?.checked_add(component)?;
        let source = "/proc/self/fd/".len().checked_add(10)?;
        let paths = component
            .checked_add(destination)?
            .checked_add(source)?
            .checked_add("run/aos/sandbox-pins/netns".len())?
            .checked_add(4)?
            .checked_mul(4)?;
        let readback = BeneathNamespaceOpenOriginalV4::receiving_obligations_v4(component)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(paths)?
            .checked_add(readback.0)?;
        // Slash, inspected filesystem duplicate, resolved pin root,
        // placeholder and readback coexist. No supplied namespace is rebilled.
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, 5)
                .with(D::MetadataEntries, 5),
        )
    }

    pub(crate) fn publish_once_v2(
        &mut self,
        handle: [u8; 32],
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkNamespacePinMutationError> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.entered = true;
        self.capture(handle, namespace);
        if self.first.is_some() {
            Err(marker())
        } else {
            Ok(())
        }
    }

    fn capture(&mut self, handle: [u8; 32], namespace: &NamespaceFd) {
        self.slash = Some(rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ));
        let Some(Ok(slash)) = self.slash.as_ref() else {
            self.first = Some(First::Slash);
            return;
        };
        self.filesystem_result = Some(self.filesystem.capture_root_once_v1(slash.as_fd()));
        if !matches!(self.filesystem_result, Some(Ok(()))) {
            self.first = Some(First::Filesystem);
            return;
        }
        let Some(filesystem) = self.filesystem.root_v1() else {
            self.first = Some(First::Filesystem);
            return;
        };
        self.directory_result = Some(self.directory.resolve_directory_with_options_once_v2(
            filesystem,
            Path::new("run/aos/sandbox-pins/netns"),
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        ));
        if !matches!(self.directory_result, Some(Ok(()))) {
            self.first = Some(First::Directory);
            return;
        }
        self.root = self.directory.take_completed_root_once_v2();
        let Some(root) = self.root.as_ref() else {
            self.first = Some(First::Root);
            return;
        };
        self.metadata = Some(rustix::fs::fstat(root.as_fd()));
        let Some(Ok(metadata)) = self.metadata.as_ref() else {
            self.first = Some(First::Metadata);
            return;
        };
        self.policy = Some(
            if root.identity().file_type == FileType::Directory
                && metadata.st_uid == 0
                && metadata.st_mode & 0o077 == 0
            {
                Ok(())
            } else {
                Err(marker())
            },
        );
        if !matches!(self.policy, Some(Ok(()))) {
            self.first = Some(First::Policy);
            return;
        }
        self.component = Some(handle_component(handle));
        let Some(Ok(component)) = self.component.as_ref() else {
            self.first = Some(First::Handle);
            return;
        };
        self.destination = Some(fixed_pin_path(component));
        self.source = Some(PathBuf::from(format!(
            "/proc/self/fd/{}",
            namespace.as_fd().as_raw_fd()
        )));
        self.placeholder = Some(rustix::fs::openat(
            root.as_fd(),
            component.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        ));
        if !matches!(self.placeholder, Some(Ok(_))) {
            self.first = Some(First::Placeholder);
            return;
        }
        let (Some(source), Some(destination)) = (self.source.as_ref(), self.destination.as_ref())
        else {
            self.first = Some(First::Root);
            return;
        };
        self.mounted = Some(rustix::mount::mount_bind(source, destination));
        if !matches!(self.mounted, Some(Ok(()))) {
            self.first = Some(First::Mount);
            self.rollback_unlink = Some(rustix::fs::unlinkat(
                root.as_fd(),
                component.as_str(),
                AtFlags::empty(),
            ));
            return;
        }
        self.readback_result = Some(self.readback.open_once_v4(
            root,
            Path::new(component),
            NamespaceKind::Network,
        ));
        if !matches!(self.readback_result, Some(Ok(()))) {
            self.first = Some(First::Readback);
        } else {
            self.identity = Some(match self.readback.completed_namespace_v4() {
                Some(observed) if observed.identity() == namespace.identity() => Ok(()),
                _ => Err(marker()),
            });
            if !matches!(self.identity, Some(Ok(()))) {
                self.first = Some(First::Identity);
            }
        }
        if self.first.is_some() {
            // Both already-owed rollback attempts run independently. Their
            // actual errors stay resident and cannot replace the first cause.
            self.rollback_unmount =
                Some(rustix::mount::unmount(destination, UnmountFlags::NOFOLLOW));
            self.rollback_unlink = Some(rustix::fs::unlinkat(
                root.as_fd(),
                component.as_str(),
                AtFlags::empty(),
            ));
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Slash => self.slash.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Filesystem => self
                .filesystem_result
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Directory => self
                .directory_result
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Metadata => self
                .metadata
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Policy => self.policy.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Handle => self
                .component
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Placeholder => self
                .placeholder
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Mount => self
                .mounted
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Readback => self.readback.failure().map(|cause| cause as _),
            First::Identity => self
                .identity
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Order | First::Root => None,
        };
        cause.or(Some(&self.closed))
    }

    fn take_local_error(&mut self) -> NetworkNamespacePinMutationError {
        match self.first {
            Some(First::Slash) => {
                if let Some(Err(cause)) = self.slash.take() {
                    return cause.into();
                }
            }
            Some(First::Filesystem) => {
                if let Some(Err(cause)) = self.filesystem_result.take() {
                    return cause.into();
                }
            }
            Some(First::Directory) => {
                if let Some(Err(cause)) = self.directory_result.take() {
                    return cause.into();
                }
            }
            Some(First::Metadata) => {
                if let Some(Err(cause)) = self.metadata.take() {
                    return cause.into();
                }
            }
            Some(First::Placeholder) => {
                if let Some(Err(cause)) = self.placeholder.take() {
                    return cause.into();
                }
            }
            Some(First::Mount) => {
                if let Some(Err(cause)) = self.mounted.take() {
                    return cause.into();
                }
            }
            Some(First::Readback) => {
                let readback = std::mem::take(&mut self.readback);
                if let Some(cause) = readback.into_ordinary_error_v2() {
                    return cause.into();
                }
            }
            _ => {}
        }
        marker()
    }
}

pub(super) fn publish_local_v2(
    handle: [u8; 32],
    namespace: &NamespaceFd,
) -> Result<(), NetworkNamespacePinMutationError> {
    let mut original = NetworkNamespacePublicationOriginalV2::new();
    match original.publish_once_v2(handle, namespace) {
        Ok(()) => Ok(()),
        Err(_) => Err(original.take_local_error()),
    }
}

fn marker() -> NetworkNamespacePinMutationError {
    NetworkNamespacePinMutationError::Identity
}

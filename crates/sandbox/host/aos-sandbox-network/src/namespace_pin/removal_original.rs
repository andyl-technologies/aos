//! Retains canonical namespace-pin teardown without supplying effect authority.
//!
//! The genuine signed9 P programme funds this destination before birth. It
//! prepares the protected root and exact pin identity, then independently
//! checks its same Source and original D immediately before removal. The
//! target namespace OFD stays on the enclosing programme through O observation.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::path::{
    BeneathDirectoryOpenOriginalV2, BeneathNamespaceOpenOriginalV4, BeneathRootOpenOriginalV2,
};
use std::error::Error;
use std::os::fd::{AsFd as _, OwnedFd};

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
    Before,
    Namespace,
    Identity,
    Retirement,
    Unmount,
    Unlink,
    After,
}

/// Keeps the actual root, exact identity and mutation results until P custody ends.
pub(crate) struct NetworkNamespaceRemovalOriginalV2 {
    entered: bool,
    removal_entered: bool,
    prepared: bool,
    complete: bool,
    absent: bool,
    slash: Option<Result<OwnedFd, rustix::io::Errno>>,
    filesystem: BeneathRootOpenOriginalV2,
    filesystem_result: Option<Result<(), aos_linux_descriptors::Error>>,
    directory: BeneathDirectoryOpenOriginalV2,
    directory_result: Option<Result<(), aos_linux_descriptors::Error>>,
    root: Option<BeneathRoot>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    policy: Option<Result<(), NetworkNamespacePinMutationError>>,
    component: Option<Result<String, NetworkNamespacePinMutationError>>,
    destination: Option<PathBuf>,
    before: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    namespace: BeneathNamespaceOpenOriginalV4,
    namespace_result: Option<Result<(), aos_linux_descriptors::Error>>,
    identity: Option<Result<(), NetworkNamespacePinMutationError>>,
    retirement: Option<Result<NamespaceIdentity, aos_linux_descriptors::Error>>,
    unmount: Option<Result<(), rustix::io::Errno>>,
    unlink: Option<Result<(), rustix::io::Errno>>,
    after: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    first: Option<First>,
    closed: NetworkNamespacePinMutationError,
}

impl NetworkNamespaceRemovalOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            removal_entered: false,
            prepared: false,
            complete: false,
            absent: false,
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
            before: None,
            namespace: BeneathNamespaceOpenOriginalV4::new(),
            namespace_result: None,
            identity: None,
            retirement: None,
            unmount: None,
            unlink: None,
            after: None,
            first: None,
            closed: marker(),
        }
    }

    /// Quotes the same qualified root/path prefix before any native allocation.
    pub(crate) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        // Publication owns the same protected root, a namespace type-check and
        // more native descriptors/paths. Keep that conservative supplier and
        // add this owner's distinct result/header carriers; no credit is taken.
        let native = NetworkNamespacePublicationOriginalV2::receiving_obligations_data_v2()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?;
        native
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                    .with(D::MetadataEntries, 3),
            )
            .ok()
    }

    /// Prepares only the canonical root and exact native pin, without mutation.
    ///
    /// The caller still owes a fresh genuine signed9/Source/D gate immediately
    /// before `remove_once_v2`; this comparison cannot authorize that gate.
    pub(crate) fn prepare_once_v2(
        &mut self,
        handle: [u8; 32],
        expected: NamespaceIdentity,
        allow_absent: bool,
    ) -> Result<(), NetworkNamespacePinMutationError> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.entered = true;
        self.capture(handle, expected, allow_absent);
        if self.first.is_some() {
            Err(marker())
        } else {
            Ok(())
        }
    }

    fn capture(&mut self, handle: [u8; 32], expected: NamespaceIdentity, allow_absent: bool) {
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
        self.before = Some(rustix::fs::statat(
            root.as_fd(),
            component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        match self.before.as_ref() {
            Some(Err(rustix::io::Errno::NOENT)) if allow_absent => {
                self.absent = true;
                self.prepared = true;
                return;
            }
            Some(Ok(_)) => {}
            _ => {
                self.first = Some(First::Before);
                return;
            }
        }
        self.namespace_result = Some(self.namespace.open_once_v4(
            root,
            Path::new(component),
            NamespaceKind::Network,
        ));
        let Some(namespace) = self.namespace.completed_namespace_v4() else {
            self.first = Some(First::Namespace);
            return;
        };
        self.identity = Some(if namespace.identity() == expected {
            Ok(())
        } else {
            Err(marker())
        });
        if !matches!(self.identity, Some(Ok(()))) {
            self.first = Some(First::Identity);
            return;
        }
        // The canonical ordinary recipe closes this disposable validation OFD
        // before unmount. The genuine target OFD remains with the P/O caller.
        self.retirement = Some(self.namespace.retire_positive_namespace_once_v2());
        if !matches!(self.retirement, Some(Ok(_))) {
            self.first = Some(First::Retirement);
            return;
        }
        self.prepared = true;
    }

    /// Executes the existing unmount/unlink recipe once after the caller's gate.
    pub(crate) fn remove_once_v2(&mut self) -> Result<(), NetworkNamespacePinMutationError> {
        if !self.prepared || self.removal_entered || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.removal_entered = true;
        let (Some(root), Some(Ok(component)), Some(destination)) = (
            self.root.as_ref(),
            self.component.as_ref(),
            self.destination.as_ref(),
        ) else {
            self.first = Some(First::Root);
            return Err(marker());
        };
        if !self.absent {
            self.unmount = Some(rustix::mount::unmount(destination, UnmountFlags::NOFOLLOW));
            if !matches!(self.unmount, Some(Ok(()))) {
                self.first = Some(First::Unmount);
            } else {
                self.unlink = Some(rustix::fs::unlinkat(
                    root.as_fd(),
                    component.as_str(),
                    AtFlags::empty(),
                ));
                if !matches!(self.unlink, Some(Ok(()))) {
                    self.first = Some(First::Unlink);
                }
            }
        }
        // Named absence is observed even after a refused mutation. It cannot
        // repair the first cause or make a failed prefix a successful teardown.
        self.after = Some(rustix::fs::statat(
            root.as_fd(),
            component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        if !matches!(self.after, Some(Err(rustix::io::Errno::NOENT))) {
            self.first.get_or_insert(First::After);
        }
        if self.first.is_some() {
            return Err(marker());
        }
        self.complete = true;
        Ok(())
    }

    /// Borrows only this original's completed native comparison.
    pub(crate) fn require_removed_v2(&self) -> Result<(), NetworkNamespacePinMutationError> {
        if self.complete && self.first.is_none() {
            Ok(())
        } else {
            Err(marker())
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Slash => error(&self.slash),
            First::Filesystem => error(&self.filesystem_result),
            First::Directory => error(&self.directory_result),
            First::Metadata => error(&self.metadata),
            First::Policy => error(&self.policy),
            First::Handle => error(&self.component),
            First::Before => error(&self.before),
            First::Namespace => self
                .namespace
                .failure()
                .map(|cause| cause as _)
                .or_else(|| error(&self.namespace_result)),
            First::Identity => error(&self.identity),
            First::Retirement => error(&self.retirement),
            First::Unmount => error(&self.unmount),
            First::Unlink => error(&self.unlink),
            First::After => self
                .after
                .as_ref()?
                .as_ref()
                .err()
                .filter(|cause| **cause != rustix::io::Errno::NOENT)
                .map(|cause| cause as _),
            First::Order | First::Root => None,
        };
        cause.or(Some(&self.closed))
    }

    fn into_local_error(mut self) -> NetworkNamespacePinMutationError {
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
            Some(First::Before) => {
                if let Some(Err(cause)) = self.before.take() {
                    return cause.into();
                }
            }
            Some(First::Namespace) => {
                if let Some(cause) = self.namespace.into_ordinary_error_v2() {
                    return cause.into();
                }
            }
            Some(First::Retirement) => {
                if let Some(Err(cause)) = self.retirement.take() {
                    return cause.into();
                }
            }
            Some(First::Unmount) => {
                if let Some(Err(cause)) = self.unmount.take() {
                    return cause.into();
                }
            }
            Some(First::Unlink) => {
                if let Some(Err(cause)) = self.unlink.take() {
                    return cause.into();
                }
            }
            _ => {}
        }
        marker()
    }
}

pub(super) fn remove_local_v2(
    handle: [u8; 32],
    expected: NamespaceIdentity,
    allow_absent: bool,
) -> Result<(), NetworkNamespacePinMutationError> {
    let mut original = NetworkNamespaceRemovalOriginalV2::new();
    let result = original
        .prepare_once_v2(handle, expected, allow_absent)
        .and_then(|()| original.remove_once_v2());
    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(original.into_local_error()),
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn marker() -> NetworkNamespacePinMutationError {
    NetworkNamespacePinMutationError::Identity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprepared_removal_performs_no_mutation_and_preserves_its_first_refusal() {
        let mut original = NetworkNamespaceRemovalOriginalV2::new();
        assert!(original.remove_once_v2().is_err());
        let cause = original.failure().unwrap() as *const dyn Error as *const ();
        assert!(original.unmount.is_none());
        assert!(original.unlink.is_none());
        assert!(
            original
                .prepare_once_v2(
                    [1; 32],
                    NamespaceIdentity {
                        device: 1,
                        inode: 1
                    },
                    false
                )
                .is_err()
        );
        assert!(original.slash.is_none());
        assert_eq!(
            original.failure().unwrap() as *const dyn Error as *const (),
            cause
        );
        assert!(original.require_removed_v2().is_err());
    }
}

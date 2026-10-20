//! Retains fixed pin-root and namespace census native prefixes.
//!
//! These owners carry the same kernel path/type checks used by the ordinary
//! catalog. Parsed handles and identities create no permission or resource.

use super::*;
use aos_sandbox_linux::path::{BeneathNamespaceOpenOriginalV4, BeneathRootOwnedOriginalV2};

pub(crate) struct NetworkPinRootOpeningOriginalV4 {
    opened: Option<Result<OwnedFd, rustix::io::Errno>>,
    metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    root: BeneathRootOwnedOriginalV2,
    result: Option<Result<(), NetworkNamespaceCatalogError>>,
    entered: bool,
}

impl NetworkPinRootOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { opened: None, metadata: None, root: BeneathRootOwnedOriginalV2::new(), result: None, entered: false }
    }

    pub(crate) fn open_once_v4(&mut self) -> Result<(), NetworkNamespaceCatalogError> {
        if self.entered { return Err(NetworkNamespaceCatalogError::InvalidCandidate); }
        self.entered = true;
        self.result = Some(self.open_inner());
        if matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(NetworkNamespaceCatalogError::InvalidCandidate) }
    }

    fn open_inner(&mut self) -> Result<(), NetworkNamespaceCatalogError> {
        self.opened = Some(open_pin_root_candidate_v4(Path::new(NAMESPACE_PIN_ROOT)));
        let descriptor = self.opened.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(NetworkNamespaceCatalogError::InvalidCandidate)?;
        self.metadata = Some(rustix::fs::fstat(descriptor));
        let metadata = self.metadata.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(NetworkNamespaceCatalogError::InvalidCandidate)?;
        validate_pin_root_metadata_v4(metadata, 0)?;
        let Some(Ok(descriptor)) = self.opened.take() else { std::process::abort() };
        self.root.from_owned_once(descriptor)
            .map_err(|_| NetworkNamespaceCatalogError::InvalidCandidate)
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<PinRoot> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.root.take_completed_once().map(PinRoot::Kernel)
    }

    pub(crate) fn receiving_demand_v4() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let bytes = size_of::<Self>().checked_mul(2)?.checked_add(256)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?).with(D::OpenFiles, 1))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opened.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.metadata.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.root.failure().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

pub(crate) struct NetworkPinObservationOriginalV4 {
    component: String,
    namespace: BeneathNamespaceOpenOriginalV4,
    absent: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    result: Option<Result<Option<PinIdentity>, NetworkNamespaceCatalogError>>,
    #[cfg(test)]
    filesystem_open: Option<Result<OwnedFd, rustix::io::Errno>>,
    #[cfg(test)]
    filesystem_metadata: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    entered: bool,
}

impl NetworkPinObservationOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { component: String::new(), namespace: BeneathNamespaceOpenOriginalV4::new(),
            absent: None, result: None, entered: false,
            #[cfg(test)] filesystem_open: None,
            #[cfg(test)] filesystem_metadata: None }
    }

    /// Borrows only this actual completed native target, never a DATA identity.
    pub(crate) fn completed_namespace_v2(&self) -> Option<&aos_sandbox_linux::pidfd::NamespaceFd> {
        if !matches!(self.result, Some(Ok(Some(_)))) { return None; }
        self.namespace.completed_namespace_v4()
    }

    pub(super) fn observe_once_v4(&mut self, root: &PinRoot, handle: &[u8; 32])
        -> Result<PinIdentity, NetworkNamespaceCatalogError> {
        if self.entered { return Err(NetworkNamespaceCatalogError::InvalidCandidate); }
        self.entered = true;
        self.component = encode_hex(handle);
        self.result = Some(self.observe_inner(root).map(Some));
        self.result.as_ref().and_then(|value| value.as_ref().ok()).copied().flatten()
            .ok_or(NetworkNamespaceCatalogError::InvalidCandidate)
    }

    fn observe_inner(&mut self, root: &PinRoot) -> Result<PinIdentity, NetworkNamespaceCatalogError> {
        match root {
            PinRoot::Kernel(root) => {
                self.namespace.open_once_v4(root, Path::new(&self.component), NamespaceKind::Network)
                    .map_err(|_| NetworkNamespaceCatalogError::InvalidCandidate)?;
                let namespace = self.namespace.completed_namespace_v4()
                    .ok_or(NetworkNamespaceCatalogError::InvalidCandidate)?;
                let identity = namespace.identity();
                if identity.device == 0 || identity.inode == 0 {
                    return Err(NetworkNamespaceCatalogError::NamespacePin(
                        "namespace pin has a reserved physical identity".to_owned()));
                }
                Ok(PinIdentity { device: identity.device, inode: identity.inode })
            }
            #[cfg(test)]
            PinRoot::Filesystem { descriptor, expected_owner } => {
                self.filesystem_open = Some(rustix::fs::openat(descriptor.as_fd(), self.component.as_str(),
                    rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty()));
                let descriptor = self.filesystem_open.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(NetworkNamespaceCatalogError::InvalidCandidate)?;
                self.filesystem_metadata = Some(rustix::fs::fstat(descriptor));
                let metadata = self.filesystem_metadata.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(NetworkNamespaceCatalogError::InvalidCandidate)?;
                if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile
                    || metadata.st_uid != *expected_owner || metadata.st_mode & 0o022 != 0
                    || metadata.st_dev == 0 || metadata.st_ino == 0 {
                    return Err(NetworkNamespaceCatalogError::NamespacePin(
                        "test pin is not the required owned regular file".to_owned()));
                }
                Ok(PinIdentity { device: metadata.st_dev, inode: metadata.st_ino })
            }
        }
    }

    pub(super) fn absent_once_v4(&mut self, root: &PinRoot, handle: &[u8; 32])
        -> Result<(), NetworkNamespaceCatalogError> {
        if self.entered { return Err(NetworkNamespaceCatalogError::InvalidCandidate); }
        self.entered = true;
        self.component = encode_hex(handle);
        let descriptor = match root {
            PinRoot::Kernel(root) => root.as_fd(),
            #[cfg(test)] PinRoot::Filesystem { descriptor, .. } => descriptor.as_fd(),
        };
        self.absent = Some(rustix::fs::statat(descriptor, self.component.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW));
        self.result = Some(match self.absent.as_ref() {
            Some(Err(rustix::io::Errno::NOENT)) => Ok(None),
            Some(Err(error)) => Err(pin_error(*error)),
            _ => Err(NetworkNamespaceCatalogError::NamespacePin("retired namespace pin unexpectedly exists".to_owned())),
        });
        if matches!(self.result, Some(Ok(None))) { Ok(()) }
        else { Err(NetworkNamespaceCatalogError::InvalidCandidate) }
    }

    pub(crate) fn receiving_demand_v4(rows: usize) -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let (native, files, names) = BeneathNamespaceOpenOriginalV4::receiving_obligations_v4(64)?;
        let bytes = size_of::<Self>().checked_mul(2)?.checked_add(native)?.checked_add(256)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes.checked_mul(rows)?).ok()?)
            .with(D::OpenFiles, u64::try_from(files.checked_mul(rows)?).ok()?)
            .with(D::MetadataEntries, u64::try_from(names.checked_mul(rows)?).ok()?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.namespace.failure().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.absent.as_ref()?.as_ref().err()
                .filter(|cause| **cause != rustix::io::Errno::NOENT).map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

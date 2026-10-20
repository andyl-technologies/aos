//! Retains the fixed policy file and every entered startup result.
//!
//! Native capture precedes typed materialization so a genuine same-role owner
//! can pay actual captured-byte geometry before serde or policy models grow.

use std::error::Error;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, open, openat};

use super::*;

pub(crate) struct ProtectedNetworkPolicyOriginalV4 {
    directory: Option<Result<OwnedFd, rustix::io::Errno>>,
    directory_metadata: Option<Result<Stat, rustix::io::Errno>>,
    opened: Option<Result<Option<OwnedFd>, rustix::io::Errno>>,
    file: Option<std::fs::File>,
    metadata: Option<Result<Stat, rustix::io::Errno>>,
    declared_size: Option<usize>,
    bytes: Vec<u8>,
    read: Option<std::io::Result<usize>>,
    current: Option<Result<Stat, rustix::io::Errno>>,
    native: Option<Result<(), ProtectedNetworkPolicyErrorV1>>,
    decoded: Option<Result<PolicyCatalogWireV1, serde_json::Error>>,
    catalog: Option<Result<NetworkPolicyCatalogV1, ProtectedNetworkPolicyErrorV1>>,
    canonical: Option<Result<Vec<u8>, ProtectedNetworkPolicyErrorV1>>,
    typed: Option<Result<(), ProtectedNetworkPolicyErrorV1>>,
    repeated: Option<ProtectedNetworkPolicyErrorV1>,
    taken: bool,
}

impl ProtectedNetworkPolicyOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            directory: None, directory_metadata: None, opened: None, file: None,
            metadata: None, declared_size: None, bytes: Vec::new(), read: None,
            current: None, native: None, decoded: None, catalog: None,
            canonical: None, typed: None, repeated: None, taken: false,
        }
    }

    pub(crate) fn native_receiving_demand_v4() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(MAXIMUM_CATALOG_BYTES.checked_add(1)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 2))
    }

    pub(crate) fn typed_receiving_demand_v4(&self) -> Option<ResourceVector> {
        if !matches!(self.native, Some(Ok(()))) { return None; }
        // Each encoded byte can introduce at most one JSON scalar/container.
        // Both wire and typed policy vectors coexist with canonical/digest
        // scratch; these are bytes, not named namespace entries.
        let node = std::mem::size_of::<PolicyCatalogWireV1>()
            .checked_add(std::mem::size_of::<PolicyProfileWireV1>())?
            .checked_add(std::mem::size_of::<NetworkPolicyCatalogV1>())?
            .checked_add(std::mem::size_of::<NetworkPolicyProfileV1>())?
            .checked_add(std::mem::size_of::<NetworkPolicyProgramV1>())?
            .checked_add(std::mem::size_of::<NetworkFlowPolicyV1>())?
            .checked_add(std::mem::size_of::<NetworkEndpointPolicyV1>())?
            .checked_add(std::mem::size_of::<NetworkAllocationPolicyV1>())?
            .checked_add(std::mem::size_of::<NetworkAddressPoolV1>())?
            .checked_add(8 * std::mem::size_of::<Vec<u8>>())?;
        let bytes = self.bytes.len().checked_mul(node.checked_mul(4)?.checked_add(8)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    pub(crate) fn capture_native_once_v4(&mut self, path: &Path)
        -> Result<(), ProtectedNetworkPolicyErrorV1> {
        if self.native.is_some() || self.taken {
            self.repeated.get_or_insert(ProtectedNetworkPolicyErrorV1::ProtectedPath);
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }
        self.native = Some(self.capture_native_v4(path));
        self.native.as_ref().and_then(|result| result.as_ref().ok())
            .map(|()| ()).ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)
    }

    fn capture_native_v4(&mut self, path: &Path) -> Result<(), ProtectedNetworkPolicyErrorV1> {
        self.directory = Some(open(path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty()));
        let directory = self.directory.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        self.directory_metadata = Some(fstat(directory));
        let directory_metadata = self.directory_metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory
            || directory_metadata.st_uid != 0
            || !matches!(directory_metadata.st_mode & 0o7777, 0o500 | 0o700) {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }
        self.opened = Some(openat(directory, NETWORK_POLICY_CATALOG_FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty()).map(Some));
        let descriptor = self.opened.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|descriptor| descriptor.as_ref()).ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        self.metadata = Some(fstat(descriptor));
        let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        let declared_size = usize::try_from(metadata.st_size)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != 0 || metadata.st_nlink != 1
            || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
            || !(1..=MAXIMUM_CATALOG_BYTES).contains(&declared_size) {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }
        self.declared_size = Some(declared_size);
        let descriptor = self.opened.as_mut().and_then(|result| result.as_mut().ok())
            .and_then(Option::take).ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        self.file = Some(std::fs::File::from(descriptor));
        let file = self.file.as_mut().ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        self.bytes = Vec::with_capacity(declared_size);
        self.read = Some((&mut *file).take((MAXIMUM_CATALOG_BYTES + 1) as u64)
            .read_to_end(&mut self.bytes));
        if self.read.as_ref().is_none_or(Result::is_err) {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }
        self.current = Some(fstat(&*file));
        let current = self.current.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        if self.bytes.len() != declared_size
            || current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino
            || current.st_size != metadata.st_size || current.st_mode != metadata.st_mode
            || current.st_uid != metadata.st_uid || current.st_gid != metadata.st_gid
            || current.st_nlink != metadata.st_nlink || current.st_mtime != metadata.st_mtime
            || current.st_mtime_nsec != metadata.st_mtime_nsec || current.st_ctime != metadata.st_ctime
            || current.st_ctime_nsec != metadata.st_ctime_nsec {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }
        Ok(())
    }

    pub(crate) fn materialize_once_v4(&mut self, minimum_generation: u64)
        -> Result<(), ProtectedNetworkPolicyErrorV1> {
        if self.typed.is_some() || self.taken || !matches!(self.native, Some(Ok(()))) {
            self.repeated.get_or_insert(ProtectedNetworkPolicyErrorV1::Malformed);
            return Err(ProtectedNetworkPolicyErrorV1::Malformed);
        }
        self.typed = Some(self.materialize_v4(minimum_generation));
        self.typed.as_ref().and_then(|result| result.as_ref().ok()).map(|()| ())
            .ok_or_else(|| self.typed.as_ref().and_then(|result| result.as_ref().err())
                .copied().unwrap_or(ProtectedNetworkPolicyErrorV1::Malformed))
    }

    fn materialize_v4(&mut self, minimum_generation: u64)
        -> Result<(), ProtectedNetworkPolicyErrorV1> {
        self.decoded = Some(serde_json::from_slice(&self.bytes));
        let document = match self.decoded.take() {
            Some(Ok(document)) => document,
            failed => { self.decoded = failed; return Err(ProtectedNetworkPolicyErrorV1::Malformed); }
        };
        if document.version != FORMAT_VERSION || document.generation < minimum_generation {
            return Err(if document.generation < minimum_generation {
                ProtectedNetworkPolicyErrorV1::Rollback
            } else { ProtectedNetworkPolicyErrorV1::Malformed });
        }
        self.catalog = Some(document.into_catalog());
        let catalog = self.catalog.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProtectedNetworkPolicyErrorV1::Malformed)?;
        self.canonical = Some(catalog.encode_protected_publication());
        if self.canonical.as_ref().and_then(|result| result.as_ref().ok()) != Some(&self.bytes) {
            return Err(ProtectedNetworkPolicyErrorV1::Malformed);
        }
        Ok(())
    }

    pub(crate) fn catalog_v4(&self) -> Option<&NetworkPolicyCatalogV1> {
        if self.taken || self.repeated.is_some() || !matches!(self.typed, Some(Ok(()))) { return None; }
        self.catalog.as_ref().and_then(|result| result.as_ref().ok())
    }

    pub(crate) fn take_completed_v4(&mut self) -> Option<NetworkPolicyCatalogV1> {
        if self.taken || self.repeated.is_some() || !matches!(self.typed, Some(Ok(()))) {
            return None;
        }
        let Some(Ok(catalog)) = self.catalog.take() else { return None; };
        self.taken = true;
        Some(catalog)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(value: &Option<Result<T,E>>) -> Option<&(dyn Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.directory).or_else(|| error(&self.directory_metadata))
            .or_else(|| error(&self.opened)).or_else(|| error(&self.metadata))
            .or_else(|| error(&self.read)).or_else(|| error(&self.current))
            .or_else(|| error(&self.native)).or_else(|| error(&self.decoded))
            .or_else(|| error(&self.catalog)).or_else(|| error(&self.canonical))
            .or_else(|| error(&self.typed)).or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }
}

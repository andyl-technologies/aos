//! Retained protected files and whole-directory replacement detection.

use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::protected_file::{self, ExactReadError};
use aos_sandbox_source_provider_protocol::{
    SourceProviderKeyTrustStateV1, SourceProviderSigningKeyV1,
};
use ed25519_dalek::SigningKey;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, Stat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::SourceProviderSecurityError;
use crate::manifest::{
    SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES, SourceProviderSecurityManifestV1,
    SourceProviderSecurityRoleV1,
};
use crate::route_file::{SOURCE_PROVIDER_ROUTE_FILE_BYTES, SourceProviderRouteFileV1};
use crate::trust_file::{MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES, SourceProviderTrustFileV1};

const MANIFEST_NAME: &str = "source-provider-manifest";
const TRUST_NAME: &str = "source-provider-trust";
const ROUTE_NAME: &str = "current-route";
const ROOT_HELLO_KEY_NAME: &str = "root-mount-hello-signing-key";
const ROOT_RECORD_KEY_NAME: &str = "root-mount-record-signing-key";
const PROVIDER_HELLO_KEY_NAME: &str = "provider-hello-signing-key";
const PROVIDER_OUTCOME_KEY_NAME: &str = "provider-outcome-signing-key";
const SECRET_BYTES: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl MetadataSnapshot {
    const fn capture(value: &Stat) -> Self {
        Self {
            device: value.st_dev,
            inode: value.st_ino,
            mode: value.st_mode,
            owner: value.st_uid,
            group: value.st_gid,
            links: value.st_nlink,
            size: value.st_size,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: value.st_mtime_nsec,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: value.st_ctime_nsec,
        }
    }
}

struct RetainedPublicFile {
    descriptor: OwnedFd,
    metadata: MetadataSnapshot,
    exact: Vec<u8>,
    digest: [u8; 32],
    label: &'static str,
}

/// Retains exact non-secret bytes captured from revalidated protected files.
#[derive(Clone)]
pub(crate) struct PublicConfigurationCaptureV5 {
    pub(crate) manifest: Vec<u8>,
    pub(crate) trust: Vec<u8>,
    pub(crate) route: Vec<u8>,
}

/// Pins the private fixed public-only configuration archive directory.
pub(crate) struct ProtectedPublicArchiveDirectoryV5 {
    directory: OwnedFd,
    metadata: MetadataSnapshot,
    group: u32,
}

/// Retains an immutable public archive inode and its bounded exact bytes.
pub(crate) struct ProtectedPublicArchiveFileV5 {
    file: RetainedPublicFile,
    name: String,
}

impl ProtectedPublicArchiveDirectoryV5 {
    pub(crate) fn sync_original_directory(&self) -> Result<(), rustix::io::Errno> {
        rustix::fs::fsync(&self.directory)
    }

    pub(crate) fn bounded_size(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<usize, SourceProviderSecurityError> {
        self.revalidate()?;
        require_archive_name(name)?;
        let descriptor = protected_file::open_nofollow_child(&self.directory, name)
            .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "inspect size"))?;
        let metadata = validate_child(&descriptor, self.group, 1, maximum, "configuration archive")?;
        usize::try_from(metadata.size).map_err(|_| SourceProviderSecurityError::Currentness)
    }

    pub(crate) fn open_fixed() -> Result<Self, SourceProviderSecurityError> {
        let group = rustix::process::getegid().as_raw();
        let pinned = open_directory(Path::new(
            "/var/lib/aos/source-provider/configuration-history",
        ))?;
        let directory = rustix::fs::openat(
            &pinned,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "open"))?;
        rustix::fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| SourceProviderSecurityError::AlreadyInUse)?;

        let metadata = validate_archive_directory(&directory, group)?;
        let retained = Self { directory, metadata, group };
        retained.revalidate()?;
        Ok(retained)
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        if rustix::process::geteuid().as_raw() != 0
            || rustix::process::getegid().as_raw() != self.group
            || validate_archive_directory(&self.directory, self.group)? != self.metadata
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let reopened = open_directory(Path::new(
            "/var/lib/aos/source-provider/configuration-history",
        ))?;
        if validate_archive_directory(&reopened, self.group)? != self.metadata {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(())
    }

    pub(crate) fn read(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<ProtectedPublicArchiveFileV5, SourceProviderSecurityError> {
        self.revalidate()?;
        require_archive_name(name)?;
        let descriptor = protected_file::open_nofollow_child(&self.directory, name)
            .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "read"))?;
        let metadata = validate_child(&descriptor, self.group, 1, maximum, "configuration archive")?;
        let exact = read_archive_bytes(&descriptor, &metadata)?;
        let file = ProtectedPublicArchiveFileV5 {
            name: name.to_owned(),
            file: RetainedPublicFile {
                descriptor,
                metadata,
                digest: Sha256::digest(&exact).into(),
                exact,
                label: "configuration archive",
            },
        };
        self.validate_file(&file)?;
        Ok(file)
    }

    pub(crate) fn install(
        &self,
        name: &str,
        exact: &[u8],
        maximum: usize,
    ) -> Result<ProtectedPublicArchiveFileV5, SourceProviderSecurityError> {
        self.revalidate()?;
        require_archive_name(name)?;
        if exact.is_empty() || exact.len() > maximum {
            return Err(SourceProviderSecurityError::format("configuration archive", "size"));
        }

        // No overwrite or rename can replace immutable evidence. A failed
        // install may leave an orphan, which is never Journal membership.
        match rustix::fs::openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o440),
        ) {
            Ok(descriptor) => {
                rustix::fs::fchmod(&descriptor, Mode::from_raw_mode(0o440))
                    .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "mode"))?;
                let mut remainder = exact;
                while !remainder.is_empty() {
                    let written = rustix::io::write(&descriptor, remainder)
                        .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "write"))?;
                    if written == 0 {
                        return Err(SourceProviderSecurityError::Currentness);
                    }
                    remainder = &remainder[written..];
                }
                rustix::fs::fsync(&descriptor)
                    .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "sync"))?;
                rustix::fs::fsync(&self.directory)
                    .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "sync directory"))?;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => {
                return Err(SourceProviderSecurityError::filesystem("configuration archive", "create"));
            }
        }

        let file = self.read(name, maximum)?;
        if file.exact() != exact {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(file)
    }

    pub(crate) fn validate_file(
        &self,
        file: &ProtectedPublicArchiveFileV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        validate_retained_public(&file.file, self.group)?;
        let reopened = protected_file::open_nofollow_child(&self.directory, &file.name)
            .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "reopen"))?;
        if validate_child(&reopened, self.group, file.exact().len(), file.exact().len(), "configuration archive")?
            != file.file.metadata
            || read_exact_size(&reopened, file.exact().len(), "configuration archive")? != file.exact()
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        self.revalidate()
    }
}

impl ProtectedPublicArchiveFileV5 {
    pub(crate) fn sync_original_inode(&self) -> Result<(), rustix::io::Errno> {
        rustix::fs::fsync(&self.file.descriptor)
    }

    pub(crate) fn exact(&self) -> &[u8] {
        &self.file.exact
    }
}

/// Pins only the fixed public archive for named O_PATH-relative reads.
///
/// This staged owner has no writer, directory listing, flock or path selector.
pub(crate) struct ReadonlyPublicArchiveDirectoryV1 {
    directory: Option<OwnedFd>,
    comparison: Option<OwnedFd>,
    metadata: Option<MetadataSnapshot>,
    group: u32,
}

impl ReadonlyPublicArchiveDirectoryV1 {
    pub(crate) fn new() -> Self {
        Self {
            directory: None,
            comparison: None,
            metadata: None,
            group: rustix::process::getegid().as_raw(),
        }
    }

    pub(crate) fn open_fixed(&mut self) -> Result<(), SourceProviderSecurityError> {
        if self.directory.is_some() {
            return Err(SourceProviderSecurityError::Currentness);
        }
        self.directory = Some(open_directory(Path::new(
            "/var/lib/aos/source-provider/configuration-history",
        ))?);
        let directory = self.directory.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        self.metadata = Some(validate_archive_directory(directory, self.group)?);
        self.revalidate()
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), SourceProviderSecurityError> {
        if self.comparison.is_some() {
            return Err(SourceProviderSecurityError::Currentness);
        }

        let directory = self.directory.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let metadata = self.metadata.ok_or(SourceProviderSecurityError::Currentness)?;
        if rustix::process::geteuid().as_raw() != 0
            || rustix::process::getegid().as_raw() != self.group
            || validate_archive_directory(directory, self.group)? != metadata
        {
            return Err(SourceProviderSecurityError::Currentness);
        }

        // Park the returned comparison before metadata can refuse or unwind.
        // A failed slot is never replaced, and the original directory stays held.
        self.comparison = Some(open_directory(Path::new(
            "/var/lib/aos/source-provider/configuration-history",
        ))?);
        let comparison = self.comparison.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        if validate_archive_directory(comparison, self.group)? != metadata {
            return Err(SourceProviderSecurityError::Currentness);
        }

        self.comparison = None;
        Ok(())
    }

    pub(crate) fn read(
        &mut self,
        file: &mut ReadonlyPublicArchiveFileV1,
        kind: ReadonlyPublicArchiveNameV1,
        maximum: usize,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        if file.descriptor.is_some() {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let directory = self.directory.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        file.name = Some(kind.filename());
        let name = file.name.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let opened = protected_file::open_nofollow_child(directory, name);
        file.descriptor = Some(opened.map_err(|source| file.record_syscall(source, "open"))?);
        let descriptor = file.descriptor.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        file.metadata = Some(validate_child(
            descriptor, self.group, 1, maximum, "configuration archive",
        )?);
        let size = usize::try_from(file.metadata.ok_or(SourceProviderSecurityError::Currentness)?.size)
            .map_err(|_| SourceProviderSecurityError::Currentness)?;
        let reserved = file.exact.try_reserve_exact(size);
        file.finish_allocation(reserved)?;
        file.exact.resize(size, 0);

        file.read_original()?;
        self.validate_file(file)
    }

    pub(crate) fn validate_file(
        &mut self,
        file: &mut ReadonlyPublicArchiveFileV1,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        let directory = self.directory.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let descriptor = file.descriptor.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let expected = file.metadata.ok_or(SourceProviderSecurityError::Currentness)?;
        let size = file.exact.len();
        if validate_child(descriptor, self.group, size, size, "configuration archive")? != expected {
            return Err(SourceProviderSecurityError::Currentness);
        }

        let reserved = file.scratch.try_reserve_exact(size.saturating_sub(file.scratch.len()));
        file.finish_allocation(reserved)?;
        file.scratch.resize(size, 0);
        file.compare_original()?;
        file.compare_original()?;
        let name = file.name.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let reopened = protected_file::open_nofollow_child(directory, name);
        file.comparison = Some(reopened.map_err(|source| file.record_syscall(source, "reopen"))?);
        let comparison = file.comparison.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        if validate_child(comparison, self.group, size, size, "configuration archive")? != expected {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let result = protected_file::read_exact_positioned_retaining_cause(comparison, &mut file.scratch);
        file.finish_read(result)?;
        if file.scratch != file.exact
            || validate_child(
                file.descriptor.as_ref().ok_or(SourceProviderSecurityError::Currentness)?,
                self.group, size, size, "configuration archive",
            )? != expected
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        self.revalidate()?;
        file.comparison = None;
        Ok(())
    }
}

/// Restricts this reader to two public image kinds, never origin/cut files.
pub(crate) enum ReadonlyPublicArchiveNameV1 {
    Selected(aos_sandbox_core::ObjectDigest),
    Deployment(aos_sandbox_core::ObjectDigest),
}

impl ReadonlyPublicArchiveNameV1 {
    fn filename(self) -> String {
        let (kind, digest) = match self {
            Self::Selected(digest) => (b's', digest),
            Self::Deployment(digest) => (b'e', digest),
        };
        archive_filename(kind, digest)
    }
}

// This is the existing Source filename encoding, shared without changing its
// allocation, byte sequence or ignored infallible String-formatting result.
pub(crate) fn archive_filename(kind: u8, identity: aos_sandbox_core::ObjectDigest) -> String {
    use std::fmt::Write as _;
    let mut name = String::with_capacity(66);
    name.push(char::from(kind));
    name.push('-');
    for byte in identity.as_bytes() {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// Retains the original inode, partial bytes and actual read cause before mapping.
pub(crate) struct ReadonlyPublicArchiveFileV1 {
    descriptor: Option<OwnedFd>,
    comparison: Option<OwnedFd>,
    name: Option<String>,
    metadata: Option<MetadataSnapshot>,
    exact: Vec<u8>,
    scratch: Vec<u8>,
    read_failure: Option<protected_file::ExactReadFailure>,
    syscall_failure: Option<rustix::io::Errno>,
    allocation_failure: Option<std::collections::TryReserveError>,
}

impl ReadonlyPublicArchiveFileV1 {
    pub(crate) const fn new() -> Self {
        Self {
            descriptor: None,
            comparison: None,
            name: None,
            metadata: None,
            exact: Vec::new(),
            scratch: Vec::new(),
            read_failure: None,
            syscall_failure: None,
            allocation_failure: None,
        }
    }

    pub(crate) fn exact(&self) -> &[u8] {
        &self.exact
    }

    pub(crate) fn read_failure(&self) -> Option<&protected_file::ExactReadFailure> {
        self.read_failure.as_ref()
    }

    pub(crate) fn syscall_failure(&self) -> Option<&rustix::io::Errno> {
        self.syscall_failure.as_ref()
    }

    pub(crate) fn allocation_failure(&self) -> Option<&std::collections::TryReserveError> {
        self.allocation_failure.as_ref()
    }

    fn finish_allocation(
        &mut self,
        result: Result<(), std::collections::TryReserveError>,
    ) -> Result<(), SourceProviderSecurityError> {
        if let Err(source) = result {
            self.allocation_failure.get_or_insert(source);
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(())
    }

    fn record_syscall(
        &mut self,
        source: rustix::io::Errno,
        operation: &'static str,
    ) -> SourceProviderSecurityError {
        self.syscall_failure.get_or_insert(source);
        SourceProviderSecurityError::filesystem("configuration archive", operation)
    }

    fn read_original(&mut self) -> Result<(), SourceProviderSecurityError> {
        let descriptor = self.descriptor.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let result = protected_file::read_exact_positioned_retaining_cause(descriptor, &mut self.exact);
        self.finish_read(result)
    }

    fn compare_original(&mut self) -> Result<(), SourceProviderSecurityError> {
        let descriptor = self.descriptor.as_ref()
            .ok_or(SourceProviderSecurityError::Currentness)?;
        let result = protected_file::read_exact_positioned_retaining_cause(descriptor, &mut self.scratch);
        self.finish_read(result)?;
        if self.scratch != self.exact {
            return Err(SourceProviderSecurityError::Currentness);
        }
        Ok(())
    }

    fn finish_read(
        &mut self,
        result: Result<(), protected_file::ExactReadFailure>,
    ) -> Result<(), SourceProviderSecurityError> {
        if let Err(source) = result {
            let source = self.read_failure.get_or_insert(source);
            return Err(match source.legacy_classification() {
                ExactReadError::Read => SourceProviderSecurityError::filesystem("configuration archive", "read"),
                ExactReadError::TrailingBytes => SourceProviderSecurityError::Metadata { object: "configuration archive" },
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod readonly_archive_tests {
    use super::*;

    #[test]
    fn fixed_names_share_exact_legacy_encoding_without_other_kinds() {
        let digest = aos_sandbox_core::ObjectDigest::from_bytes([0xab; 32]);
        let selected = ReadonlyPublicArchiveNameV1::Selected(digest).filename();
        let deployment = ReadonlyPublicArchiveNameV1::Deployment(digest).filename();

        assert_eq!(selected, archive_filename(b's', digest));
        assert_eq!(deployment, archive_filename(b'e', digest));
        assert_eq!(selected.len(), 66);
        assert!(selected.starts_with("s-abab"));
        require_archive_name(&selected).unwrap();
        require_archive_name(&deployment).unwrap();
    }

    #[test]
    fn native_read_cause_and_partial_output_survive_diagnostic_mapping() {
        let mut file = ReadonlyPublicArchiveFileV1::new();
        file.exact.extend_from_slice(b"actual partial DATA");
        let error = protected_file::ExactReadFailure::Io(rustix::io::Errno::INTR);

        assert!(file.finish_read(Err(error)).is_err());
        let first = file.read_failure().unwrap() as *const protected_file::ExactReadFailure;
        assert!(file.finish_read(Err(protected_file::ExactReadFailure::TrailingBytes)).is_err());

        assert_eq!(file.exact(), b"actual partial DATA");
        assert_eq!(file.read_failure().unwrap() as *const protected_file::ExactReadFailure, first);
        assert!(matches!(file.read_failure(), Some(protected_file::ExactReadFailure::Io(source))
            if *source == rustix::io::Errno::INTR));
        assert!(file.descriptor.is_none());
    }
}

fn require_archive_name(name: &str) -> Result<(), SourceProviderSecurityError> {
    if name.len() != 66
        || !matches!(name.get(..2), Some("e-") | Some("o-") | Some("c-") | Some("s-"))
        || !name.as_bytes()[2..].iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(SourceProviderSecurityError::DirectoryPath);
    }
    Ok(())
}

fn validate_archive_directory(
    descriptor: &OwnedFd,
    group: u32,
) -> Result<MetadataSnapshot, SourceProviderSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem("configuration archive", "inspect"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(SourceProviderSecurityError::Metadata { object: "configuration archive" });
    }
    // Entries are intentionally added; directory timestamps/size are not
    // immutable identity. Device, inode, ownership and mode remain pinned.
    let mut identity = MetadataSnapshot::capture(&stat);
    identity.size = 0;
    identity.modified_seconds = 0;
    identity.modified_nanoseconds = 0;
    identity.changed_seconds = 0;
    identity.changed_nanoseconds = 0;
    Ok(identity)
}

pub(crate) struct RetainedSecret {
    descriptor: OwnedFd,
    metadata: MetadataSnapshot,
    key_id: [u8; 16],
    signing_key: SigningKey,
    label: &'static str,
}

impl core::fmt::Debug for RetainedSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RetainedSecret([redacted])")
    }
}

impl RetainedSecret {
    pub(crate) const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

pub(crate) struct ProtectedSourceProviderFiles {
    path: PathBuf,
    group: u32,
    role: SourceProviderSecurityRoleV1,
    directory: OwnedFd,
    directory_metadata: MetadataSnapshot,
    manifest_file: RetainedPublicFile,
    trust_file: RetainedPublicFile,
    route_file: RetainedPublicFile,
    secrets: [RetainedSecret; 2],
    manifest: SourceProviderSecurityManifestV1,
    trust: SourceProviderTrustFileV1,
    route: SourceProviderRouteFileV1,
}

impl ProtectedSourceProviderFiles {
    pub(crate) fn public_archive_capture(
        &self,
    ) -> Result<PublicConfigurationCaptureV5, SourceProviderSecurityError> {
        self.revalidate()?;

        // These retained values were bounded before allocation on load. No
        // secret file or process/session authority leaves protected custody.
        let capture = PublicConfigurationCaptureV5 {
            manifest: self.manifest_file.exact.clone(),
            trust: self.trust_file.exact.clone(),
            route: self.route_file.exact.clone(),
        };

        self.revalidate()?;
        Ok(capture)
    }

    pub(crate) fn load(
        path: &Path,
        role: SourceProviderSecurityRoleV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        validate_absolute_fixed_path(path)?;
        let group = rustix::process::getegid().as_raw();
        let directory = open_directory(path)?;
        let directory_metadata = validate_directory(&directory, group)?;
        require_exact_names(&directory, directory_metadata, group, role)?;

        let manifest_file = load_fixed_public(
            &directory,
            MANIFEST_NAME,
            "manifest",
            group,
            SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES,
        )?;
        rustix::fs::flock(
            &manifest_file.descriptor,
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::AGAIN {
                SourceProviderSecurityError::AlreadyInUse
            } else {
                SourceProviderSecurityError::filesystem("manifest", "lock")
            }
        })?;
        let manifest = SourceProviderSecurityManifestV1::decode(&manifest_file.exact)?;
        if manifest.role() != role {
            return Err(SourceProviderSecurityError::format("manifest", "role"));
        }

        let trust_file = load_bounded_public(
            &directory,
            TRUST_NAME,
            "trust",
            group,
            104,
            MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES,
        )?;
        let route_file = load_fixed_public(
            &directory,
            ROUTE_NAME,
            "route",
            group,
            SOURCE_PROVIDER_ROUTE_FILE_BYTES,
        )?;
        if trust_file.digest != *manifest.trust_file_sha256()
            || route_file.digest != *manifest.route_file_sha256()
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let trust = SourceProviderTrustFileV1::decode(&trust_file.exact)?;
        let route = SourceProviderRouteFileV1::decode(&route_file.exact)?;
        validate_manifest_projections(&manifest, &trust, &route)?;

        let [
            (first_name, first_label, first_index),
            (second_name, second_label, second_index),
        ] = local_keys(role);
        let secrets = [
            load_secret(&directory, first_name, first_label, group)?,
            load_secret(&directory, second_name, second_label, group)?,
        ];
        validate_secret(&secrets[0], &manifest.signers()[first_index], &trust)?;
        validate_secret(&secrets[1], &manifest.signers()[second_index], &trust)?;
        if secrets[0].signing_key.verifying_key() == secrets[1].signing_key.verifying_key() {
            return Err(SourceProviderSecurityError::KeyMaterial {
                object: "role-local keys",
            });
        }

        let files = Self {
            path: path.to_path_buf(),
            group,
            role,
            directory,
            directory_metadata,
            manifest_file,
            trust_file,
            route_file,
            secrets,
            manifest,
            trust,
            route,
        };
        files.revalidate()?;
        Ok(files)
    }

    pub(crate) const fn manifest(&self) -> &SourceProviderSecurityManifestV1 {
        &self.manifest
    }

    pub(crate) const fn trust(&self) -> &SourceProviderTrustFileV1 {
        &self.trust
    }

    pub(crate) const fn route(&self) -> &SourceProviderRouteFileV1 {
        &self.route
    }

    pub(crate) const fn hello_key(&self) -> &RetainedSecret {
        &self.secrets[0]
    }

    pub(crate) const fn outcome_key(&self) -> &RetainedSecret {
        &self.secrets[1]
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        if rustix::process::geteuid().as_raw() != 0
            || rustix::process::getegid().as_raw() != self.group
            || validate_directory(&self.directory, self.group)? != self.directory_metadata
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        require_exact_names(
            &self.directory,
            self.directory_metadata,
            self.group,
            self.role,
        )?;
        validate_retained_public(&self.manifest_file, self.group)?;
        validate_retained_public(&self.trust_file, self.group)?;
        validate_retained_public(&self.route_file, self.group)?;
        for secret in &self.secrets {
            validate_retained_secret(secret, self.group)?;
        }

        let reopened = open_directory(&self.path)?;
        if validate_directory(&reopened, self.group)? != self.directory_metadata {
            return Err(SourceProviderSecurityError::Currentness);
        }
        require_exact_names(&reopened, self.directory_metadata, self.group, self.role)?;
        compare_reopened_public(&reopened, &self.manifest_file, self.group)?;
        compare_reopened_public(&reopened, &self.trust_file, self.group)?;
        compare_reopened_public(&reopened, &self.route_file, self.group)?;
        for (secret, (name, _, _)) in self.secrets.iter().zip(local_keys(self.role)) {
            compare_reopened_secret(&reopened, name, secret, self.group)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_manifest_projections(
    manifest: &SourceProviderSecurityManifestV1,
    trust: &SourceProviderTrustFileV1,
    route: &SourceProviderRouteFileV1,
) -> Result<(), SourceProviderSecurityError> {
    let trust_set = trust.trust_set();
    let protected_route = route.route();
    let exact = trust_set.trust_generation() == manifest.trust_generation()
        && trust_set.trust_digest() == manifest.trust_digest()
        && trust_set.revocation_generation() == manifest.revocation_generation()
        && trust_set.revocation_digest() == manifest.revocation_digest()
        && protected_route.route_id() == manifest.route_id()
        && protected_route.route_generation() == manifest.route_generation()
        && protected_route.route_digest() == manifest.route_digest()
        && protected_route.provider_authority_id() == manifest.signers()[1].authority_id()
        && route.root_mount_authority_id() == manifest.signers()[0].authority_id()
        && route.proof_capabilities() == manifest.proof_capabilities()
        && route.allow_recursive() == manifest.allow_recursive()
        && route.allow_kernel_coupled() == manifest.allow_kernel_coupled();
    if !exact {
        return Err(SourceProviderSecurityError::Currentness);
    }

    for signer in manifest.signers() {
        let key = trust_set
            .keys()
            .iter()
            .find(|entry| entry.signer() == signer)
            .ok_or(SourceProviderSecurityError::format(
                "manifest",
                "trusted signer",
            ))?;
        if key.state() != SourceProviderKeyTrustStateV1::Eligible {
            return Err(SourceProviderSecurityError::format(
                "manifest",
                "current signer",
            ));
        }
    }
    let mut public_keys = Vec::with_capacity(4);
    for signer in manifest.signers() {
        let key = trust_set
            .keys()
            .iter()
            .find(|entry| entry.signer() == signer)
            .ok_or(SourceProviderSecurityError::format(
                "manifest",
                "trusted key",
            ))?;
        public_keys.push(*key.public_key());
    }
    if (0..4).any(|left| (left + 1..4).any(|right| public_keys[left] == public_keys[right])) {
        return Err(SourceProviderSecurityError::format(
            "manifest",
            "key collision",
        ));
    }
    Ok(())
}

fn local_keys(role: SourceProviderSecurityRoleV1) -> [(&'static str, &'static str, usize); 2] {
    match role {
        SourceProviderSecurityRoleV1::RootMount => [
            (ROOT_HELLO_KEY_NAME, "Root Mount hello key", 0),
            (ROOT_RECORD_KEY_NAME, "Root Mount record key", 2),
        ],
        SourceProviderSecurityRoleV1::Provider => [
            (PROVIDER_HELLO_KEY_NAME, "provider hello key", 1),
            (PROVIDER_OUTCOME_KEY_NAME, "provider outcome key", 3),
        ],
    }
}

fn expected_names(role: SourceProviderSecurityRoleV1) -> BTreeSet<Vec<u8>> {
    [MANIFEST_NAME, TRUST_NAME, ROUTE_NAME]
        .into_iter()
        .chain(local_keys(role).map(|entry| entry.0))
        .map(|name| name.as_bytes().to_vec())
        .collect()
}

fn require_exact_names(
    directory: &OwnedFd,
    expected_metadata: MetadataSnapshot,
    group: u32,
    role: SourceProviderSecurityRoleV1,
) -> Result<(), SourceProviderSecurityError> {
    // Path-resolution descriptors are O_PATH pins. Reopen `.` through the pin
    // so enumeration can never race through a reconstructed absolute path.
    let readable = rustix::fs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceProviderSecurityError::filesystem("directory", "open for enumeration"))?;
    if validate_directory(&readable, group)? != expected_metadata {
        return Err(SourceProviderSecurityError::Currentness);
    }

    let mut observed = BTreeSet::new();
    let entries = rustix::fs::Dir::read_from(&readable)
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "enumerate"))?;
    for entry in entries {
        let entry =
            entry.map_err(|_| SourceProviderSecurityError::filesystem("directory", "enumerate"))?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if !observed.insert(name.to_vec()) {
            return Err(SourceProviderSecurityError::DirectoryContents);
        }
    }
    if validate_directory(&readable, group)? != expected_metadata
        || validate_directory(directory, group)? != expected_metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    if observed != expected_names(role) {
        return Err(SourceProviderSecurityError::DirectoryContents);
    }
    Ok(())
}

fn validate_absolute_fixed_path(path: &Path) -> Result<(), SourceProviderSecurityError> {
    if !protected_file::is_absolute_fixed_path(path) {
        return Err(SourceProviderSecurityError::DirectoryPath);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<OwnedFd, SourceProviderSecurityError> {
    let filesystem_root = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceProviderSecurityError::filesystem("filesystem root", "open"))?;
    let root = BeneathRoot::from_owned(filesystem_root)
        .map_err(|_| SourceProviderSecurityError::filesystem("filesystem root", "adopt"))?;
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| SourceProviderSecurityError::DirectoryPath)?;
    let resolved = root
        .resolve(
            relative,
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "resolve"))?;
    let resolved = BeneathRoot::from_resolved(resolved)
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "adopt"))?;
    rustix::io::dup(resolved.as_fd())
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "duplicate"))
}

fn validate_directory(
    descriptor: &OwnedFd,
    group: u32,
) -> Result<MetadataSnapshot, SourceProviderSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "inspect"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_mode & 0o7777 != 0o550
    {
        return Err(SourceProviderSecurityError::Metadata {
            object: "directory",
        });
    }
    Ok(MetadataSnapshot::capture(&stat))
}

fn load_fixed_public(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
    group: u32,
    size: usize,
) -> Result<RetainedPublicFile, SourceProviderSecurityError> {
    let descriptor = open_child(directory, name, label)?;
    let metadata = validate_child(&descriptor, group, size, size, label)?;
    let exact = read_exact_size(&descriptor, size, label)?;
    let repeated = read_exact_size(&descriptor, size, label)?;
    if exact != repeated || validate_child(&descriptor, group, size, size, label)? != metadata {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(RetainedPublicFile {
        descriptor,
        metadata,
        digest: Sha256::digest(&exact).into(),
        exact,
        label,
    })
}

fn load_bounded_public(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
    group: u32,
    minimum: usize,
    maximum: usize,
) -> Result<RetainedPublicFile, SourceProviderSecurityError> {
    let descriptor = open_child(directory, name, label)?;
    let stat = rustix::fs::fstat(&descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "inspect"))?;
    let size = usize::try_from(stat.st_size)
        .map_err(|_| SourceProviderSecurityError::Metadata { object: label })?;
    let metadata = validate_child(&descriptor, group, minimum, maximum, label)?;
    let exact = read_exact_size(&descriptor, size, label)?;
    let repeated = read_exact_size(&descriptor, size, label)?;
    if exact != repeated || validate_child(&descriptor, group, minimum, maximum, label)? != metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(RetainedPublicFile {
        descriptor,
        metadata,
        digest: Sha256::digest(&exact).into(),
        exact,
        label,
    })
}

fn load_secret(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
    group: u32,
) -> Result<RetainedSecret, SourceProviderSecurityError> {
    let descriptor = open_child(directory, name, label)?;
    let metadata = validate_child(&descriptor, group, SECRET_BYTES, SECRET_BYTES, label)?;
    let exact = Zeroizing::new(read_exact_array::<SECRET_BYTES>(&descriptor, label)?);
    let repeated = Zeroizing::new(read_exact_array::<SECRET_BYTES>(&descriptor, label)?);
    if exact[..] != repeated[..]
        || validate_child(&descriptor, group, SECRET_BYTES, SECRET_BYTES, label)? != metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let key_id = exact[..16]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::KeyMaterial { object: label })?;
    let seed: &[u8; 32] = exact[16..]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::KeyMaterial { object: label })?;
    if key_id == [0; 16] || seed == &[0; 32] {
        return Err(SourceProviderSecurityError::KeyMaterial { object: label });
    }
    let signing_key = SigningKey::from_bytes(seed);
    if signing_key.verifying_key().is_weak() {
        return Err(SourceProviderSecurityError::KeyMaterial { object: label });
    }
    Ok(RetainedSecret {
        descriptor,
        metadata,
        key_id,
        signing_key,
        label,
    })
}

fn validate_secret(
    secret: &RetainedSecret,
    signer: &SourceProviderSigningKeyV1,
    trust: &SourceProviderTrustFileV1,
) -> Result<(), SourceProviderSecurityError> {
    let public_key = secret.signing_key.verifying_key().to_bytes();
    let digest: [u8; 32] = Sha256::digest(public_key).into();
    let trusted = trust
        .trust_set()
        .keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .is_some_and(|entry| entry.public_key() == &public_key);
    if secret.key_id != signer.key_id()
        || digest != *signer.public_key_digest().as_bytes()
        || !trusted
    {
        return Err(SourceProviderSecurityError::KeyMaterial {
            object: secret.label,
        });
    }
    Ok(())
}

fn open_child(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
) -> Result<OwnedFd, SourceProviderSecurityError> {
    protected_file::open_nofollow_child(directory, name)
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "open"))
}

fn validate_child(
    descriptor: &OwnedFd,
    group: u32,
    minimum: usize,
    maximum: usize,
    label: &'static str,
) -> Result<MetadataSnapshot, SourceProviderSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "inspect"))?;
    let size = usize::try_from(stat.st_size)
        .map_err(|_| SourceProviderSecurityError::Metadata { object: label })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o440
        || !(minimum..=maximum).contains(&size)
    {
        return Err(SourceProviderSecurityError::Metadata { object: label });
    }
    Ok(MetadataSnapshot::capture(&stat))
}

fn read_exact_size(
    descriptor: &OwnedFd,
    size: usize,
    label: &'static str,
) -> Result<Vec<u8>, SourceProviderSecurityError> {
    let mut output = vec![0; size];
    read_into(descriptor, &mut output, label)?;
    Ok(output)
}

// The archive reader passes the same bounded metadata observation that admitted
// this inode. Later growth or shrinkage fails the exact read, never enlarging
// its allocation to a separately observed size.
fn read_archive_bytes(
    descriptor: &OwnedFd,
    metadata: &MetadataSnapshot,
) -> Result<Vec<u8>, SourceProviderSecurityError> {
    let size = usize::try_from(metadata.size)
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    read_exact_size(descriptor, size, "configuration archive")
}

fn read_exact_array<const N: usize>(
    descriptor: &OwnedFd,
    label: &'static str,
) -> Result<[u8; N], SourceProviderSecurityError> {
    let mut output = [0; N];
    read_into(descriptor, &mut output, label)?;
    Ok(output)
}

fn read_into(
    descriptor: &OwnedFd,
    output: &mut [u8],
    label: &'static str,
) -> Result<(), SourceProviderSecurityError> {
    protected_file::read_exact_positioned(descriptor, output).map_err(|error| match error {
        ExactReadError::Read => SourceProviderSecurityError::filesystem(label, "read"),
        ExactReadError::TrailingBytes => SourceProviderSecurityError::Metadata { object: label },
    })
}

fn validate_retained_public(
    file: &RetainedPublicFile,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    if validate_child(
        &file.descriptor,
        group,
        file.exact.len(),
        file.exact.len(),
        file.label,
    )? != file.metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let exact = read_exact_size(&file.descriptor, file.exact.len(), file.label)?;
    let repeated = read_exact_size(&file.descriptor, file.exact.len(), file.label)?;
    if validate_child(
        &file.descriptor,
        group,
        file.exact.len(),
        file.exact.len(),
        file.label,
    )? != file.metadata
        || exact != file.exact
        || repeated != exact
        || <[u8; 32]>::from(Sha256::digest(&exact)) != file.digest
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn validate_retained_secret(
    secret: &RetainedSecret,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    if validate_child(
        &secret.descriptor,
        group,
        SECRET_BYTES,
        SECRET_BYTES,
        secret.label,
    )? != secret.metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let exact = Zeroizing::new(read_exact_array::<SECRET_BYTES>(
        &secret.descriptor,
        secret.label,
    )?);
    let repeated = Zeroizing::new(read_exact_array::<SECRET_BYTES>(
        &secret.descriptor,
        secret.label,
    )?);
    let seed: &[u8; 32] = exact[16..]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    let observed = SigningKey::from_bytes(seed);
    if validate_child(
        &secret.descriptor,
        group,
        SECRET_BYTES,
        SECRET_BYTES,
        secret.label,
    )? != secret.metadata
        || exact[..] != repeated[..]
        || exact[..16] != secret.key_id
        || observed.verifying_key() != secret.signing_key.verifying_key()
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn compare_reopened_public(
    directory: &OwnedFd,
    retained: &RetainedPublicFile,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    let reopened = load_bounded_public(
        directory,
        match retained.label {
            "manifest" => MANIFEST_NAME,
            "trust" => TRUST_NAME,
            "route" => ROUTE_NAME,
            _ => return Err(SourceProviderSecurityError::Currentness),
        },
        retained.label,
        group,
        retained.exact.len(),
        retained.exact.len(),
    )?;
    if reopened.metadata != retained.metadata
        || reopened.exact != retained.exact
        || reopened.digest != retained.digest
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn compare_reopened_secret(
    directory: &OwnedFd,
    name: &'static str,
    retained: &RetainedSecret,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    let reopened = load_secret(directory, name, retained.label, group)?;
    if reopened.metadata != retained.metadata
        || reopened.key_id != retained.key_id
        || reopened.signing_key.verifying_key() != retained.signing_key.verifying_key()
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn provider_root_resolution_rejects_symlinked_ancestor_and_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("parent");
        let endpoint = parent.join("endpoint");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&endpoint).unwrap();
        symlink(&parent, temporary.path().join("parent-link")).unwrap();
        symlink(&endpoint, parent.join("endpoint-link")).unwrap();

        assert!(open_directory(&endpoint).is_ok());
        assert!(open_directory(&temporary.path().join("parent-link/endpoint")).is_err());
        assert!(open_directory(&parent.join("endpoint-link")).is_err());
    }

    // These temporary descriptors test exact bounded-extent reading only. They
    // are not genuine fixed-root protected archive owners or admissions.
    #[test]
    fn archive_read_uses_the_admitted_metadata_extent() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"data").unwrap();
        let descriptor: OwnedFd = file.try_clone().unwrap().into();
        let metadata = MetadataSnapshot::capture(&rustix::fs::fstat(&descriptor).unwrap());

        let exact = read_archive_bytes(&descriptor, &metadata).unwrap();

        assert_eq!(metadata.size, 4);
        assert_eq!(exact.as_slice(), b"data");
    }

    #[test]
    fn archive_read_refuses_growth_or_shrinkage_after_admitted_metadata() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"data").unwrap();
        let descriptor: OwnedFd = file.try_clone().unwrap().into();
        let metadata = MetadataSnapshot::capture(&rustix::fs::fstat(&descriptor).unwrap());

        file.set_len(8).unwrap();
        assert!(read_archive_bytes(&descriptor, &metadata).is_err());

        file.set_len(2).unwrap();
        assert!(read_archive_bytes(&descriptor, &metadata).is_err());
        assert_eq!(metadata.size, 4);
    }

    #[test]
    fn archive_read_refuses_an_unrepresentable_metadata_extent() {
        let file = tempfile::tempfile().unwrap();
        let descriptor: OwnedFd = file.into();
        let mut metadata = MetadataSnapshot::capture(&rustix::fs::fstat(&descriptor).unwrap());
        metadata.size = -1;

        assert!(matches!(
            read_archive_bytes(&descriptor, &metadata),
            Err(SourceProviderSecurityError::Currentness),
        ));
    }
}

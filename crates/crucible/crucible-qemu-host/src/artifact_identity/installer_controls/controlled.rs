//! Reads installed launch geometry using fixed storage under the retained original.
//!
//! This reader borrows the launcher's selected paths. It opens only immutable
//! package inputs, checks both build markers and the complete final plugin, and
//! publishes a path binding after the final original cut. Parsing a sidecar or
//! presenting matching scalar requests cannot construct that binding.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest, Sha256};

use super::{IDENTITY_BYTES, InstallerControlIdentity, InstallerControlIdentityError};

const MARKER_BYTES: usize = 4096;
const PATH_BYTES: usize = 4096;

/// Preserves the initiating original or installed-artifact refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlledInstallerIdentityError {
    #[error("installed artifact original refused: {0}")]
    Original(#[from] HostSupervisionError),
    #[error("installed artifact authentication refused: {0}")]
    Artifact(#[from] InstallerControlIdentityError),
    #[error("native constructor artifact refused: {0}")]
    Constructor(#[from] super::super::native_constructor::NativeConstructorReadError),
    #[error("actual Source verifier funding refused: {0}")]
    Funding(#[from] crucible_host_resources::host_services::process_birth::ServiceBirthError),
}

impl From<std::io::Error> for ControlledInstallerIdentityError {
    fn from(error: std::io::Error) -> Self {
        InstallerControlIdentityError::Io(error).into()
    }
}

/// Prices a conservative fixed verifier/streaming peak before helper entry.
///
/// The conservative 64 KiB covers both 4096-byte markers, fixed package paths,
/// existing plugin streaming, declaration/header/name scratch, QEMU streaming,
/// hash/candidate/error and file bodies. All loops borrow the same Original;
/// no additional task, mapping or descriptor alias is created by hashing.
pub(crate) const fn installer_verifier_extent() -> u64 {
    64 * 1024
}

impl InstallerControlIdentity {
    /// Authenticates the selected installed pair without owned strings or maps.
    ///
    /// The containing launch control and host family must already pay for this
    /// fixed stack storage and at most three simultaneously open descriptors.
    /// Every read, including hashing the complete plugin tail, checks the real
    /// retained original. The caller retains the initiating error separately
    /// from its independent final original check.
    ///
    /// # Errors
    /// Refuses the same Source payer/original, malformed immutable package
    /// inputs, changed complete artifacts or unsupported constructor geometry.
    pub(crate) fn authenticate_original_paths(
        qemu: &Path,
        plugin: &Path,
        original: &HostOperationGuard,
        control: &crucible_host_resources::host_services::process_birth::SourceHostControlLease,
    ) -> Result<Self, ControlledInstallerIdentityError> {
        control.verify_original_capacity(original, 3, installer_verifier_extent())?;
        authenticate_original_paths(qemu, plugin, original)
    }
}

// Enter the complete fixed artifact frame only after the real same-Main loan.
fn authenticate_original_paths(
    qemu: &Path,
    plugin: &Path,
    original: &HostOperationGuard,
) -> Result<InstallerControlIdentity, ControlledInstallerIdentityError> {
    original.wait_slice()?;
    let qemu_package = Package::from_selected(qemu, SelectedKind::Qemu)?;
    let plugin_package = Package::from_selected(plugin, SelectedKind::Plugin)?;

    let mut qemu_marker = [0; MARKER_BYTES];
    let qemu_length = read_marker(
        &qemu_package,
        c"share/aos/crucible/qemu-build-identity.env",
        &mut qemu_marker,
        original,
    )?;
    let mut plugin_marker = [0; MARKER_BYTES];
    let plugin_length = read_marker(
        &plugin_package,
        c"nix-support/crucible-qemu-plugin-build-info",
        &mut plugin_marker,
        original,
    )?;
    validate_markers(&qemu_marker[..qemu_length], &plugin_marker[..plugin_length])?;
    let final_qemu = qemu_package.file_follow_selected()?;
    let constructors =
        super::super::native_constructor::authenticate_final_elf(&final_qemu, original)?;
    drop(final_qemu);
    drop(qemu_package);

    let mut sidecar = plugin_package.file(c"nix-support/crucible-installer-control-layouts")?;
    let mut bytes = [0; IDENTITY_BYTES];
    read_exact_original(&mut sidecar, &mut bytes, original)?;
    original.wait_slice()?;
    if sidecar.read(&mut [0])? != 0 {
        return Err(InstallerControlIdentityError::Invalid("tail").into());
    }
    drop(sidecar);
    let mut identity = super::parse(&bytes)?;
    let mut source = plugin_package.file(c"lib/libcrucible_qemu_plugin.so")?;
    let selected_source = plugin_package.file_follow_selected()?;
    let actual = source.metadata()?;
    let selected = selected_source.metadata()?;
    if (actual.dev(), actual.ino()) != (selected.dev(), selected.ino()) {
        return Err(InstallerControlIdentityError::ArtifactMismatch.into());
    }
    drop(selected_source);
    // Close the selected alias before streaming; the pinned canonical file
    // remains the sole source whose complete digest authenticates the record.
    authenticate_plugin(&mut source, &identity, original)?;
    original.wait_slice()?;
    identity.path_binding = Some(super::path_binding(qemu, plugin));
    identity.native_constructor = Some(constructors);
    Ok(identity)
}

enum SelectedKind {
    Qemu,
    Plugin,
}

struct Package<'a> {
    directory: File,
    selected_relative: &'a [u8],
}

impl<'a> Package<'a> {
    fn from_selected(
        selected: &'a Path,
        kind: SelectedKind,
    ) -> Result<Self, ControlledInstallerIdentityError> {
        use std::os::unix::ffi::OsStrExt;

        let bytes = selected.as_os_str().as_bytes();
        let rest = bytes
            .strip_prefix(b"/nix/store/")
            .ok_or(InstallerControlIdentityError::Unavailable)?;
        let split = rest
            .iter()
            .position(|byte| *byte == b'/')
            .ok_or(InstallerControlIdentityError::Unavailable)?;
        let name = &rest[..split];
        let alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
        if name.len() <= 33
            || name[32] != b'-'
            || !name[..32].iter().all(|byte| alphabet.contains(byte))
            || name.contains(&0)
        {
            return Err(InstallerControlIdentityError::Unavailable.into());
        }
        let relative = &rest[split + 1..];
        let supported = match kind {
            SelectedKind::Qemu => matches!(
                relative,
                b"bin/qemu-system-x86_64" | b"bin/qemu-system-aarch64"
            ),
            SelectedKind::Plugin => matches!(
                relative,
                b"lib/libcrucible_qemu_plugin.so" | b"lib/qemu/plugins/crucible-qemu-plugin.so"
            ),
        };
        if !supported {
            return Err(InstallerControlIdentityError::Unavailable.into());
        }
        let mut path = [0; PATH_BYTES];
        let root_length = b"/nix/store/".len() + split;
        let root = fixed_cstr(&bytes[..root_length], &mut path)?;
        let descriptor = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let directory = File::from(descriptor);
        if directory.metadata()?.mode() & 0o222 != 0 {
            return Err(InstallerControlIdentityError::Unavailable.into());
        }
        let package = Self {
            directory,
            selected_relative: relative,
        };
        // The selected executable itself must exist in the same pinned package.
        package.file_follow_selected()?;
        Ok(package)
    }

    fn file(&self, relative: &CStr) -> Result<File, ControlledInstallerIdentityError> {
        let descriptor = openat(
            &self.directory,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        readonly_file(File::from(descriptor))
    }

    fn file_follow_selected(&self) -> Result<File, ControlledInstallerIdentityError> {
        let mut bytes = [0; PATH_BYTES];
        let relative = fixed_cstr(self.selected_relative, &mut bytes)?;
        // Only the two closed package spellings are accepted. The official
        // plugin alias is additionally checked against the canonical file inode.
        let descriptor = openat(
            &self.directory,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        readonly_file(File::from(descriptor))
    }
}

fn readonly_file(file: File) -> Result<File, ControlledInstallerIdentityError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o222 != 0 {
        return Err(InstallerControlIdentityError::Unavailable.into());
    }
    Ok(file)
}

fn fixed_cstr<'a>(
    bytes: &[u8],
    storage: &'a mut [u8; PATH_BYTES],
) -> Result<&'a CStr, InstallerControlIdentityError> {
    if bytes.len() >= storage.len() || bytes.contains(&0) {
        return Err(InstallerControlIdentityError::Unavailable);
    }
    storage[..bytes.len()].copy_from_slice(bytes);
    storage[bytes.len()] = 0;
    CStr::from_bytes_with_nul(&storage[..bytes.len() + 1])
        .map_err(|_| InstallerControlIdentityError::Unavailable)
}

fn read_marker(
    package: &Package<'_>,
    path: &CStr,
    bytes: &mut [u8; MARKER_BYTES],
    original: &HostOperationGuard,
) -> Result<usize, ControlledInstallerIdentityError> {
    original.wait_slice()?;
    let mut file = package.file(path)?;
    let mut length = 0;
    while length != bytes.len() {
        original.wait_slice()?;
        let read = file.read(&mut bytes[length..])?;
        if read == 0 {
            return Ok(length);
        }
        length += read;
    }
    original.wait_slice()?;
    if file.read(&mut [0])? != 0 {
        return Err(InstallerControlIdentityError::Invalid("marker length").into());
    }
    Ok(length)
}

fn read_exact_original(
    file: &mut File,
    mut bytes: &mut [u8],
    original: &HostOperationGuard,
) -> Result<(), ControlledInstallerIdentityError> {
    while !bytes.is_empty() {
        original.wait_slice()?;
        let length = file.read(bytes)?;
        if length == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        bytes = &mut bytes[length..];
    }
    Ok(())
}

fn authenticate_plugin(
    file: &mut File,
    identity: &InstallerControlIdentity,
    original: &HostOperationGuard,
) -> Result<(), ControlledInstallerIdentityError> {
    let mut header = [0; 20];
    read_exact_original(file, &mut header, original)?;
    if header[..7] != *b"\x7fELF\x02\x01\x01"
        || u16::from_le_bytes([header[16], header[17]]) != 3
        || u16::from_le_bytes([header[18], header[19]]) != identity.machine
    {
        return Err(InstallerControlIdentityError::ArtifactMismatch.into());
    }
    let mut hash = Sha256::new();
    hash.update(header);
    let mut bytes = [0; 8192];
    loop {
        original.wait_slice()?;
        let length = file.read(&mut bytes)?;
        if length == 0 {
            break;
        }
        hash.update(&bytes[..length]);
    }
    if <[u8; 32]>::from(hash.finalize()) != identity.plugin_sha256 {
        return Err(InstallerControlIdentityError::ArtifactMismatch.into());
    }
    Ok(())
}

fn marker_field<'a>(
    marker: &'a [u8],
    key: &[u8],
) -> Result<&'a [u8], InstallerControlIdentityError> {
    let mut found = None;
    for line in marker.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let split = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(InstallerControlIdentityError::Invalid("marker line"))?;
        if &line[..split] == key {
            if found.is_some() || split + 1 == line.len() {
                return Err(InstallerControlIdentityError::Invalid("marker field"));
            }
            found = Some(&line[split + 1..]);
        }
    }
    found.ok_or(InstallerControlIdentityError::Invalid(
        "missing marker field",
    ))
}

fn validate_markers(qemu: &[u8], plugin: &[u8]) -> Result<(), InstallerControlIdentityError> {
    validate_marker(qemu)?;
    validate_marker(plugin)?;
    for (key, value) in [
        (&b"qemu_sim_capability"[..], &b"qemu-crucible"[..]),
        (b"qemu_crucible_atomic_patch_applied", b"true"),
        (b"qemu_plugins_enabled", b"true"),
    ] {
        if marker_field(qemu, key)? != value {
            return Err(InstallerControlIdentityError::ArtifactMismatch);
        }
    }
    for (left, right) in [
        (&b"qemu_build_id"[..], &b"qemu_build_id"[..]),
        (b"qemu_shmem_abi_version", b"shmem_abi_version"),
        (b"qemu_shmem_abi", b"plugin_abi"),
        (b"qemu_shmem_abi", b"shmem_abi"),
        (b"qemu_shmem_header_hash", b"shmem_generated_header_hash"),
    ] {
        if marker_field(qemu, left)? != marker_field(plugin, right)? {
            return Err(InstallerControlIdentityError::ArtifactMismatch);
        }
    }
    marker_field(qemu, b"qemu_atomic_patch_hash")?;
    marker_field(qemu, b"qemu_shmem_header")?;
    let mut decimal = [0; 5];
    let mut value = u64::from(crucible_engine::SHMEM_ABI_VERSION);
    let mut start = decimal.len();
    loop {
        start -= 1;
        decimal[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let version = marker_field(qemu, b"qemu_shmem_abi_version")?;
    let abi = marker_field(qemu, b"qemu_shmem_abi")?;
    if version != &decimal[start..] || abi.strip_prefix(b"crucible-shmem-abi-v") != Some(version) {
        return Err(InstallerControlIdentityError::ArtifactMismatch);
    }
    Ok(())
}

fn validate_marker(marker: &[u8]) -> Result<(), InstallerControlIdentityError> {
    std::str::from_utf8(marker)
        .map_err(|_| InstallerControlIdentityError::Invalid("marker encoding"))?;
    for line in marker.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let split = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(InstallerControlIdentityError::Invalid("marker line"))?;
        // The package producer emits canonical unquoted key=value lines.
        // Requiring every key to be unique also rejects conflicting unknown
        // fields instead of silently weakening the ordinary marker grammar.
        marker_field(marker, &line[..split])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use std::io::{Seek, Write};

    #[test]
    fn bounded_marker_fields_refuse_duplicates_and_missing_values() {
        assert_eq!(
            marker_field(b"build=one\nother=two\n", b"build").ok(),
            Some(&b"one"[..])
        );
        assert!(marker_field(b"build=one\nbuild=two\n", b"build").is_err());
        assert!(marker_field(b"build=\n", b"build").is_err());
        assert!(marker_field(b"build=one\ninvalid\n", b"build").is_err());
        assert!(marker_field(b"other=one\n", b"build").is_err());
    }

    fn synthetic_plugin() -> Vec<u8> {
        let mut bytes = vec![0; 20 + 8192 + 1];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let last = bytes.len() - 1;
        bytes[last] = 7;
        bytes
    }

    fn synthetic_identity(
        bytes: &[u8],
    ) -> Result<InstallerControlIdentity, InstallerControlIdentityError> {
        let mut record = [0; IDENTITY_BYTES];
        record[..16].copy_from_slice(super::super::RECORD_HEADER);
        for index in 0..7 {
            let offset = 24 + index * 32;
            record[offset..offset + 4].copy_from_slice(&((index + 1) as u32).to_be_bytes());
            for (relative, value) in [(8, 64_u64), (16, 8), (24, 1)] {
                record[offset + relative..offset + relative + 8]
                    .copy_from_slice(&value.to_be_bytes());
            }
        }
        record[248..280].copy_from_slice(&<[u8; 32]>::from(Sha256::digest(bytes)));
        record[16..20].copy_from_slice(&62_u32.to_be_bytes());
        record[20..24].copy_from_slice(&7_u32.to_be_bytes());
        super::super::parse(&record)
    }

    fn anonymous_source(bytes: &[u8]) -> Result<File, std::io::Error> {
        let descriptor = rustix::fs::memfd_create(
            c"installed-artifact-control",
            rustix::fs::MemfdFlags::CLOEXEC,
        )?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)?;
        file.rewind()?;
        Ok(file)
    }

    #[test]
    fn complete_artifact_hash_refuses_last_byte_and_appended_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let mut bytes = synthetic_plugin();
        let identity = synthetic_identity(&bytes)?;
        authenticate_plugin(&mut anonymous_source(&bytes)?, &identity, &original)?;

        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(matches!(
            authenticate_plugin(&mut anonymous_source(&bytes)?, &identity, &original),
            Err(ControlledInstallerIdentityError::Artifact(
                InstallerControlIdentityError::ArtifactMismatch
            ))
        ));
        bytes[last] ^= 1;
        bytes.push(0);
        assert!(matches!(
            authenticate_plugin(&mut anonymous_source(&bytes)?, &identity, &original),
            Err(ControlledInstallerIdentityError::Artifact(
                InstallerControlIdentityError::ArtifactMismatch
            ))
        ));
        Ok(())
    }

    #[test]
    fn cancelled_original_precedes_valid_file_and_digest() -> Result<(), Box<dyn std::error::Error>>
    {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;
        let bytes = synthetic_plugin();
        let identity = synthetic_identity(&bytes)?;
        supervisor.cancel()?;

        assert!(matches!(
            authenticate_plugin(&mut anonymous_source(&bytes)?, &identity, &original),
            Err(ControlledInstallerIdentityError::Original(_))
        ));
        Ok(())
    }
}

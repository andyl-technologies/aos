//! Authenticates configured installer geometry against the final immutable plugin.
//!
//! The package producer reads a numerical ELF section after all output transforms.
//! Its fixed sidecar is an artifact description, not startup allocation authority:
//! loader, allocator backing, Monitor and creator-history proofs remain separate.
//!
//! ```text
//! 0..248: CRUCCTL1, BE schema/length/machine/count, seven 32-byte BE records
//! 248..280: SHA-256 of the complete final plugin
//! ```
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{Error as IoError, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::QemuLaunchArtifactIdentity;

const IDENTITY_BYTES: usize = 280;
const RECORD_HEADER: &[u8; 16] = b"CRUCCTL1\0\0\0\x01\0\0\0\xf8";

#[cfg(target_os = "linux")]
mod controlled;

#[cfg(target_os = "linux")]
pub(crate) use controlled::ControlledInstallerIdentityError;

#[cfg(target_os = "linux")]
pub(crate) use controlled::installer_verifier_extent;

/// Describes one configured shared allocation without granting its capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallerControlAllocation {
    role: u16,
    size: u64,
    alignment: u64,
    count: u64,
}

impl InstallerControlAllocation {
    /// Returns the canonical role, from controller (1) through service slot (7).
    #[must_use]
    pub fn role(&self) -> u16 {
        self.role
    }

    /// Returns the requested allocation size, including its shared header.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the requested power-of-two alignment.
    #[must_use]
    pub fn alignment(&self) -> u64 {
        self.alignment
    }

    /// Returns the fixed birth count for this role.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }
}

/// Binds seven configured requests to the complete installed plugin digest.
///
/// This opaque value authenticates geometry only. It does not certify allocator
/// backing or the earlier native namespace and cannot authorize process birth.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallerControlIdentity {
    plugin_sha256: [u8; 32],
    machine: u16,
    allocations: [InstallerControlAllocation; 7],
    requested_bytes: u64,
    launch_binding: Option<[u8; 32]>,
    path_binding: Option<[u8; 32]>,
    #[cfg(target_os = "linux")]
    native_constructor: Option<super::native_constructor::NativeConstructorArtifact>,
}

impl InstallerControlIdentity {
    /// Returns the complete installed plugin digest.
    #[must_use]
    pub fn plugin_sha256(&self) -> &[u8; 32] {
        &self.plugin_sha256
    }

    /// Returns the configured ELF machine (62 for x86-64, 183 for AArch64).
    #[must_use]
    pub fn machine(&self) -> u16 {
        self.machine
    }

    /// Borrows the canonical seven-allocation roster.
    #[must_use]
    pub fn allocations(&self) -> &[InstallerControlAllocation; 7] {
        &self.allocations
    }

    /// Returns the checked sum of requested extents, not allocator backing.
    #[must_use]
    pub fn requested_bytes(&self) -> u64 {
        self.requested_bytes
    }

    /// Reports only the preinit requests observed in the bound final QEMU.
    ///
    /// # Errors
    /// Refuses missing actual file provenance or checked request overflow. This
    /// observation cannot authorize activation, allocation or process birth.
    #[cfg(target_os = "linux")]
    pub(crate) fn native_preinit_requested_bytes(
        &self,
    ) -> Result<u64, InstallerControlIdentityError> {
        self.native_constructor
            .as_ref()
            .and_then(super::native_constructor::NativeConstructorArtifact::requested_bytes)
            .ok_or(InstallerControlIdentityError::Unavailable)
    }

    /// Borrows the whole kernel endpoint request authenticated in the final QEMU.
    ///
    /// The observation issues no storage, descriptor, constructor or operation
    /// authority. Its interior event must not be charged separately.
    ///
    /// # Errors
    /// Refuses absent immutable-file provenance and missing, duplicate, malformed
    /// or unknown request declarations. Completed startup and copied geometry
    /// cannot substitute for a lender.
    #[cfg(target_os = "linux")]
    pub(crate) fn native_userfaultfd_request(
        &self,
    ) -> Result<&super::UserfaultfdConstructorRequest, InstallerControlIdentityError> {
        self.native_constructor
            .as_ref()
            .ok_or(InstallerControlIdentityError::Unavailable)?
            .userfaultfd()
            .map_err(InstallerControlIdentityError::Invalid)?
            .ok_or(InstallerControlIdentityError::Unavailable)
    }

    /// Borrows the receiver declaration from the same complete selected QEMU.
    ///
    /// This value is unavailable on a decoded-only sidecar. It grants no Source
    /// or process credit, including when the artifact advertises activation.
    #[cfg(target_os = "linux")]
    pub(crate) fn native_receiver_artifact(&self) -> Option<super::NativeReceiverArtifact> {
        self.native_constructor
            .as_ref()
            .map(super::native_constructor::NativeConstructorArtifact::receiver_artifact)
    }

    pub(crate) fn belongs_to(&self, artifact: &QemuLaunchArtifactIdentity) -> bool {
        self.launch_binding == Some(launch_binding(artifact))
    }

    pub(crate) fn belongs_to_paths(&self, qemu: &Path, plugin: &Path) -> bool {
        self.path_binding == Some(path_binding(qemu, plugin))
    }
}

/// Preserves a filesystem refusal or rejects incompatible installer geometry.
#[derive(Debug, thiserror::Error)]
pub enum InstallerControlIdentityError {
    /// The selected artifact or sidecar could not be read.
    #[error("read installed installer geometry: {0}")]
    Io(#[from] IoError),
    /// The selected file is outside the immutable installed package.
    #[error("installer geometry requires the immutable installed plugin package")]
    Unavailable,
    /// A fixed record has an incompatible or noncanonical field.
    #[error("invalid installer geometry {0}")]
    Invalid(&'static str),
    /// Complete hashing found a different artifact or configured machine.
    #[error("installer geometry does not match the installed plugin")]
    ArtifactMismatch,
}

impl QemuLaunchArtifactIdentity {
    /// Authenticates the fixed installer descriptor for this matched plugin.
    ///
    /// Only the final canonical, read-only Nix-store plugin and its same-package
    /// sidecar are accepted. This ordinary artifact operation issues no credit;
    /// a controlled launch must separately fund this operation and certify the
    /// missing allocator and earlier-namespace terms before using its result.
    ///
    /// # Errors
    /// Preserves a read failure, or refuses mutable/non-store artifacts, a
    /// missing or malformed descriptor, trailing bytes, and digest mismatch.
    pub fn installer_control_identity(
        &self,
    ) -> Result<InstallerControlIdentity, InstallerControlIdentityError> {
        let plugin = fs::canonicalize(&self.plugin)?;
        let root = plugin
            .parent()
            .and_then(Path::parent)
            .filter(|_| {
                plugin
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "lib")
            })
            .ok_or(InstallerControlIdentityError::Unavailable)?;
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallerControlIdentityError::Unavailable)?;
        let nix_alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
        if root.parent() != Some(Path::new("/nix/store"))
            || name.len() <= 33
            || name.as_bytes()[32] != b'-'
            || !name.as_bytes()[..32]
                .iter()
                .all(|byte| nix_alphabet.contains(byte))
        {
            return Err(InstallerControlIdentityError::Unavailable);
        }
        let sidecar = root.join("nix-support/crucible-installer-control-layouts");
        if fs::canonicalize(&sidecar)? != sidecar {
            return Err(InstallerControlIdentityError::Unavailable);
        }
        for path in [&plugin, &sidecar] {
            let metadata = fs::metadata(path)?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o222 != 0 {
                return Err(InstallerControlIdentityError::Unavailable);
            }
        }

        let mut bytes = [0; IDENTITY_BYTES];
        let mut source = File::open(&sidecar)?;
        source.read_exact(&mut bytes)?;
        if source.read(&mut [0])? != 0 {
            return Err(InstallerControlIdentityError::Invalid("tail"));
        }
        let mut identity = parse(&bytes)?;
        verify_artifact(&plugin, &identity)?;
        // Only the complete installed-file authentication publishes this
        // binding. Parsing numerical layout bytes alone cannot issue it.
        identity.launch_binding = Some(launch_binding(self));
        identity.path_binding = Some(path_binding(self.qemu(), self.plugin()));
        Ok(identity)
    }
}

fn parse(
    bytes: &[u8; IDENTITY_BYTES],
) -> Result<InstallerControlIdentity, InstallerControlIdentityError> {
    if &bytes[..16] != RECORD_HEADER
        || u32::from_be_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| InstallerControlIdentityError::Invalid("count"))?,
        ) != 7
    {
        return Err(InstallerControlIdentityError::Invalid("header"));
    }
    let machine = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| InstallerControlIdentityError::Invalid("machine"))?,
    );
    if !matches!(machine, 62 | 183) {
        return Err(InstallerControlIdentityError::Invalid("machine"));
    }
    let mut identity = InstallerControlIdentity {
        plugin_sha256: [0; 32],
        machine: u16::try_from(machine)
            .map_err(|_| InstallerControlIdentityError::Invalid("machine"))?,
        allocations: [InstallerControlAllocation {
            role: 0,
            size: 0,
            alignment: 0,
            count: 0,
        }; 7],
        requested_bytes: 0,
        launch_binding: None,
        path_binding: None,
        #[cfg(target_os = "linux")]
        native_constructor: None,
    };
    identity.plugin_sha256.copy_from_slice(&bytes[248..280]);
    for (index, allocation) in identity.allocations.iter_mut().enumerate() {
        let start = 24 + index * 32;
        let record = &bytes[start..start + 32];
        let role = u32::from_be_bytes(
            record[..4]
                .try_into()
                .map_err(|_| InstallerControlIdentityError::Invalid("role"))?,
        );
        let number = |offset| {
            let mut value = [0; 8];
            value.copy_from_slice(&record[offset..offset + 8]);
            u64::from_be_bytes(value)
        };
        let size = number(8);
        let alignment = number(16);
        let count = number(24);
        if role != index as u32 + 1
            || record[4..8].iter().any(|byte| *byte != 0)
            || count != 1
            || size == 0
            || size > i64::MAX as u64
            || !alignment.is_power_of_two()
            || size % alignment != 0
        {
            return Err(InstallerControlIdentityError::Invalid("allocation"));
        }
        identity.requested_bytes = size
            .checked_mul(count)
            .and_then(|extent| identity.requested_bytes.checked_add(extent))
            .ok_or(InstallerControlIdentityError::Invalid("total"))?;
        *allocation = InstallerControlAllocation {
            role: u16::try_from(role)
                .map_err(|_| InstallerControlIdentityError::Invalid("role"))?,
            size,
            alignment,
            count,
        };
    }
    Ok(identity)
}

fn launch_binding(artifact: &QemuLaunchArtifactIdentity) -> [u8; 32] {
    let mut hash = Sha256::new();
    for bytes in [
        artifact.qemu().as_os_str().as_bytes(),
        artifact.plugin().as_os_str().as_bytes(),
        artifact.qemu_build_id().as_bytes(),
        artifact.qemu_atomic_patch_hash().as_bytes(),
        artifact.plugin_abi().as_bytes(),
        artifact.shmem_abi_version().as_bytes(),
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

fn path_binding(qemu: &Path, plugin: &Path) -> [u8; 32] {
    let mut hash = Sha256::new();
    for bytes in [qemu.as_os_str().as_bytes(), plugin.as_os_str().as_bytes()] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

fn verify_artifact(
    path: &Path,
    identity: &InstallerControlIdentity,
) -> Result<(), InstallerControlIdentityError> {
    let mut source = File::open(path)?;
    verify_artifact_file(&mut source, identity)
}

fn verify_artifact_file(
    source: &mut File,
    identity: &InstallerControlIdentity,
) -> Result<(), InstallerControlIdentityError> {
    let mut header = [0; 20];
    source.read_exact(&mut header)?;
    if header[..7] != *b"\x7fELF\x02\x01\x01"
        || u16::from_le_bytes([header[16], header[17]]) != 3
        || u16::from_le_bytes([header[18], header[19]]) != identity.machine
    {
        return Err(InstallerControlIdentityError::ArtifactMismatch);
    }
    let mut digest = Sha256::new();
    digest.update(header);
    let mut buffer = [0; 8192];
    loop {
        let length = source.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    if <[u8; 32]>::from(digest.finalize()) != identity.plugin_sha256 {
        return Err(InstallerControlIdentityError::ArtifactMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> [u8; IDENTITY_BYTES] {
        let mut bytes = [0; IDENTITY_BYTES];
        bytes[..16].copy_from_slice(RECORD_HEADER);
        bytes[16..20].copy_from_slice(&62_u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&7_u32.to_be_bytes());
        for index in 0..7 {
            let start = 24 + index * 32;
            bytes[start..start + 4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
            bytes[start + 8..start + 16].copy_from_slice(&(8 * (index as u64 + 1)).to_be_bytes());
            bytes[start + 16..start + 24].copy_from_slice(&8_u64.to_be_bytes());
            bytes[start + 24..start + 32].copy_from_slice(&1_u64.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn canonical_record_preserves_all_seven_roles_and_checked_total()
    -> Result<(), InstallerControlIdentityError> {
        let identity = parse(&record())?;

        assert_eq!(identity.requested_bytes(), 224);
        for (index, request) in identity.allocations().iter().enumerate() {
            assert_eq!(usize::from(request.role()), index + 1);
            assert_eq!(request.count(), 1);
            assert_eq!(request.alignment(), 8);
            assert_eq!(request.size(), 8 * (index as u64 + 1));
        }
        Ok(())
    }

    #[test]
    fn parsed_geometry_cannot_relabel_an_authenticated_launch_pair()
    -> Result<(), InstallerControlIdentityError> {
        let artifact = QemuLaunchArtifactIdentity {
            qemu: "/immutable/bin/qemu".into(),
            plugin: "/immutable/lib/plugin.so".into(),
            qemu_build_id: "configured-build".into(),
            qemu_atomic_patch_hash: "configured-patch".into(),
            plugin_abi: "configured-plugin-abi".into(),
            shmem_abi_version: "configured-shmem-abi".into(),
        };
        let mut identity = parse(&record())?;
        assert!(!identity.belongs_to(&artifact));

        // This models only the private publication field, not installed ELF
        // authentication. The immutable-file verifier remains the sole caller.
        identity.launch_binding = Some(launch_binding(&artifact));
        assert!(identity.belongs_to(&artifact));
        let mut changed = artifact.clone();
        changed.plugin.push("other");
        assert!(!identity.belongs_to(&changed));
        changed = artifact.clone();
        changed.qemu_atomic_patch_hash.push('x');
        assert!(!identity.belongs_to(&changed));
        changed = artifact;
        changed.shmem_abi_version.push('x');
        assert!(!identity.belongs_to(&changed));
        Ok(())
    }

    #[test]
    fn incompatible_header_reserved_bytes_and_each_request_field_refuse() {
        for offset in [0, 11, 15, 19, 23] {
            let mut bytes = record();
            bytes[offset] ^= 1;
            assert!(parse(&bytes).is_err());
        }
        for index in 0..7 {
            let start = 24 + index * 32;
            for (offset, value) in [(3, 0), (7, 1), (15, 0), (23, 3), (31, 2)] {
                let mut bytes = record();
                bytes[start + offset] = value;
                if offset == 15 {
                    bytes[start + 8..start + 16].fill(0);
                }
                assert!(parse(&bytes).is_err());
            }
        }
        let mut bytes = record();
        bytes[16..20].copy_from_slice(&3_u32.to_be_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn total_overflow_refuses_instead_of_producing_a_smaller_assignment() {
        let mut bytes = record();
        for index in 0..7 {
            let start = 24 + index * 32;
            bytes[start + 8..start + 16].copy_from_slice(&(i64::MAX as u64).to_be_bytes());
            bytes[start + 16..start + 24].copy_from_slice(&1_u64.to_be_bytes());
        }

        assert!(matches!(
            parse(&bytes),
            Err(InstallerControlIdentityError::Invalid("total"))
        ));
    }

    #[test]
    fn complete_artifact_hash_detects_machine_and_late_tail_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("plugin.so");
        let mut plugin = vec![0; 64];
        plugin[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        plugin[16..18].copy_from_slice(&3_u16.to_le_bytes());
        plugin[18..20].copy_from_slice(&62_u16.to_le_bytes());
        plugin.extend_from_slice(b"complete installed tail");
        let mut bytes = record();
        bytes[248..280].copy_from_slice(&Sha256::digest(&plugin));
        let identity = parse(&bytes)?;
        fs::write(&path, &plugin)?;

        verify_artifact(&path, &identity)?;
        plugin.push(1);
        fs::write(&path, &plugin)?;
        assert!(matches!(
            verify_artifact(&path, &identity),
            Err(InstallerControlIdentityError::ArtifactMismatch)
        ));
        plugin[18..20].copy_from_slice(&183_u16.to_le_bytes());
        fs::write(&path, &plugin)?;
        assert!(matches!(
            verify_artifact(&path, &identity),
            Err(InstallerControlIdentityError::ArtifactMismatch)
        ));
        Ok(())
    }
}

//! Parks fixed mode, provisioning and absence currentness observations.
//!
//! Ordinary and selected checks share these exact ordered comparison recipes.
//! The ordinary byte read keeps its existing consuming adapter; selected reads
//! retain the same lower fixed-credential engine at its actual open/read call.

use std::error::Error;
use std::fs::Metadata;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;

use super::*;

pub(in crate::recovery::journal) const MAXIMUM_MODE_PATH_BYTES_V1: usize = 4096;

// Actual FixedRoleCredentialReadV1 result destinations: fixed_length,
// positional_open, open, metadata, size, admission, allocation, exact, trailing
// and completion. Count the full same-reader capacity, including unused arms.
pub(super) const FIXED_CREDENTIAL_RESULT_CELLS_V1: u64 = 10;

// Canonical+binding, held+named metadata, identity, filesystem+readonly,
// bytes+mode+binding and whole result are eleven additional destinations.
pub(in crate::recovery::journal) const MODE_REVALIDATION_RESULT_CELLS_V1: u64 =
    11 + FIXED_CREDENTIAL_RESULT_CELLS_V1;


const FLOOR_NAMES: [&str; 3] = [
    "session-floor.journal",
    "session-floor.journal.lock",
    "session-floor.journal.compact.tmp",
];

/// Prices the fixed auxiliary recipes, independently of typed floor authority.
pub(in crate::recovery::journal) fn auxiliary_currentness_work_bytes_v1() -> Option<usize> {
    let canonical = canonical_currentness_work_bytes_v1()?;
    let credentials = PROVISION_BYTES.checked_add(std::mem::size_of::<[u8; 32]>())?
        .checked_add(LEGACY_MODE.len())?.checked_mul(4)?;
    let longest_name = FLOOR_NAMES.iter().map(|name| name.len()).max()?;
    let absence = MAXIMUM_MODE_PATH_BYTES_V1.checked_add(longest_name)?
        .checked_mul(FLOOR_NAMES.len())?;
    // Mode and provisioning conversions finish before the next read starts.
    // One checked byte peak covers their actual bounded consuming paths.
    let joined_paths = FixedRoleCredentialReadV1::joined_path_receiving_bytes_for_lengths_v1(
        MAXIMUM_MODE_PATH_BYTES_V1, MAXIMUM_MODE_PATH_BYTES_V1,
    )?;
    canonical.checked_add(credentials)?.checked_add(absence)?.checked_add(8 * 256)?
        .checked_add(joined_paths)
}

/// Supplies the shared dominant canonicalization work without a role grant.
pub(in crate::recovery::journal) fn canonical_currentness_work_bytes_v1() -> Option<usize> {
    // Pinned glibc realpath has three doubling scratch buffers and a forty-link
    // expansion limit. Sixteen path copies cover their dominant growth/output
    // overlap under the installed Linux path-width bound. Allocator and kernel
    // residuals remain confined by the existing service hard limits.
    41_usize.checked_mul(MAXIMUM_MODE_PATH_BYTES_V1)?.checked_mul(16)
}

/// Describes one actual retained mode comparison before native work.
pub(crate) fn mode_revalidation_receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
    use aos_sandbox_model::{ResourceDimension as Dimension, ResourceVector};

    let memory = std::mem::size_of::<ModeRevalidationOriginalV1>()
        .checked_add(canonical_currentness_work_bytes_v1()?)?
        .checked_add(MAXIMUM_MODE_PATH_BYTES_V1.checked_mul(4)?)?
        .checked_add(4 * LEGACY_MODE.len())?
        .checked_add(FixedRoleCredentialReadV1::joined_path_receiving_bytes_for_lengths_v1(
            MAXIMUM_MODE_PATH_BYTES_V1, MAXIMUM_MODE_PATH_BYTES_V1,
        )?)?
        .checked_add(8 * 256)?;
    Some(ResourceVector::ZERO
        .with(Dimension::MemoryBytes, u64::try_from(memory).ok()?)
        .with(Dimension::OpenFiles, 1)
        .with(Dimension::MetadataEntries, MODE_REVALIDATION_RESULT_CELLS_V1))
}

/// Chooses only the mechanical custody destination, without admitting a role.
#[derive(Clone, Copy)]
pub(in crate::recovery::journal) enum CredentialReadCustodyV1 {
    Ordinary,
    Retained,
}

pub(crate) struct ModeRevalidationOriginalV1 {
    canonical: Option<std::io::Result<PathBuf>>,
    canonical_binding: Option<Result<(), FloorErrorV1>>,
    held: Option<std::io::Result<Metadata>>,
    named: Option<std::io::Result<Metadata>>,
    identity: Option<Result<(), FloorErrorV1>>,
    filesystem: Option<Result<rustix::fs::StatVfs, rustix::io::Errno>>,
    readonly: Option<Result<(), FloorErrorV1>>,
    read: FixedRoleCredentialReadV1,
    bytes: Option<Result<Vec<u8>, FloorErrorV1>>,
    mode: Option<Result<ImageFloorModeV1, FloorErrorV1>>,
    mode_binding: Option<Result<(), FloorErrorV1>>,
    result: Option<Result<(), FloorErrorV1>>,
}

impl ModeRevalidationOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            canonical: None,
            canonical_binding: None,
            held: None,
            named: None,
            identity: None,
            filesystem: None,
            readonly: None,
            read: FixedRoleCredentialReadV1::prearmed(),
            bytes: None,
            mode: None,
            mode_binding: None,
            result: None,
        }
    }

    pub(in crate::recovery::journal) fn observe_once(
        &mut self,
        pin: &ModePinV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.result.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        self.result = Some(self.observe(pin, custody));
        match self.result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    fn observe(
        &mut self,
        pin: &ModePinV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        self.canonical = Some(std::fs::canonicalize(&pin.path));
        let canonical = value(&self.canonical)?;
        self.canonical_binding = Some(require(canonical == &pin.target));
        value(&self.canonical_binding)?;
        if matches!(custody, CredentialReadCustodyV1::Ordinary) {
            // The original ordinary if-condition disposed this successful
            // temporary before entering the next native metadata operation.
            drop(self.canonical.take());
        }

        self.held = Some(pin.file.metadata());
        let held = value(&self.held)?;
        self.named = Some(std::fs::symlink_metadata(&pin.target));
        let named = value(&self.named)?;
        self.identity = Some(require(
            named.is_file()
                && named.uid() == 0
                && named.gid() == 0
                && named.nlink() == 1
                && named.mode() & 0o7222 == 0
                && (named.dev(), named.ino()) == pin.identity
                && (held.dev(), held.ino()) == pin.identity,
        ));
        value(&self.identity)?;

        self.filesystem = Some(fstatvfs(&pin.file));
        self.readonly = Some(require(value(&self.filesystem)?.f_flag
            .contains(StatVfsMountFlags::RDONLY)));
        value(&self.readonly)?;

        self.bytes = Some(if matches!(custody, CredentialReadCustodyV1::Retained) {
            let parent = pin.target.parent().ok_or(FloorErrorV1::Provisioning)?;
            let name = pin.target.file_name().and_then(|name| name.to_str())
                .ok_or(FloorErrorV1::Provisioning)?;
            self.read.read_once(parent, name, REQUIRED_MODE.len(), LEGACY_MODE.len(),
                false, CredentialOwnerPolicyV1::RootOrCurrent);
            self.read.take_success_bytes_once().ok_or(FloorErrorV1::Provisioning)
        } else {
            // Same ordinary consuming helper and its original File drop point.
            read_mode(&pin.target)
        });
        self.mode = Some(decode_mode(value(&self.bytes)?));
        self.mode_binding = Some(require(*value(&self.mode)? == pin.mode));
        value(&self.mode_binding)?;
        Ok(())
    }

    pub(in crate::recovery::journal) fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(())))
    }

    // Initial mode handoff calls this only after the complete final
    // same-pin comparison. Preserve all failed reads and native causes.
    pub(super) fn retire_completed_read_v1(&mut self) -> bool {
        if !self.is_complete() || self.failure().is_some() {
            return false;
        }
        // Ordinary mode has no retained reader and keeps its old local drop.
        self.read.view().completion.is_none()
            || self.read.retire_completed_file_once_v1()
    }

    pub(in crate::recovery::journal) fn take_completed_result(
        &mut self,
    ) -> Option<Result<(), FloorErrorV1>> {
        if !self.is_complete() {
            return None;
        }
        self.result.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.canonical)
            .or_else(|| failure(&self.canonical_binding))
            .or_else(|| failure(&self.held))
            .or_else(|| failure(&self.named))
            .or_else(|| failure(&self.identity))
            .or_else(|| failure(&self.filesystem))
            .or_else(|| failure(&self.readonly))
            .or_else(|| self.read.failure())
            .or_else(|| failure(&self.bytes))
            .or_else(|| failure(&self.mode))
            .or_else(|| failure(&self.mode_binding))
            .or_else(|| failure(&self.result))
    }
}

/// Owns the original public/authentication reads and their exact comparisons.
pub(in crate::recovery::journal) struct ProvisionRevalidationOriginalV1 {
    public_read: FixedRoleCredentialReadV1,
    public: Option<Result<[u8; PROVISION_BYTES], FloorErrorV1>>,
    public_binding: Option<Result<(), FloorErrorV1>>,
    auth_read: FixedRoleCredentialReadV1,
    auth_bytes: Option<Zeroizing<Vec<u8>>>,
    auth_nonzero: Option<Result<(), FloorErrorV1>>,
    auth: Option<Result<Zeroizing<[u8; 32]>, FloorErrorV1>>,
    digest_binding: Option<Result<(), FloorErrorV1>>,
    result: Option<Result<(), FloorErrorV1>>,
}

impl ProvisionRevalidationOriginalV1 {
    pub(in crate::recovery::journal) fn new() -> Self {
        Self {
            public_read: FixedRoleCredentialReadV1::prearmed(),
            public: None,
            public_binding: None,
            auth_read: FixedRoleCredentialReadV1::prearmed(),
            auth_bytes: None,
            auth_nonzero: None,
            auth: None,
            digest_binding: None,
            result: None,
        }
    }

    pub(in crate::recovery::journal) fn observe_once(
        &mut self,
        pin: &ProvisionPinV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.result.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        self.result = Some(self.observe(pin, custody));
        value(&self.result).copied()
    }

    fn observe(
        &mut self,
        pin: &ProvisionPinV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        self.public = Some(if matches!(custody, CredentialReadCustodyV1::Retained) {
            self.public_read.read_once(
                credential_directory(pin.endpoint), PUBLIC_CREDENTIAL,
                PROVISION_BYTES, PROVISION_BYTES, false,
                CredentialOwnerPolicyV1::RootOrCurrent,
            );
            self.public_read.take_success_bytes_once()
                .ok_or(FloorErrorV1::Provisioning)?
                .try_into().map_err(|_| FloorErrorV1::Provisioning)
        } else {
            read_public(pin.endpoint)
        });
        self.public_binding = Some(require(value(&self.public)? == &pin.bytes));
        value(&self.public_binding)?;

        self.auth = Some(if matches!(custody, CredentialReadCustodyV1::Retained) {
            self.auth_read.read_once(
                credential_directory(pin.endpoint), AUTH_CREDENTIAL,
                32, 32, true, CredentialOwnerPolicyV1::RootOrCurrent,
            );
            self.auth_bytes = Some(Zeroizing::new(self.auth_read.take_success_bytes_once()
                .ok_or(FloorErrorV1::Provisioning)?));
            let mut auth = Zeroizing::new([0; 32]);
            let bytes = self.auth_bytes.as_ref().ok_or(FloorErrorV1::Provisioning)?;
            auth.copy_from_slice(bytes);
            Ok(auth)
        } else {
            read_auth(pin.endpoint)
        });
        self.auth_nonzero = Some(require(**value(&self.auth)? != [0; 32]));
        value(&self.auth_nonzero)?;

        self.digest_binding = Some(require(
            Sha256::digest(&value(&self.auth)?[..]).as_slice() == pin.auth_digest,
        ));
        value(&self.digest_binding)?;
        Ok(())
    }

    pub(in crate::recovery::journal) fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(())))
    }

    pub(in crate::recovery::journal) fn take_completed(
        &mut self,
    ) -> Option<(Result<(), FloorErrorV1>, Zeroizing<[u8; 32]>)> {
        if !self.is_complete() {
            return None;
        }
        let auth = match self.auth.take() {
            Some(Ok(auth)) => auth,
            other => {
                self.auth = other;
                return None;
            }
        };
        self.result.take().map(|result| (result, auth))
    }

    pub(in crate::recovery::journal) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.public_read.failure()
            .or_else(|| failure(&self.public))
            .or_else(|| failure(&self.public_binding))
            .or_else(|| self.auth_read.failure())
            .or_else(|| failure(&self.auth))
            .or_else(|| failure(&self.auth_nonzero))
            .or_else(|| failure(&self.digest_binding))
            .or_else(|| failure(&self.result))
    }
}

/// Retains every reached absence lookup, including expected native NotFound.
pub(in crate::recovery::journal) struct AbsentFloorNamesOriginalV1 {
    paths: [Option<PathBuf>; 3],
    metadata: [Option<std::io::Result<Metadata>>; 3],
    binding: [Option<Result<(), FloorErrorV1>>; 3],
    result: Option<Result<(), FloorErrorV1>>,
}

impl AbsentFloorNamesOriginalV1 {
    pub(in crate::recovery::journal) fn new() -> Self {
        Self {
            paths: [None, None, None],
            metadata: [None, None, None],
            binding: [None, None, None],
            result: None,
        }
    }

    pub(in crate::recovery::journal) fn observe_once(
        &mut self,
        directory: &Path,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.result.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        self.result = Some(self.observe(directory, custody));
        value(&self.result).copied()
    }

    fn observe(
        &mut self,
        directory: &Path,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        for (index, name) in FLOOR_NAMES.into_iter().enumerate() {
            self.paths[index] = Some(directory.join(name));
            self.metadata[index] = Some(std::fs::symlink_metadata(
                self.paths[index].as_ref().ok_or(FloorErrorV1::Provisioning)?,
            ));
            if matches!(custody, CredentialReadCustodyV1::Ordinary) {
                // The original joined argument temporary ended immediately
                // after symlink_metadata, before classifying its result.
                drop(self.paths[index].take());
            }
            self.binding[index] = Some(require(matches!(
                &self.metadata[index],
                Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound
            )));
            value(&self.binding[index])?;
            if matches!(custody, CredentialReadCustodyV1::Ordinary) {
                // Expected absence has completed this original iteration;
                // ordinary custody does not extend it across the next lookup.
                drop(self.metadata[index].take());
                drop(self.binding[index].take());
            }
        }
        Ok(())
    }

    pub(in crate::recovery::journal) fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(())))
    }

    pub(in crate::recovery::journal) fn take_completed_result(
        &mut self,
    ) -> Option<Result<(), FloorErrorV1>> {
        if self.is_complete() {
            self.result.take()
        } else {
            None
        }
    }

    pub(in crate::recovery::journal) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        for index in 0..3 {
            if matches!(self.binding[index], Some(Err(_))) {
                // Earlier expected absence errors are successful comparisons.
                // Only this actual failed lookup can select a native cause.
                return failure(&self.metadata[index])
                    .or_else(|| failure(&self.binding[index]));
            }
        }
        failure(&self.result)
    }
}

fn require(condition: bool) -> Result<(), FloorErrorV1> {
    if condition {
        Ok(())
    } else {
        Err(FloorErrorV1::Provisioning)
    }
}

fn value<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, FloorErrorV1> {
    match slot {
        Some(Ok(value)) => Ok(value),
        _ => Err(FloorErrorV1::Provisioning),
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>)
    -> Option<&(dyn Error + 'static)>
{
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_mode_retains_original_native_error_before_any_later_probe() {
        let directory = tempfile::tempdir().unwrap();
        let held_path = directory.path().join("held");
        std::fs::write(&held_path, LEGACY_MODE).unwrap();
        let file = File::open(&held_path).unwrap();
        let metadata = file.metadata().unwrap();
        let pin = ModePinV1 {
            currentness: None,
            path: directory.path().join("missing"),
            target: held_path,
            file,
            identity: (metadata.dev(), metadata.ino()),
            mode: ImageFloorModeV1::LegacyClosed,
        };
        let mut original = ModeRevalidationOriginalV1::new();

        assert!(original.observe_once(&pin, CredentialReadCustodyV1::Retained).is_err());
        let native = original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        let identity = native as *const std::io::Error;
        assert!(original.held.is_none());
        assert!(original.read.outcome().is_none());

        std::fs::write(&pin.path, LEGACY_MODE).unwrap();
        assert!(original.observe_once(&pin, CredentialReadCustodyV1::Retained).is_err());
        let retained = original.failure().unwrap()
            .downcast_ref::<std::io::Error>().unwrap();
        assert!(std::ptr::eq(identity, retained as *const std::io::Error));
        assert!(original.held.is_none());
    }
}

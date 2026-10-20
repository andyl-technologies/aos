//! Owns initial fixed mode and provisioning acquisition at the original reads.
//!
//! These passive one-shot destinations retain partial native acquisition and
//! typed results. Their closed caller must reserve the actual geometry before
//! entry; a completed mode or provision never pays for a floor or sidecar.

use std::fs::Metadata;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;

use super::*;

pub(crate) struct InitialModeOriginalV1 {
    path: Option<PathBuf>,
    canonical: Option<std::io::Result<PathBuf>>,
    immutable: Option<Result<(), FloorErrorV1>>,
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: Option<std::io::Result<Metadata>>,
    metadata_binding: Option<Result<(), FloorErrorV1>>,
    filesystem: Option<Result<rustix::fs::StatVfs, rustix::io::Errno>>,
    readonly: Option<Result<(), FloorErrorV1>>,
    read: FixedRoleCredentialReadV1,
    bytes: Option<Result<Vec<u8>, FloorErrorV1>>,
    mode: Option<Result<ImageFloorModeV1, FloorErrorV1>>,
    pin: Option<ModePinV1>,
    final_comparison: ModeRevalidationOriginalV1,
    result: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    taken: bool,
}

impl InitialModeOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            path: None,
            canonical: None,
            immutable: None,
            open: None,
            metadata: None,
            metadata_binding: None,
            filesystem: None,
            readonly: None,
            read: FixedRoleCredentialReadV1::prearmed(),
            bytes: None,
            mode: None,
            pin: None,
            final_comparison: ModeRevalidationOriginalV1::new(),
            result: None,
            entered: false,
            taken: false,
        }
    }

    pub(super) fn capture_once(
        &mut self,
        path: PathBuf,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.path = Some(path);
        self.result = Some(self.capture(custody));
        match self.result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(FloorErrorV1::Provisioning),
        }
    }

    fn capture(&mut self, custody: CredentialReadCustodyV1) -> Result<(), FloorErrorV1> {
        self.canonical = Some(std::fs::canonicalize(
            self.path.as_ref().ok_or(FloorErrorV1::Provisioning)?,
        ));
        let target = value(&self.canonical)?;
        self.immutable = Some(require(target.starts_with("/nix/store")));
        value(&self.immutable)?;

        self.open = Some(rustix::fs::openat(
            rustix::fs::CWD,
            target,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map(File::from));
        let file = value(&self.open)?;
        self.metadata = Some(file.metadata());
        let metadata = value(&self.metadata)?;
        self.metadata_binding = Some(require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o7222 == 0,
        ));
        value(&self.metadata_binding)?;
        self.filesystem = Some(fstatvfs(file));
        self.readonly = Some(require(
            value(&self.filesystem)?.f_flag.contains(StatVfsMountFlags::RDONLY),
        ));
        value(&self.readonly)?;

        self.bytes = Some(match custody {
            CredentialReadCustodyV1::Ordinary => read_mode(target),
            CredentialReadCustodyV1::Retained => {
                self.read.read_once(
                    target.parent().ok_or(FloorErrorV1::Provisioning)?,
                    target.file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(FloorErrorV1::Provisioning)?,
                    REQUIRED_MODE.len(),
                    LEGACY_MODE.len(),
                    false,
                    CredentialOwnerPolicyV1::RootOrCurrent,
                );
                self.read.take_success_bytes_once().ok_or(FloorErrorV1::Provisioning)
            }
        });
        self.mode = Some(decode_mode(value(&self.bytes)?));
        let mode = *value(&self.mode)?;
        let identity = (metadata.dev(), metadata.ino());

        // All fallible admission precedes this exact original transfer. On a
        // failed final comparison, the same pin remains resident in this slot.
        let path = self.path.take().ok_or(FloorErrorV1::Provisioning)?;
        let target = match self.canonical.take() {
            Some(Ok(target)) => target,
            original => {
                self.canonical = original;
                self.path = Some(path);
                return Err(FloorErrorV1::Provisioning);
            }
        };
        let file = match self.open.take() {
            Some(Ok(file)) => file,
            original => {
                self.open = original;
                self.canonical = Some(Ok(target));
                self.path = Some(path);
                return Err(FloorErrorV1::Provisioning);
            }
        };
        self.pin = Some(ModePinV1 {
            currentness: None,
            path,
            target,
            file,
            identity,
            mode,
        });
        self.final_comparison.observe_once(
            self.pin.as_ref().ok_or(FloorErrorV1::Provisioning)?,
            custody,
        )
    }

    pub(in crate::recovery::journal) fn take_pin_once(&mut self) -> Option<ModePinV1> {
        if self.taken || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        // The complete initial native comparison, including its final mode
        // revalidation, passed. Ordinary readers are empty; the selected
        // readers dispose only their complete positive native Files. The
        // actual ModePin File remains the currentness identity anchor.
        if self.read.view().completion.is_some()
            && !self.read.retire_completed_file_once_v1()
        {
            return None;
        }
        if !self.final_comparison.retire_completed_read_v1() {
            return None;
        }
        let pin = self.pin.take()?;
        self.taken = true;
        Some(pin)
    }

    pub(crate) fn failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        failure(&self.canonical)
            .or_else(|| failure(&self.immutable))
            .or_else(|| failure(&self.open))
            .or_else(|| failure(&self.metadata))
            .or_else(|| failure(&self.metadata_binding))
            .or_else(|| failure(&self.filesystem))
            .or_else(|| failure(&self.readonly))
            .or_else(|| self.read.failure())
            .or_else(|| failure(&self.bytes))
            .or_else(|| failure(&self.mode))
            .or_else(|| self.final_comparison.failure())
            .or_else(|| failure(&self.result))
    }
}

// Initial canonical/immutable/open/metadata/binding/filesystem/readonly/
// bytes/mode/whole result, one fixed reader and the final same-pin comparison.
pub(in crate::recovery::journal) const INITIAL_MODE_RESULT_CELLS_V1: u64 =
    10 + super::receiving::FIXED_CREDENTIAL_RESULT_CELLS_V1
        + super::receiving::MODE_REVALIDATION_RESULT_CELLS_V1;

// Public/decoded/auth/nonzero/whole result and two same-engine fixed readers.
pub(in crate::recovery::journal) const INITIAL_PROVISION_RESULT_CELLS_V1: u64 =
    5 + 2 * super::receiving::FIXED_CREDENTIAL_RESULT_CELLS_V1;

/// Describes the actual fixed mode acquisition without opening or admitting it.
pub(crate) fn mode_initial_receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as Dimension, ResourceVector};

    // Initial canonicalization and the final pin comparison run sequentially.
    // The first target and two reached byte buffers survive the second peak.
    let memory = std::mem::size_of::<InitialModeOriginalV1>()
        .checked_add(super::receiving::canonical_currentness_work_bytes_v1()?)?
        .checked_add(MAXIMUM_MODE_PATH_BYTES_V1.checked_mul(4)?)?
        .checked_add(8 * LEGACY_MODE.len())?
        .checked_add(FixedRoleCredentialReadV1::joined_path_receiving_bytes_for_lengths_v1(
            MAXIMUM_MODE_PATH_BYTES_V1, MAXIMUM_MODE_PATH_BYTES_V1,
        )?)?
        .checked_add(8 * 256)?;
    Some(ResourceVector::ZERO
        .with(Dimension::MemoryBytes, u64::try_from(memory).ok()?)
        .with(Dimension::OpenFiles, 3)
        .with(Dimension::MetadataEntries, INITIAL_MODE_RESULT_CELLS_V1))
}

/// Owns the initial public profile and authentication secret acquisition.
pub(in crate::recovery::journal) struct InitialProvisionOriginalV1 {
    public_read: FixedRoleCredentialReadV1,
    public: Option<Result<[u8; PROVISION_BYTES], FloorErrorV1>>,
    decoded: Option<Result<(FloorProfileV1, [u8; 34]), FloorErrorV1>>,
    auth_read: FixedRoleCredentialReadV1,
    auth_bytes: Option<Zeroizing<Vec<u8>>>,
    auth: Option<Result<Zeroizing<[u8; 32]>, FloorErrorV1>>,
    nonzero: Option<Result<(), FloorErrorV1>>,
    pin: Option<ProvisionPinV1>,
    result: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    taken: bool,
}

impl InitialProvisionOriginalV1 {
    pub(in crate::recovery::journal) fn new() -> Self {
        Self {
            public_read: FixedRoleCredentialReadV1::prearmed(),
            public: None,
            decoded: None,
            auth_read: FixedRoleCredentialReadV1::prearmed(),
            auth_bytes: None,
            auth: None,
            nonzero: None,
            pin: None,
            result: None,
            entered: false,
            taken: false,
        }
    }

    pub(super) fn capture_once(
        &mut self,
        endpoint: FloorEndpointV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.result = Some(self.capture(endpoint, custody));
        match self.result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(FloorErrorV1::Provisioning),
        }
    }

    fn capture(
        &mut self,
        endpoint: FloorEndpointV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        self.public = Some(match custody {
            CredentialReadCustodyV1::Ordinary => read_public(endpoint),
            CredentialReadCustodyV1::Retained => {
                self.public_read.read_once(
                    credential_directory(endpoint),
                    PUBLIC_CREDENTIAL,
                    PROVISION_BYTES,
                    PROVISION_BYTES,
                    false,
                    CredentialOwnerPolicyV1::RootOrCurrent,
                );
                self.public_read.take_success_bytes_once()
                    .ok_or(FloorErrorV1::Provisioning)?
                    .try_into().map_err(|_| FloorErrorV1::Provisioning)
            }
        });
        self.decoded = Some(decode_provision(value(&self.public)?, endpoint));
        let (profile, salt_name) = match self.decoded {
            Some(Ok(decoded)) => decoded,
            Some(Err(error)) => return Err(error),
            None => return Err(FloorErrorV1::Provisioning),
        };

        self.auth = Some(match custody {
            CredentialReadCustodyV1::Ordinary => read_auth(endpoint),
            CredentialReadCustodyV1::Retained => {
                self.auth_read.read_once(
                    credential_directory(endpoint),
                    AUTH_CREDENTIAL,
                    32,
                    32,
                    true,
                    CredentialOwnerPolicyV1::RootOrCurrent,
                );
                self.auth_bytes = Some(Zeroizing::new(
                    self.auth_read.take_success_bytes_once()
                        .ok_or(FloorErrorV1::Provisioning)?,
                ));
                let bytes = self.auth_bytes.as_ref().ok_or(FloorErrorV1::Provisioning)?;
                let mut auth = Zeroizing::new([0; 32]);
                auth.copy_from_slice(bytes);
                Ok(auth)
            }
        });
        self.nonzero = Some(require(**value(&self.auth)? != [0; 32]));
        value(&self.nonzero)?;
        self.pin = Some(ProvisionPinV1 {
            currentness: None,
            endpoint,
            bytes: *value(&self.public)?,
            auth_digest: Sha256::digest(&value(&self.auth)?[..]).into(),
            profile,
            salt_name,
        });
        Ok(())
    }

    pub(in crate::recovery::journal) fn take_pin_once(&mut self) -> Option<ProvisionPinV1> {
        if self.taken || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        // Public bytes, exact decoding, auth and the nonzero comparison all
        // passed. The actual ProvisionPin DATA, raw results and bytes remain;
        // later revalidation uses its own independently retained readers.
        if self.public_read.view().completion.is_some()
            && !self.public_read.retire_completed_file_once_v1()
        {
            return None;
        }
        if self.auth_read.view().completion.is_some()
            && !self.auth_read.retire_completed_file_once_v1()
        {
            return None;
        }
        let pin = self.pin.take()?;
        self.taken = true;
        Some(pin)
    }

    pub(in crate::recovery::journal) fn failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.public_read.failure()
            .or_else(|| failure(&self.public))
            .or_else(|| failure(&self.decoded))
            .or_else(|| self.auth_read.failure())
            .or_else(|| failure(&self.auth))
            .or_else(|| failure(&self.nonzero))
            .or_else(|| failure(&self.result))
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

fn failure<T, E: std::error::Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err())
        .map(|cause| cause as &dyn std::error::Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_initial_mode_keeps_native_cause_and_never_recaptures() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing-mode");
        let mut original = InitialModeOriginalV1::new();

        assert!(original.capture_once(path.clone(), CredentialReadCustodyV1::Retained).is_err());
        let native = original.canonical.as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(native.kind(), std::io::ErrorKind::NotFound);
        let native_pointer = native as *const std::io::Error;
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
            native_pointer,
        ));
        assert!(original.open.is_none());
        assert!(original.take_pin_once().is_none());

        std::fs::write(&path, LEGACY_MODE).unwrap();
        assert!(matches!(
            original.capture_once(path, CredentialReadCustodyV1::Retained),
            Err(FloorErrorV1::Unavailable),
        ));
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
            native_pointer,
        ));
        assert!(original.open.is_none());
    }
}

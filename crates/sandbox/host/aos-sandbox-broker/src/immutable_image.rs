//! Shared bounded immutable-file measurement without any authority conversion.
//!
//! This is nonauthorizing measurement: callers independently select the image,
//! role and original launch custody. Offset-independent hashing retains the
//! original file and rechecks its read-only current name around every digest.

use std::fs::{File, Metadata};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, StatVfsMountFlags, fstatvfs, openat};
use sha2::{Digest as _, Sha256};

use aos_sandbox_linux::credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};

mod executed;
use executed::executed_step_v1;
pub use executed::{ImmutableExecutedFileOriginalV1, ImmutableLoaderMapOriginalV1};

mod currentness;
pub use currentness::ImmutableFileRevalidationOriginalV1;
pub(crate) use currentness::ImmutableReadOriginalV1;
use currentness::{CurrentnessSlotsV1, observe_io_original, observe_native_original};

mod acquisition;
pub use acquisition::{ImmutableFileAcquisitionOriginalV1, ImmutableFileAcquisitionRefusalV1};
use acquisition::InitialMeasurementSlotsV1;

mod pin_read;
pub use pin_read::ImmutableImagePinReadOriginalV1;
use pin_read::PinReadSlotsV1;

mod backend_acquisition;
pub use backend_acquisition::BackendPid1ImageAcquisitionOriginalV1;
use backend_acquisition::BackendImageSlotsV1;

const MAXIMUM_IMAGE_BYTES: u64 = 16 * 1024 * 1024;

/// Reports unavailable or changed nonauthorizing immutable-file custody.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum ImmutableImageErrorV1 {
    /// A required file or kernel observation is unavailable.
    #[error("immutable image observation unavailable")]
    Unavailable,
    /// The original name, metadata or bounded content differs.
    #[error("immutable image custody or content differs")]
    Provisioning,
}

/// Retains measured bytes and read-only file custody without granting authority.
pub struct RetainedImmutableFileV1 {
    file: File,
    path: PathBuf,
    digest: [u8; 32],
    identity: (u64, u64, u64),
    maximum_bytes: u64,
    executable: bool,
    exact_data_bytes: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
enum ImmutableFileNativeCauseV1 {
    #[error(transparent)]
    Io(std::io::Error),
    #[error(transparent)]
    Errno(rustix::io::Errno),
}

// A selected pending owner keeps the actual first native cause and digest
// scratch. Ordinary public measurements use the same engine without a sink.
struct ImmutableFileObservationV1 {
    first: Option<ImmutableFileNativeCauseV1>,
    canonicalized: Option<PathBuf>,
    digest_buffer: [u8; 8192],
}

impl Default for ImmutableFileObservationV1 {
    fn default() -> Self {
        Self { first: None, canonicalized: None, digest_buffer: [0; 8192] }
    }
}

/// Retains partial measurement DATA without admitting a profile or role.
///
/// Genuine purpose owners prepay and park this destination before native IO.
/// Neither caller files nor its measured output construct a launch authority.
#[doc(hidden)]
#[derive(Default)]
pub struct PendingImmutableFileV1 {
    file: Option<File>,
    path: Option<PathBuf>,
    measured: Option<RetainedImmutableFileV1>,
    complete: bool,
    bytes: Vec<u8>,
    observation: ImmutableFileObservationV1,
    exact_data_bytes: Option<u64>,
}

impl PendingImmutableFileV1 {
    /// Parks an actual returned File before its subsequent measurement.
    pub fn park_original(&mut self, file: File) {
        self.file = Some(file);
    }

    /// Borrows the parked original File without observing or authorizing it.
    ///
    /// # Errors
    /// Rejects an absent original.
    pub fn original(&self) -> Result<&File, ImmutableImageErrorV1> {
        self.file.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)
    }

    /// Retains acquisition and measurement of the supplied immutable DATA name.
    ///
    /// # Errors
    /// Rejects unsafe paths, missing or changed native observations and unequal bounded content.
    pub fn open_and_measure(
        &mut self,
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.open_and_measure_recipe(path, expected_digest, maximum_bytes, executable, None)
    }

    fn open_and_measure_recipe(
        &mut self,
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
        mut original: Option<&mut InitialMeasurementSlotsV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.path = Some(path);
        let path = self.path.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?;
        let mut observation = Some(&mut self.observation);
        require_immutable_path_original(
            path, &mut observation,
            original.as_deref_mut().map(|slots| &mut slots.canonical_before),
        )?;
        let opened = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        );
        match original.as_deref_mut() {
            Some(slots) => match opened {
                Ok(file) => {
                    self.file = Some(File::from(file));
                    slots.opened = Some(Ok(()));
                }
                Err(cause) => {
                    slots.opened = Some(Err(cause));
                    return Err(ImmutableImageErrorV1::Unavailable);
                }
            },
            None => self.file = Some(File::from(observe_native(opened, &mut observation)?)),
        }
        self.measure_parked_recipe(expected_digest, maximum_bytes, executable, original)
    }

    /// Measures the same parked original under the bounded immutable recipe.
    ///
    /// # Errors
    /// Rejects absent originals, unsafe names or metadata, and unequal or excessive bytes.
    pub fn measure_original(
        &mut self,
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.path = Some(path);
        self.measure_parked(expected_digest, maximum_bytes, executable)
    }

    fn measure_parked(
        &mut self,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.measure_parked_recipe(expected_digest, maximum_bytes, executable, None)
    }

    fn measure_parked_recipe(
        &mut self,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
        mut original: Option<&mut InitialMeasurementSlotsV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        let path = self.path.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?;
        let mut observation = Some(&mut self.observation);
        require_immutable_path_original(
            path, &mut observation,
            original.as_deref_mut().map(|slots| &mut slots.canonical_measure),
        )?;
        let metadata = observe_io_original(
            self.file.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?.metadata(),
            &mut observation,
            original.as_deref_mut().map(|slots| &mut slots.initial_metadata),
        )?;

        // Both removals are checked together. An impossible missing slot still
        // returns its actual originals to this reservoir before refusal.
        let originals = (self.file.take(), self.path.take());
        let (file, path) = match originals {
            (Some(file), Some(path)) => (file, path),
            (file, path) => {
                self.file = file;
                self.path = path;
                return Err(ImmutableImageErrorV1::Provisioning);
            }
        };
        self.measured = Some(RetainedImmutableFileV1 {
            file,
            path,
            digest: [0; 32],
            identity: identity(&metadata),
            maximum_bytes,
            executable,
            exact_data_bytes: self.exact_data_bytes,
        });
        self.measured.as_mut().ok_or(ImmutableImageErrorV1::Provisioning)?
            .complete_measurement_recipe(expected_digest, &mut observation, original)?;
        self.complete = true;
        Ok(())
    }

    /// Retains bounded bytes from the same measured original.
    ///
    /// # Errors
    /// Rejects incomplete measurement, native IO failure or excess bytes.
    pub fn read_bounded(&mut self) -> Result<(), ImmutableImageErrorV1> {
        self.measurement()?;
        let measured = self.measured.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?;
        let mut observation = Some(&mut self.observation);
        let length = measured.bounded_read_length_observed(&mut observation)?;
        self.bytes = vec![0; length];
        measured.read_original_buffer_observed(&mut self.bytes, &mut observation)
    }

    // The pending owner remains resident while its same measurement is checked.
    /// Revalidates the same retained measurement with its original native sink.
    ///
    /// # Errors
    /// Rejects incomplete measurement or changed native names, metadata or bounded content.
    pub fn revalidate(&mut self) -> Result<(), ImmutableImageErrorV1> {
        self.measurement()?;
        self.measured.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?
            .revalidate_observed(&mut Some(&mut self.observation))
    }

    /// Borrows this pending measurement's first actual native cause.
    pub fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.observation.first.as_ref()? {
            ImmutableFileNativeCauseV1::Io(error) => Some(error),
            ImmutableFileNativeCauseV1::Errno(error) => Some(error),
        }
    }

    /// Borrows reached measurement bytes as nonauthorizing DATA.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows a completed measurement without granting a purpose role.
    ///
    /// # Errors
    /// Rejects incomplete or refused measurement.
    pub fn measurement(&self) -> Result<&RetainedImmutableFileV1, ImmutableImageErrorV1> {
        if !self.complete {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.measured.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)
    }

    /// Moves the actual completed measurement without issuing authority.
    pub fn take_measurement(&mut self) -> Option<RetainedImmutableFileV1> {
        if !self.complete {
            return None;
        }
        self.complete = false;
        self.measured.take()
    }

    // Restores only the same already-measured tuple member after an assembly
    // invariant refusal. The administrative attempt remains permanently ended.
    /// Restores custody of the same actual measurement destination.
    pub fn restore_measurement(&mut self, measured: Option<RetainedImmutableFileV1>) {
        self.complete = measured.is_some();
        self.measured = measured;
    }
}

impl RetainedImmutableFileV1 {
    /// Compares one immutable executable against separately selected bytes.
    ///
    /// # Errors
    /// Rejects unavailable, mutable, renamed, oversized or unequal files.
    pub fn open(path: PathBuf, digest: [u8; 32]) -> Result<Self, ImmutableImageErrorV1> {
        Self::open_with_profile(path, Some(digest), MAXIMUM_IMAGE_BYTES, true)
    }

    /// Pins observed immutable image policy, not an independent authorization.
    ///
    /// # Errors
    /// Rejects unavailable, mutable, renamed or oversized unit fragments.
    pub fn observe_fragment(path: PathBuf) -> Result<Self, ImmutableImageErrorV1> {
        Self::open_with_profile(path, None, 64 * 1024, false)
    }

    /// Retains bounded immutable bytes with an optional comparison digest.
    ///
    /// An observed digest or caller-supplied pathname is never image authority.
    ///
    /// # Errors
    /// Rejects unsafe names, metadata, mount flags, lengths or comparison bytes.
    pub fn open_with_profile(
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<Self, ImmutableImageErrorV1> {
        require_immutable_path(&path)?;
        let file = File::from(
            openat(
                CWD,
                &path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?,
        );
        Self::retain_with_profile(path, file, expected_digest, maximum_bytes, executable)
    }

    /// Retains an original file and compares its current immutable name.
    ///
    /// This measures custody only; it does not authenticate the file's supplier.
    ///
    /// # Errors
    /// Rejects unsafe names, metadata, mount flags, lengths or comparison bytes.
    pub fn retain_with_profile(
        path: PathBuf,
        file: File,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<Self, ImmutableImageErrorV1> {
        require_immutable_path(&path)?;
        let metadata = file
            .metadata()
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        let mut measured = Self {
            file,
            path,
            digest: [0; 32],
            identity: identity(&metadata),
            maximum_bytes,
            executable,
            exact_data_bytes: None,
        };
        measured.complete_measurement(expected_digest)?;
        Ok(measured)
    }

    fn complete_measurement(
        &mut self,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.complete_measurement_observed(expected_digest, &mut None)
    }

    fn complete_measurement_observed(
        &mut self,
        expected_digest: Option<[u8; 32]>,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.complete_measurement_recipe(expected_digest, observation, None)
    }

    fn complete_measurement_recipe(
        &mut self,
        expected_digest: Option<[u8; 32]>,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
        mut original: Option<&mut InitialMeasurementSlotsV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.validate_names_original(
            observation, original.as_deref_mut().map(|slots| &mut slots.names),
        )?;
        let digest = self.current_digest_observed(observation);
        let observed = match original.as_deref_mut() {
            Some(slots) => {
                slots.digest = Some(digest);
                let observed = match slots.digest.as_ref() {
                    Some(Ok(observed)) => *observed,
                    Some(Err(cause)) => return Err(currentness::projection(cause)),
                    None => return Err(ImmutableImageErrorV1::Unavailable),
                };
                slots.expected = Some(if expected_digest.is_some_and(|digest| digest != observed) {
                    Err(ImmutableImageErrorV1::Provisioning)
                } else {
                    Ok(())
                });
                currentness::unit(&slots.expected)?;
                observed
            }
            None => {
                let observed = digest?;
                if expected_digest.is_some_and(|digest| digest != observed) {
                    return Err(ImmutableImageErrorV1::Provisioning);
                }
                observed
            }
        };
        self.digest = observed;
        match original {
            Some(slots) => self.revalidate_retaining(&mut slots.final_comparison),
            None => self.revalidate_observed(observation),
        }
    }

    /// Bounds one same-file digest read from this actual admitted ceiling.
    ///
    /// The trailing byte covers the shared hash reader's hostile oversize/EOF
    /// frontier. This is passive IO geometry from the retained measurement,
    /// not permission to read an image or substitute its original custody.
    #[must_use]
    pub fn maximum_requested_read_bytes_v1(&self) -> Option<u64> {
        self.maximum_bytes.checked_add(1)
    }

    /// Rechecks the same original immutable file, name and bounded bytes.
    ///
    /// # Errors
    /// Rejects changed or unavailable custody, metadata, mounts or content.
    pub fn revalidate(&self) -> Result<(), ImmutableImageErrorV1> {
        self.revalidate_observed(&mut None)
    }

    fn revalidate_observed(
        &self,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.revalidate_recipe(observation, None)
    }

    fn revalidate_recipe(
        &self,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
        mut currentness: Option<CurrentnessSlotsV1<'_>>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.validate_names_original(
            observation, currentness.as_mut().map(|slots| &mut slots.names[0]),
        )?;
        let digest = self.current_digest_observed(observation);
        let equal = match currentness.as_mut() {
            Some(slots) => {
                *slots.digest = Some(digest);
                let observed = match slots.digest.as_ref() {
                    Some(Ok(observed)) => observed,
                    Some(Err(error)) => return Err(currentness::projection(error)),
                    None => return Err(ImmutableImageErrorV1::Unavailable),
                };
                *slots.digest_binding = Some(if observed == &self.digest {
                    Ok(())
                } else {
                    Err(ImmutableImageErrorV1::Provisioning)
                });
                currentness::unit(slots.digest_binding)?;
                true
            }
            None => digest? == self.digest,
        };
        if !equal {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.validate_names_original(
            observation, currentness.as_mut().map(|slots| &mut slots.names[1]),
        )
    }

    /// Parks a duplicate of this same measured original in an empty DATA slot.
    ///
    /// The genuine purpose keeps all independent execution and payment gates;
    /// a duplicate supplies no selected role, path or launch authorization.
    ///
    /// # Errors
    /// Rejects an occupied destination or failed native descriptor duplication.
    #[doc(hidden)]
    pub fn duplicate_nix_offline_original_into(
        &self, slot: &mut Option<OwnedFd>,
    ) -> std::io::Result<()> {
        if slot.is_some() {
            return Err(std::io::Error::other("offline executable slot is occupied"));
        }
        *slot = Some(rustix::io::fcntl_dupfd_cloexec(&self.file, 3)?);
        Ok(())
    }

    /// Compares a process's actual executed inode with this retained file.
    ///
    /// # Errors
    /// Rejects unavailable task-file access or a different executed inode.
    pub fn require_executed(&self, pid: u32) -> Result<(), ImmutableImageErrorV1> {
        executed::executed_recipe_v1!(Ordinary, self, pid, original)
    }

    /// Compares the same executed inode while retaining its actual native prefix.
    ///
    /// This mechanical destination supplies no process role or effect authority.
    /// A genuine caller keeps this measured file and its original pidfd through
    /// the independent process, image and purpose checks.
    ///
    /// # Errors
    /// Keeps failed open/metadata results and inode mismatch, and refuses reentry.
    #[doc(hidden)]
    pub fn require_executed_retaining_v1(
        &self, pid: u32, original: &mut ImmutableExecutedFileOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        if original.entered {
            original.reentry.get_or_insert(ImmutableImageErrorV1::Unavailable);
            return Err(ImmutableImageErrorV1::Unavailable);
        }
        original.entered = true;
        original.returned = Some((|| {
            executed::executed_recipe_v1!(Retained, self, pid, original)
        })());
        executed::project_unit(&original.returned)
    }

    /// Compares fixed offline helper executable DATA from the same original pidfd.
    ///
    /// The lower reservoir owns the actual executed inode before HELLO. A
    /// returned tuple alone is not an image proof; this method obtains it only
    /// through that reservoir's original-process and liveness bookends. The
    /// purpose caller still owns loader, startup, MAC and session comparisons.
    ///
    /// # Errors
    /// Returns the actual lower descriptor/process error. `Ok(false)` reports
    /// an original inode mismatch without inventing a native cause. Neither
    /// this method nor the lower DATA holder establishes process retirement.
    pub fn matches_nix_offline_executed_original_v5(
        &self,
        original: &aos_linux_descriptors::pidfd::PidFd,
        observations: &mut aos_sandbox_linux::pidfd::PidFdProcObservationsV1,
    ) -> Result<bool, aos_linux_descriptors::Error> {
        Ok(observations.observe_nix_offline_helper_executable_v1(original)? == self.identity)
    }

    /// Borrows this same original descriptor without duplicating or authorizing it.
    ///
    /// Callers retain independent image/role and financial bookends before any
    /// native operation. This read-only DATA view cannot create a process role.
    #[doc(hidden)]
    pub fn original_descriptor_v1(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.file)
    }

    /// Borrows the measured immutable pathname, not a launch authorization.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the measured content digest as comparison DATA, never authority.
    #[doc(hidden)]
    pub const fn measured_digest_v1(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the retained device, inode and byte length.
    pub const fn physical_identity(&self) -> (u64, u64, u64) {
        self.identity
    }

    /// Observes the original file's current device, inode and byte length.
    ///
    /// # Errors
    /// Rejects unavailable descriptor metadata.
    pub fn observed_identity(&self) -> Result<(u64, u64, u64), ImmutableImageErrorV1> {
        self.observed_identity_observed_v1(None)
    }

    fn observed_identity_observed_v1(
        &self, original: Option<&mut Option<std::io::Result<Metadata>>>,
    ) -> Result<(u64, u64, u64), ImmutableImageErrorV1> {
        match original {
            None => self.file.metadata().map(|metadata| identity(&metadata))
                .map_err(|_| ImmutableImageErrorV1::Unavailable),
            Some(original) => {
                *original = Some(self.file.metadata());
                original.as_ref().and_then(|value| value.as_ref().ok())
                    .map(identity).ok_or(ImmutableImageErrorV1::Unavailable)
            }
        }
    }

    /// Compares bounded maps DATA with this original loader's current identity.
    ///
    /// This is the canonical helper loader-mapping comparison, not a process
    /// admission. A genuine caller must acquire the maps through its retained
    /// original process and apply executable, liveness and purpose checks.
    ///
    /// # Errors
    /// Rejects unavailable original metadata, a non-UTF8 selected path or an
    /// oversized maps record. `Ok(false)` reports no matching executable map.
    pub fn mapped_in_helper_data_v5(&self, maps: &str) -> Result<bool, ImmutableImageErrorV1> {
        self.mapped_in_helper_data_observed_v1(maps, None)
    }

    /// Applies the same loader-map comparison with the original metadata result.
    ///
    /// # Errors
    /// Retains the native metadata failure, malformed maps or original mismatch;
    /// reentry cannot replace an earlier native or semantic result.
    #[doc(hidden)]
    pub fn mapped_in_helper_retaining_v1(
        &self, maps: &str, original: &mut ImmutableLoaderMapOriginalV1,
    ) -> Result<bool, ImmutableImageErrorV1> {
        if original.entered {
            original.reentry.get_or_insert(ImmutableImageErrorV1::Unavailable);
            return Err(ImmutableImageErrorV1::Unavailable);
        }
        original.entered = true;
        original.returned = Some(self.mapped_in_helper_data_observed_v1(
            maps, Some(&mut original.metadata),
        ));
        match original.returned.as_ref() {
            Some(Ok(value)) => Ok(*value),
            Some(Err(ImmutableImageErrorV1::Provisioning)) => Err(ImmutableImageErrorV1::Provisioning),
            _ => Err(ImmutableImageErrorV1::Unavailable),
        }
    }

    fn mapped_in_helper_data_observed_v1(
        &self, maps: &str, original: Option<&mut Option<std::io::Result<Metadata>>>,
    ) -> Result<bool, ImmutableImageErrorV1> {
        if maps.len() > 64 * 1024 {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let (device_id, expected_inode, _) = self.observed_identity_observed_v1(original)?;
        let device = format!(
            "{:02x}:{:02x}",
            rustix::fs::major(device_id),
            rustix::fs::minor(device_id)
        );
        let expected_path = self.path().to_str().ok_or(ImmutableImageErrorV1::Provisioning)?;
        Ok(maps.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let _address = fields.next();
            let executable = fields.next().is_some_and(|value| value.contains('x'));
            let _offset = fields.next();
            let observed_device = fields.next();
            let inode = fields.next().and_then(|value| value.parse::<u64>().ok());
            let path = fields.next();
            executable
                && observed_device == Some(device.as_str())
                && inode == Some(expected_inode)
                && path == Some(expected_path)
                && fields.next().is_none()
        }))
    }

    /// Reads bounded bytes between rechecks without moving the shared offset.
    ///
    /// # Errors
    /// Rejects changed custody, length overflow or incomplete reads.
    pub fn read_bounded(&self) -> Result<Vec<u8>, ImmutableImageErrorV1> {
        let mut bytes = Vec::new();
        self.read_bounded_recipe(&mut bytes, None)?;
        Ok(bytes)
    }

    pub(crate) fn read_bounded_retaining_v1<'original>(
        &self,
        original: &'original mut ImmutableReadOriginalV1,
    ) -> Result<&'original [u8], ImmutableImageErrorV1> {
        if original.before.is_some() {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.read_bounded_recipe(
            &mut original.bytes,
            Some(currentness::BoundedReadSlotsV1 {
                before_original: &mut original.before_original,
                before: &mut original.before,
                read: &mut original.read,
                after_original: &mut original.after_original,
                after: &mut original.after,
            }),
        )?;
        Ok(&original.bytes)
    }

    fn read_bounded_recipe(
        &self,
        bytes: &mut Vec<u8>,
        mut original: Option<currentness::BoundedReadSlotsV1<'_>>,
    ) -> Result<(), ImmutableImageErrorV1> {
        match original.as_mut() {
            Some(slots) => {
                *slots.before = Some(self.revalidate_retaining(slots.before_original));
                currentness::unit(slots.before)?;
            }
            None => self.revalidate()?,
        }
        let length = usize::try_from(self.identity.2)
            .map_err(|_| ImmutableImageErrorV1::Provisioning)?;
        *bytes = vec![0; length];
        self.read_exact_buffer_observed(
            bytes,
            &mut None,
            original.as_mut().map(|slots| &mut *slots.read),
        )?;
        match original {
            Some(slots) => {
                *slots.after = Some(self.revalidate_retaining(slots.after_original));
                currentness::unit(slots.after)
            }
            None => self.revalidate(),
        }
    }

    fn bounded_read_length_observed(
        &self,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
    ) -> Result<usize, ImmutableImageErrorV1> {
        self.revalidate_observed(observation)?;
        usize::try_from(self.identity.2).map_err(|_| ImmutableImageErrorV1::Provisioning)
    }

    fn read_original_buffer_observed(
        &self,
        bytes: &mut [u8],
        observation: &mut Option<&mut ImmutableFileObservationV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.read_exact_buffer_observed(bytes, observation, None)?;
        self.revalidate_observed(observation)
    }

    fn read_exact_buffer_observed(
        &self,
        bytes: &mut [u8],
        observation: &mut Option<&mut ImmutableFileObservationV1>,
        original: Option<&mut Option<std::io::Result<()>>>,
    ) -> Result<(), ImmutableImageErrorV1> {
        observe_io_original(self.file.read_exact_at(bytes, 0), observation, original)?;
        Ok(())
    }

    fn validate_names_observed(
        &self,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.validate_names_original(observation, None)
    }

    fn validate_names_original(
        &self,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
        original: Option<&mut currentness::NamesOriginalV1>,
    ) -> Result<(), ImmutableImageErrorV1> {
        let (held_original, named_original, mount_original, binding_original) = match original {
            Some(original) => (
                Some(&mut original.held), Some(&mut original.named),
                Some(&mut original.mount), Some(&mut original.binding),
            ),
            None => (None, None, None, None),
        };
        let metadata = observe_io_original(
            self.file.metadata(), observation,
            held_original,
        )?;
        let named = observe_io_original(
            std::fs::symlink_metadata(&self.path), observation,
            named_original,
        )?;
        let mount = observe_native_original(
            fstatvfs(&self.file), observation,
            mount_original,
        )?;
        let invalid = !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7222 != 0
            || self.executable && metadata.mode() & 0o100 == 0
            || metadata.nlink() != 1
            || metadata.len() == 0 && self.exact_data_bytes != Some(0)
            || self.exact_data_bytes.is_some_and(|length| metadata.len() != length)
            || metadata.len() > self.maximum_bytes
            || identity(&metadata) != self.identity
            || identity(&named) != self.identity
            || !named.is_file()
            || !mount.f_flag.contains(StatVfsMountFlags::RDONLY)
            || self.executable && mount.f_flag.contains(StatVfsMountFlags::NOEXEC);
        let result = if invalid {
            Err(ImmutableImageErrorV1::Provisioning)
        } else {
            Ok(())
        };
        match binding_original {
            Some(binding) => {
                *binding = Some(result);
                currentness::unit(binding)
            }
            None => result,
        }
    }

    fn current_digest_observed(
        &self,
        observation: &mut Option<&mut ImmutableFileObservationV1>,
    ) -> Result<[u8; 32], ImmutableImageErrorV1> {
        let mut hash = Sha256::new();
        let mut ordinary_buffer = [0; 8192];
        let (buffer, mut first) = match observation.as_deref_mut() {
            Some(observation) => (&mut observation.digest_buffer, Some(&mut observation.first)),
            None => (&mut ordinary_buffer, None),
        };
        let mut total = 0_u64;
        loop {
            let count = match self.file.read_at(buffer, total) {
                Ok(count) => count,
                Err(error) => {
                    retain_native_cause(&mut first, ImmutableFileNativeCauseV1::Io(error));
                    return Err(ImmutableImageErrorV1::Unavailable);
                }
            };
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|value| *value <= self.maximum_bytes)
                .ok_or(ImmutableImageErrorV1::Unavailable)?;
            hash.update(&buffer[..count]);
        }
        if total != self.identity.2 {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(hash.finalize().into())
    }
}

fn require_immutable_path(path: &Path) -> Result<(), ImmutableImageErrorV1> {
    require_immutable_path_observed(path, &mut None)
}

fn require_immutable_path_observed(
    path: &Path,
    observation: &mut Option<&mut ImmutableFileObservationV1>,
) -> Result<(), ImmutableImageErrorV1> {
    require_immutable_path_original(path, observation, None)
}

fn require_immutable_path_original(
    path: &Path,
    observation: &mut Option<&mut ImmutableFileObservationV1>,
    original: Option<&mut Option<std::io::Result<PathBuf>>>,
) -> Result<(), ImmutableImageErrorV1> {
    if !path.starts_with("/nix/store") {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    let returned = std::fs::canonicalize(path);
    let same = match original {
        Some(original) => {
            *original = Some(returned);
            match original.as_ref() {
                Some(Ok(canonicalized)) => canonicalized.as_path() == path,
                _ => return Err(ImmutableImageErrorV1::Provisioning),
            }
        }
        None => {
            let canonicalized = observe_io(returned, observation, true)?;
            let same = canonicalized == path;
            if let Some(observation) = observation.as_deref_mut() {
                observation.canonicalized = Some(canonicalized);
            } else {
                // Preserve the ordinary comparison temporary's pre-refusal disposal.
                drop(canonicalized);
            }
            same
        }
    };
    if !same {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    Ok(())
}

// These helpers retain only original native causes. Logical custody/shape
// refusals continue to use the unchanged public error and owning upper Result.
fn observe_io<T>(
    result: std::io::Result<T>,
    observation: &mut Option<&mut ImmutableFileObservationV1>,
    provisioning: bool,
) -> Result<T, ImmutableImageErrorV1> {
    result.map_err(|error| {
        let mut first = observation.as_deref_mut().map(|value| &mut value.first);
        retain_native_cause(&mut first, ImmutableFileNativeCauseV1::Io(error));
        if provisioning { ImmutableImageErrorV1::Provisioning } else { ImmutableImageErrorV1::Unavailable }
    })
}

fn observe_native<T>(
    result: Result<T, rustix::io::Errno>,
    observation: &mut Option<&mut ImmutableFileObservationV1>,
) -> Result<T, ImmutableImageErrorV1> {
    result.map_err(|error| {
        let mut first = observation.as_deref_mut().map(|value| &mut value.first);
        retain_native_cause(&mut first, ImmutableFileNativeCauseV1::Errno(error));
        ImmutableImageErrorV1::Unavailable
    })
}

fn retain_native_cause(
    first: &mut Option<&mut Option<ImmutableFileNativeCauseV1>>,
    cause: ImmutableFileNativeCauseV1,
) {
    if let Some(first) = first {
        if first.is_none() {
            **first = Some(cause);
        }
    }
}

/// Rejects file-status flags that do not describe a read-only data descriptor.
///
/// # Errors
/// Rejects path-only, writable, append or truncating descriptors.
pub fn require_readonly_launch_flags(flags: OFlags) -> Result<(), ImmutableImageErrorV1> {
    if flags
        .intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND | OFlags::TRUNC)
    {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    Ok(())
}

/// Measures an original PID 1 file against the image-built backend artifact.
///
/// The file must come from the caller's genuine original launch capture. This
/// shared measurement does not authenticate its supplier, confer floor or
/// worker authority, or establish continuous identity after manager reexec.
///
/// # Errors
///
/// Rejects missing compiled selection, unsafe artifact metadata, malformed
/// pins, unavailable cloning, writable descriptors, or changed image custody.
pub fn retain_original_backend_pid1_v1(
    original: &File,
) -> Result<RetainedImmutableFileV1, ImmutableImageErrorV1> {
    retain_original_backend_pid1_recipe(original, None)
}

fn retain_original_backend_pid1_recipe(
    original: &File,
    mut destination: Option<&mut BackendImageSlotsV1>,
) -> Result<RetainedImmutableFileV1, ImmutableImageErrorV1> {
    let path = PathBuf::from(
        option_env!("AOS_METHOD46_TPM_PID1").ok_or(ImmutableImageErrorV1::Unavailable)?,
    );
    if let Some(destination) = destination.as_deref_mut() {
        destination.path = Some(path.clone());
    }
    let package = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(ImmutableImageErrorV1::Provisioning)?;
    let ordinary_pin;
    let pin: &[u8] = match destination.as_deref_mut() {
        Some(destination) => {
            destination.pin.read_once(&package.join("share/aos"), "backend-policy-artifact-v2", 74, 4096)?;
            destination.pin.completed_bytes().ok_or(ImmutableImageErrorV1::Provisioning)?
        }
        None => {
            ordinary_pin = read_immutable_image_pin_v1(
                &package.join("share/aos"), "backend-policy-artifact-v2", 74, 4096,
            )?;
            &ordinary_pin
        }
    };
    if !pin.starts_with(b"AOSBPA02\n") {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    let digest = decode_immutable_sha256_pin_v1(
        pin.get(9..74).ok_or(ImmutableImageErrorV1::Provisioning)?,
    );
    let digest = match destination.as_deref_mut() {
        Some(destination) => {
            destination.digest = Some(digest);
            match destination.digest.as_ref() {
                Some(Ok(value)) => *value,
                Some(Err(cause)) => return Err(currentness::projection(cause)),
                None => return Err(ImmutableImageErrorV1::Provisioning),
            }
        }
        None => digest?,
    };

    // Clone this original inode, never reopen a nominally selected PID 1 image.
    // Selected capture parks that File before the actual flag syscall.
    let cloned = original.try_clone();
    let mut ordinary_file = None;
    let (file, flags_original) = match destination.as_deref_mut() {
        Some(destination) => {
            destination.cloned = Some(cloned);
            let file = match destination.cloned.as_ref() {
                Some(Ok(file)) => file,
                _ => return Err(ImmutableImageErrorV1::Unavailable),
            };
            (file, Some(&mut destination.flags))
        }
        None => {
            ordinary_file = Some(cloned.map_err(|_| ImmutableImageErrorV1::Unavailable)?);
            (ordinary_file.as_ref().ok_or(ImmutableImageErrorV1::Unavailable)?, None)
        }
    };
    let flags = observe_native_original(rustix::fs::fcntl_getfl(file), &mut None, flags_original)?;
    let binding = require_readonly_launch_flags(*flags);
    match destination.as_deref_mut() {
        Some(destination) => {
            destination.readonly = Some(binding);
            currentness::unit(&destination.readonly)?;
        }
        None => binding?,
    }
    match destination {
        Some(destination) => {
            let file = match destination.cloned.take() {
                Some(Ok(file)) => {
                    destination.clone_transferred = true;
                    file
                }
                original => {
                    destination.cloned = original;
                    return Err(ImmutableImageErrorV1::Unavailable);
                }
            };
            destination.measurement_entry = Some(destination.measurement.measure_original_once(
                path, file, Some(digest), MAXIMUM_IMAGE_BYTES, true,
            ));
            if !matches!(destination.measurement_entry, Some(Ok(()))) {
                return Err(destination.measurement.completion_failure_v1()
                    .map(currentness::projection).unwrap_or(ImmutableImageErrorV1::Unavailable));
            }
            destination.measurement.take_completed_measurement_once()
                .ok_or(ImmutableImageErrorV1::Unavailable)
        }
        None => RetainedImmutableFileV1::retain_with_profile(
            path, ordinary_file.take().ok_or(ImmutableImageErrorV1::Unavailable)?,
            Some(digest), MAXIMUM_IMAGE_BYTES, true,
        ),
    }
}

/// Reads bounded root-owned immutable image-pin DATA through the shared reader.
///
/// A pathname and returned bytes are not independent image authorization.
///
/// # Errors
///
/// Rejects missing pins, unsafe metadata, bounds, or incomplete reads.
pub fn read_immutable_image_pin_v1(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, ImmutableImageErrorV1> {
    read_immutable_image_pin_recipe(directory, name, minimum, maximum, None)
}

fn read_immutable_image_pin_recipe(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
    original: Option<&mut PinReadSlotsV1>,
) -> Result<Vec<u8>, ImmutableImageErrorV1> {
    // The ordinary temporary pathname ends at the original metadata frontier.
    // A selected sink instead keeps that exact path and native result resident.
    let path = directory.join(name);
    let native = std::fs::symlink_metadata(&path);
    let (metadata, binding_original, reader_original) = match original {
        Some(original) => {
            original.path = Some(path);
            original.metadata = Some(native);
            let metadata = match original.metadata.as_ref() {
                Some(Ok(value)) => currentness::NativeOutputV1::Original(value),
                _ => return Err(ImmutableImageErrorV1::Provisioning),
            };
            (metadata, Some(&mut original.binding), Some(&mut original.reader))
        }
        None => {
            drop(path);
            (currentness::NativeOutputV1::Local(native
                .map_err(|_| ImmutableImageErrorV1::Provisioning)?), None, None)
        }
    };
    let binding = if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o222 != 0
    {
        Err(ImmutableImageErrorV1::Provisioning)
    } else {
        Ok(())
    };
    match binding_original {
        Some(original) => {
            *original = Some(binding);
            currentness::unit(original)?;
        }
        None => binding?,
    }
    // Metadata remains in scope through this same read, including ordinary
    // success/error disposal. Disjoint sink fields preserve that native order.
    match reader_original {
        Some(reader) => {
            reader.read_once(directory, name, minimum, maximum, false,
                CredentialOwnerPolicyV1::RootOrCurrent);
            reader.take_success_bytes_once().ok_or(ImmutableImageErrorV1::Provisioning)
        }
        None => read_optional_bounded_role_credential_v1(
            directory, name, minimum, maximum, false, CredentialOwnerPolicyV1::RootOrCurrent,
        ).map_err(|_| ImmutableImageErrorV1::Provisioning)?
            .ok_or(ImmutableImageErrorV1::Provisioning),
    }
}

/// Decodes exact lowercase SHA-256 pin DATA terminated by one newline.
///
/// # Errors
///
/// Rejects any length, character, or terminator outside the canonical form.
pub fn decode_immutable_sha256_pin_v1(
    bytes: &[u8],
) -> Result<[u8; 32], ImmutableImageErrorV1> {
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || bytes[..64]
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    let mut digest = [0; 32];
    for (index, pair) in bytes[..64].chunks_exact(2).enumerate() {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        digest[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
}

fn identity(metadata: &Metadata) -> (u64, u64, u64) {
    (metadata.dev(), metadata.ino(), metadata.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek as _, SeekFrom, Write as _};

    #[test]
    fn immutable_image_hashing_ignores_and_preserves_shared_file_offset() {
        let mut file = tempfile::tempfile().unwrap();
        let bytes = b"bounded original image bytes";
        file.write_all(bytes).unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let mut duplicate = file.try_clone().unwrap();
        let mut measurement = RetainedImmutableFileV1 {
            identity: identity(&file.metadata().unwrap()),
            file,
            path: PathBuf::from("/hash-only-test-not-image-authority"),
            digest: [0; 32],
            maximum_bytes: bytes.len() as u64,
            executable: false,
            exact_data_bytes: None,
        };
        let expected: [u8; 32] = Sha256::digest(bytes).into();

        assert_eq!(measurement.current_digest_observed(&mut None).unwrap(), expected);
        assert_eq!(duplicate.stream_position().unwrap(), 7);
        duplicate.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(measurement.current_digest_observed(&mut None).unwrap(), expected);
        assert_eq!(duplicate.stream_position().unwrap(), 3);
        measurement.maximum_bytes -= 1;
        assert!(measurement.current_digest_observed(&mut None).is_err());
        // Hashing test-local bytes never admits a package/launcher image.
        assert!(measurement.revalidate().is_err());
    }

    #[test]
    fn exact_empty_data_uses_the_same_native_hash_and_retains_growth_refusal() {
        let file = tempfile::tempfile().unwrap();
        let mut duplicate = file.try_clone().unwrap();
        duplicate.seek(SeekFrom::Start(17)).unwrap();
        let measurement = RetainedImmutableFileV1 {
            identity: identity(&file.metadata().unwrap()), file,
            path: PathBuf::from("/hash-only-empty-data-not-image-authority"),
            digest: Sha256::digest([]).into(), maximum_bytes: 0,
            executable: false, exact_data_bytes: Some(0),
        };

        assert_eq!(measurement.current_digest_observed(&mut None).unwrap(), measurement.digest);
        assert_eq!(duplicate.stream_position().unwrap(), 17);
        assert!(measurement.revalidate().is_err());

        duplicate.seek(SeekFrom::Start(0)).unwrap();
        duplicate.write_all(b"x").unwrap();
        assert!(measurement.current_digest_observed(&mut None).is_err());
        assert_eq!(measurement.file.metadata().unwrap().len(), 1);
        assert_eq!(measurement.exact_data_bytes, Some(0));
    }

    #[test]
    fn selected_failed_name_keeps_the_original_file_and_actual_native_error() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-name");
        let file = tempfile::tempfile().unwrap();
        let identity = identity(&file.metadata().unwrap());
        let mut pending = PendingImmutableFileV1::default();
        pending.measured = Some(RetainedImmutableFileV1 {
            file, path: missing, digest: [0; 32], identity,
            maximum_bytes: 16, executable: false,
            exact_data_bytes: None,
        });
        pending.complete = true;

        assert!(pending.read_bounded().is_err());
        let error = pending.native_failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(pending.measured.as_ref().unwrap().file.metadata().is_ok());
        assert!(pending.bytes().is_empty());
    }

    #[test]
    fn selected_hash_uses_same_offset_independent_engine_with_retained_scratch() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"selected-digest-data").unwrap();
        file.seek(SeekFrom::Start(4)).unwrap();
        let mut duplicate = file.try_clone().unwrap();
        let measurement = RetainedImmutableFileV1 {
            identity: identity(&file.metadata().unwrap()), file,
            path: PathBuf::from("/test-only-not-image-authority"), digest: [0; 32],
            maximum_bytes: 32, executable: false,
            exact_data_bytes: None,
        };
        let mut observation = ImmutableFileObservationV1::default();

        let digest = measurement.current_digest_observed(&mut Some(&mut observation)).unwrap();
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(b"selected-digest-data")));
        assert_eq!(duplicate.stream_position().unwrap(), 4);
        assert_eq!(&observation.digest_buffer[..20], b"selected-digest-data");
        assert!(observation.first.is_none());
    }
}

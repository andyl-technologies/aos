//! Measures closed compiled TPM-helper ELF and loader pairs as passive DATA.
//!
//! The source-built package records hashes after explicit stripping. The parent
//! retains both files and can check the actual executable inode and loader map.
//! Callers independently admit their Source, child and private carrier before
//! releasing any index auth. Subsequent checks retain
//! the same read-only names, contents and process instance; the helper never
//! execs or forks after this observation.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

#[cfg(test)]
use rustix::fs::OFlags;

use crate::immutable_image::ImmutableImageErrorV1;

mod currentness;
mod executed;
pub use executed::HelperExecutedImageOriginalV1;
use executed::{helper_executed_recipe_v1, helper_executed_step_v1};
mod acquisition;
pub use acquisition::HelperImageAcquisitionOriginalV1;
pub use currentness::HelperImageRevalidationOriginalV1;

const MAXIMUM_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
pub(super) use crate::immutable_image::RetainedImmutableFileV1 as MeasuredFileV1;
#[cfg(test)]
use crate::immutable_image::require_readonly_launch_flags;

const MAXIMUM_MAPS_BYTES: u64 = 64 * 1024;

/// Selects one compiled helper image for passive measurement.
///
/// This closed selector accepts no pathname and grants no role or TPM authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedTpmHelperPurposeV1 {
    /// Selects the normal method-46 helper.
    Broker,
    /// Selects the normal Host deployment helper.
    RuntimeDeployment,
    /// Selects the Controller online-Nix helper.
    ControllerNix,
    /// Selects the Nix owner helper.
    NixOwner,
    /// Selects the root manual Controller initializer helper.
    InitialController,
    /// Selects the root manual Storage initializer helper.
    InitialStorage,
}

impl FixedTpmHelperPurposeV1 {
    fn compiled_path(&self) -> Result<&'static str, ImmutableImageErrorV1> {
        match self {
            Self::Broker => option_env!("AOS_METHOD46_TPM_HELPER"),
            Self::RuntimeDeployment => option_env!("AOS_RUNTIME_DEPLOYMENT_TPM_HELPER"),
            Self::ControllerNix => option_env!("AOS_NIX_CONTROLLER_TPM_HELPER"),
            Self::NixOwner => option_env!("AOS_NIX_OWNER_TPM_HELPER"),
            Self::InitialController => option_env!("AOS_METHOD46_INITIAL_CONTROLLER_TPM_HELPER"),
            Self::InitialStorage => option_env!("AOS_METHOD46_INITIAL_STORAGE_TPM_HELPER"),
        }
        .ok_or(ImmutableImageErrorV1::Unavailable)
    }

    const fn names(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Broker => (
                "aos-method46-tpm-helper",
                "aos-method46-tpm-helper.sha256",
                "aos-method46-tpm-helper.loader",
            ),
            Self::RuntimeDeployment => (
                "aos-runtime-deployment-tpm-helper",
                "aos-runtime-deployment-tpm-helper.sha256",
                "aos-runtime-deployment-tpm-helper.loader",
            ),
            Self::ControllerNix => (
                "aos-nix-controller-tpm-helper",
                "aos-nix-controller-tpm-helper.sha256",
                "aos-nix-controller-tpm-helper.loader",
            ),
            Self::InitialController => (
                "aos-method46-initial-controller-tpm-helper",
                "aos-method46-initial-controller-tpm-helper.sha256",
                "aos-method46-initial-controller-tpm-helper.loader",
            ),
            Self::InitialStorage => (
                "aos-method46-initial-storage-tpm-helper",
                "aos-method46-initial-storage-tpm-helper.sha256",
                "aos-method46-initial-storage-tpm-helper.loader",
            ),
            Self::NixOwner => (
                "aos-nix-owner-tpm-helper",
                "aos-nix-owner-tpm-helper.sha256",
                "aos-nix-owner-tpm-helper.loader",
            ),
        }
    }
}

/// Retains the measured fixed executable and loader without granting authority.
///
/// The owner must independently admit its Source, process, channel and effect.
#[must_use = "retain both measured originals through their owed comparisons"]
pub struct MeasuredHelperImageV1 {
    purpose: FixedTpmHelperPurposeV1,
    executable: MeasuredFileV1,
    loader: MeasuredFileV1,
}

impl MeasuredHelperImageV1 {
    /// Measures the selected compiled helper and its final loader pin.
    ///
    /// Retained callers use `HelperImageAcquisitionOriginalV1` to keep native
    /// failed prefixes; this consuming path preserves the normal runtime API.
    ///
    /// # Errors
    /// Rejects absent compiled paths, unsafe or malformed pins, native IO
    /// failures and changed immutable image names, metadata or contents.
    pub fn open(purpose: FixedTpmHelperPurposeV1) -> Result<Self, ImmutableImageErrorV1> {
        Self::open_purpose_recipe(purpose, &mut None)
    }

    fn open_purpose_recipe(
        purpose: FixedTpmHelperPurposeV1,
        original: &mut Option<&mut HelperImageAcquisitionOriginalV1>,
    ) -> Result<Self, ImmutableImageErrorV1> {
        let path = PathBuf::from(purpose.compiled_path()?);
        if let Some(original) = original.as_deref_mut() {
            original.path = Some(path.clone());
        }
        let (basename, executable_pin_name, loader_pin_name) = purpose.names();
        let relative = path
            .strip_prefix("/nix/store")
            .map_err(|_| ImmutableImageErrorV1::Provisioning)?;
        if relative.components().count() != 3
            || relative
                .components()
                .nth(1)
                .is_none_or(|part| part.as_os_str() != "libexec")
            || path.file_name().is_none_or(|name| name != basename)
        {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let directory = path.parent().ok_or(ImmutableImageErrorV1::Provisioning)?;
        let executable_pin = acquisition::read_pin_once(
            directory,
            executable_pin_name,
            65,
            65,
            original
                .as_deref_mut()
                .map(|original| &mut original.pins[0]),
        )?;
        let executable_digest = decode_hash(&executable_pin);
        if let Some(original) = original.as_deref_mut() {
            original.executable_digest = Some(executable_digest);
        }
        let executable_digest = executable_digest?;
        let loader_pin = acquisition::read_pin_once(
            directory,
            loader_pin_name,
            79,
            578,
            original
                .as_deref_mut()
                .map(|original| &mut original.pins[1]),
        )?;
        let mut lines = loader_pin.split_inclusive(|byte| *byte == b'\n');
        let loader_path = lines.next().ok_or(ImmutableImageErrorV1::Provisioning)?;
        let loader_digest = decode_hash(lines.next().ok_or(ImmutableImageErrorV1::Provisioning)?);
        if let Some(original) = original.as_deref_mut() {
            original.loader_digest = Some(loader_digest);
        }
        let loader_digest = loader_digest?;
        if lines.next().is_some() || loader_path.last() != Some(&b'\n') || loader_path.len() > 513 {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let loader_path = PathBuf::from(acquisition::loader_text_once(
            &loader_path[..loader_path.len() - 1],
            original.as_deref_mut(),
        )?);
        match original.as_deref_mut() {
            Some(original) => {
                // The actual executable remains resident if the later loader
                // acquisition fails. No native return lives only in a local.
                original.loader_path = Some(loader_path.clone());
                original.measurements[0] = Some(original.files[0].open_and_measure_once(
                    path,
                    Some(executable_digest),
                    MAXIMUM_IMAGE_BYTES,
                    true,
                ));
                if !matches!(original.measurements[0], Some(Ok(()))) {
                    return Err(ImmutableImageErrorV1::Provisioning);
                }
                original.executable = original.files[0].take_completed_measurement_once();
                original.measurements[1] = Some(original.files[1].open_and_measure_once(
                    loader_path,
                    Some(loader_digest),
                    MAXIMUM_IMAGE_BYTES,
                    true,
                ));
                if !matches!(original.measurements[1], Some(Ok(()))) {
                    return Err(ImmutableImageErrorV1::Provisioning);
                }
                original.loader = original.files[1].take_completed_measurement_once();
                match (original.executable.take(), original.loader.take()) {
                    (Some(executable), Some(loader)) => {
                        original.image = Some(Self {
                            purpose,
                            executable,
                            loader,
                        });
                    }
                    (executable, loader) => {
                        original.executable = executable;
                        original.loader = loader;
                        return Err(ImmutableImageErrorV1::Unavailable);
                    }
                }
                let image = original
                    .image
                    .as_ref()
                    .ok_or(ImmutableImageErrorV1::Unavailable)?;
                original.revalidated =
                    Some(image.revalidate_owed_retaining_v1(&mut original.revalidation));
                match original.revalidated {
                    Some(Ok(())) => original
                        .image
                        .take()
                        .ok_or(ImmutableImageErrorV1::Unavailable),
                    Some(Err(cause)) => Err(cause),
                    None => Err(ImmutableImageErrorV1::Unavailable),
                }
            }
            None => {
                let mut image = Self {
                    purpose,
                    executable: MeasuredFileV1::open(path, executable_digest)?,
                    loader: MeasuredFileV1::open(loader_path, loader_digest)?,
                };
                image.revalidate()?;
                Ok(image)
            }
        }
    }

    /// Returns the closed purpose whose compiled image and pins were measured.
    ///
    /// This immutable selector authenticates no Source, process or TPM effect.
    pub const fn purpose_data_v1(&self) -> FixedTpmHelperPurposeV1 {
        self.purpose
    }

    /// Borrows the measured executable description for fixed native setup.
    ///
    /// The owner must fund a duplicate before native handoff. This read-only
    /// borrow is comparison custody, not process or effect authorization.
    pub fn executable_description_v1(&self) -> std::os::fd::BorrowedFd<'_> {
        self.executable.original_descriptor_v1()
    }

    /// Borrows the original compiled executable path as comparison DATA.
    pub fn path(&self) -> &Path {
        self.executable.path()
    }

    /// Compares the actual process executable and loader map with both originals.
    ///
    /// # Errors
    /// Rejects unavailable proc observations, foreign executable identity,
    /// excess map bytes or a missing or changed loader mapping.
    pub fn require_executed(&self, pid: u32) -> Result<(), ImmutableImageErrorV1> {
        helper_executed_recipe_v1!(Ordinary, self, pid, original)
    }

    /// Retains one actual process executable and loader-map comparison.
    ///
    /// # Errors
    /// Retains proc IO and comparison failures and refuses repeated entry.
    pub fn require_executed_retaining_v1(
        &self,
        pid: u32,
        original: &mut HelperExecutedImageOriginalV1,
    ) -> Result<(), ImmutableImageErrorV1> {
        if original.returned.is_some() {
            original
                .reentry
                .get_or_insert(ImmutableImageErrorV1::Unavailable);
            return Err(ImmutableImageErrorV1::Unavailable);
        }
        original.returned = Some((|| {
            helper_executed_recipe_v1!(Retained, self, pid, original)
        })());
        original
            .returned
            .as_ref()
            .copied()
            .unwrap_or(Err(ImmutableImageErrorV1::Unavailable))
    }

    /// Rechecks both original immutable files in executable-then-loader order.
    ///
    /// # Errors
    /// Rejects native IO failures or changed names, metadata or bounded bytes.
    pub fn revalidate(&mut self) -> Result<(), ImmutableImageErrorV1> {
        self.executable.revalidate()?;
        self.loader.revalidate().map_err(Into::into)
    }
}

fn read_pin(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, ImmutableImageErrorV1> {
    crate::immutable_image::read_immutable_image_pin_v1(directory, name, minimum, maximum)
        .map_err(Into::into)
}

fn decode_hash(bytes: &[u8]) -> Result<[u8; 32], ImmutableImageErrorV1> {
    crate::immutable_image::decode_immutable_sha256_pin_v1(bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_floor_helper_image_hash_is_exact_lowercase_and_bounded() {
        assert_eq!(
            decode_hash(&[b"09".repeat(32), b"\n".to_vec()].concat()).unwrap(),
            [9; 32]
        );
        for bytes in [
            b"".to_vec(),
            b"A".repeat(65),
            b"0".repeat(64),
            [b"0".repeat(64), b"\n\0".to_vec()].concat(),
        ] {
            assert!(decode_hash(&bytes).is_err());
        }
    }

    #[test]
    fn tpm_floor_pid1_launch_image_rejects_non_readonly_descriptor_flags() {
        assert!(require_readonly_launch_flags(OFlags::RDONLY | OFlags::CLOEXEC).is_ok());
        for flags in [
            OFlags::WRONLY,
            OFlags::RDWR,
            OFlags::PATH,
            OFlags::RDONLY | OFlags::APPEND,
            OFlags::RDONLY | OFlags::TRUNC,
        ] {
            assert!(require_readonly_launch_flags(flags).is_err());
        }
    }
}

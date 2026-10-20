//! Shared original-descriptor and self-process image observations, never authority.

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use sha2::{Digest as _, Sha256};

use crate::immutable_image::{
    ImmutableImageErrorV1, PendingImmutableFileV1, RetainedImmutableFileV1,
    require_readonly_launch_flags,
};

use super::{
    ControllerProfileErrorV1 as NormalRootStartupErrorV1,
    schema::{ImagePinV1, NormalRootProfileV1, MAXIMUM_PROFILE_BYTES},
};

const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_MAPS_BYTES: u64 = 256 * 1024;

mod actual_mappings;
pub use actual_mappings::{ActualExecutableMappingsClosedV1, ActualExecutableMappingsOriginalV1};

/// Retains actual native or fixed-classification image observation failure.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum ImageObservationErrorV1 {
    /// Holds the original fixed profile classification.
    #[error("selected profile shape differs")]
    Profile(#[from] NormalRootStartupErrorV1),
    /// Holds the original native IO error.
    #[error("selected original file observation failed")]
    Io(#[from] std::io::Error),
    /// Holds the actual descriptor errno.
    #[error("selected original descriptor inspection failed")]
    Descriptor(#[from] rustix::io::Errno),
    /// Holds the shared immutable measurement refusal.
    #[error("selected immutable measurement differs")]
    Image(#[from] ImmutableImageErrorV1),
}

impl ImageObservationErrorV1 {
    /// Returns the existing fixed image classification without moving its cause.
    pub fn legacy_error(&self) -> NormalRootStartupErrorV1 {
        match self {
            Self::Profile(error) => match error {
                NormalRootStartupErrorV1::Activation => NormalRootStartupErrorV1::Activation,
                NormalRootStartupErrorV1::Profile => NormalRootStartupErrorV1::Profile,
                NormalRootStartupErrorV1::Image => NormalRootStartupErrorV1::Image,
                NormalRootStartupErrorV1::Service => NormalRootStartupErrorV1::Service,
                NormalRootStartupErrorV1::Confinement => NormalRootStartupErrorV1::Confinement,
            },
            Self::Io(_) | Self::Descriptor(_) | Self::Image(_) => NormalRootStartupErrorV1::Image,
        }
    }

    /// Preserves the original fixed consuming classification.
    pub fn into_legacy(self) -> NormalRootStartupErrorV1 {
        match self {
            Self::Profile(error) => error,
            Self::Io(_) | Self::Descriptor(_) | Self::Image(_) => NormalRootStartupErrorV1::Image,
        }
    }
}

/// Measures a fixed pin through the shared immutable DATA engine.
///
/// # Errors
/// Rejects unsafe original flags, immutable name or bytes, or differing bounded content.
pub fn retain_pin(
    pin: &ImagePinV1,
    original: Option<File>,
    executable: bool,
) -> Result<RetainedImmutableFileV1, NormalRootStartupErrorV1> {
    let path = PathBuf::from(&pin.path);
    match original {
        Some(file) => {
            require_original_pin_flags(&file).map_err(ImageObservationErrorV1::into_legacy)?;
            RetainedImmutableFileV1::retain_with_profile(
                path,
                file,
                Some(pin.sha256),
                MAXIMUM_IMAGE_BYTES,
                executable,
            )
        }
        None => RetainedImmutableFileV1::open_with_profile(
            path,
            Some(pin.sha256),
            MAXIMUM_IMAGE_BYTES,
            executable,
        ),
    }
    .map_err(|_| NormalRootStartupErrorV1::Image)
}

fn require_original_pin_flags(file: &File) -> Result<(), ImageObservationErrorV1> {
    require_readonly_launch_flags(rustix::fs::fcntl_getfl(file)?)?;
    Ok(())
}

// The caller parks its genuine original before entering this same flag/pin
// engine. No selected pathname can substitute for the inherited descriptor.
/// Measures the already-parked original against the fixed pin.
///
/// # Errors
/// Rejects unsafe originals, names, metadata or differing bounded content.
pub fn park_original_pin(
    pin: &ImagePinV1,
    executable: bool,
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = PathBuf::from(&pin.path);
    require_original_pin_flags(pending.original()?)?;
    pending.measure_original(path, Some(pin.sha256), MAXIMUM_IMAGE_BYTES, executable)?;
    Ok(())
}

/// Measures and reads the actual original selected profile file.
///
/// # Errors
/// Rejects unsafe flags or names, changed immutable bytes, or bounded read refusal.
pub fn retain_profile(
    file: File,
) -> Result<(RetainedImmutableFileV1, Vec<u8>), NormalRootStartupErrorV1> {
    let path = controller_profile_path(&file).map_err(ImageObservationErrorV1::into_legacy)?;
    let retained = RetainedImmutableFileV1::retain_with_profile(
        path,
        file,
        None,
        MAXIMUM_PROFILE_BYTES as u64,
        false,
    )
    .map_err(|_| NormalRootStartupErrorV1::Image)?;
    let bytes = retained
        .read_bounded()
        .map_err(|_| NormalRootStartupErrorV1::Image)?;
    Ok((retained, bytes))
}

fn original_profile_path(file: &File, role: Option<NixProfileFileRoleV1>) -> Result<PathBuf, ImageObservationErrorV1> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    require_readonly_launch_flags(flags)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    super::schema::require_store_path(path.to_str().ok_or(NormalRootStartupErrorV1::Profile)?)?;
    let valid = match role {
        None => {
            let path = path.to_string_lossy();
            path.ends_with("-aos-normal-root-startup-profile-2/profile.json")
                || path.ends_with("-aos-normal-root-startup-profile-3/profile.json")
        }
        Some(role) => {
            let basename = if role == NixProfileFileRoleV1::Controller {
                "controller.json"
            } else {
                "owner.json"
            };
            path.to_string_lossy().ends_with(&format!("-aos-nix-startup-profile-2/{basename}"))
        }
    };
    if !valid {
        return Err(NormalRootStartupErrorV1::Profile.into());
    }
    Ok(path)
}

fn controller_profile_path(file: &File) -> Result<PathBuf, ImageObservationErrorV1> {
    original_profile_path(file, None)
}

/// Describes the existing immutable Nix delivery file role as comparison DATA.
#[doc(hidden)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum NixProfileFileRoleV1 {
    /// The original Controller-side Nix delivery.
    Controller,
    /// The original hardware-owner Nix delivery.
    Owner,
}

/// Observes the existing fixed Nix profile pathname and readonly flags.
///
/// # Errors
/// Rejects native inspection failure, unsafe flags or a foreign immutable path.
#[doc(hidden)]
pub fn nix_profile_path(
    file: &File,
    role: NixProfileFileRoleV1,
) -> Result<PathBuf, ImageObservationErrorV1> {
    original_profile_path(file, Some(role))
}

/// Measures and reads the existing original Nix Controller profile.
///
/// # Errors
/// Preserves the fixed path, original measurement or bounded read refusal.
pub fn retain_nix_controller_profile(
    file: File,
) -> Result<RetainedImmutableFileV1, NormalRootStartupErrorV1> {
    let path = nix_profile_path(&file, NixProfileFileRoleV1::Controller)
        .map_err(ImageObservationErrorV1::into_legacy)?;
    let retained = RetainedImmutableFileV1::retain_with_profile(path, file, None, 1_048_576, false)
        .map_err(|_| NormalRootStartupErrorV1::Image)?;
    let _bytes = retained.read_bounded().map_err(|_| NormalRootStartupErrorV1::Image)?;
    Ok(retained)
}

/// Parks the same original Nix profile measurement and bounded bytes.
///
/// # Errors
/// Preserves the reached original, path, measurement or bounded read failure.
pub fn park_nix_controller_profile(
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = nix_profile_path(pending.original()?, NixProfileFileRoleV1::Controller)?;
    pending.measure_original(path, None, 1_048_576, false)?;
    pending.read_bounded()?;
    Ok(())
}

/// Retains the existing original Controller profile measurement and bytes.
///
/// # Errors
/// Rejects unsafe original delivery, names, metadata or bounded content.
pub fn park_controller_profile(
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = controller_profile_path(pending.original()?)?;
    pending.measure_original(
        path,
        None,
        MAXIMUM_PROFILE_BYTES as u64,
        false,
    )?;
    pending.read_bounded()?;
    Ok(())
}

/// Retains one selected pin through the same bounded measurement recipe.
///
/// # Errors
/// Rejects unsafe names, metadata, missing native files or differing content.
pub fn park_selected_pin(
    pin: &ImagePinV1,
    executable: bool,
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = PathBuf::from(&pin.path);
    pending.open_and_measure(path, Some(pin.sha256), MAXIMUM_IMAGE_BYTES, executable)?;
    Ok(())
}

/// Measures the selected pin through the same retaining acquisition engine.
///
/// The actual purpose owns this destination before native entry. A supplied
/// image pin remains comparison DATA and grants no file, profile or role.
///
/// # Errors
/// Preserves unsafe names, metadata, native IO and bounded content refusals.
pub fn park_selected_pin_retaining_v1(
    pin: &ImagePinV1,
    executable: bool,
    original: &mut crate::immutable_image::ImmutableFileAcquisitionOriginalV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = PathBuf::from(&pin.path);
    original.open_and_measure_once(path, Some(pin.sha256), MAXIMUM_IMAGE_BYTES, executable)?;
    Ok(())
}

/// Compares the actual bounded self executable map with retained pins.
///
/// # Errors
/// Rejects unavailable or excessive maps, foreign executable mappings or missing required pins.
pub fn require_actual_mappings(
    files: &[RetainedImmutableFileV1],
    required: &[&str],
) -> Result<(), NormalRootStartupErrorV1> {
    let mut original = super::shared_read::BoundedFileReadOriginalV1::new();
    require_actual_mappings_recipe(files, required, &mut original, false)
}

pub(crate) fn require_actual_mappings_retaining_v1(
    files: &[RetainedImmutableFileV1],
    required: &[&str],
    original: &mut super::shared_read::BoundedFileReadOriginalV1,
) -> Result<(), NormalRootStartupErrorV1> {
    require_actual_mappings_recipe(files, required, original, true)
}

fn require_actual_mappings_recipe(
    files: &[RetainedImmutableFileV1],
    required: &[&str],
    original: &mut super::shared_read::BoundedFileReadOriginalV1,
    retained: bool,
) -> Result<(), NormalRootStartupErrorV1> {
    original.read_once("/proc/self/maps", MAXIMUM_MAPS_BYTES, true, retained)
        .map_err(|_| NormalRootStartupErrorV1::Image)?;
    if original.text.len() as u64 > MAXIMUM_MAPS_BYTES {
        return Err(NormalRootStartupErrorV1::Image);
    }
    require_executable_mapping_data_v2(files, required, &original.text)
}

/// Compares bounded executable maps DATA through the existing closure engine.
///
/// This neither opens a process nor authenticates the source of these bytes.
/// A selected caller must retain its genuine subject, original maps descriptor
/// and immutable image pins, with the same owner checks around acquisition.
///
/// # Errors
/// Rejects oversized, malformed or foreign executable mappings and missing
/// required executable/loader members, exactly as the ordinary self reader.
pub fn require_executable_mapping_data_v2(
    files: &[RetainedImmutableFileV1],
    required: &[&str],
    maps: &str,
) -> Result<(), NormalRootStartupErrorV1> {
    if maps.len() as u64 > MAXIMUM_MAPS_BYTES {
        return Err(NormalRootStartupErrorV1::Image);
    }
    let identities = files
        .iter()
        .map(|file| file.physical_identity())
        .collect::<Vec<_>>();
    let mut present = vec![false; files.len()];
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let _address = fields.next();
        let permissions = fields.next().ok_or(NormalRootStartupErrorV1::Image)?;
        if !permissions.contains('x') {
            continue;
        }
        let _offset = fields.next();
        let device = fields.next().ok_or(NormalRootStartupErrorV1::Image)?;
        let inode = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(NormalRootStartupErrorV1::Image)?;
        let path = fields.next().ok_or(NormalRootStartupErrorV1::Image)?;
        if fields.next().is_some() {
            return Err(NormalRootStartupErrorV1::Image);
        }
        if matches!(path, "[vdso]" | "[vsyscall]") && inode == 0 {
            continue;
        }
        let member = files
            .iter()
            .zip(&identities)
            .position(|(file, identity)| {
                device
                    == format!(
                        "{:02x}:{:02x}",
                        rustix::fs::major(identity.0),
                        rustix::fs::minor(identity.0)
                    )
                    && inode == identity.1
                    && file.path().to_str() == Some(path)
            })
            .ok_or(NormalRootStartupErrorV1::Image)?;
        present[member] = true;
    }
    if required.iter().any(|path| {
        !files
            .iter()
            .zip(&present)
            .any(|(file, present)| *present && file.path().to_str() == Some(*path))
    }) {
        return Err(NormalRootStartupErrorV1::Image);
    }
    Ok(())
}

/// Compares the actual retained Root fragment with the original profile hash.
///
/// This reads only the retained immutable fragment through its existing engine.
/// The resulting comparison grants no Root readiness or writer authority.
///
/// # Errors
/// Refuses changed or unreadable bytes, invalid normalization or a different hash.
pub fn require_unit(
    fragment: &RetainedImmutableFileV1,
    profile_file: &RetainedImmutableFileV1,
    profile: &NormalRootProfileV1,
) -> Result<(), NormalRootStartupErrorV1> {
    require_unit_recipe(fragment, profile_file, profile, None)
}

pub(crate) fn require_unit_retaining_v1(
    fragment: &RetainedImmutableFileV1,
    profile_file: &RetainedImmutableFileV1,
    profile: &NormalRootProfileV1,
    original: &mut crate::immutable_image::ImmutableReadOriginalV1,
) -> Result<(), NormalRootStartupErrorV1> {
    require_unit_recipe(fragment, profile_file, profile, Some(original))
}

fn require_unit_recipe(
    fragment: &RetainedImmutableFileV1,
    profile_file: &RetainedImmutableFileV1,
    profile: &NormalRootProfileV1,
    original: Option<&mut crate::immutable_image::ImmutableReadOriginalV1>,
) -> Result<(), NormalRootStartupErrorV1> {
    let normalized = {
        let local;
        let bytes = match original {
            Some(original) => fragment.read_bounded_retaining_v1(original)
                .map_err(|_| NormalRootStartupErrorV1::Service)?,
            None => {
                local = fragment.read_bounded().map_err(|_| NormalRootStartupErrorV1::Service)?;
                &local
            }
        };
        super::schema::normalized_unit(
            bytes,
            profile_file.path().to_str().ok_or(NormalRootStartupErrorV1::Profile)?,
        )
    }?;
    if <[u8; 32]>::from(Sha256::digest(normalized)) != profile.unit_sha256 {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}

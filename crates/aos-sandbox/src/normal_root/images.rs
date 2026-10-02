//! Shared original-descriptor and self-process image observations, never authority.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;

use crate::immutable_image::{
    ImmutableImageErrorV1, PendingImmutableFileV1, RetainedImmutableFileV1,
    require_readonly_launch_flags,
};

use super::{
    NormalRootStartupErrorV1,
    profile::{ImagePinV1, MAXIMUM_PROFILE_BYTES},
};

const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_MAPS_BYTES: u64 = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub(super) enum ImageObservationErrorV1 {
    #[error("selected profile shape differs")]
    Profile(#[from] NormalRootStartupErrorV1),
    #[error("selected original file observation failed")]
    Io(#[from] std::io::Error),
    #[error("selected original descriptor inspection failed")]
    Descriptor(#[from] rustix::io::Errno),
    #[error("selected immutable measurement differs")]
    Image(#[from] ImmutableImageErrorV1),
}

impl ImageObservationErrorV1 {
    pub(super) fn legacy_error(&self) -> NormalRootStartupErrorV1 {
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

    pub(super) fn into_legacy(self) -> NormalRootStartupErrorV1 {
        match self {
            Self::Profile(error) => error,
            Self::Io(_) | Self::Descriptor(_) | Self::Image(_) => NormalRootStartupErrorV1::Image,
        }
    }
}

pub(super) fn retain_pin(
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
pub(super) fn park_original_pin(
    pin: &ImagePinV1,
    executable: bool,
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = PathBuf::from(&pin.path);
    require_original_pin_flags(pending.original()?)?;
    pending.measure_original(path, Some(pin.sha256), MAXIMUM_IMAGE_BYTES, executable)?;
    Ok(())
}

pub(super) fn retain_profile(
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

fn controller_profile_path(file: &File) -> Result<PathBuf, ImageObservationErrorV1> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    require_readonly_launch_flags(flags)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(ImageObservationErrorV1::Io)?;
    super::profile::require_store_path(path.to_str().ok_or(NormalRootStartupErrorV1::Profile)?)?;
    if !path
        .to_string_lossy()
        .ends_with("-aos-normal-root-startup-profile-1/profile.json")
    {
        return Err(NormalRootStartupErrorV1::Profile.into());
    }
    Ok(path)
}

pub(super) fn park_controller_profile(
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

pub(super) fn park_selected_pin(
    pin: &ImagePinV1,
    executable: bool,
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ImageObservationErrorV1> {
    let path = PathBuf::from(&pin.path);
    pending.open_and_measure(path, Some(pin.sha256), MAXIMUM_IMAGE_BYTES, executable)?;
    Ok(())
}

pub(crate) fn require_actual_mappings(
    files: &[RetainedImmutableFileV1],
    required: &[&str],
) -> Result<(), NormalRootStartupErrorV1> {
    let mut maps = String::new();
    File::open("/proc/self/maps")
        .map_err(|_| NormalRootStartupErrorV1::Image)?
        .take(MAXIMUM_MAPS_BYTES + 1)
        .read_to_string(&mut maps)
        .map_err(|_| NormalRootStartupErrorV1::Image)?;
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

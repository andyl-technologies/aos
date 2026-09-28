//! Original descriptor and self-process image observations, never peer authority.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;

use crate::immutable_image::{RetainedImmutableFileV1, require_readonly_launch_flags};

use super::{
    NormalRootStartupErrorV1,
    profile::{ImagePinV1, MAXIMUM_PROFILE_BYTES},
};

const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_MAPS_BYTES: u64 = 256 * 1024;

pub(super) fn retain_pin(
    pin: &ImagePinV1,
    original: Option<File>,
    executable: bool,
) -> Result<RetainedImmutableFileV1, NormalRootStartupErrorV1> {
    let path = PathBuf::from(&pin.path);
    match original {
        Some(file) => {
            require_readonly_launch_flags(
                rustix::fs::fcntl_getfl(&file).map_err(|_| NormalRootStartupErrorV1::Image)?,
            )
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
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

pub(super) fn retain_profile(
    file: File,
) -> Result<(RetainedImmutableFileV1, Vec<u8>), NormalRootStartupErrorV1> {
    require_readonly_launch_flags(
        rustix::fs::fcntl_getfl(&file).map_err(|_| NormalRootStartupErrorV1::Image)?,
    )
    .map_err(|_| NormalRootStartupErrorV1::Image)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| NormalRootStartupErrorV1::Image)?;
    super::profile::require_store_path(path.to_str().ok_or(NormalRootStartupErrorV1::Profile)?)?;
    if !path
        .to_string_lossy()
        .ends_with("-aos-normal-root-startup-profile-1/profile.json")
    {
        return Err(NormalRootStartupErrorV1::Profile);
    }
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

pub(super) fn require_actual_mappings(
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

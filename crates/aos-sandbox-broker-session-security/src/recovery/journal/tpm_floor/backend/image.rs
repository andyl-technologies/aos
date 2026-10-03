//! Measures the fixed helper ELF and loader under immutable lower-store custody.
//!
//! The source-built package records hashes after explicit stripping. The parent
//! retains both files and checks the actually executed inode and loader mapping
//! before releasing index auth to the private child. Subsequent checks retain
//! the same read-only names, contents and process instance; the helper never
//! execs or forks after this observation.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

#[cfg(test)]
use rustix::fs::OFlags;

use super::super::FloorErrorV1;

const MAXIMUM_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
pub(super) use crate::immutable_image::RetainedImmutableFileV1 as MeasuredFileV1;
#[cfg(test)]
use crate::immutable_image::require_readonly_launch_flags;

const MAXIMUM_MAPS_BYTES: u64 = 64 * 1024;

// Only these image-built purposes can enter the shared measurement engine.
enum HelperImagePurposeV1 {
    Broker,
    RuntimeDeployment,
}

impl HelperImagePurposeV1 {
    fn compiled_path(&self) -> Result<&'static str, FloorErrorV1> {
        match self {
            Self::Broker => option_env!("AOS_METHOD46_TPM_HELPER"),
            Self::RuntimeDeployment => option_env!("AOS_RUNTIME_DEPLOYMENT_TPM_HELPER"),
        }
        .ok_or(FloorErrorV1::Unavailable)
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
        }
    }
}

pub(crate) struct MeasuredHelperImageV1 {
    executable: MeasuredFileV1,
    loader: MeasuredFileV1,
}

impl MeasuredHelperImageV1 {
    pub(crate) fn open() -> Result<Self, FloorErrorV1> {
        Self::open_purpose(HelperImagePurposeV1::Broker)
    }

    /// Retains the compiled Host helper and loader through the same image engine.
    ///
    /// # Errors
    /// Rejects missing compiled pins or unsafe, malformed or changed images.
    pub(crate) fn open_runtime_deployment() -> Result<Self, FloorErrorV1> {
        Self::open_purpose(HelperImagePurposeV1::RuntimeDeployment)
    }

    fn open_purpose(purpose: HelperImagePurposeV1) -> Result<Self, FloorErrorV1> {
        let path = PathBuf::from(purpose.compiled_path()?);
        let (basename, executable_pin_name, loader_pin_name) = purpose.names();
        let relative = path
            .strip_prefix("/nix/store")
            .map_err(|_| FloorErrorV1::Provisioning)?;
        if relative.components().count() != 3
            || relative
                .components()
                .nth(1)
                .is_none_or(|part| part.as_os_str() != "libexec")
            || path
                .file_name()
                .is_none_or(|name| name != basename)
        {
            return Err(FloorErrorV1::Provisioning);
        }
        let directory = path.parent().ok_or(FloorErrorV1::Provisioning)?;
        let executable_pin = read_pin(directory, executable_pin_name, 65, 65)?;
        let executable_digest = decode_hash(&executable_pin)?;
        let loader_pin = read_pin(directory, loader_pin_name, 79, 578)?;
        let mut lines = loader_pin.split_inclusive(|byte| *byte == b'\n');
        let loader_path = lines.next().ok_or(FloorErrorV1::Provisioning)?;
        let loader_digest = decode_hash(lines.next().ok_or(FloorErrorV1::Provisioning)?)?;
        if lines.next().is_some() || loader_path.last() != Some(&b'\n') || loader_path.len() > 513 {
            return Err(FloorErrorV1::Provisioning);
        }
        let loader_path = PathBuf::from(
            std::str::from_utf8(&loader_path[..loader_path.len() - 1])
                .map_err(|_| FloorErrorV1::Provisioning)?,
        );
        let mut image = Self {
            executable: MeasuredFileV1::open(path, executable_digest)?,
            loader: MeasuredFileV1::open(loader_path, loader_digest)?,
        };
        image.revalidate()?;
        Ok(image)
    }

    pub(crate) fn path(&self) -> &Path {
        self.executable.path()
    }

    pub(crate) fn require_executed(&self, pid: u32) -> Result<(), FloorErrorV1> {
        self.executable.require_executed(pid)?;
        let mut maps = String::new();
        File::open(format!("/proc/{pid}/maps"))
            .map_err(|_| FloorErrorV1::Unavailable)?
            .take(MAXIMUM_MAPS_BYTES + 1)
            .read_to_string(&mut maps)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        if maps.len() as u64 > MAXIMUM_MAPS_BYTES {
            return Err(FloorErrorV1::Provisioning);
        }
        let mapped = self.loader.mapped_in_helper_data_v5(&maps)?;
        if !mapped {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.executable.revalidate()?;
        self.loader.revalidate().map_err(Into::into)
    }
}

/// Retains the original PID 1 launch file against the existing backend image pin.
pub(super) fn open_original_pid1_image(
    launch_image: &crate::production_startup::Pid1LaunchImageV1,
) -> Result<MeasuredFileV1, FloorErrorV1> {
    let original = launch_image.file().map_err(|_| FloorErrorV1::Provisioning)?;
    aos_sandbox::immutable_image::retain_original_backend_pid1_v1(original)
        .map_err(Into::into)
}

impl From<crate::immutable_image::ImmutableImageErrorV1> for FloorErrorV1 {
    fn from(error: crate::immutable_image::ImmutableImageErrorV1) -> Self {
        match error {
            crate::immutable_image::ImmutableImageErrorV1::Unavailable => Self::Unavailable,
            crate::immutable_image::ImmutableImageErrorV1::Provisioning => Self::Provisioning,
        }
    }
}

fn read_pin(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, FloorErrorV1> {
    aos_sandbox::immutable_image::read_immutable_image_pin_v1(directory, name, minimum, maximum)
        .map_err(Into::into)
}

fn decode_hash(bytes: &[u8]) -> Result<[u8; 32], FloorErrorV1> {
    aos_sandbox::immutable_image::decode_immutable_sha256_pin_v1(bytes).map_err(Into::into)
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

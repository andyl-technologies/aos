//! Exact early-boot configuration preparation commands.
//!
//! This binary owns the small amount of orchestration around the AOS package
//! runtime and image-selected filesystem tools. Their immutable paths are
//! compiled into this artifact, so one authenticated artifact reference binds
//! the complete command implementation and dependency closure.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PACKAGE_RUNTIME: &str = env!("AOS_PACKAGE_RUNTIME");
const MKFS_EROFS: &str = env!("AOS_MKFS_EROFS");
const FSCK_EROFS: &str = env!("AOS_FSCK_EROFS");
const MOUNT: &str = env!("AOS_MOUNT");
const SYSROOT: &str = "/sysroot";
const PROFILE_ENV: &str = "/run/aos-profile-gen.env";

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-boot-preparations: {error}");
        std::process::exit(1);
    }
}

type Result<T> = std::result::Result<T, PreparationError>;

#[derive(Debug)]
struct PreparationError(String);

impl PreparationError {
    fn message(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn io(action: &str, error: std::io::Error) -> Self {
        Self(format!("{action}: {error}"))
    }
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PreparationError {}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command] if command == "seed-configuration" => {
            seed_configuration(Path::new(SYSROOT), Path::new(PROFILE_ENV))
        }
        _ => Err(PreparationError::message(
            "usage: aos-boot-preparations seed-configuration",
        )),
    }
}

fn seed_configuration(root: &Path, profile_environment: &Path) -> Result<()> {
    let generation_number = read_profile_generation(profile_environment)?;
    let generation = root
        .join("var/lib/profiles/system")
        .join(format!("gen-{generation_number}"));
    let manifest = generation.join("manifest.json");
    let lower = PathBuf::from(format!("/run/etc/config-{generation_number}/etc"));
    fs::create_dir_all(&lower)
        .map_err(|error| PreparationError::io("creating configuration lower mountpoint", error))?;
    if !is_nonempty_regular_file(&manifest)? {
        return Ok(());
    }

    let generation_text = generation
        .to_str()
        .ok_or_else(|| PreparationError::message("configuration generation path is not UTF-8"))?;
    let manifest_text = manifest
        .to_str()
        .ok_or_else(|| PreparationError::message("configuration manifest path is not UTF-8"))?;
    run_exact(
        PACKAGE_RUNTIME,
        &[
            "__materialize",
            "--manifest",
            manifest_text,
            "--generation-dir",
            generation_text,
            "--mkfs-erofs",
            MKFS_EROFS,
            "--fsck-erofs",
            FSCK_EROFS,
        ],
        &[],
    )
    .map_err(|error| {
        PreparationError::message(format!(
            "materializing the retained configuration lower: {error}"
        ))
    })?;
    let image = generation.join("config-lower/etc.erofs");
    let image_text = image
        .to_str()
        .ok_or_else(|| PreparationError::message("configuration lower image path is not UTF-8"))?;
    let lower_text = lower
        .to_str()
        .ok_or_else(|| PreparationError::message("configuration lower mountpoint is not UTF-8"))?;
    run_exact(
        MOUNT,
        &[
            "-t",
            "erofs",
            "-o",
            "ro,nodev,nosuid",
            image_text,
            lower_text,
        ],
        &[],
    )
    .map_err(|error| {
        PreparationError::message(format!(
            "mounting the retained configuration lower: {error}"
        ))
    })
}

fn read_profile_generation(path: &Path) -> Result<u32> {
    let text = fs::read_to_string(path)
        .map_err(|error| PreparationError::io("reading profile generation environment", error))?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or_else(|| PreparationError::message("profile generation environment is empty"))?;
    if lines.next().is_some() {
        return Err(PreparationError::message(
            "profile generation environment contains extra lines",
        ));
    }
    let value = line.strip_prefix("AOS_PROFILE_GEN=").ok_or_else(|| {
        PreparationError::message("profile generation environment has an unexpected key")
    })?;
    let generation = value.parse::<u32>().map_err(|error| {
        PreparationError::message(format!("profile generation is not a u32: {error}"))
    })?;
    if generation == 0 {
        return Err(PreparationError::message(
            "profile generation must be positive",
        ));
    }
    Ok(generation)
}

fn is_nonempty_regular_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && metadata.len() > 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PreparationError::io(
            "inspecting configuration manifest",
            error,
        )),
    }
}

fn run_exact(
    executable: &str,
    arguments: &[&str],
    environment: &[(&str, &std::ffi::OsStr)],
) -> Result<()> {
    let status = Command::new(executable)
        .args(arguments)
        .env_clear()
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| {
            PreparationError::io(&format!("starting exact command {executable}"), error)
        })?;
    if !status.success() {
        return Err(PreparationError::message(format!(
            "exact command {executable} failed with {status}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_generation_requires_one_exact_assignment() {
        let directory =
            std::env::temp_dir().join(format!("aos-boot-preparations-test-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let path = directory.join("profile.env");
        fs::write(&path, "AOS_PROFILE_GEN=17\n").expect("write environment");
        assert_eq!(read_profile_generation(&path).expect("generation"), 17);

        fs::write(&path, "AOS_PROFILE_GEN=17\nEXTRA=1\n").expect("write invalid environment");
        assert!(read_profile_generation(&path).is_err());
        fs::remove_dir_all(&directory).expect("remove temporary directory");
    }
}

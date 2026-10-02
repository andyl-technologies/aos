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
use std::path::Path;
use std::process::{Command, Stdio};

const PACKAGE_RUNTIME: &str = env!("AOS_PACKAGE_RUNTIME");
const BOOT_CONFIGURATION: &str = env!("AOS_BOOT_CONFIGURATION");
const CONFIGURATION_BOOT: &str = env!("AOS_CONFIGURATION_BOOT");
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
        [
            operation,
            input_flag,
            bundle,
            state_flag,
            state_directory,
            store_flag,
            nix_store,
        ] if matches!(
            operation.as_str(),
            "apply-deployment" | "verify-deployment" | "handoff-initrd-store"
        ) && input_flag == "--input"
            && state_flag == "--state-directory"
            && store_flag == "--nix-store" =>
        {
            run_deployment(operation, Path::new(bundle), state_directory, nix_store)
        }
        _ => Err(PreparationError::message(
            "usage: aos-boot-preparations seed-configuration | \
             <apply-deployment|verify-deployment|handoff-initrd-store> --input BUNDLE \
             --state-directory STATE --nix-store EXECUTABLE",
        )),
    }
}

/// Dispatches a native package transaction rooted in the verified boot image.
///
/// The fixed image locations are populated before boot and remain on the
/// authenticated immutable image. The caller must already have established the
/// image's integrity, mounted the stage journal, and initialized and registered
/// the local store. This command does not establish those prerequisites.
fn run_deployment(
    operation: &str,
    bundle: &Path,
    state_directory: &str,
    nix_store: &str,
) -> Result<()> {
    if !matches!(
        bundle.to_str(),
        Some(
            "/lib/aos/initrd/deployment"
                | "/usr/lib/aos/initrd/deployment"
                | "/usr/lib/aos/host/deployment"
        )
    ) {
        return Err(PreparationError::message(
            "deployment bundle is outside the fixed verified image locations",
        ));
    }
    // The verified image retains the original immutable bundle and its member
    // aliases. Resolve this member only to its canonical store identity.
    let digest_path = fs::canonicalize(bundle.join("admission-sha256"))
        .map_err(|error| PreparationError::io("resolving image admission digest", error))?;
    if !digest_path.starts_with("/nix/store") {
        return Err(PreparationError::message(
            "image admission digest is outside the immutable store",
        ));
    }
    let metadata = fs::symlink_metadata(&digest_path)
        .map_err(|error| PreparationError::io("inspecting image admission digest", error))?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err(PreparationError::message(
            "image admission digest is not a bounded regular file",
        ));
    }
    let digest = fs::read_to_string(&digest_path)
        .map_err(|error| PreparationError::io("reading image admission digest", error))?;
    let digest = digest.trim_end_matches('\n');
    validate_admission_digest(digest)?;

    let bundle_text = bundle
        .to_str()
        .ok_or_else(|| PreparationError::message("bundle path is not UTF-8"))?;
    let admission = bundle.join("admission.json");
    let admission_text = admission
        .to_str()
        .ok_or_else(|| PreparationError::message("admission path is not UTF-8"))?;
    let mut arguments = vec![
        operation,
        "--input",
        bundle_text,
        "--state-directory",
        state_directory,
        "--nix-store",
        nix_store,
        "--admission",
        admission_text,
        "--admission-sha256",
        digest,
    ];
    if bundle_text == "/usr/lib/aos/host/deployment" {
        if state_directory != "/var/lib/profiles/system/deployment" {
            return Err(PreparationError::message(
                "host deployment state must belong to the system profile",
            ));
        }
        arguments.extend(["--profile", "/var/lib/profiles/system"]);
    }
    if operation == "handoff-initrd-store" {
        if bundle_text != "/lib/aos/initrd/deployment" {
            return Err(PreparationError::message(
                "receipt handoff requires the source initrd bundle",
            ));
        }
        run_exact(BOOT_CONFIGURATION, &arguments, &[])
    } else if bundle_text == "/usr/lib/aos/host/deployment" && operation == "apply-deployment" {
        run_exact(BOOT_CONFIGURATION, &arguments[1..], &[])
    } else {
        run_exact(PACKAGE_RUNTIME, &arguments, &[])
    }
}

fn validate_admission_digest(digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(PreparationError::message(
            "image admission digest has an unsupported algorithm",
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PreparationError::message(
            "image admission digest is not canonical SHA-256",
        ));
    }
    Ok(())
}

fn seed_configuration(root: &Path, profile_environment: &Path) -> Result<()> {
    let generation = read_profile_generation(profile_environment)?;
    let lower = format!("/run/etc/config-{generation}/etc");
    let root_text = root
        .to_str()
        .ok_or_else(|| PreparationError::message("sysroot is not UTF-8"))?;
    run_exact(
        CONFIGURATION_BOOT,
        &[root_text, &generation.to_string(), &lower],
        &[],
    )
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
    Ok(generation)
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
    fn deployment_rejects_mutable_or_unrecognized_bundle_locations() {
        for path in [
            "/tmp/deployment",
            "/var/lib/profiles/deployment",
            "/usr/lib/aos/../deployment",
        ] {
            assert!(
                run_deployment(
                    "apply-deployment",
                    Path::new(path),
                    "/run/journal",
                    "/nix/store/tool/bin/nix-store"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn admission_digest_accepts_only_canonical_sha256() {
        assert!(validate_admission_digest(&format!("sha256:{}", "a".repeat(64))).is_ok());
        for digest in [
            "",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:abc",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha512:abc",
        ] {
            assert!(validate_admission_digest(digest).is_err());
        }
    }

    #[test]
    fn profile_generation_requires_one_exact_assignment() {
        let directory =
            std::env::temp_dir().join(format!("aos-boot-preparations-test-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let path = directory.join("profile.env");
        fs::write(&path, "AOS_PROFILE_GEN=17\n").expect("write environment");
        assert_eq!(read_profile_generation(&path).expect("generation"), 17);
        fs::write(&path, "AOS_PROFILE_GEN=0\n").expect("write bootstrap environment");
        assert_eq!(
            read_profile_generation(&path).expect("bootstrap generation"),
            0
        );

        fs::write(&path, "AOS_PROFILE_GEN=17\nEXTRA=1\n").expect("write invalid environment");
        assert!(read_profile_generation(&path).is_err());
        fs::remove_dir_all(&directory).expect("remove temporary directory");
    }
}

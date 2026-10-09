//! Source-built closed gem5 policy and independently measured launch artifacts.
//!
//! Only the manifest compiled into the production suite selects policy. Runtime
//! environment variables, scenario labels and operator-provided hashes cannot
//! install a different guest or qualify native execution. Development builds
//! without that installed package explicitly refuse this profile.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    rc::Rc,
};

use crucible_node_contract::{ContentRef, U64, canonical};
use crucible_node_provider::{
    ProviderError,
    gem5::{Gem5ExactProfileVerifier, Gem5Launch, Gem5LaunchArtifact, Gem5OpaqueProfileVerifier},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{NodeObservedError, refused};

mod schema;

use schema::Manifest;

#[cfg(test)]
mod tests;

const SCHEMA: &str = "crucible.gem5.installed-closed-profile.v1";
const POLICY: &str = "freestanding-o3-classic-ddr3-v1";
const MAPPING: &str = "gem5/even-reaction-odd-publication-v1";
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Authenticates the fixed source-built gem5 package and its known guest programs.
///
/// The package's native closure witnesses qualify only this no-ingress O3
/// profile. They do not promote modeled diagnostic coverage, full-system device
/// parity, arbitrary guest binaries, or another source implementation.
pub struct InstalledGem5ClosedProfile {
    manifest: Manifest,
    identity: ContentRef,
    document: Vec<u8>,
    artifacts: BTreeMap<String, Gem5LaunchArtifact>,
    guests: BTreeMap<String, Gem5LaunchArtifact>,
}

impl InstalledGem5ClosedProfile {
    /// Loads and measures the independently installed compile-time package.
    ///
    /// # Errors
    /// Refuses an absent production package, invalid metadata, missing native
    /// witness scope, changed artifact bytes, or unsupported model/clock policy.
    pub fn built_in() -> Result<Rc<Self>, NodeObservedError> {
        let path = option_env!("CRUCIBLE_GEM5_CLOSED_PROFILE_MANIFEST")
            .ok_or_else(|| refused("source-built gem5 closed-profile package is not installed"))?;
        if !std::path::Path::new(path).starts_with("/nix/store") {
            return Err(refused(
                "gem5 policy is not the compiled source-built package",
            ));
        }
        let mut file = File::open(path).map_err(io_error)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let value = canonical::parse_json(&bytes, MAX_MANIFEST_BYTES)?;
        let manifest: Manifest = serde_json::from_value(value)?;
        manifest.validate()?;
        manifest.measure_provenance(
            std::path::Path::new(path)
                .parent()
                .ok_or_else(|| refused("compiled gem5 package root is absent"))?,
        )?;

        let artifacts = manifest
            .artifacts
            .iter()
            .map(|(name, artifact)| Ok((name.clone(), artifact.measure()?)))
            .collect::<Result<_, NodeObservedError>>()?;
        let guests = manifest
            .guests
            .iter()
            .map(|(isa, guest)| Ok((isa.clone(), guest.artifact.measure()?)))
            .collect::<Result<_, NodeObservedError>>()?;
        let identity = canonical::content_ref(&bytes, "application/json")?;
        Ok(Rc::new(Self {
            manifest,
            identity,
            document: bytes,
            artifacts,
            guests,
        }))
    }

    /// Returns the exact installed policy document identity.
    pub fn identity(&self) -> &ContentRef {
        &self.identity
    }

    /// Borrows the complete original installed policy bytes and their identity.
    ///
    /// These immutable bytes preserve provenance; they grant no live native
    /// execution, preparation or restore authority.
    pub fn document(&self) -> (&ContentRef, &[u8]) {
        (&self.identity, &self.document)
    }

    /// Returns the independently measured named source-owned launch artifact.
    ///
    /// # Errors
    /// Refuses any name outside the fixed installed artifact roster.
    pub fn artifact(&self, name: &str) -> Result<Gem5LaunchArtifact, NodeObservedError> {
        self.artifacts
            .get(name)
            .cloned()
            .ok_or_else(|| refused("unknown installed gem5 launch artifact"))
    }

    /// Returns the fixed known guest executable for an approved ISA.
    ///
    /// # Errors
    /// Refuses unknown ISAs rather than accepting caller-supplied guest code.
    pub fn guest(&self, isa: &str) -> Result<Gem5LaunchArtifact, NodeObservedError> {
        self.guests
            .get(isa)
            .cloned()
            .ok_or_else(|| refused("unknown installed gem5 guest ISA"))
    }

    /// Returns the finite source-qualified same-time closure budget.
    pub fn maximum_microsteps(&self) -> U64 {
        self.manifest.clock.maximum_microsteps
    }

    fn match_artifact(
        &self,
        name: &str,
        actual: &Gem5LaunchArtifact,
        managed_copy: Option<(&Path, &str)>,
    ) -> Result<(), ProviderError> {
        let expected = self.artifacts.get(name).ok_or(ProviderError::Correlation(
            "installed gem5 launch artifact is absent",
        ))?;
        if expected.content != actual.content {
            return Err(ProviderError::Correlation(
                "gem5 launch differs from installed policy",
            ));
        }
        let spec = self
            .manifest
            .artifacts
            .get(name)
            .ok_or(ProviderError::Correlation(
                "installed gem5 artifact measurement is absent",
            ))?;
        if spec.measure().map_err(policy_error)?.content != expected.content {
            return Err(ProviderError::Correlation(
                "installed gem5 launch artifact changed",
            ));
        }
        if actual.path != expected.path {
            let (root, filename) = managed_copy.ok_or(ProviderError::Correlation(
                "gem5 launch path differs from installed policy",
            ))?;
            require_managed_copy(root, filename, &actual.path)?;
            if spec
                .measure_bytes(&actual.path)
                .map_err(policy_error)?
                .content
                != expected.content
            {
                return Err(ProviderError::Correlation(
                    "gem5 managed copy differs from installed bytes",
                ));
            }
        }
        Ok(())
    }
}

impl Gem5OpaqueProfileVerifier for InstalledGem5ClosedProfile {
    fn verify_opaque_profile(
        &self,
        launch: &Gem5Launch,
        auditor: &Gem5LaunchArtifact,
    ) -> Result<(), ProviderError> {
        self.match_artifact("native_executable", &launch.executable, None)?;
        self.match_artifact(
            "controller",
            &launch.owner_script,
            Some((&launch.resource_root, "native-owner.py")),
        )?;
        self.match_artifact(
            "model",
            &launch.model_script,
            Some((&launch.resource_root, "native-owner-model.py")),
        )?;
        self.match_artifact("auditor", auditor, None)?;
        let expected_guest =
            self.guests
                .get(&launch.guest_isa)
                .ok_or(ProviderError::Correlation(
                    "gem5 guest ISA is not source-qualified",
                ))?;
        if expected_guest.content != launch.guest.content {
            return Err(ProviderError::Correlation(
                "gem5 guest is not the fixed qualified executable",
            ));
        }
        let guest =
            self.manifest
                .guests
                .get(&launch.guest_isa)
                .ok_or(ProviderError::Correlation(
                    "source-qualified gem5 guest measurement is absent",
                ))?;
        if guest.artifact.measure().map_err(policy_error)?.content != expected_guest.content {
            return Err(ProviderError::Correlation("installed gem5 guest changed"));
        }
        if launch.guest.path != expected_guest.path {
            require_managed_copy(&launch.resource_root, "guest.elf", &launch.guest.path)?;
            if guest
                .artifact
                .measure_bytes(&launch.guest.path)
                .map_err(policy_error)?
                .content
                != expected_guest.content
            {
                return Err(ProviderError::Correlation(
                    "gem5 managed guest differs from installed bytes",
                ));
            }
        }
        let tools = launch
            .process_images
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "gem5 closed profile requires complete native image custody",
            ))?;
        self.match_artifact("dmtcp_launch", &tools.launcher, None)?;
        self.match_artifact("dmtcp_restart", &tools.restarter, None)?;
        self.match_artifact("mtcp_restart", &tools.reconstruction_executable, None)?;
        self.match_artifact("image_guard", &tools.resource_helper, None)
    }
}

impl Gem5ExactProfileVerifier for InstalledGem5ClosedProfile {
    fn verify_superdense_mapping(
        &self,
        launch: &Gem5Launch,
        maximum_microsteps: U64,
    ) -> Result<(), ProviderError> {
        let auditor = self
            .artifacts
            .get("auditor")
            .ok_or(ProviderError::Correlation(
                "installed gem5 auditor artifact is absent",
            ))?;
        self.verify_opaque_profile(launch, auditor)?;
        if maximum_microsteps != self.maximum_microsteps() {
            return Err(ProviderError::Correlation(
                "gem5 same-time cap differs from installed qualification",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    sha256: String,
    length: U64,
}

impl Artifact {
    fn measure(&self) -> Result<Gem5LaunchArtifact, NodeObservedError> {
        if !self.path.is_absolute()
            || !self.path.starts_with("/nix/store")
            || self.path.components().any(|component| {
                !matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || self.length.get() == 0
            || self.length.get() > MAX_ARTIFACT_BYTES
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refused("invalid source-built gem5 artifact identity"));
        }
        self.measure_bytes(&self.path)
    }

    fn measure_bytes(&self, path: &Path) -> Result<Gem5LaunchArtifact, NodeObservedError> {
        let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
        if !metadata.is_file() || metadata.len() != self.length.get() {
            return Err(refused("installed gem5 artifact is not a regular file"));
        }
        let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
            .map_err(|_| refused("native nofollow open flag is unrepresentable"))?;
        let mut file = File::options()
            .read(true)
            .custom_flags(nofollow)
            .open(path)
            .map_err(io_error)?;
        let mut digest = Sha256::new();
        let mut content = blake3::Hasher::new();
        content.update(b"CNP/1\0");
        content.update(&("cnp.blob.v1".len() as u32).to_be_bytes());
        content.update(b"cnp.blob.v1");
        content.update(&self.length.get().to_be_bytes());
        let mut total = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|length| *length <= self.length.get())
                .ok_or_else(|| {
                    refused("installed gem5 artifact exceeds its exact measured length")
                })?;
            digest.update(&buffer[..count]);
            content.update(&buffer[..count]);
        }
        if total != self.length.get() || format!("{:x}", digest.finalize()) != self.sha256 {
            return Err(refused(
                "installed gem5 artifact differs from source-built qualification",
            ));
        }
        Ok(Gem5LaunchArtifact {
            path: path.to_owned(),
            content: ContentRef {
                hash: crucible_node_contract::HashRef {
                    algorithm: "blake3-256".into(),
                    domain: "cnp.blob.v1".into(),
                    digest: content.finalize().to_hex().to_string(),
                },
                length: self.length,
                media_type: "application/octet-stream".into(),
            },
        })
    }
}

fn require_managed_copy(root: &Path, filename: &str, path: &Path) -> Result<(), ProviderError> {
    let root_metadata = std::fs::symlink_metadata(root)?;
    let file_metadata = std::fs::symlink_metadata(path)?;
    let owner = rustix::process::getuid().as_raw();
    if path != root.join(filename)
        || !root_metadata.is_dir()
        || root_metadata.mode() & 0o077 != 0
        || root_metadata.uid() != owner
        || std::fs::canonicalize(root)? != root
        || !file_metadata.is_file()
        || file_metadata.nlink() != 1
        || file_metadata.mode() & 0o077 != 0
        || file_metadata.uid() != owner
    {
        return Err(ProviderError::Correlation(
            "gem5 copied artifact is not in its exact private managed route",
        ));
    }
    Ok(())
}

fn policy_error(error: NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}

fn io_error(error: std::io::Error) -> NodeObservedError {
    NodeObservedError::Native(format!("source-built gem5 profile read refused: {error}"))
}

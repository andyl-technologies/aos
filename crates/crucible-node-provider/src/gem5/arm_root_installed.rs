//! Independently checks a compile-time installed ARM mechanism bundle.
//!
//! A mechanism bundle is not execution authority. This checker never accepts an
//! operator manifest path or expected-hash table, and its private result cannot
//! create a live opaque certificate. Model-aware native peer/capture supervision
//! and a genuine common-node continuation witness remain separate prerequisites.

use crate::ProviderError;
use crucible_node_contract::{U64, canonical};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const MAX_ARTIFACT: u64 = 2 * 1024 * 1024 * 1024;
const ROLES: &[&str] = &[
    "board_model",
    "model_check",
    "native_executable",
    "controller",
    "entrypoint",
    "model",
    "publication_model",
    "asset_checker",
    "auditor",
    "auditor_core",
    "image_guard",
    "dmtcp_launch",
    "dmtcp_restart",
    "mtcp_restart",
    "python",
    "kernel",
    "initramfs",
    "firmware",
    "source_manifest",
    "source_recipe",
    "witness",
    "image_witness",
    "image_custody_check",
    "asset_check",
    "auditor_check",
    "native_source_manifest",
    "mechanism_evidence",
    "profile_writer",
    "profile_recipe",
    "terminal_runtime_manifest",
    "terminal_inventory_patch",
    "terminal_runtime_recipe",
    "terminal_inventory_witness",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    length: U64,
    sha256: String,
}

/// Retains measured installed mechanism data without public admission authority.
#[derive(Clone)]
pub struct InstalledArmRootMechanism {
    document: Value,
}

impl InstalledArmRootMechanism {
    /// Checks the source-owned compile-time installed mechanism and all artifacts.
    ///
    /// Runtime environment variables and imported archive metadata cannot select
    /// this trust entry point. All admission flags must remain false in this stage.
    ///
    /// # Errors
    /// Refuses absent build-time binding, nonimmutable resources, changed bodies,
    /// unsupported model/dialect/clock metadata or any capability overclaim.
    pub fn load() -> Result<Self, ProviderError> {
        let path = option_env!("CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST").ok_or(
            ProviderError::Frame("no installed ARM model mechanism binding"),
        )?;
        let mut file = immutable_file(Path::new(path), MAX_MANIFEST)?;
        let before = fingerprint(&file.metadata()?);
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut bytes)?;
        if fingerprint(&file.metadata()?) != before || bytes.len() as u64 != before.2 {
            return Err(ProviderError::Correlation(
                "installed ARM manifest changed during read",
            ));
        }
        let document = canonical::parse_json(&bytes, MAX_MANIFEST as usize)?;
        validate_scope(&document)?;
        let artifacts: BTreeMap<String, Artifact> =
            serde_json::from_value(document["artifacts"].clone()).map_err(|_| {
                ProviderError::Frame("invalid closed installed ARM artifact roster")
            })?;
        if artifacts.len() != ROLES.len() || ROLES.iter().any(|role| !artifacts.contains_key(*role))
        {
            return Err(ProviderError::Frame("installed ARM artifact roles differ"));
        }
        for artifact in artifacts.values() {
            remeasure(artifact)?;
        }
        Ok(Self { document })
    }

    /// Returns inert fixed-model metadata after source-installed byte verification.
    pub fn document(&self) -> &Value {
        &self.document
    }

    pub(crate) fn artifact(&self, role: &str) -> Result<super::Gem5LaunchArtifact, ProviderError> {
        if !ROLES.contains(&role) {
            return Err(ProviderError::Frame(
                "unknown installed ARM root artifact role",
            ));
        }
        let artifact: Artifact =
            serde_json::from_value(self.document["artifacts"][role].clone())
                .map_err(|_| ProviderError::Frame("installed ARM root role shape"))?;
        remeasure(&artifact)?;
        let content = super::images::measure_image_file(&artifact.path)?;
        if content.length != artifact.length {
            return Err(ProviderError::Correlation(
                "installed ARM root role extent changed",
            ));
        }
        Ok(super::Gem5LaunchArtifact {
            path: artifact.path,
            content,
        })
    }

    pub(crate) fn manifest_content(
        &self,
    ) -> Result<crucible_node_contract::ContentRef, ProviderError> {
        let path = option_env!("CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST")
            .ok_or(ProviderError::Frame("no installed ARM root model binding"))?;
        super::images::measure_file(Path::new(path))
    }

    /// Returns an independently remeasured source-owned artifact binding.
    ///
    /// This value identifies installed bytes only. It carries no live process,
    /// execution certificate or native preparation authority.
    ///
    /// # Errors
    /// Refuses unknown roles, changed installed bytes or extents, unavailable
    /// source artifacts and measurement errors.
    pub fn artifact_binding(&self, role: &str) -> Result<super::Gem5LaunchArtifact, ProviderError> {
        self.artifact(role)
    }

    /// Returns the complete original installed manifest's measured binding.
    ///
    /// The binding supplies immutable selection data, never execution or
    /// readiness authority for a process.
    ///
    /// # Errors
    /// Refuses an absent source-installed manifest or failed byte measurement.
    pub fn manifest_binding(&self) -> Result<crucible_node_contract::ContentRef, ProviderError> {
        self.manifest_content()
    }

    /// Refuses execution admission until actual common-node qualification exists.
    ///
    /// # Errors
    /// Always refuses in this mechanism-only edition; a complete image-byte
    /// witness cannot substitute for live peer, continuation or device authority.
    pub fn require_execution_admission(&self) -> Result<(), ProviderError> {
        Err(ProviderError::Frame(
            "ARM common-node admission is not yet qualified",
        ))
    }
}

fn immutable_file(path: &Path, maximum: u64) -> Result<File, ProviderError> {
    if !path.starts_with("/nix/store") || path.canonicalize()? != path {
        return Err(ProviderError::Frame(
            "ARM installed artifact lacks canonical immutable custody",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o222 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(ProviderError::Frame(
            "ARM installed artifact exceeds immutable finite custody",
        ));
    }
    Ok(file)
}

fn fingerprint(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u64, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
        metadata.mode(),
    )
}

fn remeasure(artifact: &Artifact) -> Result<(), ProviderError> {
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderError::Frame(
            "ARM installed artifact digest is not canonical",
        ));
    }
    let mut file = immutable_file(&artifact.path, MAX_ARTIFACT)?;
    let before = fingerprint(&file.metadata()?);
    if before.2 != artifact.length.get() {
        return Err(ProviderError::Correlation(
            "ARM installed artifact extent differs",
        ));
    }
    let mut hash = Sha256::new();
    let mut remaining = before.2;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ProviderError::Frame("ARM artifact extent cannot be represented"))?;
        let count = file.read(&mut buffer[..limit])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "ARM installed artifact shrank during read",
            ));
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if file.read(&mut buffer[..1])? != 0
        || fingerprint(&file.metadata()?) != before
        || format!("{:x}", hash.finalize()) != artifact.sha256
    {
        return Err(ProviderError::Correlation(
            "ARM installed artifact bytes differ",
        ));
    }
    Ok(())
}

pub(super) fn validate_scope(document: &Value) -> Result<(), ProviderError> {
    if document["schema"] != "crucible.gem5.installed-arm-root-profile-mechanism.v1"
        || document["policy_id"] != "arm-linux-vexpress-atomic-root-functional-v1"
        || document["native_dialect"] != "crucible.gem5.arm-linux-native/1"
        || document["host_abi"]
            != serde_json::json!({"os":"linux","architecture":"x86_64",
            "endian":"little","pointer_bits":"64","page_bytes":"4096","image_format":"dmtcp-4.2.0/mtcp"})
        || document["clock"]
            != serde_json::json!({"native_tick_ps":"1",
            "mapping_id":"gem5/even-reaction-odd-publication-v1", "maximum_microsteps":"1000000",
            "cpu_clock_hz":"100000000"})
        || document["qualification"]
            != serde_json::json!({"opaque_capture_mechanism_verified":true,
            "execution_admission_qualified":false,"full_system_admission_qualified":false,
            "device_parity_qualified":false,"guest_readiness_qualified":false,"cpu_timing_qualified":false})
    {
        return Err(ProviderError::Frame(
            "ARM installed model scope or qualification differs",
        ));
    }
    let model = &document["model"];
    if model["board"] != "VExpress_GEM5_V2"
        || model["guest_isa"] != "aarch64"
        || model["cpu"] != "ArmAtomicSimpleCPU"
        || model["width"] != "16"
        || model["memory_bytes"] != "268435456"
        || model["memory"] != "SimpleMemory"
        || model["exposed_facets"]
            != serde_json::json!([{"kind":"serial",
            "terminal":"system.terminal","direction":"output","causal_parent":"0"}])
    {
        return Err(ProviderError::Frame(
            "ARM installed source-owned realization differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- invalid test fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- fixture construction and counterexample assertions are test-only.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn installed_loading_requires_the_actual_compile_time_binding() {
        let result = InstalledArmRootMechanism::load();
        match option_env!("CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST") {
            None => assert!(matches!(
                result,
                Err(ProviderError::Frame(
                    "no installed ARM model mechanism binding"
                ))
            )),
            Some(_) => {
                let installed = result.unwrap();
                validate_scope(installed.document()).unwrap();
                assert!(installed.require_execution_admission().is_err());
            }
        }
    }

    #[test]
    fn previous_model_or_nonroot_facet_never_falls_back() {
        // This inert schema fixture supplies no installed paths or live authority.
        // Its negative cases must run even in the lightweight reference package.
        let document: Value =
            serde_json::from_str(include_str!("arm-root-scope-fixture.json")).unwrap();
        validate_scope(&document).unwrap();

        let mut previous = document.clone();
        previous["policy_id"] = "arm-linux-vexpress-atomic-functional-v1".into();
        assert!(validate_scope(&previous).is_err());
        let mut forged = document.clone();
        forged["model"]["exposed_facets"][0]["causal_parent"] = "17".into();
        assert!(validate_scope(&forged).is_err());
        let mut promoted = document.clone();
        promoted["qualification"]["execution_admission_qualified"] = true.into();
        assert!(validate_scope(&promoted).is_err());
    }
}

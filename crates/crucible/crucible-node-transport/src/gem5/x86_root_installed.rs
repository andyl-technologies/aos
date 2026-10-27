//! Independently checks a compile-time installed x86 mechanism bundle.
//!
//! A mechanism bundle is not execution authority. This checker never accepts an
//! operator manifest path or expected-hash table, and its private result cannot
//! create a live opaque certificate. Model-aware native peer/capture supervision
//! and a genuine common-node continuation witness remain separate prerequisites.

use crate::ProviderError;
use crucible_node_format::{U64, canonical};
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
    "native_executable",
    "controller",
    "entrypoint",
    "model",
    "board_model",
    "publication_model",
    "asset_checker",
    "loader",
    "auditor",
    "auditor_core",
    "python",
    "kernel",
    "initramfs",
    "image_guard",
    "dmtcp_launch",
    "dmtcp_restart",
    "mtcp_restart",
    "assets_manifest",
    "assets_verifier",
    "profile_writer",
    "profile_recipe",
    "native_source_manifest",
    "root_model_check",
    "mechanism_evidence",
    "witness",
    "image_witness",
    "proof_recipe",
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
pub struct InstalledX86RootModel {
    document: Value,
}

impl InstalledX86RootModel {
    /// Returns the exact source-owned installed artifact-role roster.
    ///
    /// This immutable DATA view supplies no artifact bytes or live authority.
    /// Owning constructors and retained-file census checks use this same roster.
    pub const fn artifact_roles() -> &'static [&'static str] {
        ROLES
    }

    /// Checks the source-owned compile-time installed mechanism and all artifacts.
    ///
    /// Runtime environment variables and imported archive metadata cannot select
    /// this trust entry point. The source-built opaque capture mechanism gate
    /// must have passed; execution/device/readiness/timing flags remain false.
    /// Each owning process still requires its own current audit.
    ///
    /// # Errors
    /// Refuses absent build-time binding, nonimmutable resources, changed bodies,
    /// unsupported model/dialect/clock metadata or any capability overclaim.
    pub fn load() -> Result<Self, ProviderError> {
        let path = option_env!("CRUCIBLE_GEM5_X86_ROOT_MODEL_MANIFEST").ok_or(
            ProviderError::Frame("no installed x86 model mechanism binding"),
        )?;
        let mut file = immutable_file(Path::new(path), MAX_MANIFEST)?;
        let before = fingerprint(&file.metadata()?);
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut bytes)?;
        if fingerprint(&file.metadata()?) != before || bytes.len() as u64 != before.2 {
            return Err(ProviderError::Correlation(
                "installed x86 manifest changed during read",
            ));
        }
        let document = canonical::parse_json(&bytes, MAX_MANIFEST as usize)?;
        validate_scope(&document)?;
        let artifacts: BTreeMap<String, Artifact> =
            serde_json::from_value(document["artifacts"].clone()).map_err(|_| {
                ProviderError::Frame("invalid closed installed x86 artifact roster")
            })?;
        if artifacts.len() != ROLES.len() || ROLES.iter().any(|role| !artifacts.contains_key(*role))
        {
            return Err(ProviderError::Frame("installed x86 artifact roles differ"));
        }
        for artifact in artifacts.values() {
            remeasure(artifact)?;
        }
        validate_qualification_sources(&document, &artifacts)?;
        Ok(Self { document })
    }

    /// Returns inert fixed-model metadata after source-installed byte verification.
    pub fn document(&self) -> &Value {
        &self.document
    }

    pub(crate) fn artifact(&self, role: &str) -> Result<super::Gem5LaunchArtifact, ProviderError> {
        if !ROLES.contains(&role) {
            return Err(ProviderError::Frame(
                "unknown installed x86 root artifact role",
            ));
        }
        let artifact: Artifact =
            serde_json::from_value(self.document["artifacts"][role].clone())
                .map_err(|_| ProviderError::Frame("installed x86 root role shape"))?;
        remeasure(&artifact)?;
        let content = super::images::measure_image_file(&artifact.path)?;
        if content.length != artifact.length {
            return Err(ProviderError::Correlation(
                "installed x86 root role extent changed",
            ));
        }
        Ok(super::Gem5LaunchArtifact {
            path: artifact.path,
            content,
        })
    }

    pub(crate) fn manifest_content(
        &self,
    ) -> Result<crucible_node_format::ContentRef, ProviderError> {
        let path = option_env!("CRUCIBLE_GEM5_X86_ROOT_MODEL_MANIFEST")
            .ok_or(ProviderError::Frame("no installed x86 root model binding"))?;
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
    pub fn manifest_binding(&self) -> Result<crucible_node_format::ContentRef, ProviderError> {
        self.manifest_content()
    }

    /// Refuses treating installed mechanism metadata as execution admission.
    ///
    /// # Errors
    /// Always refuses. The installed factory must separately authenticate its
    /// original peer, current opaque certificate and common preparation. A
    /// process-image witness cannot substitute for those owning authorities.
    pub fn require_execution_admission(&self) -> Result<(), ProviderError> {
        Err(ProviderError::Frame(
            "x86 common-node admission is not yet qualified",
        ))
    }
}

fn immutable_file(path: &Path, maximum: u64) -> Result<File, ProviderError> {
    if !path.starts_with("/nix/store") || path.canonicalize()? != path {
        return Err(ProviderError::Frame(
            "x86 installed artifact lacks canonical immutable custody",
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
            "x86 installed artifact exceeds immutable finite custody",
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
            "x86 installed artifact digest is not canonical",
        ));
    }
    let mut file = immutable_file(&artifact.path, MAX_ARTIFACT)?;
    let before = fingerprint(&file.metadata()?);
    if before.2 != artifact.length.get() {
        return Err(ProviderError::Correlation(
            "x86 installed artifact extent differs",
        ));
    }
    let mut hash = Sha256::new();
    let mut remaining = before.2;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ProviderError::Frame("x86 artifact extent cannot be represented"))?;
        let count = file.read(&mut buffer[..limit])?;
        if count == 0 {
            return Err(ProviderError::Correlation(
                "x86 installed artifact shrank during read",
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
            "x86 installed artifact bytes differ",
        ));
    }
    Ok(())
}

fn validate_qualification_sources(
    document: &Value,
    artifacts: &BTreeMap<String, Artifact>,
) -> Result<(), ProviderError> {
    let Some(raw) = document.get("qualification_inputs") else {
        return Ok(());
    };
    let inputs: BTreeMap<String, Artifact> = serde_json::from_value(raw.clone())
        .map_err(|_| ProviderError::Frame("invalid Root qualification input records"))?;
    // validate_scope already checked the closed v2 namespace. Each independent
    // source file is still remeasured; no test file is staged into the guest.
    for artifact in inputs.values() {
        remeasure(artifact)?;
    }
    let source = inputs
        .get("source_manifest")
        .ok_or(ProviderError::Frame("Root qualification receipt absent"))?;
    let check = inputs
        .get("temporary_root_check")
        .ok_or(ProviderError::Frame("Root qualification test absent"))?;
    let controller = artifacts
        .get("controller")
        .ok_or(ProviderError::Frame("Root native controller absent"))?;
    let value = super::installed_qualification::read_source_document(
        immutable_file(&source.path, MAX_MANIFEST)?,
        MAX_MANIFEST as usize,
    )?;
    super::installed_qualification::validate_source_document(
        &value,
        &controller.sha256,
        &check.sha256,
    )
}

pub(super) fn validate_scope(document: &Value) -> Result<(), ProviderError> {
    super::installed_qualification::validate_profile_version(
        document,
        "crucible.gem5.installed-x86-root-profile-mechanism.v1",
        "crucible.gem5.installed-x86-root-profile-mechanism.v2",
    )?;
    if document["policy_id"] != "x86-linux-pc-atomic-root-functional-v1"
        || document["native_dialect"] != "crucible.gem5.x86-linux-native/1"
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
            "x86 installed model scope or qualification differs",
        ));
    }
    super::x86_root_model::validate_loader_data(&document["model"]["loader_geometry"])?;
    let model = &document["model"];
    if model["board"] != "PC"
        || model["guest_isa"] != "x86_64"
        || model["cpu"] != "X86AtomicSimpleCPU"
        || model["width"] != "16"
        || model["memory_bytes"] != "268435456"
        || model["memory"] != "SimpleMemory"
        || model["exposed_facets"]
            != serde_json::json!([{"kind":"serial",
            "terminal":"system.pc.com_1.device","direction":"output","causal_parent":"0"}])
    {
        return Err(ProviderError::Frame(
            "x86 installed source-owned realization differs",
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
        let result = InstalledX86RootModel::load();
        match option_env!("CRUCIBLE_GEM5_X86_ROOT_MODEL_MANIFEST") {
            None => assert!(matches!(
                result,
                Err(ProviderError::Frame(
                    "no installed x86 model mechanism binding"
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
            serde_json::from_str(include_str!("x86-root-scope-fixture.json")).unwrap();
        validate_scope(&document).unwrap();

        let mut previous = document.clone();
        previous["policy_id"] = "x86-linux-pc-atomic-functional-v1".into();
        assert!(validate_scope(&previous).is_err());
        let mut forged = document.clone();
        forged["model"]["exposed_facets"][0]["causal_parent"] = "17".into();
        assert!(validate_scope(&forged).is_err());
        let mut promoted = document.clone();
        promoted["qualification"]["execution_admission_qualified"] = true.into();
        assert!(validate_scope(&promoted).is_err());
    }

    #[test]
    fn current_profile_requires_separate_qualification_inputs() {
        let mut document: Value =
            serde_json::from_str(include_str!("x86-root-scope-fixture.json")).unwrap();
        document["schema"] = "crucible.gem5.installed-x86-root-profile-mechanism.v2".into();
        assert!(validate_scope(&document).is_err());
        document["qualification_inputs"] = serde_json::json!({
            "source_manifest":{"path":"/nix/store/inert-receipt","length":"1","sha256":"a".repeat(64)},
            "temporary_root_check":{"path":"/nix/store/inert-check","length":"1","sha256":"b".repeat(64)},
        });
        validate_scope(&document).unwrap();
        document["qualification_inputs"]["unexpected"] = serde_json::json!({});
        assert!(validate_scope(&document).is_err());
        document["schema"] = "crucible.gem5.installed-x86-root-profile-mechanism.v1".into();
        assert!(validate_scope(&document).is_err());
    }
}

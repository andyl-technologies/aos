//! Measures the compile-time installed public reference implementation closure.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use crucible_node_contract::{ContentRef, Id, U64, Validate, canonical};
use crucible_node_provider::reference_service::ReferenceProfile;
use serde::Deserialize;

use super::super::{NodeObservedError, refused};

const MAXIMUM_MANIFEST_BYTES: usize = 1024 * 1024;
const MAXIMUM_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_CLOSURE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    policy_id: String,
    policy_version: u16,
    artifacts: BTreeMap<String, Artifact>,
    source_artifacts: BTreeMap<String, Artifact>,
    limitations: Vec<Limitation>,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    content: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeClosure {
    schema: String,
    roots: BTreeMap<String, Artifact>,
    reference_graph: Artifact,
    store_paths: Vec<PathBuf>,
    objects: Vec<Artifact>,
    build_reference_graph: Artifact,
    build_tools: BTreeMap<String, Artifact>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Limitation {
    ConditionalNativeTiming,
    ExactExecutionUnsupported,
    LimitedStateOnly,
    NativePreservationUnsupported,
    PhysicalPauseUnsupported,
    RepeatabilityUnqualified,
}

/// Retains independently measured implementation identity without qualification.
///
/// The only production constructor reads the package pinned at compilation.
/// Scenario input, runtime environment variables and supplied expected hashes
/// cannot install a different implementation or upgrade its guarantees.
pub struct InstalledPublicReferencePackage {
    manifest: Manifest,
    identity: ContentRef,
    bytes: Vec<u8>,
    runtime: RuntimeClosure,
}

impl InstalledPublicReferencePackage {
    /// Loads the pinned implementation and measures all declared source artifacts.
    ///
    /// # Errors
    /// Refuses missing compile-time installation, unsupported closed metadata,
    /// unrepresentable geometry, nonregular files or changed artifact bytes.
    pub fn built_in() -> Result<Rc<Self>, NodeObservedError> {
        let path = option_env!("CRUCIBLE_REFERENCE_IMPLEMENTATION_MANIFEST").ok_or_else(|| {
            refused("source-built public reference implementation is not installed")
        })?;
        Self::load_installed(Path::new(path)).map(Rc::new)
    }

    fn load_installed(path: &Path) -> Result<Self, NodeObservedError> {
        require_store_path(path)?;
        let mut bytes = Vec::new();
        open_regular(path)?
            .take(MAXIMUM_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
        if bytes.len() > MAXIMUM_MANIFEST_BYTES {
            return Err(refused(
                "public reference implementation manifest byte ceiling",
            ));
        }
        let value = canonical::parse_json(&bytes, MAXIMUM_MANIFEST_BYTES)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused(
                "public reference implementation manifest is not canonical",
            ));
        }
        let manifest: Manifest = serde_json::from_value(value)?;
        manifest.validate()?;
        let mut total = 0u64;
        for artifact in manifest
            .artifacts
            .values()
            .chain(manifest.source_artifacts.values())
        {
            total = total
                .checked_add(artifact.content.length.get())
                .filter(|size| *size <= MAXIMUM_CLOSURE_BYTES)
                .ok_or_else(|| refused("public reference implementation closure byte ceiling"))?;
            artifact.measure()?;
        }
        let closure_artifact = &manifest.source_artifacts["build_closure"];
        if closure_artifact.content.length.get() > 4 * 1024 * 1024 {
            return Err(refused("public reference runtime closure metadata ceiling"));
        }
        let closure_bytes = read_bounded(&closure_artifact.path, 4 * 1024 * 1024)?;
        closure_artifact.content.verify(&closure_bytes)?;
        let closure = canonical::parse_json(&closure_bytes, 4 * 1024 * 1024)?;
        if canonical::canonical_json(&closure)? != closure_bytes {
            return Err(refused("public reference runtime closure is not canonical"));
        }
        let runtime: RuntimeClosure = serde_json::from_value(closure)?;
        runtime.validate(&manifest)?;
        let expected_roots = manifest
            .artifacts
            .values()
            .map(|artifact| super::graphs::store_root(&artifact.path))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let graph_bytes = read_bounded(&runtime.reference_graph.path, 1024 * 1024)?;
        runtime.reference_graph.content.verify(&graph_bytes)?;
        let roots = super::graphs::validate_graph(&graph_bytes, Some(&expected_roots))?;
        if roots != runtime.store_paths.iter().cloned().collect() {
            return Err(refused(
                "installed runtime roster differs from original graph",
            ));
        }
        let build_bytes = read_bounded(&runtime.build_reference_graph.path, 1024 * 1024)?;
        runtime.build_reference_graph.content.verify(&build_bytes)?;
        let build_roster = super::graphs::validate_graph(&build_bytes, None)?;
        for tool in runtime.build_tools.values() {
            if !build_roster.contains(&super::graphs::store_root(&tool.path)?) {
                return Err(refused(
                    "installed build tool is absent from original graph",
                ));
            }
        }
        for artifact in runtime
            .objects
            .iter()
            .chain([&runtime.reference_graph, &runtime.build_reference_graph])
            .chain(runtime.build_tools.values())
        {
            total = total
                .checked_add(artifact.content.length.get())
                .filter(|size| *size <= MAXIMUM_CLOSURE_BYTES)
                .ok_or_else(|| refused("public reference runtime closure byte ceiling"))?;
            artifact.measure()?;
        }
        let identity = canonical::content_ref(&bytes, "application/json")?;
        Ok(Self {
            manifest,
            identity,
            bytes,
            runtime,
        })
    }

    /// Returns the exact source-installed implementation descriptor identity.
    pub fn identity(&self) -> &ContentRef {
        &self.identity
    }

    /// Returns original descriptor bytes without synthesizing a qualification.
    pub fn document(&self) -> &[u8] {
        &self.bytes
    }

    /// Regenerates the known public byte-linked profile from measured artifacts.
    ///
    /// This constructs immutable metadata only. Live enrollment, stopped gate,
    /// native readiness and complete behavioral coverage are not inferred.
    ///
    /// # Errors
    /// Refuses changed installed artifact bytes, unsupported logical window or
    /// physical budget, malformed identifiers or profile construction errors.
    pub fn profile(
        &self,
        node: Id,
        owner: Id,
        quantum_ps: U64,
        host_budget_ns: U64,
        closed_ingress: bool,
    ) -> Result<ReferenceProfile, NodeObservedError> {
        let provider = self.artifact("provider")?;
        let device = self.artifact("device")?;
        provider.measure()?;
        device.measure()?;
        ReferenceProfile::build_public_linked(
            node,
            owner,
            provider.content.clone(),
            device.content.clone(),
            quantum_ps,
            host_budget_ns,
            closed_ingress,
        )
        .map_err(|error| refused_owned(error.to_string()))
    }

    pub(super) fn executable(&self, role: &str) -> Result<&Path, NodeObservedError> {
        let artifact = self.artifact(role)?;
        artifact.measure()?;
        Ok(&artifact.path)
    }

    pub(super) fn artifact_content(&self, role: &str) -> Result<&ContentRef, NodeObservedError> {
        Ok(&self.artifact(role)?.content)
    }

    pub(super) fn authenticate_mapped_elf(
        &self,
        path: &Path,
    ) -> Result<ContentRef, NodeObservedError> {
        let artifact = self
            .runtime
            .objects
            .iter()
            .find(|artifact| artifact.path == path)
            .ok_or_else(|| refused("native public reference maps an uninstalled ELF object"))?;
        artifact.measure()?;
        Ok(artifact.content.clone())
    }

    fn artifact(&self, role: &str) -> Result<&Artifact, NodeObservedError> {
        self.manifest
            .artifacts
            .get(role)
            .ok_or_else(|| refused("unknown installed public reference artifact role"))
    }
}

impl RuntimeClosure {
    fn validate(&self, manifest: &Manifest) -> Result<(), NodeObservedError> {
        if self.schema != "crucible.reference.runtime-closure.v1"
            || self.roots != manifest.artifacts
            || self.store_paths.is_empty()
            || self.store_paths.len() > 512
            || self.objects.is_empty()
            || self.objects.len() > 4096
            || !self.build_tools.keys().map(String::as_str).eq([
                "archive",
                "c_compiler",
                "cargo",
                "compression",
                "copy",
                "rustc",
            ])
            || self.store_paths.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .objects
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(refused(
                "invalid installed public reference runtime closure",
            ));
        }
        for root in &self.store_paths {
            require_store_path(root)?;
            if root.components().count() != 4 {
                return Err(refused(
                    "public reference closure root is not one store object",
                ));
            }
        }
        for artifact in &self.objects {
            require_store_path(&artifact.path)?;
            artifact.content.validate()?;
            if artifact.content.length.get() == 0
                || artifact.content.length.get() > MAXIMUM_ARTIFACT_BYTES
                || artifact.content.hash.domain != "cnp.blob.v1"
                || artifact.content.media_type != "application/octet-stream"
                || !self
                    .store_paths
                    .iter()
                    .any(|root| artifact.path.starts_with(root))
            {
                return Err(refused("invalid installed public reference runtime object"));
            }
        }
        for root in self.roots.values() {
            if !self.objects.iter().any(|object| object == root) {
                return Err(refused(
                    "public reference executable absent from ELF closure",
                ));
            }
        }
        for artifact in std::iter::once(&self.reference_graph)
            .chain(std::iter::once(&self.build_reference_graph))
            .chain(self.build_tools.values())
        {
            require_store_path(&artifact.path)?;
            artifact.content.validate()?;
            if artifact.content.length.get() == 0
                || artifact.content.length.get() > MAXIMUM_ARTIFACT_BYTES
                || artifact.content.hash.domain != "cnp.blob.v1"
            {
                return Err(refused("invalid public reference build provenance object"));
            }
        }
        Ok(())
    }
}

impl Manifest {
    fn validate(&self) -> Result<(), NodeObservedError> {
        if self.schema != "crucible.reference.installed-implementation.v1"
            || self.policy_id != "public-byte-linked-checksum-v1"
            || self.policy_version != 1
            || !self
                .artifacts
                .keys()
                .map(String::as_str)
                .eq(["device", "provider"])
            || !self.source_artifacts.keys().map(String::as_str).eq([
                "build_closure",
                "contract",
                "recipe",
                "source",
            ])
            || self.limitations
                != [
                    Limitation::ConditionalNativeTiming,
                    Limitation::ExactExecutionUnsupported,
                    Limitation::LimitedStateOnly,
                    Limitation::NativePreservationUnsupported,
                    Limitation::PhysicalPauseUnsupported,
                    Limitation::RepeatabilityUnqualified,
                ]
        {
            return Err(refused(
                "unsupported installed public reference implementation scope",
            ));
        }
        for artifact in self
            .artifacts
            .values()
            .chain(self.source_artifacts.values())
        {
            require_store_path(&artifact.path)?;
            artifact.content.validate()?;
            if artifact.content.length.get() == 0
                || artifact.content.length.get() > MAXIMUM_ARTIFACT_BYTES
                || artifact.content.hash.domain != "cnp.blob.v1"
            {
                return Err(refused(
                    "invalid installed public reference artifact geometry",
                ));
            }
        }
        if self
            .artifacts
            .values()
            .any(|artifact| artifact.content.media_type != "application/octet-stream")
        {
            return Err(refused("public reference executable media type differs"));
        }
        Ok(())
    }
}

impl Artifact {
    fn measure(&self) -> Result<(), NodeObservedError> {
        let mut file = open_regular(&self.path)?;
        if file.metadata().map_err(read_error)?.len() != self.content.length.get() {
            return Err(refused(
                "installed public reference artifact length differs",
            ));
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"CNP/1\0");
        let domain_length = u32::try_from(b"cnp.blob.v1".len())
            .map_err(|_| refused("public reference content domain length overflow"))?;
        hash.update(&domain_length.to_be_bytes());
        hash.update(b"cnp.blob.v1");
        hash.update(&self.content.length.get().to_be_bytes());
        let mut buffer = [0; 65_536];
        let mut length = 0u64;
        loop {
            let count = file.read(&mut buffer).map_err(read_error)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .filter(|length| *length <= self.content.length.get())
                .ok_or_else(|| {
                    refused("installed public reference artifact exceeds original length")
                })?;
            hash.update(&buffer[..count]);
        }
        if length != self.content.length.get()
            || hash.finalize().to_hex().as_str() != self.content.hash.digest
        {
            return Err(refused("installed public reference artifact bytes differ"));
        }
        Ok(())
    }
}

fn require_store_path(path: &Path) -> Result<(), NodeObservedError> {
    super::graphs::store_root(path)?;
    if !path.is_absolute()
        || !path.starts_with("/nix/store")
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(refused(
            "public reference implementation artifact is outside installed store",
        ));
    }
    Ok(())
}

fn open_regular(path: &Path) -> Result<File, NodeObservedError> {
    if !std::fs::symlink_metadata(path)
        .map_err(read_error)?
        .is_file()
    {
        return Err(refused(
            "public reference implementation artifact is not regular",
        ));
    }
    let flags = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
        .map_err(|_| refused("installed public reference nofollow flag unavailable"))?;
    File::options()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(read_error)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, NodeObservedError> {
    let mut bytes = Vec::new();
    open_regular(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.len() > maximum {
        return Err(refused("public reference metadata byte ceiling"));
    }
    Ok(bytes)
}

fn read_error(error: std::io::Error) -> NodeObservedError {
    refused_owned(format!("installed public reference read refused: {error}"))
}

fn refused_owned(message: String) -> NodeObservedError {
    NodeObservedError::Native(message)
}

#[cfg(test)]
#[path = "qualification_review_tests.rs"]
mod qualification_review_tests;

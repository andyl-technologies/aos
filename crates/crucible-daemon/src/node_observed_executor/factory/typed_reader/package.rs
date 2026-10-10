//! Measures a separately pinned candidate reader and its complete source closure.
//!
//! This installation retains unqualified package limitations. It does not issue
//! an accepted behavioral class or expose an ordinary runtime selector.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use crucible_node_contract::{ContentRef, Id, U64, Validate, canonical};
use crucible_node_provider::reference_service::{
    ReferenceProfile, profile::InputLineageProfileSelection,
};
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
    limitations: Vec<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub(super) path: PathBuf,
    pub(super) content: ContentRef,
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

/// Retains the separately measured typed reader package without qualification.
///
/// Independently configured host policy supplies the original descriptor.
/// The loader measures that closed package before any Child; the resulting
/// metadata supplies no ordinary class acceptance or capability upgrade.
pub struct InstalledTypedReaderPackage {
    manifest: Manifest,
    identity: ContentRef,
    bytes: Vec<u8>,
    runtime: RuntimeClosure,
    definition: super::definition::InstalledDefinition,
}

impl InstalledTypedReaderPackage {
    /// Measures the exact predeclared candidate package before any child exists.
    ///
    /// # Errors
    /// Refuses a changed original manifest, unsupported closed scope, invalid
    /// geometry, mismatching artifact bytes or unregenerated reader definitions.
    pub fn load(path: &Path, original: &ContentRef) -> Result<Rc<Self>, NodeObservedError> {
        Self::load_installed(path, original).map(Rc::new)
    }

    fn load_installed(path: &Path, original: &ContentRef) -> Result<Self, NodeObservedError> {
        require_store_path(path)?;
        original.validate()?;
        if original.length.get() > MAXIMUM_MANIFEST_BYTES as u64
            || original.hash.domain != "cnp.blob.v1"
            || original.hash.algorithm != "blake3-256"
        {
            return Err(refused(
                "typed reader original manifest credit or role differs",
            ));
        }
        let bytes = read_bounded(path, MAXIMUM_MANIFEST_BYTES)?;
        original.verify(&bytes)?;
        if original.media_type != "application/json" {
            return Err(refused("reader candidate manifest role differs"));
        }
        let value = canonical::parse_json(&bytes, MAXIMUM_MANIFEST_BYTES)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused(
                "public reference implementation manifest is not canonical",
            ));
        }
        super::metadata::keys(&value, "artifacts", &["device", "provider"])?;
        super::metadata::keys(
            &value,
            "source_artifacts",
            &[
                "build_closure",
                "contract",
                "event",
                "handler",
                "input",
                "namespace_publication",
                "reader_definition",
                "recipe",
                "source",
                "stop",
            ],
        )?;
        super::metadata::array(&value, "limitations", 9)?;
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
        super::metadata::keys(&closure, "roots", &["device", "provider"])?;
        super::metadata::keys(
            &closure,
            "build_tools",
            &[
                "archive",
                "c_compiler",
                "cargo",
                "compression",
                "copy",
                "rustc",
            ],
        )?;
        super::metadata::array(&closure, "store_paths", 512)?;
        super::metadata::array(&closure, "objects", 4096)?;
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
        let definition = super::definition::InstalledDefinition::load(
            &manifest.source_artifacts,
            &manifest.artifacts,
            &mut total,
        )?;
        let identity = canonical::content_ref(&bytes, "application/json")?;
        Ok(Self {
            manifest,
            identity,
            bytes,
            runtime,
            definition,
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

    /// Regenerates the distinct typed input-reader profile from measured artifacts.
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
        ReferenceProfile::build_public_negotiated_lineage_reader(
            node,
            owner,
            provider.content.clone(),
            device.content.clone(),
            quantum_ps,
            host_budget_ns,
            InputLineageProfileSelection {
                closed_ingress,
                definition: self.definition.regenerated().clone(),
            },
        )
        .map_err(|error| refused_owned(error.to_string()))
    }

    /// Remeasures and returns one declared executable path.
    ///
    /// # Errors
    /// Refuses an unknown role or changed original executable bytes.
    pub fn executable(&self, role: &str) -> Result<&Path, NodeObservedError> {
        let artifact = self.artifact(role)?;
        artifact.measure()?;
        Ok(&artifact.path)
    }

    /// Borrows one previously authenticated executable identity.
    ///
    /// # Errors
    /// Refuses a role absent from the closed installed executable table.
    pub fn artifact_content(&self, role: &str) -> Result<&ContentRef, NodeObservedError> {
        Ok(&self.artifact(role)?.content)
    }

    /// Borrows the exact regenerated typed extension definition as measured data.
    pub fn definition(&self) -> &crucible_node_provider::reference_lineage::InputLineageDefinition {
        self.definition.regenerated()
    }

    /// Borrows each original definition body without copying it or installing authority.
    pub fn definition_objects(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        self.definition.objects()
    }

    /// Borrows all eight source-authenticated semantic contract identities.
    pub fn semantic_contracts(&self) -> &BTreeMap<String, ContentRef> {
        self.definition.axes()
    }

    /// Iterates the original measured runtime role paths and full content identities.
    pub fn runtime_objects(&self) -> impl Iterator<Item = (&Path, &ContentRef)> {
        self.runtime
            .objects
            .iter()
            .map(|artifact| (artifact.path.as_path(), &artifact.content))
    }

    /// Projects the exact typed peer contract from an independently installed registry.
    ///
    /// Measurement cannot install a handler. The supplied registry must already
    /// authenticate this source declaration, original handler and all eight
    /// source semantic contracts. Durable applications and dynamic inputs still
    /// require their separate installed owning qualification callbacks.
    ///
    /// # Errors
    /// Refuses an uninstalled tuple, changed handler or semantic contract, or
    /// exhausted peer projection credit. No class or runtime authority is issued.
    pub fn peer_policy(
        &self,
        registry: Rc<crucible::node_admission::InstalledExtensionRegistry>,
    ) -> Result<crucible::node_admission::InstalledExtensionPeerPolicy, NodeObservedError> {
        use crucible::node_admission::{
            ExtensionImpact, ExtensionRecordKind, ExtensionSemanticContract,
            InstalledExtensionPeerPolicy,
        };
        use crucible_node_contract::OperatingMode;

        let selection = std::slice::from_ref(self.definition().selection());
        let policy = InstalledExtensionPeerPolicy::new(registry, selection, selection)
            .map_err(|error| refused_owned(error.to_string()))?;
        let (declaration, handler, semantics) = policy
            .contract(self.definition().selection())
            .map_err(|error| refused_owned(error.to_string()))?;
        let axis = |name: &str| {
            self.semantic_contracts()
                .get(name)
                .cloned()
                .ok_or_else(|| refused("typed reader semantic contract missing"))
        };
        let expected = ExtensionSemanticContract {
            class_contract: axis("class")?,
            facet_contract: axis("facet")?,
            mode_contract: axis("mode")?,
            port_contract: axis("port")?,
            timing_contract: axis("timing")?,
            state_contract: axis("state")?,
            error_contract: axis("error")?,
            qualification_contract: axis("qualification")?,
            locations: BTreeSet::from([
                ExtensionRecordKind::FacetSelection,
                ExtensionRecordKind::BindingCompatibility,
            ]),
            roles: BTreeSet::new(),
            facets: BTreeSet::from([Id::new(
                "reference-device/quantized-lineage-reader-typed-v2",
            )?]),
            modes: vec![OperatingMode::Quantized],
            interfaces: BTreeSet::new(),
            impact: ExtensionImpact::Behavior,
        };
        if declaration != self.definition().declaration()
            || handler != self.definition().handler()
            || semantics != &expected
        {
            return Err(refused(
                "installed typed reader peer interpretation differs from source",
            ));
        }
        Ok(policy)
    }

    /// Borrows every original package limitation without issuing acceptance.
    pub fn limitations(&self) -> &[String] {
        &self.manifest.limitations
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
                || artifact.content.hash.algorithm != "blake3-256"
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
                || artifact.content.hash.algorithm != "blake3-256"
            {
                return Err(refused("invalid public reference build provenance object"));
            }
        }
        Ok(())
    }
}

impl Manifest {
    fn validate(&self) -> Result<(), NodeObservedError> {
        if self.schema != "crucible.reference.installed-lineage-reader-implementation.v1"
            || self.policy_id != "public-original-input-lineage-reader-typed-v2"
            || self.policy_version != 1
            || !self
                .artifacts
                .keys()
                .map(String::as_str)
                .eq(["device", "provider"])
            || !self.source_artifacts.keys().map(String::as_str).eq([
                "build_closure",
                "contract",
                "event",
                "handler",
                "input",
                "namespace_publication",
                "reader_definition",
                "recipe",
                "source",
                "stop",
            ])
            || self.limitations
                != [
                    "conditional-native-timing",
                    "exact-execution-unsupported",
                    "limited-state-only",
                    "native-preservation-unsupported",
                    "physical-pause-unsupported",
                    "repeatability-unqualified",
                    "source-class-unqualified",
                    "coordinator-lineage-association-unsupported",
                    "higher-hop-input-adoption-unsupported",
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
                || artifact.content.hash.algorithm != "blake3-256"
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
    /// Streams the exact artifact extent and checks stable file metadata.
    ///
    /// # Errors
    /// Refuses invalid paths, lengths, hashes, file kinds, changing metadata
    /// or unavailable source bytes.
    pub(super) fn measure(&self) -> Result<(), NodeObservedError> {
        require_store_path(&self.path)?;
        self.content.validate()?;
        if self.content.length.get() == 0
            || self.content.length.get() > MAXIMUM_ARTIFACT_BYTES
            || self.content.hash.domain != "cnp.blob.v1"
            || self.content.hash.algorithm != "blake3-256"
        {
            return Err(refused("typed reader artifact credit or hash role differs"));
        }
        let mut file = open_regular(&self.path)?;
        if file.metadata().map_err(read_error)?.len() != self.content.length.get() {
            return Err(refused(
                "installed public reference artifact length differs",
            ));
        }
        let before = file.metadata().map_err(read_error)?;
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
        let after = file.metadata().map_err(read_error)?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) || length != self.content.length.get()
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

/// Reads an original regular store object under an explicit byte ceiling.
///
/// # Errors
/// Refuses unsupported paths/file kinds, unavailable reads or an exceeded extent.
pub(super) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, NodeObservedError> {
    require_store_path(path)?;
    let mut file = open_regular(path)?;
    let before = file.metadata().map_err(read_error)?;
    let length =
        usize::try_from(before.len()).map_err(|_| refused("reader metadata extent overflow"))?;
    if length > maximum {
        return Err(refused("reader metadata byte ceiling"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| refused("reader metadata reservation refused"))?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes).map_err(read_error)?;
    let mut trailing = [0];
    if file.read(&mut trailing).map_err(read_error)? != 0 {
        return Err(refused("reader metadata grew beyond original extent"));
    }
    let after = file.metadata().map_err(read_error)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(refused("reader metadata changed during read"));
    }
    Ok(bytes)
}

fn read_error(error: std::io::Error) -> NodeObservedError {
    refused_owned(format!("installed public reference read refused: {error}"))
}

fn refused_owned(message: String) -> NodeObservedError {
    NodeObservedError::Native(message)
}

//! Verifies the selected source-built installation as DATA before Source birth.
//!
//! Measurements cover the SAME original helper/worker files held by the L2
//! program. Complete no-follow inventory and actual loader edges must agree;
//! neither a manifest field nor content equality creates process authority.
//!
//! The private JSON records below are emitted by the source-built installation
//! measurer. This schematic shows field names and descriptor values; `Artifact`
//! and `ContentRef` stand for the repeated object shapes beneath it.
//!
//! ```text
//! installation.json:
//!   schema: "crucible.pure-worker.installation/1"
//!   profile: "pure-worker-v1"
//!   launcher, worker, runtime_closure: Artifact
//!   read_only_roots: sorted unique absolute store roots (at most 128)
//!   source, vendor, recipe, algorithm, request_codec, result_codec: Artifact
//! Artifact: {"path": "/nix/store/<hash>-<package>/...", "content": ContentRef}
//! ContentRef:
//!   hash: {"algorithm": "blake3-256", "domain": "cnp.blob.v1",
//!          "digest": "<64 lowercase hexadecimal characters>"}
//!   length: "123"                 # decimal JSON string, not a JSON number
//!   media_type: "application/octet-stream"
//! algorithm.json:
//!   schema: "crucible.pure-worker.algorithm/1"
//!   id: "crucible.source-birth.derivation/1"
//!   source, vendor, recipe: ContentRef
//! request-codec.json / result-codec.json:
//!   schema: "crucible.pure-worker.codec/1"
//!   id: "crucible.source-birth.request/1" / "crucible.source-birth.result/1"
//!   magic: "CSBIN001" / "CSBR0001"
//!   version: 1
//!   header_bytes: 160 / 240
//!   source: ContentRef
//! runtime-closure.json:
//!   schema: "crucible.pure-worker.runtime-closure/1"
//!   reference_graph: Artifact
//!   store_paths: sorted unique absolute store roots
//!   objects: regular ELF Artifacts
//!   entries: {kind: "directory", path, mode}, {kind: "file", path, mode,
//!             content: ContentRef}, or {kind: "symlink", path, target}
//! ```
//!
//! The supported deployment trusts its source-built immutable Nix installation
//! and excludes an administrator mutating it through another mount. Actual
//! readonly mounts, original executable leases and loader policy are checked;
//! this owner grants no Source job or accepted-result authority.

use super::request_wire::ExportWorkspace;
use crate::node_contract::RuntimeError;
use crucible_host_resources::{
    LinuxProcessSupervisor, LinuxPureWorkerAttempt, LinuxPureWorkerConfiguration,
    LinuxPureWorkerError, LinuxPureWorkerFactory, LinuxPureWorkerLimits, LinuxPureWorkerProgram,
};
use crucible_node_format::{ContentRef, HashRef};
use serde::Deserialize;
use std::rc::Rc;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

#[path = "installation/loader.rs"]
mod loader;

const MAXIMUM_METADATA_BYTES: usize = 1024 * 1024;
const MAXIMUM_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_MEASURED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 65_536;
const MAXIMUM_OBJECTS: usize = 4096;
const MAXIMUM_ROOTS: usize = 128;

type Failure = RuntimeError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    content: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    schema: String,
    profile: String,
    launcher: Artifact,
    worker: Artifact,
    runtime_closure: Artifact,
    read_only_roots: Vec<PathBuf>,
    source: Artifact,
    vendor: Artifact,
    recipe: Artifact,
    algorithm: Artifact,
    request_codec: Artifact,
    result_codec: Artifact,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Algorithm {
    schema: String,
    id: String,
    source: ContentRef,
    vendor: ContentRef,
    recipe: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Codec {
    schema: String,
    id: String,
    magic: String,
    version: u32,
    header_bytes: usize,
    source: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeClosure {
    schema: String,
    reference_graph: Artifact,
    store_paths: Vec<PathBuf>,
    objects: Vec<Artifact>,
    entries: Vec<TreeEntry>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TreeEntry {
    Directory {
        path: PathBuf,
        mode: u32,
    },
    File {
        path: PathBuf,
        mode: u32,
        content: ContentRef,
    },
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
}

impl TreeEntry {
    fn path(&self) -> &Path {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } | Self::Symlink { path, .. } => {
                path
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceGraph {
    schema: String,
    roots: Vec<PathBuf>,
    #[serde(rename = "subtractRoots")]
    subtract_roots: Vec<PathBuf>,
    paths: Vec<GraphPath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphPath {
    path: PathBuf,
    #[serde(rename = "narHash")]
    _nar_hash: String,
    #[serde(rename = "narSize")]
    _nar_size: u64,
    references: Vec<PathBuf>,
}

/// Records exact measured artifact commitments without granting Source authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceBirthInstallationBindings {
    /// Commits the exact compiled installation manifest bytes.
    pub installation: [u8; 32],
    /// Commits the same original opened source-built launcher.
    pub launcher: [u8; 32],
    /// Commits the same original opened source-built worker.
    pub worker: [u8; 32],
    /// Commits the complete measured immutable runtime inventory.
    pub runtime: [u8; 32],
    /// Commits the algorithm/source/vendor/recipe descriptor.
    pub algorithm: [u8; 32],
    /// Commits the closed request-codec descriptor.
    pub request_codec: [u8; 32],
    /// Commits the closed result-codec descriptor.
    pub result_codec: [u8; 32],
}

enum ProcessEnforcement {
    CreatorThread(Rc<LinuxProcessSupervisor>),
    Deployment(crucible_host_resources::DeploymentResourceLease),
}

impl ProcessEnforcement {
    fn authenticate_current(
        &self,
    ) -> Result<(), crucible_host_resources::LinuxProcessSupervisorError> {
        match self {
            Self::CreatorThread(original) => original.authenticate_current(),
            Self::Deployment(original) => original.authenticate_current(),
        }
    }
}

/// Preserves a verifier failure with a fixed installation-stage diagnostic.
///
/// The stage is selected by the verifier, never by installation contents. Its
/// label can be copied into a test observation without exposing artifact paths,
/// decoded metadata or dynamic error text. It grants no installation authority.
#[derive(Debug, thiserror::Error)]
#[error("{stage}: {cause}")]
pub struct SourceBirthInstallationFailure {
    stage: &'static str,
    #[source]
    cause: RuntimeError,
}

impl SourceBirthInstallationFailure {
    /// Reads the fixed stage at which the original verification refused.
    pub fn stage_data(&self) -> &'static str {
        self.stage
    }

    /// Borrows the original runtime refusal without rendering its contents.
    pub fn cause_data(&self) -> &RuntimeError {
        &self.cause
    }
}

/// Retains the independently selected installed derivation mechanism.
///
/// Only the exact source-built package compiled into the parent can construct
/// this owner. Neither a caller path/digest, measured readonly executable nor
/// public manifest DATA supplies a substitute. The child binary's Engine build
/// omits this binding; the finished measured package is an input to the parent
/// suite build, so no executable self-hash dependency is required.
///
/// This owner proves installed mechanism/parent containment only. Source job,
/// physical L2 completion and the same result-bank join remain independent.
#[must_use = "retain the original installed mechanism through every supervised job"]
pub struct VerifiedSourceBirthMechanism {
    supervisor: ProcessEnforcement,
    factory: LinuxPureWorkerFactory,
    program: LinuxPureWorkerProgram,
    bindings: SourceBirthInstallationBindings,
    limits: LinuxPureWorkerLimits,
    slots: usize,
}

impl VerifiedSourceBirthMechanism {
    /// Opens the compiled installation under original shared-process containment.
    ///
    /// This does not install limits in a running service. The actual completed
    /// supervisor must have been installed at the deployment's single-threaded
    /// entry; absence of the compiled package or real host controls refuses.
    ///
    /// # Errors
    /// Refuses unavailable/changed process enforcement, any missing or changed
    /// trusted artifact/runtime/loader edge, unsupported installation profile,
    /// delegated host controls or invalid operational workspace geometry.
    pub fn open(
        supervisor: Rc<LinuxProcessSupervisor>,
        configuration: LinuxPureWorkerConfiguration,
        limits: LinuxPureWorkerLimits,
        slots: usize,
    ) -> Result<Self, RuntimeError> {
        open(
            ProcessEnforcement::CreatorThread(supervisor),
            configuration,
            limits,
            slots,
        )
        .map_err(|failure| failure.cause)
    }

    /// Opens the compiled mechanism under the same funded process reservation.
    ///
    /// The trusted before-actors controller retains the nonClone original. Only
    /// its completed process-scoped lease crosses into the owning actor; this
    /// actor constructs its local Rc and opens/measures the original files.
    ///
    /// # Errors
    /// Preserves installation/currentness refusals with a fixed stage diagnostic
    /// and refuses incomplete, revoked or foreign deployment ownership. It
    /// issues no Source stage row.
    pub fn open_with_deployment(
        reservation: &crucible_host_resources::OriginalDeploymentResourceReservation,
        configuration: LinuxPureWorkerConfiguration,
        limits: LinuxPureWorkerLimits,
        slots: usize,
    ) -> Result<Self, SourceBirthInstallationFailure> {
        let lease = reservation
            .lease()
            .map_err(|_| SourceBirthInstallationFailure {
                stage: "installed worker deployment lease refused",
                cause: RuntimeError::ResourceLimit,
            })?;
        open(
            ProcessEnforcement::Deployment(lease),
            configuration,
            limits,
            slots,
        )
    }

    pub(in crate::node_adapters::cnp) fn deployment_lease(
        &self,
    ) -> Result<&crucible_host_resources::DeploymentResourceLease, RuntimeError> {
        match &self.supervisor {
            ProcessEnforcement::Deployment(lease) => {
                lease
                    .authenticate_current()
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                Ok(lease)
            }
            ProcessEnforcement::CreatorThread(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }

    /// Authenticates the same process enforcement and opened program guards.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete deployment, changed current kernel limits,
    /// broken original executable leases or changed read-only runtime guards.
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.supervisor
            .authenticate_current()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.program
            .verify_current()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    /// Copies the exact measured artifact commitments as ordinary DATA.
    ///
    /// Equal copied commitments cannot reconstruct this owner, authenticate
    /// another program instance or accept worker result banks.
    pub fn bindings_data(&self) -> SourceBirthInstallationBindings {
        self.bindings
    }

    /// Copies the frozen operational limits used by every reserved original.
    pub fn limits_data(&self) -> LinuxPureWorkerLimits {
        self.limits
    }

    /// Copies the frozen reusable export-frame slot restriction.
    ///
    /// The actual caller separately admits and allocates this frame bank before
    /// taking any original Source export loan; this getter grants no storage.
    pub fn workspace_slots(&self) -> usize {
        self.slots
    }

    /// Observes only the original factory's direct requested buffer backing.
    ///
    /// These DATA exclude opaque/runtime/thread allocations and are not a
    /// complete footprint; the separate actual supervisor bounds that work.
    ///
    /// # Errors
    /// Refuses arithmetic that cannot represent the actual owned capacities.
    pub fn direct_buffer_census(
        &self,
    ) -> Result<crucible_host_resources::LinuxPureWorkerDirectBuffers, LinuxPureWorkerError> {
        self.factory.direct_buffer_census()
    }

    /// Reserves the same verified factory after authenticating parent enforcement.
    ///
    /// # Errors
    /// Refuses revoked deployment, busy/quarantined cleanup slot, invalid limits
    /// or actual supervisor reservation failure. No Source loan is accepted.
    pub fn reserve_attempt(&self) -> Result<LinuxPureWorkerAttempt, LinuxPureWorkerError> {
        self.authenticate_current()
            .map_err(|_| LinuxPureWorkerError::HostControlsUnavailable)?;
        self.factory.reserve(self.limits)
    }
}

fn open(
    supervisor: ProcessEnforcement,
    configuration: LinuxPureWorkerConfiguration,
    limits: LinuxPureWorkerLimits,
    slots: usize,
) -> Result<VerifiedSourceBirthMechanism, SourceBirthInstallationFailure> {
    let mut stage = "installed worker process enforcement refused";
    let result = (|| -> Result<VerifiedSourceBirthMechanism, Failure> {
        // Build-time selection pins the source-built package. Runtime environment
        // variables cannot replace it, and absence never selects a fallback.
        supervisor
            .authenticate_current()
            .map_err(|_| RuntimeError::ResourceLimit)?;

        stage = "installed worker compiled manifest unavailable";
        let path = option_env!("CRUCIBLE_SOURCE_BIRTH_WORKER_MANIFEST")
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let path = Path::new(path);

        stage = "installed worker manifest read refused";
        let bytes = read_metadata(path)?;

        stage = "installed worker manifest validation refused";
        let installed: Installation = decode(&bytes)?;
        if installed.schema != "crucible.pure-worker.installation/1"
            || installed.profile != "pure-worker-v1"
            || installed.read_only_roots.is_empty()
            || installed.read_only_roots.len() > MAXIMUM_ROOTS
            || installed
                .read_only_roots
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || installed
                .read_only_roots
                .iter()
                .any(|path| !matches!(store_root(path), Ok(root) if &root == path))
        {
            return Err(RuntimeError::UnsupportedFacet);
        }

        stage = "installed worker runtime closure metadata refused";
        let mut measured = 0;
        let runtime_bytes = artifact_metadata(&installed.runtime_closure, &mut measured)?;
        let closure: RuntimeClosure = decode(&runtime_bytes)?;
        if closure.schema != "crucible.pure-worker.runtime-closure/1"
            || closure.store_paths != installed.read_only_roots
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        stage = "installed worker runtime reference graph refused";
        check_graph(&closure, &installed, &mut measured)?;

        stage = "installed worker algorithm metadata refused";
        let algorithm_bytes = artifact_metadata(&installed.algorithm, &mut measured)?;
        let algorithm: Algorithm = decode(&algorithm_bytes)?;
        if algorithm.schema != "crucible.pure-worker.algorithm/1"
            || algorithm.id != "crucible.source-birth.derivation/1"
            || algorithm.source != installed.source.content
            || algorithm.vendor != installed.vendor.content
            || algorithm.recipe != installed.recipe.content
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        stage = "installed worker request codec refused";
        check_codec(
            &installed.request_codec,
            "crucible.source-birth.request/1",
            "CSBIN001",
            160,
            &installed.source.content,
            &mut measured,
        )?;

        stage = "installed worker result codec refused";
        check_codec(
            &installed.result_codec,
            "crucible.source-birth.result/1",
            "CSBR0001",
            240,
            &installed.source.content,
            &mut measured,
        )?;

        stage = "installed worker source, vendor or recipe measurement refused";
        for artifact in [&installed.source, &installed.vendor, &installed.recipe] {
            let file = open_regular(&artifact.path)?;
            measure(&file, &artifact.content, &mut measured)?;
        }

        stage = "installed worker artifact identity refused";
        let worker = digest(&installed.worker.content.hash)?;
        let algorithm = digest(&installed.algorithm.content.hash)?;

        stage = "installed worker executable or readonly runtime guards refused";
        let program = LinuxPureWorkerProgram::open(
            &installed.launcher.path,
            &installed.worker.path,
            &installed.read_only_roots,
            worker,
            algorithm,
        )
        .map_err(|_| RuntimeError::UnsupportedFacet)?;

        stage = "installed worker original executable measurement refused";
        // Do not reopen either executable by pathname for these measurements.
        measure(
            program.launcher_file(),
            &installed.launcher.content,
            &mut measured,
        )?;
        measure(
            program.worker_file(),
            &installed.worker.content,
            &mut measured,
        )?;

        stage = "installed worker runtime inventory or loader edges refused";
        check_tree(&closure, &installed, &program, &mut measured)?;

        stage = "installed worker executable currentness refused";
        program
            .verify_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let bindings = SourceBirthInstallationBindings {
            installation: *blob_hash(&bytes).as_bytes(),
            launcher: digest(&installed.launcher.content.hash)?,
            worker,
            runtime: digest(&installed.runtime_closure.content.hash)?,
            algorithm,
            request_codec: digest(&installed.request_codec.content.hash)?,
            result_codec: digest(&installed.result_codec.content.hash)?,
        };

        stage = "installed worker cgroup or quota factory refused";
        let identity = program.identity();
        let factory = LinuxPureWorkerFactory::open(configuration, program.clone())
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        if factory.profile_id() != "pure-worker-v1" || factory.program_identity() != identity {
            return Err(RuntimeError::ForeignAuthority);
        }
        // The operational workspace is admitted by the parent before allocation,
        // and allocated only immediately before the synchronous Source export.

        stage = "installed worker export workspace refused";
        ExportWorkspace::requested_bytes(slots).map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(VerifiedSourceBirthMechanism {
            supervisor,
            factory,
            program,
            bindings,
            limits,
            slots,
        })
    })();
    result.map_err(|cause| SourceBirthInstallationFailure { stage, cause })
}

fn check_codec(
    artifact: &Artifact,
    id: &str,
    magic: &str,
    bytes: usize,
    source: &ContentRef,
    measured: &mut u64,
) -> Result<(), Failure> {
    let codec: Codec = decode(&artifact_metadata(artifact, measured)?)?;
    if codec.schema != "crucible.pure-worker.codec/1"
        || codec.id != id
        || codec.magic != magic
        || codec.version != 1
        || codec.header_bytes != bytes
        || &codec.source != source
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn check_graph(
    closure: &RuntimeClosure,
    installed: &Installation,
    measured: &mut u64,
) -> Result<(), Failure> {
    let graph: ReferenceGraph = decode(&artifact_metadata(&closure.reference_graph, measured)?)?;
    let expected = BTreeSet::from([
        store_root(&installed.launcher.path)?,
        store_root(&installed.worker.path)?,
    ]);
    if graph.schema != "aos.reference-graph/v1"
        || !graph.subtract_roots.is_empty()
        || graph.paths.len() != closure.store_paths.len()
        || graph.paths.len() > MAXIMUM_ROOTS
        || graph.roots.len() != expected.len()
        || graph.roots.iter().cloned().collect::<BTreeSet<_>>() != expected
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let mut reachable = BTreeSet::new();
    let mut pending = expected.into_iter().collect::<Vec<_>>();
    for (entry, path) in graph.paths.iter().zip(&closure.store_paths) {
        if &entry.path != path
            || store_root(path)? != *path
            || entry.references.len() > MAXIMUM_ROOTS
            || entry.references.windows(2).any(|pair| pair[0] >= pair[1])
            || entry
                .references
                .iter()
                .any(|path| closure.store_paths.binary_search(path).is_err())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
    }
    while let Some(path) = pending.pop() {
        if !reachable.insert(path.clone()) {
            continue;
        }
        let index = closure
            .store_paths
            .binary_search(&path)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        for reference in &graph.paths[index].references {
            if !reachable.contains(reference) {
                pending.push(reference.clone());
            }
        }
        if pending.len() > MAXIMUM_ROOTS * MAXIMUM_ROOTS {
            return Err(RuntimeError::ResourceLimit);
        }
    }
    if reachable.len() != graph.paths.len() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn check_tree(
    closure: &RuntimeClosure,
    installed: &Installation,
    program: &LinuxPureWorkerProgram,
    measured: &mut u64,
) -> Result<(), Failure> {
    if closure.entries.len() > MAXIMUM_ENTRIES
        || closure.objects.len() > MAXIMUM_OBJECTS
        || closure
            .entries
            .windows(2)
            .any(|pair| pair[0].path() >= pair[1].path())
        || closure
            .objects
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let entries = closure
        .entries
        .iter()
        .map(|entry| (entry.path().to_path_buf(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut pending = closure.store_paths.clone();
    let mut visited = BTreeSet::new();
    let mut objects = BTreeSet::new();
    while let Some(path) = pending.pop() {
        if !visited.insert(path.clone()) || visited.len() + pending.len() > MAXIMUM_ENTRIES {
            return Err(RuntimeError::ResourceLimit);
        }
        if closure
            .store_paths
            .binary_search(&store_root(&path)?)
            .is_err()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let entry = entries.get(&path).ok_or(RuntimeError::ForeignAuthority)?;
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| RuntimeError::OwnerUnavailable)?;
        match entry {
            TreeEntry::Directory { mode, .. }
                if metadata.is_dir() && metadata.mode() & 0o7777 == *mode =>
            {
                // A writable nested mount is not protected by the retained
                // readonly root guard. Check each actual directory as well.
                let directory = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits()
                            as i32,
                    )
                    .open(&path)
                    .map_err(|_| RuntimeError::OwnerUnavailable)?;
                if !rustix::fs::fstatvfs(&directory)
                    .map_err(|_| RuntimeError::OwnerUnavailable)?
                    .f_flag
                    .contains(rustix::fs::StatVfsMountFlags::RDONLY)
                {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                for child in std::fs::read_dir(&path).map_err(|_| RuntimeError::OwnerUnavailable)? {
                    if visited.len() + pending.len() >= MAXIMUM_ENTRIES {
                        return Err(RuntimeError::ResourceLimit);
                    }
                    pending.push(child.map_err(|_| RuntimeError::OwnerUnavailable)?.path());
                }
            }
            TreeEntry::Symlink { target, .. } if metadata.file_type().is_symlink() => {
                if std::fs::read_link(&path).map_err(|_| RuntimeError::OwnerUnavailable)? != *target
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                resolve(&path, &entries, &closure.store_paths)?;
            }
            TreeEntry::File { mode, content, .. }
                if metadata.is_file() && metadata.mode() & 0o7777 == *mode =>
            {
                let file;
                let original = if path == installed.launcher.path {
                    program.launcher_file()
                } else if path == installed.worker.path {
                    program.worker_file()
                } else {
                    file = open_regular(&path)?;
                    &file
                };
                measure(original, content, measured)?;
                let mut magic = [0; 4];
                if original
                    .read_at(&mut magic, 0)
                    .map_err(|_| RuntimeError::OwnerUnavailable)?
                    == 4
                    && magic == *b"\x7fELF"
                {
                    let object = closure
                        .objects
                        .binary_search_by(|object| object.path.cmp(&path))
                        .map_err(|_| RuntimeError::ForeignAuthority)?;
                    if closure.objects[object].content != *content {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    objects.insert(path.clone());
                }
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
    }
    if visited.len() != entries.len()
        || objects.len() != closure.objects.len()
        || !objects.contains(&installed.launcher.path)
        || !objects.contains(&installed.worker.path)
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    loader::check_program(installed, program, &entries, &closure.store_paths)?;
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Failure> {
    serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidReceipt)
}

fn artifact_metadata(artifact: &Artifact, measured: &mut u64) -> Result<Vec<u8>, Failure> {
    if artifact.content.media_type != "application/json" {
        return Err(RuntimeError::InvalidReceipt);
    }
    let file = open_regular(&artifact.path)?;
    let bytes = read_metadata_original(&file)?;
    measure(&file, &artifact.content, measured)?;
    // Compare the decoded bytes to the SAME measured opened original, not a
    // separate pathname read that could be exchanged during verification.
    if *blob_hash(&bytes).as_bytes() != digest(&artifact.content.hash)?
        || u64::try_from(bytes.len()).map_err(|_| RuntimeError::ResourceLimit)?
            != artifact.content.length.get()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(bytes)
}

fn read_metadata(path: &Path) -> Result<Vec<u8>, Failure> {
    read_metadata_original(&open_regular(path)?)
}

fn read_metadata_original(original: &File) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    original
        .take(MAXIMUM_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    if bytes.len() > MAXIMUM_METADATA_BYTES {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(bytes)
}

fn open_regular(path: &Path) -> Result<File, Failure> {
    store_root(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    if !rustix::fs::fstatvfs(&file)
        .map_err(|_| RuntimeError::OwnerUnavailable)?
        .f_flag
        .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    if !file
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?
        .is_file()
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(file)
}

fn measure(file: &File, expected: &ContentRef, measured: &mut u64) -> Result<(), Failure> {
    let before = file
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    if !before.is_file()
        || before.len() != expected.length.get()
        || before.len() > MAXIMUM_ARTIFACT_BYTES
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    *measured = measured
        .checked_add(before.len())
        .filter(|bytes| *bytes <= MAXIMUM_MEASURED_BYTES)
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut hash = blob_hasher(before.len());
    let mut offset = 0;
    let mut buffer = [0; 65_536];
    while offset < before.len() {
        let request = usize::try_from((before.len() - offset).min(buffer.len() as u64))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let count = file
            .read_at(&mut buffer[..request], offset)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        if count == 0 {
            return Err(RuntimeError::ForeignAuthority);
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    let after = file
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    if identity(&before) != identity(&after)
        || *hash.finalize().as_bytes() != digest(&expected.hash)?
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn blob_hasher(length: u64) -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(11u32).to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&length.to_be_bytes());
    hash
}

fn blob_hash(bytes: &[u8]) -> blake3::Hash {
    let mut hash = blob_hasher(bytes.len() as u64);
    hash.update(bytes);
    hash.finalize()
}

fn digest(hash: &HashRef) -> Result<[u8; 32], Failure> {
    if hash.algorithm != "blake3-256" || hash.domain != "cnp.blob.v1" || hash.digest.len() != 64 {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut result = [0; 32];
    for (slot, pair) in result
        .iter_mut()
        .zip(hash.digest.as_bytes().chunks_exact(2))
    {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(RuntimeError::InvalidReceipt),
        };
        *slot = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Ok(result)
}

fn store_root(path: &Path) -> Result<PathBuf, Failure> {
    let text = path.to_str().ok_or(RuntimeError::UnsupportedFacet)?;
    if text.len() > 4096
        || text.contains('\0')
        || text.contains("//")
        || text.split('/').any(|part| part == "." || part == "..")
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal("nix".as_ref()))
        || components.next() != Some(Component::Normal("store".as_ref()))
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let Some(Component::Normal(name)) = components.next() else {
        return Err(RuntimeError::UnsupportedFacet);
    };
    let text = name.to_str().ok_or(RuntimeError::UnsupportedFacet)?;
    let (hash, label) = text.split_once('-').ok_or(RuntimeError::UnsupportedFacet)?;
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        || label.is_empty()
        || !label.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(Path::new("/nix/store").join(name))
}

fn resolve(
    path: &Path,
    entries: &BTreeMap<PathBuf, &TreeEntry>,
    roots: &[PathBuf],
) -> Result<PathBuf, Failure> {
    let mut pending = path.to_path_buf();
    let mut seen = BTreeSet::new();
    for _ in 0..MAXIMUM_ENTRIES {
        if pending.as_os_str().len() > 4096
            || !pending.is_absolute()
            || !seen.insert(pending.clone())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut prefix = PathBuf::new();
        // Retain `.` and a trailing slash: traversing `file/.` or `file/`
        // requires a directory, even though Path::components normalizes them.
        let components = pending
            .to_str()
            .ok_or(RuntimeError::ForeignAuthority)?
            .split('/')
            .collect::<Vec<_>>();
        prefix.push("/");
        let mut replaced = false;
        for (index, component) in components.iter().enumerate() {
            match *component {
                "" | "." => {}
                ".." => {
                    if !prefix.pop() {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                }
                name => {
                    prefix.push(name);
                    if prefix == Path::new("/nix") || prefix == Path::new("/nix/store") {
                        continue;
                    }
                    if roots.binary_search(&store_root(&prefix)?).is_err() {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    let entry = entries.get(&prefix).ok_or(RuntimeError::ForeignAuthority)?;
                    if let TreeEntry::Symlink { target, .. } = entry {
                        let mut next = if target.is_absolute() {
                            target.clone()
                        } else {
                            prefix
                                .parent()
                                .ok_or(RuntimeError::ForeignAuthority)?
                                .join(target)
                        };
                        for suffix in &components[index + 1..] {
                            next.push(suffix);
                        }
                        pending = next;
                        replaced = true;
                        break;
                    }
                    if index + 1 < components.len() && !matches!(entry, TreeEntry::Directory { .. })
                    {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                }
            }
        }
        if !replaced {
            if roots.binary_search(&store_root(&prefix)?).is_err() || !entries.contains_key(&prefix)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            return Ok(prefix);
        }
    }
    Err(RuntimeError::ForeignAuthority)
}

#[cfg(test)]
#[path = "installation/tests.rs"]
mod tests;

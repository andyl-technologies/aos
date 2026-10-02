//! Native deployment execution for authenticated image and bootstrap callers.
//!
//! The caller's verified image command supplies the admission document's byte
//! digest. That digest binds an immutable NAR catalog to existing image trust;
//! it does not authenticate an arbitrary catalog on its own. Retained receipts
//! preserve that authorization across recovery, while live NAR verification
//! checks every rooted or executable artifact against its admitted identity.
//!
//! An immutable input directory contains `packages.json` (the native resolved
//! package set) and `transaction.json` (its checked desired transaction).
//! The separate admission artifact precedes the transaction:
//!
//! ```json
//! {"schema":"aos.package.admission","roots":[{"storePath":"/nix/store/00000000000000000000000000000000-source","narHash":"sha256:...","narSize":1,"references":[]}]}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::deployment::model::{Deployment, ResolvedPackages};
use crate::deployment::retention::{ArtifactAdmission, NixStore};
use crate::deployment::transaction::{Transactions, journal_limits};
use crate::store::verification::verify_store_object_in;

mod admission;
mod document;
pub use document::read_immutable_document_in;
pub(crate) use document::{read_descriptor_in, read_regular_store_document_in};
mod bootstrap;
mod evaluate;

pub use crate::native_registry::solver::{LockedEdge, ResolutionLock};
pub use admission::{AdmissionCatalog, AdmittedRoot};
pub use bootstrap::{SourceAuthorization, apply_with_sources, resume_profile};
pub use evaluate::evaluate_input;
pub(crate) use evaluate::{
    os_requirements, retained_declarations, validate_target_os, validated_declarations,
};

#[derive(clap::Args)]
pub struct NativeDeploymentArgs {
    /// Read the immutable native transaction directory.
    #[arg(long)]
    input: PathBuf,
    /// Use the private native generation and effect journals.
    #[arg(long)]
    state_directory: PathBuf,
    /// Publish a completed host transaction through this system profile.
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Use this absolute AOS-built Nix store executable.
    #[arg(long)]
    nix_store: PathBuf,
    /// Read the immutable image admission document.
    #[arg(long)]
    admission: PathBuf,
    /// Bind admission bytes to the verified image command's SHA-256 digest.
    #[arg(long)]
    admission_sha256: String,
}

impl NativeDeploymentArgs {
    pub(crate) fn command(&self) -> Result<NativeDeploymentCommand> {
        Ok(NativeDeploymentCommand {
            input: self.input.clone(),
            state_directory: self.state_directory.clone(),
            profile: self.profile.clone(),
            nix_store: self.nix_store.clone(),
            admission: self.admission.clone(),
            admission_sha256: Sha256Digest::parse(&self.admission_sha256)?,
        })
    }
}

/// Supplies an immutable native transaction and its verified image authority.
pub struct NativeDeploymentCommand {
    /// Contains native `packages.json` and `transaction.json` documents.
    pub input: PathBuf,
    /// Holds the private generation, effect, and authorization receipts.
    pub state_directory: PathBuf,
    /// Publishes host payloads and metadata through the authoritative profile.
    pub profile: Option<PathBuf>,
    /// Selects the AOS-built Nix store executable explicitly.
    pub nix_store: PathBuf,
    /// Identifies the separate immutable admission document.
    pub admission: PathBuf,
    /// Binds the admission bytes to the caller's verified image command.
    pub admission_sha256: Sha256Digest,
}

/// Describes the admitted immutable inputs before evaluating a package graph.
///
/// The descriptor contains no output graph or self locator. Package-owned
/// operations can retain its path as ordinary input without a reference cycle.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationInput {
    /// Identifies the native pre-evaluation input contract.
    pub schema: String,
    /// Locates the immutable generic module library entrypoint.
    pub library: PathBuf,
    /// Binds the library root to its admitted NAR identity.
    #[serde(rename = "libraryNarHash")]
    pub library_nar_hash: Sha256Digest,
    /// Identifies the stable profile or deployment scope.
    pub scope: Vec<String>,
    /// Contains the exact resolved package modules and payload artifacts.
    pub packages: ResolvedPackages,
    /// Retains each resolved module's original authenticated deployment envelope.
    #[serde(rename = "moduleEnvelopes")]
    pub module_envelopes: std::collections::BTreeMap<String, PathBuf>,
    /// Retains selected payload envelopes, including packages without a module.
    #[serde(default, rename = "packageEnvelopes")]
    pub package_envelopes: BTreeMap<String, PathBuf>,
    /// Pins the host release used for runtime compatibility checks.
    #[serde(default, rename = "osRelease", skip_serializing_if = "Option::is_none")]
    pub os_release: Option<aos_doc_model::runtime::OsRelease>,
    /// Pins ranged dependency choices; exact-only closures omit this field.
    #[serde(
        default,
        rename = "resolutionLock",
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution_lock: Option<ResolutionLock>,
    /// Orders the retained baseline module sources.
    pub configuration: Vec<PathBuf>,
    /// Orders the replaceable operator module snapshot entrypoints.
    #[serde(default, rename = "runtimeConfiguration")]
    pub runtime_configuration: Vec<PathBuf>,
    /// Retains immutable authority and domain artifacts without importing them as modules.
    #[serde(default, rename = "supplementalInputs")]
    pub supplemental_inputs: Vec<PathBuf>,
}

impl EvaluationInput {
    /// Reads one bounded native descriptor from an immutable source.
    ///
    /// # Errors
    /// Returns an error for non-store sources, malformed or oversized documents,
    /// an unsupported schema, or invalid library/source locators and scope.
    pub fn read(path: &Path) -> Result<Self> {
        let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
        Self::read_in(path, &executable, &CancellationToken::default())
    }

    /// Reads a native descriptor through an explicitly selected store executable.
    ///
    /// Canonical store identities are resolved by Nix, including isolated local
    /// stores. A retained profile symlink is resolved only to obtain its identity.
    ///
    /// # Errors
    /// Returns an error for invalid locators, inaccessible or oversized documents,
    /// malformed descriptors, store failure, timeout, or cancellation.
    pub fn read_in(
        path: &Path,
        nix_store: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let (_, bytes) = read_descriptor_in(path, nix_store, cancellation)?;
        Self::decode(&bytes)
    }

    /// Decodes and validates a bounded native descriptor without reading its sources.
    ///
    /// # Errors
    /// Returns an error for malformed data, an unsupported schema, an empty
    /// scope, or noncanonical immutable source locators.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let input: Self = GRAPH_LIMITS.decode(bytes, "native evaluation input")?;
        ensure!(
            input.schema == "aos.package.evaluation-input",
            "unsupported native evaluation input"
        );
        ensure!(
            !input.scope.is_empty() && input.scope.iter().all(|segment| !segment.is_empty()),
            "native evaluation scope is empty"
        );
        for source in std::iter::once(&input.library)
            .chain(&input.configuration)
            .chain(&input.runtime_configuration)
            .chain(&input.supplemental_inputs)
        {
            crate::deployment::nix::store_root_and_suffix(source)?;
        }
        for supplemental in &input.supplemental_inputs {
            let (root, suffix) = crate::deployment::nix::store_root_and_suffix(supplemental)?;
            ensure!(
                root == *supplemental && suffix.as_os_str().is_empty(),
                "supplemental input must name a canonical store root"
            );
        }
        let mut module_names = std::collections::BTreeSet::new();
        for module in &input.packages.modules {
            ensure!(
                module_names.insert(&module.name),
                "resolved module names are duplicated"
            );
        }
        ensure!(
            module_names == input.module_envelopes.keys().collect(),
            "module envelope catalog differs from resolved module names"
        );
        let payloads: BTreeSet<_> = input
            .packages
            .artifacts
            .iter()
            .map(|artifact| artifact.canonical_catalog().path)
            .collect();
        ensure!(
            payloads == input.package_envelopes.keys().cloned().collect(),
            "selected payloads differ from retained envelope catalog"
        );

        if let Some(release) = &input.os_release {
            ensure!(
                !release.name.is_empty()
                    && release.name.len() <= 256
                    && release.version.len() <= 128
                    && semver::Version::parse(&release.version).is_ok(),
                "retained host release has an invalid name or semantic version"
            );
        }
        for path in input
            .module_envelopes
            .values()
            .chain(input.package_envelopes.values())
        {
            let (root, suffix) = crate::deployment::nix::store_root_and_suffix(path)?;
            ensure!(
                root == *path && suffix.as_os_str().is_empty(),
                "module envelope must name a canonical store root"
            );
        }
        ensure!(
            input.resolution_lock.is_some()
                || input
                    .packages
                    .modules
                    .iter()
                    .all(|module| module.module_requirements.is_empty()),
            "ranged module requirements have no exact resolution lock"
        );
        if let Some(lock) = &input.resolution_lock {
            lock.check()?;
        }
        Ok(input)
    }

    /// Imports a caller-assembled descriptor into the configured AOS store.
    ///
    /// Callers must already authenticate the represented sources and record the
    /// resulting descriptor's NAR identity before dispatching package effects.
    ///
    /// # Errors
    /// Returns an error for invalid serialization, failed store import, output
    /// limits, timeout or cancellation, or changed imported document bytes.
    pub fn import(
        &self,
        nix_store: &Path,
        staging: &Path,
        cancellation: &CancellationToken,
    ) -> Result<ImportedEvaluationInput> {
        let mut temporary_roots =
            crate::store::temp_roots::TemporaryRoots::open(nix_store, cancellation)?;
        let path = self.import_retained(nix_store, staging, cancellation, &mut temporary_roots)?;
        Ok(ImportedEvaluationInput {
            path,
            _temporary_roots: temporary_roots,
        })
    }

    pub(crate) fn import_retained(
        &self,
        nix_store: &Path,
        staging: &Path,
        cancellation: &CancellationToken,
        temporary_roots: &mut crate::store::temp_roots::TemporaryRoots,
    ) -> Result<PathBuf> {
        let temporary = tempfile::tempdir_in(staging)?;
        let path = temporary.path().join("evaluation-input.json");
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= GRAPH_LIMITS.max_bytes,
            "evaluation input exceeds its byte bound"
        );
        fs::write(&path, &bytes)?;
        let expected = crate::store::temp_roots::fixed_path(
            nix_store,
            Sha256Digest::of_bytes(&bytes),
            "evaluation-input.json",
            false,
            cancellation,
        )?;
        temporary_roots.retain(
            [expected
                .to_str()
                .context("descriptor path is not UTF-8")?
                .to_owned()],
            cancellation,
        )?;
        let mut command = crate::store::verification::live_store_command(Some(nix_store))?;
        command.args(["--add-fixed", "sha256"]).arg(&path);
        let environment = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect::<Vec<_>>();
        let output = crate::deployment::process::run_bounded(
            &mut command,
            None,
            64 * 1024,
            &ImportControl(cancellation),
            &environment,
        )?;
        ensure!(
            output.status.success(),
            "native evaluation input import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let imported = PathBuf::from(std::str::from_utf8(&output.stdout)?.trim());
        let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&imported)?;
        ensure!(
            suffix.as_os_str().is_empty() && root == imported,
            "store import returned a noncanonical descriptor root"
        );
        ensure!(
            imported == expected
                && read_immutable_document_in(&imported, nix_store, cancellation)? == bytes,
            "imported evaluation input changed"
        );
        Ok(imported)
    }
}

/// Keeps an imported evaluation descriptor rooted until its caller publishes it.
pub struct ImportedEvaluationInput {
    /// Immutable descriptor locator in the configured store.
    pub path: PathBuf,
    _temporary_roots: crate::store::temp_roots::TemporaryRoots,
}

pub(crate) struct ImportControl<'a>(pub(crate) &'a CancellationToken);

impl aos_ability_runtime::adapter::RuntimeControl for ImportControl<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
    fn elapsed_millis(&self) -> u64 {
        0
    }
    fn attempt_remaining_millis(&self) -> u64 {
        60_000
    }
    fn recovery_remaining_millis(&self) -> u64 {
        60_000
    }
}

/// Resolves a retained descriptor and checks its exact committed source context.
///
/// # Errors
/// Returns an error for invalid transport aliases, inaccessible documents,
/// missing descriptor retention, or mismatched scope and package selection.
pub(crate) fn read_retained_evaluation_in(
    path: &Path,
    desired: &Deployment,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<(PathBuf, EvaluationInput)> {
    let (identity, bytes) = read_descriptor_in(path, nix_store, cancellation)?;
    let (root, _) = crate::deployment::nix::store_root_and_suffix(&identity)?;
    let root = root.to_str().context("descriptor root is not UTF-8")?;
    ensure!(
        desired.inputs().iter().any(|input| input == root),
        "committed native deployment does not retain its evaluation descriptor"
    );
    let input = EvaluationInput::decode(&bytes)?;
    ensure!(
        input.scope == desired.scope() && input.packages == desired.resolved(),
        "retained evaluation descriptor differs from committed scope or packages"
    );
    for companion in input
        .module_envelopes
        .values()
        .chain(input.package_envelopes.values())
    {
        ensure!(
            desired
                .inputs()
                .iter()
                .any(|root| Path::new(root) == companion),
            "committed deployment does not retain its package envelope"
        );
    }
    os_requirements(&input, nix_store, cancellation)?;
    Ok((identity, input))
}

/// Preserves the explicit evaluation roles and ordering owned by a profile.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationInputs {
    #[serde(default, rename = "osRelease")]
    pub(crate) os_release: Option<aos_doc_model::runtime::OsRelease>,
    pub(crate) library: PathBuf,
    pub(crate) configuration: Vec<PathBuf>,
    #[serde(default, rename = "runtimeConfiguration")]
    pub(crate) runtime_configuration: Vec<PathBuf>,
    #[serde(default, rename = "supplementalInputs")]
    pub(crate) supplemental_inputs: Vec<PathBuf>,
}

impl EvaluationInputs {
    pub(crate) fn read(path: &Path) -> Result<Self> {
        {
            let input = EvaluationInput::read(path)?;
            Ok(Self {
                os_release: input.os_release,
                library: input.library,
                configuration: input.configuration,
                runtime_configuration: input.runtime_configuration,
                supplemental_inputs: input.supplemental_inputs,
            })
        }
    }

    pub(crate) fn admit(
        &self,
        deployment: &Deployment,
        admission: &mut impl ArtifactAdmission,
    ) -> Result<()> {
        for path in std::iter::once(&self.library)
            .chain(&self.configuration)
            .chain(&self.runtime_configuration)
            .chain(&self.supplemental_inputs)
        {
            let (root, _) = crate::deployment::nix::store_root_and_suffix(path)?;
            let root = root.to_str().context("evaluation input is not UTF-8")?;
            ensure!(
                deployment.inputs().iter().any(|input| input == root),
                "evaluation input is not retained by its deployment"
            );
            admission.admit(root)?;
        }
        Ok(())
    }

    pub(crate) fn retain_descriptor(
        path: &Path,
        generation: &crate::profile::Generation,
    ) -> Result<()> {
        let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
        let (identity, _) = read_descriptor_in(path, &executable, &CancellationToken::default())?;
        std::os::unix::fs::symlink(identity, generation.path.join("evaluation.json"))?;
        Ok(())
    }
}

fn apply_profile(
    command: &NativeDeploymentCommand,
    path: &Path,
    deployment: &Deployment,
    _image_admission: Admission,
    image_evaluation: &EvaluationInputs,
    cancellation: &CancellationToken,
    mut sources: Option<bootstrap::BootstrapSources<'_>>,
) -> Result<()> {
    use crate::profile::{Profile, deployment::ProfileDeployment};
    use crate::types::{InstalledMeta, ProfileScope};

    ensure!(
        deployment.scope() == ["profile", "system"],
        "host deployment must use the system profile scope"
    );
    let inspection = Profile {
        path: path.to_owned(),
        scope: ProfileScope::System,
    };
    let _profile_guard = inspection.lock_mutation()?;
    let profile = Profile::open_at(path.to_owned(), ProfileScope::System)?;
    let admission = crate::native_registry::RegistryAdmission::new(
        command.nix_store.clone(),
        &command.state_directory.join("registry-admissions"),
    )?;
    let store = NixStore::open(
        command.nix_store.clone(),
        command.state_directory.join("roots"),
        admission,
    )?;
    let mut consumer = ProfileDeployment::open(&profile, store, journal_limits())?;
    configure_profile_observer(&mut consumer, &profile, None, cancellation)?;
    consumer.recover(cancellation)?;
    // The image seeds an empty profile. Subsequent boots reconcile the latest
    // committed package desired state, preserving operator installs and removals.
    let mut source_descriptor = match consumer.current() {
        Some(_) => profile
            .current_generation()?
            .context("committed profile pointer is absent")?
            .path
            .join("evaluation.json"),
        None => command.input.join("evaluation.json"),
    };
    let (mut deployment, installed, mut evaluation) = match consumer.current() {
        Some(committed) => {
            let generation = profile
                .current_generation()?
                .context("committed profile pointer is absent")?;
            (
                committed.deployment.clone(),
                crate::profile::meta::list_meta(&profile)?,
                EvaluationInputs::read(&generation.path.join("evaluation.json"))?,
            )
        }
        None => {
            let installed: Vec<InstalledMeta> = GRAPH_LIMITS.decode(
                &read_regular_document(&command.input.join("installed.json"))?,
                "image installed package metadata",
            )?;
            (deployment.clone(), installed, image_evaluation.clone())
        }
    };
    let mut admission = crate::native_registry::RegistryAdmission::new(
        command.nix_store.clone(),
        &command.state_directory.join("registry-admissions"),
    )?;
    let (identity, mut descriptor) = read_retained_evaluation_in(
        &source_descriptor,
        &deployment,
        &command.nix_store,
        cancellation,
    )?;
    source_descriptor = identity;
    ensure!(
        descriptor.scope == deployment.scope() && descriptor.packages == deployment.resolved(),
        "retained evaluation descriptor differs from native desired packages"
    );
    let mut temporary_roots =
        crate::store::temp_roots::TemporaryRoots::open(&command.nix_store, cancellation)?;
    temporary_roots.retain(
        deployment.inputs().iter().cloned().chain(
            deployment
                .artifacts()
                .iter()
                .map(|artifact| artifact.path.clone()),
        ),
        cancellation,
    )?;
    if let Some(sources) = sources.as_mut() {
        sources.authority.verify_integrity()?;
        let proof_root = bootstrap::root(&sources.authority.proof)?;
        if consumer.current().is_some() {
            ensure!(
                descriptor.supplemental_inputs.contains(&proof_root)
                    && admission.has_source_authority(&proof_root, &sources.authority),
                "committed profile has a different bootstrap source authority"
            );
        } else {
            let added_roots = sources
                .configuration
                .iter()
                .chain(&sources.runtime.entrypoints)
                .chain(sources.supplemental_inputs)
                .chain([&sources.runtime.store_path, &proof_root])
                .map(|path| bootstrap::root(path))
                .collect::<Result<BTreeSet<_>>>()?;
            temporary_roots.retain(
                added_roots
                    .iter()
                    .map(|root| {
                        root.to_str()
                            .context("bootstrap root is not UTF-8")
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>>>()?,
                cancellation,
            )?;
            for root in &added_roots {
                let root = root.to_str().context("bootstrap root is not UTF-8")?;
                sources.admission.admit(root)?;
                admission.trust_authorized_input(root, &sources.authority)?;
            }
            descriptor
                .configuration
                .extend(sources.configuration.iter().cloned());
            descriptor.runtime_configuration = sources.runtime.entrypoints.clone();
            descriptor.supplemental_inputs.extend(
                sources
                    .supplemental_inputs
                    .iter()
                    .map(|path| bootstrap::root(path))
                    .collect::<Result<Vec<_>>>()?,
            );
            descriptor.supplemental_inputs.push(proof_root);
            descriptor
                .supplemental_inputs
                .push(sources.runtime.store_path.clone());
            descriptor.supplemental_inputs.sort();
            descriptor.supplemental_inputs.dedup();
            let staging = tempfile::tempdir_in(&profile.path)?;
            source_descriptor = descriptor.import_retained(
                &command.nix_store,
                staging.path(),
                cancellation,
                &mut temporary_roots,
            )?;
            admission.trust_runtime_input(
                source_descriptor
                    .to_str()
                    .context("bootstrap descriptor is not UTF-8")?,
            )?;
            let names = crate::install::native::configuration::selected_packages(
                &descriptor,
                &command.nix_store,
                cancellation,
            )?;
            if !names.is_empty() {
                // Metadata authorizes only these source bytes. Package roots
                // are acquired separately under their original registry release.
                admission.persist(&command.state_directory.join("registry-admissions"))?;
                drop(consumer);
                let config = crate::config::ApmConfig::load(ProfileScope::System)?;
                return crate::install::native::configuration::apply_from_descriptor(
                    &config,
                    &profile,
                    &installed,
                    descriptor,
                    deployment,
                    names,
                    cancellation,
                    &aos_core::output::Printer::new(0, true, false),
                );
            }
            let supplemental = descriptor
                .supplemental_inputs
                .iter()
                .map(|path| {
                    bootstrap::root(path).and_then(|root| {
                        Ok(root
                            .to_str()
                            .context("bootstrap root is not UTF-8")?
                            .to_owned())
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let retained_inputs = deployment
                .inputs()
                .iter()
                .cloned()
                .chain(supplemental)
                .map(PathBuf::from)
                .collect();
            let declarations = retained_declarations(
                &descriptor.package_envelopes,
                descriptor.os_release.as_ref(),
                &command.nix_store,
            )?;
            let evaluator = crate::deployment::evaluation::Evaluation {
                os_release: descriptor.os_release.clone(),
                os_requirements: declarations.os_requirements,
                package_releases: declarations.package_releases,
                module_requirements: descriptor
                    .resolution_lock
                    .as_ref()
                    .map_or_else(Vec::new, |lock| lock.module_requirements()),
                nix_store: command.nix_store.clone(),
                library: descriptor.library.clone(),
                scope: descriptor.scope.clone(),
                packages: descriptor.packages.clone(),
                configuration: descriptor
                    .configuration
                    .iter()
                    .chain(&descriptor.runtime_configuration)
                    .cloned()
                    .collect(),
                retained_inputs,
                evaluation_input: Some(source_descriptor.clone()),
            };
            deployment = evaluator.evaluate(staging.path(), 60_000, cancellation)?;
            evaluation = EvaluationInputs::read(&source_descriptor)?;
            admission.persist(&command.state_directory.join("registry-admissions"))?;
        }
    }
    let (descriptor_root, _) = crate::deployment::nix::store_root_and_suffix(&source_descriptor)?;
    let descriptor_root = descriptor_root
        .to_str()
        .context("descriptor root is not UTF-8")?;
    ensure!(
        deployment
            .inputs()
            .iter()
            .any(|root| root == descriptor_root),
        "evaluation descriptor is not retained"
    );
    admission.admit(descriptor_root)?;
    evaluation.admit(&deployment, &mut admission)?;
    let selected: BTreeSet<_> = deployment
        .artifacts()
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    let paths: BTreeSet<_> = installed
        .iter()
        .map(|meta| meta.store_path.as_str())
        .collect();
    ensure!(
        paths.len() == installed.len() && paths == selected,
        "image installed metadata differs from native payloads"
    );
    for meta in &installed {
        let package = meta
            .apm
            .as_ref()
            .context("image package lacks native metadata")?;
        let artifact = package
            .deployment
            .as_ref()
            .context("image package lacks its native envelope")?;
        ensure!(
            deployment.inputs().contains(&artifact.store_path),
            "image envelope is not retained"
        );
        admission.admit(&artifact.store_path)?;
        let envelope = crate::native_artifact::read_envelope_in(
            artifact,
            &package.name,
            &package.version,
            &crate::platform::native_platform(),
            &command.nix_store,
            cancellation,
        )?;
        ensure!(
            envelope
                .package
                .outputs
                .values()
                .any(|path| path == &meta.store_path),
            "image envelope differs from installed payload"
        );
        for documentation in [&package.module_documentation].into_iter().flatten() {
            ensure!(
                deployment.inputs().contains(&documentation.store_path),
                "image documentation is not retained"
            );
            admission.admit(&documentation.store_path)?;
        }
    }
    // Replace the initial recovery reader's store with the complete admission
    // assembled above. Source receipts are durable before any new graph intent.
    drop(consumer);
    let store = NixStore::open(
        command.nix_store.clone(),
        command.state_directory.join("roots"),
        admission,
    )?;
    let mut consumer = ProfileDeployment::open(&profile, store, journal_limits())?;
    let generation = profile.new_generation()?;
    let staged = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    fs::create_dir_all(generation.path.join("usr"))?;
    for meta in &installed {
        let hash = crate::registry::store_path_hash(&meta.store_path);
        std::os::unix::fs::symlink(&meta.store_path, generation.path.join("usr").join(hash))?;
        crate::profile::meta::write_meta(&staged, hash, meta)?;
    }
    crate::profile::merge::build_generation_fhs_tree(
        &generation,
        &aos_core::output::Printer::new(0, true, false),
    )?;
    EvaluationInputs::retain_descriptor(&source_descriptor, &generation)?;
    configure_profile_observer(
        &mut consumer,
        &profile,
        Some((&source_descriptor, &deployment)),
        cancellation,
    )?;
    consumer.apply(&deployment, &generation, cancellation)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    path: PathBuf,
    digest: Sha256Digest,
}

pub(crate) struct Admission {
    executable: PathBuf,
    roots: BTreeMap<String, AdmittedRoot>,
    receipts: BTreeMap<String, Receipt>,
}

impl Admission {
    pub(crate) fn new(executable: PathBuf) -> Result<Self> {
        ensure!(
            executable.is_absolute(),
            "Nix store executable must be absolute"
        );
        Ok(Self {
            executable,
            roots: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    fn add(&mut self, receipt: Receipt) -> Result<String> {
        let (path, bytes) = read_descriptor_in(
            &receipt.path,
            &self.executable,
            &CancellationToken::default(),
        )
        .context("resolving immutable admission document")?;
        let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&path)?;
        ensure!(
            suffix.as_os_str().is_empty(),
            "admission must be an immutable regular store-root file"
        );
        let catalog = AdmissionCatalog::decode(&bytes, receipt.digest)?;
        let root = root
            .to_str()
            .context("admission root is not UTF-8")?
            .to_owned();
        for record in catalog.roots().values().cloned() {
            if let Some(previous) = self.roots.get(&record.store_path) {
                ensure!(
                    previous == &record,
                    "retained receipts disagree about an artifact identity"
                );
            }
            self.roots.insert(record.store_path.clone(), record);
        }
        let receipt = Receipt { path, ..receipt };
        if let Some(previous) = self.receipts.get(&root) {
            ensure!(
                previous.digest == receipt.digest,
                "retained receipt root has conflicting digests"
            );
        }
        self.receipts.insert(root.clone(), receipt);
        Ok(root)
    }

    pub(crate) fn receipt_roots(&self) -> Vec<PathBuf> {
        self.receipts.keys().map(PathBuf::from).collect()
    }

    pub(crate) fn receipt_for(&self, root: &str) -> Result<Option<(PathBuf, Sha256Digest)>> {
        if let Some(receipt) = self.receipts.get(root) {
            return Ok(Some((receipt.path.clone(), receipt.digest)));
        }
        let Some(expected) = self.roots.get(root) else {
            return Ok(None);
        };
        for receipt in self.receipts.values() {
            let bytes = read_immutable_document_in(
                &receipt.path,
                &self.executable,
                &CancellationToken::default(),
            )?;
            ensure!(
                Sha256Digest::of_bytes(&bytes) == receipt.digest,
                "retained image receipt changed"
            );
            let catalog = AdmissionCatalog::decode(&bytes, receipt.digest)?;
            if catalog.roots().values().any(|record| record == expected) {
                return Ok(Some((receipt.path.clone(), receipt.digest)));
            }
        }
        anyhow::bail!("image-admitted root has no retained original receipt")
    }

    pub(crate) fn load_retained(&mut self, directory: &Path) -> Result<()> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "retained admission receipt must be a regular file"
            );
            let receipt = GRAPH_LIMITS.decode(
                &read_regular_document(&entry.path())?,
                "retained image authority",
            )?;
            self.add(receipt)?;
        }
        Ok(())
    }
}

impl ArtifactAdmission for Admission {
    fn admit(&mut self, root: &str) -> Result<()> {
        check_root(root)?;
        if let Some(receipt) = self.receipts.get(root) {
            // The receipt cannot contain its own NAR identity. Its document
            // remains bound to the original image authority on every admission.
            let bytes = read_immutable_document_in(
                &receipt.path,
                &self.executable,
                &CancellationToken::default(),
            )?;
            ensure!(
                Sha256Digest::of_bytes(&bytes) == receipt.digest,
                "retained image receipt changed"
            );
            return Ok(());
        }
        let admitted = self
            .roots
            .get(root)
            .with_context(|| format!("artifact lacks authenticated image admission: {root}"))?;
        verify_store_object_in(
            root,
            Sha256Digest::parse(&admitted.nar_hash)?,
            admitted.nar_size,
            &admitted.references,
            Some(&self.executable),
        )
    }
}

/// Resumes pending work and applies the image-authenticated native transaction.
///
/// # Errors
/// Returns an error for invalid immutable documents, missing authentication,
/// changed NAR contents or references, journal errors, or failed effects.
pub fn apply(command: &NativeDeploymentCommand, cancellation: &CancellationToken) -> Result<()> {
    let (deployment, mut admission, receipt) = prepare(command)?;
    let mut temporary_roots =
        crate::store::temp_roots::TemporaryRoots::open(&command.nix_store, cancellation)?;
    temporary_roots.retain(
        deployment.inputs().iter().cloned().chain(
            deployment
                .artifacts()
                .iter()
                .map(|artifact| artifact.path.clone()),
        ),
        cancellation,
    )?;
    fs::create_dir_all(&command.state_directory)?;
    persist_receipt(&command.state_directory.join("admissions"), &receipt)?;
    if let Some(path) = &command.profile {
        let evaluation = EvaluationInputs::read(&command.input.join("evaluation.json"))?;
        evaluation.admit(&deployment, &mut admission)?;
        return apply_profile(
            command,
            path,
            &deployment,
            admission,
            &evaluation,
            cancellation,
            None,
        );
    }
    let descriptor = command.input.join("evaluation.json");
    let observer = deployment_observer(&descriptor, &deployment, &mut admission, cancellation)?;
    let store = NixStore::open(
        command.nix_store.clone(),
        command.state_directory.join("roots"),
        admission,
    )?;
    let mut transactions = Transactions::open(&command.state_directory, store, journal_limits())?;
    transactions.set_observer(observer);
    transactions.resume(cancellation)?;
    transactions.apply(&deployment, cancellation)?;
    Ok(())
}

pub(crate) fn deployment_observer(
    descriptor: &Path,
    deployment: &Deployment,
    admission: &mut impl ArtifactAdmission,
    cancellation: &CancellationToken,
) -> Result<Option<Box<dyn aos_ability_runtime::activation::BoundaryObserver>>> {
    let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    let (descriptor, _) = read_descriptor_in(descriptor, &executable, cancellation)?;
    let input = EvaluationInput::read_in(&descriptor, &executable, cancellation)?;
    ensure!(
        input.scope == deployment.scope() && input.packages == deployment.resolved(),
        "observer evaluation input differs from the admitted deployment"
    );
    let (descriptor_root, _) = crate::deployment::nix::store_root_and_suffix(&descriptor)?;
    ensure!(
        deployment
            .inputs()
            .iter()
            .any(|root| Path::new(root) == descriptor_root),
        "deployment does not retain its observer evaluation input"
    );
    admission.admit(
        descriptor_root
            .to_str()
            .context("descriptor root is not UTF-8")?,
    )?;
    EvaluationInputs::read(&descriptor)?.admit(deployment, admission)?;
    for module in &input.packages.modules {
        admission.admit(&module.config_root)?;
    }
    let declarations = retained_declarations(
        &input.package_envelopes,
        input.os_release.as_ref(),
        &executable,
    )?;
    let evaluation = crate::deployment::evaluation::Evaluation {
        os_release: input.os_release.clone(),
        os_requirements: declarations.os_requirements,
        package_releases: declarations.package_releases,
        module_requirements: input
            .resolution_lock
            .as_ref()
            .map_or_else(Vec::new, |lock| lock.module_requirements()),
        nix_store: executable.clone(),
        library: input.library,
        scope: input.scope,
        packages: input.packages,
        configuration: input
            .configuration
            .into_iter()
            .chain(input.runtime_configuration)
            .collect(),
        retained_inputs: Vec::new(),
        evaluation_input: Some(descriptor),
    };
    let staging = tempfile::tempdir()?;
    let value = evaluation.project_optional(
        &["aos".into(), "execution".into(), "observer".into()],
        staging.path(),
        90_000,
        cancellation,
    )?;
    if value.is_null() {
        return Ok(None);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct ObserverConfiguration {
        socket_path: PathBuf,
        timeout_millis: u64,
    }
    let configuration: ObserverConfiguration = serde_json::from_value(value)?;
    ensure!(
        (1..=90_000).contains(&configuration.timeout_millis),
        "observer timeout exceeds the native bounded dispatch limit"
    );
    Ok(Some(Box::new(
        aos_ability_runtime::activation::SocketBoundaryObserver::new(
            configuration.socket_path,
            std::time::Duration::from_millis(configuration.timeout_millis),
        )?,
    )))
}

pub(crate) fn configure_profile_observer<S: crate::deployment::transaction::DeploymentStore>(
    consumer: &mut crate::profile::deployment::ProfileDeployment<'_, S>,
    profile: &crate::profile::Profile,
    desired: Option<(&Path, &Deployment)>,
    cancellation: &CancellationToken,
) -> Result<()> {
    let pending = consumer.recovery_evaluation()?;
    let selected = pending
        .as_ref()
        .map(|(path, deployment)| (path.as_path(), deployment))
        .or(desired);
    let Some((descriptor, deployment)) = selected else {
        consumer.set_observer(None);
        return Ok(());
    };
    let executable = PathBuf::from(
        std::env::var_os("AOS_NIX_STORE")
            .context("native observer requires its packaged Nix store")?,
    );
    let mut admission = crate::native_registry::RegistryAdmission::new(
        executable,
        &profile.path.join("deployment/registry-admissions"),
    )?;
    consumer.set_observer(deployment_observer(
        descriptor,
        deployment,
        &mut admission,
        cancellation,
    )?);
    Ok(())
}

/// Checks that the exact native transaction durably completed without executing effects.
///
/// # Errors
/// Returns an error for invalid authority or documents, missing journals,
/// pending activation, or a committed generation that differs from the input.
pub fn verify(command: &NativeDeploymentCommand) -> Result<()> {
    let (deployment, _admission, _) = prepare(command)?;
    ensure!(
        command
            .state_directory
            .join("generations.journal")
            .is_file()
            && command.state_directory.join("effects.journal").is_file()
            && command.state_directory.join("roots").is_dir(),
        "native deployment has no durable completion state"
    );
    let transactions =
        crate::deployment::transaction::inspect(&command.state_directory, journal_limits())?;
    ensure!(
        !transactions.has_pending_work()
            && transactions.incomplete_tail_bytes() == 0
            && transactions.activation().incomplete_tail_bytes == 0,
        "native deployment still has pending activation"
    );
    let committed = transactions
        .current()
        .context("native deployment has no committed generation")?;
    ensure!(
        committed.deployment.scope() == deployment.scope()
            && (command.profile.is_some() || committed.content == deployment.id()?),
        "committed native deployment differs from requested input"
    );
    if let Some(path) = &command.profile {
        let profile = crate::profile::Profile {
            path: path.clone(),
            scope: crate::types::ProfileScope::System,
        };
        let generation = profile
            .current_generation()?
            .context("host profile has no published generation")?;
        // Keep the shared journal lock while checking the profile mapping.
        let sequence = committed.sequence;
        ensure!(
            crate::profile::deployment::committed_generation(path, generation.number)?.sequence
                == sequence,
            "host profile pointer differs from its committed journal"
        );
    }
    Ok(())
}

fn prepare(command: &NativeDeploymentCommand) -> Result<(Deployment, Admission, Receipt)> {
    ensure!(
        command.state_directory.is_absolute(),
        "native deployment state directory must be absolute"
    );
    if let Some(profile) = &command.profile {
        ensure!(
            profile.is_absolute() && command.state_directory == profile.join("deployment"),
            "host state directory must be the selected profile's deployment directory"
        );
    }
    let (input, _) = document::read_directory_in(
        &command.input,
        &command.nix_store,
        &CancellationToken::default(),
    )
    .context("resolving immutable native deployment input")?;
    crate::deployment::nix::store_root_and_suffix(&input)?;
    let packages: ResolvedPackages = GRAPH_LIMITS.decode(
        &read_immutable_document_in(
            &input.join("packages.json"),
            &command.nix_store,
            &CancellationToken::default(),
        )?,
        "native resolved packages",
    )?;
    let deployment = Deployment::decode(
        &read_immutable_document_in(
            &input.join("transaction.json"),
            &command.nix_store,
            &CancellationToken::default(),
        )?,
        &packages,
    )?;
    let receipt = Receipt {
        path: read_descriptor_in(
            &command.admission,
            &command.nix_store,
            &CancellationToken::default(),
        )?
        .0,
        digest: command.admission_sha256,
    };
    let mut admission = Admission::new(command.nix_store.clone())?;
    admission.load_retained(&command.state_directory.join("admissions"))?;
    let receipt_root = admission.add(receipt.clone())?;
    ensure!(
        deployment.inputs().contains(&receipt_root),
        "native transaction does not retain its image admission receipt"
    );
    Ok((deployment, admission, receipt))
}

fn check_root(root: &str) -> Result<()> {
    let (canonical, suffix) = crate::deployment::nix::store_root_and_suffix(Path::new(root))?;
    ensure!(
        suffix.as_os_str().is_empty() && canonical == Path::new(root),
        "admitted artifact must be a canonical store root"
    );
    Ok(())
}

pub(crate) fn read_regular_document(path: &Path) -> Result<Vec<u8>> {
    if path.starts_with("/nix/store") {
        let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
        return read_immutable_document_in(path, &executable, &CancellationToken::default());
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= GRAPH_LIMITS.max_bytes as u64,
        "native document must be a bounded regular file"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() <= GRAPH_LIMITS.max_bytes,
        "native document exceeds its byte bound"
    );
    Ok(bytes)
}

fn persist_receipt(directory: &Path, receipt: &Receipt) -> Result<()> {
    fs::create_dir_all(directory)?;
    ensure!(
        fs::symlink_metadata(directory)?.is_dir(),
        "admission receipt directory is not private storage"
    );
    let bytes = serde_json::to_vec(receipt)?;
    let path = directory.join(format!("{}.json", Sha256Digest::of_bytes(&bytes).hex()));
    let temporary = directory.join(format!(".receipt-{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::File::open(&temporary)?.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

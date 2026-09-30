//! Native evaluation and transaction publication for signed registry installs.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::journal::JournalLimits;

use crate::config::ApmConfig;
use crate::deployment::evaluation::{Evaluation, resolve_packages};
use crate::deployment::model::Deployment;
use crate::deployment::retention::ArtifactAdmission;
use crate::deployment::retention::NixStore;
use crate::native_deployment::{EvaluationInput, EvaluationInputs};
use crate::native_registry::{NativeRegistry, RegistryAdmission};
use crate::profile::deployment::ProfileDeployment;
use crate::profile::{Generation, Profile};
use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::ResolvedClosure;
use crate::types::{InstalledMeta, PackageMeta};

/// Realizes pinned module companions before invoking the pure package resolver.
pub(crate) async fn realize_modules(
    config: &ApmConfig,
    registries: &RegistrySet,
    closures: &[ResolvedClosure],
    printer: &aos_core::output::Printer,
    download_only: bool,
    temporary_roots: &mut Option<crate::store::temp_roots::TemporaryRoots>,
) -> Result<Vec<(String, PackageMeta)>> {
    let mut pending = closures
        .iter()
        .flat_map(|closure| {
            closure.closure.iter().filter_map(|meta| {
                meta.deployment
                    .as_ref()
                    .map(|_| (closure.registry_name.clone(), meta.clone()))
            })
        })
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut discovered = Vec::new();
    while let Some((registry_name, meta)) = pending.pop() {
        if !seen.insert((
            meta.name.clone(),
            meta.version.clone(),
            meta.store_path.clone(),
        )) {
            continue;
        }
        ensure!(
            seen.len() <= 16_384,
            "native module companion closure exceeds its bound"
        );
        let artifact = meta
            .deployment
            .as_ref()
            .context("native companion has no envelope")?;
        let envelope = if download_only {
            let results = realize_companions(
                config,
                registries,
                &registry_name,
                &meta,
                printer,
                true,
                temporary_roots,
            )
            .await?;
            cached_envelope(artifact, &meta, &results)?
        } else {
            crate::native_artifact::read_envelope(
                artifact,
                &meta.name,
                &meta.version,
                &meta.platform,
            )?
        };
        for source in envelope.module_dependencies {
            let candidates = registries
                .all_versions(&source.name)
                .into_iter()
                .filter(|(_, meta)| meta.version == source.version && meta.deployment.is_some())
                .map(|(registry, meta)| (registry.config.name.clone(), meta.clone()))
                .collect::<Vec<_>>();
            let mut selected = None;
            let mut selected_envelope = None;
            for (registry_name, meta) in candidates {
                let results = realize_companions(
                    config,
                    registries,
                    &registry_name,
                    &meta,
                    printer,
                    download_only,
                    temporary_roots,
                )
                .await?;
                let artifact = meta
                    .deployment
                    .as_ref()
                    .context("native dependency has no envelope")?;
                let candidate = if download_only {
                    cached_envelope(artifact, &meta, &results)?
                } else {
                    crate::native_artifact::read_envelope(
                        artifact,
                        &meta.name,
                        &meta.version,
                        &meta.platform,
                    )?
                };
                if candidate.module.as_ref() == Some(&source) {
                    if let Some(previous) = &selected_envelope {
                        ensure!(
                            crate::native_registry::same_package_context(previous, &candidate),
                            "pinned native module source has ambiguous authenticated artifact contexts"
                        );
                    } else {
                        selected_envelope = Some(candidate);
                        selected = Some((registry_name, meta));
                    }
                }
            }
            let selected = selected.with_context(|| {
                format!(
                    "pinned native module {}@{} is unavailable",
                    source.name, source.version
                )
            })?;
            discovered.push(selected.clone());
            pending.push(selected);
        }
        for dependency in envelope.runtime_dependencies.values() {
            if seen.iter().any(|(name, version, path)| {
                name == &dependency.name
                    && version == &dependency.version
                    && path == &dependency.path
            }) {
                continue;
            }
            let candidates = registries
                .all_versions(&dependency.name)
                .into_iter()
                .filter(|(_, meta)| meta.version == dependency.version && meta.deployment.is_some())
                .map(|(registry, meta)| (registry.config.name.clone(), meta.clone()))
                .collect::<Vec<_>>();
            let mut selected = None;
            let mut selected_envelope = None;
            for (registry, meta) in candidates {
                let results = realize_companions(
                    config,
                    registries,
                    &registry,
                    &meta,
                    printer,
                    download_only,
                    temporary_roots,
                )
                .await?;
                let artifact = meta
                    .deployment
                    .as_ref()
                    .context("native runtime package lacks its envelope")?;
                let candidate = if download_only {
                    cached_envelope(artifact, &meta, &results)?
                } else {
                    crate::native_artifact::read_envelope(
                        artifact,
                        &meta.name,
                        &meta.version,
                        &meta.platform,
                    )?
                };
                if selected_artifact_matches(&candidate.package, dependency) {
                    if let Some(previous) = &selected_envelope {
                        ensure!(
                            crate::native_registry::same_package_context(previous, &candidate),
                            "native runtime artifact has ambiguous authenticated package contexts"
                        );
                    } else {
                        selected_envelope = Some(candidate);
                        selected = Some((registry, meta));
                    }
                }
            }
            let selected = selected.with_context(|| {
                format!(
                    "native runtime dependency {}@{} lacks an authenticated exact envelope",
                    dependency.name, dependency.version
                )
            })?;
            discovered.push(selected.clone());
            pending.push(selected);
        }
    }
    Ok(discovered)
}

async fn realize_companions(
    config: &ApmConfig,
    registries: &RegistrySet,
    registry_name: &str,
    meta: &PackageMeta,
    printer: &aos_core::output::Printer,
    download_only: bool,
    temporary_roots: &mut Option<crate::store::temp_roots::TemporaryRoots>,
) -> Result<Vec<crate::download::DownloadResult>> {
    let registry = registries
        .get_registry(registry_name)
        .context("native companion registry is unavailable")?;
    ensure!(
        registry.release_trust().is_some() && registry.store_map().is_present(),
        "native companion discovery requires an authenticated signed release graph"
    );
    let artifacts = [&meta.deployment, &meta.module_documentation]
        .into_iter()
        .flatten()
        .map(|artifact| super::SecondaryArtifactDownload {
            registry_name: registry_name.to_owned(),
            store_path: artifact.store_path.clone(),
            nar_hash: artifact.nar_hash.clone(),
            trust_graph_root: true,
            requires_empty_references: false,
        })
        .collect::<Vec<_>>();
    let paths = artifacts
        .iter()
        .map(|artifact| artifact.store_path.clone())
        .collect::<Vec<_>>();
    let missing = if download_only {
        paths
    } else {
        crate::store::filter_missing(&paths).await?
    };
    let requests = super::build_secondary_artifact_download_requests(
        registries,
        &artifacts,
        &missing,
        download_only,
        config,
    )?;
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let roots = artifacts
        .iter()
        .map(|artifact| (registry_name, store_path_hash(&artifact.store_path)))
        .collect::<Vec<_>>();
    let trust = registries.trust_context_for_roots(&roots);
    trust.enforce_totality()?;
    let resolved = crate::download::fetch_narinfo_closure(
        std::sync::Arc::new(crate::download::default_engine()),
        &requests,
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    let results = crate::download::download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    crate::verify::verify_downloads(&results, &trust, printer)?;
    super::verify_secondary_artifact_downloads(&results, &artifacts)?;
    if download_only {
        return Ok(results);
    }
    if let Some(lease) = temporary_roots.as_mut() {
        lease.retain(
            results.iter().map(|result| result.store_path.clone()),
            &Default::default(),
        )?;
    }
    for result in &results {
        crate::store::import_nar_with_compression(
            &result.local_path,
            &result.store_path,
            &result.references,
            result.deriver.as_deref(),
            &result.compression,
        )
        .await?;
    }
    Ok(results)
}

fn cached_envelope(
    artifact: &crate::types::NativeArtifactMeta,
    package: &PackageMeta,
    results: &[crate::download::DownloadResult],
) -> Result<crate::deployment::model::Envelope> {
    use std::io::Read;
    let result = results
        .iter()
        .find(|result| result.store_path == artifact.store_path)
        .context("native envelope cache result is absent")?;
    ensure!(
        artifact.nar_size <= 16 * 1024 * 1024,
        "native envelope NAR exceeds its document boundary"
    );
    crate::verify::verify_nar_identity_with_compression(
        &result.local_path,
        &artifact.nar_hash,
        artifact.nar_size,
        &result.compression,
    )?;
    let file = std::fs::File::open(&result.local_path)?;
    let reader: Box<dyn Read> = match result.compression.as_str() {
        "none" => Box::new(file),
        "zstd" => Box::new(zstd::stream::read::Decoder::new(file)?),
        compression => anyhow::bail!("unsupported native envelope compression {compression}"),
    };
    let mut nar = Vec::new();
    reader.take(artifact.nar_size + 1).read_to_end(&mut nar)?;
    ensure!(
        nar.len() as u64 == artifact.nar_size,
        "native envelope NAR size changed"
    );
    let document = aos_doc_model::decode_native_artifact_nar(&nar, "deployment.json")?;
    ensure!(
        document.len() as u64 == artifact.document_size
            && aos_contract::Sha256Digest::of_bytes(document).to_string()
                == artifact.document_sha256,
        "native envelope document differs from authenticated metadata"
    );
    let envelope = crate::deployment::model::Envelope::decode(document)?;
    ensure!(
        envelope.package.name == package.name
            && envelope.package.version == package.version
            && envelope.system == package.platform,
        "cached native envelope has another package coordinate"
    );
    Ok(envelope)
}

fn select_payload(
    payloads: &mut Vec<crate::deployment::model::Artifact>,
    envelope: &crate::deployment::model::Envelope,
    path: &str,
) -> Result<()> {
    ensure!(
        envelope
            .package
            .outputs
            .values()
            .any(|output| output == path),
        "selected output is absent from its authenticated native envelope"
    );
    let mut selected = envelope.package.clone();
    selected.path = path.into();
    payloads.push(selected);
    Ok(())
}

// A selected named output carries the canonical package identity and output
// map. Only its payload locator changes; its envelope and module remain exact.
fn selected_artifact_matches(
    canonical: &crate::deployment::model::Artifact,
    selected: &crate::deployment::model::Artifact,
) -> bool {
    if !canonical
        .outputs
        .values()
        .any(|path| path == &selected.path)
    {
        return false;
    }
    let mut expected = canonical.clone();
    expected.path.clone_from(&selected.path);
    expected == *selected
}

fn resolve_scope_packages(
    system: &str,
    modules: Vec<crate::deployment::model::Envelope>,
    payloads: Vec<crate::deployment::model::Artifact>,
    resolver: &mut impl crate::deployment::evaluation::PackageResolver,
) -> Result<crate::deployment::model::ResolvedPackages> {
    let mut resolved = resolve_packages(system, modules, resolver)?;
    // Module imports supply availability catalogs. Installation is determined
    // independently by the caller's selected payloads, including aliases.
    resolved.artifacts.clear();
    for payload in payloads {
        if let Some(previous) = resolved
            .artifacts
            .iter()
            .find(|artifact| artifact.path == payload.path)
        {
            ensure!(
                previous == &payload,
                "selected payload has conflicting native artifact identities"
            );
        } else {
            resolved.artifacts.push(payload);
        }
    }
    resolved
        .artifacts
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(resolved)
}

pub(crate) struct Prepared {
    config: ApmConfig,
    deployment: Deployment,
    admission: RegistryAdmission,
    executable: PathBuf,
    evaluation_input: PathBuf,
    _temporary_roots: crate::store::temp_roots::TemporaryRoots,
    pub(crate) additional: Vec<(String, PackageMeta)>,
}

pub(crate) fn recover(profile: &Profile) -> Result<()> {
    if !profile
        .path
        .join("deployment/generations.journal")
        .is_file()
    {
        ensure!(
            !profile.path.join("deployment/effects.journal").exists(),
            "native profile journal is partially initialized"
        );
        return Ok(());
    }
    let executable = packaged_path("AOS_NIX_STORE")?;
    let admission = RegistryAdmission::new(
        executable.clone(),
        &profile.path.join("deployment/registry-admissions"),
    )?;
    let store = NixStore::open(executable, profile.path.join("deployment/roots"), admission)?;
    let mut consumer = ProfileDeployment::open(profile, store, JournalLimits::default())?;
    let cancellation = crate::cancellation::AbilityCancellationGuard::install()?;
    crate::native_deployment::configure_profile_observer(
        &mut consumer,
        profile,
        None,
        cancellation.token(),
    )?;
    consumer.recover(cancellation.token())
}

pub(crate) fn prepare(
    config: &ApmConfig,
    profile: &Profile,
    registries: &RegistrySet,
    installed: &[InstalledMeta],
    closures: &[ResolvedClosure],
    realized_modules: &[(String, PackageMeta)],
    obsolete: &HashSet<String>,
) -> Result<Prepared> {
    prepare_with_inputs(
        config,
        profile,
        registries,
        installed,
        closures,
        realized_modules,
        obsolete,
        None,
    )
}

fn prepare_with_inputs(
    config: &ApmConfig,
    profile: &Profile,
    registries: &RegistrySet,
    installed: &[InstalledMeta],
    closures: &[ResolvedClosure],
    realized_modules: &[(String, PackageMeta)],
    obsolete: &HashSet<String>,
    runtime: Option<&crate::runtime_modules::RuntimeModuleSnapshot>,
) -> Result<Prepared> {
    for meta in closures.iter().flat_map(|closure| &closure.closure) {
        ensure!(
            meta.deployment.is_some(),
            "package {}@{} has no native deployment envelope",
            meta.name,
            meta.version
        );
    }
    for meta in installed {
        ensure!(
            meta.apm
                .as_ref()
                .is_some_and(|package| package.deployment.is_some()),
            "installed root {} has no authenticated native package envelope",
            meta.store_path
        );
    }
    let executable = packaged_path("AOS_NIX_STORE")?;
    let mut temporary_roots =
        crate::store::temp_roots::TemporaryRoots::open(&executable, &Default::default())?;

    let mut admission = RegistryAdmission::new(
        executable.clone(),
        &profile.path.join("deployment/registry-admissions"),
    )?;
    let mut retained_modules = BTreeSet::new();
    let mut evaluation_inputs = match profile.current_generation()? {
        Some(generation) if generation.path.join("native-deployment.json").is_file() => {
            let committed =
                crate::profile::deployment::committed_generation(&profile.path, generation.number)?;
            let (_, descriptor) = crate::native_deployment::read_retained_evaluation_in(
                &generation.path.join("evaluation.json"),
                &committed.deployment,
                &executable,
                &aos_ability_runtime::adapter::CancellationToken::default(),
            )?;
            retained_modules.extend(
                descriptor
                    .packages
                    .modules
                    .into_iter()
                    .map(|module| module.name),
            );
            let inputs = EvaluationInputs {
                library: descriptor.library,
                configuration: descriptor.configuration,
                runtime_configuration: descriptor.runtime_configuration,
                supplemental_inputs: descriptor.supplemental_inputs,
            };
            for path in std::iter::once(&inputs.library)
                .chain(&inputs.configuration)
                .chain(&inputs.runtime_configuration)
                .chain(&inputs.supplemental_inputs)
            {
                let (root, _) = crate::deployment::nix::store_root_and_suffix(path)?;
                admission.admit(root.to_str().context("evaluation input is not UTF-8")?)?;
            }
            inputs
        }
        _ => {
            let library = packaged_path("AOS_PACKAGE_MODULE_LIBRARY")?;
            let (root, _) = crate::deployment::nix::store_root_and_suffix(&library)?;
            admission.trust_runtime_input(root.to_str().context("module library is not UTF-8")?)?;
            EvaluationInputs {
                library,
                configuration: Vec::new(),
                runtime_configuration: Vec::new(),
                supplemental_inputs: Vec::new(),
            }
        }
    };
    if let Some(runtime) = runtime {
        admission.trust_runtime_input(
            runtime
                .store_path
                .to_str()
                .context("runtime snapshot is not UTF-8")?,
        )?;
        evaluation_inputs.runtime_configuration = runtime.entrypoints.clone();
    }
    let mut resolver = NativeRegistry::new(registries, admission);
    let mut roots = Vec::new();
    let mut payloads = Vec::new();
    let mut selected = BTreeSet::new();
    for closure in closures {
        for meta in &closure.closure {
            let explicit_module = meta.store_path == closure.root.store_path;
            if selected.insert(meta.store_path.clone()) || explicit_module {
                let envelope = resolver.package(&closure.registry_name, meta)?;
                if explicit_module {
                    roots.push(envelope.clone());
                }
                select_payload(&mut payloads, &envelope, &meta.store_path)?;
            }
        }
    }
    for meta in installed {
        if !obsolete.contains(store_path_hash(&meta.store_path))
            && selected.insert(meta.store_path.clone())
        {
            let envelope = resolver.installed(meta)?;
            if retained_modules.contains(&envelope.package.name) {
                roots.push(envelope.clone());
            }
            select_payload(&mut payloads, &envelope, &meta.store_path)?;
        }
    }
    for (registry, meta) in realized_modules {
        // Companions populate the authenticated resolver and retention catalog.
        // Runtime payload metadata does not make its optional module a root.
        resolver.package(registry, meta)?;
    }
    let packages = resolve_scope_packages(
        &crate::platform::native_platform(),
        roots,
        payloads,
        &mut resolver,
    )?;
    let additional = packages
        .artifacts
        .iter()
        .filter(|artifact| !selected.contains(&artifact.path))
        .map(|artifact| resolver.metadata(&artifact.path))
        .collect::<Result<Vec<_>>>()?;
    let scope = vec![
        "profile".into(),
        match profile.scope {
            crate::types::ProfileScope::System => "system".into(),
            crate::types::ProfileScope::User => profile
                .path
                .to_str()
                .context("profile path is not UTF-8")?
                .into(),
        },
    ];
    let retained_inputs: Vec<PathBuf> = resolver
        .retained_inputs()
        .into_iter()
        .chain(evaluation_inputs.supplemental_inputs.iter().cloned())
        .chain(runtime.map(|snapshot| snapshot.store_path.clone()))
        .collect();
    let mut admission = resolver.into_admission();
    let (library_root, _) =
        crate::deployment::nix::store_root_and_suffix(&evaluation_inputs.library)?;
    let (library_nar_hash, _) = crate::store::verification::dump_store_path_identity_in(
        library_root
            .to_str()
            .context("module library root is not UTF-8")?,
        Some(&executable),
    )?;
    let descriptor = EvaluationInput {
        schema: "aos.package.evaluation-input".into(),
        library: evaluation_inputs.library.clone(),
        library_nar_hash,
        scope: scope.clone(),
        packages: packages.clone(),
        configuration: evaluation_inputs.configuration.clone(),
        runtime_configuration: evaluation_inputs.runtime_configuration.clone(),
        supplemental_inputs: evaluation_inputs.supplemental_inputs.clone(),
    };
    let staging = tempfile::tempdir_in(&profile.path)?;
    let cancellation = crate::cancellation::AbilityCancellationGuard::install()?;
    temporary_roots.retain(
        retained_inputs
            .iter()
            .chain([&evaluation_inputs.library])
            .chain(evaluation_inputs.configuration.iter())
            .chain(evaluation_inputs.runtime_configuration.iter())
            .map(|path| {
                crate::deployment::nix::store_root_and_suffix(path).and_then(|(root, _)| {
                    Ok(root
                        .to_str()
                        .context("evaluation root is not UTF-8")?
                        .to_owned())
                })
            })
            .collect::<Result<Vec<_>>>()?,
        cancellation.token(),
    )?;
    let evaluation_input = descriptor.import_retained(
        &executable,
        staging.path(),
        cancellation.token(),
        &mut temporary_roots,
    )?;
    admission.trust_runtime_input(
        evaluation_input
            .to_str()
            .context("evaluation descriptor is not UTF-8")?,
    )?;
    let evaluation = Evaluation {
        nix_store: executable.clone(),
        library: descriptor.library,
        scope,
        packages,
        configuration: descriptor
            .configuration
            .into_iter()
            .chain(descriptor.runtime_configuration)
            .collect(),
        retained_inputs,
        evaluation_input: Some(evaluation_input.clone()),
    };
    let deployment = evaluation.evaluate(staging.path(), 60_000, cancellation.token())?;
    ensure!(
        profile.scope == config.scope,
        "native install profile differs from configured scope"
    );
    Ok(Prepared {
        config: config.clone(),
        deployment,
        admission,
        executable,
        evaluation_input,
        _temporary_roots: temporary_roots,
        additional,
    })
}

impl Prepared {
    pub(crate) fn selected_paths(&self) -> BTreeSet<&str> {
        self.deployment
            .artifacts()
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect()
    }

    pub(crate) fn commit(mut self, profile: &Profile, generation: &Generation) -> Result<()> {
        let cancellation = crate::cancellation::AbilityCancellationGuard::install()?;
        self.admission.realize_inputs(
            &self.config,
            self.deployment.inputs(),
            &mut self._temporary_roots,
            cancellation.token(),
        )?;
        EvaluationInputs::retain_descriptor(&self.evaluation_input, generation)?;
        // Authorization must be durable before a transaction can become pending.
        self.admission
            .persist(&profile.path.join("deployment/registry-admissions"))?;
        let store = NixStore::open(
            self.executable,
            profile.path.join("deployment/roots"),
            self.admission,
        )?;
        let mut consumer = ProfileDeployment::open(profile, store, JournalLimits::default())?;
        crate::native_deployment::configure_profile_observer(
            &mut consumer,
            profile,
            Some((&self.evaluation_input, &self.deployment)),
            cancellation.token(),
        )?;
        consumer.apply(&self.deployment, generation, cancellation.token())
    }
}

/// Evaluates and optionally commits a replacement operator worktree snapshot.
pub(crate) fn reconfigure(
    config: &ApmConfig,
    runtime: &crate::runtime_modules::RuntimeModuleSnapshot,
    dry_run: bool,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);
    reconfigure_at(config, &profile, runtime, dry_run, printer)
}

/// Reuses normal native source replacement for an explicit profile owner.
pub(crate) fn reconfigure_at(
    config: &ApmConfig,
    profile: &Profile,
    runtime: &crate::runtime_modules::RuntimeModuleSnapshot,
    dry_run: bool,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    ensure!(
        profile.scope == config.scope,
        "native profile scope differs from operator scope"
    );
    let _profile_guard = if dry_run {
        None
    } else {
        Some(profile.lock_mutation()?)
    };
    if !dry_run {
        recover(profile)?;
    }
    let current = profile
        .current_generation()?
        .context("native configuration requires an active profile")?;
    let base = crate::profile::deployment::committed_generation(&profile.path, current.number)?;
    let installed = crate::profile::meta::list_meta(&profile)?;
    let registries = crate::registry::RegistrySet::new(Vec::new());
    let prepared = prepare_with_inputs(
        config,
        &profile,
        &registries,
        &installed,
        &[],
        &[],
        &HashSet::new(),
        Some(runtime),
    )?;
    ensure!(
        prepared.additional.is_empty(),
        "runtime configuration selected uninstalled native packages"
    );
    let before: BTreeSet<_> = base.deployment.graph().graph().nodes.keys().collect();
    let after: BTreeSet<_> = prepared.deployment.graph().graph().nodes.keys().collect();
    let changed = after
        .intersection(&before)
        .filter(|key| {
            base.deployment.graph().graph().nodes[**key].revision
                != prepared.deployment.graph().graph().nodes[**key].revision
        })
        .collect::<Vec<_>>();
    if printer.mode() == aos_core::output::OutputMode::Json {
        printer.json(&serde_json::json!({"action":"switch","dry_run":dry_run,
            "before":base.content,"after":prepared.deployment.id()?,
            "added":after.difference(&before).collect::<Vec<_>>(),
            "removed":before.difference(&after).collect::<Vec<_>>(), "changed":changed}));
    } else {
        printer.info(&format!(
            "Native configuration: {} added, {} changed, {} removed effects.",
            after.difference(&before).count(),
            changed.len(),
            before.difference(&after).count()
        ));
    }
    if dry_run {
        return Ok(());
    }
    let generation = profile.new_generation()?;
    super::copy_roots_except_hashes(&current, &generation, &HashSet::new())?;
    let selected = prepared.selected_paths();
    let staged = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    for (hash, path) in generation.roots()? {
        if !selected.contains(path.to_str().context("profile root is not UTF-8")?) {
            std::fs::remove_file(generation.path.join("usr").join(hash))?;
        }
    }
    for meta in &installed {
        if selected.contains(meta.store_path.as_str()) {
            crate::profile::meta::write_meta(&staged, store_path_hash(&meta.store_path), meta)?;
        }
    }
    crate::profile::merge::build_generation_fhs_tree(&generation, printer)?;
    prepared.commit(&profile, &generation)?;
    printer.success(&format!("Configured generation {}.", generation.number));
    Ok(())
}

/// Appends an authored operator snapshot after the existing ordered runtime sources.
pub(crate) fn append_runtime_snapshot(
    config: &ApmConfig,
    snapshot: &crate::runtime_modules::RuntimeModuleSnapshot,
    printer: &aos_core::output::Printer,
) -> Result<(Generation, Deployment)> {
    let inspection = Profile::open_readonly(config.scope);
    let _profile_guard = inspection.lock_mutation()?;
    let profile = Profile::open(config.scope)?;
    recover(&profile)?;
    let current = profile
        .current_generation()?
        .context("native source append requires a committed profile")?;
    let committed =
        crate::profile::deployment::committed_generation(&profile.path, current.number)?;
    let (_, input) = crate::native_deployment::read_retained_evaluation_in(
        &current.path.join("evaluation.json"),
        &committed.deployment,
        &packaged_path("AOS_NIX_STORE")?,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )?;
    let mut combined = snapshot.clone();
    combined.entrypoints = input
        .runtime_configuration
        .into_iter()
        .chain(snapshot.entrypoints.iter().cloned())
        .collect();
    let installed = crate::profile::meta::list_meta(&profile)?;
    let prepared = prepare_with_inputs(
        config,
        &profile,
        &RegistrySet::new(Vec::new()),
        &installed,
        &[],
        &[],
        &HashSet::new(),
        Some(&combined),
    )?;
    ensure!(
        prepared.additional.is_empty(),
        "native source append requires packages absent from the committed profile"
    );
    let desired = prepared.deployment.clone();
    let generation = profile.new_generation()?;
    super::copy_roots_except_hashes(&current, &generation, &HashSet::new())?;
    let staged = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    for meta in &installed {
        crate::profile::meta::write_meta(&staged, store_path_hash(&meta.store_path), meta)?;
    }
    crate::profile::merge::build_generation_fhs_tree(&generation, printer)?;
    prepared.commit(&profile, &generation)?;
    Ok((generation, desired))
}

/// Checks original admission for a retained native rollback target without effects.
pub(crate) fn probe_rollback(profile: &Profile, target: &Generation) -> Result<Deployment> {
    let committed = crate::profile::deployment::committed_generation(&profile.path, target.number)?;
    let descriptor = target.path.join("evaluation.json");
    let (_, input) = crate::native_deployment::read_retained_evaluation_in(
        &descriptor,
        &committed.deployment,
        &packaged_path("AOS_NIX_STORE")?,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )?;
    ensure!(
        input.scope == committed.deployment.scope()
            && input.packages == committed.deployment.resolved(),
        "rollback descriptor differs from its committed native deployment"
    );
    let mut admission = RegistryAdmission::new(
        packaged_path("AOS_NIX_STORE")?,
        &profile.path.join("deployment/registry-admissions"),
    )?;
    EvaluationInputs::read(&descriptor)?.admit(&committed.deployment, &mut admission)?;
    for root in committed.deployment.inputs().iter().chain(
        committed
            .deployment
            .artifacts()
            .iter()
            .map(|artifact| &artifact.path),
    ) {
        admission.admit(root)?;
    }
    Ok(committed.deployment)
}

/// Reconciles an old checked desired deployment as a new profile transaction.
pub(crate) fn rollback(
    profile: &Profile,
    target: &Generation,
    printer: &aos_core::output::Printer,
) -> Result<Generation> {
    let _profile_guard = profile.lock_mutation()?;
    rollback_locked(profile, target, printer)
}

/// Reconciles a rollback while its caller retains profile mutation ownership.
pub(crate) fn rollback_locked(
    profile: &Profile,
    target: &Generation,
    printer: &aos_core::output::Printer,
) -> Result<Generation> {
    let desired = probe_rollback(profile, target)?;
    let evaluation = EvaluationInputs::read(&target.path.join("evaluation.json"))?;
    let executable = packaged_path("AOS_NIX_STORE")?;
    let mut admission = RegistryAdmission::new(
        executable.clone(),
        &profile.path.join("deployment/registry-admissions"),
    )?;
    evaluation.admit(&desired, &mut admission)?;
    let generation = profile.new_generation()?;
    super::copy_roots_except_hashes(target, &generation, &HashSet::new())?;
    let staged = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    for (hash, _) in target.roots()? {
        let metadata = crate::profile::meta::read_generation_meta(target, &hash)?
            .context("native rollback payload metadata is absent")?;
        crate::profile::meta::write_meta(&staged, &hash, &metadata)?;
    }
    crate::profile::merge::build_generation_fhs_tree(&generation, printer)?;
    EvaluationInputs::retain_descriptor(&target.path.join("evaluation.json"), &generation)?;
    let store = NixStore::open(executable, profile.path.join("deployment/roots"), admission)?;
    let mut consumer = ProfileDeployment::open(profile, store, JournalLimits::default())?;
    let cancellation = crate::cancellation::AbilityCancellationGuard::install()?;
    crate::native_deployment::configure_profile_observer(
        &mut consumer,
        profile,
        Some((&target.path.join("evaluation.json"), &desired)),
        cancellation.token(),
    )?;
    consumer.apply(&desired, &generation, cancellation.token())?;
    Ok(generation)
}

/// Releases a retained native generation before its profile tree is deleted.
pub(crate) fn prune(profile: &Profile, generation: &Generation) -> Result<()> {
    let executable = packaged_path("AOS_NIX_STORE")?;
    let admission = RegistryAdmission::new(
        executable.clone(),
        &profile.path.join("deployment/registry-admissions"),
    )?;
    let store = NixStore::open(executable, profile.path.join("deployment/roots"), admission)?;
    let mut consumer = ProfileDeployment::open(profile, store, JournalLimits::default())?;
    consumer.prune(generation)
}

pub(crate) fn packaged_path(variable: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(variable)
            .with_context(|| format!("packaged native runtime omitted {variable}"))?,
    );
    ensure!(
        path.is_absolute(),
        "{variable} must identify an absolute packaged input"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::evaluation::PackageResolver;
    use crate::deployment::model::{Artifact, Envelope, ModuleSource};
    use std::collections::BTreeMap;

    struct NoModuleDependencies;

    impl PackageResolver for NoModuleDependencies {
        fn resolve(&mut self, _: &ModuleSource) -> Result<Envelope> {
            anyhow::bail!("test package has no module dependency")
        }
    }

    fn package(name: &str, hash: char) -> Envelope {
        let root = format!("/nix/store/{}-{name}", hash.to_string().repeat(32));
        Envelope {
            schema: "aos.package.deployment".into(),
            system: "x86_64-linux".into(),
            package: Artifact {
                name: name.into(),
                version: "1.0.0".into(),
                path: root.clone(),
                outputs: BTreeMap::from([("out".into(), root)]),
                main_program: None,
            },
            module: Some(ModuleSource {
                name: name.into(),
                version: "1.0.0".into(),
                source: format!("/nix/store/{}-{name}-module", "f".repeat(32)),
                entrypoint: "module.nix".into(),
            }),
            runtime_dependencies: BTreeMap::new(),
            module_dependencies: Vec::new(),
        }
    }

    #[test]
    fn runtime_payload_with_optional_module_requires_explicit_module_selection() {
        let dependency = package("optional-service", 'b');
        let mut selected = package("application", 'a');
        selected
            .runtime_dependencies
            .insert("helper".into(), dependency.package.clone());
        let payloads = vec![selected.package.clone(), dependency.package.clone()];
        let mut resolver = NoModuleDependencies;

        let resolved = resolve_scope_packages(
            "x86_64-linux",
            vec![selected.clone()],
            payloads.clone(),
            &mut resolver,
        )
        .unwrap();
        assert_eq!(resolved.artifacts.len(), 2);
        assert_eq!(
            resolved
                .modules
                .iter()
                .map(|module| module.name.as_str())
                .collect::<Vec<_>>(),
            vec!["application"]
        );

        let explicit = resolve_scope_packages(
            "x86_64-linux",
            vec![selected, dependency],
            payloads,
            &mut resolver,
        )
        .unwrap();
        assert_eq!(
            explicit
                .modules
                .iter()
                .map(|module| module.name.as_str())
                .collect::<Vec<_>>(),
            vec!["application", "optional-service"]
        );
    }

    #[test]
    fn selected_named_output_preserves_module_context_without_selecting_other_outputs() {
        let mut envelope = package("library", 'a');
        let development = format!("/nix/store/{}-library-dev", "b".repeat(32));
        envelope
            .package
            .outputs
            .insert("dev".into(), development.clone());
        let original = envelope.clone();
        let mut selected = envelope.package.clone();
        selected.path.clone_from(&development);
        assert!(selected_artifact_matches(&envelope.package, &selected));
        selected.version = "2.0.0".into();
        assert!(!selected_artifact_matches(&envelope.package, &selected));

        let mut payloads = Vec::new();
        select_payload(&mut payloads, &envelope, &development).unwrap();

        let resolved = resolve_scope_packages(
            "x86_64-linux",
            vec![envelope.clone()],
            payloads,
            &mut NoModuleDependencies,
        )
        .unwrap();
        assert_eq!(envelope, original);
        assert_eq!(resolved.artifacts.len(), 1);
        assert!(
            resolved
                .artifacts
                .iter()
                .any(|artifact| artifact.path == development)
        );
        assert!(
            !resolved
                .artifacts
                .iter()
                .any(|artifact| artifact.path == original.package.path)
        );
        assert_eq!(resolved.modules.len(), 1);
    }
}

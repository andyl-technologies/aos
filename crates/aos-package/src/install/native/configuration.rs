//! Acquires host-selected package modules before a single native transaction.
//!
//! Selection reads declared package names from the retained Nix fixed point.
//! Registry acquisition imports immutable inputs without changing live state;
//! complete evaluation and publication still use the ordinary coordinator.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context as _, Result};
use aos_ability_runtime::adapter::CancellationToken;
use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::deployment::evaluation::Evaluation;
use crate::deployment::model::Deployment;
use crate::native_deployment::EvaluationInput;
use crate::profile::{Generation, Profile};
use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::ResolvedClosure;
use crate::store::temp_roots::TemporaryRoots;
use crate::types::{ApmMeta, InstalledMeta, PackageMeta};

/// Publishes acquired host roots and authored sources in one generation.
///
/// The caller holds the profile mutation lock and has authenticated the supplied
/// baseline and every new source before entering this path.
pub(crate) fn apply_from_descriptor(
    config: &ApmConfig,
    profile: &Profile,
    installed: &[InstalledMeta],
    descriptor: EvaluationInput,
    baseline: Deployment,
    names: BTreeSet<String>,
    cancellation: &CancellationToken,
    printer: &Printer,
) -> Result<()> {
    let packages = acquire(config, names, installed, printer)?;
    anyhow::ensure!(
        !cancellation.is_cancelled(),
        "host package acquisition cancelled"
    );
    let prepared = super::prepare_with_inputs(
        config,
        profile,
        &packages.registries,
        installed,
        &packages.closures,
        &packages.modules,
        &Default::default(),
        None,
        None,
        Some((descriptor, baseline)),
        &packages.names,
    )?;
    let generation = profile.new_generation()?;
    stage(&generation, profile, installed, &packages, &prepared)?;
    crate::profile::merge::build_generation_fhs_tree(&generation, printer)?;
    prepared.commit(profile, &generation)
}

pub(super) struct ConfigurationPackages {
    pub(super) names: BTreeSet<String>,
    pub(super) registries: RegistrySet,
    pub(super) closures: Vec<ResolvedClosure>,
    pub(super) modules: Vec<(String, PackageMeta)>,
    // Acquisition roots remain live until the generation has durable custody.
    pub(super) _temporary_roots: Option<TemporaryRoots>,
}

pub(crate) fn selected_packages(
    descriptor: &EvaluationInput,
    executable: &Path,
    cancellation: &CancellationToken,
) -> Result<BTreeSet<String>> {
    let declarations = crate::native_deployment::retained_declarations(
        &descriptor.package_envelopes,
        descriptor.os_release.as_ref(),
        executable,
    )?;
    let evaluation = Evaluation {
        os_release: descriptor.os_release.clone(),
        os_requirements: declarations.os_requirements,
        package_releases: declarations.package_releases,
        nix_store: executable.into(),
        library: descriptor.library.clone(),
        scope: descriptor.scope.clone(),
        packages: descriptor.packages.clone(),
        module_requirements: descriptor
            .resolution_lock
            .as_ref()
            .map_or_else(Vec::new, |lock| lock.module_requirements()),
        configuration: descriptor
            .configuration
            .iter()
            .chain(&descriptor.runtime_configuration)
            .cloned()
            .collect(),
        retained_inputs: descriptor.supplemental_inputs.clone(),
        evaluation_input: None,
    };
    let scratch = tempfile::tempdir()?;
    Ok(evaluation
        .selected_packages(scratch.path(), cancellation)?
        .into_iter()
        .collect())
}

pub(super) fn acquire(
    config: &ApmConfig,
    names: BTreeSet<String>,
    installed: &[InstalledMeta],
    printer: &Printer,
) -> Result<ConfigurationPackages> {
    let missing = names
        .iter()
        .filter(|name| {
            !installed.iter().any(|entry| {
                entry
                    .apm
                    .as_ref()
                    .is_some_and(|package| &package.name == *name)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut temporary_roots = None;
    let (registries, closures, modules) = if missing.is_empty() {
        (RegistrySet::new(Vec::new()), Vec::new(), Vec::new())
    } else {
        // The bridge is also invoked by synchronous boot helpers inside an
        // async process. Use a scoped worker rather than nest Tokio runtimes.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async {
                        let cached = crate::install::load_registries(config);
                        let registries = match cached {
                            Ok(registries)
                                if crate::resolve::resolve_multiple(
                                    &registries,
                                    &missing,
                                    None,
                                )
                                .is_ok() =>
                            {
                                registries
                            }
                            _ => {
                                crate::update::run(config, None, printer)
                                    .await
                                    .context("refreshing registries for host-selected packages")?;
                                crate::install::load_registries(config)?
                            }
                        };
                        let closures = crate::install::acquire::acquire(
                            config,
                            &registries,
                            &missing,
                            printer,
                            &mut temporary_roots,
                        )
                        .await?;
                        let modules = super::realize_modules(
                            config,
                            &registries,
                            &closures,
                            printer,
                            false,
                            &mut temporary_roots,
                        )
                        .await?;
                        Ok::<_, anyhow::Error>((registries, closures, modules))
                    })
                })
                .join()
                .map_err(|_| anyhow::anyhow!("host package acquisition worker panicked"))?
        })?
    };
    Ok(ConfigurationPackages {
        names,
        registries,
        closures,
        modules,
        _temporary_roots: temporary_roots,
    })
}

pub(super) fn stage(
    generation: &Generation,
    profile: &Profile,
    installed: &[InstalledMeta],
    packages: &ConfigurationPackages,
    prepared: &super::Prepared,
) -> Result<()> {
    let staged = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    let selected = prepared.selected_paths();
    std::fs::create_dir_all(generation.path.join("usr"))?;
    for entry in installed {
        if selected.contains(entry.store_path.as_str()) {
            let hash = store_path_hash(&entry.store_path);
            std::os::unix::fs::symlink(&entry.store_path, generation.path.join("usr").join(hash))?;
            let mut metadata = entry.clone();
            if let Some(package) = &mut metadata.apm {
                package.explicit |= packages.names.contains(&package.name);
            }
            crate::profile::meta::write_meta(&staged, hash, &metadata)?;
        }
    }
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    let entries = packages
        .closures
        .iter()
        .flat_map(|closure| {
            closure
                .closure
                .iter()
                .map(|entry| (closure.registry_name.as_str(), entry))
        })
        .chain(
            prepared
                .additional
                .iter()
                .map(|(registry, entry)| (registry.as_str(), entry)),
        );
    let mut written = BTreeSet::new();
    for (registry, entry) in entries {
        if !selected.contains(entry.store_path.as_str())
            || installed
                .iter()
                .any(|existing| existing.store_path == entry.store_path)
            || !written.insert(entry.store_path.clone())
        {
            continue;
        }
        let hash = store_path_hash(&entry.store_path);
        let root = generation.path.join("usr").join(hash);
        if !root.exists() {
            std::os::unix::fs::symlink(&entry.store_path, &root)?;
        }
        let metadata = InstalledMeta {
            store_path: entry.store_path.clone(),
            pushed_at: now,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: now,
            access_count: 0,
            apm: Some(ApmMeta {
                name: entry.name.clone(),
                version: entry.version.clone(),
                explicit: packages.names.contains(&entry.name),
                registry: registry.into(),
                installed_at: crate::install::chrono_iso8601(now),
                held: false,
                source_drv: entry.source_drv.clone(),
                source_nar_hash: entry.source_nar_hash.clone(),
                deployment: entry.deployment.clone(),
                module_documentation: entry.module_documentation.clone(),
                qualification: entry.qualification.clone(),
                attestation: entry.attestation.clone(),
            }),
        };
        crate::profile::meta::write_meta(&staged, hash, &metadata)?;
    }
    Ok(())
}

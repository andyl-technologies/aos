//! Runtime reconciliation for RFC-0001 exposed package systemd units.
//!
//! Exposed packages publish rendered unit files in a separate store artifact.
//! A system package-profile generation roots those artifacts under
//! `gen-N/expose/`, while the live host sees unit-file symlinks in
//! `system.attached/` and an exact APM preset file generated from the current
//! package-profile metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::ApmConfig;
use crate::profile::meta::list_meta;
use crate::profile::{Generation, Profile};
use crate::registry::store_path_hash;
use crate::types::{
    CapabilityKind, InstalledMeta, ProfileScope, ProvidedCapabilityMeta, RequiredCapabilityMeta,
};
use crate::unit_diff::{self, Parsed, UnitDiff};
use aos_core::output::Printer;
use aos_systemd::{JobOutcome, SystemdClient};
use tempfile::TempDir;

const APM_PRESET_REL: &str = "systemd/system-preset/30-aos-apm.preset";
const ATTACHED_REL: &str = "systemd/system.attached";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExposedPackage {
    name: String,
    target: String,
    units: BTreeSet<String>,
    artifact_hash: String,
    artifact_store_path: String,
    provides: Vec<ProvidedCapabilityMeta>,
    uses: Vec<RequiredCapabilityMeta>,
}

/// Rebuild the generation's `expose/` GC-root symlinks from metadata.
///
/// # Errors
///
/// Returns an error if the generation's `expose/` directory cannot be
/// recreated or an artifact symlink cannot be written.
pub(crate) fn rebuild_generation_expose_roots(
    generation: &Generation,
    installed: &[InstalledMeta],
) -> Result<()> {
    let expose_dir = generation.path.join("expose");
    reset_dir(&expose_dir)?;

    let mut rooted = BTreeMap::<String, String>::new();
    for entry in installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if !apm.explicit || apm.expose.is_none() {
            continue;
        }
        let Some(artifact) = apm.expose_artifact.as_ref() else {
            continue;
        };
        rooted.insert(
            store_path_hash(&artifact.store_path).to_string(),
            artifact.store_path.clone(),
        );
    }

    for (hash, store_path) in rooted {
        atomic_symlink(Path::new(&store_path), &expose_dir.join(hash))?;
    }

    Ok(())
}

/// Rebuild the generation's `expose-images/` GC-root symlinks from metadata.
///
/// # Errors
///
/// Returns an error if the generation's `expose-images/` directory cannot be
/// recreated or an image symlink cannot be written.
pub(crate) fn rebuild_generation_expose_image_roots(
    generation: &Generation,
    installed: &[InstalledMeta],
) -> Result<()> {
    let image_dir = generation.path.join("expose-images");
    reset_dir(&image_dir)?;

    let mut rooted = BTreeMap::<String, String>::new();
    for entry in installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if !apm.explicit {
            continue;
        }
        let Some(expose) = apm.expose.as_ref() else {
            continue;
        };
        for image in &expose.images {
            rooted.insert(
                store_path_hash(&image.store_path).to_string(),
                image.store_path.clone(),
            );
        }
    }

    for (hash, store_path) in rooted {
        atomic_symlink(Path::new(&store_path), &image_dir.join(hash))?;
    }

    Ok(())
}

/// Validate a generation's exposed package metadata and rooted artifacts.
///
/// # Errors
///
/// Returns an error if an exposed package is missing its rendered artifact,
/// declares duplicate units, references missing unit files, or has invalid
/// capability routes.
pub(crate) fn validate_generation_exposed_units(
    generation: &Generation,
    installed: &[InstalledMeta],
) -> Result<()> {
    let expose_dir = generation.path.join("expose");
    exposed_packages_from_expose_dir(&expose_dir, installed)?;
    Ok(())
}

/// Reconcile the live systemd unit view from the current system package profile.
///
/// Non-system scopes are a no-op. For system scope, this rewrites the APM
/// attached-unit directory and preset file exactly, disables targets that
/// disappeared since the previous run, reloads systemd, presets current
/// targets, and starts them.
///
/// # Errors
///
/// Returns an error if profile metadata cannot be read, unit artifacts are
/// incomplete, filesystem reconciliation fails, or systemd rejects the live
/// reload/preset/start operations.
pub(crate) async fn reconcile_system_profile(config: &ApmConfig, printer: &Printer) -> Result<()> {
    if config.scope != ProfileScope::System {
        return Ok(());
    }

    let profile = Profile::open_readonly(ProfileScope::System);
    let Some(current) = profile.current_generation()? else {
        return Ok(());
    };
    let installed = list_meta(&profile)?;
    rebuild_generation_expose_roots(&current, &installed)?;

    let packages = exposed_packages(&profile, &installed)?;
    let root = aos_root_path();
    let old_targets = read_existing_preset_targets(&root)?;
    let current_targets = packages
        .iter()
        .map(|package| package.target.clone())
        .collect::<BTreeSet<_>>();
    let removed_targets = old_targets
        .difference(&current_targets)
        .cloned()
        .collect::<Vec<_>>();
    let attached_diff = compute_attached_unit_diff(&root, &packages)?;

    let had_attached_units = has_attached_units(&root)?;
    if packages.is_empty() && removed_targets.is_empty() {
        write_attached_units(&root, &packages)?;
        write_exact_preset(&root, &current_targets)?;
        if had_attached_units {
            apply_systemd_changes(&root, &current_targets, &attached_diff).await?;
        }
        printer.info("No exposed package targets are installed.");
        return Ok(());
    }

    disable_removed_targets(&root, &removed_targets)?;
    write_attached_units(&root, &packages)?;
    write_exact_preset(&root, &current_targets)?;
    apply_systemd_changes(&root, &current_targets, &attached_diff).await?;

    if current_targets.is_empty() {
        printer.info("Removed exposed package target enablement.");
    } else {
        printer.info(&format!(
            "Reconciled {} exposed package target(s).",
            current_targets.len()
        ));
    }

    Ok(())
}

fn exposed_packages(profile: &Profile, installed: &[InstalledMeta]) -> Result<Vec<ExposedPackage>> {
    let expose_dir = profile.current_path().join("expose");
    exposed_packages_from_expose_dir(&expose_dir, installed)
}

fn exposed_packages_from_expose_dir(
    expose_dir: &Path,
    installed: &[InstalledMeta],
) -> Result<Vec<ExposedPackage>> {
    let mut packages = Vec::new();
    let mut unit_owners = BTreeMap::<String, String>::new();
    for entry in installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if !apm.explicit {
            continue;
        }
        let Some(expose) = apm.expose.as_ref() else {
            continue;
        };
        let Some(artifact) = apm.expose_artifact.as_ref() else {
            bail!(
                "installed exposed package '{}' is missing expose artifact metadata",
                apm.name
            );
        };

        let artifact_hash = store_path_hash(&artifact.store_path).to_string();
        let artifact_root = expose_dir.join(&artifact_hash).join("units");

        let mut units = expose.units.iter().cloned().collect::<BTreeSet<_>>();
        units.insert(expose.target.clone());
        for unit in &units {
            let path = artifact_root.join(unit);
            if !path.exists() {
                bail!(
                    "expose artifact for package '{}' is missing unit {} at {}",
                    apm.name,
                    unit,
                    path.display()
                );
            }
            if let Some(owner) = unit_owners.get(unit) {
                bail!(
                    "exposed unit '{}' is declared by both packages '{}' and '{}'",
                    unit,
                    owner,
                    apm.name
                );
            }
            unit_owners.insert(unit.clone(), apm.name.clone());
        }

        packages.push(ExposedPackage {
            name: apm.name.clone(),
            target: expose.target.clone(),
            units,
            artifact_hash,
            artifact_store_path: artifact.store_path.clone(),
            provides: expose.provides.clone(),
            uses: expose.uses.clone(),
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    validate_capability_routes(&packages)?;
    Ok(packages)
}

fn write_attached_units(root: &Path, packages: &[ExposedPackage]) -> Result<()> {
    for dir in attached_dirs(root) {
        reset_dir(&dir)?;
        for package in packages {
            for unit in &package.units {
                let target = Path::new(&package.artifact_store_path)
                    .join("units")
                    .join(unit);
                let link = dir.join(unit);
                atomic_symlink(&target, &link).with_context(|| {
                    format!(
                        "linking attached unit {} -> {}",
                        link.display(),
                        target.display()
                    )
                })?;
            }
        }
        write_capability_route_dropins(&dir, packages)?;
    }
    Ok(())
}

fn validate_capability_routes(packages: &[ExposedPackage]) -> Result<()> {
    let package_names = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut socket_routes = BTreeMap::<String, String>::new();
    for package in packages {
        for route in &package.uses {
            if !package.units.contains(&route.unit) {
                bail!(
                    "package '{}' consumes capability '{}.{}' from unknown unit '{}'",
                    package.name,
                    route.provider,
                    route.name,
                    route.unit
                );
            }
            if !route.unit.ends_with(".service") {
                bail!(
                    "package '{}' consumes capability '{}.{}' from non-service unit '{}'",
                    package.name,
                    route.provider,
                    route.name,
                    route.unit
                );
            }
            if !package_names.contains(route.provider.as_str()) {
                bail!(
                    "package '{}' requires capability '{}.{}' from package '{}' which is not installed in this generation",
                    package.name,
                    route.provider,
                    route.name,
                    route.provider
                );
            }
            let provider = packages
                .iter()
                .find(|candidate| candidate.name == route.provider)
                .expect("provider package checked above");
            let provided = find_provided_capability(provider, &route.name)?;
            if provided.kind != route.kind {
                bail!(
                    "package '{}' requires capability '{}.{}' as {:?}, but provider declares {:?}",
                    package.name,
                    route.provider,
                    route.name,
                    route.kind,
                    provided.kind
                );
            }
            match route.kind {
                CapabilityKind::Directory => {
                    if provided.path.is_none() {
                        bail!(
                            "provider package '{}' capability '{}' is missing a directory path",
                            provider.name,
                            provided.name
                        );
                    }
                }
                CapabilityKind::Namespace => {
                    let Some(unit) = provided.unit.as_ref() else {
                        bail!(
                            "provider package '{}' capability '{}' is missing a namespace unit",
                            provider.name,
                            provided.name
                        );
                    };
                    if !provider.units.contains(unit) {
                        bail!(
                            "provider package '{}' capability '{}' references unknown unit '{}'",
                            provider.name,
                            provided.name,
                            unit
                        );
                    }
                }
                CapabilityKind::Socket => {
                    let Some(unit) = provided.unit.as_ref() else {
                        bail!(
                            "provider package '{}' capability '{}' is missing a socket unit",
                            provider.name,
                            provided.name
                        );
                    };
                    if !unit.ends_with(".socket") {
                        bail!(
                            "provider package '{}' capability '{}' references non-socket unit '{}'",
                            provider.name,
                            provided.name,
                            unit
                        );
                    }
                    if !provider.units.contains(unit) {
                        bail!(
                            "provider package '{}' capability '{}' references unknown unit '{}'",
                            provider.name,
                            provided.name,
                            unit
                        );
                    }
                    validate_routed_socket_unit(provider, provided, route)?;
                    let route_key = unit.clone();
                    let consumer = format!("{}:{}", package.name, route.unit);
                    if let Some(existing) = socket_routes.insert(route_key, consumer.clone()) {
                        bail!(
                            "socket capability '{}.{}' uses socket unit '{}' which is routed to both {} and {}",
                            route.provider,
                            route.name,
                            unit,
                            existing,
                            consumer
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_routed_socket_unit(
    provider: &ExposedPackage,
    provided: &ProvidedCapabilityMeta,
    route: &RequiredCapabilityMeta,
) -> Result<()> {
    let unit = provided
        .unit
        .as_ref()
        .context("socket capability missing unit")?;
    let socket_path = Path::new(&provider.artifact_store_path)
        .join("units")
        .join(unit);
    let text = std::fs::read_to_string(&socket_path)
        .with_context(|| format!("reading routed socket unit {}", socket_path.display()))?;
    let parsed = Parsed::parse(&text);
    let socket = parsed.sections.get("Socket");
    let last_value = |key: &str| {
        socket
            .and_then(|section| section.get(key))
            .and_then(|values| values.last())
            .map(String::as_str)
    };
    if last_value("Accept").is_some_and(systemd_bool) {
        bail!(
            "provider package '{}' capability '{}' references socket unit '{}' with Accept=yes",
            provider.name,
            provided.name,
            unit
        );
    }
    if let Some(service) = last_value("Service") {
        bail!(
            "provider package '{}' capability '{}' references socket unit '{}' that already declares Service={}; routed socket capabilities set Service={} at activation",
            provider.name,
            provided.name,
            unit,
            service,
            route.unit
        );
    }
    for directive in ["PrivateNetwork", "NetworkNamespacePath", "JoinsNamespaceOf"] {
        if parsed
            .sections
            .values()
            .any(|section| section.contains_key(directive))
        {
            bail!(
                "provider package '{}' capability '{}' references socket unit '{}' that declares {}=; routed socket capabilities keep provider sockets in the host network namespace",
                provider.name,
                provided.name,
                unit,
                directive
            );
        }
    }
    Ok(())
}

fn systemd_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn find_provided_capability<'a>(
    package: &'a ExposedPackage,
    name: &str,
) -> Result<&'a ProvidedCapabilityMeta> {
    package
        .provides
        .iter()
        .find(|provided| provided.name == name)
        .with_context(|| {
            format!(
                "provider package '{}' does not declare capability '{}'",
                package.name, name
            )
        })
}

fn write_capability_route_dropins(dir: &Path, packages: &[ExposedPackage]) -> Result<()> {
    for (unit, content) in capability_route_dropins(packages)? {
        let dropin_dir = dir.join(format!("{unit}.d"));
        std::fs::create_dir_all(&dropin_dir)
            .with_context(|| format!("creating {}", dropin_dir.display()))?;
        std::fs::write(dropin_dir.join("50-aos-capability-routes.conf"), content)
            .with_context(|| format!("writing capability route drop-in for {unit}"))?;
    }
    Ok(())
}

fn capability_route_dropins(packages: &[ExposedPackage]) -> Result<BTreeMap<String, String>> {
    let mut dropins = BTreeMap::<String, DropinSections>::new();
    for package in packages {
        for route in &package.uses {
            let provider = packages
                .iter()
                .find(|candidate| candidate.name == route.provider)
                .with_context(|| {
                    format!(
                        "package '{}' requires capability '{}.{}' from missing provider '{}'",
                        package.name, route.provider, route.name, route.provider
                    )
                })?;
            let provided = find_provided_capability(provider, &route.name)?;
            let entry = dropins.entry(route.unit.clone()).or_default();
            match route.kind {
                CapabilityKind::Directory => {
                    let path = provided
                        .path
                        .as_ref()
                        .context("directory capability missing path")?;
                    entry.unit_lines.push(format!("Wants={}", provider.target));
                    entry.unit_lines.push(format!("After={}", provider.target));
                    entry
                        .service_lines
                        .push(format!("BindReadOnlyPaths={path}"));
                }
                CapabilityKind::Namespace => {
                    let unit = provided
                        .unit
                        .as_ref()
                        .context("namespace capability missing unit")?;
                    entry.unit_lines.push(format!("Wants={unit}"));
                    entry.unit_lines.push(format!("After={unit}"));
                    entry.unit_lines.push(format!("JoinsNamespaceOf={unit}"));
                }
                CapabilityKind::Socket => {
                    let socket_unit = provided
                        .unit
                        .as_ref()
                        .context("socket capability missing unit")?;
                    entry.unit_lines.push(format!("Wants={socket_unit}"));
                    entry.unit_lines.push(format!("After={socket_unit}"));

                    let target_entry = dropins.entry(package.target.clone()).or_default();
                    target_entry.unit_lines.push(format!("Wants={socket_unit}"));
                    target_entry.unit_lines.push(format!("After={socket_unit}"));

                    let socket_entry = dropins.entry(socket_unit.clone()).or_default();
                    socket_entry
                        .socket_lines
                        .push(format!("Service={}", route.unit));
                    socket_entry.socket_lines.push(format!(
                        "FileDescriptorName={}",
                        socket_file_descriptor_name(&route.provider, &route.name)
                    ));
                }
            }
        }
    }

    Ok(dropins
        .into_iter()
        .map(|(unit, sections)| (unit, sections.render()))
        .collect())
}

#[derive(Debug, Default)]
struct DropinSections {
    unit_lines: Vec<String>,
    service_lines: Vec<String>,
    socket_lines: Vec<String>,
}

impl DropinSections {
    fn render(mut self) -> String {
        self.unit_lines.sort();
        self.unit_lines.dedup();
        self.service_lines.sort();
        self.service_lines.dedup();
        self.socket_lines.sort();
        self.socket_lines.dedup();

        let mut out = String::new();
        if !self.unit_lines.is_empty() {
            out.push_str("[Unit]\n");
            for line in self.unit_lines {
                out.push_str(&line);
                out.push('\n');
            }
        }
        if !self.service_lines.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str("[Service]\n");
            for line in self.service_lines {
                out.push_str(&line);
                out.push('\n');
            }
        }
        if !self.socket_lines.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str("[Socket]\n");
            for line in self.socket_lines {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

fn socket_file_descriptor_name(provider: &str, name: &str) -> String {
    format!("aos-{provider}-{name}")
}

fn write_exact_preset(root: &Path, targets: &BTreeSet<String>) -> Result<()> {
    let mut text = String::new();
    for target in targets {
        text.push_str("enable ");
        text.push_str(target);
        text.push('\n');
    }
    for path in preset_paths(root) {
        let parent = path
            .parent()
            .with_context(|| format!("finding parent for {}", path.display()))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExposedTargetStartMode {
    AwaitJob,
    QueueOnly,
}

fn exposed_target_start_mode_from_env(value: Option<std::ffi::OsString>) -> ExposedTargetStartMode {
    if value.is_some() {
        ExposedTargetStartMode::QueueOnly
    } else {
        ExposedTargetStartMode::AwaitJob
    }
}

fn exposed_target_start_mode() -> ExposedTargetStartMode {
    exposed_target_start_mode_from_env(std::env::var_os("AOS_EXPOSE_START_NO_WAIT"))
}

async fn apply_systemd_changes(
    root: &Path,
    current_targets: &BTreeSet<String>,
    attached_diff: &UnitDiff,
) -> Result<()> {
    if root == Path::new("/") {
        let client = SystemdClient::connect().await?;
        let start_mode = exposed_target_start_mode();
        client.daemon_reload().await?;
        preset_targets(root, current_targets)?;
        apply_attached_unit_diff(&client, attached_diff).await?;
        for target in current_targets {
            match start_mode {
                ExposedTargetStartMode::QueueOnly => {
                    client.start_unit_no_wait(target).await.with_context(|| {
                        format!("queueing start for exposed package target {target}")
                    })?;
                }
                ExposedTargetStartMode::AwaitJob => {
                    let outcome = client.start_unit(target).await?;
                    if !outcome.result.is_done() {
                        bail!(
                            "systemd failed to start exposed package target {target}: {}",
                            outcome.result.label()
                        );
                    }
                }
            }
        }
    } else {
        preset_targets(root, current_targets)?;
    }
    Ok(())
}

async fn apply_attached_unit_diff(client: &SystemdClient, diff: &UnitDiff) -> Result<()> {
    for unit in &diff.to_stop {
        ensure_job_done("stop", unit, client.stop_unit(unit).await?)?;
    }
    for unit in &diff.to_reload {
        ensure_job_done("reload", unit, client.reload_unit(unit).await?)?;
    }
    for unit in &diff.to_restart {
        ensure_job_done("restart", unit, client.restart_unit(unit).await?)?;
    }
    Ok(())
}

fn ensure_job_done(action: &str, unit: &str, outcome: JobOutcome) -> Result<()> {
    if outcome.result.is_done() {
        return Ok(());
    }
    bail!(
        "systemd failed to {action} exposed package unit {unit}: {}",
        outcome.result.label()
    )
}

fn preset_targets(root: &Path, targets: &BTreeSet<String>) -> Result<()> {
    if targets.is_empty() {
        return Ok(());
    }
    let mut command = systemctl(root);
    command.arg("preset");
    command.args(targets);
    run_systemctl(command, "preset exposed package targets")
}

fn disable_removed_targets(root: &Path, targets: &[String]) -> Result<()> {
    if targets.is_empty() {
        return Ok(());
    }
    let mut command = systemctl(root);
    if root == Path::new("/") {
        command.arg("disable").arg("--now");
    } else {
        command.arg("disable");
    }
    command.args(targets);
    run_systemctl(command, "disable removed exposed package targets")
}

fn systemctl(root: &Path) -> Command {
    let mut command = Command::new("systemctl");
    if root != Path::new("/") {
        command.arg(format!("--root={}", root.display()));
    }
    command
}

fn run_systemctl(mut command: Command, action: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("running systemctl to {action}"))?;
    if !status.success() {
        bail!("systemctl failed to {action}: {status}");
    }
    Ok(())
}

fn read_existing_preset_targets(root: &Path) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for path in preset_paths(root) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let Some(target) = line.trim().strip_prefix("enable ") else {
                continue;
            };
            if target.starts_with("aos-pkg-") && target.ends_with(".target") {
                targets.insert(target.to_string());
            }
        }
    }
    Ok(targets)
}

fn preset_paths(root: &Path) -> [PathBuf; 2] {
    [
        root.join("var/etc").join(APM_PRESET_REL),
        root.join("etc").join(APM_PRESET_REL),
    ]
}

fn attached_dirs(root: &Path) -> [PathBuf; 2] {
    [
        root.join("var/etc").join(ATTACHED_REL),
        root.join("etc").join(ATTACHED_REL),
    ]
}

fn compute_attached_unit_diff(root: &Path, packages: &[ExposedPackage]) -> Result<UnitDiff> {
    let temp = TempDir::new().context("creating attached unit diff workspace")?;
    let live_root = temp.path().join("live");
    let candidate_root = temp.path().join("candidate");
    let live_units = live_root.join("systemd/system");
    let candidate_units = candidate_root.join("systemd/system");
    std::fs::create_dir_all(&live_units)
        .with_context(|| format!("creating {}", live_units.display()))?;
    std::fs::create_dir_all(&candidate_units)
        .with_context(|| format!("creating {}", candidate_units.display()))?;

    copy_existing_attached_units(root, &live_units)?;
    link_candidate_attached_units(packages, &candidate_units)?;

    Ok(unit_diff::compute_diff(&live_root, &candidate_root))
}

fn copy_existing_attached_units(root: &Path, destination: &Path) -> Result<()> {
    for dir in attached_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            if !is_unit_file_name(&file_name) {
                if is_dropin_dir_name(&file_name) {
                    copy_dropin_dir(&entry.path(), &destination.join(file_name))?;
                }
                continue;
            }
            atomic_symlink(&entry.path(), &destination.join(file_name))?;
        }
    }
    Ok(())
}

fn link_candidate_attached_units(packages: &[ExposedPackage], destination: &Path) -> Result<()> {
    for package in packages {
        for unit in &package.units {
            let target = Path::new(&package.artifact_store_path)
                .join("units")
                .join(unit);
            atomic_symlink(&target, &destination.join(unit))?;
        }
    }
    write_capability_route_dropins(destination, packages)?;
    Ok(())
}

fn has_attached_units(root: &Path) -> Result<bool> {
    for dir in attached_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            if is_unit_file_name(&entry.file_name()) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn is_unit_file_name(name: &OsStr) -> bool {
    const UNIT_SUFFIXES: &[&str] = &[
        ".service",
        ".target",
        ".socket",
        ".timer",
        ".path",
        ".mount",
        ".slice",
        ".automount",
        ".swap",
    ];
    let name = name.to_string_lossy();
    UNIT_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

fn is_dropin_dir_name(name: &OsStr) -> bool {
    name.to_string_lossy().ends_with(".d")
}

fn copy_dropin_dir(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    for entry in
        std::fs::read_dir(source).with_context(|| format!("reading {}", source.display()))?
    {
        let entry = entry?;
        if entry.path().extension().and_then(OsStr::to_str) != Some("conf") {
            continue;
        }
        atomic_symlink(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn reset_dir(path: &Path) -> Result<()> {
    if path.symlink_metadata().is_ok() {
        for entry in
            std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))?
        {
            let entry = entry?;
            let entry_path = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("reading file type for {}", entry_path.display()))?;
            if file_type.is_dir() {
                std::fs::remove_dir_all(&entry_path)
                    .with_context(|| format!("removing {}", entry_path.display()))?;
            } else {
                std::fs::remove_file(&entry_path)
                    .with_context(|| format!("removing {}", entry_path.display()))?;
            }
        }
    } else {
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    }
    Ok(())
}

fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if let Ok(existing) = std::fs::read_link(link) {
        if existing == target {
            return Ok(());
        }
    }

    let parent = link
        .parent()
        .with_context(|| format!("finding parent for {}", link.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let tmp = link.with_file_name(format!(
        ".{}.tmp.{}",
        link.file_name().and_then(OsStr::to_str).unwrap_or("link"),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    symlink(target, &tmp).with_context(|| {
        format!(
            "creating temp symlink {} -> {}",
            tmp.display(),
            target.display()
        )
    })?;
    std::fs::rename(&tmp, link)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), link.display()))
}

fn aos_root_path() -> PathBuf {
    match std::env::var("AOS_ROOT") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                return path;
            }
        }
        _ => {}
    }
    PathBuf::from("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::TempDir;

    use crate::types::{
        ApmMeta, CapabilityKind, ExposeArtifactMeta, ExposeMeta, InstalledMeta,
        ProvidedCapabilityMeta, RequiredCapabilityMeta, SysrootImageEntry,
    };

    #[test]
    fn exposed_target_start_mode_defaults_to_awaited_jobs() {
        assert_eq!(
            exposed_target_start_mode_from_env(None),
            ExposedTargetStartMode::AwaitJob
        );
    }

    #[test]
    fn exposed_target_start_mode_queues_jobs_when_env_is_present() {
        assert_eq!(
            exposed_target_start_mode_from_env(Some(OsString::new())),
            ExposedTargetStartMode::QueueOnly
        );
    }

    fn installed_with_expose(
        tmp: &TempDir,
        name: &str,
        package_hash: &str,
        artifact_hash: &str,
    ) -> InstalledMeta {
        let artifact = tmp.path().join(format!("{artifact_hash}-expose-{name}"));
        std::fs::create_dir_all(artifact.join("units")).unwrap();
        std::fs::write(
            artifact
                .join("units")
                .join(format!("aos-pkg-{name}.target")),
            "[Unit]\n",
        )
        .unwrap();
        std::fs::write(
            artifact.join("units").join(format!("{name}.service")),
            "[Unit]\n",
        )
        .unwrap();

        InstalledMeta {
            store_path: format!("/var/lib/store/{package_hash}-{name}-1.0"),
            pushed_at: 1,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.into(),
                version: "1.0".into(),
                explicit: true,
                registry: "test".into(),
                installed_at: "2026-06-16T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: Some(ExposeMeta {
                    target: format!("aos-pkg-{name}.target"),
                    units: vec![format!("{name}.service")],
                    images: Vec::new(),
                    requires: Vec::new(),
                    config: Default::default(),
                    provides: Vec::new(),
                    uses: Vec::new(),
                }),
                expose_artifact: Some(ExposeArtifactMeta {
                    store_path: artifact.display().to_string(),
                    nar_hash: "sha256:test".into(),
                    nar_size: 1,
                }),
                permissions: Default::default(),
            }),
        }
    }

    fn routed_socket_fixture(
        tmp: &TempDir,
        socket_text: &str,
    ) -> (Profile, InstalledMeta, InstalledMeta) {
        let mut provider = installed_with_expose(tmp, "provider", "pkghash111", "artifacthash111");
        let provider_artifact = provider
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&provider_artifact).join("units/provider.socket"),
            socket_text,
        )
        .unwrap();
        let provider_expose = provider.apm.as_mut().unwrap().expose.as_mut().unwrap();
        provider_expose.units.push("provider.socket".into());
        provider_expose.provides = vec![ProvidedCapabilityMeta {
            name: "api".into(),
            kind: CapabilityKind::Socket,
            path: None,
            unit: Some("provider.socket".into()),
        }];

        let mut consumer = installed_with_expose(tmp, "consumer", "pkghash222", "artifacthash222");
        consumer.apm.as_mut().unwrap().expose.as_mut().unwrap().uses =
            vec![RequiredCapabilityMeta {
                provider: "provider".into(),
                name: "api".into(),
                kind: CapabilityKind::Socket,
                unit: "consumer.service".into(),
            }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &consumer] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        (profile, provider, consumer)
    }

    fn routed_socket_error(socket_text: &str) -> anyhow::Error {
        let tmp = TempDir::new().unwrap();
        let (profile, provider, consumer) = routed_socket_fixture(&tmp, socket_text);

        exposed_packages(&profile, &[provider, consumer]).unwrap_err()
    }

    #[test]
    fn rebuild_generation_expose_roots_links_artifacts_once() {
        let tmp = TempDir::new().unwrap();
        let generation = Generation {
            number: 1,
            path: tmp.path().join("gen-1"),
        };
        let installed = vec![
            installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111"),
            installed_with_expose(&tmp, "api", "pkghash222", "artifacthash111"),
        ];

        rebuild_generation_expose_roots(&generation, &installed).unwrap();

        let entries = std::fs::read_dir(generation.path.join("expose"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), "artifacthash111");
    }

    #[test]
    fn rebuild_generation_expose_image_roots_links_images_once() {
        let tmp = TempDir::new().unwrap();
        let generation = Generation {
            number: 1,
            path: tmp.path().join("gen-1"),
        };
        let mut web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let mut api = installed_with_expose(&tmp, "api", "pkghash222", "artifacthash222");
        let image_path = tmp.path().join("imagehash111-rootfs");
        for installed in [&mut web, &mut api] {
            let expose = installed.apm.as_mut().unwrap().expose.as_mut().unwrap();
            expose.images = vec![SysrootImageEntry {
                format: "dir".to_string(),
                store_path: image_path.display().to_string(),
                nar_hash: "sha256:image".to_string(),
                nar_size: 1,
                sb_signer_cert_sha256: None,
                sbat: Vec::new(),
                expected_pcr11: None,
            }];
        }

        rebuild_generation_expose_image_roots(&generation, &[web, api]).unwrap();

        let entries = std::fs::read_dir(generation.path.join("expose-images"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), "imagehash111");
    }

    #[test]
    fn write_attached_units_replaces_stale_units_in_live_and_durable_dirs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::os::unix::fs::symlink(
            &artifact,
            profile.current_path().join("expose/artifacthash111"),
        )
        .unwrap();

        let packages = exposed_packages(&profile, &[installed]).unwrap();
        for dir in attached_dirs(&root) {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("stale.service"), "[Unit]\n").unwrap();
        }

        write_attached_units(&root, &packages).unwrap();

        for dir in attached_dirs(&root) {
            assert!(!dir.join("stale.service").exists());
            assert!(dir.join("aos-pkg-web.target").symlink_metadata().is_ok());
            assert!(dir.join("web.service").symlink_metadata().is_ok());
        }
    }

    #[test]
    fn write_attached_units_removes_stale_routed_socket_namespace_dropins() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let (profile, provider, consumer) =
            routed_socket_fixture(&tmp, "[Socket]\nListenStream=127.0.0.1:18080\n");
        let packages = exposed_packages(&profile, &[provider, consumer]).unwrap();

        for dir in attached_dirs(&root) {
            let stale_dropin_dir = dir.join("provider.socket.d");
            std::fs::create_dir_all(&stale_dropin_dir).unwrap();
            std::fs::write(
                stale_dropin_dir.join("10-local.conf"),
                "[Unit]\nJoinsNamespaceOf=other.service\n[Socket]\nPrivateNetwork=true\nNetworkNamespacePath=/run/netns/aos-pkg-provider\n",
            )
            .unwrap();
        }

        write_attached_units(&root, &packages).unwrap();

        for dir in attached_dirs(&root) {
            assert!(!dir.join("provider.socket.d/10-local.conf").exists());
            let route_dropin = std::fs::read_to_string(
                dir.join("provider.socket.d/50-aos-capability-routes.conf"),
            )
            .unwrap();
            assert!(route_dropin.contains("Service=consumer.service"));
            assert!(route_dropin.contains("FileDescriptorName=aos-provider-api"));
            assert!(!route_dropin.contains("PrivateNetwork="));
            assert!(!route_dropin.contains("NetworkNamespacePath="));
            assert!(!route_dropin.contains("JoinsNamespaceOf="));
        }
    }

    #[test]
    fn exposed_packages_rejects_duplicate_unit_names() {
        let tmp = TempDir::new().unwrap();
        let web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let mut api = installed_with_expose(&tmp, "api", "pkghash222", "artifacthash222");
        let api_artifact = api
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&api_artifact).join("units/web.service"),
            "[Unit]\n",
        )
        .unwrap();
        api.apm.as_mut().unwrap().expose.as_mut().unwrap().units = vec!["web.service".into()];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&web, &api] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let err = exposed_packages(&profile, &[web, api]).unwrap_err();

        assert!(format!("{err:#}").contains("declared by both packages"));
    }

    #[test]
    fn capability_route_dropins_bind_provider_directories() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        provider
            .apm
            .as_mut()
            .unwrap()
            .expose
            .as_mut()
            .unwrap()
            .provides = vec![ProvidedCapabilityMeta {
            name: "data".into(),
            kind: CapabilityKind::Directory,
            path: Some("/var/lib/provider/data".into()),
            unit: None,
        }];
        let mut consumer = installed_with_expose(&tmp, "consumer", "pkghash222", "artifacthash222");
        consumer.apm.as_mut().unwrap().expose.as_mut().unwrap().uses =
            vec![RequiredCapabilityMeta {
                provider: "provider".into(),
                name: "data".into(),
                kind: CapabilityKind::Directory,
                unit: "consumer.service".into(),
            }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &consumer] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let packages = exposed_packages(&profile, &[provider, consumer]).unwrap();
        let dropins = capability_route_dropins(&packages).unwrap();
        let dropin = dropins.get("consumer.service").unwrap();
        assert!(dropin.contains("Wants=aos-pkg-provider.target"));
        assert!(dropin.contains("After=aos-pkg-provider.target"));
        assert!(dropin.contains("BindReadOnlyPaths=/var/lib/provider/data"));
    }

    #[test]
    fn capability_route_dropins_route_provider_sockets() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        let provider_artifact = provider
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&provider_artifact).join("units/provider.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\n",
        )
        .unwrap();
        provider
            .apm
            .as_mut()
            .unwrap()
            .expose
            .as_mut()
            .unwrap()
            .units
            .push("provider.socket".into());
        provider
            .apm
            .as_mut()
            .unwrap()
            .expose
            .as_mut()
            .unwrap()
            .provides = vec![ProvidedCapabilityMeta {
            name: "api".into(),
            kind: CapabilityKind::Socket,
            path: None,
            unit: Some("provider.socket".into()),
        }];
        let mut consumer = installed_with_expose(&tmp, "consumer", "pkghash222", "artifacthash222");
        consumer.apm.as_mut().unwrap().expose.as_mut().unwrap().uses =
            vec![RequiredCapabilityMeta {
                provider: "provider".into(),
                name: "api".into(),
                kind: CapabilityKind::Socket,
                unit: "consumer.service".into(),
            }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &consumer] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let packages = exposed_packages(&profile, &[provider, consumer]).unwrap();
        let dropins = capability_route_dropins(&packages).unwrap();
        let consumer_dropin = dropins.get("consumer.service").unwrap();
        assert!(consumer_dropin.contains("Wants=provider.socket"));
        assert!(consumer_dropin.contains("After=provider.socket"));
        assert!(!consumer_dropin.contains("JoinsNamespaceOf=provider.socket"));
        let target_dropin = dropins.get("aos-pkg-consumer.target").unwrap();
        assert!(target_dropin.contains("Wants=provider.socket"));
        assert!(target_dropin.contains("After=provider.socket"));
        let socket_dropin = dropins.get("provider.socket").unwrap();
        assert!(socket_dropin.contains("[Socket]"));
        assert!(socket_dropin.contains("Service=consumer.service"));
        assert!(socket_dropin.contains("FileDescriptorName=aos-provider-api"));
        assert!(!socket_dropin.contains("PrivateNetwork=true"));
    }

    #[test]
    fn exposed_packages_rejects_socket_capability_from_non_socket_unit() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        provider
            .apm
            .as_mut()
            .unwrap()
            .expose
            .as_mut()
            .unwrap()
            .provides = vec![ProvidedCapabilityMeta {
            name: "api".into(),
            kind: CapabilityKind::Socket,
            path: None,
            unit: Some("provider.service".into()),
        }];
        let mut consumer = installed_with_expose(&tmp, "consumer", "pkghash222", "artifacthash222");
        consumer.apm.as_mut().unwrap().expose.as_mut().unwrap().uses =
            vec![RequiredCapabilityMeta {
                provider: "provider".into(),
                name: "api".into(),
                kind: CapabilityKind::Socket,
                unit: "consumer.service".into(),
            }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &consumer] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let err = exposed_packages(&profile, &[provider, consumer]).unwrap_err();

        assert!(format!("{err:#}").contains("references non-socket unit 'provider.service'"));
    }

    #[test]
    fn exposed_packages_rejects_socket_capability_routed_to_multiple_consumers() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        let provider_artifact = provider
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&provider_artifact).join("units/provider.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\n",
        )
        .unwrap();
        let provider_expose = provider.apm.as_mut().unwrap().expose.as_mut().unwrap();
        provider_expose.units.push("provider.socket".into());
        provider_expose.provides = vec![ProvidedCapabilityMeta {
            name: "api".into(),
            kind: CapabilityKind::Socket,
            path: None,
            unit: Some("provider.socket".into()),
        }];

        let mut first = installed_with_expose(&tmp, "first", "pkghash222", "artifacthash222");
        first.apm.as_mut().unwrap().expose.as_mut().unwrap().uses = vec![RequiredCapabilityMeta {
            provider: "provider".into(),
            name: "api".into(),
            kind: CapabilityKind::Socket,
            unit: "first.service".into(),
        }];
        let mut second = installed_with_expose(&tmp, "second", "pkghash333", "artifacthash333");
        second.apm.as_mut().unwrap().expose.as_mut().unwrap().uses = vec![RequiredCapabilityMeta {
            provider: "provider".into(),
            name: "api".into(),
            kind: CapabilityKind::Socket,
            unit: "second.service".into(),
        }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &first, &second] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let err = exposed_packages(&profile, &[provider, first, second]).unwrap_err();

        assert!(format!("{err:#}").contains("uses socket unit 'provider.socket'"));
        assert!(format!("{err:#}").contains("routed to both"));
    }

    #[test]
    fn exposed_packages_rejects_distinct_socket_capabilities_on_one_socket_unit() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        let provider_artifact = provider
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&provider_artifact).join("units/provider.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\n",
        )
        .unwrap();
        let provider_expose = provider.apm.as_mut().unwrap().expose.as_mut().unwrap();
        provider_expose.units.push("provider.socket".into());
        provider_expose.provides = vec![
            ProvidedCapabilityMeta {
                name: "api".into(),
                kind: CapabilityKind::Socket,
                path: None,
                unit: Some("provider.socket".into()),
            },
            ProvidedCapabilityMeta {
                name: "metrics".into(),
                kind: CapabilityKind::Socket,
                path: None,
                unit: Some("provider.socket".into()),
            },
        ];

        let mut first = installed_with_expose(&tmp, "first", "pkghash222", "artifacthash222");
        first.apm.as_mut().unwrap().expose.as_mut().unwrap().uses = vec![RequiredCapabilityMeta {
            provider: "provider".into(),
            name: "api".into(),
            kind: CapabilityKind::Socket,
            unit: "first.service".into(),
        }];
        let mut second = installed_with_expose(&tmp, "second", "pkghash333", "artifacthash333");
        second.apm.as_mut().unwrap().expose.as_mut().unwrap().uses = vec![RequiredCapabilityMeta {
            provider: "provider".into(),
            name: "metrics".into(),
            kind: CapabilityKind::Socket,
            unit: "second.service".into(),
        }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &first, &second] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let err = exposed_packages(&profile, &[provider, first, second]).unwrap_err();

        assert!(format!("{err:#}").contains("uses socket unit 'provider.socket'"));
        assert!(format!("{err:#}").contains("routed to both"));
    }

    #[test]
    fn exposed_packages_rejects_routed_socket_namespace_directives() {
        for (directive, socket_text) in [
            (
                "PrivateNetwork",
                "[Socket]\nListenStream=127.0.0.1:18080\nPrivateNetwork=true\n",
            ),
            (
                "NetworkNamespacePath",
                "[Socket]\nListenStream=127.0.0.1:18080\nNetworkNamespacePath=/run/netns/aos-pkg-provider\n",
            ),
            (
                "JoinsNamespaceOf",
                "[Unit]\nJoinsNamespaceOf=other.service\n[Socket]\nListenStream=127.0.0.1:18080\n",
            ),
        ] {
            let err = routed_socket_error(socket_text);
            assert!(format!("{err:#}").contains(&format!("declares {directive}=")));
        }
    }

    #[test]
    fn exposed_packages_rejects_routed_socket_accept_yes() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        let provider_artifact = provider
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&provider_artifact).join("units/provider.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\nAccept=Yes\n",
        )
        .unwrap();
        let provider_expose = provider.apm.as_mut().unwrap().expose.as_mut().unwrap();
        provider_expose.units.push("provider.socket".into());
        provider_expose.provides = vec![ProvidedCapabilityMeta {
            name: "api".into(),
            kind: CapabilityKind::Socket,
            path: None,
            unit: Some("provider.socket".into()),
        }];

        let mut consumer = installed_with_expose(&tmp, "consumer", "pkghash222", "artifacthash222");
        consumer.apm.as_mut().unwrap().expose.as_mut().unwrap().uses =
            vec![RequiredCapabilityMeta {
                provider: "provider".into(),
                name: "api".into(),
                kind: CapabilityKind::Socket,
                unit: "consumer.service".into(),
            }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &consumer] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let err = exposed_packages(&profile, &[provider, consumer]).unwrap_err();

        assert!(format!("{err:#}").contains("with Accept=yes"));
    }

    #[test]
    fn exposed_packages_rejects_routed_socket_with_existing_service() {
        let tmp = TempDir::new().unwrap();
        let mut provider = installed_with_expose(&tmp, "provider", "pkghash111", "artifacthash111");
        let provider_artifact = provider
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&provider_artifact).join("units/provider.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\nService=provider.service\n",
        )
        .unwrap();
        let provider_expose = provider.apm.as_mut().unwrap().expose.as_mut().unwrap();
        provider_expose.units.push("provider.socket".into());
        provider_expose.provides = vec![ProvidedCapabilityMeta {
            name: "api".into(),
            kind: CapabilityKind::Socket,
            path: None,
            unit: Some("provider.socket".into()),
        }];

        let mut consumer = installed_with_expose(&tmp, "consumer", "pkghash222", "artifacthash222");
        consumer.apm.as_mut().unwrap().expose.as_mut().unwrap().uses =
            vec![RequiredCapabilityMeta {
                provider: "provider".into(),
                name: "api".into(),
                kind: CapabilityKind::Socket,
                unit: "consumer.service".into(),
            }];

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for installed in [&provider, &consumer] {
            let artifact = installed
                .apm
                .as_ref()
                .unwrap()
                .expose_artifact
                .as_ref()
                .unwrap()
                .store_path
                .clone();
            std::os::unix::fs::symlink(
                &artifact,
                profile
                    .current_path()
                    .join("expose")
                    .join(store_path_hash(&artifact)),
            )
            .unwrap();
        }

        let err = exposed_packages(&profile, &[provider, consumer]).unwrap_err();

        assert!(format!("{err:#}").contains("already declares Service=provider.service"));
    }

    #[test]
    fn attached_unit_diff_restarts_changed_services() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let old_artifact = tmp.path().join("oldartifacthash-expose-web");
        let new_artifact = tmp.path().join("newartifacthash-expose-web");
        std::fs::create_dir_all(old_artifact.join("units")).unwrap();
        std::fs::create_dir_all(new_artifact.join("units")).unwrap();
        std::fs::write(
            old_artifact.join("units/aos-pkg-web.target"),
            "[Unit]\nWants=web.service\n",
        )
        .unwrap();
        std::fs::write(
            old_artifact.join("units/web.service"),
            "[Service]\nExecStart=/old\n",
        )
        .unwrap();
        std::fs::write(
            new_artifact.join("units/aos-pkg-web.target"),
            "[Unit]\nWants=web.service\n",
        )
        .unwrap();
        std::fs::write(
            new_artifact.join("units/web.service"),
            "[Service]\nExecStart=/new\n",
        )
        .unwrap();
        let live_attached = root.join("etc").join(ATTACHED_REL);
        std::fs::create_dir_all(&live_attached).unwrap();
        std::os::unix::fs::symlink(
            old_artifact.join("units/aos-pkg-web.target"),
            live_attached.join("aos-pkg-web.target"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            old_artifact.join("units/web.service"),
            live_attached.join("web.service"),
        )
        .unwrap();

        let package = ExposedPackage {
            name: "web".into(),
            target: "aos-pkg-web.target".into(),
            units: BTreeSet::from(["aos-pkg-web.target".to_string(), "web.service".to_string()]),
            artifact_hash: "newartifacthash".into(),
            artifact_store_path: new_artifact.display().to_string(),
            provides: Vec::new(),
            uses: Vec::new(),
        };

        let diff = compute_attached_unit_diff(&root, &[package]).unwrap();

        assert_eq!(diff.to_restart, vec!["web.service"]);
    }

    #[test]
    fn attached_unit_diff_stops_removed_services_without_preset() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let old_artifact = tmp.path().join("oldartifacthash-expose-web");
        std::fs::create_dir_all(old_artifact.join("units")).unwrap();
        std::fs::write(
            old_artifact.join("units/web.service"),
            "[Service]\nExecStart=/old\n",
        )
        .unwrap();
        let live_attached = root.join("etc").join(ATTACHED_REL);
        std::fs::create_dir_all(&live_attached).unwrap();
        std::os::unix::fs::symlink(
            old_artifact.join("units/web.service"),
            live_attached.join("web.service"),
        )
        .unwrap();

        let diff = compute_attached_unit_diff(&root, &[]).unwrap();

        assert_eq!(diff.to_stop, vec!["web.service"]);
    }

    #[test]
    fn write_exact_preset_removes_stale_targets() {
        let tmp = TempDir::new().unwrap();
        let mut targets = BTreeSet::new();
        targets.insert("aos-pkg-web.target".to_string());

        write_exact_preset(tmp.path(), &targets).unwrap();
        targets.clear();
        write_exact_preset(tmp.path(), &targets).unwrap();

        for path in preset_paths(tmp.path()) {
            assert_eq!(std::fs::read_to_string(path).unwrap(), "");
        }
    }
}

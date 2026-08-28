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
    CapabilityKind, ConfinementClass, CredentialMeta, ExposeMeta, HostPathMode, InstalledMeta,
    NetworkPermission, PermissionsMeta, ProfileScope, ProvidedCapabilityMeta,
    RequiredCapabilityMeta, SysrootImageEntry,
};
use crate::unit_diff::{self, Parsed, UnitDiff};
use aos_core::output::Printer;
use aos_systemd::{JobOutcome, SystemdClient};
use tempfile::TempDir;

const APM_PRESET_REL: &str = "systemd/system-preset/30-aos-apm.preset";
const ATTACHED_REL: &str = "systemd/system.attached";
const GENERATED_CREDSTORE_REL: &str = "run/credstore.encrypted/aos";
const GENERATED_CREDSTORE_SOURCE_PREFIX: &str = "/run/credstore.encrypted/";
const LANDLOCK_WRAPPER_ENV: &str = "AOS_LANDLOCK_WRAPPER";
const SELINUX_RUNNER_ENV: &str = "AOS_SELINUX_RUNNER";
const VERITY_ROOT_GUARD_ENV: &str = "AOS_VERITY_ROOT_GUARD";
const SERVICE_ROOT_HELPER_ENV: &str = "AOS_SERVICE_ROOT_HELPER";
const EBPF_NET_POLICY_ENV: &str = "AOS_EBPF_NET_POLICY";
const EBPF_NET_POLICY_OBJECT_ENV: &str = "AOS_EBPF_NET_POLICY_OBJECT";
const SEMODULE_ENV: &str = "AOS_SEMODULE";
#[cfg(not(test))]
const CHECKMODULE_ENV: &str = "AOS_CHECKMODULE";
#[cfg(not(test))]
const SEMODULE_PACKAGE_ENV: &str = "AOS_SEMODULE_PACKAGE";
const LANDLOCK_EXEC_KEYS: &[&str] = &[
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "ExecCondition",
];
const MAC_LOADER_FORBIDDEN_EXEC_KEYS: &[&str] = &[
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExposedPackage {
    name: String,
    target: String,
    units: BTreeSet<String>,
    artifact_hash: String,
    artifact_store_path: String,
    credential_blobs: Vec<CredentialBlob>,
    provides: Vec<ProvidedCapabilityMeta>,
    uses: Vec<RequiredCapabilityMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialBlob {
    relative_path: PathBuf,
    store_path: PathBuf,
    units: BTreeSet<String>,
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
    rebuild_generation_expose_image_roots(&current, &installed)?;

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

    stop_changed_service_root_targets_before_swap(&root, &attached_diff).await?;

    let had_attached_units = has_attached_units(&root)?;
    if packages.is_empty() && removed_targets.is_empty() {
        write_attached_units(&root, &packages)?;
        let changed_credential_units = write_generated_credential_blobs(&root, &packages)?;
        write_exact_preset(&root, &current_targets)?;
        if had_attached_units {
            apply_systemd_changes(
                &root,
                &current_targets,
                &attached_diff,
                &changed_credential_units,
            )
            .await?;
        }
        printer.info("No exposed package targets are installed.");
        return Ok(());
    }

    disable_removed_targets(&root, &removed_targets)?;
    write_attached_units(&root, &packages)?;
    let changed_credential_units = write_generated_credential_blobs(&root, &packages)?;
    write_exact_preset(&root, &current_targets)?;
    load_ebpf_lsm_before_package_targets(&root, &current_targets)?;
    crate::package_attestation::measure_activated_packages(&root, &installed)
        .context("measuring exposed package set into PCR 15")?;
    apply_systemd_changes(
        &root,
        &current_targets,
        &attached_diff,
        &changed_credential_units,
    )
    .await?;

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

fn load_ebpf_lsm_before_package_targets(
    root: &Path,
    current_targets: &BTreeSet<String>,
) -> Result<()> {
    if root == Path::new("/") && !current_targets.is_empty() {
        crate::ebpf_lsm::load_system_policies()
            .context("loading BPF-LSM policies before exposed package targets")?;
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
    let mut credential_blob_owners = BTreeMap::<PathBuf, String>::new();
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
        let expected_target = format!("aos-pkg-{}.target", apm.name);
        if expose.target != expected_target {
            bail!(
                "installed exposed package '{}' declares target '{}' but expected '{}'",
                apm.name,
                expose.target,
                expected_target
            );
        }
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
        validate_network_policy_artifact(
            &apm.name,
            Path::new(&artifact.store_path),
            &artifact_root,
            &units,
            &apm.permissions,
        )?;
        let mac_profile = validate_mac_profile_artifact(
            &apm.name,
            Path::new(&artifact.store_path),
            &apm.permissions,
        )?;

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
        validate_socket_listener_permissions(&apm.name, &artifact_root, &units, &apm.permissions)?;
        validate_workload_exec_wrappers(&apm.name, &artifact_root, &units, &apm.permissions)?;
        validate_workload_roots(
            &apm.name,
            Path::new(&entry.store_path),
            Path::new(&artifact.store_path),
            &artifact_root,
            &units,
            expose,
            &apm.permissions,
        )?;
        validate_ebpf_policy_service(
            &apm.name,
            &expose.target,
            Path::new(&artifact.store_path),
            &artifact_root,
            &units,
            &apm.permissions,
        )?;
        validate_mac_policy_service(
            &apm.name,
            &expose.target,
            Path::new(&artifact.store_path),
            &artifact_root,
            &units,
            mac_profile.as_ref(),
            &apm.permissions,
        )?;

        let credential_blobs =
            generated_credential_blobs(&apm.name, Path::new(&artifact.store_path), expose)
                .with_context(|| format!("reading credential blobs for package '{}'", apm.name))?;
        for blob in &credential_blobs {
            if let Some(owner) = credential_blob_owners.get(&blob.relative_path) {
                bail!(
                    "exposed credential blob '{}' is declared by both packages '{}' and '{}'",
                    blob.relative_path.display(),
                    owner,
                    apm.name
                );
            }
            credential_blob_owners.insert(blob.relative_path.clone(), apm.name.clone());
        }

        packages.push(ExposedPackage {
            name: apm.name.clone(),
            target: expose.target.clone(),
            units,
            artifact_hash,
            artifact_store_path: artifact.store_path.clone(),
            credential_blobs,
            provides: expose.provides.clone(),
            uses: expose.uses.clone(),
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    validate_capability_routes(&packages)?;
    Ok(packages)
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyArtifact {
    version: u32,
    package: String,
    mode: NetworkPermission,
    #[serde(rename = "securityLabel")]
    security_label: String,
    tcp: NetworkPolicyTcp,
    #[serde(default)]
    fs: Option<NetworkPolicyFs>,
    landlock: NetworkPolicyLandlock,
    ebpf: NetworkPolicyEbpf,
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyTcp {
    bind: Vec<u16>,
    connect: Vec<u16>,
}

#[derive(Clone, Debug, Default, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyFs {
    #[serde(rename = "readOnly")]
    read_only: Vec<String>,
    #[serde(rename = "readWrite")]
    read_write: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyLandlock {
    abi: u32,
    tcp: NetworkPolicyTcp,
    #[serde(default)]
    fs: Option<NetworkPolicyFs>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyEbpf {
    identity: String,
    hooks: Vec<String>,
    tcp: NetworkPolicyTcp,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MacProfileArtifact {
    version: u32,
    package: String,
    backend: String,
    #[serde(rename = "securityLabel")]
    security_label: String,
    #[serde(rename = "defaultDeny")]
    default_deny: bool,
    #[serde(rename = "profilePath")]
    profile_path: Option<String>,
}

#[derive(Debug)]
struct CompiledSelinuxProfile {
    module: Vec<u8>,
    profile: Vec<u8>,
}

fn validate_network_policy_artifact(
    package_name: &str,
    artifact_store_path: &Path,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    permissions: &PermissionsMeta,
) -> Result<()> {
    let path = artifact_store_path.join("network-policy.json");
    let exists = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                bail!(
                    "network policy artifact for package '{}' is not a regular file: {}",
                    package_name,
                    path.display()
                );
            }
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(err).with_context(|| format!("checking {}", path.display())),
    };
    if !exists {
        if permissions.has_network_policy() || requires_landlock_wrapper(package_name, permissions)?
        {
            bail!(
                "network policy artifact for package '{}' is missing required network-policy.json",
                package_name
            );
        }
        return Ok(());
    }

    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let policy: NetworkPolicyArtifact =
        serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let expected_permissions = normalized_permissions(package_name, permissions);
    let expected_mode = expected_permissions
        .network
        .unwrap_or(NetworkPermission::Private);
    let expected_label = expected_permissions
        .security_label
        .as_deref()
        .context("normalized permissions have no security label")?;
    let expected_tcp = NetworkPolicyTcp {
        bind: expected_permissions.tcp_bind.clone(),
        connect: expected_permissions.tcp_connect.clone(),
    };
    let expected_fs = expected_manifest_fs(&expected_permissions);
    let expected_service_paths =
        expected_landlock_service_paths(package_name, artifact_root, units).with_context(|| {
            format!("reading service directory grants for package '{package_name}'")
        })?;
    let expected_landlock_fs = expected_landlock_fs(&expected_permissions, &expected_service_paths);
    let policy_fs = policy.fs.unwrap_or_default();
    let policy_landlock_fs = policy.landlock.fs.unwrap_or_else(|| {
        if expected_fs == NetworkPolicyFs::default() {
            expected_landlock_fs.clone()
        } else {
            NetworkPolicyFs::default()
        }
    });

    if policy.version != 1 {
        bail!(
            "network policy artifact for package '{}' has unsupported version {}",
            package_name,
            policy.version
        );
    }
    if policy.package != package_name {
        bail!(
            "network policy artifact package mismatch: expected '{}', got '{}'",
            package_name,
            policy.package
        );
    }
    if policy.mode != expected_mode {
        bail!(
            "network policy artifact mode mismatch for package '{}'",
            package_name
        );
    }
    if policy.security_label != expected_label {
        bail!(
            "network policy artifact security label mismatch for package '{}'",
            package_name
        );
    }
    if policy.tcp != expected_tcp
        || policy.landlock.tcp != expected_tcp
        || policy.ebpf.tcp != expected_tcp
    {
        bail!(
            "network policy artifact TCP grants differ from admitted permissions for package '{}'",
            package_name
        );
    }
    if policy_fs != expected_fs || policy_landlock_fs != expected_landlock_fs {
        bail!(
            "network policy artifact filesystem grants differ from admitted permissions for package '{}'",
            package_name
        );
    }
    if policy.landlock.abi != 4 {
        bail!(
            "network policy artifact for package '{}' has unsupported Landlock ABI {}",
            package_name,
            policy.landlock.abi
        );
    }
    if policy.ebpf.identity != expected_label {
        bail!(
            "network policy artifact eBPF identity mismatch for package '{}'",
            package_name
        );
    }
    if policy.ebpf.hooks != ["socket_bind", "socket_connect"] {
        bail!(
            "network policy artifact eBPF hooks mismatch for package '{}'",
            package_name
        );
    }
    Ok(())
}

fn validate_mac_profile_artifact(
    package_name: &str,
    artifact_store_path: &Path,
    permissions: &PermissionsMeta,
) -> Result<Option<MacProfileArtifact>> {
    let path = artifact_store_path.join("mac-profile.json");
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                bail!(
                    "MAC profile artifact for package '{}' is not a regular file: {}",
                    package_name,
                    path.display()
                );
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(err) => return Err(err).with_context(|| format!("checking {}", path.display())),
    }

    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let profile: MacProfileArtifact =
        serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let expected_permissions = normalized_permissions(package_name, permissions);
    let expected_label = expected_permissions
        .security_label
        .as_deref()
        .context("normalized permissions have no security label")?;
    let expected_default_deny = expected_permissions
        .confinement
        .as_ref()
        .context("normalized permissions have no confinement summary")?
        .class
        != ConfinementClass::Unconfined;
    let expected_profile_path =
        expected_default_deny.then(|| expected_selinux_profile_path(expected_label));

    if profile.version != 1 {
        bail!(
            "MAC profile artifact for package '{}' has unsupported version {}",
            package_name,
            profile.version
        );
    }
    if profile.package != package_name {
        bail!(
            "MAC profile artifact package mismatch: expected '{}', got '{}'",
            package_name,
            profile.package
        );
    }
    if profile.backend != "selinux" {
        bail!(
            "MAC profile artifact backend mismatch for package '{}'",
            package_name
        );
    }
    if profile.security_label != expected_label {
        bail!(
            "MAC profile artifact security label mismatch for package '{}'",
            package_name
        );
    }
    if profile.default_deny != expected_default_deny
        || profile.profile_path.as_deref() != expected_profile_path.as_deref()
    {
        bail!(
            "MAC profile artifact confinement mode mismatch for package '{}'",
            package_name
        );
    }

    let Some(profile_path) = expected_profile_path else {
        return Ok(Some(profile));
    };
    let module_name = selinux_identifier_for_label(expected_label);
    let source_path = format!("mac/selinux/{module_name}.te");
    let module_path = format!("mac/selinux/{module_name}.mod");
    let profile_bytes =
        read_artifact_regular_bytes_no_symlink(artifact_store_path, Path::new(&profile_path))
            .with_context(|| {
                format!(
                    "MAC profile file for package '{}' is missing required {}",
                    package_name, profile_path
                )
            })?;
    if profile_bytes.is_empty() {
        bail!(
            "MAC profile file for package '{}' is empty: {}",
            package_name,
            profile_path
        );
    }
    let module_bytes =
        read_artifact_regular_bytes_no_symlink(artifact_store_path, Path::new(&module_path))
            .with_context(|| {
                format!(
                    "MAC module file for package '{}' is missing required {}",
                    package_name, module_path
                )
            })?;
    if module_bytes.is_empty() {
        bail!(
            "MAC module file for package '{}' is empty: {}",
            package_name,
            module_path
        );
    }
    let source_text =
        read_artifact_regular_file_no_symlink(artifact_store_path, Path::new(&source_path))
            .with_context(|| {
                format!(
                    "MAC source file for package '{}' is missing required {}",
                    package_name, source_path
                )
            })?;
    let expected_profile = expected_selinux_profile(expected_label);
    if source_text.trim_end() != expected_profile.trim_end() {
        bail!(
            "MAC source file for package '{}' does not match the expected default-deny scaffold",
            package_name
        );
    }
    validate_compiled_selinux_profile(
        package_name,
        &source_text,
        &module_name,
        &module_path,
        &module_bytes,
        &profile_path,
        &profile_bytes,
    )?;
    Ok(Some(profile))
}

fn validate_compiled_selinux_profile(
    package_name: &str,
    source_text: &str,
    module_name: &str,
    module_path: &str,
    module_bytes: &[u8],
    profile_path: &str,
    profile_bytes: &[u8],
) -> Result<()> {
    let expected = compile_selinux_profile(source_text, module_name)
        .with_context(|| format!("rebuilding SELinux profile for package '{package_name}'"))?;
    if module_bytes != expected.module {
        bail!(
            "MAC module file for package '{}' does not match the validated SELinux source: {}",
            package_name,
            module_path
        );
    }
    if profile_bytes != expected.profile {
        bail!(
            "MAC profile file for package '{}' does not match the validated SELinux source: {}",
            package_name,
            profile_path
        );
    }
    Ok(())
}

#[cfg(test)]
fn compile_selinux_profile(
    source_text: &str,
    _module_name: &str,
) -> Result<CompiledSelinuxProfile> {
    Ok(CompiledSelinuxProfile {
        module: format!("compiled-module\n{source_text}").into_bytes(),
        profile: format!("compiled-policy\n{source_text}").into_bytes(),
    })
}

#[cfg(not(test))]
fn compile_selinux_profile(source_text: &str, module_name: &str) -> Result<CompiledSelinuxProfile> {
    let checkmodule = trusted_checkmodule_path()?;
    let semodule_package = trusted_semodule_package_path()?;
    let tmp = TempDir::new().context("creating SELinux policy validation tempdir")?;
    let source_path = tmp.path().join(format!("{module_name}.te"));
    let module_path = tmp.path().join(format!("{module_name}.mod"));
    let profile_path = tmp.path().join(format!("{module_name}.pp"));
    std::fs::write(&source_path, source_text)
        .with_context(|| format!("writing {}", source_path.display()))?;
    run_selinux_policy_tool(
        &checkmodule,
        &[
            OsStr::new("-M"),
            OsStr::new("-m"),
            OsStr::new("-o"),
            module_path.as_os_str(),
            source_path.as_os_str(),
        ],
    )?;
    run_selinux_policy_tool(
        &semodule_package,
        &[
            OsStr::new("-o"),
            profile_path.as_os_str(),
            OsStr::new("-m"),
            module_path.as_os_str(),
        ],
    )?;
    Ok(CompiledSelinuxProfile {
        module: std::fs::read(&module_path)
            .with_context(|| format!("reading {}", module_path.display()))?,
        profile: std::fs::read(&profile_path)
            .with_context(|| format!("reading {}", profile_path.display()))?,
    })
}

#[cfg(not(test))]
fn run_selinux_policy_tool(program: &str, args: &[&OsStr]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!(
            "{} failed with status {}: {}{}",
            program,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn read_artifact_regular_file_no_symlink(root: &Path, relative_path: &Path) -> Result<String> {
    let current = artifact_regular_file_no_symlink(root, relative_path)?;
    std::fs::read_to_string(&current).with_context(|| format!("reading {}", current.display()))
}

fn read_artifact_regular_bytes_no_symlink(root: &Path, relative_path: &Path) -> Result<Vec<u8>> {
    let current = artifact_regular_file_no_symlink(root, relative_path)?;
    std::fs::read(&current).with_context(|| format!("reading {}", current.display()))
}

fn artifact_regular_file_no_symlink(root: &Path, relative_path: &Path) -> Result<PathBuf> {
    let mut components = relative_path.components().peekable();
    if components.peek().is_none() {
        bail!("artifact-relative path is empty");
    }

    let mut current = root.to_path_buf();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            bail!(
                "artifact-relative path contains unsupported component: {}",
                relative_path.display()
            );
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("checking {}", current.display()))?;
        if components.peek().is_some() {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                bail!(
                    "artifact path component is not a non-symlink directory: {}",
                    current.display()
                );
            }
        } else if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!(
                "artifact path is not a non-symlink regular file: {}",
                current.display()
            );
        }
    }

    Ok(current)
}

fn expected_selinux_profile_path(label: &str) -> String {
    format!("mac/selinux/{}.pp", selinux_identifier_for_label(label))
}

fn selinux_identifier_for_label(label: &str) -> String {
    let mut normalized = String::with_capacity(label.len());
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            normalized.push(byte as char);
        } else {
            normalized.push_str(&format!("_x{byte:02x}"));
        }
    }
    if normalized
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        normalized
    } else {
        format!("aos_pkg_{normalized}")
    }
}

fn selinux_type_for_label(label: &str) -> String {
    format!("{}_t", selinux_identifier_for_label(label))
}

fn expected_selinux_context(label: &str) -> String {
    format!("system_u:system_r:{}", selinux_type_for_label(label))
}

fn expected_selinux_profile(label: &str) -> String {
    let module_name = selinux_identifier_for_label(label);
    let type_name = selinux_type_for_label(label);
    format!(
        "# Generated by AOS package expose renderer.\n# RFC-0001 per-package SELinux default-deny module.\nmodule {module_name} 1.0;\n\nrequire {{\n  type init_t;\n  type kernel_t;\n  type root_t;\n  type tmp_t;\n  type tmpfs_t;\n  type unlabeled_t;\n  type var_lib_t;\n  type var_t;\n  attribute domain;\n  attribute file_type;\n  role system_r;\n  class dir {{ getattr open read search }};\n  class fd use;\n  class file {{ execute execute_no_trans execmod getattr map open read }};\n  class lnk_file {{ getattr read }};\n  class process {{ dyntransition execmem execstack execheap }};\n  class process2 {{ nnp_transition nosuid_transition }};\n}}\n\ntype {type_name};\ntypeattribute {type_name} domain;\nrole system_r types {type_name};\n\nallow {type_name} init_t:fd use;\nallow init_t {type_name}:process dyntransition;\nallow init_t {type_name}:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} kernel_t:fd use;\nallow kernel_t {type_name}:process dyntransition;\nallow kernel_t {type_name}:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} self:process {{ execmem execstack execheap }};\nallow {type_name} self:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} file_type:file execmod;\nallow {type_name} root_t:dir {{ getattr open read search }};\nallow {type_name} tmp_t:dir {{ getattr open read search }};\nallow {type_name} tmp_t:lnk_file {{ getattr read }};\nallow {type_name} tmpfs_t:dir {{ getattr open read search }};\nallow {type_name} tmpfs_t:lnk_file {{ getattr read }};\nallow {type_name} unlabeled_t:dir {{ getattr open read search }};\nallow {type_name} unlabeled_t:file {{ execute execute_no_trans execmod getattr map open read }};\nallow {type_name} unlabeled_t:lnk_file {{ getattr read }};\nallow {type_name} var_t:dir {{ getattr open read search }};\nallow {type_name} var_t:lnk_file {{ getattr read }};\nallow {type_name} var_lib_t:dir {{ getattr open read search }};\nallow {type_name} var_lib_t:lnk_file {{ getattr read }};\n"
    )
}

fn validate_socket_listener_permissions(
    package_name: &str,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    permissions: &PermissionsMeta,
) -> Result<()> {
    for unit in units {
        if !unit.ends_with(".socket") {
            continue;
        }
        let path = artifact_root.join(unit);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading exposed socket unit {}", path.display()))?;
        let parsed = Parsed::parse(&text);
        let Some(socket) = parsed.sections.get("Socket") else {
            continue;
        };
        let Some(listen_streams) = socket.get("ListenStream") else {
            continue;
        };
        for listen_stream in listen_streams {
            let Some(port) = tcp_listen_stream_port(listen_stream).with_context(|| {
                format!(
                    "validating ListenStream endpoint '{}' for package '{}' socket unit '{}'",
                    listen_stream, package_name, unit
                )
            })?
            else {
                continue;
            };
            if !permissions.tcp_bind.contains(&port) {
                bail!(
                    "socket unit '{}' for package '{}' binds TCP port {} without a matching permissions.tcp-bind grant",
                    unit,
                    package_name,
                    port
                );
            }
        }
    }
    Ok(())
}

fn tcp_listen_stream_port(value: &str) -> Result<Option<u16>> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('@')
        || value.starts_with("vsock:")
    {
        return Ok(None);
    }
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        return parse_tcp_listen_port(value).map(Some);
    }
    if let Some((_, port)) = value.rsplit_once("]:")
        && value.starts_with('[')
    {
        return parse_tcp_listen_port(port).map(Some);
    }
    if value.matches(':').count() == 1 {
        let (_, port) = value
            .rsplit_once(':')
            .context("TCP ListenStream endpoint has no port")?;
        if port.chars().all(|ch| ch.is_ascii_digit()) {
            return parse_tcp_listen_port(port).map(Some);
        }
    }
    bail!(
        "unsupported ListenStream endpoint '{value}'; use a Unix socket path or a TCP port/host:port endpoint"
    )
}

fn parse_tcp_listen_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .with_context(|| format!("invalid TCP ListenStream port '{value}'"))?;
    if port == 0 {
        bail!("TCP ListenStream port must be between 1 and 65535");
    }
    Ok(port)
}

fn normalized_permissions(package_name: &str, permissions: &PermissionsMeta) -> PermissionsMeta {
    let mut normalized = permissions.clone();
    if normalized.security_label.is_none() {
        normalized.security_label = Some(format!("aos-pkg-{package_name}"));
    }
    if normalized.confinement.is_none() {
        normalized.confinement = Some(normalized.computed_confinement());
    }
    normalized
}

fn validate_workload_exec_wrappers(
    package_name: &str,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    permissions: &PermissionsMeta,
) -> Result<()> {
    let permissions = normalized_permissions(package_name, permissions);
    if permissions
        .confinement
        .as_ref()
        .context("normalized permissions have no confinement summary")?
        .class
        == ConfinementClass::Unconfined
    {
        return Ok(());
    }

    let expected_service_paths =
        expected_landlock_service_paths(package_name, artifact_root, units).with_context(|| {
            format!("reading service directory grants for package '{package_name}'")
        })?;
    let expected_args = expected_landlock_args(&permissions, &expected_service_paths);
    let trusted_selinux_runner = trusted_selinux_runner_path()?;
    let trusted_landlock_wrapper = trusted_landlock_wrapper_path()?;
    let trusted_verity_root_guard = trusted_verity_root_guard_path()?;
    let expected_context = expected_selinux_context(
        permissions
            .security_label
            .as_deref()
            .context("normalized permissions have no security label")?,
    );
    for unit in units {
        if !unit.ends_with(".service")
            || is_generated_expose_side_effect_service(package_name, unit)
        {
            continue;
        }
        let path = artifact_root.join(unit);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading exposed unit {}", path.display()))?;
        let parsed = Parsed::parse(&text);
        let Some(service) = parsed.sections.get("Service") else {
            continue;
        };
        for key in LANDLOCK_EXEC_KEYS {
            let Some(commands) = service.get(*key) else {
                continue;
            };
            for command in commands {
                let tokens = command.split_whitespace().collect::<Vec<_>>();
                let is_signature_only_precheck = *key == "ExecStartPre"
                    && tokens
                        .first()
                        .is_some_and(|token| *token == trusted_verity_root_guard)
                    && tokens
                        .get(1)
                        .is_some_and(|token| *token == "--signature-only");
                let command_tokens = validate_verity_root_guard_exec_command(
                    package_name,
                    unit,
                    key,
                    &tokens,
                    &trusted_verity_root_guard,
                    service,
                )?;
                if is_signature_only_precheck && command_tokens.is_empty() {
                    continue;
                }
                let command_tokens = validate_selinux_exec_command(
                    package_name,
                    unit,
                    key,
                    command_tokens,
                    &trusted_selinux_runner,
                    &expected_context,
                )?;
                validate_landlock_exec_command(
                    package_name,
                    unit,
                    key,
                    command_tokens,
                    &trusted_landlock_wrapper,
                    &expected_args,
                )?;
            }
        }
    }

    Ok(())
}

fn validate_workload_roots(
    package_name: &str,
    runtime_store_path: &Path,
    artifact_store_path: &Path,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    expose: &ExposeMeta,
    permissions: &PermissionsMeta,
) -> Result<()> {
    let verity_images = expose
        .images
        .iter()
        .filter(|image| is_verity_root_image(image))
        .collect::<Vec<_>>();
    if verity_images.len() > 1 {
        bail!("package '{package_name}' declares multiple verity root images");
    }
    let expected = verity_images.first().copied();
    let confinement = normalized_permissions(package_name, permissions)
        .confinement
        .context("normalized permissions have no confinement summary")?
        .class;
    let root_unit = format!("aos-pkg-{package_name}-service-roots.service");
    let workload_units = units
        .iter()
        .filter(|unit| {
            unit.ends_with(".service")
                && !is_generated_expose_side_effect_service(package_name, unit)
        })
        .cloned()
        .collect::<Vec<_>>();
    let uses_overlay_roots = expected.is_none()
        && confinement != ConfinementClass::Unconfined
        && !workload_units.is_empty();

    if uses_overlay_roots {
        validate_service_root_preparation(
            package_name,
            runtime_store_path,
            artifact_root,
            &root_unit,
            &workload_units,
        )?;
    } else if units.contains(&root_unit) {
        bail!(
            "package '{package_name}' declares a service-root preparation unit without confined non-verity workloads"
        );
    }

    for unit in &workload_units {
        let path = artifact_root.join(unit);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading exposed unit {}", path.display()))?;
        let parsed = Parsed::parse(&text);
        let Some(service) = parsed.sections.get("Service") else {
            if expected.is_some() {
                bail!(
                    "service unit '{}' for package '{}' is missing [Service] for RootImage validation",
                    unit,
                    package_name
                );
            }
            continue;
        };

        let root_image_keys = [
            "RootImage",
            "RootVerity",
            "RootHash",
            "RootHashSignature",
            "RootImagePolicy",
        ];
        if let Some(image) = expected {
            validate_expected_workload_root_image(package_name, unit, &parsed, service, image)?;
        } else if root_image_keys.iter().any(|key| service.contains_key(*key)) {
            bail!(
                "service unit '{}' for package '{}' declares RootImage dm-verity directives without signed expose.images metadata",
                unit,
                package_name
            );
        } else if uses_overlay_roots {
            let expected_root = format!("/run/aos/service-roots/{package_name}/{unit}/merged");
            require_service_value(package_name, unit, service, "RootDirectory", &expected_root)?;
            if Path::new(&expected_root) == runtime_store_path
                || expected_root.starts_with(artifact_store_path.to_string_lossy().as_ref())
            {
                bail!(
                    "service unit '{unit}' for package '{package_name}' must use its volatile overlay root"
                );
            }
            require_section_word(package_name, unit, &parsed, "Unit", "After", &root_unit)?;
            require_section_word(package_name, unit, &parsed, "Unit", "Requires", &root_unit)?;
        }
    }

    Ok(())
}

fn validate_service_root_preparation(
    package_name: &str,
    runtime_store_path: &Path,
    artifact_root: &Path,
    root_unit: &str,
    workload_units: &[String],
) -> Result<()> {
    let path = artifact_root.join(root_unit);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading service-root preparation unit {}", path.display()))?;
    let parsed = Parsed::parse(&text);
    let service = parsed.sections.get("Service").with_context(|| {
        format!("service-root preparation unit '{root_unit}' has no [Service] section")
    })?;
    let trusted_helper = trusted_service_root_helper_path()?;
    let mut expected_prepare = vec![
        trusted_helper.as_str(),
        "prepare",
        package_name,
        runtime_store_path
            .to_str()
            .context("runtime package store path is not UTF-8")?,
    ];
    expected_prepare.extend(workload_units.iter().map(String::as_str));
    let prepare = single_service_value(package_name, root_unit, service, "ExecStart")?;
    if prepare.split_whitespace().collect::<Vec<_>>() != expected_prepare {
        bail!(
            "service-root preparation unit '{root_unit}' for package '{package_name}' has an invalid trusted-helper prepare command"
        );
    }
    let expected_cleanup = format!(
        "{trusted_helper} cleanup {package_name} {} {}",
        runtime_store_path.display(),
        workload_units.join(" ")
    );
    require_service_value(
        package_name,
        root_unit,
        service,
        "ExecStop",
        &expected_cleanup,
    )?;
    require_service_value(
        package_name,
        root_unit,
        service,
        "ExecStopPost",
        &expected_cleanup,
    )?;
    require_service_value(package_name, root_unit, service, "Type", "oneshot")?;
    require_service_value(package_name, root_unit, service, "RemainAfterExit", "true")?;
    require_service_value(
        package_name,
        root_unit,
        service,
        "CapabilityBoundingSet",
        "CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN",
    )?;
    require_service_value(
        package_name,
        root_unit,
        service,
        "AmbientCapabilities",
        "CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN",
    )?;
    require_service_value(package_name, root_unit, service, "PrivateMounts", "false")?;
    require_service_value(package_name, root_unit, service, "NoNewPrivileges", "false")?;
    require_service_value(
        package_name,
        root_unit,
        service,
        "RestrictAddressFamilies",
        "AF_UNIX",
    )?;
    require_service_value(package_name, root_unit, service, "UMask", "0077")?;
    let target = format!("aos-pkg-{package_name}.target");
    require_section_word(package_name, root_unit, &parsed, "Unit", "PartOf", &target)?;
    require_section_word(
        package_name,
        root_unit,
        &parsed,
        "Install",
        "WantedBy",
        &target,
    )?;
    for unit in workload_units {
        require_section_word(package_name, root_unit, &parsed, "Unit", "Before", unit)?;
    }
    Ok(())
}

fn validate_expected_workload_root_image(
    package_name: &str,
    unit: &str,
    parsed: &Parsed,
    service: &BTreeMap<String, Vec<String>>,
    image: &SysrootImageEntry,
) -> Result<()> {
    if service.contains_key("RootDirectory") {
        bail!(
            "service unit '{}' for package '{}' must not combine RootDirectory with RootImage",
            unit,
            package_name
        );
    }
    require_section_word(
        package_name,
        unit,
        parsed,
        "Unit",
        "After",
        "systemd-udevd.service",
    )?;
    require_section_word(
        package_name,
        unit,
        parsed,
        "Unit",
        "Requires",
        "systemd-udevd.service",
    )?;

    let root_image = required_verity_image_member(package_name, image, "root_image")?;
    let root_verity = required_verity_image_member(package_name, image, "root_verity")?;
    let root_hash = image.root_hash.as_deref().with_context(|| {
        format!(
            "verity image '{}' for package '{}' is missing root_hash",
            image.store_path, package_name
        )
    })?;
    let root_hash_sig = required_verity_image_member(package_name, image, "root_hash_sig")?;

    require_service_value(
        package_name,
        unit,
        service,
        "RootImage",
        &image_member_path(&image.store_path, root_image),
    )?;
    require_service_value(
        package_name,
        unit,
        service,
        "RootVerity",
        &image_member_path(&image.store_path, root_verity),
    )?;
    require_service_value(
        package_name,
        unit,
        service,
        "RootHash",
        root_hash_hex(root_hash),
    )?;
    require_service_value(
        package_name,
        unit,
        service,
        "RootHashSignature",
        &image_member_path(&image.store_path, root_hash_sig),
    )?;
    require_service_value(
        package_name,
        unit,
        service,
        "RootImagePolicy",
        "root=signed",
    )?;
    require_service_value(package_name, unit, service, "PrivateDevices", "false")?;
    require_service_value(package_name, unit, service, "PermissionsStartOnly", "true")?;
    let trusted_guard = trusted_verity_root_guard_path()?;
    let has_precheck = service.get("ExecStartPre").is_some_and(|values| {
        values.iter().any(|value| {
            value
                .split_whitespace()
                .next()
                .is_some_and(|first| first == trusted_guard)
        })
    });
    if !has_precheck {
        bail!(
            "service unit '{}' for package '{}' must run aos-verity-root-guard in ExecStartPre",
            unit,
            package_name
        );
    }

    Ok(())
}

fn is_verity_root_image(image: &SysrootImageEntry) -> bool {
    matches!(image.format.as_str(), "ext4-verity" | "erofs-verity")
}

fn required_verity_image_member<'a>(
    package_name: &str,
    image: &'a SysrootImageEntry,
    field: &str,
) -> Result<&'a str> {
    let value = match field {
        "root_image" => image.root_image.as_deref(),
        "root_verity" => image.root_verity.as_deref(),
        "root_hash_sig" => image.root_hash_sig.as_deref(),
        _ => None,
    };
    value.with_context(|| {
        format!(
            "verity image '{}' for package '{}' is missing {field}",
            image.store_path, package_name
        )
    })
}

fn image_member_path(store_path: &str, member: &str) -> String {
    Path::new(store_path).join(member).display().to_string()
}

fn root_hash_hex(hash: &str) -> &str {
    hash.strip_prefix("sha256:")
        .or_else(|| hash.strip_prefix("sha256-"))
        .unwrap_or(hash)
}

fn validate_ebpf_policy_service(
    package_name: &str,
    target: &str,
    artifact_store_path: &Path,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    permissions: &PermissionsMeta,
) -> Result<()> {
    let permissions = normalized_permissions(package_name, permissions);
    let package_slice = expected_package_slice(package_name);
    if !units.contains(&package_slice) {
        bail!(
            "eBPF network policy for package '{}' is missing required package slice {}",
            package_name,
            package_slice
        );
    }
    validate_package_slice_membership(package_name, artifact_root, units, &package_slice)?;

    let ebpf_unit = expected_ebpf_unit(package_name);
    let unconfined = permissions
        .confinement
        .as_ref()
        .context("normalized permissions have no confinement summary")?
        .class
        == ConfinementClass::Unconfined;
    let network_unrestricted = permissions.network == Some(NetworkPermission::Host);
    if unconfined || network_unrestricted {
        if units.contains(&ebpf_unit) {
            bail!(
                "package '{}' without eBPF network confinement must not declare network policy service {}",
                package_name,
                ebpf_unit
            );
        }
        return Ok(());
    }
    if !units.contains(&ebpf_unit) {
        bail!(
            "eBPF network policy for package '{}' is missing required service {}",
            package_name,
            ebpf_unit
        );
    }
    validate_target_membership(package_name, target, artifact_root, &ebpf_unit)?;
    validate_workload_side_effect_ordering(package_name, artifact_root, units, &ebpf_unit)?;

    let path = artifact_root.join(&ebpf_unit);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading eBPF policy unit {}", path.display()))?;
    let parsed = Parsed::parse(&text);
    let service = parsed
        .sections
        .get("Service")
        .with_context(|| format!("eBPF policy unit '{}' is missing [Service]", ebpf_unit))?;

    require_service_value(package_name, &ebpf_unit, service, "Type", "notify")?;
    require_service_value(package_name, &ebpf_unit, service, "NotifyAccess", "main")?;
    require_service_value(package_name, &ebpf_unit, service, "Slice", &package_slice)?;
    require_section_word(package_name, &ebpf_unit, &parsed, "Unit", "PartOf", target)?;
    require_section_word(
        package_name,
        &ebpf_unit,
        &parsed,
        "Install",
        "WantedBy",
        target,
    )?;
    require_service_value(package_name, &ebpf_unit, service, "NoNewPrivileges", "true")?;
    require_service_value(
        package_name,
        &ebpf_unit,
        service,
        "CapabilityBoundingSet",
        "CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE",
    )?;
    require_service_value(
        package_name,
        &ebpf_unit,
        service,
        "LimitMEMLOCK",
        "infinity",
    )?;
    require_service_value(package_name, &ebpf_unit, service, "PrivateDevices", "true")?;
    require_service_value(package_name, &ebpf_unit, service, "DevicePolicy", "closed")?;
    require_service_value(package_name, &ebpf_unit, service, "PrivateNetwork", "true")?;
    require_service_value(package_name, &ebpf_unit, service, "ProtectSystem", "strict")?;
    require_service_value(package_name, &ebpf_unit, service, "ProtectHome", "true")?;
    require_service_value(
        package_name,
        &ebpf_unit,
        service,
        "RestrictAddressFamilies",
        "AF_UNIX",
    )?;
    require_service_value(
        package_name,
        &ebpf_unit,
        service,
        "RestrictNamespaces",
        "true",
    )?;
    require_service_value(
        package_name,
        &ebpf_unit,
        service,
        "MemoryDenyWriteExecute",
        "true",
    )?;
    if service.contains_key("RootDirectory") {
        bail!(
            "eBPF network policy service '{}' for package '{}' must run host-side",
            ebpf_unit,
            package_name
        );
    }

    let exec_start = single_service_value(package_name, &ebpf_unit, service, "ExecStart")?;
    let expected = expected_ebpf_exec_command(package_name, artifact_store_path)?;
    let actual = exec_start
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if actual != expected {
        bail!(
            "eBPF network policy service '{}' for package '{}' has invalid aos-ebpf-net-policy command",
            ebpf_unit,
            package_name
        );
    }

    Ok(())
}

fn validate_target_membership(
    package_name: &str,
    target: &str,
    artifact_root: &Path,
    side_effect_unit: &str,
) -> Result<()> {
    let path = artifact_root.join(target);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading exposed target unit {}", path.display()))?;
    let parsed = Parsed::parse(&text);
    require_section_word(
        package_name,
        target,
        &parsed,
        "Unit",
        "Wants",
        side_effect_unit,
    )?;
    Ok(())
}

fn validate_package_slice_membership(
    package_name: &str,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    package_slice: &str,
) -> Result<()> {
    for unit in units {
        if !unit.ends_with(".service")
            || is_generated_expose_side_effect_service(package_name, unit)
        {
            continue;
        }
        let path = artifact_root.join(unit);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading exposed unit {}", path.display()))?;
        let parsed = Parsed::parse(&text);
        let service = parsed
            .sections
            .get("Service")
            .with_context(|| format!("exposed service unit '{}' is missing [Service]", unit))?;
        require_service_value(package_name, unit, service, "Slice", package_slice)?;
    }
    Ok(())
}

fn validate_workload_side_effect_ordering(
    package_name: &str,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    side_effect_unit: &str,
) -> Result<()> {
    for unit in units {
        if !unit.ends_with(".service")
            || is_generated_expose_side_effect_service(package_name, unit)
        {
            continue;
        }
        let path = artifact_root.join(unit);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading exposed unit {}", path.display()))?;
        let parsed = Parsed::parse(&text);
        require_section_word(
            package_name,
            unit,
            &parsed,
            "Unit",
            "After",
            side_effect_unit,
        )?;
        require_section_word(
            package_name,
            unit,
            &parsed,
            "Unit",
            "Requires",
            side_effect_unit,
        )?;
    }
    Ok(())
}

fn expected_package_slice(package_name: &str) -> String {
    format!("aos-pkg-{package_name}.slice")
}

fn expected_mac_unit(package_name: &str) -> String {
    format!("aos-pkg-{package_name}-mac.service")
}

fn expected_ebpf_unit(package_name: &str) -> String {
    format!("aos-pkg-{package_name}-ebpf.service")
}

fn expected_mac_exec_command(
    artifact_store_path: &Path,
    permissions: &PermissionsMeta,
) -> Result<Vec<String>> {
    let expected_label = permissions
        .security_label
        .as_deref()
        .context("normalized permissions have no security label")?;
    Ok(vec![
        trusted_semodule_path()?,
        "-i".to_string(),
        artifact_store_path
            .join(expected_selinux_profile_path(expected_label))
            .display()
            .to_string(),
    ])
}

fn expected_ebpf_exec_command(
    package_name: &str,
    artifact_store_path: &Path,
) -> Result<Vec<String>> {
    Ok(vec![
        trusted_ebpf_net_policy_path()?,
        "run".to_string(),
        "--policy".to_string(),
        artifact_store_path
            .join("network-policy.json")
            .display()
            .to_string(),
        "--cgroup".to_string(),
        expected_ebpf_cgroup_path(package_name),
        "--object".to_string(),
        trusted_ebpf_net_policy_object_path()?,
    ])
}

fn expected_ebpf_cgroup_path(package_name: &str) -> String {
    format!(
        "/sys/fs/cgroup/{}",
        systemd_slice_cgroup_path(&expected_package_slice(package_name))
    )
}

fn systemd_slice_cgroup_path(slice: &str) -> String {
    let stem = slice.strip_suffix(".slice").unwrap_or(slice);
    let mut prefix = String::new();
    let mut components = Vec::new();
    for part in stem.split('-') {
        if prefix.is_empty() {
            prefix.push_str(part);
        } else {
            prefix.push('-');
            prefix.push_str(part);
        }
        components.push(format!("{prefix}.slice"));
    }
    components.join("/")
}

fn trusted_ebpf_net_policy_path() -> Result<String> {
    if let Ok(path) = std::env::var(EBPF_NET_POLICY_ENV) {
        if path.is_empty() {
            bail!("{EBPF_NET_POLICY_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/aos-ebpf-net-policy") {
            bail!("{EBPF_NET_POLICY_ENV} must point to an absolute aos-ebpf-net-policy binary");
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok("/nix/store/hash-aos-ebpf-net-policy-0/bin/aos-ebpf-net-policy".to_string());
    }

    #[cfg(not(test))]
    {
        bail!("{EBPF_NET_POLICY_ENV} is not configured for network policy validation");
    }
}

fn trusted_ebpf_net_policy_object_path() -> Result<String> {
    if let Ok(path) = std::env::var(EBPF_NET_POLICY_OBJECT_ENV) {
        if path.is_empty() {
            bail!("{EBPF_NET_POLICY_OBJECT_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/lib/bpf/aos-ebpf-net-policy.bpf.o") {
            bail!(
                "{EBPF_NET_POLICY_OBJECT_ENV} must point to an absolute aos-ebpf-net-policy BPF object"
            );
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok(
            "/nix/store/hash-aos-ebpf-net-policy-0/lib/bpf/aos-ebpf-net-policy.bpf.o".to_string(),
        );
    }

    #[cfg(not(test))]
    {
        bail!("{EBPF_NET_POLICY_OBJECT_ENV} is not configured for network policy validation");
    }
}

#[cfg(not(test))]
fn trusted_checkmodule_path() -> Result<String> {
    if let Ok(path) = std::env::var(CHECKMODULE_ENV) {
        if path.is_empty() {
            bail!("{CHECKMODULE_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/checkmodule") {
            bail!("{CHECKMODULE_ENV} must point to an absolute checkmodule binary");
        }
        return Ok(path);
    }

    bail!("{CHECKMODULE_ENV} is not configured for MAC policy validation");
}

fn trusted_semodule_path() -> Result<String> {
    if let Ok(path) = std::env::var(SEMODULE_ENV) {
        if path.is_empty() {
            bail!("{SEMODULE_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/sbin/semodule") {
            bail!("{SEMODULE_ENV} must point to an absolute semodule binary");
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok("/nix/store/hash-policycoreutils-0/sbin/semodule".to_string());
    }

    #[cfg(not(test))]
    {
        bail!("{SEMODULE_ENV} is not configured for MAC policy validation");
    }
}

#[cfg(not(test))]
fn trusted_semodule_package_path() -> Result<String> {
    if let Ok(path) = std::env::var(SEMODULE_PACKAGE_ENV) {
        if path.is_empty() {
            bail!("{SEMODULE_PACKAGE_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/semodule_package") {
            bail!("{SEMODULE_PACKAGE_ENV} must point to an absolute semodule_package binary");
        }
        return Ok(path);
    }

    bail!("{SEMODULE_PACKAGE_ENV} is not configured for MAC policy validation");
}

fn single_service_value<'a>(
    package_name: &str,
    unit: &str,
    service: &'a BTreeMap<String, Vec<String>>,
    key: &str,
) -> Result<&'a str> {
    let values = service.get(key).with_context(|| {
        format!("service unit '{unit}' for package '{package_name}' is missing {key}")
    })?;
    if values.len() != 1 {
        bail!(
            "service unit '{}' for package '{}' must contain exactly one {} entry",
            unit,
            package_name,
            key
        );
    }
    Ok(&values[0])
}

fn require_service_value(
    package_name: &str,
    unit: &str,
    service: &BTreeMap<String, Vec<String>>,
    key: &str,
    expected: &str,
) -> Result<()> {
    let actual = single_service_value(package_name, unit, service, key)?;
    if actual != expected {
        bail!(
            "service unit '{}' for package '{}' has invalid {} value: expected '{}', got '{}'",
            unit,
            package_name,
            key,
            expected,
            actual
        );
    }
    Ok(())
}

fn require_section_word(
    package_name: &str,
    unit: &str,
    parsed: &Parsed,
    section: &str,
    key: &str,
    expected: &str,
) -> Result<()> {
    let values = parsed
        .sections
        .get(section)
        .and_then(|section| section.get(key))
        .with_context(|| {
            format!("unit '{unit}' for package '{package_name}' is missing {section}.{key}")
        })?;
    if !values
        .iter()
        .any(|value| value.split_whitespace().any(|word| word == expected))
    {
        bail!(
            "unit '{}' for package '{}' must include {} in {}.{}",
            unit,
            package_name,
            expected,
            section,
            key
        );
    }
    Ok(())
}

fn requires_landlock_wrapper(package_name: &str, permissions: &PermissionsMeta) -> Result<bool> {
    let permissions = normalized_permissions(package_name, permissions);
    Ok(permissions
        .confinement
        .as_ref()
        .context("normalized permissions have no confinement summary")?
        .class
        != ConfinementClass::Unconfined)
}

fn expected_landlock_args(permissions: &PermissionsMeta, service_paths: &[String]) -> Vec<String> {
    let mut args = vec!["--require-abi".to_string(), "4".to_string()];
    let network_unrestricted = permissions.network == Some(NetworkPermission::Host);
    if network_unrestricted {
        args.push("--network-unrestricted".to_string());
    }
    let fs = expected_landlock_fs(permissions, service_paths);
    for path in fs.read_only {
        args.push("--fs-ro".to_string());
        args.push(path);
    }
    for path in fs.read_write {
        args.push("--fs-rw".to_string());
        args.push(path);
    }
    if !network_unrestricted {
        for port in &permissions.tcp_bind {
            args.push("--tcp-bind".to_string());
            args.push(port.to_string());
        }
        for port in &permissions.tcp_connect {
            args.push("--tcp-connect".to_string());
            args.push(port.to_string());
        }
    }
    args.push("--".to_string());
    args
}

fn expected_manifest_fs(permissions: &PermissionsMeta) -> NetworkPolicyFs {
    let mut read_only = Vec::new();
    let mut read_write = Vec::new();
    for host_path in &permissions.host_paths {
        match host_path.mode {
            HostPathMode::ReadOnly => read_only.push(host_path.path.clone()),
            HostPathMode::Rw => read_write.push(host_path.path.clone()),
        }
    }
    NetworkPolicyFs {
        read_only,
        read_write,
    }
}

fn expected_landlock_fs(
    permissions: &PermissionsMeta,
    service_paths: &[String],
) -> NetworkPolicyFs {
    let unconfined = permissions
        .confinement
        .as_ref()
        .is_some_and(|confinement| confinement.class == ConfinementClass::Unconfined);
    if unconfined {
        return NetworkPolicyFs {
            read_only: Vec::new(),
            read_write: Vec::new(),
        };
    }

    let mut read_write = vec![
        "/tmp".to_string(),
        "/var/tmp".to_string(),
        "/dev/null".to_string(),
    ];
    for path in service_paths {
        if !read_write.contains(path) {
            read_write.push(path.clone());
        }
    }
    for host_path in &permissions.host_paths {
        if host_path.mode == HostPathMode::Rw && !read_write.contains(&host_path.path) {
            read_write.push(host_path.path.clone());
        }
    }

    let mut read_only = vec!["/".to_string()];
    for host_path in &permissions.host_paths {
        if host_path.mode == HostPathMode::ReadOnly
            && !read_only.contains(&host_path.path)
            && !read_write.contains(&host_path.path)
        {
            read_only.push(host_path.path.clone());
        }
    }

    NetworkPolicyFs {
        read_only,
        read_write,
    }
}

fn expected_landlock_service_paths(
    package_name: &str,
    artifact_root: &Path,
    units: &BTreeSet<String>,
) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for unit in units {
        if !unit.ends_with(".service")
            || is_generated_expose_side_effect_service(package_name, unit)
        {
            continue;
        }
        let path = artifact_root.join(unit);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading exposed unit {}", path.display()))?;
        let parsed = Parsed::parse(&text);
        let service_paths = parsed.sections.get("Service").map_or_else(
            || default_state_paths(package_name),
            |service| landlock_service_paths_for_service(package_name, service),
        );
        append_unique_strings(&mut paths, service_paths);
    }
    Ok(paths)
}

fn landlock_service_paths_for_service(
    package_name: &str,
    service: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let state_values = service
        .get("StateDirectory")
        .filter(|values| !values.is_empty())
        .cloned()
        .unwrap_or_else(|| vec![format!("aos-pkg-{package_name}")]);
    let mut paths = service_directory_values_to_paths("/var/lib", &state_values);
    for (key, prefix) in [
        ("RuntimeDirectory", "/run"),
        ("CacheDirectory", "/var/cache"),
        ("LogsDirectory", "/var/log"),
    ] {
        if let Some(values) = service.get(key) {
            append_unique_strings(
                &mut paths,
                service_directory_values_to_paths(prefix, values),
            );
        }
    }
    paths
}

fn default_state_paths(package_name: &str) -> Vec<String> {
    vec![format!("/var/lib/aos-pkg-{package_name}")]
}

fn service_directory_values_to_paths(prefix: &str, values: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    for value in values {
        for name in value.split_whitespace().filter(|name| !name.is_empty()) {
            append_unique_string(&mut paths, format!("{prefix}/{name}"));
        }
    }
    paths
}

fn append_unique_strings(values: &mut Vec<String>, additions: Vec<String>) {
    for value in additions {
        append_unique_string(values, value);
    }
}

fn append_unique_string(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn trusted_landlock_wrapper_path() -> Result<String> {
    if let Ok(path) = std::env::var(LANDLOCK_WRAPPER_ENV) {
        if path.is_empty() {
            bail!("{LANDLOCK_WRAPPER_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/aos-landlock") {
            bail!("{LANDLOCK_WRAPPER_ENV} must point to an absolute aos-landlock binary");
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok("/nix/store/hash-aos-landlock-0/bin/aos-landlock".to_string());
    }

    #[cfg(not(test))]
    {
        bail!("{LANDLOCK_WRAPPER_ENV} is not configured for network policy validation");
    }
}

fn trusted_selinux_runner_path() -> Result<String> {
    if let Ok(path) = std::env::var(SELINUX_RUNNER_ENV) {
        if path.is_empty() {
            bail!("{SELINUX_RUNNER_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/aos-selinux-run") {
            bail!("{SELINUX_RUNNER_ENV} must point to an absolute aos-selinux-run binary");
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok("/nix/store/hash-aos-selinux-run-0/bin/aos-selinux-run".to_string());
    }

    #[cfg(not(test))]
    {
        bail!("{SELINUX_RUNNER_ENV} is not configured for MAC policy validation");
    }
}

fn trusted_verity_root_guard_path() -> Result<String> {
    if let Ok(path) = std::env::var(VERITY_ROOT_GUARD_ENV) {
        if path.is_empty() {
            bail!("{VERITY_ROOT_GUARD_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/aos-verity-root-guard") {
            bail!("{VERITY_ROOT_GUARD_ENV} must point to an absolute aos-verity-root-guard binary");
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok("/nix/store/hash-aos-verity-root-guard-0/bin/aos-verity-root-guard".to_string());
    }

    #[cfg(not(test))]
    {
        bail!("{VERITY_ROOT_GUARD_ENV} is not configured for RootImage validation");
    }
}

fn trusted_service_root_helper_path() -> Result<String> {
    if let Ok(path) = std::env::var(SERVICE_ROOT_HELPER_ENV) {
        if path.is_empty() {
            bail!("{SERVICE_ROOT_HELPER_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/aos-service-root") {
            bail!("{SERVICE_ROOT_HELPER_ENV} must point to an absolute aos-service-root binary");
        }
        return Ok(path);
    }

    #[cfg(test)]
    {
        return Ok("/nix/store/hash-aos-service-root-0/bin/aos-service-root".to_string());
    }

    #[cfg(not(test))]
    {
        bail!("{SERVICE_ROOT_HELPER_ENV} is not configured for service-root validation");
    }
}

fn is_generated_expose_side_effect_service(package_name: &str, unit: &str) -> bool {
    [
        "host-paths",
        "service-roots",
        "modules",
        "sysctl",
        "firewall",
        "netns",
        "mac",
        "ebpf",
    ]
    .into_iter()
    .any(|suffix| unit == format!("aos-pkg-{package_name}-{suffix}.service"))
}

fn validate_verity_root_guard_exec_command<'a>(
    package_name: &str,
    unit: &str,
    key: &str,
    tokens: &'a [&'a str],
    trusted_guard: &str,
    service: &BTreeMap<String, Vec<String>>,
) -> Result<&'a [&'a str]> {
    let Some((guard, rest)) = tokens.split_first() else {
        return Ok(tokens);
    };
    if *guard != trusted_guard {
        return Ok(tokens);
    }
    let Some(root_hash) = service.get("RootHash").and_then(|values| values.first()) else {
        bail!(
            "workload service '{}' {} for package '{}' uses aos-verity-root-guard without RootHash",
            unit,
            key,
            package_name
        );
    };
    let expected_hash = root_hash_hex(root_hash);
    let Some(root_hash_signature) = service
        .get("RootHashSignature")
        .and_then(|values| values.first())
    else {
        bail!(
            "workload service '{}' {} for package '{}' uses aos-verity-root-guard without RootHashSignature",
            unit,
            key,
            package_name
        );
    };
    let signature_only = rest.first().is_some_and(|arg| *arg == "--signature-only");
    let offset = if signature_only { 1 } else { 0 };
    if signature_only
        && rest.len() == offset + 2
        && rest[offset] == expected_hash
        && rest[offset + 1] == root_hash_signature
    {
        return Ok(&[]);
    }
    if rest.len() < offset + 4
        || rest[offset] != expected_hash
        || rest[offset + 1] != root_hash_signature
        || rest[offset + 2] != "--"
    {
        bail!(
            "workload service '{}' {} for package '{}' has invalid aos-verity-root-guard arguments",
            unit,
            key,
            package_name
        );
    }
    Ok(&rest[offset + 3..])
}

fn validate_selinux_exec_command<'a>(
    package_name: &str,
    unit: &str,
    key: &str,
    tokens: &'a [&'a str],
    trusted_runner: &str,
    expected_context: &str,
) -> Result<&'a [&'a str]> {
    let Some((runner, rest)) = tokens.split_first() else {
        return Ok(tokens);
    };
    if runner
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'-' | b'@' | b':' | b'!' | b'+'))
        || *runner != trusted_runner
    {
        bail!(
            "workload service '{}' {} for package '{}' is missing required aos-selinux-run wrapper",
            unit,
            key,
            package_name
        );
    }
    if rest.len() < 4 || rest[0] != "--context" || rest[1] != expected_context || rest[2] != "--" {
        bail!(
            "workload service '{}' {} for package '{}' has invalid aos-selinux-run arguments",
            unit,
            key,
            package_name
        );
    }
    Ok(&rest[3..])
}

fn validate_landlock_exec_command(
    package_name: &str,
    unit: &str,
    key: &str,
    tokens: &[&str],
    trusted_wrapper: &str,
    expected_args: &[String],
) -> Result<()> {
    let Some((wrapper, rest)) = tokens.split_first() else {
        return Ok(());
    };
    if wrapper
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'-' | b'@' | b':' | b'!' | b'+'))
        || *wrapper != trusted_wrapper
    {
        bail!(
            "network policy service '{}' {} for package '{}' is missing required aos-landlock wrapper",
            unit,
            key,
            package_name
        );
    }
    if rest.len() <= expected_args.len()
        || !rest
            .iter()
            .zip(expected_args)
            .all(|(actual, expected)| *actual == expected)
    {
        bail!(
            "network policy service '{}' {} for package '{}' has invalid aos-landlock arguments",
            unit,
            key,
            package_name
        );
    }
    let command = &rest[expected_args.len()..];
    let Some(executable) = command.first() else {
        bail!(
            "network policy service '{}' {} for package '{}' is missing command after aos-landlock wrapper",
            unit,
            key,
            package_name
        );
    };
    if executable
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'-' | b'@' | b':' | b'|' | b'!' | b'+'))
        || !executable.starts_with('/')
    {
        bail!(
            "network policy service '{}' {} for package '{}' has command executable that cannot be preserved exactly by aos-landlock: {}",
            unit,
            key,
            package_name,
            executable
        );
    }
    Ok(())
}

fn validate_mac_policy_service(
    package_name: &str,
    target: &str,
    artifact_store_path: &Path,
    artifact_root: &Path,
    units: &BTreeSet<String>,
    profile: Option<&MacProfileArtifact>,
    permissions: &PermissionsMeta,
) -> Result<()> {
    let permissions = normalized_permissions(package_name, permissions);
    let package_slice = expected_package_slice(package_name);
    let mac_unit = expected_mac_unit(package_name);
    let unconfined = permissions
        .confinement
        .as_ref()
        .context("normalized permissions have no confinement summary")?
        .class
        == ConfinementClass::Unconfined;
    if unconfined || !profile.is_some_and(|profile| profile.default_deny) {
        if units.contains(&mac_unit) {
            bail!(
                "unconfined package '{}' must not declare MAC policy service {}",
                package_name,
                mac_unit
            );
        }
        return Ok(());
    }
    if !units.contains(&mac_unit) {
        bail!(
            "MAC policy for package '{}' is missing required service {}",
            package_name,
            mac_unit
        );
    }
    validate_target_membership(package_name, target, artifact_root, &mac_unit)?;
    validate_workload_side_effect_ordering(package_name, artifact_root, units, &mac_unit)?;

    let path = artifact_root.join(&mac_unit);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading MAC policy unit {}", path.display()))?;
    let parsed = Parsed::parse(&text);
    let service = parsed
        .sections
        .get("Service")
        .with_context(|| format!("MAC policy unit '{}' is missing [Service]", mac_unit))?;

    require_section_word(package_name, &mac_unit, &parsed, "Unit", "PartOf", target)?;
    require_section_word(
        package_name,
        &mac_unit,
        &parsed,
        "Unit",
        "ConditionSecurity",
        "selinux",
    )?;
    require_section_word(
        package_name,
        &mac_unit,
        &parsed,
        "Install",
        "WantedBy",
        target,
    )?;
    require_service_value(package_name, &mac_unit, service, "Type", "oneshot")?;
    require_service_value(package_name, &mac_unit, service, "RemainAfterExit", "true")?;
    require_service_value(package_name, &mac_unit, service, "Slice", &package_slice)?;
    require_service_value(package_name, &mac_unit, service, "NoNewPrivileges", "true")?;
    require_service_value(
        package_name,
        &mac_unit,
        service,
        "CapabilityBoundingSet",
        "CAP_MAC_ADMIN",
    )?;
    require_service_value(package_name, &mac_unit, service, "PrivateDevices", "true")?;
    require_service_value(package_name, &mac_unit, service, "DevicePolicy", "closed")?;
    require_service_value(package_name, &mac_unit, service, "PrivateNetwork", "true")?;
    require_service_value(package_name, &mac_unit, service, "ProtectSystem", "full")?;
    require_service_value(
        package_name,
        &mac_unit,
        service,
        "ReadWritePaths",
        "/etc/selinux /var/lib/selinux",
    )?;
    require_service_value(package_name, &mac_unit, service, "ProtectHome", "true")?;
    require_service_value(
        package_name,
        &mac_unit,
        service,
        "RestrictAddressFamilies",
        "AF_UNIX",
    )?;
    require_service_value(
        package_name,
        &mac_unit,
        service,
        "RestrictNamespaces",
        "true",
    )?;
    require_service_value(
        package_name,
        &mac_unit,
        service,
        "MemoryDenyWriteExecute",
        "true",
    )?;
    if service.contains_key("RootDirectory") {
        bail!(
            "MAC policy service '{}' for package '{}' must run host-side",
            mac_unit,
            package_name
        );
    }
    for key in MAC_LOADER_FORBIDDEN_EXEC_KEYS {
        if service.contains_key(*key) {
            bail!(
                "MAC policy service '{}' for package '{}' must not declare {}",
                mac_unit,
                package_name,
                key
            );
        }
    }

    let exec_start = single_service_value(package_name, &mac_unit, service, "ExecStart")?;
    let expected = expected_mac_exec_command(artifact_store_path, &permissions)?;
    let actual = exec_start
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if actual != expected {
        bail!(
            "MAC policy service '{}' for package '{}' has invalid semodule command",
            mac_unit,
            package_name
        );
    }

    Ok(())
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
        write_firewall_reload_dropin(&dir, packages)?;
    }
    Ok(())
}

fn generated_credential_blobs(
    package_name: &str,
    artifact_store_path: &Path,
    expose: &ExposeMeta,
) -> Result<Vec<CredentialBlob>> {
    let artifact_credstore = artifact_store_path.join("credstore.encrypted");
    let mut expected = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    for credential in &expose.config.credentials {
        let Some(relative) = generated_credential_relative_path(package_name, credential)? else {
            continue;
        };
        let units = credential_blob_units(credential, expose);
        if expected.insert(relative.clone(), units).is_some() {
            bail!(
                "expose metadata declares generated credential blob '{}' more than once",
                relative.display()
            );
        }
    }

    let actual = actual_generated_credential_paths(&artifact_credstore)?;
    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    for path in actual.difference(&expected_paths) {
        bail!(
            "expose artifact contains undeclared generated credential blob '{}'",
            path.display()
        );
    }

    let mut blobs = Vec::new();
    for (relative_path, units) in expected {
        let store_path = artifact_credstore.join(&relative_path);
        let metadata = std::fs::symlink_metadata(&store_path).with_context(|| {
            format!(
                "generated credential blob '{}' is missing from expose artifact",
                relative_path.display()
            )
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!(
                "generated credential blob {} is not a regular file",
                store_path.display()
            );
        }
        blobs.push(CredentialBlob {
            relative_path,
            store_path,
            units,
        });
    }
    blobs.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(blobs)
}

fn generated_credential_relative_path(
    package_name: &str,
    credential: &CredentialMeta,
) -> Result<Option<PathBuf>> {
    let Some(source) = credential.source.as_deref() else {
        return Ok(None);
    };
    let Some(relative) = source.strip_prefix(GENERATED_CREDSTORE_SOURCE_PREFIX) else {
        return Ok(None);
    };
    let relative = PathBuf::from(relative);
    let mut components = relative.components();
    if components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        != Some("aos")
    {
        return Ok(None);
    }
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("generated credential source path must not contain '..': {source}");
    }
    let expected = PathBuf::from("aos")
        .join(package_name)
        .join(&credential.name);
    if relative != expected {
        bail!(
            "generated credential source path must match owning package namespace '{}': {}",
            expected.display(),
            source
        );
    }
    Ok(Some(relative))
}

fn credential_blob_units(credential: &CredentialMeta, expose: &ExposeMeta) -> BTreeSet<String> {
    if credential.units.is_empty() {
        return expose
            .units
            .iter()
            .filter(|unit| unit.ends_with(".service"))
            .cloned()
            .collect();
    }
    credential.units.iter().cloned().collect()
}

fn actual_generated_credential_paths(root: &Path) -> Result<BTreeSet<PathBuf>> {
    if !root.exists() {
        return Ok(BTreeSet::new());
    }
    let mut paths = BTreeSet::new();
    collect_actual_generated_credential_paths(root, root, &mut paths)?;
    Ok(paths)
}

fn collect_actual_generated_credential_paths(
    root: &Path,
    dir: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", path.display()))?;
        if file_type.is_dir() {
            collect_actual_generated_credential_paths(root, &path, paths)?;
            continue;
        }
        if !file_type.is_file() {
            bail!(
                "generated credential blob {} is not a regular file",
                path.display()
            );
        }
        paths.insert(
            path.strip_prefix(root)
                .with_context(|| format!("computing credential blob path for {}", path.display()))?
                .to_path_buf(),
        );
    }
    Ok(())
}

fn write_generated_credential_blobs(
    root: &Path,
    packages: &[ExposedPackage],
) -> Result<BTreeSet<String>> {
    let managed_root = root.join(GENERATED_CREDSTORE_REL);
    let mut changed_units = BTreeSet::new();
    for package in packages {
        for blob in &package.credential_blobs {
            let link = root
                .join("run/credstore.encrypted")
                .join(&blob.relative_path);
            if credential_blob_link_changed(&link, &blob.store_path) {
                changed_units.extend(blob.units.iter().cloned());
            }
        }
    }
    reset_dir(&managed_root)?;
    for package in packages {
        for blob in &package.credential_blobs {
            let link = root
                .join("run/credstore.encrypted")
                .join(&blob.relative_path);
            if !link.starts_with(&managed_root) {
                bail!(
                    "generated credential blob path escapes managed credstore namespace: {}",
                    link.display()
                );
            }
            atomic_symlink(&blob.store_path, &link).with_context(|| {
                format!(
                    "linking generated credential blob {} -> {}",
                    link.display(),
                    blob.store_path.display()
                )
            })?;
        }
    }
    Ok(changed_units)
}

fn credential_blob_link_changed(link: &Path, target: &Path) -> bool {
    match std::fs::read_link(link) {
        Ok(existing) => existing != target,
        Err(_) => link.symlink_metadata().is_ok(),
    }
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

fn write_firewall_reload_dropin(dir: &Path, packages: &[ExposedPackage]) -> Result<()> {
    let content = firewall_reload_dropin(packages);
    if content.is_empty() {
        return Ok(());
    }

    let dropin_dir = dir.join("nftables.service.d");
    std::fs::create_dir_all(&dropin_dir)
        .with_context(|| format!("creating {}", dropin_dir.display()))?;
    std::fs::write(
        dropin_dir.join("50-aos-package-firewall-reload.conf"),
        content,
    )
    .context("writing nftables package firewall reload drop-in")?;
    Ok(())
}

fn firewall_reload_dropin(packages: &[ExposedPackage]) -> String {
    let units = firewall_reload_units(packages);
    if units.is_empty() {
        return String::new();
    }

    format!(
        "[Unit]\nX-RestartIfChanged=false\nPropagatesReloadTo={}\n",
        units.join(" ")
    )
}

fn firewall_reload_units(packages: &[ExposedPackage]) -> Vec<String> {
    let mut units = packages
        .iter()
        .flat_map(|package| {
            package
                .units
                .iter()
                .filter(move |unit| is_package_firewall_reload_unit(&package.name, unit))
                .cloned()
        })
        .collect::<Vec<_>>();
    units.sort();
    units.dedup();
    units
}

fn is_package_firewall_reload_unit(package_name: &str, unit: &str) -> bool {
    unit == format!("aos-pkg-{package_name}-firewall.service")
        || unit == format!("aos-pkg-{package_name}-netns.service")
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
    changed_credential_units: &BTreeSet<String>,
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
        let restarted_units = attached_diff
            .to_restart
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let credential_restart_units = changed_credential_units
            .difference(&restarted_units)
            .cloned()
            .collect::<BTreeSet<_>>();
        try_restart_changed_credential_units(root, &credential_restart_units)?;
    } else {
        preset_targets(root, current_targets)?;
    }
    Ok(())
}

async fn stop_changed_service_root_targets_before_swap(
    root: &Path,
    attached_diff: &UnitDiff,
) -> Result<()> {
    if root != Path::new("/") {
        return Ok(());
    }

    let targets = service_root_targets_requiring_preswap_stop(attached_diff);
    if targets.is_empty() {
        return Ok(());
    }

    let client = SystemdClient::connect().await?;
    for target in targets {
        match client.stop_unit(&target).await {
            Ok(outcome) => ensure_job_done("stop", &target, outcome)?,
            Err(err) if err.is_no_such_unit() => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("stopping exposed package target {target} before attached-unit swap")
                });
            }
        }
    }
    Ok(())
}

fn service_root_targets_requiring_preswap_stop(attached_diff: &UnitDiff) -> BTreeSet<String> {
    attached_diff
        .to_restart
        .iter()
        .chain(&attached_diff.to_stop)
        .filter_map(|unit| unit_diff::service_root_target(unit))
        .collect()
}

fn try_restart_changed_credential_units(root: &Path, units: &BTreeSet<String>) -> Result<()> {
    if units.is_empty() || root != Path::new("/") {
        return Ok(());
    }
    let mut command = systemctl(root);
    command.arg("try-restart");
    command.args(units);
    run_systemctl(command, "try-restart changed package credential consumers")
}

async fn apply_attached_unit_diff(client: &SystemdClient, diff: &UnitDiff) -> Result<()> {
    for unit in &diff.to_stop {
        match client.stop_unit(unit).await {
            Ok(outcome) => ensure_job_done("stop", unit, outcome)?,
            Err(err) if err.is_no_such_unit() => {}
            Err(err) => return Err(err).with_context(|| format!("stopping removed unit {unit}")),
        }
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
        // Reconcile the mounted view before its persistent lower directory.
        // That lets OverlayFS create whiteouts for removed units while the
        // corresponding lower entries still exist.
        root.join("etc").join(ATTACHED_REL),
        root.join("var/etc").join(ATTACHED_REL),
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
    write_firewall_reload_dropin(destination, packages)?;
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
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            remove_file_if_present(path)?;
            std::fs::create_dir_all(path)
                .with_context(|| format!("creating {}", path.display()))?;
        }
        Ok(_) => {
            for entry in
                std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))?
            {
                let entry = entry?;
                let entry_path = entry.path();
                let file_type = entry
                    .file_type()
                    .with_context(|| format!("reading file type for {}", entry_path.display()))?;
                if file_type.is_dir() {
                    remove_dir_if_present(&entry_path)?;
                } else {
                    remove_file_if_present(&entry_path)?;
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .with_context(|| format!("creating {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading metadata for {}", path.display()));
        }
    }
    Ok(())
}

/// Removes a file or symlink, treating an already-absent overlay entry as success.
fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Removes a directory tree, treating an already-absent overlay entry as success.
fn remove_dir_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
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
    use std::ffi::{OsStr, OsString};
    use tempfile::TempDir;

    use crate::types::{
        ApmMeta, CapabilityKind, CredentialMeta, ExposeArtifactMeta, ExposeMeta,
        HostPathPermission, InstalledMeta, ProvidedCapabilityMeta, RequiredCapabilityMeta,
        SysrootImageEntry,
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

    #[test]
    fn systemd_slice_cgroup_paths_follow_hyphen_hierarchy() {
        assert_eq!(
            systemd_slice_cgroup_path("aos-pkg-web-worker.slice"),
            "aos.slice/aos-pkg.slice/aos-pkg-web.slice/aos-pkg-web-worker.slice"
        );
        assert_eq!(
            systemd_slice_cgroup_path("aos-pkg-expose.smoke.regex.slice"),
            "aos.slice/aos-pkg.slice/aos-pkg-expose.smoke.regex.slice"
        );
    }

    #[test]
    fn selinux_identifiers_escape_label_punctuation_without_collisions() {
        let labels = ["a.b", "a-b", "a_b", "a+b", "a=b"];
        let identifiers = labels
            .iter()
            .map(|label| selinux_identifier_for_label(label))
            .collect::<BTreeSet<_>>();

        assert_eq!(identifiers.len(), labels.len());
        assert_eq!(
            selinux_identifier_for_label("aos-pkg-web"),
            "aos_x2dpkg_x2dweb"
        );
        assert_eq!(selinux_identifier_for_label("1web"), "aos_pkg_1web");
    }

    fn installed_with_expose(
        tmp: &TempDir,
        name: &str,
        package_hash: &str,
        artifact_hash: &str,
    ) -> InstalledMeta {
        let artifact = tmp.path().join(format!("{artifact_hash}-expose-{name}"));
        let runtime_store_path = format!("/var/lib/store/{package_hash}-{name}-1.0");
        let service_root_unit = format!("aos-pkg-{name}-service-roots.service");
        std::fs::create_dir_all(artifact.join("units")).unwrap();
        std::fs::write(
            artifact
                .join("units")
                .join(format!("aos-pkg-{name}.target")),
            format!(
                "[Unit]\nWants=aos-pkg-{name}.slice {name}.service aos-pkg-{name}-mac.service aos-pkg-{name}-ebpf.service {service_root_unit}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            artifact.join("units").join(format!("aos-pkg-{name}.slice")),
            "[Slice]\n",
        )
        .unwrap();
        let ebpf = trusted_ebpf_net_policy_for_test();
        let ebpf_object = trusted_ebpf_net_policy_object_for_test();
        let ebpf_cgroup = expected_ebpf_cgroup_path(name);
        let ebpf_exec_start = format!(
            "{ebpf} run --policy {}/network-policy.json --cgroup {ebpf_cgroup} --object {ebpf_object}",
            artifact.display()
        );
        let semodule = trusted_semodule_for_test();
        let mac_module = selinux_identifier_for_label(&format!("aos-pkg-{name}"));
        let mac_exec_start = format!(
            "{semodule} -i {}/mac/selinux/{mac_module}.pp",
            artifact.display()
        );
        std::fs::write(
            artifact.join("units").join(format!("{name}.service")),
            workload_service_text(
                name,
                &format!("{name}.service"),
                &format!("[Service]\nSlice=aos-pkg-{name}.slice\n"),
            ),
        )
        .unwrap();
        std::fs::write(
            artifact
                .join("units")
                .join(format!("aos-pkg-{name}-mac.service")),
            mac_policy_service_text(name, &mac_exec_start),
        )
        .unwrap();
        std::fs::write(
            artifact
                .join("units")
                .join(format!("aos-pkg-{name}-ebpf.service")),
            ebpf_policy_service_text(name, &ebpf_exec_start),
        )
        .unwrap();
        std::fs::write(
            artifact.join("units").join(&service_root_unit),
            service_root_unit_text(name, &runtime_store_path, &[format!("{name}.service")]),
        )
        .unwrap();

        let installed = InstalledMeta {
            store_path: runtime_store_path,
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
                    units: vec![
                        format!("{name}.service"),
                        format!("aos-pkg-{name}.slice"),
                        format!("aos-pkg-{name}-mac.service"),
                        format!("aos-pkg-{name}-ebpf.service"),
                        service_root_unit,
                    ],
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
                config_module: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        };
        write_network_policy_file(&installed, &[], &[]);
        write_mac_profile_file(&installed);
        installed
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
        grant_tcp_bind(&mut provider, 18080);

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

    fn link_expose_artifact(profile: &Profile, installed: &InstalledMeta) {
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

    fn exposed_packages_for_installed(
        tmp: &TempDir,
        profile_name: &str,
        installed: &[InstalledMeta],
    ) -> Vec<ExposedPackage> {
        let profile = Profile {
            path: tmp.path().join(profile_name),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        for entry in installed {
            link_expose_artifact(&profile, entry);
        }
        exposed_packages(&profile, installed).unwrap()
    }

    #[test]
    fn exposed_packages_rejects_target_bound_to_other_package() {
        let tmp = TempDir::new().unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkgwebhash11", "artifactweb11");
        installed
            .apm
            .as_mut()
            .unwrap()
            .expose
            .as_mut()
            .unwrap()
            .target = "aos-pkg-other.target".into();
        let profile = Profile {
            path: tmp.path().join("profile-target-binding"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            format!("{err:#}").contains("expected 'aos-pkg-web.target'"),
            "{err:#}"
        );
    }

    #[test]
    fn exposed_packages_rejects_missing_service_root_preparation() {
        let tmp = TempDir::new().unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkgwebhash11", "artifactweb11");
        let apm = installed.apm.as_mut().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let root_unit = "aos-pkg-web-service-roots.service";
        apm.expose
            .as_mut()
            .unwrap()
            .units
            .retain(|unit| unit != root_unit);
        std::fs::remove_file(Path::new(&artifact).join("units").join(root_unit)).unwrap();
        let profile = Profile {
            path: tmp.path().join("profile-missing-service-root"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            format!("{err:#}").contains("reading service-root preparation unit"),
            "{err:#}"
        );
    }

    #[test]
    fn exposed_packages_accepts_confined_socket_only_package_without_service_roots() {
        let tmp = TempDir::new().unwrap();
        let mut installed =
            installed_with_expose(&tmp, "listener", "pkglistener1", "artifactlistener1");
        let apm = installed.apm.as_mut().unwrap();
        let artifact = PathBuf::from(&apm.expose_artifact.as_ref().unwrap().store_path);
        let expose = apm.expose.as_mut().unwrap();
        let root_unit = "aos-pkg-listener-service-roots.service";

        expose
            .units
            .retain(|unit| unit != "listener.service" && unit != root_unit);
        expose.units.push("listener.socket".into());
        std::fs::remove_file(artifact.join("units/listener.service")).unwrap();
        std::fs::remove_file(artifact.join("units").join(root_unit)).unwrap();
        std::fs::write(
            artifact.join("units/listener.socket"),
            "[Unit]\nPartOf=aos-pkg-listener.target\n[Socket]\nListenStream=127.0.0.1:18080\n",
        )
        .unwrap();
        std::fs::write(
            artifact.join("units/aos-pkg-listener.target"),
            "[Unit]\nWants=aos-pkg-listener.slice listener.socket aos-pkg-listener-mac.service aos-pkg-listener-ebpf.service\n",
        )
        .unwrap();
        grant_tcp_bind(&mut installed, 18080);
        write_network_policy_file(&installed, &[18080], &[]);

        let profile = Profile {
            path: tmp.path().join("profile-socket-only"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_rejects_malformed_service_root_preparation() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkgwebhash11", "artifactweb11");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let root_unit = Path::new(&artifact).join("units/aos-pkg-web-service-roots.service");
        let text = std::fs::read_to_string(&root_unit)
            .unwrap()
            .replace(" prepare web ", " prepare other ");
        std::fs::write(root_unit, text).unwrap();
        let profile = Profile {
            path: tmp.path().join("profile-malformed-service-root"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            format!("{err:#}").contains("invalid trusted-helper prepare command"),
            "{err:#}"
        );
    }

    #[test]
    fn exposed_packages_rejects_incomplete_service_root_capabilities() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkgwebhash11", "artifactweb11");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let root_unit = Path::new(&artifact).join("units/aos-pkg-web-service-roots.service");
        let text = std::fs::read_to_string(&root_unit).unwrap().replace(
            "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN",
            "CapabilityBoundingSet=CAP_SYS_ADMIN",
        );
        std::fs::write(root_unit, text).unwrap();
        let profile = Profile {
            path: tmp
                .path()
                .join("profile-incomplete-service-root-capabilities"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            format!("{err:#}").contains("CapabilityBoundingSet"),
            "{err:#}"
        );
    }

    fn write_exposed_unit_surface(root: &Path, packages: &[ExposedPackage]) {
        write_attached_units(root, packages).unwrap();
        let targets = packages
            .iter()
            .map(|package| package.target.clone())
            .collect::<BTreeSet<_>>();
        write_exact_preset(root, &targets).unwrap();
    }

    fn add_generated_credential_blob(installed: &mut InstalledMeta, relative: &str, content: &str) {
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let path = Path::new(&artifact)
            .join("credstore.encrypted")
            .join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();

        declare_generated_credential_blob(installed, relative);
    }

    fn declare_generated_credential_blob(installed: &mut InstalledMeta, relative: &str) {
        let apm = installed.apm.as_mut().unwrap();
        let package = apm.name.clone();
        let expose = apm.expose.as_mut().unwrap();
        let credential_name = Path::new(relative)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap()
            .to_string();
        expose.config.credentials.push(CredentialMeta {
            name: credential_name,
            source: Some(format!("/run/credstore.encrypted/{relative}")),
            ciphertext: None,
            units: vec![format!("{package}.service")],
            encrypted: true,
            optional: false,
        });
    }

    fn write_generated_credential_blob_file(
        installed: &InstalledMeta,
        relative: &str,
        content: &str,
    ) {
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let path = Path::new(&artifact)
            .join("credstore.encrypted")
            .join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn write_network_policy_file(installed: &InstalledMeta, tcp_bind: &[u16], tcp_connect: &[u16]) {
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let permissions = normalized_permissions(&apm.name, &apm.permissions);
        let manifest_fs = expected_manifest_fs(&permissions);
        let mut units = apm
            .expose
            .as_ref()
            .unwrap()
            .units
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        units.insert(apm.expose.as_ref().unwrap().target.clone());
        let service_paths =
            expected_landlock_service_paths(&apm.name, &Path::new(&artifact).join("units"), &units)
                .unwrap();
        let landlock_fs = expected_landlock_fs(&permissions, &service_paths);
        let label = permissions.security_label.clone().unwrap();
        let mode = permissions.network.unwrap_or(NetworkPermission::Private);
        let policy = serde_json::json!({
            "version": 1,
            "package": apm.name,
            "mode": mode,
            "securityLabel": label,
            "tcp": {
                "bind": tcp_bind,
                "connect": tcp_connect,
            },
            "fs": {
                "readOnly": manifest_fs.read_only,
                "readWrite": manifest_fs.read_write,
            },
            "landlock": {
                "abi": 4,
                "tcp": {
                    "bind": tcp_bind,
                    "connect": tcp_connect,
                },
                "fs": {
                    "readOnly": landlock_fs.read_only,
                    "readWrite": landlock_fs.read_write,
                },
            },
            "ebpf": {
                "identity": label,
                "hooks": ["socket_bind", "socket_connect"],
                "tcp": {
                    "bind": tcp_bind,
                    "connect": tcp_connect,
                },
            },
        });
        std::fs::write(
            Path::new(&artifact).join("network-policy.json"),
            serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
    }

    fn write_mac_profile_file(installed: &InstalledMeta) {
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let permissions = normalized_permissions(&apm.name, &apm.permissions);
        let label = permissions.security_label.clone().unwrap();
        let default_deny =
            permissions.confinement.as_ref().unwrap().class != ConfinementClass::Unconfined;
        let profile_path = default_deny.then(|| expected_selinux_profile_path(&label));
        let policy = serde_json::json!({
            "version": 1,
            "package": apm.name,
            "backend": "selinux",
            "securityLabel": label,
            "defaultDeny": default_deny,
            "profilePath": profile_path.clone(),
        });
        std::fs::write(
            Path::new(&artifact).join("mac-profile.json"),
            serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
        if let Some(profile_path) = profile_path {
            let module_name = selinux_identifier_for_label(&label);
            let source_text = expected_selinux_profile(&label);
            let compiled = compile_selinux_profile(&source_text, &module_name).unwrap();
            let profile_file = Path::new(&artifact).join(&profile_path);
            let source_file = Path::new(&artifact).join(format!("mac/selinux/{module_name}.te"));
            let module_file = Path::new(&artifact).join(format!("mac/selinux/{module_name}.mod"));
            std::fs::create_dir_all(profile_file.parent().unwrap()).unwrap();
            std::fs::write(profile_file, compiled.profile).unwrap();
            std::fs::write(module_file, compiled.module).unwrap();
            std::fs::write(source_file, source_text).unwrap();
        }
    }

    fn remove_network_policy_file(installed: &InstalledMeta) {
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        std::fs::remove_file(Path::new(&artifact).join("network-policy.json")).unwrap();
    }

    fn remove_ebpf_policy_service(installed: &mut InstalledMeta) {
        let apm = installed.apm.as_mut().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let unit = format!("aos-pkg-{}-ebpf.service", apm.name);
        apm.expose
            .as_mut()
            .unwrap()
            .units
            .retain(|candidate| candidate != &unit);
        let _ = std::fs::remove_file(Path::new(&artifact).join("units").join(unit));
    }

    fn remove_mac_policy_service(installed: &mut InstalledMeta) {
        let apm = installed.apm.as_mut().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let unit = format!("aos-pkg-{}-mac.service", apm.name);
        apm.expose
            .as_mut()
            .unwrap()
            .units
            .retain(|candidate| candidate != &unit);
        let _ = std::fs::remove_file(Path::new(&artifact).join("units").join(unit));
    }

    fn grant_tcp_bind(installed: &mut InstalledMeta, port: u16) {
        installed.apm.as_mut().unwrap().permissions.tcp_bind = vec![port];
        write_network_policy_file(installed, &[port], &[]);
    }

    fn write_service_unit(installed: &InstalledMeta, text: &str) {
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let text = if text.contains("Slice=") {
            text.to_string()
        } else {
            format!("{text}Slice=aos-pkg-{}.slice\n", apm.name)
        };
        let uses_overlay_root = !apm
            .expose
            .as_ref()
            .unwrap()
            .images
            .iter()
            .any(is_verity_root_image)
            && normalized_permissions(&apm.name, &apm.permissions)
                .confinement
                .is_some_and(|confinement| confinement.class != ConfinementClass::Unconfined);
        let text = if uses_overlay_root {
            workload_service_text(&apm.name, &format!("{}.service", apm.name), &text)
        } else {
            text
        };
        std::fs::write(
            Path::new(&artifact)
                .join("units")
                .join(format!("{}.service", apm.name)),
            text,
        )
        .unwrap();
    }

    fn add_verity_image(installed: &mut InstalledMeta, image_path: &Path) {
        installed
            .apm
            .as_mut()
            .unwrap()
            .expose
            .as_mut()
            .unwrap()
            .images = vec![SysrootImageEntry {
            format: "ext4-verity".to_string(),
            store_path: image_path.display().to_string(),
            nar_hash: "sha256:root".to_string(),
            nar_size: 1,
            delivery: crate::types::test_image_delivery("raw"),
            sb_signer_cert_sha256: None,
            sbat: Vec::new(),
            expected_pcr11: None,
            ukis: Vec::new(),
            recovery_ukis: Vec::new(),
            recovery_bundle: None,
            root_image: Some("root.img".to_string()),
            root_verity: Some("root.verity".to_string()),
            root_hash: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            root_hash_sig: Some("root.roothash.p7s".to_string()),
        }];
        remove_service_root_preparation(installed);
    }

    fn verity_workload_service_text(
        package_name: &str,
        image_path: &Path,
        root_hash: &str,
        private_devices: &str,
        root_directory: Option<&str>,
    ) -> String {
        let root_directory = root_directory
            .map(|path| format!("RootDirectory={path}\n"))
            .unwrap_or_default();
        let root_hash_signature = format!("{}/root.roothash.p7s", image_path.display());
        let guard = trusted_verity_root_guard_for_test();
        let precheck = format!("{guard} --signature-only {root_hash} {root_hash_signature}");
        format!(
            "[Unit]\nAfter=aos-pkg-{package_name}-mac.service aos-pkg-{package_name}-ebpf.service systemd-udevd.service\nRequires=aos-pkg-{package_name}-mac.service aos-pkg-{package_name}-ebpf.service systemd-udevd.service\n[Service]\nRootImage={}/root.img\nRootVerity={}/root.verity\nRootHash={root_hash}\nRootHashSignature={}/root.roothash.p7s\nRootImagePolicy=root=signed\nExecStartPre={precheck}\nPermissionsStartOnly=true\n{root_directory}PrivateDevices={private_devices}\nSlice=aos-pkg-{package_name}.slice\n",
            image_path.display(),
            image_path.display(),
            image_path.display(),
        )
    }

    fn without_verity_guard_precheck(unit_text: &str) -> String {
        unit_text
            .lines()
            .filter(|line| !line.starts_with("ExecStartPre="))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn workload_service_text(package_name: &str, unit_name: &str, text: &str) -> String {
        let root_unit = format!("aos-pkg-{package_name}-service-roots.service");
        let text = if text.contains("[Unit]") {
            text.replacen(
                "[Unit]\n",
                &format!("[Unit]\nAfter={root_unit}\nRequires={root_unit}\n"),
                1,
            )
        } else {
            format!(
                "[Unit]\nAfter=aos-pkg-{package_name}-mac.service aos-pkg-{package_name}-ebpf.service {root_unit}\nRequires=aos-pkg-{package_name}-mac.service aos-pkg-{package_name}-ebpf.service {root_unit}\n{text}"
            )
        };
        if text.contains("RootDirectory=") {
            text
        } else {
            text.replacen(
                "[Service]\n",
                &format!(
                    "[Service]\nRootDirectory=/run/aos/service-roots/{package_name}/{unit_name}/merged\n"
                ),
                1,
            )
        }
    }

    fn service_root_unit_text(
        package_name: &str,
        runtime_store_path: &str,
        workload_units: &[String],
    ) -> String {
        let helper = trusted_service_root_helper_path().unwrap();
        let target = format!("aos-pkg-{package_name}.target");
        let workloads = workload_units.join(" ");
        let command = format!("{package_name} {runtime_store_path} {workloads}");
        format!(
            "[Unit]\nPartOf={target}\nBefore={workloads}\n[Service]\nType=oneshot\nRemainAfterExit=true\nExecStart={helper} prepare {command}\nExecStop={helper} cleanup {command}\nExecStopPost={helper} cleanup {command}\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN\nAmbientCapabilities=CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN\nPrivateMounts=false\nNoNewPrivileges=false\nRestrictAddressFamilies=AF_UNIX\nUMask=0077\n[Install]\nWantedBy={target}\n"
        )
    }

    fn rewrite_service_root_preparation(installed: &InstalledMeta) {
        let apm = installed.apm.as_ref().unwrap();
        let expose = apm.expose.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let workloads = expose
            .units
            .iter()
            .filter(|unit| {
                unit.ends_with(".service")
                    && !is_generated_expose_side_effect_service(&apm.name, unit)
            })
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        std::fs::write(
            Path::new(&artifact)
                .join("units")
                .join(format!("aos-pkg-{}-service-roots.service", apm.name)),
            service_root_unit_text(&apm.name, &installed.store_path, &workloads),
        )
        .unwrap();
    }

    fn remove_service_root_preparation(installed: &mut InstalledMeta) {
        let apm = installed.apm.as_mut().unwrap();
        let root_unit = format!("aos-pkg-{}-service-roots.service", apm.name);
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        apm.expose
            .as_mut()
            .unwrap()
            .units
            .retain(|unit| unit != &root_unit);
        std::fs::remove_file(Path::new(&artifact).join("units").join(root_unit)).unwrap();
    }

    fn trusted_landlock_wrapper_for_test() -> String {
        trusted_landlock_wrapper_path().unwrap()
    }

    fn trusted_selinux_runner_for_test() -> String {
        trusted_selinux_runner_path().unwrap()
    }

    fn trusted_verity_root_guard_for_test() -> String {
        trusted_verity_root_guard_path().unwrap()
    }

    fn selinux_prefix_for_test(package_name: &str) -> String {
        let runner = trusted_selinux_runner_for_test();
        let context = expected_selinux_context(&format!("aos-pkg-{package_name}"));
        format!("{runner} --context {context} --")
    }

    fn sandbox_exec_for_test(package_name: &str, landlock_args: &str, command: &str) -> String {
        let selinux = selinux_prefix_for_test(package_name);
        let landlock = trusted_landlock_wrapper_for_test();
        format!("{selinux} {landlock} {landlock_args} -- {command}")
    }

    fn verity_guard_exec_for_test(
        package_name: &str,
        root_hash: &str,
        root_hash_signature: &str,
        landlock_args: &str,
        command: &str,
    ) -> String {
        let guard = trusted_verity_root_guard_for_test();
        let sandboxed = sandbox_exec_for_test(package_name, landlock_args, command);
        format!("{guard} {root_hash} {root_hash_signature} -- {sandboxed}")
    }

    fn trusted_ebpf_net_policy_for_test() -> String {
        trusted_ebpf_net_policy_path().unwrap()
    }

    fn trusted_semodule_for_test() -> String {
        trusted_semodule_path().unwrap()
    }

    fn trusted_ebpf_net_policy_object_for_test() -> String {
        trusted_ebpf_net_policy_object_path().unwrap()
    }

    fn mac_policy_service_text(name: &str, exec_start: &str) -> String {
        format!(
            "[Unit]\n\
             PartOf=aos-pkg-{name}.target\n\
             ConditionSecurity=selinux\n\
             Before={name}.service\n\
             [Service]\n\
             Type=oneshot\n\
             RemainAfterExit=true\n\
             Slice=aos-pkg-{name}.slice\n\
             ExecStart={exec_start}\n\
             NoNewPrivileges=true\n\
             CapabilityBoundingSet=CAP_MAC_ADMIN\n\
             AmbientCapabilities=\n\
             PrivateDevices=true\n\
             DevicePolicy=closed\n\
             PrivateNetwork=true\n\
             PrivateTmp=true\n\
             ProtectSystem=full\n\
             ReadWritePaths=/etc/selinux /var/lib/selinux\n\
             ProtectHome=true\n\
             ProtectClock=true\n\
             ProtectHostname=true\n\
             ProtectKernelLogs=true\n\
             ProtectKernelModules=true\n\
             ProtectProc=invisible\n\
             ProcSubset=pid\n\
             SystemCallArchitectures=native\n\
             RestrictAddressFamilies=AF_UNIX\n\
             RestrictNamespaces=true\n\
             RestrictRealtime=true\n\
             RestrictSUIDSGID=true\n\
             LockPersonality=true\n\
             MemoryDenyWriteExecute=true\n\
             UMask=0077\n\
             [Install]\n\
             WantedBy=aos-pkg-{name}.target\n"
        )
    }

    fn ebpf_policy_service_text(name: &str, exec_start: &str) -> String {
        format!(
            "[Unit]\n\
             PartOf=aos-pkg-{name}.target\n\
             Before={name}.service\n\
             [Service]\n\
             Type=notify\n\
             NotifyAccess=main\n\
             Slice=aos-pkg-{name}.slice\n\
             ExecStart={exec_start}\n\
             NoNewPrivileges=true\n\
             CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE\n\
             AmbientCapabilities=\n\
             LimitMEMLOCK=infinity\n\
             PrivateDevices=true\n\
             DevicePolicy=closed\n\
             PrivateNetwork=true\n\
             PrivateTmp=true\n\
             ProtectSystem=strict\n\
             ProtectHome=true\n\
             ProtectClock=true\n\
             ProtectHostname=true\n\
             ProtectKernelLogs=true\n\
             ProtectKernelModules=true\n\
             ProtectProc=invisible\n\
             ProcSubset=pid\n\
             SystemCallArchitectures=native\n\
             RestrictAddressFamilies=AF_UNIX\n\
             RestrictNamespaces=true\n\
             RestrictRealtime=true\n\
             RestrictSUIDSGID=true\n\
             LockPersonality=true\n\
             MemoryDenyWriteExecute=true\n\
             UMask=0077\n\
             [Install]\n\
             WantedBy=aos-pkg-{name}.target\n"
        )
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
                delivery: crate::types::test_image_delivery("raw"),
                sb_signer_cert_sha256: None,
                sbat: Vec::new(),
                expected_pcr11: None,
                ukis: Vec::new(),
                recovery_ukis: Vec::new(),
                recovery_bundle: None,
                root_image: None,
                root_verity: None,
                root_hash: None,
                root_hash_sig: None,
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
    fn exposed_packages_accepts_matching_verity_root_image_unit() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        write_service_unit(
            &installed,
            &verity_workload_service_text(
                "web",
                &image_path,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "false",
                None,
            ),
        );
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_accepts_verity_root_guard_wrapper() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        write_network_policy_file(&installed, &[], &[]);
        let root_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root_hash_signature = format!("{}/root.roothash.p7s", image_path.display());
        let exec_start = verity_guard_exec_for_test(
            "web",
            root_hash,
            &root_hash_signature,
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        let unit_text = format!(
            "{}ExecStart={exec_start}\n",
            verity_workload_service_text("web", &image_path, root_hash, "false", None),
        );
        write_service_unit(&installed, &unit_text);
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_rejects_verity_root_guard_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        write_network_policy_file(&installed, &[], &[]);
        let root_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root_hash_signature = format!("{}/root.roothash.p7s", image_path.display());
        let exec_start = verity_guard_exec_for_test(
            "web",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &root_hash_signature,
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        let unit_text = format!(
            "{}ExecStart={exec_start}\n",
            verity_workload_service_text("web", &image_path, root_hash, "false", None),
        );
        write_service_unit(&installed, &unit_text);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid aos-verity-root-guard arguments"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_verity_root_image_missing_guard_precheck() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        write_network_policy_file(&installed, &[], &[]);
        let root_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root_hash_signature = format!("{}/root.roothash.p7s", image_path.display());
        let exec_start = verity_guard_exec_for_test(
            "web",
            root_hash,
            &root_hash_signature,
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        let unit_text = format!(
            "{}ExecStart={exec_start}\n",
            without_verity_guard_precheck(&verity_workload_service_text(
                "web",
                &image_path,
                root_hash,
                "false",
                None,
            )),
        );
        write_service_unit(&installed, &unit_text);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("must run aos-verity-root-guard in ExecStartPre"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_undeclared_root_image_unit() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        write_service_unit(
            &installed,
            &verity_workload_service_text(
                "web",
                &image_path,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "false",
                None,
            ),
        );
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(format!("{err:#}").contains("without signed expose.images metadata"));
    }

    #[test]
    fn exposed_packages_rejects_mismatched_verity_root_hash() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        write_service_unit(
            &installed,
            &verity_workload_service_text(
                "web",
                &image_path,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "false",
                None,
            ),
        );
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(format!("{err:#}").contains("invalid RootHash value"));
    }

    #[test]
    fn exposed_packages_rejects_unsigned_verity_root_image_policy() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        let unit_text = verity_workload_service_text(
            "web",
            &image_path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "false",
            None,
        )
        .replace(
            "RootImagePolicy=root=signed",
            "RootImagePolicy=root=verity+signed",
        );
        write_service_unit(&installed, &unit_text);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(format!("{err:#}").contains("invalid RootImagePolicy value"));
    }

    #[test]
    fn exposed_packages_rejects_verity_root_image_with_private_devices() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        write_service_unit(
            &installed,
            &verity_workload_service_text(
                "web",
                &image_path,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "true",
                None,
            ),
        );
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(format!("{err:#}").contains("invalid PrivateDevices value"));
    }

    #[test]
    fn exposed_packages_rejects_verity_root_image_without_udev_requires() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let image_path = tmp.path().join("imagehash111-rootfs");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_verity_image(&mut installed, &image_path);
        let unit_text = verity_workload_service_text(
            "web",
            &image_path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "false",
            None,
        )
        .replace(" systemd-udevd.service\n[Service]", "\n[Service]");
        write_service_unit(&installed, &unit_text);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(format!("{err:#}").contains("must include systemd-udevd.service in Unit.Requires"));
    }

    #[test]
    fn exposed_packages_rejects_missing_required_network_policy_artifact() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        remove_network_policy_file(&installed);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(
            err.to_string().contains("missing required network-policy"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_missing_default_landlock_policy_artifact() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        remove_network_policy_file(&installed);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(
            err.to_string().contains("missing required network-policy"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_accepts_legacy_missing_mac_profile_artifact() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::remove_file(Path::new(&artifact).join("mac-profile.json")).unwrap();
        remove_mac_policy_service(&mut installed);
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();
        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_rejects_mac_profile_label_mismatch() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let mac_path = Path::new(&artifact).join("mac-profile.json");
        let mut mac: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mac_path).unwrap()).unwrap();
        mac["securityLabel"] = serde_json::json!("aos-pkg-other");
        std::fs::write(&mac_path, serde_json::to_string(&mac).unwrap()).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(
            err.to_string().contains("security label mismatch"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_missing_mac_profile_file() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::remove_file(Path::new(&artifact).join("mac/selinux/aos_x2dpkg_x2dweb.pp"))
            .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing required mac/selinux/aos_x2dpkg_x2dweb.pp"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_mac_profile_payload_mismatch() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        std::fs::write(
            Path::new(&artifact).join("mac/selinux/aos_x2dpkg_x2dweb.pp"),
            b"permissive compiled policy",
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match the validated SELinux source"),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exposed_packages_rejects_mac_profile_parent_symlink() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let artifact = installed
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let external_mac = tmp.path().join("external-mac");
        let external_profile = external_mac.join("selinux/aos_x2dpkg_x2dweb.te");
        std::fs::create_dir_all(external_profile.parent().unwrap()).unwrap();
        std::fs::write(&external_profile, expected_selinux_profile("aos-pkg-web")).unwrap();
        std::fs::remove_dir_all(Path::new(&artifact).join("mac")).unwrap();
        std::os::unix::fs::symlink(&external_mac, Path::new(&artifact).join("mac")).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a non-symlink directory"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_network_policy_grants_outside_metadata() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443, 8443]);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(err.to_string().contains("TCP grants differ"), "{err:?}");
    }

    #[test]
    fn exposed_packages_accepts_legacy_tcp_policy_without_fs_fields() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443]);

        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let policy_path = Path::new(&artifact).join("network-policy.json");
        let mut policy: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&policy_path).unwrap()).unwrap();
        policy.as_object_mut().unwrap().remove("fs");
        policy["landlock"].as_object_mut().unwrap().remove("fs");
        std::fs::write(&policy_path, serde_json::to_string(&policy).unwrap()).unwrap();

        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web --tcp-connect 443",
            "/bin/true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_rejects_network_policy_host_paths_outside_metadata() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.host_paths = vec![HostPathPermission {
            path: "/srv/data".into(),
            mode: HostPathMode::Rw,
        }];
        write_network_policy_file(&installed, &[], &[]);

        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let policy_path = Path::new(&artifact).join("network-policy.json");
        let mut policy: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&policy_path).unwrap()).unwrap();
        policy["landlock"]["fs"]["readWrite"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("/srv/other"));
        std::fs::write(&policy_path, serde_json::to_string(&policy).unwrap()).unwrap();

        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();
        assert!(
            err.to_string().contains("filesystem grants differ"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_missing_landlock_wrapper_for_network_policy() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443]);
        let selinux = selinux_prefix_for_test("web");
        write_service_unit(
            &installed,
            &format!("[Service]\nExecStart={selinux} /bin/true\n"),
        );
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("missing required aos-landlock wrapper"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_unwrapped_selinux_exec_start_pre() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443]);
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web --tcp-connect 443",
            "/bin/true",
        );
        write_service_unit(
            &installed,
            &format!("[Service]\nExecStartPre=/bin/true\nExecStart={exec_start}\n"),
        );
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string().contains("ExecStartPre")
                && err
                    .to_string()
                    .contains("missing required aos-selinux-run wrapper"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_landlock_wrapper_with_wrong_ports() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443]);
        let exec_start =
            sandbox_exec_for_test("web", "--require-abi 4 --tcp-connect 8443", "/bin/true");
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string().contains("invalid aos-landlock arguments"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_landlock_wrapper_with_missing_host_path() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.host_paths = vec![HostPathPermission {
            path: "/srv/data".into(),
            mode: HostPathMode::Rw,
        }];
        write_network_policy_file(&installed, &[], &[]);
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string().contains("invalid aos-landlock arguments"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_untrusted_landlock_wrapper_path() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443]);
        let selinux = selinux_prefix_for_test("web");
        write_service_unit(
            &installed,
            &format!(
                "[Service]\nExecStart={selinux} /nix/store/fake-aos-landlock-0/bin/aos-landlock --require-abi 4 --tcp-connect 443 -- /bin/true\n"
            ),
        );
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("missing required aos-landlock wrapper"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_landlock_wrapped_shell_prefix_command() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        write_network_policy_file(&installed, &[], &[]);
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "|/bin/true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("cannot be preserved exactly by aos-landlock"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_landlock_wrapped_slashless_command() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        write_network_policy_file(&installed, &[], &[]);
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("cannot be preserved exactly by aos-landlock"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_accepts_landlock_wrapper_for_network_policy() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.tcp_connect = vec![443];
        write_network_policy_file(&installed, &[], &[443]);
        let exec_start_pre = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web --tcp-connect 443",
            "/bin/true",
        );
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web --tcp-connect 443",
            "/bin/true",
        );
        write_service_unit(
            &installed,
            &format!("[Service]\nExecStartPre={exec_start_pre}\nExecStart={exec_start}\n"),
        );
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_accepts_default_landlock_wrapper() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        write_network_policy_file(&installed, &[], &[]);
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_rejects_missing_mac_policy_service() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        remove_mac_policy_service(&mut installed);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("missing required service aos-pkg-web-mac.service"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_untrusted_mac_policy_helper() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let exec_start = format!(
            "/nix/store/fake-policycoreutils-0/sbin/semodule -i {artifact}/mac/selinux/aos_x2dpkg_x2dweb.pp"
        );
        std::fs::write(
            Path::new(&artifact).join("units/aos-pkg-web-mac.service"),
            mac_policy_service_text("web", &exec_start),
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string().contains("invalid semodule command"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_mac_policy_extra_exec_hook() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let path = Path::new(&artifact).join("units/aos-pkg-web-mac.service");
        let mut unit = std::fs::read_to_string(&path).unwrap();
        unit = unit.replace(
            "ExecStart=",
            "ExecStartPre=/nix/store/fake-coreutils-0/bin/true\nExecStart=",
        );
        std::fs::write(&path, unit).unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string().contains("must not declare ExecStartPre"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_workload_missing_mac_after() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        std::fs::write(
            Path::new(&artifact).join("units/web.service"),
            "[Unit]\nAfter=aos-pkg-web-ebpf.service aos-pkg-web-service-roots.service\nRequires=aos-pkg-web-mac.service aos-pkg-web-ebpf.service aos-pkg-web-service-roots.service\n[Service]\nRootDirectory=/run/aos/service-roots/web/web.service/merged\nSlice=aos-pkg-web.slice\n",
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(err.to_string().contains("Unit.After"), "{err:?}");
    }

    #[test]
    fn exposed_packages_rejects_missing_ebpf_policy_service() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        remove_ebpf_policy_service(&mut installed);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("missing required service aos-pkg-web-ebpf.service"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_untrusted_ebpf_policy_helper() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let ebpf_object = trusted_ebpf_net_policy_object_for_test();
        let ebpf_cgroup = expected_ebpf_cgroup_path("web");
        let exec_start = format!(
            "/nix/store/fake-aos-ebpf-net-policy-0/bin/aos-ebpf-net-policy run --policy {artifact}/network-policy.json --cgroup {ebpf_cgroup} --object {ebpf_object}"
        );
        std::fs::write(
            Path::new(&artifact).join("units/aos-pkg-web-ebpf.service"),
            ebpf_policy_service_text("web", &exec_start),
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid aos-ebpf-net-policy command"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_ebpf_policy_wrong_cgroup() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let ebpf = trusted_ebpf_net_policy_for_test();
        let ebpf_object = trusted_ebpf_net_policy_object_for_test();
        let wrong_cgroup = expected_ebpf_cgroup_path("other");
        let exec_start = format!(
            "{ebpf} run --policy {artifact}/network-policy.json --cgroup {wrong_cgroup} --object {ebpf_object}"
        );
        std::fs::write(
            Path::new(&artifact).join("units/aos-pkg-web-ebpf.service"),
            ebpf_policy_service_text("web", &exec_start),
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid aos-ebpf-net-policy command"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_ebpf_policy_missing_target_wants() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        std::fs::write(
            Path::new(&artifact).join("units/aos-pkg-web.target"),
            "[Unit]\nWants=aos-pkg-web.slice web.service\n",
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("must include aos-pkg-web-ebpf.service in Unit.Wants"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_workload_missing_ebpf_after() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        std::fs::write(
            Path::new(&artifact).join("units/web.service"),
            "[Unit]\nAfter=aos-pkg-web-service-roots.service\nRequires=aos-pkg-web-ebpf.service aos-pkg-web-service-roots.service\n[Service]\nRootDirectory=/run/aos/service-roots/web/web.service/merged\nSlice=aos-pkg-web.slice\n",
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(err.to_string().contains("Unit.After"), "{err:?}");
    }

    #[test]
    fn exposed_packages_rejects_workload_missing_ebpf_requires() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        std::fs::write(
            Path::new(&artifact).join("units/web.service"),
            "[Unit]\nAfter=aos-pkg-web-ebpf.service aos-pkg-web-service-roots.service\nRequires=aos-pkg-web-service-roots.service\n[Service]\nRootDirectory=/run/aos/service-roots/web/web.service/merged\nSlice=aos-pkg-web.slice\n",
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(err.to_string().contains("Unit.Requires"), "{err:?}");
    }

    #[test]
    fn exposed_packages_rejects_workload_outside_package_slice() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_ref().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        std::fs::write(
            Path::new(&artifact).join("units/web.service"),
            workload_service_text(
                "web",
                "web.service",
                &format!("[Service]\nExecStart={exec_start}\n"),
            ),
        )
        .unwrap();
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(err.to_string().contains("missing Slice"), "{err:?}");
    }

    #[test]
    fn exposed_packages_accepts_package_state_paths_for_all_landlock_wrappers() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_mut().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        apm.expose
            .as_mut()
            .unwrap()
            .units
            .push("web-worker.service".into());
        std::fs::write(
            Path::new(&artifact).join("units/web-worker.service"),
            workload_service_text(
                "web",
                "web-worker.service",
                "[Service]\nStateDirectory=aos-pkg-web-worker\nSlice=aos-pkg-web.slice\n",
            ),
        )
        .unwrap();
        write_network_policy_file(&installed, &[], &[]);

        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web-worker --fs-rw /var/lib/aos-pkg-web",
            "/bin/true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        std::fs::write(
            Path::new(&artifact).join("units/web-worker.service"),
            workload_service_text(
                "web",
                "web-worker.service",
                &format!(
                    "[Service]\nStateDirectory=aos-pkg-web-worker\nSlice=aos-pkg-web.slice\nExecStart={exec_start}\n"
                ),
            ),
        )
        .unwrap();
        rewrite_service_root_preparation(&installed);
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_rejects_tcp_socket_without_bind_permission() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_mut().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        apm.expose.as_mut().unwrap().units.push("web.socket".into());
        std::fs::write(
            Path::new(&artifact).join("units/web.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\n",
        )
        .unwrap();
        write_network_policy_file(&installed, &[], &[]);
        link_expose_artifact(&profile, &installed);

        let err = exposed_packages(&profile, &[installed]).unwrap_err();

        assert!(
            err.to_string()
                .contains("without a matching permissions.tcp-bind grant"),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_accepts_reset_tcp_socket_without_bind_permission() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_mut().unwrap();
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        apm.expose.as_mut().unwrap().units.push("web.socket".into());
        std::fs::write(
            Path::new(&artifact).join("units/web.socket"),
            "[Socket]\nListenStream=127.0.0.1:18080\nListenStream=\n",
        )
        .unwrap();
        write_network_policy_file(&installed, &[], &[]);
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_accepts_tcp_socket_with_bind_permission() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let apm = installed.apm.as_mut().unwrap();
        apm.permissions.tcp_bind = vec![18080];
        let artifact = apm.expose_artifact.as_ref().unwrap().store_path.clone();
        apm.expose.as_mut().unwrap().units.push("web.socket".into());
        std::fs::write(
            Path::new(&artifact).join("units/web.socket"),
            "[Socket]\nListenStream=[::1]:18080\n",
        )
        .unwrap();
        write_network_policy_file(&installed, &[18080], &[]);
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_accepts_landlock_wrapper_for_host_paths() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        installed.apm.as_mut().unwrap().permissions.host_paths = vec![
            HostPathPermission {
                path: "/srv/public".into(),
                mode: HostPathMode::ReadOnly,
            },
            HostPathPermission {
                path: "/srv/data".into(),
                mode: HostPathMode::Rw,
            },
        ];
        write_network_policy_file(&installed, &[], &[]);
        let exec_start = sandbox_exec_for_test(
            "web",
            "--require-abi 4 --fs-ro / --fs-ro /srv/public --fs-rw /tmp --fs-rw /var/tmp --fs-rw /dev/null --fs-rw /var/lib/aos-pkg-web --fs-rw /srv/data",
            "/bin/true",
        );
        write_service_unit(&installed, &format!("[Service]\nExecStart={exec_start}\n"));
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn exposed_packages_accepts_unconfined_host_paths_without_landlock_wrapper() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        let permissions = &mut installed.apm.as_mut().unwrap().permissions;
        permissions.privileged_users = true;
        permissions.host_paths = vec![HostPathPermission {
            path: "/srv/data".into(),
            mode: HostPathMode::ReadOnly,
        }];
        write_network_policy_file(&installed, &[], &[]);
        write_mac_profile_file(&installed);
        remove_mac_policy_service(&mut installed);
        remove_ebpf_policy_service(&mut installed);
        remove_service_root_preparation(&mut installed);
        write_service_unit(
            &installed,
            "[Unit]\n[Service]\nSlice=aos-pkg-web.slice\nExecStart=/bin/true\n",
        );
        link_expose_artifact(&profile, &installed);

        let packages = exposed_packages(&profile, &[installed]).unwrap();

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn attached_dirs_reconcile_live_overlay_before_durable_lower() {
        let root = Path::new("/test-root");
        assert_eq!(
            attached_dirs(root),
            [
                root.join("etc").join(ATTACHED_REL),
                root.join("var/etc").join(ATTACHED_REL),
            ]
        );
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
    fn exposed_unit_surface_rewrites_to_rolled_back_generation() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let v1_installed = vec![installed_with_expose(
            &tmp,
            "web",
            "pkghash111",
            "artifacthash111",
        )];
        let v2_installed = vec![
            installed_with_expose(&tmp, "web", "pkghash222", "artifacthash222"),
            installed_with_expose(&tmp, "api", "pkghash333", "artifacthash333"),
        ];
        let v1_packages = exposed_packages_for_installed(&tmp, "profile-v1", &v1_installed);
        let v2_packages = exposed_packages_for_installed(&tmp, "profile-v2", &v2_installed);

        write_exposed_unit_surface(&root, &v2_packages);

        for dir in attached_dirs(&root) {
            let web_target = std::fs::read_link(dir.join("web.service")).unwrap();
            assert!(
                web_target
                    .display()
                    .to_string()
                    .contains("artifacthash222-expose-web"),
                "web.service should point at v2 artifact, got {}",
                web_target.display()
            );
            assert!(dir.join("api.service").symlink_metadata().is_ok());
        }
        for path in preset_paths(&root) {
            let preset = std::fs::read_to_string(path).unwrap();
            assert_eq!(
                preset,
                "enable aos-pkg-api.target\nenable aos-pkg-web.target\n"
            );
        }

        write_exposed_unit_surface(&root, &v1_packages);

        for dir in attached_dirs(&root) {
            let web_target = std::fs::read_link(dir.join("web.service")).unwrap();
            assert!(
                web_target
                    .display()
                    .to_string()
                    .contains("artifacthash111-expose-web"),
                "web.service should point back at v1 artifact, got {}",
                web_target.display()
            );
            assert!(dir.join("api.service").symlink_metadata().is_err());
            assert!(dir.join("aos-pkg-api.target").symlink_metadata().is_err());
        }
        for path in preset_paths(&root) {
            let preset = std::fs::read_to_string(path).unwrap();
            assert_eq!(preset, "enable aos-pkg-web.target\n");
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
    fn write_generated_credential_blobs_links_managed_credstore_namespace() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_generated_credential_blob(&mut installed, "aos/web/join-token", "ciphertext");
        let stale = root.join("run/credstore.encrypted/aos/stale-token");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, "stale").unwrap();
        let old = tmp.path().join("old-credential");
        std::fs::write(&old, "old").unwrap();
        let link = root.join("run/credstore.encrypted/aos/web/join-token");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&old, &link).unwrap();

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);
        let packages = exposed_packages(&profile, &[installed]).unwrap();

        let changed_units = write_generated_credential_blobs(&root, &packages).unwrap();

        let target = std::fs::read_link(&link).unwrap();
        assert!(target.ends_with("credstore.encrypted/aos/web/join-token"));
        assert!(!stale.exists());
        assert!(changed_units.contains("web.service"));
    }

    #[test]
    fn write_generated_credential_blobs_replaces_symlinked_managed_root() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let mut installed = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_generated_credential_blob(&mut installed, "aos/web/join-token", "ciphertext");
        let external = tmp.path().join("external-credstore");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("sentinel"), "keep").unwrap();
        let managed_root = root.join(GENERATED_CREDSTORE_REL);
        std::fs::create_dir_all(managed_root.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&external, &managed_root).unwrap();

        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        link_expose_artifact(&profile, &installed);
        let packages = exposed_packages(&profile, &[installed]).unwrap();

        write_generated_credential_blobs(&root, &packages).unwrap();

        assert!(external.join("sentinel").exists());
        let metadata = std::fs::symlink_metadata(&managed_root).unwrap();
        assert!(metadata.file_type().is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert!(std::fs::read_link(managed_root.join("web/join-token")).is_ok());
    }

    #[test]
    fn exposed_packages_rejects_duplicate_generated_credential_blobs() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_generated_credential_blob(&mut web, "aos/web/token", "web");
        declare_generated_credential_blob(&mut web, "aos/web/token");
        link_expose_artifact(&profile, &web);

        let err = exposed_packages(&profile, &[web]).unwrap_err();

        assert!(
            err.chain()
                .any(|cause| cause.to_string().contains("more than once")),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_generated_credential_outside_package_namespace() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        add_generated_credential_blob(&mut web, "aos/other-package/join-token", "ciphertext");
        link_expose_artifact(&profile, &web);

        let err = exposed_packages(&profile, &[web]).unwrap_err();

        assert!(
            err.chain().any(|cause| cause
                .to_string()
                .contains("owning package namespace 'aos/web/join-token'")),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_missing_generated_credential_blob_files() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        declare_generated_credential_blob(&mut web, "aos/web/missing-token");
        link_expose_artifact(&profile, &web);

        let err = exposed_packages(&profile, &[web]).unwrap_err();

        assert!(
            err.chain().any(|cause| cause
                .to_string()
                .contains("is missing from expose artifact")),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_symlink_generated_credential_blob_files() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let mut web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        declare_generated_credential_blob(&mut web, "aos/web/join-token");
        let artifact = web
            .apm
            .as_ref()
            .unwrap()
            .expose_artifact
            .as_ref()
            .unwrap()
            .store_path
            .clone();
        let blob = Path::new(&artifact).join("credstore.encrypted/aos/web/join-token");
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        let target = tmp.path().join("credential-target");
        std::fs::write(&target, "ciphertext").unwrap();
        std::os::unix::fs::symlink(&target, &blob).unwrap();
        link_expose_artifact(&profile, &web);

        let err = exposed_packages(&profile, &[web]).unwrap_err();

        assert!(
            err.chain()
                .any(|cause| cause.to_string().contains("is not a regular file")),
            "{err:?}"
        );
    }

    #[test]
    fn exposed_packages_rejects_undeclared_generated_credential_blob_files() {
        let tmp = TempDir::new().unwrap();
        let profile = Profile {
            path: tmp.path().join("profile"),
            scope: ProfileScope::System,
        };
        std::fs::create_dir_all(profile.current_path().join("expose")).unwrap();
        let web = installed_with_expose(&tmp, "web", "pkghash111", "artifacthash111");
        write_generated_credential_blob_file(&web, "aos/web/extra-token", "extra");
        link_expose_artifact(&profile, &web);

        let err = exposed_packages(&profile, &[web]).unwrap_err();

        assert!(
            err.chain().any(|cause| cause
                .to_string()
                .contains("undeclared generated credential blob")),
            "{err:?}"
        );
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
        grant_tcp_bind(&mut provider, 18080);
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
    fn firewall_reload_dropin_propagates_to_package_side_effects() {
        let packages = vec![
            ExposedPackage {
                name: "api".into(),
                target: "aos-pkg-api.target".into(),
                units: BTreeSet::from([
                    "api.service".to_string(),
                    "aos-pkg-api-firewall.service".to_string(),
                    "aos-pkg-api-netns.service".to_string(),
                    "aos-pkg-api-sysctl.service".to_string(),
                ]),
                artifact_hash: "artifacthash111".into(),
                artifact_store_path: "/nix/store/artifacthash111-expose-api".into(),
                credential_blobs: Vec::new(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            ExposedPackage {
                name: "worker".into(),
                target: "aos-pkg-worker.target".into(),
                units: BTreeSet::from([
                    "worker.service".to_string(),
                    "aos-pkg-worker-firewall.service".to_string(),
                ]),
                artifact_hash: "artifacthash222".into(),
                artifact_store_path: "/nix/store/artifacthash222-expose-worker".into(),
                credential_blobs: Vec::new(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
        ];

        assert_eq!(
            firewall_reload_dropin(&packages),
            concat!(
                "[Unit]\n",
                "X-RestartIfChanged=false\n",
                "PropagatesReloadTo=aos-pkg-api-firewall.service ",
                "aos-pkg-api-netns.service ",
                "aos-pkg-worker-firewall.service\n",
            ),
        );
    }

    #[test]
    fn firewall_reload_dropin_change_does_not_restart_nftables() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("root");
        let live_attached = root.join("etc").join(ATTACHED_REL);
        std::fs::create_dir_all(live_attached.join("nftables.service.d")).unwrap();
        std::fs::write(
            live_attached
                .join("nftables.service.d")
                .join("50-aos-package-firewall-reload.conf"),
            "[Unit]\nX-RestartIfChanged=false\nPropagatesReloadTo=aos-pkg-api-firewall.service\n",
        )
        .unwrap();

        let packages = vec![
            ExposedPackage {
                name: "api".into(),
                target: "aos-pkg-api.target".into(),
                units: BTreeSet::from(["aos-pkg-api-firewall.service".to_string()]),
                artifact_hash: "artifacthash111".into(),
                artifact_store_path: "/nix/store/artifacthash111-expose-api".into(),
                credential_blobs: Vec::new(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            ExposedPackage {
                name: "worker".into(),
                target: "aos-pkg-worker.target".into(),
                units: BTreeSet::from(["aos-pkg-worker-firewall.service".to_string()]),
                artifact_hash: "artifacthash222".into(),
                artifact_store_path: "/nix/store/artifacthash222-expose-worker".into(),
                credential_blobs: Vec::new(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
        ];

        let diff = compute_attached_unit_diff(&root, &packages).unwrap();

        assert!(!diff.to_restart.contains(&"nftables.service".to_string()));
        assert!(diff.to_reload.is_empty());
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
        grant_tcp_bind(&mut provider, 18080);

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
        grant_tcp_bind(&mut provider, 18080);

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
        grant_tcp_bind(&mut provider, 18080);

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
        grant_tcp_bind(&mut provider, 18080);

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
            credential_blobs: Vec::new(),
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
    fn changed_or_removed_service_roots_require_old_target_stop() {
        let diff = UnitDiff {
            to_restart: vec![
                "aos-pkg-web-service-roots.service".to_string(),
                "web.service".to_string(),
            ],
            to_stop: vec!["aos-pkg-api-service-roots.service".to_string()],
            ..Default::default()
        };

        assert_eq!(
            service_root_targets_requiring_preswap_stop(&diff),
            BTreeSet::from([
                "aos-pkg-api.target".to_string(),
                "aos-pkg-web.target".to_string(),
            ])
        );
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

    #[test]
    fn landlock_service_paths_include_systemd_managed_directories() {
        let service = BTreeMap::from([
            ("StateDirectory".into(), vec!["state-a state-b".into()]),
            ("RuntimeDirectory".into(), vec!["runtime-a".into()]),
            ("CacheDirectory".into(), vec!["cache-a".into()]),
            ("LogsDirectory".into(), vec!["logs-a".into()]),
        ]);

        assert_eq!(
            landlock_service_paths_for_service("web", &service),
            vec![
                "/var/lib/state-a",
                "/var/lib/state-b",
                "/run/runtime-a",
                "/var/cache/cache-a",
                "/var/log/logs-a",
            ]
        );
        assert_eq!(
            landlock_service_paths_for_service("web", &BTreeMap::new()),
            vec!["/var/lib/aos-pkg-web"]
        );
    }

    #[test]
    fn host_network_keeps_filesystem_landlock_only() {
        let permissions = PermissionsMeta {
            network: Some(NetworkPermission::Host),
            tcp_bind: vec![8080],
            tcp_connect: vec![443],
            ..PermissionsMeta::default()
        };

        let args = expected_landlock_args(&permissions, &["/var/lib/example".to_string()]);

        assert_eq!(
            args,
            vec![
                "--require-abi",
                "4",
                "--network-unrestricted",
                "--fs-ro",
                "/",
                "--fs-rw",
                "/tmp",
                "--fs-rw",
                "/var/tmp",
                "--fs-rw",
                "/dev/null",
                "--fs-rw",
                "/var/lib/example",
                "--",
            ]
        );
    }
}

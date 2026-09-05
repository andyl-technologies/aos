//! Expose manifest validation and compilation of mandatory-access-control artifacts.

use crate::registry_ops::store_paths::{
    StorePathInfo, introspect_store_path, store_dir_from_store_path,
};
use crate::types::{
    ConfinementClass, ExposeArtifactMeta, ExposeMeta, PermissionsMeta,
    validate_expose_artifact_meta, validate_expose_meta_for_package, validate_permissions_meta,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::process::Command;

#[cfg(not(test))]
const CHECKMODULE_ENV: &str = "AOS_CHECKMODULE";

#[cfg(not(test))]
const SEMODULE_PACKAGE_ENV: &str = "AOS_SEMODULE_PACKAGE";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct PublishExposeManifest {
    pub(in crate::registry_ops) expose: ExposeMeta,
    pub(in crate::registry_ops) permissions: PermissionsMeta,
    #[serde(default)]
    pub(in crate::registry_ops) mac: Option<PublishMacProfileManifest>,
    #[serde(default, rename = "kernel")]
    pub(in crate::registry_ops) _kernel: Option<Value>,
    #[serde(default, rename = "firewall")]
    pub(in crate::registry_ops) _firewall: Option<Value>,
    #[serde(default, rename = "confinement")]
    pub(in crate::registry_ops) _confinement: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct PublishMacProfileManifest {
    pub(in crate::registry_ops) version: u32,
    pub(in crate::registry_ops) package: String,
    pub(in crate::registry_ops) backend: String,
    #[serde(rename = "securityLabel")]
    pub(in crate::registry_ops) security_label: String,
    #[serde(rename = "defaultDeny")]
    pub(in crate::registry_ops) default_deny: bool,
    #[serde(rename = "profilePath")]
    pub(in crate::registry_ops) profile_path: Option<String>,
}

#[derive(Debug)]
pub(in crate::registry_ops) struct CompiledSelinuxProfile {
    pub(in crate::registry_ops) module: Vec<u8>,
    pub(in crate::registry_ops) profile: Vec<u8>,
}

pub(in crate::registry_ops) fn read_publish_expose_manifest(
    path: &str,
    package_name: &str,
) -> Result<PublishExposeManifest> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading expose manifest {path}"))?;
    let mut manifest: PublishExposeManifest = serde_json::from_str(&content)
        .with_context(|| format!("parsing expose manifest {path}"))?;

    validate_expose_meta_for_package(package_name, &manifest.expose)
        .with_context(|| format!("validating expose manifest for package '{package_name}'"))?;
    if manifest.permissions.confinement.is_none() {
        manifest.permissions.confinement = Some(manifest.permissions.computed_confinement());
    }
    validate_permissions_meta(package_name, &manifest.permissions)
        .with_context(|| format!("validating permissions manifest for package '{package_name}'"))?;
    if let Some(mac) = &manifest.mac {
        validate_publish_mac_profile_manifest(package_name, &manifest.permissions, mac)
            .with_context(|| {
                format!("validating MAC profile manifest for package '{package_name}'")
            })?;
        validate_publish_mac_profile_artifacts(Path::new(path), package_name, mac)?;
    }

    Ok(manifest)
}

pub(in crate::registry_ops) fn read_publish_manifest_digest(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("reading expose manifest {}", path.display()))?;
    Ok(crate::package_attestation::package_manifest_digest_bytes(
        &bytes,
    ))
}

fn validate_publish_mac_profile_manifest(
    package_name: &str,
    permissions: &PermissionsMeta,
    mac: &PublishMacProfileManifest,
) -> Result<()> {
    let expected_label = permissions
        .security_label
        .clone()
        .unwrap_or_else(|| format!("aos-pkg-{package_name}"));
    let expected_default_deny = permissions
        .confinement
        .as_ref()
        .map(|confinement| confinement.class != ConfinementClass::Unconfined)
        .unwrap_or_else(|| {
            permissions.computed_confinement().class != ConfinementClass::Unconfined
        });
    let expected_profile_path =
        expected_default_deny.then(|| expected_publish_selinux_profile_path(&expected_label));

    if mac.version != 1 {
        bail!(
            "MAC profile manifest for package '{}' has unsupported version {}",
            package_name,
            mac.version
        );
    }
    if mac.package != package_name {
        bail!(
            "MAC profile manifest package mismatch: expected '{}', got '{}'",
            package_name,
            mac.package
        );
    }
    if mac.backend != "selinux" {
        bail!(
            "MAC profile manifest backend mismatch for package '{}'",
            package_name
        );
    }
    if mac.security_label != expected_label {
        bail!(
            "MAC profile manifest security label mismatch for package '{}'",
            package_name
        );
    }
    if mac.default_deny != expected_default_deny
        || mac.profile_path.as_deref() != expected_profile_path.as_deref()
    {
        bail!(
            "MAC profile manifest confinement mode mismatch for package '{}'",
            package_name
        );
    }
    Ok(())
}

fn validate_publish_mac_profile_artifacts(
    manifest_path: &Path,
    package_name: &str,
    mac: &PublishMacProfileManifest,
) -> Result<()> {
    let artifact_root = manifest_path.parent().with_context(|| {
        format!(
            "expose manifest path has no parent: {}",
            manifest_path.display()
        )
    })?;
    let mac_path = artifact_root.join("mac-profile.json");
    let artifact_mac: PublishMacProfileManifest = read_publish_mac_profile_file(&mac_path)
        .with_context(|| {
            format!(
                "validating MAC profile artifact for package '{}' at {}",
                package_name,
                mac_path.display()
            )
        })?;
    if &artifact_mac != mac {
        bail!(
            "MAC profile artifact for package '{}' does not match manifest.mac",
            package_name
        );
    }

    let Some(profile_path) = &mac.profile_path else {
        return Ok(());
    };
    let profile_bytes =
        read_artifact_regular_bytes_no_symlink(artifact_root, Path::new(profile_path))
            .with_context(|| format!("reading MAC profile file {}", profile_path))?;
    if profile_bytes.is_empty() {
        bail!(
            "MAC profile file for package '{}' is empty: {}",
            package_name,
            profile_path
        );
    }
    let module_name = publish_selinux_identifier_for_label(&mac.security_label);
    let module_path = format!("mac/selinux/{module_name}.mod");
    let module_bytes =
        read_artifact_regular_bytes_no_symlink(artifact_root, Path::new(&module_path))
            .with_context(|| format!("reading MAC module file {}", module_path))?;
    if module_bytes.is_empty() {
        bail!(
            "MAC module file for package '{}' is empty: {}",
            package_name,
            module_path
        );
    }
    let source_path = format!("mac/selinux/{module_name}.te");
    let source_text = read_artifact_regular_file_no_symlink(artifact_root, Path::new(&source_path))
        .with_context(|| format!("reading MAC source file {}", source_path))?;
    let expected_profile = expected_publish_selinux_profile(&mac.security_label);
    if source_text.trim_end() != expected_profile.trim_end() {
        bail!(
            "MAC source file for package '{}' does not match the expected default-deny scaffold",
            package_name
        );
    }
    validate_publish_compiled_selinux_profile(
        package_name,
        &source_text,
        &module_name,
        &module_path,
        &module_bytes,
        profile_path,
        &profile_bytes,
    )?;
    Ok(())
}

fn validate_publish_compiled_selinux_profile(
    package_name: &str,
    source_text: &str,
    module_name: &str,
    module_path: &str,
    module_bytes: &[u8],
    profile_path: &str,
    profile_bytes: &[u8],
) -> Result<()> {
    let expected = compile_publish_selinux_profile(source_text, module_name)
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
pub(in crate::registry_ops) fn compile_publish_selinux_profile(
    source_text: &str,
    _module_name: &str,
) -> Result<CompiledSelinuxProfile> {
    Ok(CompiledSelinuxProfile {
        module: format!("compiled-module\n{source_text}").into_bytes(),
        profile: format!("compiled-policy\n{source_text}").into_bytes(),
    })
}

#[cfg(not(test))]
pub(in crate::registry_ops) fn compile_publish_selinux_profile(
    source_text: &str,
    module_name: &str,
) -> Result<CompiledSelinuxProfile> {
    let checkmodule = trusted_publish_checkmodule_path()?;
    let semodule_package = trusted_publish_semodule_package_path()?;
    let tmp = tempfile::TempDir::new().context("creating SELinux policy validation tempdir")?;
    let source_path = tmp.path().join(format!("{module_name}.te"));
    let module_path = tmp.path().join(format!("{module_name}.mod"));
    let profile_path = tmp.path().join(format!("{module_name}.pp"));
    fs::write(&source_path, source_text)
        .with_context(|| format!("writing {}", source_path.display()))?;
    run_selinux_policy_tool(
        &checkmodule,
        &[
            std::ffi::OsStr::new("-M"),
            std::ffi::OsStr::new("-m"),
            std::ffi::OsStr::new("-o"),
            module_path.as_os_str(),
            source_path.as_os_str(),
        ],
    )?;
    run_selinux_policy_tool(
        &semodule_package,
        &[
            std::ffi::OsStr::new("-o"),
            profile_path.as_os_str(),
            std::ffi::OsStr::new("-m"),
            module_path.as_os_str(),
        ],
    )?;
    Ok(CompiledSelinuxProfile {
        module: fs::read(&module_path)
            .with_context(|| format!("reading {}", module_path.display()))?,
        profile: fs::read(&profile_path)
            .with_context(|| format!("reading {}", profile_path.display()))?,
    })
}

#[cfg(not(test))]
fn run_selinux_policy_tool(program: &str, args: &[&std::ffi::OsStr]) -> Result<()> {
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

fn read_publish_mac_profile_file(path: &Path) -> Result<PublishMacProfileManifest> {
    let content = read_regular_file_no_symlink(path)?;
    serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))
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

fn read_regular_file_no_symlink(path: &Path) -> Result<String> {
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("checking {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

#[cfg(not(test))]
fn trusted_publish_checkmodule_path() -> Result<String> {
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

#[cfg(not(test))]
fn trusted_publish_semodule_package_path() -> Result<String> {
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

fn expected_publish_selinux_profile_path(label: &str) -> String {
    format!(
        "mac/selinux/{}.pp",
        publish_selinux_identifier_for_label(label)
    )
}

pub(in crate::registry_ops) fn publish_selinux_identifier_for_label(label: &str) -> String {
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

fn publish_selinux_type_for_label(label: &str) -> String {
    format!("{}_t", publish_selinux_identifier_for_label(label))
}

pub(in crate::registry_ops) fn expected_publish_selinux_profile(label: &str) -> String {
    let module_name = publish_selinux_identifier_for_label(label);
    let type_name = publish_selinux_type_for_label(label);
    format!(
        "# Generated by AOS package expose renderer.\n# RFC-0001 per-package SELinux default-deny module.\nmodule {module_name} 1.0;\n\nrequire {{\n  type init_t;\n  type kernel_t;\n  type root_t;\n  type tmp_t;\n  type tmpfs_t;\n  type unlabeled_t;\n  type var_lib_t;\n  type var_t;\n  attribute domain;\n  attribute file_type;\n  role system_r;\n  class dir {{ getattr open read search }};\n  class fd use;\n  class file {{ execute execute_no_trans execmod getattr map open read }};\n  class lnk_file {{ getattr read }};\n  class process {{ dyntransition execmem execstack execheap }};\n  class process2 {{ nnp_transition nosuid_transition }};\n}}\n\ntype {type_name};\ntypeattribute {type_name} domain;\nrole system_r types {type_name};\n\nallow {type_name} init_t:fd use;\nallow init_t {type_name}:process dyntransition;\nallow init_t {type_name}:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} kernel_t:fd use;\nallow kernel_t {type_name}:process dyntransition;\nallow kernel_t {type_name}:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} self:process {{ execmem execstack execheap }};\nallow {type_name} self:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} file_type:file execmod;\nallow {type_name} root_t:dir {{ getattr open read search }};\nallow {type_name} tmp_t:dir {{ getattr open read search }};\nallow {type_name} tmp_t:lnk_file {{ getattr read }};\nallow {type_name} tmpfs_t:dir {{ getattr open read search }};\nallow {type_name} tmpfs_t:lnk_file {{ getattr read }};\nallow {type_name} unlabeled_t:dir {{ getattr open read search }};\nallow {type_name} unlabeled_t:file {{ execute execute_no_trans execmod getattr map open read }};\nallow {type_name} unlabeled_t:lnk_file {{ getattr read }};\nallow {type_name} var_t:dir {{ getattr open read search }};\nallow {type_name} var_t:lnk_file {{ getattr read }};\nallow {type_name} var_lib_t:dir {{ getattr open read search }};\nallow {type_name} var_lib_t:lnk_file {{ getattr read }};\n"
    )
}

/// Infer the rendered expose artifact from a manifest produced by
/// `_expose-renderer.nix`.
pub(in crate::registry_ops) fn infer_publish_expose_artifact(path: &str) -> Result<StorePathInfo> {
    let manifest_path = Path::new(path);
    let Some(parent) = manifest_path.parent() else {
        bail!("expose manifest path has no parent: {path}");
    };
    let Some(parent_str) = parent.to_str() else {
        bail!(
            "expose manifest parent path is not UTF-8: {}",
            parent.display()
        );
    };
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("manifest.json") {
        bail!("expose manifest must be named manifest.json: {path}");
    }
    if store_dir_from_store_path(parent_str).is_none() {
        bail!("expose manifest must live directly in a Nix store artifact: {path}");
    }
    if !parent.join("units").is_dir() {
        bail!(
            "expose artifact {} is missing required units/ directory",
            parent.display()
        );
    }

    let info = introspect_store_path(parent_str)
        .with_context(|| format!("introspecting expose artifact {parent_str}"))?;
    let artifact = ExposeArtifactMeta {
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
    };
    validate_expose_artifact_meta(&artifact)?;
    Ok(info)
}

#[cfg(test)]
mod tests;

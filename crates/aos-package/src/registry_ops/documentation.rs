//! Package documentation derivation, runtime surface descriptions, and publication.

use crate::registry_ops::attestation::documentation_nar_identity;
use crate::registry_ops::config_modules::{
    DerivedOptionDeclaration, PublishConfigModuleManifest, nix_publish_string,
};
use crate::registry_ops::mac::PublishExposeManifest;
use crate::registry_ops::store_paths::{
    StorePathInfo, introspect_store_path, nix_command, store_dir_from_store_path,
};
use crate::registry_ops::uki::sha256_hex;
use crate::types::{
    ConfigModuleMeta, ConfinementClass, DocumentationArtifactMeta,
    validate_documentation_artifact_meta,
};
use anyhow::{Context, Result, bail};
use aos_doc_model::{
    ActivationEffect, ActivationKind, ConfinementSummary, CredentialContract, DOCUMENT_FORMAT,
    DOCUMENT_SCHEMA, DocumentationIdentity, DocumentedPackage, OptionDocument, OptionOwner,
    PackageDocumentation, PathSegment, ProseBlock, RuntimeCapability, RuntimeConfigArtifact,
    RuntimeListener, RuntimeSurface, RuntimeUnit, Section, Visibility,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Command;

/// Package-authored enrichment that cannot be inferred from option/expose
/// declarations. It is closed data copied into the trusted config companion;
/// the canonical document model performs the final deep validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct PublishDocumentationManifest {
    #[serde(default)]
    pub(in crate::registry_ops) summary: Option<String>,
    #[serde(default)]
    sections: BTreeMap<String, PublishDocumentationSection>,
    #[serde(default)]
    options: BTreeMap<String, PublishOptionDocumentation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDocumentationSection {
    title: String,
    blocks: Vec<ProseBlock>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishOptionDocumentation {
    #[serde(default)]
    activation: Option<ActivationEffect>,
    #[serde(default)]
    deprecated: Option<String>,
    #[serde(default)]
    replacement: Option<Vec<PathSegment>>,
}

#[derive(Debug)]
pub(in crate::registry_ops) struct PublishedDocumentation {
    pub(in crate::registry_ops) metadata: DocumentationArtifactMeta,
    pub(in crate::registry_ops) info: StorePathInfo,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedSystemDocumentation {
    declarations: Vec<DerivedOptionDeclaration>,
    units: Vec<String>,
}

#[derive(Debug)]
pub(in crate::registry_ops) struct PublishedSystemDocumentation {
    pub(in crate::registry_ops) base_lib: StorePathInfo,
    pub(in crate::registry_ops) declarations: Vec<DerivedOptionDeclaration>,
    pub(in crate::registry_ops) units: Vec<String>,
}

/// Extracts system-owned service options from the immutable Nix catalog in an
/// image evaluation base library.
pub(in crate::registry_ops) fn derive_system_documentation(
    base_lib: StorePathInfo,
    package_name: &str,
) -> Result<Option<PublishedSystemDocumentation>> {
    let expression = format!(
        r#"let
  base = import <aos-documentation-base-lib>;
  catalog = import <aos-documentation-base-lib/lib/service-documentation.nix>;
  service = catalog.services.{} or null;
  evaluated = base.evalHostConfig {{}};
  publicDeclarations = builtins.filter
    (declaration: declaration.visibility != "internal")
    (base.lib.optionSurface evaluated);
  matchesPrefix = prefix: declaration:
    declaration.pathStr == prefix || base.lib.hasPrefix "${{prefix}}." declaration.pathStr;
  selected =
    if service == null || service.ownership == "package" then []
    else if service.ownership == "platform" then publicDeclarations
    else builtins.filter
      (declaration: builtins.any (prefix: matchesPrefix prefix declaration) service.optionPrefixes)
      publicDeclarations;
in assert catalog.schema == "aos.service-documentation/v1";
  if service == null || service.ownership == "package" then null else {{
    declarations = builtins.map (declaration: {{
      inherit (declaration)
        path pathStr typeSig type description default example visibility readOnly
        contributable;
      owner = "aos";
    }}) selected;
    units = service.units or [];
  }}"#,
        nix_publish_string(package_name),
    );
    let search_path = format!("aos-documentation-base-lib={}", base_lib.path);
    let evaluator = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join("nix-instantiate"))
                .find(|candidate| candidate.is_file())
        })
        .context("cannot find nix-instantiate in the AOS command path")?;
    let output = Command::new(evaluator)
        .env_clear()
        .args([
            "--eval",
            "--strict",
            "--json",
            "--option",
            "restrict-eval",
            "true",
            "--option",
            "allow-import-from-derivation",
            "false",
            "-I",
            &search_path,
            "--expr",
            &expression,
        ])
        .output()
        .with_context(|| {
            format!("extracting system-owned documentation for package '{package_name}'")
        })?;
    if !output.status.success() {
        bail!(
            "system-owned documentation evaluation failed for package '{package_name}': {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let surface: Option<DerivedSystemDocumentation> = serde_json::from_slice(&output.stdout)
        .with_context(|| {
            format!("parsing system-owned documentation for package '{package_name}'")
        })?;
    let Some(mut surface) = surface else {
        return Ok(None);
    };
    if surface.declarations.is_empty() {
        bail!(
            "system-owned documentation catalog entry for package '{package_name}' selects no options"
        );
    }
    surface.units.sort();
    surface.units.dedup();
    Ok(Some(PublishedSystemDocumentation {
        base_lib,
        declarations: surface.declarations,
        units: surface.units,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(in crate::registry_ops) fn publish_package_documentation(
    name: &str,
    version: &str,
    platform: &str,
    description: &str,
    homepage: Option<&str>,
    license: &str,
    runtime: &StorePathInfo,
    source: Option<&StorePathInfo>,
    config_module: Option<&ConfigModuleMeta>,
    config_manifest: Option<&PublishConfigModuleManifest>,
    system_documentation: Option<&PublishedSystemDocumentation>,
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact: Option<&StorePathInfo>,
    declarations: &[DerivedOptionDeclaration],
) -> Result<PublishedDocumentation> {
    let authored = config_manifest
        .map(|manifest| &manifest.documentation)
        .cloned()
        .unwrap_or_default();
    if let Some(summary) = authored.summary.as_deref()
        && summary != description
    {
        bail!(
            "package '{name}' documentation summary must equal its catalog description so there is one summary authority"
        );
    }

    let declaration_paths = documented_option_declarations(declarations)
        .map(|declaration| declaration.path_str.as_str())
        .collect::<HashSet<_>>();
    if let Some(foreign) = authored
        .options
        .keys()
        .find(|path| !declaration_paths.contains(path.as_str()))
    {
        bail!("package '{name}' documentation enriches undeclared option '{foreign}'");
    }

    let sections = authored
        .sections
        .into_iter()
        .map(|(id, section)| Section {
            id,
            title: section.title,
            blocks: section.blocks,
        })
        .collect::<Vec<_>>();
    let options = documented_option_declarations(declarations)
        .map(|declaration| {
            let enrichment = authored.options.get(&declaration.path_str);
            if declaration.description.trim().is_empty() {
                bail!(
                    "public configuration option '{}' has no description",
                    declaration.path_str
                );
            }
            let description = declaration.description.clone();
            let root = declaration
                .path
                .first()
                .cloned()
                .context("documentation option path is empty")?;
            let interface_abi = config_manifest.and_then(|manifest| {
                manifest
                    .owns_roots
                    .iter()
                    .find(|owned| owned.root == root)
                    .map(|owned| owned.interface_abi)
            });
            Ok(OptionDocument {
                path: declaration
                    .path
                    .iter()
                    .cloned()
                    .map(|value| PathSegment::Literal { value })
                    .collect(),
                display_path: declaration.path_str.clone(),
                option_type: declaration.option_type.clone(),
                type_signature: declaration.type_sig.clone(),
                description: vec![ProseBlock::Paragraph {
                    spans: vec![aos_doc_model::InlineSpan::Text { text: description }],
                }],
                default: declaration.default.clone(),
                example: declaration.example.clone(),
                visibility: declaration.visibility,
                read_only: declaration.read_only,
                deprecated: enrichment.and_then(|entry| entry.deprecated.clone()),
                replacement: enrichment.and_then(|entry| entry.replacement.clone()),
                owner: OptionOwner {
                    package: declaration.owner.clone(),
                    root,
                    interface_abi,
                },
                contributable: declaration.contributable,
                activation: enrichment.and_then(|entry| entry.activation.clone()),
                source: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut document = PackageDocumentation {
        schema: DOCUMENT_SCHEMA.to_string(),
        package: DocumentedPackage {
            name: name.to_string(),
            version: version.to_string(),
            platform: platform.to_string(),
            summary: description.to_string(),
            homepage: homepage.map(str::to_string),
            license: license.to_string(),
        },
        identity: DocumentationIdentity {
            semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
            runtime_nar_hash: documentation_nar_identity(&runtime.nar_hash)?,
            config_module_nar_hash: config_module
                .map(|module| documentation_nar_identity(&module.config_output.nar_hash))
                .transpose()?,
            system_module_nar_hash: system_documentation
                .map(|surface| documentation_nar_identity(&surface.base_lib.nar_hash))
                .transpose()?,
            expose_artifact_nar_hash: expose_artifact
                .map(|artifact| documentation_nar_identity(&artifact.nar_hash))
                .transpose()?,
            source_nar_hash: documentation_nar_identity(
                source.map_or(runtime.nar_hash.as_str(), |source| source.nar_hash.as_str()),
            )?,
        },
        sections,
        options,
        runtime: documentation_runtime_surface(
            expose_manifest,
            expose_artifact,
            system_documentation,
        )?,
    };
    document.identity.semantic_schema_sha256 = document
        .computed_semantic_schema_sha256()
        .context("computing package documentation semantic schema digest")?;
    document
        .verify_semantic_schema_sha256()
        .context("verifying package documentation semantic schema digest")?;
    let bytes = document
        .canonical_json()
        .context("encoding canonical package documentation")?;
    let document_sha256 = format!("sha256:{}", sha256_hex(&bytes));

    let directory = tempfile::tempdir().context("creating documentation materialization input")?;
    let path = directory
        .path()
        .join(format!("{name}-{version}-aos-docs.json"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("creating documentation input {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("writing documentation input {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing documentation input {}", path.display()))?;
    drop(file);

    let output = nix_command("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(&path)
        .output()
        .context("adding canonical package documentation to the Nix store")?;
    if !output.status.success() {
        bail!(
            "nix-store --add-fixed failed for package documentation: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_path = String::from_utf8(output.stdout)
        .context("documentation store path is not UTF-8")?
        .trim()
        .to_string();
    let info = introspect_store_path(&store_path)
        .context("introspecting canonical package documentation store object")?;
    if !info.references.is_empty() {
        bail!("package documentation store object must have no references");
    }
    let stored = fs::metadata(&info.path)
        .with_context(|| format!("inspecting documentation object {}", info.path))?;
    if !stored.is_file() || stored.len() != bytes.len() as u64 {
        bail!("package documentation store object must be one exact regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if stored.permissions().mode() & 0o111 != 0 {
            bail!("package documentation store object must not be executable");
        }
    }

    let metadata = DocumentationArtifactMeta {
        format: DOCUMENT_FORMAT.to_string(),
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
        document_sha256,
        document_size: bytes.len() as u64,
        semantic_schema_sha256: document.identity.semantic_schema_sha256,
        system_module_nar_hash: system_documentation
            .map(|surface| documentation_nar_identity(&surface.base_lib.nar_hash))
            .transpose()?,
        references: Vec::new(),
    };
    validate_documentation_artifact_meta(&metadata)
        .context("validating published package documentation metadata")?;
    Ok(PublishedDocumentation { metadata, info })
}

/// Selects the declarations that form the user/tooling documentation surface.
///
/// Internal module-system plumbing remains part of the signed config-module
/// declaration schema and authorization checks, but it is not a package API
/// and may intentionally use reserved path segments such as
/// `_aosExposeConfigProjection`.
fn documented_option_declarations(
    declarations: &[DerivedOptionDeclaration],
) -> impl Iterator<Item = &DerivedOptionDeclaration> {
    declarations
        .iter()
        .filter(|declaration| declaration.visibility != Visibility::Internal)
}

fn documentation_runtime_surface(
    manifest: Option<&PublishExposeManifest>,
    expose_artifact: Option<&StorePathInfo>,
    system_documentation: Option<&PublishedSystemDocumentation>,
) -> Result<RuntimeSurface> {
    let Some(manifest) = manifest else {
        let units = system_documentation
            .into_iter()
            .flat_map(|surface| surface.units.iter())
            .map(|name| RuntimeUnit {
                name: name.clone(),
                kind: name
                    .rsplit_once('.')
                    .map_or("unit", |(_, kind)| kind)
                    .to_string(),
                summary: "System-owned service unit".to_string(),
                requires: Vec::new(),
            })
            .collect();
        return Ok(RuntimeSurface {
            units,
            ..RuntimeSurface::default()
        });
    };
    let expose_artifact =
        expose_artifact.context("exposed package documentation has no expose artifact")?;
    let expose = &manifest.expose;
    let permissions = &manifest.permissions;
    let network = match permissions.network {
        Some(crate::types::NetworkPermission::PrivateOutbound) => "private-outbound",
        Some(crate::types::NetworkPermission::Host) => "host",
        Some(crate::types::NetworkPermission::Private) | None => "private",
    };
    let mut units = expose
        .units
        .iter()
        .map(|name| {
            Ok(RuntimeUnit {
                name: name.clone(),
                kind: name
                    .rsplit_once('.')
                    .map_or("unit", |(_, kind)| kind)
                    .to_string(),
                summary: exposed_unit_description(&expose_artifact.path, name)?,
                requires: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if !units.iter().any(|unit| unit.name == expose.target) {
        units.push(RuntimeUnit {
            name: expose.target.clone(),
            kind: "target".to_string(),
            summary: "Package activation target".to_string(),
            requires: Vec::new(),
        });
    }
    units.sort_by(|left, right| left.name.cmp(&right.name));

    let listeners = permissions
        .tcp_bind
        .iter()
        .copied()
        .map(|port| RuntimeListener {
            unit: expose.target.clone(),
            protocol: "tcp".to_string(),
            port: Some(port),
            network_mode: network.to_string(),
        })
        .collect();
    let mut managed_paths = permissions
        .host_paths
        .iter()
        .map(|path| aos_doc_model::ManagedPath {
            path: path.path.clone(),
            purpose: "host-path".to_string(),
            writable: path.mode == crate::types::HostPathMode::Rw,
        })
        .collect::<Vec<_>>();
    managed_paths.extend(expose.config.artifacts.iter().map(|artifact| {
        aos_doc_model::ManagedPath {
            path: artifact.path.clone(),
            purpose: "configuration".to_string(),
            writable: false,
        }
    }));
    managed_paths.sort_by(|left, right| left.path.cmp(&right.path));

    let config_artifacts = expose
        .config
        .artifacts
        .iter()
        .map(|artifact| {
            let kind = match artifact.reload {
                crate::types::ConfigReloadPolicy::Reload => ActivationKind::Reload,
                crate::types::ConfigReloadPolicy::Restart => ActivationKind::Restart,
                crate::types::ConfigReloadPolicy::None => ActivationKind::None,
            };
            let mut units = artifact.units.clone();
            units.sort();
            units.dedup();
            RuntimeConfigArtifact {
                name: artifact.name.clone(),
                destination: artifact.path.clone(),
                format: match artifact.format {
                    crate::types::ConfigArtifactFormat::Env => "env",
                    crate::types::ConfigArtifactFormat::Json => "json",
                    crate::types::ConfigArtifactFormat::Toml => "toml",
                }
                .to_string(),
                activation: Some(ActivationEffect { kind, units }),
            }
        })
        .collect();
    let credentials = expose
        .config
        .credentials
        .iter()
        .map(|credential| CredentialContract {
            name: credential.name.clone(),
            purpose: format!("Credential consumed by {}", credential.units.join(", ")),
            destination: format!("%d/{}", credential.name),
            accepted_kinds: if credential.encrypted {
                vec![
                    "tpm2-credential".to_string(),
                    "system-credential".to_string(),
                ]
            } else {
                vec!["system-credential".to_string()]
            },
            required: !credential.optional,
            mode: 0o600,
            activation: Some(ActivationEffect {
                kind: ActivationKind::Restart,
                units: {
                    let mut units = credential.units.clone();
                    units.sort();
                    units.dedup();
                    units
                },
            }),
        })
        .collect();
    let mut capabilities = expose
        .provides
        .iter()
        .map(|capability| RuntimeCapability {
            name: capability.name.clone(),
            direction: "provides".to_string(),
        })
        .chain(expose.uses.iter().map(|capability| RuntimeCapability {
            name: format!("{}/{}", capability.provider, capability.name),
            direction: "uses".to_string(),
        }))
        .collect::<Vec<_>>();
    capabilities
        .sort_by(|left, right| (&left.direction, &left.name).cmp(&(&right.direction, &right.name)));
    let computed = permissions.computed_confinement();
    let class = match computed.class {
        ConfinementClass::Sandboxed => "sandboxed",
        ConfinementClass::SandboxedWithHoles => "sandboxed-with-holes",
        ConfinementClass::Unconfined => "unconfined",
    };

    Ok(RuntimeSurface {
        units,
        listeners,
        managed_paths,
        config_artifacts,
        credentials,
        capabilities,
        confinement: Some(ConfinementSummary {
            class: class.to_string(),
            network: network.to_string(),
            private_root: computed.class != ConfinementClass::Unconfined,
        }),
    })
}

/// Extracts the human-facing unit description from an authenticated expose artifact.
fn exposed_unit_description(expose_artifact: &str, unit: &str) -> Result<String> {
    crate::types::validate_unit_name(unit)
        .with_context(|| format!("validating documented runtime unit '{unit}'"))?;
    let path = Path::new(expose_artifact).join("units").join(unit);
    let link_metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspecting documented runtime unit {}", path.display()))?;
    let source = if link_metadata.file_type().is_symlink() {
        let target = fs::read_link(&path)
            .with_context(|| format!("resolving documented runtime unit {}", path.display()))?;
        let expose_store_dir = store_dir_from_store_path(expose_artifact);
        let target_store_path = target.parent().and_then(Path::to_str);
        if target.file_name() != Some(std::ffi::OsStr::new(unit))
            || expose_store_dir.is_none()
            || target_store_path.and_then(store_dir_from_store_path) != expose_store_dir
        {
            bail!(
                "documented runtime unit symlink must select the same unit from one direct store object: {}",
                path.display()
            );
        }
        target
    } else {
        path.clone()
    };
    let metadata = fs::metadata(&source)
        .with_context(|| format!("inspecting documented runtime unit {}", source.display()))?;
    if !metadata.is_file() {
        bail!(
            "documented runtime unit must be one regular file: {}",
            source.display()
        );
    }

    const MAX_DOCUMENTED_UNIT_BYTES: u64 = 1024 * 1024;
    let mut content = String::new();
    fs::File::open(&source)?
        .take(MAX_DOCUMENTED_UNIT_BYTES + 1)
        .read_to_string(&mut content)
        .with_context(|| format!("reading documented runtime unit {}", source.display()))?;
    if content.len() as u64 > MAX_DOCUMENTED_UNIT_BYTES {
        bail!(
            "documented runtime unit exceeds {MAX_DOCUMENTED_UNIT_BYTES} bytes: {}",
            source.display()
        );
    }

    let mut in_unit_section = false;
    let mut description = None;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_unit_section = line == "[Unit]";
            continue;
        }
        if in_unit_section && let Some(value) = line.strip_prefix("Description=") {
            let value = value.trim();
            description = (!value.is_empty()).then(|| value.to_string());
        }
    }
    description.with_context(|| {
        format!(
            "documented runtime unit '{}' has no non-empty [Unit] Description",
            source.display()
        )
    })
}

#[cfg(test)]
mod tests;

//! Package documentation derivation and publication.

use crate::registry_ops::attestation::documentation_nar_identity;
use crate::registry_ops::config_modules::{
    DerivedOptionDeclaration, PublishConfigModuleManifest, nix_publish_string,
};
use crate::registry_ops::mac::PublishExposeManifest;
use crate::registry_ops::store_paths::{StorePathInfo, introspect_store_path, nix_command};
use crate::registry_ops::uki::sha256_hex;
use crate::types::{
    ConfigModuleMeta, DocumentationArtifactMeta, validate_documentation_artifact_meta,
};
use anyhow::{Context, Result, bail};
use aos_doc_model::{
    ActivationEffect, DOCUMENT_FORMAT, DOCUMENT_SCHEMA, DocumentationIdentity, DocumentedPackage,
    OptionDocument, OptionOwner, PackageDocumentation, PathSegment, ProseBlock, Section, Visibility,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
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
}

#[derive(Debug)]
pub(in crate::registry_ops) struct PublishedSystemDocumentation {
    pub(in crate::registry_ops) base_lib: StorePathInfo,
    pub(in crate::registry_ops) declarations: Vec<DerivedOptionDeclaration>,
}

/// Extracts system-owned service options from the evaluated image module graph.
pub(in crate::registry_ops) fn derive_system_documentation(
    base_lib: StorePathInfo,
    package_name: &str,
) -> Result<Option<PublishedSystemDocumentation>> {
    let expression = format!(
        r#"let
  base = import <aos-documentation-base-lib>;
  evaluated = base.evalHostConfig {{}};
  service = evaluated.config.aos.documentation.systemServices.{} or null;
  publicDeclarations = builtins.filter
    (declaration: declaration.visibility != "internal")
    (base.lib.optionSurface evaluated);
  matchesPrefix = prefix: declaration:
    declaration.pathStr == prefix || base.lib.hasPrefix "${{prefix}}." declaration.pathStr;
  selected =
    if service == null then []
    else builtins.filter
      (declaration: builtins.any (prefix: matchesPrefix prefix declaration) service.optionPrefixes)
      publicDeclarations;
in if service == null then null else {{
    declarations = builtins.map (declaration: {{
      inherit (declaration)
        path pathStr typeSig type description default example visibility readOnly
        contributable;
      owner = "aos";
    }}) selected;
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
    let Some(surface) = surface else {
        return Ok(None);
    };
    if surface.declarations.is_empty() {
        bail!("system-owned documentation entry for package '{package_name}' selects no options");
    }
    Ok(Some(PublishedSystemDocumentation {
        base_lib,
        declarations: surface.declarations,
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
    _expose_manifest: Option<&PublishExposeManifest>,
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

#[cfg(test)]
mod tests;

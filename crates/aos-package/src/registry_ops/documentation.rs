//! Package documentation derivation and publication.

use crate::registry_ops::attestation::documentation_nar_identity;
use crate::registry_ops::store_paths::{StorePathInfo, introspect_store_path, nix_command};
use crate::registry_ops::uki::sha256_hex;
use crate::types::{DocumentationArtifactMeta, validate_documentation_artifact_meta};
use anyhow::{Context, Result, bail};
use aos_doc_model::{
    DOCUMENT_FORMAT, DOCUMENT_SCHEMA, DocumentationIdentity, DocumentedPackage,
    PackageDocumentation,
};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;

#[derive(Debug)]
pub(in crate::registry_ops) struct PublishedDocumentation {
    pub(in crate::registry_ops) metadata: DocumentationArtifactMeta,
    pub(in crate::registry_ops) info: StorePathInfo,
}

pub(in crate::registry_ops) fn publish_package_documentation(
    name: &str,
    version: &str,
    platform: &str,
    description: &str,
    homepage: Option<&str>,
    license: &str,
    runtime: &StorePathInfo,
    source: Option<&StorePathInfo>,
) -> Result<PublishedDocumentation> {
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
            source_nar_hash: documentation_nar_identity(
                source.map_or(runtime.nar_hash.as_str(), |source| source.nar_hash.as_str()),
            )?,
        },
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
        references: Vec::new(),
    };
    validate_documentation_artifact_meta(&metadata)
        .context("validating published package documentation metadata")?;
    Ok(PublishedDocumentation { metadata, info })
}

#[cfg(test)]
mod tests;

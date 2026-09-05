//! Signed publication provenance artifacts and append-only transparency records.
//!
//! Publication stores signed DSSE statements and an append-only JSONL log:
//!
//! ```text
//! provenance/<bucket>/<package>/<platform>/<measurement>.intoto.jsonl
//! transparency/package-provenance.jsonl
//!   one signed statement binding per line, chained by entry hash
//! ```

#[cfg(test)]
use crate::provenance::sign_statement_dsse_jsonl;
use crate::provenance::{
    ProvenanceSignature, ProvenanceSigner, TrustedProvenanceKey,
    builder_id as provenance_builder_id, digest_map as provenance_digest_map, sha256_hex_payload,
    sign_statement_dsse_jsonl_external,
};
use crate::registry::keys;
use crate::registry_ops::attestation::{
    config_publish_binding_digest, documentation_nar_identity, publish_attestation_meta,
};
use crate::registry_ops::config::read_registry_toml;
use crate::registry_ops::git::{git_try, registry_relative_path};
use crate::registry_ops::mac::PublishExposeManifest;
use crate::registry_ops::provenance::staged::git_tree_file_bytes;
use crate::registry_ops::provenance::statement::{
    ensure_safe_package_provenance_statement_path, package_provenance_transparency_entry_hash,
};
use crate::registry_ops::signing::ResolvedSigningKey;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::trust::{derive_trust_key, load_committed_roster, validate_roster_key_id};
use crate::registry_ops::uki::sha256_hex;
use crate::security::parse_signing_key;
use crate::types::{
    AttestationMeta, BpfLsmPolicyMeta, ConfigModuleMeta, DocumentationArtifactMeta,
    ExposeArtifactMeta, ExposeMeta, PermissionsMeta, package_name_bucket,
    validate_attestation_meta, validate_package_name, validate_platform_name,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub(in crate::registry_ops) const PACKAGE_PROVENANCE_TRANSPARENCY_LOG: &str =
    "transparency/package-provenance.jsonl";

const PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA: &str =
    "https://andyl.com/aos/transparency/package-provenance/v1";

pub(in crate::registry_ops) const PACKAGE_PROVENANCE_STATEMENT_TYPE: &str =
    "https://in-toto.io/Statement/v1";

pub(in crate::registry_ops) const PACKAGE_PROVENANCE_PREDICATE_TYPE: &str =
    "https://slsa.dev/provenance/v1";

pub(in crate::registry_ops) const PACKAGE_PROVENANCE_BUILD_TYPE: &str =
    "https://andyl.com/aos/apr-publish/v1";

pub(in crate::registry_ops) struct PublishProvenanceArtifact {
    pub(in crate::registry_ops) path: String,
    pub(in crate::registry_ops) jsonl: String,
    pub(in crate::registry_ops) attestation: AttestationMeta,
}

pub(in crate::registry_ops) struct LocalPackageProvenanceSigner {
    pub(in crate::registry_ops) key_id: String,
    pub(in crate::registry_ops) key_path: PathBuf,
}

#[async_trait::async_trait]
impl ProvenanceSigner for LocalPackageProvenanceSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn sign_provenance(&mut self, payload: &[u8]) -> Result<ProvenanceSignature> {
        let armored_signature = crate::security::sign_payload_signature(
            &self.key_path,
            crate::provenance::DSSE_SIGNATURE_NAMESPACE,
            payload,
        )?;
        Ok(ProvenanceSignature {
            key_id: self.key_id.clone(),
            provider_operation_id: "local-file-key".to_string(),
            armored_signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct PackageProvenanceTransparencyLogEntry {
    pub(in crate::registry_ops) body: PackageProvenanceTransparencyLogBody,
    pub(in crate::registry_ops) entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct PackageProvenanceTransparencyLogBody {
    pub(in crate::registry_ops) schema: String,
    pub(in crate::registry_ops) sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::registry_ops) previous_entry_hash: Option<String>,
    pub(in crate::registry_ops) package: String,
    pub(in crate::registry_ops) version: String,
    pub(in crate::registry_ops) platform: String,
    pub(in crate::registry_ops) store_path: String,
    pub(in crate::registry_ops) nar_hash: String,
    pub(in crate::registry_ops) nar_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::registry_ops) root_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::registry_ops) root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::registry_ops) root_hash_sig: Option<String>,
    pub(in crate::registry_ops) provenance: String,
    pub(in crate::registry_ops) measurement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<PackageProvenanceTransparencySource>,
    statement: PackageProvenanceTransparencyStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProvenanceTransparencySource {
    store_path: String,
    nar_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProvenanceTransparencyStatement {
    path: String,
    jsonl_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::registry_ops) struct StagedPackageProvenanceMeta {
    pub(in crate::registry_ops) path: String,
    pub(in crate::registry_ops) package: String,
    pub(in crate::registry_ops) version: String,
    pub(in crate::registry_ops) platform: String,
    pub(in crate::registry_ops) store_path: String,
    pub(in crate::registry_ops) source_drv: String,
    pub(in crate::registry_ops) source_nar_hash: String,
    pub(in crate::registry_ops) root_digest: String,
    pub(in crate::registry_ops) root_hash: Option<String>,
    pub(in crate::registry_ops) root_hash_sig: Option<String>,
    pub(in crate::registry_ops) provenance: String,
    pub(in crate::registry_ops) measurement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::registry_ops) struct PackageTomlPlatformKey {
    pub(in crate::registry_ops) package: String,
    pub(in crate::registry_ops) version: String,
    pub(in crate::registry_ops) platform: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::registry_ops) struct StagedPackageRfc0001Meta {
    #[serde(default)]
    pub(in crate::registry_ops) expose: Option<ExposeMeta>,
    #[serde(default)]
    pub(in crate::registry_ops) expose_artifact: Option<ExposeArtifactMeta>,
    #[serde(default)]
    pub(in crate::registry_ops) permissions: PermissionsMeta,
    #[serde(default, rename = "bpf_lsm")]
    pub(in crate::registry_ops) bpf_lsm: Option<BpfLsmPolicyMeta>,
}

fn unsigned_publish_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    documentation: Option<&DocumentationArtifactMeta>,
    key_id: &str,
) -> Result<Option<(String, Value, AttestationMeta)>> {
    let Some(attestation) = publish_attestation_meta(
        name,
        version,
        platform,
        info,
        manifest,
        Some(manifest_digest),
    )?
    else {
        return Ok(None);
    };
    let attestation = match documentation {
        Some(documentation) => {
            bind_documentation_provenance(attestation, name, platform, documentation)?
        }
        None => attestation,
    };
    let provenance = attestation.provenance.as_deref().map(str::to_string);
    let Some(provenance) = provenance else {
        return Ok(None);
    };
    let mut statement = publish_provenance_statement(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest_digest,
        &attestation,
        key_id,
    )?;
    if let Some(documentation) = documentation {
        append_documentation_provenance_subject(
            &mut statement,
            name,
            version,
            platform,
            documentation,
        )?;
    }
    Ok(Some((provenance, statement, attestation)))
}

#[allow(clippy::too_many_arguments)]
async fn publish_provenance_artifact_inner(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    documentation: Option<&DocumentationArtifactMeta>,
    signer: &mut dyn ProvenanceSigner,
) -> Result<Option<PublishProvenanceArtifact>> {
    let Some((path, statement, attestation)) = unsigned_publish_provenance_artifact(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest,
        manifest_digest,
        documentation,
        signer.key_id(),
    )?
    else {
        return Ok(None);
    };
    let jsonl = sign_statement_dsse_jsonl_external(&statement, signer).await?;
    Ok(Some(PublishProvenanceArtifact {
        path,
        jsonl,
        attestation,
    }))
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(in crate::registry_ops) fn publish_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    signer: &LocalPackageProvenanceSigner,
) -> Result<Option<PublishProvenanceArtifact>> {
    let Some((path, statement, attestation)) = unsigned_publish_provenance_artifact(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest,
        manifest_digest,
        None,
        &signer.key_id,
    )?
    else {
        return Ok(None);
    };
    let jsonl = sign_statement_dsse_jsonl(&statement, &signer.key_id, &signer.key_path)?;
    Ok(Some(PublishProvenanceArtifact {
        path,
        jsonl,
        attestation,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(in crate::registry_ops) async fn publish_provenance_artifact_with_documentation(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    documentation: &DocumentationArtifactMeta,
    signer: &mut dyn ProvenanceSigner,
) -> Result<Option<PublishProvenanceArtifact>> {
    publish_provenance_artifact_inner(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest,
        manifest_digest,
        Some(documentation),
        signer,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn unsigned_config_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    documentation: Option<&DocumentationArtifactMeta>,
    key_id: &str,
) -> Result<(String, Value, AttestationMeta)> {
    let provenance = attestation
        .provenance
        .clone()
        .context("config-module attestation is missing its provenance reference")?;
    let base_lib = module
        .evaluation_base_lib
        .as_ref()
        .context("published config module is missing its evaluation base-lib binding")?;
    let mut statement = publish_provenance_statement(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        &config_publish_binding_digest(module, expose_manifest_digest)?,
        attestation,
        key_id,
    )?;
    let subjects = statement
        .get_mut("subject")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no subject array")?;
    if let Some(expose_digest) = expose_manifest_digest {
        subjects.push(serde_json::json!({
            "name": format!("aos:expose-manifest:{name}:{version}:{platform}"),
            "digest": provenance_digest_map(expose_digest),
        }));
    }
    subjects.push(serde_json::json!({
        "name": format!("aos:config-module:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&module.config_output.nar_hash),
    }));
    subjects.push(serde_json::json!({
        "name": format!("aos:config-base-lib:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&base_lib.nar_hash),
    }));
    let dependencies = statement
        .pointer_mut("/predicate/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no resolvedDependencies array")?;
    dependencies.push(serde_json::json!({
        "uri": module.config_output.store_path,
        "digest": provenance_digest_map(&module.config_output.nar_hash),
    }));
    dependencies.push(serde_json::json!({
        "uri": base_lib.store_path,
        "digest": provenance_digest_map(&base_lib.nar_hash),
    }));
    if let Some(documentation) = documentation {
        append_documentation_provenance_subject(
            &mut statement,
            name,
            version,
            platform,
            documentation,
        )?;
    }
    Ok((provenance, statement, attestation.clone()))
}

#[allow(clippy::too_many_arguments)]
async fn publish_config_provenance_artifact_inner(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    documentation: Option<&DocumentationArtifactMeta>,
    signer: &mut dyn ProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    let (path, statement, attestation) = unsigned_config_provenance_artifact(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        module,
        expose_manifest_digest,
        attestation,
        documentation,
        signer.key_id(),
    )?;
    let jsonl = sign_statement_dsse_jsonl_external(&statement, signer).await?;
    Ok(PublishProvenanceArtifact {
        path,
        jsonl,
        attestation,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(in crate::registry_ops) fn publish_config_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    signer: &LocalPackageProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    let (path, statement, attestation) = unsigned_config_provenance_artifact(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        module,
        expose_manifest_digest,
        attestation,
        None,
        &signer.key_id,
    )?;
    let jsonl = sign_statement_dsse_jsonl(&statement, &signer.key_id, &signer.key_path)?;
    Ok(PublishProvenanceArtifact {
        path,
        jsonl,
        attestation,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::registry_ops) async fn publish_config_provenance_artifact_with_documentation(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    documentation: &DocumentationArtifactMeta,
    signer: &mut dyn ProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    publish_config_provenance_artifact_inner(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        module,
        expose_manifest_digest,
        attestation,
        Some(documentation),
        signer,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(in crate::registry_ops) async fn publish_documentation_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    documentation: &DocumentationArtifactMeta,
    attestation: &AttestationMeta,
    signer: &mut dyn ProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    let provenance = attestation
        .provenance
        .clone()
        .context("documentation attestation is missing its provenance reference")?;
    let binding_digest = format!("sha256:{}", sha256_hex(b"aos.package-runtime-binding/v1"));
    let mut statement = publish_provenance_statement(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        &binding_digest,
        attestation,
        signer.key_id(),
    )?;
    append_documentation_provenance_subject(
        &mut statement,
        name,
        version,
        platform,
        documentation,
    )?;
    let jsonl = sign_statement_dsse_jsonl_external(&statement, signer).await?;
    Ok(PublishProvenanceArtifact {
        path: provenance,
        jsonl,
        attestation: attestation.clone(),
    })
}

fn append_documentation_provenance_subject(
    statement: &mut Value,
    name: &str,
    version: &str,
    platform: &str,
    documentation: &DocumentationArtifactMeta,
) -> Result<()> {
    let subjects = statement
        .get_mut("subject")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no subject array")?;
    subjects.push(serde_json::json!({
        "name": format!("aos:package-documentation:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&documentation.nar_hash),
    }));
    subjects.push(serde_json::json!({
        "name": format!("aos:package-document:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&documentation.document_sha256),
    }));
    subjects.push(serde_json::json!({
        "name": format!("aos:package-schema:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&documentation.semantic_schema_sha256),
    }));
    let dependencies = statement
        .pointer_mut("/predicate/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no resolvedDependencies array")?;
    dependencies.push(serde_json::json!({
        "uri": documentation.store_path,
        "digest": provenance_digest_map(&documentation.nar_hash),
    }));
    Ok(())
}

pub(in crate::registry_ops) fn resolve_package_provenance_signer(
    dir: &Path,
    registry_name: &str,
    signing_key: Option<&ResolvedSigningKey>,
    key_id: Option<&str>,
) -> Result<LocalPackageProvenanceSigner> {
    let key_id = key_id.context(
        "publishing privileged package provenance requires --key-id so the DSSE builder \
         identity is tied to keys.toml",
    )?;
    validate_roster_key_id(key_id)?;
    let signing_key = signing_key
        .context("publishing privileged package provenance requires a resolved signing key")?;
    let roster = load_committed_roster(dir)?;
    if keys::is_revoked(&roster, key_id) {
        bail!("provenance signing key id '{key_id}' is revoked in keys.toml");
    }
    let active = keys::active_key_by_id(&roster, key_id).ok_or_else(|| {
        anyhow::anyhow!("provenance signing key id '{key_id}' is not active in keys.toml")
    })?;
    let derived = derive_trust_key(registry_name, signing_key.path())?;
    if derived != active.key {
        bail!(
            "provenance signing key id '{key_id}' derives '{derived}', but keys.toml declares '{}'",
            active.key
        );
    }
    Ok(LocalPackageProvenanceSigner {
        key_id: key_id.to_string(),
        key_path: PathBuf::from(signing_key.path()),
    })
}

pub(in crate::registry_ops) fn validate_external_provenance_signer(
    dir: &Path,
    signer: &dyn ProvenanceSigner,
) -> Result<()> {
    let trusted_key = signer
        .trusted_key_line()
        .context("external provenance signer must expose its pinned roster trust line")?;
    require_active_registry_key(dir, signer.key_id(), trusted_key)
}

pub(crate) fn require_active_registry_key(
    dir: &Path,
    key_id: &str,
    trusted_key: &str,
) -> Result<()> {
    validate_roster_key_id(key_id)?;
    let roster = load_committed_roster(dir)?;
    if keys::is_revoked(&roster, key_id) {
        bail!("signing key id '{}' is revoked in keys.toml", key_id);
    }
    let active = keys::active_key_by_id(&roster, key_id)
        .ok_or_else(|| anyhow::anyhow!("signing key id '{}' is not active in keys.toml", key_id))?;
    if trusted_key != active.key {
        bail!(
            "external signing key for '{}' differs from keys.toml",
            key_id
        );
    }
    Ok(())
}

pub(in crate::registry_ops) fn package_provenance_trusted_keys(
    dir: &Path,
) -> Result<(String, Vec<TrustedProvenanceKey>)> {
    let registry_name = read_registry_toml(dir)?
        .map(|config| config.registry.name)
        .context("package provenance DSSE verification requires registry.toml [registry].name")?;
    let roster = load_committed_roster(dir)?;
    if roster.active.is_empty() {
        bail!("package provenance DSSE verification requires at least one active key in keys.toml");
    }
    let mut trusted = Vec::with_capacity(roster.active.len());
    for entry in &roster.active {
        if keys::is_revoked(&roster, &entry.id) {
            bail!(
                "package provenance DSSE key id '{}' is both active and revoked in keys.toml",
                entry.id
            );
        }
        let (entry_registry, _algorithm, _public_key) = parse_signing_key(&entry.key)
            .with_context(|| format!("invalid package provenance DSSE key id '{}'", entry.id))?;
        if entry_registry != registry_name {
            bail!(
                "package provenance DSSE key id '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry_name
            );
        }
        trusted.push(TrustedProvenanceKey {
            key_id: entry.id.clone(),
            key: entry.key.clone(),
            retired_before_sequence: None,
        });
    }
    for entry in &roster.revoked {
        let Some(key) = entry.key.as_ref() else {
            continue;
        };
        let retired_before_sequence = entry.provenance_before_sequence.with_context(|| {
            format!(
                "revoked package provenance DSSE key id '{}' declares key material without provenance-before-sequence",
                entry.id
            )
        })?;
        let (entry_registry, _algorithm, _public_key) =
            parse_signing_key(key).with_context(|| {
                format!(
                    "invalid revoked package provenance DSSE key id '{}'",
                    entry.id
                )
            })?;
        if entry_registry != registry_name {
            bail!(
                "revoked package provenance DSSE key id '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry_name
            );
        }
        trusted.push(TrustedProvenanceKey {
            key_id: entry.id.clone(),
            key: key.clone(),
            retired_before_sequence: Some(retired_before_sequence),
        });
    }
    Ok((registry_name, trusted))
}

pub(in crate::registry_ops) fn append_package_provenance_transparency_log(
    dir: &Path,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    artifact: &PublishProvenanceArtifact,
    provenance_file_path: &Path,
) -> Result<PathBuf> {
    let path = dir.join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG);
    ensure_package_provenance_transparency_log_extends_head(dir, &path)?;
    let (sequence, previous_entry_hash) = read_package_provenance_transparency_log_state(&path)?;
    let root_digest = artifact
        .attestation
        .root_digest
        .as_deref()
        .context("package transparency entry missing root_digest")?;
    let root_hash = artifact.attestation.root_hash.clone();
    let root_hash_sig = artifact.attestation.root_hash_sig.clone();
    if root_hash.is_some() != root_hash_sig.is_some() {
        bail!("package transparency entry root_hash and root_hash_sig must be declared together");
    }
    let provenance = artifact
        .attestation
        .provenance
        .as_deref()
        .context("package transparency entry missing provenance")?;
    if artifact.path != provenance {
        bail!(
            "package transparency entry provenance path mismatch: expected '{}', got '{}'",
            provenance,
            artifact.path
        );
    }
    let provenance_file_ref = registry_relative_path(dir, provenance_file_path)?;
    if provenance_file_ref != artifact.path {
        bail!(
            "package transparency entry provenance file mismatch: expected '{}', got '{}'",
            artifact.path,
            provenance_file_ref
        );
    }
    ensure_safe_package_provenance_statement_path(&provenance_file_ref)?;
    let provenance_file = fs::read(provenance_file_path).with_context(|| {
        format!(
            "reading provenance artifact {}",
            provenance_file_path.display()
        )
    })?;
    let measurement = artifact
        .attestation
        .measurement
        .as_deref()
        .context("package transparency entry missing measurement")?;
    let body = PackageProvenanceTransparencyLogBody {
        schema: PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA.to_string(),
        sequence,
        previous_entry_hash,
        package: name.to_string(),
        version: version.to_string(),
        platform: platform.to_string(),
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
        root_digest: Some(root_digest.to_string()),
        root_hash,
        root_hash_sig,
        provenance: provenance.to_string(),
        measurement: measurement.to_string(),
        source: source_info.map(|source| PackageProvenanceTransparencySource {
            store_path: source.path.clone(),
            nar_hash: source.nar_hash.clone(),
        }),
        statement: PackageProvenanceTransparencyStatement {
            path: artifact.path.clone(),
            jsonl_sha256: format!("sha256:{}", sha256_hex(&provenance_file)),
        },
    };

    if path.is_file() {
        let content =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let (_, _, entries) =
            parse_package_provenance_transparency_log(&content, &path.display().to_string())?;
        if let Some(existing) = entries
            .iter()
            .find(|entry| entry.body.provenance == body.provenance)
        {
            let mut expected = body.clone();
            expected.sequence = existing.body.sequence;
            expected.previous_entry_hash = existing.body.previous_entry_hash.clone();
            if existing.body == expected {
                return Ok(path);
            }
            bail!(
                "package transparency provenance '{}' is already bound to different publication metadata",
                body.provenance
            );
        }
    }

    let entry_hash = package_provenance_transparency_entry_hash(&body)?;
    let entry = PackageProvenanceTransparencyLogEntry { body, entry_hash };
    let parent = path
        .parent()
        .with_context(|| format!("transparency log path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let line =
        serde_json::to_string(&entry).context("serializing package transparency log entry")?;
    writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub(in crate::registry_ops) fn read_package_provenance_transparency_log_state(
    path: &Path,
) -> Result<(u64, Option<String>)> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, None));
        }
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    let (next_sequence, previous_entry_hash, _) =
        parse_package_provenance_transparency_log(&content, &path.display().to_string())?;
    Ok((next_sequence, previous_entry_hash))
}

pub(in crate::registry_ops) fn parse_package_provenance_transparency_log(
    content: &str,
    source: &str,
) -> Result<(
    u64,
    Option<String>,
    Vec<PackageProvenanceTransparencyLogEntry>,
)> {
    let mut next_sequence = 0u64;
    let mut previous_entry_hash: Option<String> = None;
    let mut entries = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: PackageProvenanceTransparencyLogEntry = serde_json::from_str(line)
            .with_context(|| {
                format!(
                    "deserializing package transparency log entry {} in {}",
                    line_index + 1,
                    source
                )
            })?;
        if entry.body.schema != PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA {
            bail!(
                "package transparency log entry {} has unsupported schema '{}'",
                line_index + 1,
                entry.body.schema
            );
        }
        if entry.body.sequence != next_sequence {
            bail!(
                "package transparency log entry {} sequence mismatch: expected {}, got {}",
                line_index + 1,
                next_sequence,
                entry.body.sequence
            );
        }
        if entry.body.previous_entry_hash != previous_entry_hash {
            bail!(
                "package transparency log entry {} previous hash mismatch",
                line_index + 1
            );
        }
        let expected_entry_hash = package_provenance_transparency_entry_hash(&entry.body)
            .with_context(|| {
                format!(
                    "hashing package transparency log entry {} in {}",
                    line_index + 1,
                    source
                )
            })?;
        if entry.entry_hash != expected_entry_hash {
            bail!(
                "package transparency log entry {} hash mismatch: expected '{}', got '{}'",
                line_index + 1,
                expected_entry_hash,
                entry.entry_hash
            );
        }
        previous_entry_hash = Some(entry.entry_hash.clone());
        next_sequence = next_sequence
            .checked_add(1)
            .context("package transparency log sequence overflow")?;
        entries.push(entry);
    }
    Ok((next_sequence, previous_entry_hash, entries))
}

fn ensure_package_provenance_transparency_log_extends_head(dir: &Path, path: &Path) -> Result<()> {
    let Some(head_log) = head_package_provenance_transparency_log(dir)? else {
        return Ok(());
    };
    let current = match fs::read(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    ensure_package_provenance_transparency_bytes_extend_head(
        dir,
        &current,
        &head_log,
        &path.display().to_string(),
    )
}

pub(in crate::registry_ops) fn ensure_package_provenance_transparency_bytes_extend_head(
    dir: &Path,
    current: &[u8],
    head_log: &[u8],
    source: &str,
) -> Result<()> {
    if !current.starts_with(head_log) {
        bail!(
            "package transparency log {source} does not extend committed HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}; restore the committed prefix before publishing"
        );
    }
    let head_text = std::str::from_utf8(head_log)
        .with_context(|| format!("decoding HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG} as UTF-8"))?;
    parse_package_provenance_transparency_log(
        head_text,
        &format!("HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}"),
    )
    .with_context(|| {
        format!(
            "validating HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG} in {}",
            dir.display()
        )
    })?;
    Ok(())
}

pub(in crate::registry_ops) fn head_package_provenance_transparency_log(
    dir: &Path,
) -> Result<Option<Vec<u8>>> {
    let (is_repo, _, _) = git_try(dir, &["rev-parse", "--is-inside-work-tree"])?;
    if !is_repo {
        return Ok(None);
    }
    let (has_head, _, _) = git_try(dir, &["rev-parse", "--verify", "HEAD"])?;
    if !has_head {
        return Ok(None);
    }
    git_tree_file_bytes(dir, "HEAD", PACKAGE_PROVENANCE_TRANSPARENCY_LOG)
}

fn publish_provenance_statement(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest_digest: &str,
    attestation: &AttestationMeta,
    key_id: &str,
) -> Result<serde_json::Value> {
    let root_digest = attestation
        .root_digest
        .as_deref()
        .context("package attestation root_digest missing")?;
    let measurement = attestation
        .measurement
        .as_deref()
        .context("package attestation measurement missing")?;
    let provenance = attestation
        .provenance
        .as_deref()
        .context("package attestation provenance missing")?;
    if attestation.root_hash.is_some() != attestation.root_hash_sig.is_some() {
        bail!("package attestation root_hash and root_hash_sig must be declared together");
    }
    let resolved_dependencies = source_info
        .into_iter()
        .map(|source| {
            serde_json::json!({
                "uri": format!("nix:{}", source.path.as_str()),
                "digest": provenance_digest_map(&source.nar_hash),
            })
        })
        .collect::<Vec<_>>();
    let mut external_parameters = serde_json::Map::new();
    external_parameters.insert("package".to_string(), serde_json::json!(name));
    external_parameters.insert("version".to_string(), serde_json::json!(version));
    external_parameters.insert("platform".to_string(), serde_json::json!(platform));
    external_parameters.insert(
        "store_path".to_string(),
        serde_json::json!(info.path.as_str()),
    );
    external_parameters.insert("root_digest".to_string(), serde_json::json!(root_digest));
    if let Some(root_hash) = attestation.root_hash.as_deref() {
        external_parameters.insert("root_hash".to_string(), serde_json::json!(root_hash));
    }
    if let Some(root_hash_sig) = attestation.root_hash_sig.as_deref() {
        external_parameters.insert(
            "root_hash_sig".to_string(),
            serde_json::json!(root_hash_sig),
        );
    }
    external_parameters.insert("provenance".to_string(), serde_json::json!(provenance));

    Ok(serde_json::json!({
        "_type": PACKAGE_PROVENANCE_STATEMENT_TYPE,
        "subject": [
            {
                "name": info.path.as_str(),
                "digest": provenance_digest_map(&info.nar_hash),
            },
            {
                "name": format!("aos:permissions-manifest:{name}:{version}:{platform}"),
                "digest": provenance_digest_map(manifest_digest),
            },
            {
                "name": format!("aos:package-measurement:{name}:{version}:{platform}"),
                "digest": provenance_digest_map(measurement),
            },
        ],
        "predicateType": PACKAGE_PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": PACKAGE_PROVENANCE_BUILD_TYPE,
                "externalParameters": external_parameters,
                "internalParameters": {},
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": provenance_builder_id(registry_name, key_id),
                },
                "metadata": {
                    "invocationId": format!("apr-publish:{name}:{version}:{platform}"),
                },
            },
        },
    }))
}

pub(in crate::registry_ops) fn publish_provenance_ref(
    name: &str,
    platform: &str,
    measurement: &str,
) -> Result<String> {
    validate_package_name(name)?;
    validate_platform_name(platform)?;
    let measurement_hex = sha256_hex_payload(measurement).with_context(|| {
        format!("package measurement must be a sha256 digest with 64 hex characters: {measurement}")
    })?;
    Ok(format!(
        "provenance/{}/{name}/{platform}/{measurement_hex}.intoto.jsonl",
        package_name_bucket(name)
    ))
}

pub(in crate::registry_ops) fn bind_documentation_provenance(
    mut attestation: AttestationMeta,
    name: &str,
    platform: &str,
    documentation: &DocumentationArtifactMeta,
) -> Result<AttestationMeta> {
    let measurement = attestation
        .measurement
        .as_deref()
        .context("documented attestation is missing its measurement")?;
    let measurement_hex = sha256_hex_payload(measurement).with_context(|| {
        format!("package measurement must be a sha256 digest with 64 hex characters: {measurement}")
    })?;
    let documentation_hex =
        sha256_hex_payload(&documentation_nar_identity(&documentation.nar_hash)?)
            .context("documentation NAR identity is not a canonical sha256 digest")?;

    validate_package_name(name)?;
    validate_platform_name(platform)?;
    attestation.provenance = Some(format!(
        "provenance/{}/{name}/{platform}/{measurement_hex}-{documentation_hex}.intoto.jsonl",
        package_name_bucket(name)
    ));
    validate_attestation_meta(&attestation)?;
    Ok(attestation)
}

#[cfg(test)]
mod tests;

pub(super) mod staged;

pub(super) mod statement;

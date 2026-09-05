//! Attestation metadata and content digests binding published artifacts.

use crate::provenance::sha256_hex_payload;
use crate::registry_ops::mac::PublishExposeManifest;
use crate::registry_ops::provenance::publish_provenance_ref;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::uki::sha256_hex;
use crate::types::{AttestationMeta, ConfigModuleMeta, validate_attestation_meta};
use anyhow::{Context, Result};

pub(in crate::registry_ops) fn publish_attestation_meta(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    manifest: &PublishExposeManifest,
    expose_manifest_digest: Option<&str>,
) -> Result<Option<AttestationMeta>> {
    let image = manifest
        .expose
        .images
        .iter()
        .find(|image| image.root_hash.is_some() || image.root_hash_sig.is_some());
    let manifest_digest = expose_manifest_digest
        .context("package root attestation requires an expose manifest digest")?;
    let root_hash = image
        .map(|image| {
            image
                .root_hash
                .clone()
                .context("verity package root image is missing root_hash")
        })
        .transpose()?;
    let root_hash_sig = image
        .map(|image| {
            image
                .root_hash_sig
                .clone()
                .context("verity package root image is missing root_hash_sig")
        })
        .transpose()?;
    let root_digest = root_hash
        .clone()
        .unwrap_or_else(|| package_nar_root_digest(&info.nar_hash));
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        manifest_digest,
    );
    let provenance = Some(publish_provenance_ref(name, platform, &measurement)?);
    let meta = AttestationMeta {
        root_digest: Some(root_digest),
        root_hash,
        root_hash_sig,
        provenance,
        measurement: Some(measurement),
    };
    validate_attestation_meta(&meta)?;
    Ok(Some(meta))
}

pub(in crate::registry_ops) fn publish_config_attestation_meta(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
) -> Result<AttestationMeta> {
    let root_digest = package_nar_root_digest(&info.nar_hash);
    let binding_digest = config_publish_binding_digest(module, expose_manifest_digest)?;
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        &binding_digest,
    );
    let meta = AttestationMeta {
        root_digest: Some(root_digest),
        root_hash: None,
        root_hash_sig: None,
        provenance: Some(publish_provenance_ref(name, platform, &measurement)?),
        measurement: Some(measurement),
    };
    validate_attestation_meta(&meta)?;
    Ok(meta)
}

pub(in crate::registry_ops) fn publish_documentation_attestation_meta(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
) -> Result<AttestationMeta> {
    let root_digest = package_nar_root_digest(&info.nar_hash);
    let binding_digest = format!("sha256:{}", sha256_hex(b"aos.package-runtime-binding/v1"));
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        &binding_digest,
    );
    let meta = AttestationMeta {
        root_digest: Some(root_digest),
        root_hash: None,
        root_hash_sig: None,
        provenance: Some(publish_provenance_ref(name, platform, &measurement)?),
        measurement: Some(measurement),
    };
    validate_attestation_meta(&meta)?;
    Ok(meta)
}

pub(in crate::registry_ops) fn config_publish_binding_digest(
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
) -> Result<String> {
    crate::package_attestation::config_module_binding_digest(module, expose_manifest_digest)
}

pub(in crate::registry_ops) fn package_nar_root_digest(nar_hash: &str) -> String {
    if let Some(hex) = sha256_hex_payload(nar_hash) {
        format!("sha256:{hex}")
    } else {
        format!("sha256:{}", sha256_hex(nar_hash.as_bytes()))
    }
}

/// Returns the canonical hexadecimal identity of the NAR bytes themselves.
pub(in crate::registry_ops) fn documentation_nar_identity(nar_hash: &str) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        aos_registry_surface::store::canonical_digest_hex(nar_hash)?
    ))
}

#[cfg(test)]
mod tests;

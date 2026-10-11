//! Exact JSON reads from authenticated native artifact roots.
//!
//! Callers admit and realize the signed NAR before opening its JSON document.
//! This reader checks the catalog's byte identity and rejects symlink files.

use std::path::Path;

use anyhow::{Result, ensure};
use aos_contract::Sha256Digest;

use crate::deployment::model::Envelope;
use crate::types::NativeArtifactMeta;

/// Reads a native envelope from a realized, authenticated release artifact.
///
/// # Errors
/// Returns an error for invalid locators, missing files, byte identity drift,
/// malformed envelopes, or mismatched release coordinates.
pub fn read_envelope(
    artifact: &NativeArtifactMeta,
    package: &str,
    version: &str,
    platform: &str,
) -> Result<Envelope> {
    let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    read_envelope_in(
        artifact,
        package,
        version,
        platform,
        &executable,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )
}

/// Reads an authenticated envelope using the caller's explicit store executable.
///
/// # Errors
/// Returns an error for store failures, invalid document identities, malformed
/// envelopes, or mismatched authenticated coordinates.
pub fn read_envelope_in(
    artifact: &NativeArtifactMeta,
    package: &str,
    version: &str,
    platform: &str,
    executable: &Path,
    cancellation: &aos_ability_runtime::adapter::CancellationToken,
) -> Result<Envelope> {
    let bytes = read_document_in(artifact, "deployment.json", executable, cancellation)?;
    let envelope = Envelope::decode(&bytes)?;
    ensure!(
        envelope.package.name == package
            && envelope.package.version == version
            && envelope.system == platform,
        "native envelope differs from its authenticated package coordinate"
    );
    Ok(envelope)
}

/// Reads the closed qualification recipe from an authenticated native artifact.
///
/// # Errors
/// Returns an error for byte drift, malformed recipes, owning coordinate mismatch,
/// or payload bindings absent from the signed artifact reference edges.
pub fn read_qualification(
    artifact: &NativeArtifactMeta,
    package: &str,
    version: &str,
) -> Result<aos_release::qualification_document::QualificationDocument> {
    let bytes = read_document(artifact, "qualification.json")?;
    let document = aos_release::qualification_document::QualificationDocument::decode(
        &bytes, package, version,
    )?;
    for binding in document.artifacts() {
        ensure!(
            artifact
                .references
                .contains(&crate::registry::store_path_hash(&binding.path).to_owned()),
            "qualification binding is absent from authenticated artifact references"
        );
    }
    Ok(document)
}

/// Reads an exact document within a previously authenticated native artifact root.
///
/// # Errors
/// Returns an error when the locator is invalid, the requested filename is not
/// a supported native document, or the JSON file's size or digest differs.
pub fn read_document(artifact: &NativeArtifactMeta, filename: &str) -> Result<Vec<u8>> {
    let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    read_document_in(
        artifact,
        filename,
        &executable,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )
}

/// Reads exact companion bytes using the caller's explicit store executable.
///
/// # Errors
/// Returns an error for unsupported filenames, malformed locators, store errors,
/// symlinks, nonregular or executable documents, and byte identity drift.
pub fn read_document_in(
    artifact: &NativeArtifactMeta,
    filename: &str,
    executable: &Path,
    cancellation: &aos_ability_runtime::adapter::CancellationToken,
) -> Result<Vec<u8>> {
    artifact.validate()?;
    ensure!(
        matches!(
            filename,
            "deployment.json" | "options.json" | "qualification.json"
        ),
        "unsupported native artifact filename"
    );
    let path = Path::new(&artifact.store_path).join(filename);
    let bytes =
        crate::native_deployment::read_regular_store_document_in(&path, executable, cancellation)?;
    validate_document_bytes(artifact, &bytes)?;
    Ok(bytes)
}

/// Checks exact document bytes against authenticated companion metadata.
///
/// # Errors
/// Returns an error when the document size or SHA-256 binding differs.
pub(crate) fn validate_document_bytes(artifact: &NativeArtifactMeta, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 == artifact.document_size
            && Sha256Digest::of_bytes(bytes).to_string() == artifact.document_sha256,
        "native artifact document byte identity differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_binding_rejects_same_size_drift_and_size_mismatch() {
        let bytes = b"{}";
        let artifact = NativeArtifactMeta {
            store_path: format!("/nix/store/{}-documentation", "a".repeat(32)),
            nar_hash: format!("sha256:{}", "1".repeat(64)),
            nar_size: 128,
            references: Vec::new(),
            document_sha256: Sha256Digest::of_bytes(bytes).to_string(),
            document_size: bytes.len() as u64,
        };
        validate_document_bytes(&artifact, bytes).unwrap();
        assert!(validate_document_bytes(&artifact, b"[]").is_err());
        assert!(validate_document_bytes(&artifact, b"{} ").is_err());
        assert!(
            read_document_in(
                &artifact,
                "../options.json",
                Path::new("/nix/store/pinned/bin/nix-store"),
                &aos_ability_runtime::adapter::CancellationToken::default()
            )
            .is_err()
        );
    }
}

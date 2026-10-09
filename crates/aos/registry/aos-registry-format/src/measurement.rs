//! Stable package measurement identities shared by registry authoring and TPM verification.
//!
//! ```text
//! aos-package-v1|name=<length>:<name>|version=<length>:<version>|root-digest=<length>:<digest>|manifest-digest=<length>:<digest>
//! ```

use anyhow::Result;
use sha2::{Digest, Sha256};



/// Commits to the exact native companions used in a package measurement.
///
/// # Errors
/// Rejects invalid native locators or failed canonical document encoding.
pub fn native_package_binding_digest(
    deployment: &crate::manifest::NativeArtifactMeta,
    documentation: Option<&crate::manifest::NativeArtifactMeta>,
    qualification: Option<&crate::manifest::NativeArtifactMeta>,
) -> Result<String> {
    deployment.validate()?;
    for companion in [documentation, qualification].into_iter().flatten() {
        companion.validate()?;
    }
    if documentation.is_none() && qualification.is_none() {
        return Ok(deployment.document_sha256.clone());
    }

    // Optional authenticated companions participate in the package identity;
    // their locators retain exact NAR and document commitments independently.
    let canonical = aos_core::json::to_vec(&serde_json::json!({
        "deployment": deployment,
        "documentation": documentation,
        "qualification": qualification,
    }))?;
    Ok(aos_core::Sha256Digest::of_bytes(&canonical).to_string())
}

/// Returns the RFC-0001 package measurement tuple digest.
#[must_use]
pub fn package_measurement_digest(name: &str, version: &str, root_digest: &str, manifest_digest: &str) -> String {
 fn canonical(value: &str) -> String {
  let value = value.trim();
  if let Some(digest) = value.strip_prefix("sha256:").or_else(|| value.strip_prefix("sha256-"))
   && digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    return format!("sha256:{}", digest.to_ascii_lowercase());
  }
  value.to_owned()
 }
 let root = canonical(root_digest);
 let manifest = canonical(manifest_digest);
 let mut word = String::from("aos-package-v1");
 for (field, value) in [("name",name),("version",version),("root-digest",root.as_str()),("manifest-digest",manifest.as_str())] {
  word.push_str(&format!("|{field}={}:{}", value.len(), value));
 }
 format!("sha256:{}", hex::encode(Sha256::digest(word.as_bytes())))
}
/// Returns the manifest digest format used in package measurement events.
#[must_use]
pub fn package_manifest_digest_bytes(bytes: &[u8]) -> String {
 format!("sha256:{}",hex::encode(Sha256::digest(bytes)))
}

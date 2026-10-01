//! Bounded narinfo index and signing projections produced beside object bytes.
//!
//! The original file's SHA/size remain distinct from this parsed projection.
//! Unknown textual fields stay in storage, not in the Native completion body.

use anyhow::{bail, Context as _, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Largest encoded narinfo projection admitted by Native ingress.
// Reserves space for the enclosing 64 KiB cache admission JSON fields.
pub const MAX_HYBRID_NARINFO_PROJECTION_BYTES: usize = 60 * 1024;
const MAX_REFERENCES: usize = 1024;
const MAX_SIGNATURES: usize = 16;
const MAX_FIELD_BYTES: usize = 1024;

/// One Nix signature over the original parsed fingerprint fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridNarinfoSignature {
    /// Exact signing-key name.
    pub key_name: String,
    /// Canonical padded base64 Ed25519 signature.
    pub signature: String,
}

/// Parsed narinfo metadata bound to one exact original object digest and size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridNarinfoProjection {
    /// Protocol format, currently one.
    pub version: u32,
    /// SHA-256 of the original file, not of this projection's serialization.
    pub source_sha256: String,
    /// Original narinfo length within the existing file-size bound.
    pub source_size: u32,
    /// Absolute store path covered by the Nix signature.
    pub store_path: String,
    /// NarHash field covered by the Nix signature.
    pub nar_hash: String,
    /// Lossless canonical decimal uncompressed size covered by the signature.
    pub nar_size: String,
    /// Ordered absolute store references covered by the Nix signature.
    pub references: Vec<String>,
    /// Original signature fields, without the whole narinfo text.
    pub signatures: Vec<HybridNarinfoSignature>,
    /// Canonical cache-relative NAR delivery path needed by the index.
    pub nar_url: String,
    /// Compressed-file hash needed by the index.
    pub file_hash: String,
    /// Lossless canonical decimal compressed-file size.
    pub file_size: String,
    /// Declared compression format.
    pub compression: String,
    /// Optional derivation store basename.
    pub deriver: Option<String>,
    /// Optional content-addressed store metadata.
    pub content_address: Option<String>,
}

impl HybridNarinfoProjection {
    /// Parses signing and index fields beside an exact retained narinfo file.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized/non-UTF8 body, duplicate recognized
    /// fields, missing required fields, noncanonical counters or excessive
    /// metadata. Standalone narinfo parsing retains its existing behavior.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > crate::fetch::MAX_CACHE_NARINFO_BYTES {
            bail!("narinfo source exceeds its bounded file size");
        }
        let text = std::str::from_utf8(bytes).context("narinfo source is not UTF-8")?;
        let mut fields = std::collections::BTreeMap::new();
        let mut signatures = Vec::new();
        for line in text.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name == "Sig" {
                let (key_name, signature) = value
                    .split_once(':')
                    .context("narinfo signature field is malformed")?;
                signatures.push(HybridNarinfoSignature {
                    key_name: key_name.to_owned(),
                    signature: signature.to_owned(),
                });
            } else if matches!(
                name,
                "StorePath"
                    | "NarHash"
                    | "NarSize"
                    | "References"
                    | "URL"
                    | "FileHash"
                    | "FileSize"
                    | "Compression"
                    | "Deriver"
                    | "CA"
            ) && fields.insert(name, value).is_some()
            {
                bail!("narinfo has a duplicate recognized field");
            }
        }
        let required = |name| {
            fields
                .get(name)
                .copied()
                .with_context(|| format!("narinfo omitted {name}"))
        };
        let store_path = required("StorePath")?.to_owned();
        let store_dir = store_path
            .rsplit_once('/')
            .map(|(dir, _)| dir)
            .context("narinfo store path is not absolute")?;
        let references = fields
            .get("References")
            .copied()
            .unwrap_or_default()
            .split_whitespace()
            .map(|reference| {
                if reference.starts_with('/') {
                    reference.to_owned()
                } else {
                    format!("{store_dir}/{reference}")
                }
            })
            .collect();
        let result = Self {
            version: 1,
            source_sha256: super::super::body_sha256(bytes),
            source_size: u32::try_from(bytes.len()).context("narinfo source size overflows")?,
            store_path,
            nar_hash: required("NarHash")?.to_owned(),
            nar_size: required("NarSize")?.to_owned(),
            references,
            signatures,
            nar_url: required("URL")?.to_owned(),
            file_hash: fields
                .get("FileHash")
                .copied()
                .unwrap_or_default()
                .to_owned(),
            file_size: fields.get("FileSize").copied().unwrap_or("0").to_owned(),
            compression: fields
                .get("Compression")
                .copied()
                .filter(|value| !value.is_empty())
                .unwrap_or("none")
                .to_owned(),
            deriver: fields
                .get("Deriver")
                .copied()
                .filter(|value| !value.is_empty() && *value != "unknown-deriver")
                .map(str::to_owned),
            content_address: fields
                .get("CA")
                .copied()
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        };
        result.validate()?;
        Ok(result)
    }

    /// Correlates parsed store identity with the exact admitted cache object path.
    ///
    /// The original source SHA remains independent of the store-path hash. A
    /// valid signature for another store object does not authorize this key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid projection fields or a mismatched narinfo key.
    pub fn validate_cache_path(&self, path: &str) -> Result<()> {
        self.validate()?;
        let basename = self.store_path.rsplit('/').next().unwrap_or_default();
        let (store_hash, name) = basename
            .split_once('-')
            .context("narinfo store basename has no name")?;
        if store_hash.is_empty() || name.is_empty() || path != format!("{store_hash}.narinfo") {
            bail!("narinfo projection does not match its admitted cache path");
        }
        Ok(())
    }

    /// Validates a received closed projection without reading the source file.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed source identity, oversized metadata,
    /// invalid paths/signatures or noncanonical decimal counters.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.source_size == 0
            || self.source_size as usize > crate::fetch::MAX_CACHE_NARINFO_BYTES
            || !super::valid_sha256(&self.source_sha256)
            || self.references.len() > MAX_REFERENCES
            || self.signatures.len() > MAX_SIGNATURES
        {
            bail!("narinfo projection identity or count is invalid");
        }
        decimal(&self.nar_size)?;
        decimal(&self.file_size)?;
        for field in [
            &self.store_path,
            &self.nar_hash,
            &self.nar_url,
            &self.file_hash,
            &self.compression,
        ]
        .into_iter()
        .chain(self.references.iter())
        .chain(self.deriver.iter())
        .chain(self.content_address.iter())
        {
            if field.len() > MAX_FIELD_BYTES || field.bytes().any(|byte| byte.is_ascii_control()) {
                bail!("narinfo projection field is invalid");
            }
        }
        if self.nar_hash.is_empty()
            || self
                .nar_hash
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b';')
            || !canonical_signature_path(&self.store_path)
            || self
                .references
                .iter()
                .any(|reference| !canonical_signature_path(reference))
        {
            bail!("narinfo projection signature paths must be absolute");
        }
        if !self.nar_url.starts_with("nar/")
            || !crate::keymap::is_machine_path(&self.nar_url)
            || crate::url_guard::validate_http_surface_path(&self.nar_url).is_err()
        {
            bail!("narinfo projection URL is not an admitted cache-relative NAR path");
        }
        for signature in &self.signatures {
            if signature.key_name.is_empty()
                || signature.key_name.len() > 128
                || signature
                    .key_name
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b':')
                || signature.signature.len() != 88
            {
                bail!("narinfo projection signature is malformed");
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&signature.signature)
                .context("narinfo signature is not base64")?;
            if bytes.len() != 64
                || base64::engine::general_purpose::STANDARD.encode(&bytes) != signature.signature
            {
                bail!("narinfo signature is not canonical Ed25519 base64");
            }
        }
        if serde_json::to_vec(self)?.len() > MAX_HYBRID_NARINFO_PROJECTION_BYTES {
            bail!("narinfo projection exceeds its encoded control bound");
        }
        Ok(())
    }

    /// Verifies the exact configured public key over the Nix fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed projection/key, an absent selected
    /// signature or failed Ed25519 verification.
    pub fn verify_selected_key(&self, key_name: &str, public_key: &str) -> Result<()> {
        self.validate()?;
        let signature = self
            .signatures
            .iter()
            .find(|signature| signature.key_name == key_name)
            .context("narinfo projection omitted the selected key")?;
        let public_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(public_key)
            .context("narinfo public key is not base64")?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("narinfo public key is not 32 bytes"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)?;
        let signature = base64::engine::general_purpose::STANDARD.decode(&signature.signature)?;
        let signature = ed25519_dalek::Signature::from_slice(&signature)?;
        let fingerprint = crate::nix_sign::fingerprint(
            &self.store_path,
            &self.nar_hash,
            decimal(&self.nar_size)?,
            &self.references,
        );
        use ed25519_dalek::Verifier as _;
        key.verify(fingerprint.as_bytes(), &signature)
            .context("narinfo projection signature failed")
    }
}

fn decimal(value: &str) -> Result<i64> {
    let parsed = value
        .parse::<i64>()
        .context("narinfo size is not an integer")?;
    if parsed < 0 || parsed.to_string() != value {
        bail!("narinfo size is not canonical nonnegative decimal");
    }
    Ok(parsed)
}

// Nix's fingerprint uses semicolons and comma-separated references. Paths
// containing those delimiters or whitespace cannot be represented unambiguously.
fn canonical_signature_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.ends_with('/')
        && !path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b';' | b','))
        && path[1..]
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine;

use super::info::{self, NarInfo, PathInfoParams, basename, store_hash};

/// Compression setting used in Nix narinfo output and NAR file naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarCompression {
    None,
    Zstd,
    Xz,
}

impl NarCompression {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Xz => "xz",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::None => "nar",
            Self::Zstd => "nar.zst",
            Self::Xz => "nar.xz",
        }
    }
}

/// Input for rendering one static Nix binary-cache narinfo file.
pub struct StaticNarInfoInput<'a> {
    pub store_path: &'a str,
    pub nar_hash: &'a str,
    pub nar_size: u64,
    pub references: &'a [String],
    pub deriver: Option<&'a str>,
    pub signatures: &'a [String],
    pub file_hash: &'a str,
    pub file_size: u64,
    pub compression: NarCompression,
}

/// Optional narinfo signer using a Nix Ed25519 secret key file.
pub struct NarInfoSigner {
    key_data: Option<(String, Vec<u8>)>,
}

impl NarInfoSigner {
    /// Load the signing key from a `name:base64-secret` file, or return a
    /// no-op signer when `key_file` is `None`.
    pub fn load(key_file: Option<&Path>) -> Result<Self> {
        let key_data = match key_file {
            Some(path) => {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("reading signing key from {}", path.display()))?;
                Some(parse_key_data(content.trim())?)
            }
            None => None,
        };
        Ok(Self { key_data })
    }

    /// Build a signer directly from `name:base64-secret` content.
    pub fn from_key_content(content: &str) -> Result<Self> {
        Ok(Self {
            key_data: Some(parse_key_data(content.trim())?),
        })
    }

    pub fn key_name(&self) -> Option<&str> {
        self.key_data.as_ref().map(|(name, _)| name.as_str())
    }

    pub fn is_configured(&self) -> bool {
        self.key_data.is_some()
    }

    /// Sign a narinfo fingerprint. Returns `name:base64_sig` or `None` if this
    /// signer is intentionally unconfigured.
    pub fn sign(&self, fingerprint: &str) -> Option<String> {
        let (name, secret) = self.key_data.as_ref()?;
        let key_bytes: [u8; 32] = secret.get(..32)?.try_into().ok()?;
        use ed25519_dalek::Signer as _;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(fingerprint.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        Some(format!("{name}:{sig_b64}"))
    }

    /// Compute the Nix narinfo fingerprint for signing.
    pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
        let refs_str = refs.join(",");
        format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
    }
}

fn parse_key_data(content: &str) -> Result<(String, Vec<u8>)> {
    let (name, b64) = content
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("signing key must be name:base64"))?;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("decoding signing key base64")?;
    if secret.len() < 32 {
        bail!("signing key secret must contain at least 32 bytes");
    }
    Ok((name.to_string(), secret))
}

/// Build the relative `URL:` path for a static NAR.
pub fn nar_url(store_path: &str, nar_hash: &str, compression: NarCompression) -> String {
    format!(
        "nar/{}-{}.{}",
        store_hash(store_path),
        hash_path_fragment(nar_hash),
        compression.extension(),
    )
}

/// Convert a hash string into one filesystem- and URL-path-safe segment.
pub fn hash_path_fragment(hash: &str) -> String {
    hash.chars()
        .map(|ch| match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => ch,
            ':' => '-',
            _ => '_',
        })
        .collect()
}

/// Render one static narinfo body.
pub fn render_static_narinfo(
    input: &StaticNarInfoInput<'_>,
    store_dir: &str,
    signer: Option<&NarInfoSigner>,
) -> String {
    let store_path = format!("{store_dir}/{}", basename(input.store_path));
    let references: Vec<String> = input
        .references
        .iter()
        .map(|reference| basename(reference).to_string())
        .collect();
    let deriver = input.deriver.map(basename);
    let url = nar_url(input.store_path, input.nar_hash, input.compression);

    let mut signatures = input.signatures.to_vec();
    if let Some(signer) = signer {
        let fingerprint = NarInfoSigner::fingerprint(
            &store_path,
            input.nar_hash,
            input.nar_size as i64,
            &references,
        );
        if let Some(signature) = signer.sign(&fingerprint) {
            signatures.push(signature);
        }
    }

    let info = info::from_path_info(&PathInfoParams {
        path: &store_path,
        nar_hash: input.nar_hash,
        nar_size: input.nar_size,
        references: &references,
        deriver,
        signatures: &signatures,
        file_hash: input.file_hash,
        file_size: input.file_size,
        compression: input.compression.name(),
        nar_url: &url,
    });
    info::format(&info)
}

/// Build a `NarInfo` value for callers that need structured data.
pub fn static_narinfo(
    input: &StaticNarInfoInput<'_>,
    store_dir: &str,
    signer: Option<&NarInfoSigner>,
) -> NarInfo {
    info::parse(&render_static_narinfo(input, store_dir, signer))
        .expect("rendered static narinfo is parseable")
}

/// Render a stock Nix `nix-cache-info` file body.
pub fn nix_cache_info(store_dir: &str, priority: u32) -> String {
    format!("StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: {priority}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_signer() -> NarInfoSigner {
        let mut key = [0u8; 64];
        key[0] = 1;
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        NarInfoSigner::from_key_content(&format!("cache:{encoded}")).unwrap()
    }

    #[test]
    fn nar_url_uses_store_hash_and_nar_hash() {
        assert_eq!(
            nar_url(
                "/nix/store/abc123-hello",
                "sha256:def456",
                NarCompression::Zstd
            ),
            "nar/abc123-sha256-def456.nar.zst"
        );
    }

    #[test]
    fn nar_url_escapes_sri_hash_path_separators() {
        assert_eq!(
            nar_url(
                "/nix/store/abc123-hello",
                "sha256-/zAxVUL1gFIy9KJWVLMtN8dFXaIq11tx+2AucyOskko=",
                NarCompression::Zstd,
            ),
            "nar/abc123-sha256-_zAxVUL1gFIy9KJWVLMtN8dFXaIq11tx_2AucyOskko_.nar.zst"
        );
    }

    #[test]
    fn render_static_narinfo_round_trips_and_signs() {
        let refs = vec!["/nix/store/ref111-libc".to_string()];
        let input = StaticNarInfoInput {
            store_path: "/nix/store/abc123-hello",
            nar_hash: "sha256:def456",
            nar_size: 42,
            references: &refs,
            deriver: Some("/nix/store/drv111-hello.drv"),
            signatures: &[],
            file_hash: "sha256:file789",
            file_size: 24,
            compression: NarCompression::Zstd,
        };

        let text = render_static_narinfo(&input, "/nix/store", Some(&test_signer()));
        let parsed = info::parse(&text).unwrap();

        assert_eq!(parsed.store_path, "/nix/store/abc123-hello");
        assert_eq!(parsed.url, "nar/abc123-sha256-def456.nar.zst");
        assert_eq!(parsed.compression, "zstd");
        assert_eq!(parsed.file_hash.as_deref(), Some("sha256:file789"));
        assert_eq!(parsed.file_size, Some(24));
        assert_eq!(parsed.references, vec!["ref111-libc"]);
        assert_eq!(parsed.deriver.as_deref(), Some("drv111-hello.drv"));
        assert_eq!(parsed.signatures.len(), 1);
        assert!(parsed.signatures[0].starts_with("cache:"));
    }

    #[test]
    fn static_narinfo_signature_uses_stock_nix_fingerprint() {
        let refs = vec!["/nix/store/ref111-libc".to_string()];
        let input = StaticNarInfoInput {
            store_path: "/nix/store/abc123-hello",
            nar_hash: "sha256:def456",
            nar_size: 42,
            references: &refs,
            deriver: None,
            signatures: &[],
            file_hash: "sha256:file789",
            file_size: 24,
            compression: NarCompression::Zstd,
        };

        let text = render_static_narinfo(&input, "/nix/store", Some(&test_signer()));
        let parsed = info::parse(&text).unwrap();
        let (_, sig_b64) = parsed.signatures[0].split_once(':').unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let signature = ed25519_dalek::Signature::try_from(sig_bytes.as_slice()).unwrap();

        let mut key = [0u8; 32];
        key[0] = 1;
        let verifying_key = ed25519_dalek::SigningKey::from_bytes(&key).verifying_key();
        let fingerprint = NarInfoSigner::fingerprint(
            &parsed.store_path,
            &parsed.nar_hash,
            parsed.nar_size as i64,
            &parsed.references,
        );
        use ed25519_dalek::Verifier as _;
        verifying_key
            .verify(fingerprint.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn nix_cache_info_body() {
        assert_eq!(
            nix_cache_info("/nix/store", 30),
            "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n"
        );
    }
}

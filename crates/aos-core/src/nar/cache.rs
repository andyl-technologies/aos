//! Static Nix binary-cache layout: NAR URLs, narinfo rendering, and
//! Ed25519 narinfo signing.
//!
//! A static binary cache is just a directory (or HTTP prefix) holding a
//! `nix-cache-info` file, one `<hash>.narinfo` per store path, and the
//! NAR files under `nar/`. This module produces all three artifacts:
//!
//! - [`nar_url`] / [`hash_path_fragment`] compute the cache-relative
//!   NAR file name for a store path.
//! - [`render_static_narinfo`] / [`static_narinfo`] turn a
//!   [`StaticNarInfoInput`] into a narinfo body, optionally signed.
//! - [`NarInfoSigner`] signs narinfo fingerprints with a Nix-style
//!   `name:base64-secret` Ed25519 key, compatible with stock Nix's
//!   `nix-store --generate-binary-cache-key` output and signature
//!   verification (including Nix's base32 hash encoding).
//! - [`nix_cache_info`] renders the `nix-cache-info` body.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use base64::Engine;

use super::info::{self, NarInfo, PathInfoParams, basename, store_hash};

/// Compression setting used in Nix narinfo output and NAR file naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarCompression {
    /// Uncompressed NAR (`Compression: none`, `.nar`).
    None,
    /// Zstandard-compressed NAR (`Compression: zstd`, `.nar.zst`).
    Zstd,
    /// XZ-compressed NAR (`Compression: xz`, `.nar.xz`).
    Xz,
}

impl NarCompression {
    /// Returns the value used in the narinfo `Compression:` field.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Xz => "xz",
        }
    }

    /// Returns the file extension (without a leading dot) for NAR files
    /// with this compression.
    pub fn extension(self) -> &'static str {
        match self {
            Self::None => "nar",
            Self::Zstd => "nar.zst",
            Self::Xz => "nar.xz",
        }
    }
}

/// Input for rendering one static Nix binary-cache narinfo file.
///
/// `store_path`, `references`, and `deriver` may be full store paths;
/// rendering re-roots them under the target cache's store dir (for the
/// `StorePath:` field and signing fingerprint) or reduces them to
/// basenames (for `References:` and `Deriver:`).
pub struct StaticNarInfoInput<'a> {
    /// The store path being published.
    pub store_path: &'a str,
    /// Hash of the uncompressed NAR.
    pub nar_hash: &'a str,
    /// Size in bytes of the uncompressed NAR.
    pub nar_size: u64,
    /// Store paths referenced by `store_path`.
    pub references: &'a [String],
    /// The deriver `.drv` path, if known.
    pub deriver: Option<&'a str>,
    /// Pre-existing signatures to carry over verbatim.
    pub signatures: &'a [String],
    /// Hash of the compressed NAR file as stored in the cache.
    pub file_hash: &'a str,
    /// Size in bytes of the compressed NAR file.
    pub file_size: u64,
    /// Compression applied to the stored NAR file.
    pub compression: NarCompression,
}

/// Optional narinfo signer using a Nix Ed25519 secret key file.
///
/// A signer may be deliberately unconfigured (no key), in which case
/// [`sign`](Self::sign) returns `None` and rendering proceeds without
/// adding a signature. Keys use Nix's `name:base64-secret` format, as
/// produced by `nix-store --generate-binary-cache-key`.
pub struct NarInfoSigner {
    key_data: Option<(String, Vec<u8>)>,
}

impl NarInfoSigner {
    /// Loads the signing key from a `name:base64-secret` file, or returns a
    /// no-op signer when `key_file` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, is not in
    /// `name:base64` form, contains invalid base64, or decodes to fewer
    /// than 32 bytes of secret material.
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

    /// Builds a signer directly from `name:base64-secret` content.
    ///
    /// # Errors
    ///
    /// Returns an error if the content is not in `name:base64` form,
    /// contains invalid base64, or decodes to fewer than 32 bytes of
    /// secret material.
    pub fn from_key_content(content: &str) -> Result<Self> {
        Ok(Self {
            key_data: Some(parse_key_data(content.trim())?),
        })
    }

    /// Returns the key name (the part before `:` in the key file), or
    /// `None` when the signer is unconfigured.
    pub fn key_name(&self) -> Option<&str> {
        self.key_data.as_ref().map(|(name, _)| name.as_str())
    }

    /// Returns `true` if a signing key is loaded.
    pub fn is_configured(&self) -> bool {
        self.key_data.is_some()
    }

    /// Signs a narinfo fingerprint. Returns `name:base64_sig` or `None` if this
    /// signer is intentionally unconfigured.
    ///
    /// The first 32 bytes of the secret are used as the Ed25519 seed,
    /// matching Nix's 64-byte (seed + public key) key files.
    pub fn sign(&self, fingerprint: &str) -> Option<String> {
        let (name, secret) = self.key_data.as_ref()?;
        let key_bytes: [u8; 32] = secret.get(..32)?.try_into().ok()?;
        use ed25519_dalek::Signer as _;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(fingerprint.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        Some(format!("{name}:{sig_b64}"))
    }

    /// Computes the Nix narinfo fingerprint for signing:
    /// `1;<store_path>;<nar_hash>;<nar_size>;<refs,comma,separated>`.
    ///
    /// `refs` must be full store paths. The NAR hash is normalised to
    /// Nix's base32 `sha256:` form (see `normalize_sha256_nix32`) so
    /// the signature verifies against stock Nix regardless of whether
    /// the caller holds an SRI, hex, or base32 hash.
    pub fn fingerprint(store_path: &str, nar_hash: &str, nar_size: i64, refs: &[String]) -> String {
        let refs_str = refs.join(",");
        let nar_hash = normalize_sha256_nix32(nar_hash);
        format!("1;{store_path};{nar_hash};{nar_size};{refs_str}")
    }
}

/// Nix's custom base32 alphabet (omits `e`, `o`, `t`, `u`).
const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Normalises a SHA-256 NAR hash to Nix's base32 `sha256:` form.
///
/// Accepts SRI (`sha256-<base64>`), hex (`sha256:<64 hex digits>`), or
/// already-base32 (`sha256:<base32>`) input; anything unrecognised is
/// returned unchanged so callers (signing fingerprints, `store/` graph
/// comparisons) degrade gracefully rather than failing.
pub fn normalize_sha256_nix32(hash: &str) -> String {
    if let Some(encoded) = hash.strip_prefix("sha256-") {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded)
            && bytes.len() == 32
        {
            return format!("sha256:{}", encode_nix_base32(&bytes));
        }
        return hash.to_string();
    }

    let Some(encoded) = hash.strip_prefix("sha256:") else {
        return hash.to_string();
    };
    if encoded.len() == 64
        && encoded
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
        && let Ok(bytes) = hex::decode(encoded)
        && bytes.len() == 32
    {
        return format!("sha256:{}", encode_nix_base32(&bytes));
    }
    hash.to_string()
}

/// Decodes Nix's base32 variant (the inverse of [`encode_nix_base32`]).
///
/// Returns `None` for characters outside the Nix alphabet, for an
/// encoding whose spare high bits are non-zero (which no valid Nix
/// encoder produces), or for a length that does not round-trip a whole
/// number of bytes (e.g. lengths `1, 3, 6, …` where the top digit would
/// have no byte to land in). The output length is `len * 5 / 8` bytes -
/// pass a 52-char digest to get the 32 bytes of a SHA-256.
///
/// Never panics: every buffer index is bounds-checked rather than indexed
/// directly, so a malformed or wrong-length input fails with `None`.
pub fn decode_nix_base32(encoded: &str) -> Option<Vec<u8>> {
    let len = encoded.len() * 5 / 8;
    let mut out = vec![0u8; len];

    for (n, ch) in encoded.chars().rev().enumerate() {
        let digit = NIX_BASE32.iter().position(|&b| b as char == ch)? as u16;
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        // The lowest 8-j bits land in byte i; the rest carry into i+1.
        // A digit whose low bits have no byte (i >= len) is an invalid
        // length, not a valid encoding.
        *out.get_mut(i)? |= (digit << j) as u8;
        let carry = digit >> (8 - j);
        match out.get_mut(i + 1) {
            Some(next) => *next |= carry as u8,
            None if carry != 0 => return None,
            None => {}
        }
    }

    Some(out)
}

/// Encodes bytes in Nix's base32 variant: little-endian bit order,
/// most-significant digit first, using the [`NIX_BASE32`] alphabet.
/// Matches `nix hash convert --to nix32`.
fn encode_nix_base32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let len = (bytes.len() * 8).div_ceil(5);
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let j = bit % 8;
        let mut c = (bytes[i] >> j) as u16;
        if i + 1 < bytes.len() {
            c |= (bytes[i + 1] as u16) << (8 - j);
        }
        out.push(NIX_BASE32[(c & 0x1f) as usize] as char);
    }
    out
}

/// Splits and decodes a `name:base64-secret` key string into its name
/// and raw secret bytes, validating the minimum 32-byte seed length.
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

/// Builds the cache-relative `URL:` path for a static NAR, e.g.
/// `nar/<store-hash>-<file-hash>.nar.zst`.
///
/// The compressed file hash makes the URL identify the exact bytes transferred
/// by a binary-cache client. It is passed through [`hash_path_fragment`] so SRI
/// hashes containing `/`, `+`, or `=` remain filesystem- and URL-safe.
pub fn nar_url(store_path: &str, file_hash: &str, compression: NarCompression) -> String {
    format!(
        "nar/{}-{}.{}",
        store_hash(store_path),
        hash_path_fragment(file_hash),
        compression.extension(),
    )
}

/// Converts a hash string into one filesystem- and URL-path-safe segment.
///
/// Alphanumerics and `.`/`_`/`-` pass through, `:` becomes `-`, and
/// every other character (notably base64's `/`, `+`, `=`) becomes `_`.
pub fn hash_path_fragment(hash: &str) -> String {
    hash.chars()
        .map(|ch| match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => ch,
            ':' => '-',
            _ => '_',
        })
        .collect()
}

/// Renders one static narinfo body for the given input.
///
/// The store path, references, and deriver are re-rooted under
/// `store_dir`: `StorePath:` uses the full re-rooted path while
/// `References:` and `Deriver:` use basenames, matching stock Nix
/// binary-cache conventions. When `signer` is configured, a signature
/// over the [`NarInfoSigner::fingerprint`] of the re-rooted path and
/// full-path references is appended to any signatures already present
/// in the input.
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
    let fingerprint_references: Vec<String> = input
        .references
        .iter()
        .map(|reference| format!("{store_dir}/{}", basename(reference)))
        .collect();
    let deriver = input.deriver.map(basename);
    let url = nar_url(input.store_path, input.file_hash, input.compression);

    let mut signatures = input.signatures.to_vec();
    if let Some(signer) = signer {
        let fingerprint = NarInfoSigner::fingerprint(
            &store_path,
            input.nar_hash,
            input.nar_size as i64,
            &fingerprint_references,
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

/// Builds a structured [`NarInfo`] for callers that need data rather
/// than text; equivalent to parsing [`render_static_narinfo`] output.
///
/// # Panics
///
/// Panics if the rendered narinfo fails to parse, which would indicate
/// a bug in [`render_static_narinfo`] itself.
pub fn static_narinfo(
    input: &StaticNarInfoInput<'_>,
    store_dir: &str,
    signer: Option<&NarInfoSigner>,
) -> NarInfo {
    info::parse(&render_static_narinfo(input, store_dir, signer))
        .expect("rendered static narinfo is parseable")
}

/// Renders a stock Nix `nix-cache-info` file body advertising
/// `store_dir`, mass-query support, and the given cache `priority`
/// (lower numbers are preferred by Nix).
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
    fn nar_url_uses_store_hash_and_file_hash() {
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
    fn nar_url_changes_when_compressed_bytes_change() {
        let store_path = "/nix/store/abc123-hello";
        let first = nar_url(store_path, "sha256:first", NarCompression::Zstd);
        let second = nar_url(store_path, "sha256:second", NarCompression::Zstd);

        assert_ne!(first, second);
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
        assert_eq!(parsed.url, "nar/abc123-sha256-file789.nar.zst");
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
            nar_hash: "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
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
        let fingerprint_refs = vec!["/nix/store/ref111-libc".to_string()];
        let fingerprint = NarInfoSigner::fingerprint(
            &parsed.store_path,
            &parsed.nar_hash,
            parsed.nar_size as i64,
            &fingerprint_refs,
        );
        assert_eq!(
            fingerprint,
            "1;/nix/store/abc123-hello;sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s;42;/nix/store/ref111-libc"
        );
        use ed25519_dalek::Verifier as _;
        verifying_key
            .verify(fingerprint.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn nix_base32_matches_stock_nix_hash_convert() {
        let bytes = hex::decode("800d59cfcd3c05e900cb4e214be48f6b886a08df").unwrap();
        assert_eq!(
            encode_nix_base32(&bytes),
            "vw46m23bizj4n8afrc0fj19wrp7mj3c0"
        );
    }

    #[test]
    fn decode_nix_base32_roundtrips_sha256_digests() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let encoded = encode_nix_base32(&bytes);
        assert_eq!(encoded.len(), 52);
        assert_eq!(decode_nix_base32(&encoded).unwrap(), bytes);

        // Invalid alphabet character ('e' is excluded).
        assert!(decode_nix_base32(&encoded.replace(|c: char| c.is_ascii_digit(), "e")).is_none());
    }

    #[test]
    fn decode_nix_base32_roundtrips_all_byte_lengths() {
        // Every whole-byte length must round-trip exactly.
        for n in 0u8..=40 {
            let bytes: Vec<u8> = (0..n).map(|b| b.wrapping_mul(7).wrapping_add(3)).collect();
            let encoded = encode_nix_base32(&bytes);
            assert_eq!(
                decode_nix_base32(&encoded).as_deref(),
                Some(bytes.as_slice()),
                "round-trip failed at {n} bytes",
            );
        }
    }

    #[test]
    fn decode_nix_base32_never_panics_on_any_length() {
        // Lengths like 1, 3, 6, ... do not encode a whole number of bytes;
        // decode must return None, never index out of bounds.
        for len in 0..80 {
            let input: String = std::iter::repeat('1').take(len).collect();
            let _ = decode_nix_base32(&input); // must not panic
        }
        assert!(decode_nix_base32("1").is_none());
        assert!(decode_nix_base32("111").is_none());
    }

    #[test]
    fn normalize_sha256_nix32_normalizes_sha256_hash_formats() {
        let sri = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
        let hex = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let nix32 = "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s";

        assert_eq!(normalize_sha256_nix32(sri), nix32);
        assert_eq!(normalize_sha256_nix32(hex), nix32);
        assert_eq!(normalize_sha256_nix32(nix32), nix32);
    }

    #[test]
    fn nix_cache_info_body() {
        assert_eq!(
            nix_cache_info("/nix/store", 30),
            "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n"
        );
    }
}

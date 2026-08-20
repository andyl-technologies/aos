//! Signed `store/` realization-graph records.
//!
//! A modern registry keeps exact NAR identity and dependency edges in one
//! signed file per input-addressed store path:
//!
//! ```text
//! ca:sha256:<ca-hash> nar:sha256:<nar-hash>:<size>
//!   ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
//! ```
//!
//! Input-addressed-only records omit the `ca:` token. This module owns the
//! pure parser and serializer so native consumers, the Hub indexer, and the
//! Worker cannot disagree about this trust-bearing format.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use base64::Engine as _;

/// Name of the realization-graph directory at the registry tree root.
pub const STORE_DIR: &str = "store";

/// Nix's custom base32 alphabet (omits `e`, `o`, `t`, `u`).
const NIX_BASE32_ALPHABET: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// Length of a SHA-256 digest in nixbase32 characters.
const SHA256_NIX32_LEN: usize = 52;

fn is_nix32_digest(value: &str) -> bool {
    value.len() == SHA256_NIX32_LEN
        && value
            .chars()
            .all(|character| NIX_BASE32_ALPHABET.contains(character))
}

fn is_store_hash(value: &str) -> bool {
    value.len() >= 2
        && value
            .chars()
            .all(|character| NIX_BASE32_ALPHABET.contains(character))
}

/// Returns the input-addressed hash from a canonical absolute store path.
///
/// The store root itself is intentionally configurable; only normalized path
/// syntax and the final `<hash>-<name>` component are load-bearing.
///
/// # Errors
///
/// Returns an error for a relative or non-normalized path, or for a basename
/// that does not begin with a valid nixbase32 store hash.
pub fn store_path_hash(store_path: &str) -> Result<&str> {
    let mut components = store_path.split('/');
    anyhow::ensure!(components.next() == Some(""), "store path must be absolute");
    let components = components.collect::<Vec<_>>();
    anyhow::ensure!(
        components.len() >= 2
            && components
                .iter()
                .all(|component| !component.is_empty() && *component != "." && *component != ".."),
        "store path is not normalized"
    );
    let basename = components
        .last()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("store path has no basename"))?;
    let hash = basename
        .split_once('-')
        .map(|(hash, _)| hash)
        .ok_or_else(|| anyhow::anyhow!("store path has no store hash"))?;
    anyhow::ensure!(is_store_hash(hash), "store path has an invalid store hash");
    Ok(hash)
}

fn parse_sha256(token: &str) -> Result<String> {
    let digest = token
        .strip_prefix("sha256:")
        .filter(|digest| is_nix32_digest(digest))
        .ok_or_else(|| anyhow::anyhow!("expected sha256:<52-char-nixbase32>, got '{token}'"))?;
    Ok(digest.to_string())
}

fn parse_ia_ref(token: &str) -> Result<String> {
    let hash = token
        .strip_prefix("sha256:")
        .filter(|hash| is_store_hash(hash))
        .ok_or_else(|| anyhow::anyhow!("expected sha256:<store-path-hash>, got '{token}'"))?;
    Ok(hash.to_string())
}

/// Normalizes an accepted SHA-256 spelling to a bare nixbase32 digest.
///
/// # Errors
///
/// Returns an error when `hash` is not an SRI, hexadecimal, or nixbase32
/// SHA-256 value.
pub fn normalize_digest(hash: &str) -> Result<String> {
    let canonical = if let Some(encoded) = hash.strip_prefix("sha256-") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .with_context(|| format!("decoding SRI SHA-256 hash '{hash}'"))?;
        if bytes.len() != 32 {
            bail!("SRI SHA-256 hash has {} bytes, expected 32", bytes.len());
        }
        format!("sha256:{}", encode_nix_base32(&bytes))
    } else if let Some(encoded) = hash.strip_prefix("sha256:") {
        if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let bytes = hex::decode(encoded)
                .with_context(|| format!("decoding hexadecimal SHA-256 hash '{hash}'"))?;
            format!("sha256:{}", encode_nix_base32(&bytes))
        } else {
            hash.to_string()
        }
    } else {
        hash.to_string()
    };
    parse_sha256(&canonical)
        .with_context(|| format!("cannot derive a nixbase32 SHA-256 digest from '{hash}'"))
}

/// Converts an accepted SHA-256 spelling to lowercase hexadecimal.
///
/// # Errors
///
/// Returns an error when `hash` is not an SRI, hexadecimal, or nixbase32
/// SHA-256 value.
pub fn canonical_digest_hex(hash: &str) -> Result<String> {
    if let Some(encoded) = hash.strip_prefix("sha256-") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .with_context(|| format!("decoding SRI SHA-256 hash '{hash}'"))?;
        anyhow::ensure!(bytes.len() == 32, "SRI SHA-256 hash must contain 32 bytes");
        return Ok(hex::encode(bytes));
    }
    let encoded = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("SHA-256 hash must use a sha256: or sha256- prefix"))?;
    let bytes = if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        hex::decode(encoded).with_context(|| format!("decoding hexadecimal SHA-256 '{hash}'"))?
    } else if encoded.len() == SHA256_NIX32_LEN {
        decode_nix_base32(encoded)
            .ok_or_else(|| anyhow::anyhow!("invalid nixbase32 SHA-256 hash '{hash}'"))?
    } else {
        bail!("invalid SHA-256 hash '{hash}'");
    };
    anyhow::ensure!(bytes.len() == 32, "SHA-256 hash must contain 32 bytes");
    Ok(hex::encode(bytes))
}

fn decode_nix_base32(encoded: &str) -> Option<Vec<u8>> {
    let len = encoded.len() * 5 / 8;
    let mut output = vec![0_u8; len];
    for (position, character) in encoded.chars().rev().enumerate() {
        let digit = NIX_BASE32_ALPHABET.find(character)? as u16;
        let bit = position * 5;
        let byte = bit / 8;
        let shift = bit % 8;
        *output.get_mut(byte)? |= (digit << shift) as u8;
        let carry = digit >> (8 - shift);
        match output.get_mut(byte + 1) {
            Some(next) => *next |= carry as u8,
            None if carry != 0 => return None,
            None => {}
        }
    }
    Some(output)
}

fn encode_nix_base32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let alphabet = NIX_BASE32_ALPHABET.as_bytes();
    let len = (bytes.len() * 8).div_ceil(5);
    let mut output = String::with_capacity(len);
    for digit in (0..len).rev() {
        let bit = digit * 5;
        let byte = bit / 8;
        let shift = bit % 8;
        let mut value = (bytes[byte] >> shift) as u16;
        if byte + 1 < bytes.len() {
            value |= (bytes[byte + 1] as u16) << (8 - shift);
        }
        output.push(alphabet[(value & 0x1f) as usize] as char);
    }
    output
}

/// Exact uncompressed NAR bytes for one blessed realization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NarBytes {
    /// Nixbase32 SHA-256 of the uncompressed NAR, without a prefix.
    pub sha256_nix32: String,
    /// Uncompressed NAR size in bytes.
    pub size: u64,
}

impl NarBytes {
    /// Builds a NAR identity from any accepted SHA-256 spelling.
    ///
    /// # Errors
    ///
    /// Returns an error when `nar_hash` is not a supported SHA-256 value.
    pub fn from_hash(nar_hash: &str, size: u64) -> Result<Self> {
        Ok(Self {
            sha256_nix32: normalize_digest(nar_hash)?,
            size,
        })
    }

    /// Returns the canonical `sha256:<nixbase32>` spelling.
    #[must_use]
    pub fn nar_hash(&self) -> String {
        format!("sha256:{}", self.sha256_nix32)
    }

    /// Returns whether the supplied hash and size identify these bytes.
    #[must_use]
    pub fn matches(&self, nar_hash: &str, size: u64) -> bool {
        Self::from_hash(nar_hash, size).is_ok_and(|candidate| candidate == *self)
    }
}

/// One direct dependency edge in a realization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepEdge {
    /// Dependency input-addressed store-path hash.
    pub dep_ia: String,
    /// Optional pinned content-addressed realization.
    pub dep_ca: Option<String>,
}

/// One blessed realization of an input-addressed store path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Realisation {
    /// Exact NAR bytes of this realization.
    pub nar: NarBytes,
    /// Content address, or `None` for an input-addressed-only realization.
    pub ca: Option<String>,
    /// Direct dependency edges.
    pub deps: Vec<DepEdge>,
}

impl Realisation {
    /// Returns the canonical content-address spelling when present.
    #[must_use]
    pub fn ca_hash(&self) -> Option<String> {
        self.ca.as_ref().map(|digest| format!("sha256:{digest}"))
    }
}

/// Every blessed realization recorded for one input-addressed store path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreEntry {
    /// Realizations in stable order.
    pub realisations: Vec<Realisation>,
}

impl StoreEntry {
    /// Returns direct dependency input-addresses, deduplicated in first-seen order.
    #[must_use]
    pub fn dep_ias(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut dependencies = Vec::new();
        for realization in &self.realisations {
            for edge in &realization.deps {
                if seen.insert(edge.dep_ia.clone()) {
                    dependencies.push(edge.dep_ia.clone());
                }
            }
        }
        dependencies
    }

    /// Returns each distinct blessed NAR identity.
    #[must_use]
    pub fn blessed_nars(&self) -> Vec<NarBytes> {
        let mut nars = Vec::new();
        for realization in &self.realisations {
            if !nars.contains(&realization.nar) {
                nars.push(realization.nar.clone());
            }
        }
        nars
    }
}

/// Parses one signed `store/` realization record.
///
/// # Errors
///
/// Returns an error for malformed header or edge tokens, extra tokens, or an
/// edge that appears before its realization header.
pub fn parse_entry(content: &str) -> Result<StoreEntry> {
    let mut realisations: Vec<Realisation> = Vec::new();
    for raw in content.lines() {
        let line = raw.split_once('#').map_or(raw, |(prefix, _)| prefix).trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let first = tokens
            .next()
            .ok_or_else(|| anyhow::anyhow!("non-empty store line has no token"))?;
        if first.starts_with("ia:") {
            let edge = parse_edge(first)?;
            let current = realisations.last_mut().ok_or_else(|| {
                anyhow::anyhow!("dependency edge before any realization: '{line}'")
            })?;
            current.deps.push(edge);
            if tokens.next().is_some() {
                bail!("unexpected extra token on dependency edge line: '{line}'");
            }
            continue;
        }
        if !first.starts_with("ca:") && !first.starts_with("nar:") {
            bail!("unrecognized store line (expected ca:/nar:/ia:): '{line}'");
        }
        let (ca, nar_token) = if let Some(ca) = first.strip_prefix("ca:") {
            let nar = tokens.next().ok_or_else(|| {
                anyhow::anyhow!("realization header missing nar: token: '{line}'")
            })?;
            (Some(parse_ia_ref(ca)?), nar)
        } else {
            (None, first)
        };
        let nar = parse_nar_token(nar_token)?;
        if tokens.next().is_some() {
            bail!("unexpected extra token on realization header: '{line}'");
        }
        realisations.push(Realisation {
            nar,
            ca,
            deps: Vec::new(),
        });
    }
    Ok(StoreEntry { realisations })
}

fn parse_nar_token(token: &str) -> Result<NarBytes> {
    let rest = token
        .strip_prefix("nar:")
        .ok_or_else(|| anyhow::anyhow!("expected nar:sha256:<hash>:<size>, got '{token}'"))?;
    let (algorithm, tail) = rest
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("malformed nar token '{token}'"))?;
    if algorithm != "sha256" {
        bail!("unsupported nar hash algorithm in '{token}'");
    }
    let (digest, size) = tail
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("nar token '{token}' missing size"))?;
    if !is_nix32_digest(digest) {
        bail!("nar token '{token}' digest is not 52-char nixbase32");
    }
    let size = size
        .parse()
        .with_context(|| format!("nar token '{token}' has a bad size"))?;
    Ok(NarBytes {
        sha256_nix32: digest.to_string(),
        size,
    })
}

fn parse_edge(token: &str) -> Result<DepEdge> {
    let rest = token
        .strip_prefix("ia:")
        .ok_or_else(|| anyhow::anyhow!("expected ia:sha256:<hash>, got '{token}'"))?;
    let (ia, ca) = rest
        .split_once("/ca:")
        .map_or((rest, None), |(ia, ca)| (ia, Some(ca)));
    let dep_ia =
        parse_ia_ref(ia).with_context(|| format!("malformed dependency IA in edge '{token}'"))?;
    let dep_ca = ca
        .map(parse_ia_ref)
        .transpose()
        .with_context(|| format!("malformed dependency CA pin in edge '{token}'"))?;
    Ok(DepEdge { dep_ia, dep_ca })
}

/// Serializes a realization record with stable realization and edge ordering.
#[must_use]
pub fn serialize_entry(entry: &StoreEntry) -> String {
    let mut realisations = entry.realisations.clone();
    realisations.sort();
    let mut output = String::new();
    for realization in realisations {
        match realization.ca {
            Some(ca) => output.push_str(&format!(
                "ca:sha256:{ca} nar:sha256:{}:{}\n",
                realization.nar.sha256_nix32, realization.nar.size
            )),
            None => output.push_str(&format!(
                "nar:sha256:{}:{}\n",
                realization.nar.sha256_nix32, realization.nar.size
            )),
        }
        let mut dependencies = realization.deps;
        dependencies.sort();
        for edge in dependencies {
            match edge.dep_ca {
                Some(ca) => {
                    output.push_str(&format!("  ia:sha256:{}/ca:sha256:{ca}\n", edge.dep_ia))
                }
                None => output.push_str(&format!("  ia:sha256:{}\n", edge.dep_ia)),
            }
        }
    }
    output
}

/// Returns the two-character shard for an input-addressed store hash.
///
/// # Errors
///
/// Returns an error when the hash is too short or contains non-nixbase32
/// characters.
pub fn shard(ia_hash: &str) -> Result<&str> {
    if !is_store_hash(ia_hash) {
        bail!("'{ia_hash}' is not a nixbase32 store-path hash; refusing to derive a shard");
    }
    Ok(&ia_hash[..2])
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAR_A: &str = "1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";
    const NAR_B: &str = "0b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";

    #[test]
    fn canonical_hex_accepts_every_supported_digest_spelling() {
        let bytes = [0_u8; 32];
        let expected = "0".repeat(64);
        assert_eq!(
            canonical_digest_hex(&format!("sha256:{expected}")).unwrap(),
            expected
        );
        assert_eq!(
            canonical_digest_hex(&format!("sha256:{}", encode_nix_base32(&bytes))).unwrap(),
            "0".repeat(64)
        );
        assert_eq!(
            canonical_digest_hex(&format!(
                "sha256-{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ))
            .unwrap(),
            "0".repeat(64)
        );
    }

    #[test]
    fn store_path_hash_accepts_custom_roots_but_rejects_ambiguous_paths() {
        let hash = "9rd6z1174svja44vjm38h6iql4sz4z9k";
        assert_eq!(
            store_path_hash(&format!("/custom/store/{hash}-image")).unwrap(),
            hash
        );
        assert!(store_path_hash(&format!("relative/{hash}-image")).is_err());
        assert!(store_path_hash(&format!("/custom/../store/{hash}-image")).is_err());
        assert!(store_path_hash("/custom/store/not-a-hash-image").is_err());
    }

    #[test]
    fn realization_record_round_trips_canonical_text() {
        let text = format!(
            "ca:sha256:{NAR_B} nar:sha256:{NAR_A}:367184\n  ia:sha256:9rd6z1174svja44vjm38h6iql4sz4z9k/ca:sha256:{NAR_B}\n"
        );
        let entry = parse_entry(&text).unwrap();
        assert_eq!(
            entry.blessed_nars()[0].nar_hash(),
            format!("sha256:{NAR_A}")
        );
        assert_eq!(entry.blessed_nars()[0].size, 367184);
        assert_eq!(entry.dep_ias(), ["9rd6z1174svja44vjm38h6iql4sz4z9k"]);
        assert_eq!(serialize_entry(&entry), text);
    }

    #[test]
    fn realization_record_rejects_malformed_or_orphaned_edges() {
        assert!(parse_entry("ia:sha256:9rd6z1174svja44vjm38h6iql4sz4z9k\n").is_err());
        assert!(parse_entry("nar:sha256:short:1\n").is_err());
        assert!(parse_entry(&format!("nar:sha256:{NAR_A}:not-a-size\n")).is_err());
    }
}

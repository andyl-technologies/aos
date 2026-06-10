//! Parsing and rendering of `.narinfo` metadata files.
//!
//! In a Nix binary cache, each store path is described by a `.narinfo`
//! file -- a simple `Key: value` text document recording where the NAR
//! lives (`URL`, `Compression`), its hashes and sizes (`NarHash`,
//! `NarSize`, `FileHash`, `FileSize`), its `References` and `Deriver`,
//! and any `Sig` signatures. [`parse`] and [`format`](fn@format)
//! round-trip that format through the [`NarInfo`] struct, which is
//! shared between the cache server and the client.
//!
//! The module also hosts the small store-path helpers [`store_hash`]
//! and [`basename`] used throughout the NAR code.

use anyhow::{Context, Result};

/// Parsed narinfo data — shared between server and cache client.
///
/// Field names mirror the keys of the narinfo text format. Path-valued
/// fields (`store_path`, `references`, `deriver`) may hold either full
/// store paths or bare basenames depending on the producer; the text
/// format conventionally uses a full path for `StorePath` and basenames
/// for `References` and `Deriver`.
#[derive(Debug, Clone)]
pub struct NarInfo {
    /// The store path this narinfo describes (`StorePath`).
    pub store_path: String,
    /// Cache-relative URL of the NAR file (`URL`), e.g. `nar/<hash>.nar.zst`.
    pub url: String,
    /// Compression applied to the NAR file (`Compression`), e.g. `none`,
    /// `zstd`, or `xz`. Defaults to `none` when absent.
    pub compression: String,
    /// Hash of the compressed NAR file as stored (`FileHash`).
    pub file_hash: Option<String>,
    /// Size in bytes of the compressed NAR file (`FileSize`).
    pub file_size: Option<u64>,
    /// Hash of the uncompressed NAR (`NarHash`).
    pub nar_hash: String,
    /// Size in bytes of the uncompressed NAR (`NarSize`).
    pub nar_size: u64,
    /// Store paths referenced by this path (`References`).
    pub references: Vec<String>,
    /// The deriver `.drv` that produced this path, if known (`Deriver`).
    pub deriver: Option<String>,
    /// `name:base64` Ed25519 signatures (`Sig`), one per line.
    pub signatures: Vec<String>,
}

/// Parses a narinfo text document into a [`NarInfo`].
///
/// Blank lines and unknown keys are ignored, so the parser is forwards
/// compatible with fields this crate does not model. An empty `Deriver`
/// value is treated as absent.
///
/// # Errors
///
/// Returns an error if any of the required fields -- `StorePath`,
/// `URL`, `NarHash`, or `NarSize` -- is missing (or, for `NarSize`,
/// not a valid integer).
pub fn parse(text: &str) -> Result<NarInfo> {
    let mut store_path = None;
    let mut url = None;
    let mut compression = "none".to_string();
    let mut file_hash = None;
    let mut file_size = None;
    let mut nar_hash = None;
    let mut nar_size = None;
    let mut references = Vec::new();
    let mut deriver = None;
    let mut signatures = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "StorePath" => store_path = Some(value.to_string()),
                "URL" => url = Some(value.to_string()),
                "Compression" => compression = value.to_string(),
                "FileHash" => file_hash = Some(value.to_string()),
                "FileSize" => file_size = value.parse().ok(),
                "NarHash" => nar_hash = Some(value.to_string()),
                "NarSize" => nar_size = value.parse().ok(),
                "References" => {
                    references = value.split_whitespace().map(String::from).collect();
                }
                "Deriver" => {
                    if !value.is_empty() {
                        deriver = Some(value.to_string());
                    }
                }
                "Sig" => signatures.push(value.to_string()),
                _ => {} // Ignore unknown fields
            }
        }
    }

    Ok(NarInfo {
        store_path: store_path.context("missing StorePath in narinfo")?,
        url: url.context("missing URL in narinfo")?,
        compression,
        file_hash,
        file_size,
        nar_hash: nar_hash.context("missing NarHash in narinfo")?,
        nar_size: nar_size.context("missing NarSize in narinfo")?,
        references,
        deriver,
        signatures,
    })
}

/// Formats a [`NarInfo`] into the standard narinfo text format.
///
/// Optional fields (`FileHash`, `FileSize`, `References`, `Deriver`)
/// are omitted when unset or empty; each signature is emitted as its
/// own `Sig:` line. The output round-trips through [`parse`].
pub fn format(info: &NarInfo) -> String {
    let mut out = String::with_capacity(512);

    out.push_str(&format!("StorePath: {}\n", info.store_path));
    out.push_str(&format!("URL: {}\n", info.url));
    out.push_str(&format!("Compression: {}\n", info.compression));

    if let Some(ref fh) = info.file_hash {
        out.push_str(&format!("FileHash: {fh}\n"));
    }
    if let Some(fs) = info.file_size {
        out.push_str(&format!("FileSize: {fs}\n"));
    }

    out.push_str(&format!("NarHash: {}\n", info.nar_hash));
    out.push_str(&format!("NarSize: {}\n", info.nar_size));

    if !info.references.is_empty() {
        out.push_str(&format!("References: {}\n", info.references.join(" ")));
    }

    if let Some(ref d) = info.deriver {
        out.push_str(&format!("Deriver: {d}\n"));
    }

    for sig in &info.signatures {
        out.push_str(&format!("Sig: {sig}\n"));
    }

    out
}

/// Parameters for constructing a NarInfo from path metadata and compressed NAR
/// metadata.
///
/// The first group of fields comes from the store's path info
/// (`nix-store` queries or the Nix DB); the second group describes the
/// compressed NAR artifact as it will be stored in the cache.
pub struct PathInfoParams<'a> {
    /// The store path being described.
    pub path: &'a str,
    /// Hash of the uncompressed NAR.
    pub nar_hash: &'a str,
    /// Size in bytes of the uncompressed NAR.
    pub nar_size: u64,
    /// Store paths referenced by `path`.
    pub references: &'a [String],
    /// The deriver `.drv` path, if known.
    pub deriver: Option<&'a str>,
    /// Pre-existing `name:base64` signatures to carry over.
    pub signatures: &'a [String],
    /// Hash of the compressed NAR file.
    pub file_hash: &'a str,
    /// Size in bytes of the compressed NAR file.
    pub file_size: u64,
    /// Compression name (`none`, `zstd`, `xz`).
    pub compression: &'a str,
    /// Cache-relative URL where the NAR file is served.
    pub nar_url: &'a str,
}

/// Builds a [`NarInfo`] from path metadata plus compressed NAR metadata.
pub fn from_path_info(params: &PathInfoParams<'_>) -> NarInfo {
    NarInfo {
        store_path: params.path.to_string(),
        url: params.nar_url.to_string(),
        compression: params.compression.to_string(),
        file_hash: Some(params.file_hash.to_string()),
        file_size: Some(params.file_size),
        nar_hash: params.nar_hash.to_string(),
        nar_size: params.nar_size,
        references: params.references.to_vec(),
        deriver: params.deriver.map(String::from),
        signatures: params.signatures.to_vec(),
    }
}

/// Extracts the hash portion from a store path (or basename): the part
/// of the last path component before the first `-`.
///
/// E.g. `/nix/store/abc123-foo-1.0` -> `abc123`, and
/// `abc123-foo-1.0` -> `abc123`.
pub fn store_hash(path: &str) -> &str {
    let name = basename(path);
    name.split('-').next().unwrap_or(name)
}

/// Extracts the basename (last `/`-separated component) from a store
/// path; returns the input unchanged when it contains no `/`.
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let info = NarInfo {
            store_path: "/nix/store/abc123-hello-2.12".to_string(),
            url: "nar/sha256-def456.nar.zst".to_string(),
            compression: "zstd".to_string(),
            file_hash: Some("sha256:789abc".to_string()),
            file_size: Some(34567),
            nar_hash: "sha256:def456".to_string(),
            nar_size: 89012,
            references: vec!["ghi789-glibc-2.38".to_string()],
            deriver: Some("jkl012-hello-2.12.drv".to_string()),
            signatures: vec!["cache.example.com:abcdef==".to_string()],
        };

        let text = format(&info);
        let parsed = parse(&text).unwrap();

        assert_eq!(parsed.store_path, info.store_path);
        assert_eq!(parsed.url, info.url);
        assert_eq!(parsed.compression, info.compression);
        assert_eq!(parsed.file_hash, info.file_hash);
        assert_eq!(parsed.file_size, info.file_size);
        assert_eq!(parsed.nar_hash, info.nar_hash);
        assert_eq!(parsed.nar_size, info.nar_size);
        assert_eq!(parsed.references, info.references);
        assert_eq!(parsed.deriver, info.deriver);
        assert_eq!(parsed.signatures, info.signatures);
    }

    #[test]
    fn store_hash_from_path() {
        assert_eq!(store_hash("/nix/store/abc123-foo-1.0"), "abc123");
    }

    #[test]
    fn store_hash_from_basename() {
        assert_eq!(store_hash("abc123-foo-1.0"), "abc123");
    }

    #[test]
    fn basename_full_path() {
        assert_eq!(basename("/nix/store/abc123-foo"), "abc123-foo");
    }
}

use anyhow::{Context, Result};

/// Parsed narinfo data — shared between server and cache client.
#[derive(Debug, Clone)]
pub struct NarInfo {
    pub store_path: String,
    pub url: String,
    pub compression: String,
    pub file_hash: Option<String>,
    pub file_size: Option<u64>,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub signatures: Vec<String>,
}

/// Parse a narinfo text response into a NarInfo struct.
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
                    references = value
                        .split_whitespace()
                        .map(String::from)
                        .collect();
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

/// Format a NarInfo into the standard narinfo text format.
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

/// Generate a NarInfo from PathInfo metadata + compressed NAR metadata.
pub fn from_path_info(
    path: &str,
    nar_hash: &str,
    nar_size: u64,
    references: &[String],
    deriver: Option<&str>,
    signatures: &[String],
    file_hash: &str,
    file_size: u64,
    compression: &str,
    nar_url: &str,
) -> NarInfo {
    NarInfo {
        store_path: path.to_string(),
        url: nar_url.to_string(),
        compression: compression.to_string(),
        file_hash: Some(file_hash.to_string()),
        file_size: Some(file_size),
        nar_hash: nar_hash.to_string(),
        nar_size,
        references: references.to_vec(),
        deriver: deriver.map(String::from),
        signatures: signatures.to_vec(),
    }
}

/// Extract the hash portion from a store path (or basename).
/// E.g., "/nix/store/abc123-foo-1.0" → "abc123"
/// E.g., "abc123-foo-1.0" → "abc123"
pub fn store_hash(path: &str) -> &str {
    let name = basename(path);
    name.split('-').next().unwrap_or(name)
}

/// Extract the basename (last path component) from a store path.
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

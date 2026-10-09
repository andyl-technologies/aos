//! Normalized NAR metadata and bounded recovery cursor identities.

/// Parsed metadata used to activate one normalized cache object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCacheNarinfo {
    /// Logical cache database identity.
    pub cache_id: i64,
    /// Store-path hash used as the logical object key.
    pub store_hash: String,
    /// Final store-path component including hash and package name.
    pub store_name: String,
    /// Surface-relative archive URL advertised by the narinfo.
    pub nar_url: String,
    /// Uncompressed NAR digest advertised by the producer.
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: i64,
    /// Compressed archive digest advertised by the producer.
    pub file_hash: String,
    /// Compressed archive size in bytes.
    pub file_size: i64,
    /// Archive compression identifier.
    pub compression: String,
    /// Optional derivation store path.
    pub deriver: Option<String>,
    /// Sorted, unique store hashes referenced by this NAR.
    pub references: Vec<String>,
    /// Optional newline-separated narinfo signatures.
    pub signature: Option<String>,
    /// Optional Nix content-address declaration.
    pub content_address: Option<String>,
    /// Receipt time in Unix seconds.
    pub published_at: i64,
}

/// Parse a `.narinfo` body into normalized logical cache-object metadata.
///
/// `store_hash` is the primary key carried by the upload path (`<hash>.narinfo`);
/// the rest is read from the body. Returns `None` when the required `StorePath`
/// or `URL` field is absent (a malformed narinfo is not indexed, but its bytes
/// still land on the surface — the surface is the source of truth, the index is
/// rebuildable). Pure string parsing, so it runs on the wasm Worker too.
///
/// Shared with the cache inventory scanner, which re-derives the whole index by
/// parsing every narinfo it lists off the surface.
pub fn parse_cache_narinfo(
    cache_id: i64,
    store_hash: &str,
    text: &str,
    uploaded_at: i64,
) -> Option<ParsedCacheNarinfo> {
    let mut store_path: Option<String> = None;
    let mut nar_url: Option<String> = None;
    let mut nar_hash = String::new();
    let mut nar_size = 0i64;
    let mut file_hash = String::new();
    let mut file_size = 0i64;
    let mut compression = "none".to_string();
    let mut deriver: Option<String> = None;
    let mut refs: Vec<String> = Vec::new();
    let mut sig: Option<String> = None;
    let mut ca: Option<String> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "StorePath" => store_path = Some(value.to_string()),
            "URL" => nar_url = Some(value.to_string()),
            "NarHash" => nar_hash = value.to_string(),
            "NarSize" => nar_size = value.parse().unwrap_or(0),
            "FileHash" => file_hash = value.to_string(),
            "FileSize" => file_size = value.parse().unwrap_or(0),
            "Compression" if !value.is_empty() => compression = value.to_string(),
            "Deriver" if !value.is_empty() && value != "unknown-deriver" => {
                deriver = Some(value.to_string());
            }
            "References" => {
                refs = value.split_whitespace().map(narinfo_store_hash).collect();
            }
            // narinfo may carry multiple `Sig:` lines; keep them all (newline-joined).
            "Sig" => {
                sig = Some(match sig.take() {
                    Some(prev) => format!("{prev}\n{value}"),
                    None => value.to_string(),
                });
            }
            "CA" if !value.is_empty() => ca = Some(value.to_string()),
            _ => {}
        }
    }
    let store_path = store_path?;
    refs.sort();
    refs.dedup();
    Some(ParsedCacheNarinfo {
        cache_id,
        store_hash: store_hash.to_string(),
        store_name: store_path
            .rsplit('/')
            .next()
            .unwrap_or(&store_path)
            .to_string(),
        nar_url: nar_url?,
        nar_hash,
        nar_size,
        file_hash,
        file_size,
        compression,
        deriver,
        references: refs,
        signature: sig,
        content_address: ca,
        published_at: uploaded_at,
    })
}

fn narinfo_store_hash(entry: &str) -> String {
    let base = entry.rsplit('/').next().unwrap_or(entry);
    base.split('-').next().unwrap_or(base).to_string()
}

/// Initial cursor preceding all exact JavaScript Unix timestamps.
pub const CACHE_WRITE_RECOVERY_CURSOR_START: i64 = -9_007_199_254_740_991;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narinfo_store_hash_strips_path_and_name() {
        assert_eq!(narinfo_store_hash("/nix/store/abc123-foo-1.0"), "abc123");
        assert_eq!(narinfo_store_hash("abc123-foo-1.0"), "abc123");
        assert_eq!(narinfo_store_hash("abc123"), "abc123");
    }

    #[test]
    fn parse_narinfo_extracts_fields_and_refs() {
        let text = "StorePath: /nix/store/abc-foo-1.0\n\
                        URL: nar/deadbeef.nar.zst\n\
                        Compression: zstd\n\
                        NarHash: sha256:aaa\n\
                        NarSize: 100\n\
                        FileHash: sha256:bbb\n\
                        FileSize: 50\n\
                        References: abc-foo-1.0 def-bar-2.0\n\
                        Deriver: ghi-foo.drv\n\
                        Sig: key:sigvalue\n";
        let o = parse_cache_narinfo(7, "abc", text, 123).unwrap();
        assert_eq!(o.cache_id, 7);
        assert_eq!(o.store_hash, "abc");
        assert_eq!(o.store_name, "abc-foo-1.0");
        assert_eq!(o.nar_url, "nar/deadbeef.nar.zst");
        assert_eq!(o.compression, "zstd");
        assert_eq!(o.nar_size, 100);
        assert_eq!(o.file_size, 50);
        assert_eq!(o.references, vec!["abc".to_string(), "def".to_string()]);
        assert_eq!(o.deriver.as_deref(), Some("ghi-foo.drv"));
        assert_eq!(o.signature.as_deref(), Some("key:sigvalue"));
        assert_eq!(o.published_at, 123);
    }

    #[test]
    fn parse_narinfo_keeps_multiple_sig_lines() {
        let text = "StorePath: /nix/store/x-a\nURL: nar/y.nar\nSig: k1:a\nSig: k2:b\n";
        let o = parse_cache_narinfo(1, "x", text, 0).unwrap();
        assert_eq!(o.signature.as_deref(), Some("k1:a\nk2:b"));
    }

    #[test]
    fn parse_narinfo_empty_compression_keeps_default() {
        let text = "StorePath: /nix/store/x-a\nURL: nar/y.nar\nCompression:\n";
        let o = parse_cache_narinfo(1, "x", text, 0).unwrap();
        assert_eq!(o.compression, "none");
    }

    #[test]
    fn parse_narinfo_requires_storepath_and_url() {
        assert!(parse_cache_narinfo(1, "x", "Compression: zstd\n", 0).is_none());
        assert!(parse_cache_narinfo(1, "x", "StorePath: /nix/store/x-a\n", 0).is_none());
    }

}

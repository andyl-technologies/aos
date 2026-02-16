use crate::server::config::CompressionConfig;
use crate::server::sign::NarInfoSigner;
use crate::server::store::PathInfo;

/// Extract the basename (everything after the last `/`) from a store path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Extract the hash portion from a store path basename.
/// E.g., "abc123-foo-1.0" → "abc123"
fn store_hash(path: &str) -> &str {
    let name = basename(path);
    name.split('-').next().unwrap_or(name)
}

/// Resolve compression name and file extension from config.
fn compression_parts(config: &CompressionConfig) -> (&str, &str) {
    match config.algorithm.as_str() {
        "zstd" => ("zstd", "nar.zst"),
        "xz" => ("xz", "nar.xz"),
        _ => ("none", "nar"),
    }
}

/// Format a PathInfo as a Nix narinfo response.
pub fn format_narinfo(info: &PathInfo, store_dir: &str, compression: &CompressionConfig, signer: Option<&NarInfoSigner>) -> String {
    let path_basename = basename(&info.path);
    let path_hash = store_hash(&info.path);

    // The NarHash in the DB is stored as "sha256:{base16}" — narinfo needs it as-is.
    let nar_hash = &info.nar_hash;

    let (comp_name, comp_ext) = compression_parts(compression);

    // URL uses the store hash + nar hash for resolution (nix-serve style).
    let url = format!("nar/{path_hash}-{}.{comp_ext}", nar_hash.replace(':', "-"));

    let mut out = String::with_capacity(512);
    out.push_str(&format!("StorePath: {store_dir}/{path_basename}\n"));
    out.push_str(&format!("URL: {url}\n"));
    out.push_str(&format!("Compression: {comp_name}\n"));
    if comp_name == "none" {
        out.push_str(&format!("FileHash: {nar_hash}\n"));
        out.push_str(&format!("FileSize: {}\n", info.nar_size));
    }
    out.push_str(&format!("NarHash: {nar_hash}\n"));
    out.push_str(&format!("NarSize: {}\n", info.nar_size));

    // References: space-separated basenames
    if !info.refs.is_empty() {
        let ref_basenames: Vec<&str> = info.refs.iter().map(|r| basename(r)).collect();
        out.push_str(&format!("References: {}\n", ref_basenames.join(" ")));
    }

    // Deriver
    if let Some(ref deriver) = info.deriver {
        out.push_str(&format!("Deriver: {}\n", basename(deriver)));
    }

    // Signatures from DB
    for sig in &info.sigs {
        out.push_str(&format!("Sig: {sig}\n"));
    }

    // Live signing with ed25519 key
    if let Some(signer) = signer {
        let store_path = format!("{store_dir}/{}", basename(&info.path));
        let fingerprint = NarInfoSigner::fingerprint(&store_path, &info.nar_hash, info.nar_size, &info.refs);
        if let Some(sig) = signer.sign(&fingerprint) {
            out.push_str(&format!("Sig: {sig}\n"));
        }
    }

    out
}

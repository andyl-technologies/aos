use aos_core::nar::info::{basename, store_hash};
use crate::compress::{compute_file_hash_size, Compression};
use crate::config::CompressionConfig;
use crate::sign::NarInfoSigner;
use crate::store::DbPathInfo;

/// Resolve compression name and file extension from config.
fn compression_parts(config: &CompressionConfig) -> (&str, &str) {
    match config.algorithm.as_str() {
        "zstd" => ("zstd", "nar.zst"),
        "xz" => ("xz", "nar.xz"),
        _ => ("none", "nar"),
    }
}

/// Resolve narinfo `Compression:` config into the typed `Compression` used
/// by the compression pipeline.
fn compression_from_config(config: &CompressionConfig) -> Compression {
    match config.algorithm.as_str() {
        "zstd" => Compression::Zstd { level: config.level },
        "xz" => Compression::Xz { level: config.level },
        _ => Compression::None,
    }
}

/// Format a DbPathInfo as a Nix narinfo response.
pub fn format_narinfo(info: &DbPathInfo, store_dir: &str, compression: &CompressionConfig, signer: Option<&NarInfoSigner>) -> String {
    let path_basename = basename(&info.path);
    let path_hash = store_hash(&info.path);

    // The NarHash in the DB is stored as "sha256:{base16}" — narinfo needs it as-is.
    let nar_hash = &info.nar_hash;

    let (comp_name, comp_ext) = compression_parts(compression);

    // URL uses the store hash + nar hash for resolution (nix-serve style).
    let url = format!("nar/{path_hash}-{}.{comp_ext}", nar_hash.replace(':', "-"));

    // FileHash / FileSize describe the compressed bytes the client will
    // actually download. For Compression::None they coincide with
    // NarHash / NarSize; for zstd / xz we have to actually run the
    // compression pipeline once to compute them. Apm-side verification
    // (`crates/aos-package/src/verify.rs`) requires both to be present
    // and non-empty regardless of compression, so we always emit them.
    let (file_hash, file_size): (String, u64) = if comp_name == "none" {
        (nar_hash.clone(), info.nar_size as u64)
    } else {
        match compute_file_hash_size(&info.path, compression_from_config(compression)) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(
                    path = %info.path,
                    error = %e,
                    "FileHash/FileSize computation failed; falling back to NarHash"
                );
                (nar_hash.clone(), info.nar_size as u64)
            }
        }
    };

    let mut out = String::with_capacity(512);
    out.push_str(&format!("StorePath: {store_dir}/{path_basename}\n"));
    out.push_str(&format!("URL: {url}\n"));
    out.push_str(&format!("Compression: {comp_name}\n"));
    out.push_str(&format!("FileHash: {file_hash}\n"));
    out.push_str(&format!("FileSize: {file_size}\n"));
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

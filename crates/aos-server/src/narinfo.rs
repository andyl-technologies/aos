use crate::compress::{Compression, compute_file_hash_size};
use crate::config::CompressionConfig;
use crate::sign::NarInfoSigner;
use crate::store::DbPathInfo;
use aos_core::nar::cache::{NarCompression, StaticNarInfoInput, render_static_narinfo};

/// Resolve compression name from config.
fn nar_compression(config: &CompressionConfig) -> NarCompression {
    match config.algorithm.as_str() {
        "zstd" => NarCompression::Zstd,
        "xz" => NarCompression::Xz,
        _ => NarCompression::None,
    }
}

/// Resolve narinfo `Compression:` config into the typed `Compression` used
/// by the compression pipeline.
fn compression_from_config(config: &CompressionConfig) -> Compression {
    match config.algorithm.as_str() {
        "zstd" => Compression::Zstd {
            level: config.level,
        },
        "xz" => Compression::Xz {
            level: config.level,
        },
        _ => Compression::None,
    }
}

/// Format a DbPathInfo as a Nix narinfo response.
pub fn format_narinfo(
    info: &DbPathInfo,
    store_dir: &str,
    compression: &CompressionConfig,
    signer: Option<&NarInfoSigner>,
) -> String {
    // The NarHash in the DB is stored as "sha256:{base16}" — narinfo needs it as-is.
    let nar_hash = &info.nar_hash;
    let nar_compression = nar_compression(compression);

    // FileHash / FileSize describe the compressed bytes the client will
    // actually download. For Compression::None they coincide with
    // NarHash / NarSize; for zstd / xz we have to actually run the
    // compression pipeline once to compute them. Apm-side verification
    // (`crates/aos-package/src/verify.rs`) requires both to be present
    // and non-empty regardless of compression, so we always emit them.
    let (file_hash, file_size): (String, u64) = if nar_compression == NarCompression::None {
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

    render_static_narinfo(
        &StaticNarInfoInput {
            store_path: &info.path,
            nar_hash,
            nar_size: info.nar_size as u64,
            references: &info.refs,
            deriver: info.deriver.as_deref(),
            signatures: &info.sigs,
            file_hash: &file_hash,
            file_size,
            compression: nar_compression,
        },
        store_dir,
        signer,
    )
}

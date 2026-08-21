//! Rendering of `.narinfo` responses.
//!
//! A narinfo document is the small text record a Nix binary cache serves at
//! `GET /{view}/{hash}.narinfo`. It describes a store path (NAR hash and
//! size, references, deriver, signatures) and tells the client where to
//! download the NAR and how it is compressed.
//!
//! [`format_narinfo`] is the single entry point: it takes the path metadata
//! read from the Nix SQLite database ([`crate::store::DbPathInfo`]), the
//! configured compression ([`crate::config::CompressionConfig`]), and an
//! optional [`NarInfoSigner`], and renders the final response body. When
//! compression is enabled, the `FileHash`/`FileSize` fields (which describe
//! the *compressed* download) are computed by running the compression
//! pipeline once via [`crate::compress::compute_file_hash_size`].

use crate::compress::{Compression, compute_file_hash_size};
use crate::config::CompressionConfig;
use crate::sign::NarInfoSigner;
use crate::store::DbPathInfo;
use anyhow::Context as _;
use aos_core::nar::cache::{NarCompression, StaticNarInfoInput, render_static_narinfo};

/// Resolves the configured algorithm name to the narinfo `Compression:` enum.
///
/// Unknown algorithm strings fall back to [`NarCompression::None`].
fn nar_compression(config: &CompressionConfig) -> NarCompression {
    match config.algorithm.as_str() {
        "zstd" => NarCompression::Zstd,
        "xz" => NarCompression::Xz,
        _ => NarCompression::None,
    }
}

/// Resolves the configured algorithm name into the typed [`Compression`]
/// used by the compression pipeline, carrying the configured level.
///
/// Unknown algorithm strings fall back to [`Compression::None`].
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

/// Formats a [`DbPathInfo`] as a Nix `.narinfo` response body.
///
/// The rendered document advertises a NAR URL whose extension matches the
/// configured compression (`.nar`, `.nar.zst`, or `.nar.xz`). `FileHash` and
/// `FileSize` always describe the bytes the client will actually download:
/// for uncompressed responses they equal `NarHash`/`NarSize`, while for
/// zstd/xz the compression pipeline is run once to measure them.
///
/// When `signer` is provided, a fresh `Sig:` line is appended in addition to
/// any signatures already stored in the database.
///
/// # Errors
///
/// Returns an error if compressed-byte measurement fails, or if the stored or
/// computed file hash is not a supported, well-formed SHA-256 hash.
pub fn format_narinfo(
    info: &DbPathInfo,
    store_dir: &str,
    compression: &CompressionConfig,
    signer: Option<&NarInfoSigner>,
) -> anyhow::Result<String> {
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
        compute_file_hash_size(&info.path, compression_from_config(compression))
            .with_context(|| format!("measuring compressed NAR for {}", info.path))?
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_narinfo_fails_when_payload_measurement_fails() {
        let info = DbPathInfo {
            id: 1,
            path: "/path/that/does/not/exist".to_string(),
            nar_hash: format!("sha256:{}", "11".repeat(32)),
            nar_size: 7,
            deriver: None,
            sigs: Vec::new(),
            refs: Vec::new(),
        };

        let error =
            format_narinfo(&info, "/nix/store", &CompressionConfig::default(), None).unwrap_err();
        assert!(error.to_string().contains("measuring compressed NAR"));
    }
}

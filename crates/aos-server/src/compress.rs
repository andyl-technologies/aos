//! NAR streaming and compression pipelines.
//!
//! NAR responses are produced by piping `nix-store --dump <path>` through an
//! external compressor (`zstd` or `xz`) selected by [`Compression`]. Three
//! entry points cover the cache handlers' needs:
//!
//! - [`nar_stream`] — streaming body for full `GET .../nar/...` responses;
//!   bytes flow from the subprocess pipeline straight into the HTTP body
//!   without buffering.
//! - [`nar_bytes`] — fully buffered variant, used for `Range:` requests
//!   where the total length must be known up front.
//! - [`compute_file_hash_size`] — hashes the compressed output to fill the
//!   `FileHash`/`FileSize` narinfo fields (see [`crate::narinfo`]).

use std::process::Stdio;

use anyhow::{Context as _, Result};
use aos_core::nix::aos_nix_env;
use axum::body::Body;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio_util::io::ReaderStream;

/// Compression algorithm for NAR responses.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    /// Serve the raw, uncompressed NAR.
    None,
    /// Pipe through `zstd -c -{level}`.
    Zstd { level: i32 },
    /// Pipe through `xz -c -T0 -{level}`.
    Xz { level: i32 },
}

impl Compression {
    /// Returns the file extension for this compression type
    /// (`nar`, `nar.zst`, or `nar.xz`).
    pub fn extension(&self) -> &str {
        match self {
            Compression::None => "nar",
            Compression::Zstd { .. } => "nar.zst",
            Compression::Xz { .. } => "nar.xz",
        }
    }

    /// Returns the `Content-Type` header value for NAR responses
    /// (always `application/x-nix-nar`, regardless of compression).
    pub fn content_type(&self) -> &str {
        "application/x-nix-nar"
    }

    /// Returns the compression name for the narinfo `Compression:` field
    /// (`none`, `zstd`, or `xz`).
    pub fn narinfo_name(&self) -> &str {
        match self {
            Compression::None => "none",
            Compression::Zstd { .. } => "zstd",
            Compression::Xz { .. } => "xz",
        }
    }
}

/// Spawns `nix-store --dump <store_path>` and streams the (optionally
/// compressed) NAR as an axum response [`Body`].
///
/// For [`Compression::Zstd`] and [`Compression::Xz`], the dump's stdout is
/// connected directly to the compressor's stdin so nothing is buffered in
/// the server process. Note that errors from the subprocesses *after* a
/// successful spawn surface as stream errors in the body, not as an `Err`
/// from this function.
///
/// # Errors
///
/// Returns an error if `nix-store` or the compressor process cannot be
/// spawned, or if a child's stdout pipe is unavailable.
pub async fn nar_stream(store_path: &str, compression: Compression) -> Result<Body> {
    match compression {
        Compression::None => {
            let mut child = Command::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning nix-store --dump")
                .map_err(|e| {
                    tracing::error!(store_path = %store_path, error = %e, "NAR dump failed to spawn");
                    e
                })?;

            let stdout = child.stdout.take().context("no stdout")?;
            let stream = ReaderStream::new(stdout);
            Ok(Body::from_stream(stream))
        }
        Compression::Zstd { level } => {
            // Use std::process for the dump command so we can pipe its
            // ChildStdout directly into the zstd process as Stdio.
            let mut dump = std::process::Command::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning nix-store --dump")
                .map_err(|e| {
                    tracing::error!(store_path = %store_path, error = %e, "NAR dump failed to spawn");
                    e
                })?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let mut zstd_child = Command::new("zstd")
                .args(["-c", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning zstd compressor")
                .map_err(|e| {
                    tracing::error!(store_path = %store_path, error = %e, "zstd compressor failed to spawn");
                    e
                })?;

            let zstd_stdout = zstd_child.stdout.take().context("no stdout from zstd")?;
            let stream = ReaderStream::new(zstd_stdout);
            Ok(Body::from_stream(stream))
        }
        Compression::Xz { level } => {
            let mut dump = std::process::Command::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning nix-store --dump")
                .map_err(|e| {
                    tracing::error!(store_path = %store_path, error = %e, "NAR dump failed to spawn");
                    e
                })?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let mut xz_child = Command::new("xz")
                .args(["-c", "-T0", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning xz compressor")
                .map_err(|e| {
                    tracing::error!(store_path = %store_path, error = %e, "xz compressor failed to spawn");
                    e
                })?;

            let xz_stdout = xz_child.stdout.take().context("no stdout from xz")?;
            let stream = ReaderStream::new(xz_stdout);
            Ok(Body::from_stream(stream))
        }
    }
}

/// Computes `(file_hash, file_size)` of a store path's compressed NAR —
/// i.e. the SHA-256 and byte length of exactly what [`nar_stream`] would
/// emit for the given [`Compression`].
///
/// Used to populate the `FileHash` / `FileSize` fields of the narinfo
/// response ([`crate::narinfo::format_narinfo`]); the corresponding
/// `NarHash` / `NarSize` come from the Nix DB and describe the uncompressed
/// NAR instead. The returned hash is formatted as `sha256:{base16}`.
///
/// Buffers the whole compressed stream in memory — fine for the small
/// paths typical in tests and `apm install` consumers, but a future
/// streaming-hash refactor would be friendlier to large closures.
///
/// # Errors
///
/// Returns an error if the dump/compression pipeline cannot be spawned or
/// exits unsuccessfully (see [`nar_bytes`]).
pub fn compute_file_hash_size(store_path: &str, compression: Compression) -> Result<(String, u64)> {
    let bytes = nar_bytes(store_path, compression)?;
    let digest = Sha256::digest(&bytes);
    Ok((
        format!("sha256:{}", hex::encode(digest)),
        bytes.len() as u64,
    ))
}

/// Returns the exact compressed NAR bytes for a store path, fully buffered
/// in memory.
///
/// This is used for byte-range responses, where the server must know the full
/// response length before it can answer a `Range:` request. Normal full-body
/// NAR GETs still use [`nar_stream`] to avoid buffering.
///
/// # Errors
///
/// Returns an error if `nix-store --dump` or the compressor cannot be
/// spawned, or if the pipeline exits with a non-zero status.
pub fn nar_bytes(store_path: &str, compression: Compression) -> Result<Vec<u8>> {
    use std::process::Command as StdCommand;

    let output = match compression {
        Compression::None => StdCommand::new("nix-store")
            .envs(aos_nix_env())
            .args(["--dump", store_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .with_context(|| format!("nix-store --dump {store_path}"))?,
        Compression::Zstd { level } => {
            let mut dump = StdCommand::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("spawning nix-store --dump {store_path}"))?;
            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();
            let level_arg = format!("-{level}");
            let out = StdCommand::new("zstd")
                .args(["-c", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .context("spawning zstd")?;
            let dump_status = dump.wait().context("waiting for nix-store --dump")?;
            if !dump_status.success() {
                anyhow::bail!("NAR dump failed for {store_path}");
            }
            out
        }
        Compression::Xz { level } => {
            let mut dump = StdCommand::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("spawning nix-store --dump {store_path}"))?;
            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();
            let level_arg = format!("-{level}");
            let out = StdCommand::new("xz")
                .args(["-c", "-T0", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .context("spawning xz")?;
            let dump_status = dump.wait().context("waiting for nix-store --dump")?;
            if !dump_status.success() {
                anyhow::bail!("NAR dump failed for {store_path}");
            }
            out
        }
    };

    if !output.status.success() {
        anyhow::bail!("compression pipeline failed for {store_path}");
    }

    Ok(output.stdout)
}

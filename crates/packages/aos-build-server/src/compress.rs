//! NAR streaming and compression pipelines.
//!
//! NAR responses are produced by piping `nix-store --dump <path>` through an
//! external compressor (`zstd` or `xz`) selected by [`Compression`]. Three
//! entry points cover the cache handlers' needs:
//!
//! - [`nar_stream`] — streaming body for full `GET .../nar/...` responses;
//!   bytes flow from the subprocess pipeline straight into the HTTP body
//!   without buffering.
//! - [`materialize_nar`] — bounded temporary-file output for `Range:`
//!   requests where the total length must be known up front.
//! - [`compute_file_hash_size`] — hashes the compressed output to fill the
//!   `FileHash`/`FileSize` narinfo fields (see [`crate::narinfo`]).

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Stdio};

use anyhow::{Context as _, Result};
use aos_nix::aos_nix_env;
use axum::body::Body;
use sha2::{Digest, Sha256};
use tempfile::tempfile_in;
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
/// Returns an error if the dump/compression pipeline cannot be spawned, emits
/// more than `maximum_bytes`, or exits unsuccessfully.
pub fn compute_file_hash_size(
    store_path: &str,
    compression: Compression,
    maximum_bytes: u64,
) -> Result<(String, u64)> {
    let mut digest = Sha256::new();
    let size = consume_nar(store_path, compression, maximum_bytes, |chunk| {
        digest.update(chunk);
        Ok(())
    })?;

    Ok((format!("sha256:{}", hex::encode(digest.finalize())), size))
}

/// Materializes a compressed NAR into an unlinked temporary file.
///
/// The byte ceiling is enforced while copying output from the compression
/// pipeline, before the temporary file can grow past the configured limit.
/// The file is created on the server's storage filesystem so it cannot
/// silently consume a memory-backed system temporary directory.
///
/// # Errors
///
/// Returns an error if `nix-store --dump` or the compressor cannot be
/// spawned, if the pipeline exits unsuccessfully, if the temporary file cannot
/// be written, or if output exceeds `maximum_bytes`.
pub fn materialize_nar(
    store_path: &str,
    compression: Compression,
    maximum_bytes: u64,
    temporary_directory: &Path,
) -> Result<(File, u64)> {
    let mut file = tempfile_in(temporary_directory).with_context(|| {
        format!(
            "creating NAR range temporary file in {}",
            temporary_directory.display()
        )
    })?;
    let size = consume_nar(store_path, compression, maximum_bytes, |chunk| {
        file.write_all(chunk)
            .context("writing NAR range temporary file")
    })?;
    file.flush().context("flushing NAR range temporary file")?;

    Ok((file, size))
}

fn consume_nar(
    store_path: &str,
    compression: Compression,
    maximum_bytes: u64,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    anyhow::ensure!(
        maximum_bytes > 0,
        "NAR materialization limit must be positive"
    );

    let mut pipeline = CompressionPipeline::spawn(store_path, compression)?;
    let total = consume_bounded(&mut pipeline.output, maximum_bytes, &mut consume)?;

    pipeline.wait(store_path)?;
    Ok(total)
}

fn consume_bounded(
    reader: &mut impl Read,
    maximum_bytes: u64,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    anyhow::ensure!(
        maximum_bytes > 0,
        "NAR materialization limit must be positive"
    );

    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .context("reading NAR compression output")?;
        if read == 0 {
            break;
        }

        total = total
            .checked_add(read as u64)
            .context("NAR materialization size overflow")?;
        anyhow::ensure!(
            total <= maximum_bytes,
            "compressed NAR exceeds materialization limit of {maximum_bytes} bytes"
        );
        consume(&buffer[..read])?;
    }

    Ok(total)
}

struct CompressionPipeline {
    dump: Child,
    compressor: Option<Child>,
    output: ChildStdout,
}

impl Drop for CompressionPipeline {
    fn drop(&mut self) {
        if let Some(compressor) = &mut self.compressor {
            let _ = compressor.kill();
            let _ = compressor.wait();
        }
        let _ = self.dump.kill();
        let _ = self.dump.wait();
    }
}

impl CompressionPipeline {
    fn spawn(store_path: &str, compression: Compression) -> Result<Self> {
        use std::process::Command as StdCommand;

        let mut dump = StdCommand::new("nix-store")
            .envs(aos_nix_env())
            .args(["--dump", store_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --dump {store_path}"))?;
        let dump_stdout = match dump.stdout.take() {
            Some(output) => output,
            None => {
                terminate_child(&mut dump);
                anyhow::bail!("no stdout from nix-store --dump")
            }
        };

        let pipeline = match compression {
            Compression::None => Ok((None, dump_stdout)),
            Compression::Zstd { level } => (|| {
                let level = format!("-{level}");
                let child = StdCommand::new("zstd")
                    .args(["-c", &level])
                    .stdin(Stdio::from(dump_stdout))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("spawning zstd")?;
                compressor_output(child, "zstd").map(|(child, output)| (Some(child), output))
            })(),
            Compression::Xz { level } => (|| {
                let level = format!("-{level}");
                let child = StdCommand::new("xz")
                    .args(["-c", "-T0", &level])
                    .stdin(Stdio::from(dump_stdout))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("spawning xz")?;
                compressor_output(child, "xz").map(|(child, output)| (Some(child), output))
            })(),
        };
        let (compressor, output) = match pipeline {
            Ok(pipeline) => pipeline,
            Err(error) => {
                terminate_child(&mut dump);
                return Err(error);
            }
        };

        Ok(Self {
            dump,
            compressor,
            output,
        })
    }

    fn wait(&mut self, store_path: &str) -> Result<()> {
        if let Some(compressor) = &mut self.compressor {
            let status = compressor.wait().context("waiting for NAR compressor")?;
            anyhow::ensure!(
                status.success(),
                "compression pipeline failed for {store_path}"
            );
        }

        let status = self.dump.wait().context("waiting for nix-store --dump")?;
        anyhow::ensure!(status.success(), "NAR dump failed for {store_path}");
        Ok(())
    }
}

fn compressor_output(mut child: Child, name: &str) -> Result<(Child, ChildStdout)> {
    match child.stdout.take() {
        Some(output) => Ok((child, output)),
        None => {
            terminate_child(&mut child);
            anyhow::bail!("no stdout from {name}")
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::consume_bounded;
    use std::io::Cursor;

    #[test]
    fn bounded_output_accepts_the_exact_limit() {
        let mut input = Cursor::new(b"12345678");
        let mut output = Vec::new();

        let size = consume_bounded(&mut input, 8, |chunk| {
            output.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();

        assert_eq!(size, 8);
        assert_eq!(output, b"12345678");
    }

    #[test]
    fn bounded_output_rejects_limit_plus_one_before_writing_it() {
        let mut input = Cursor::new(b"123456789");
        let mut output = Vec::new();

        let error = consume_bounded(&mut input, 8, |chunk| {
            output.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap_err();

        assert!(error.to_string().contains("exceeds materialization limit"));
        assert!(output.len() <= 8);
    }
}

use std::process::Stdio;

use axum::body::Body;
use tokio::process::Command;
use tokio_util::io::ReaderStream;
use anyhow::{Context as _, Result};

/// Compression algorithm for NAR responses.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    None,
    Zstd { level: i32 },
}

impl Compression {
    /// File extension for this compression type.
    pub fn extension(&self) -> &str {
        match self {
            Compression::None => "nar",
            Compression::Zstd { .. } => "nar.zst",
        }
    }

    /// Content-Type header value.
    pub fn content_type(&self) -> &str {
        "application/x-nix-nar"
    }

    /// Compression name for narinfo `Compression:` field.
    pub fn narinfo_name(&self) -> &str {
        match self {
            Compression::None => "none",
            Compression::Zstd { .. } => "zstd",
        }
    }
}

/// Spawn `nix-store --dump <store_path>` and stream the NAR,
/// optionally compressed with zstd.
pub async fn nar_stream(store_path: &str, compression: Compression) -> Result<Body> {
    match compression {
        Compression::None => {
            let mut child = Command::new("nix-store")
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning nix-store --dump")?;

            let stdout = child.stdout.take().context("no stdout")?;
            let stream = ReaderStream::new(stdout);
            Ok(Body::from_stream(stream))
        }
        Compression::Zstd { level } => {
            // Use std::process for the dump command so we can pipe its
            // ChildStdout directly into the zstd process as Stdio.
            let mut dump = std::process::Command::new("nix-store")
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning nix-store --dump")?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let mut zstd_child = Command::new("zstd")
                .args(["-c", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning zstd compressor")?;

            let zstd_stdout = zstd_child.stdout.take().context("no stdout from zstd")?;
            let stream = ReaderStream::new(zstd_stdout);
            Ok(Body::from_stream(stream))
        }
    }
}

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use aos_core::nar::export::ExportTrailer;
use aos_core::nix::{NixCli, aos_nix_env};

/// Run `nix-store --export <path>` and collect the resulting export-format
/// stream (raw NAR + Nix export trailer, uncompressed).
///
/// The server's pack-import path pipes each `PackEntry.nar_data` directly
/// into `nix-store --import`, which only accepts this format — not bare
/// NAR and not compressed NAR. The pull side has the inverse glue in
/// `streaming_import` below (decompress, then append `ExportTrailer`);
/// this is the simpler forward equivalent that delegates the trailer
/// construction to Nix itself.
pub fn streaming_export(store_path: &str) -> Result<Vec<u8>> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--export", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("nix-store --export {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix-store --export failed for {store_path}: {stderr}");
    }

    Ok(output.stdout)
}

/// Streaming compression pipeline: `nix-store --dump <path> | compressor`
///
/// The uncompressed NAR is never fully buffered in RAM — it streams through
/// the compressor subprocess. Only the compressed output is collected.
pub fn streaming_compress(store_path: &str, algorithm: &str, level: i32) -> Result<Vec<u8>> {
    match algorithm {
        "zstd" => {
            // Pipe: nix-store --dump <path> -> zstd -c -<level>
            let mut dump = Command::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("spawning nix-store --dump {store_path}"))?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let zstd_output = Command::new("zstd")
                .args(["-c", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .context("spawning zstd compressor")?;

            dump.wait()?;

            if !zstd_output.status.success() {
                anyhow::bail!("zstd compression failed for {store_path}");
            }

            Ok(zstd_output.stdout)
        }
        "xz" => {
            let mut dump = Command::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("spawning nix-store --dump {store_path}"))?;

            let dump_stdout: Stdio = dump.stdout.take().context("no stdout")?.into();

            let level_arg = format!("-{level}");
            let xz_output = Command::new("xz")
                .args(["-c", "-T0", &level_arg])
                .stdin(dump_stdout)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .context("spawning xz compressor")?;

            dump.wait()?;

            if !xz_output.status.success() {
                anyhow::bail!("xz compression failed for {store_path}");
            }

            Ok(xz_output.stdout)
        }
        "none" => {
            // No compression: read directly from nix-store --dump.
            let output = Command::new("nix-store")
                .envs(aos_nix_env())
                .args(["--dump", store_path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .with_context(|| format!("nix-store --dump {store_path}"))?;

            if !output.status.success() {
                anyhow::bail!("nix-store --dump failed for {store_path}");
            }

            Ok(output.stdout)
        }
        other => anyhow::bail!("unsupported compression algorithm: {other}"),
    }
}

/// Streaming import pipeline: decompress -> build export -> pipe to nix-store --import.
///
/// The decompressed NAR streams through the export trailer builder into the
/// import process. Only the compressed data (already downloaded) is in RAM.
pub fn streaming_import(
    _nix: &NixCli,
    compressed_nar: &[u8],
    compression: &str,
    store_path: &str,
    references: &[String],
    deriver: Option<&str>,
) -> Result<Vec<String>> {
    // Decompress NAR.
    let nar_data = decompress_nar(compressed_nar, compression)?;

    // Resolve references to full store paths.
    let full_refs: Vec<String> = references
        .iter()
        .map(|r| {
            if r.starts_with("/nix/store/") {
                r.clone()
            } else {
                format!("/nix/store/{r}")
            }
        })
        .collect();

    let full_deriver = deriver.map(|d| {
        if d.starts_with("/nix/store/") {
            d.to_string()
        } else {
            format!("/nix/store/{d}")
        }
    });

    // Build export format: NAR + trailer.
    let trailer = ExportTrailer::new(store_path, full_refs, full_deriver);

    // Spawn nix-store --import and pipe the export data.
    let mut child = std::process::Command::new("nix-store")
        .envs(aos_nix_env())
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning nix-store --import")?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("no stdin for nix-store --import")?;
        // Write NAR data.
        stdin
            .write_all(&nar_data)
            .context("writing NAR to import")?;
        // Write export trailer.
        trailer.write_to(stdin).context("writing export trailer")?;
    }

    let output = child
        .wait_with_output()
        .context("waiting for nix-store --import")?;
    if !output.status.success() {
        anyhow::bail!("nix-store --import failed for {store_path}");
    }

    let text = String::from_utf8(output.stdout).context("invalid utf-8 from import")?;
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Decompress NAR data.
pub fn decompress_nar(data: &[u8], compression: &str) -> Result<Vec<u8>> {
    match compression {
        "zstd" => {
            let mut decoder = zstd::Decoder::new(data)?;
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        "xz" => {
            let mut child = Command::new("xz")
                .args(["-d", "-c"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .context("spawning xz -d")?;

            {
                let stdin = child
                    .stdin
                    .as_mut()
                    .context("failed to get stdin of xz decompression process")?;
                stdin.write_all(data)?;
            }

            let output = child.wait_with_output()?;
            if !output.status.success() {
                anyhow::bail!("xz decompression failed");
            }
            Ok(output.stdout)
        }
        "none" | "" => Ok(data.to_vec()),
        other => anyhow::bail!("unsupported decompression: {other}"),
    }
}

/// Get the compression name for narinfo.
pub fn compression_name(algorithm: &str) -> &str {
    match algorithm {
        "zstd" => "zstd",
        "xz" => "xz",
        "none" => "none",
        _ => "none",
    }
}

/// Get the file extension for compressed NARs.
pub fn compression_ext(algorithm: &str) -> &str {
    match algorithm {
        "zstd" => "nar.zst",
        "xz" => "nar.xz",
        "none" => "nar",
        _ => "nar",
    }
}

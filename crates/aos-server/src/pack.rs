//! The AOS pack wire format ("AOSP") and pack import.
//!
//! A *pack* batches multiple NAR-serialized store paths into one upload so
//! a client can push a whole closure in a single
//! `POST /{view}/upload-pack` request instead of one PUT per path.
//!
//! # Wire format (version 1, all integers big-endian)
//!
//! ```text
//! header:   "AOSP" magic (4) | version u32 (4) | entry count u32 (4)
//! entry *N: store hash, 32 hex ASCII bytes | NAR size u64 (8) | NAR data
//! trailer:  SHA-256 digest of everything before it (32)
//! ```
//!
//! [`create_pack`] and [`parse_pack`] round-trip this format;
//! [`import_pack`] feeds each entry to `nix-store --import` and then
//! security-screens the resulting paths with [`validate_imported_path`],
//! which only admits `.drv` files and content-addressed (fixed-output)
//! paths — anything else could smuggle arbitrary binaries into the store
//! under an input-addressed name.

use sha2::{Digest, Sha256};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

use aos_core::nix::{aos_nix_command, aos_tokio_nix_command};

const MAGIC: &[u8; 4] = b"AOSP";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 4 + 4 + 4; // magic + version + entry count
const HASH_HEX_LEN: usize = 32;
const TRAILER_SIZE: usize = 32; // SHA-256 digest

/// A single entry in the pack wire format.
#[derive(Debug, Clone)]
pub struct PackEntry {
    /// 32-character hex store path hash.
    pub hash: String,
    /// Raw NAR data (as produced by `nix-store --export`).
    pub nar_data: Vec<u8>,
}

/// Parses a pack from its wire format into its entries.
///
/// The trailing SHA-256 checksum is verified before any entry is parsed,
/// so a corrupted upload is rejected wholesale.
///
/// # Errors
///
/// Returns a descriptive message if the data is too short, the checksum
/// does not match, the magic or version is wrong, an entry is truncated or
/// has a non-UTF-8 hash, or unconsumed bytes remain after the last entry.
pub fn parse_pack(data: &[u8]) -> Result<Vec<PackEntry>, String> {
    if data.len() < HEADER_SIZE + TRAILER_SIZE {
        return Err("data too short for pack header and trailer".into());
    }

    // Verify trailing SHA-256 checksum.
    let payload = &data[..data.len() - TRAILER_SIZE];
    let trailer = &data[data.len() - TRAILER_SIZE..];
    let digest = Sha256::digest(payload);
    if digest.as_slice() != trailer {
        return Err("SHA-256 trailer mismatch".into());
    }

    let mut pos = 0;

    // Magic.
    if &data[pos..pos + 4] != MAGIC {
        return Err(format!(
            "bad magic: expected {:?}, got {:?}",
            MAGIC,
            &data[pos..pos + 4]
        ));
    }
    pos += 4;

    // Version.
    let version = u32::from_be_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| "failed to read version")?,
    );
    if version != VERSION {
        return Err(format!("unsupported pack version: {version}"));
    }
    pos += 4;

    // Entry count.
    let count = u32::from_be_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| "failed to read entry count")?,
    ) as usize;
    pos += 4;

    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        // Store path hash (32 bytes of hex ASCII).
        if pos + HASH_HEX_LEN > payload.len() {
            return Err(format!("entry {i}: unexpected end of data reading hash"));
        }
        let hash = std::str::from_utf8(&data[pos..pos + HASH_HEX_LEN])
            .map_err(|_| format!("entry {i}: hash is not valid UTF-8"))?
            .to_string();
        pos += HASH_HEX_LEN;

        // NAR size (u64 BE).
        if pos + 8 > payload.len() {
            return Err(format!(
                "entry {i}: unexpected end of data reading NAR size"
            ));
        }
        let nar_size = u64::from_be_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| format!("entry {i}: failed to read NAR size"))?,
        ) as usize;
        pos += 8;

        // NAR data.
        if pos + nar_size > payload.len() {
            return Err(format!(
                "entry {i}: NAR data extends past payload (need {nar_size} bytes at offset {pos}, have {})",
                payload.len() - pos
            ));
        }
        let nar_data = data[pos..pos + nar_size].to_vec();
        pos += nar_size;

        entries.push(PackEntry { hash, nar_data });
    }

    if pos != payload.len() {
        return Err(format!(
            "trailing data: {pos} bytes consumed but payload is {} bytes",
            payload.len()
        ));
    }

    Ok(entries)
}

/// Serializes entries into the pack wire format, including the header and
/// SHA-256 trailer.
///
/// The output round-trips through [`parse_pack`].
pub fn create_pack(entries: &[PackEntry]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header.
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_be_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    // Entries.
    for entry in entries {
        buf.extend_from_slice(entry.hash.as_bytes());
        buf.extend_from_slice(&(entry.nar_data.len() as u64).to_be_bytes());
        buf.extend_from_slice(&entry.nar_data);
    }

    // SHA-256 trailer.
    let digest = Sha256::digest(&buf);
    buf.extend_from_slice(&digest);

    buf
}

/// Validates that an imported store path is safe to accept.
///
/// Only two classes of path are admitted:
///
/// - `.drv` files — build recipes, not binaries, so always safe; and
/// - content-addressed (fixed-output) paths, detected by the presence of a
///   `ca` field in `nix path-info --json` output — their store hash is
///   derived from their contents, so a client cannot substitute malicious
///   bytes under a trusted name.
///
/// Everything else (regular input-addressed build outputs) is rejected;
/// such paths must be produced by the server's own builds instead of being
/// uploaded directly.
///
/// Note this consults the Nix store, so the path must already be imported
/// when called (it is used post-import to vet `nix-store --import` results).
///
/// # Errors
///
/// Returns a reason string if the path is neither a `.drv` nor
/// content-addressed, or if `nix path-info` cannot be run or its output
/// cannot be parsed.
pub fn validate_imported_path(store_path: &str) -> Result<(), String> {
    // .drv files are always safe (they're build recipes, not binaries)
    if store_path.ends_with(".drv") {
        return Ok(());
    }

    // Check if the path is content-addressed by querying nix path-info.
    // Content-addressed paths have a "ca" field in their narinfo.
    //
    // `nix path-info` is part of the "new" CLI and only runs when the
    // `nix-command` experimental feature is enabled — without it the
    // process exits non-zero with `error: experimental Nix feature
    // 'nix-command' is disabled` on stderr. The aos rootfs ships no
    // system-wide `nix.conf`, so we have to opt in per-invocation.
    let output = aos_nix_command("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--json",
            store_path,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("failed to query path info: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "nix path-info failed for {store_path}: {}",
            stderr.trim()
        ));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    // nix path-info --json returns an array of objects or {path: {info}} format
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("failed to parse path info: {e}"))?;

    // Check for "ca" field which indicates content-addressed / fixed-output
    let has_ca = if let Some(arr) = parsed.as_array() {
        arr.first().and_then(|obj| obj.get("ca")).is_some()
    } else if let Some(obj) = parsed.as_object() {
        // Some versions return {path: {info}} format
        obj.values().next().and_then(|v| v.get("ca")).is_some()
    } else {
        false
    };

    if has_ca {
        Ok(())
    } else {
        tracing::warn!(path = %store_path, "imported path rejected: not .drv or content-addressed");
        Err(format!(
            "rejected: {store_path} is neither a .drv nor a content-addressed path"
        ))
    }
}

/// Imports pack entries into the Nix store via `nix-store --import`.
///
/// Entries are imported sequentially; every resulting store path is vetted
/// with [`validate_imported_path`] before being included in the returned
/// list. The import stops at the first failure, so earlier entries may
/// already be in the store when an error is returned.
///
/// # Errors
///
/// Returns a reason string if spawning or waiting on `nix-store --import`
/// fails, the import exits non-zero, or an imported path fails validation.
pub async fn import_pack(entries: &[PackEntry]) -> Result<Vec<String>, String> {
    tracing::info!(count = entries.len(), "importing pack entries");
    let mut paths = Vec::with_capacity(entries.len());

    for (i, entry) in entries.iter().enumerate() {
        let mut child = aos_tokio_nix_command("nix-store")
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("entry {i}: failed to spawn nix-store --import: {e}"))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("entry {i}: no stdin on child process"))?;

        let nar_data = entry.nar_data.clone();
        let stdin_task = tokio::spawn(async move {
            stdin.write_all(&nar_data).await?;
            stdin.shutdown().await?;
            Ok::<(), std::io::Error>(())
        });

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("entry {i}: waiting for nix-store --import: {e}"))?;

        // Join the stdin writer task and propagate errors.
        match stdin_task.await {
            Ok(Err(e)) => {
                tracing::warn!(entry = i, hash = %entry.hash, error = %e, "stdin write error during pack import");
            }
            Err(e) => {
                tracing::warn!(entry = i, hash = %entry.hash, error = %e, "stdin writer task panicked during pack import");
            }
            Ok(Ok(())) => {}
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(entry = i, hash = %entry.hash, stderr = %stderr, "pack entry import failed");
            return Err(format!(
                "entry {i} ({}): nix-store --import failed: {stderr}",
                entry.hash
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                // Validate the imported path
                if let Err(reason) = validate_imported_path(trimmed) {
                    return Err(format!("entry {i} ({}): {reason}", entry.hash));
                }
                paths.push(trimmed.to_string());
            }
        }
    }

    Ok(paths)
}

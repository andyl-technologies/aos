use sha2::{Digest, Sha256};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

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
    /// Raw NAR data.
    pub nar_data: Vec<u8>,
}

/// Parse a pack from its wire format.
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
            return Err(format!("entry {i}: unexpected end of data reading NAR size"));
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

/// Serialize entries into the pack wire format.
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

/// Validate that an imported store path is safe to accept.
/// Returns Ok(()) if the path is a .drv or content-addressed (fixed-output) path.
/// Returns Err with a reason string if the path should be rejected.
pub fn validate_imported_path(store_path: &str) -> Result<(), String> {
    // .drv files are always safe (they're build recipes, not binaries)
    if store_path.ends_with(".drv") {
        return Ok(());
    }

    // Check if the path is content-addressed by querying nix path-info.
    // Content-addressed paths have a "ca" field in their narinfo.
    let output = std::process::Command::new("nix")
        .args(["path-info", "--json", store_path])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("failed to query path info: {e}"))?;

    if !output.status.success() {
        return Err(format!("path not found in store: {store_path}"));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    // nix path-info --json returns an array of objects or {path: {info}} format
    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("failed to parse path info: {e}"))?;

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
        Err(format!(
            "rejected: {store_path} is neither a .drv nor a content-addressed path"
        ))
    }
}

/// Import pack entries into the Nix store via `nix-store --import`.
pub async fn import_pack(entries: &[PackEntry]) -> Result<Vec<String>, String> {
    let mut paths = Vec::with_capacity(entries.len());

    for (i, entry) in entries.iter().enumerate() {
        let mut child = Command::new("nix-store")
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
        tokio::spawn(async move {
            let _ = stdin.write_all(&nar_data).await;
            let _ = stdin.shutdown().await;
        });

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("entry {i}: waiting for nix-store --import: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
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
                    // TODO: ideally we'd delete the imported path, but nix-store
                    // doesn't support targeted deletion. The path will be GC'd
                    // if not rooted.
                    return Err(format!("entry {i} ({}): {reason}", entry.hash));
                }
                paths.push(trimmed.to_string());
            }
        }
    }

    Ok(paths)
}

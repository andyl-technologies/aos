//! Deterministic dm-verity reconstruction and command-line binding.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::assembly::ImageLayoutV1;
use crate::tools::PinnedTool;

const MAX_VERITY_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Finalized dm-verity artifacts for the rebuilt immutable root.
#[derive(Clone, Debug)]
pub struct VerityOutputV1 {
    /// Deterministic hash-tree image.
    pub hash_tree: PathBuf,
    /// ASCII lowercase hexadecimal root hash file.
    pub root_hash_file: PathBuf,
    /// Lowercase hexadecimal root hash embedded into normal UKIs.
    pub root_hash: String,
}

/// Formats and independently verifies deterministic dm-verity data.
///
/// # Errors
///
/// Returns an error when an output exists, formatting fails, root-hash parsing
/// is ambiguous, the hash tree exceeds its partition, or independent
/// verification/dump evidence differs from the captured salt and UUID.
pub async fn build_verity(
    veritysetup: &PinnedTool,
    root_filesystem: &Path,
    output_directory: &Path,
    layout: &ImageLayoutV1,
) -> Result<VerityOutputV1> {
    let hash_tree = output_directory.join("root.verity");
    let root_hash_file = output_directory.join("root.roothash");
    if hash_tree.symlink_metadata().is_ok() || root_hash_file.symlink_metadata().is_ok() {
        bail!("dm-verity output already exists");
    }
    let format = veritysetup
        .run(
            [
                "format",
                "--salt",
                &layout.verity_salt,
                "--uuid",
                &layout.verity_uuid,
                path_text(root_filesystem)?,
                path_text(&hash_tree)?,
            ],
            MAX_VERITY_OUTPUT_BYTES,
        )
        .await?;
    let root_hash = parse_root_hash(&format.stdout)?;
    let maximum_hash_bytes = layout
        .verity_partition_mib
        .checked_mul(1024 * 1024)
        .context("verity partition byte budget overflow")?;
    let metadata = hash_tree.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_hash_bytes {
        bail!("dm-verity tree is empty, special, or exceeds its partition");
    }

    let _ = veritysetup
        .run(
            [
                "verify",
                path_text(root_filesystem)?,
                path_text(&hash_tree)?,
                &root_hash,
            ],
            MAX_VERITY_OUTPUT_BYTES,
        )
        .await?;
    let dump = veritysetup
        .run(["dump", path_text(&hash_tree)?], MAX_VERITY_OUTPUT_BYTES)
        .await?;
    verify_dump(&dump.stdout, layout)?;
    write_new(&root_hash_file, root_hash.as_bytes())?;
    Ok(VerityOutputV1 {
        hash_tree,
        root_hash_file,
        root_hash,
    })
}

/// Replaces exactly one prior `roothash=` token with the finalized value.
///
/// # Errors
///
/// Returns an error when the new hash is malformed or the source command line
/// does not contain exactly one well-formed prior root hash.
pub fn bind_root_hash(command_line: &str, root_hash: &str) -> Result<String> {
    require_root_hash(root_hash)?;
    let mut found = 0_u8;
    let mut output = Vec::new();
    for token in command_line.split_ascii_whitespace() {
        if let Some(value) = token.strip_prefix("roothash=") {
            require_root_hash(value)?;
            found = found.checked_add(1).context("root hash count overflow")?;
            output.push(format!("roothash={root_hash}"));
        } else {
            output.push(token.to_owned());
        }
    }
    if found != 1 {
        bail!("normal kernel command line must contain exactly one roothash token");
    }
    Ok(output.join(" "))
}

fn parse_root_hash(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("dm-verity format output is not UTF-8")?;
    let hashes = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(label, _)| label.trim() == "Root hash")
        .map(|(_, value)| value.trim().to_owned())
        .collect::<Vec<_>>();
    if hashes.len() != 1 {
        bail!("dm-verity format output lacks one unambiguous root hash");
    }
    require_root_hash(&hashes[0])?;
    Ok(hashes[0].clone())
}

fn verify_dump(bytes: &[u8], layout: &ImageLayoutV1) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("dm-verity dump output is not UTF-8")?;
    let field = |wanted: &str| {
        text.lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(label, _)| label.trim() == wanted)
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>()
    };
    let uuid = field("UUID");
    let salt = field("Salt");
    if uuid.as_slice() != [layout.verity_uuid.as_str()]
        || salt.as_slice() != [layout.verity_salt.as_str()]
    {
        bail!("dm-verity dump differs from the captured UUID or salt");
    }
    Ok(())
}

fn require_root_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("dm-verity root hash must be 64 lowercase hexadecimal digits");
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("dm-verity path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_one_well_formed_root_hash() -> Result<()> {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        let bound = bind_root_hash(&format!("quiet roothash={old} root=a"), &new)?;
        assert_eq!(bound, format!("quiet roothash={new} root=a"));
        assert!(bind_root_hash("quiet", &new).is_err());
        assert!(bind_root_hash(&format!("roothash={old} roothash={old}"), &new).is_err());
        Ok(())
    }

    #[test]
    fn parses_one_exact_format_hash() -> Result<()> {
        let hash = "c".repeat(64);
        assert_eq!(
            parse_root_hash(format!("UUID: x\nRoot hash: {hash}\n").as_bytes())?,
            hash
        );
        assert!(parse_root_hash(b"Root hash: bad\n").is_err());
        Ok(())
    }
}

//! Admission of frozen Nix cache metadata against verified staged NAR bytes.
//!
//! Metadata uses the existing cache parser after strict scalar validation. The
//! compressed file identity binds the admitted inventory; the uncompressed NAR
//! identity remains separate and immutable when a store path already exists.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context as _, Result};
use aos_registry_format::{staging::StageObject, store};

const MAX_NARINFO_BYTES: usize = 1024 * 1024;

/// Admits one canonical narinfo without replacing an existing store identity.
///
/// # Errors
/// Returns an error for malformed metadata, an inventory mismatch, or an
/// altered existing archive identity, reference set, or signature.
pub(super) fn validate_narinfo(
    path: &str,
    current: Option<&[u8]>,
    proposed: &[u8],
    inventory: &BTreeMap<&str, &StageObject>,
) -> Result<()> {
    let hash = path
        .strip_suffix(".narinfo")
        .context("invalid narinfo path")?;
    ensure!(
        hash.len() == 32 && !hash.contains('/'),
        "narinfo filename must identify a canonical store hash"
    );
    let fields = metadata_fields(proposed)?;
    let store_path = required(&fields, "StorePath")?;
    ensure!(
        store_path
            .strip_prefix("/nix/store/")
            .is_some_and(|name| !name.contains('/'))
            && store::store_path_hash(store_path)? == hash,
        "narinfo StorePath differs from its filename"
    );
    let nar_hash = store::canonical_digest_hex(required(&fields, "NarHash")?)?;
    let nar_size = required(&fields, "NarSize")?.parse::<u64>()?;
    let file_hash = store::canonical_digest_hex(required(&fields, "FileHash")?)?;
    let file_size = required(&fields, "FileSize")?.parse::<u64>()?;
    let text = std::str::from_utf8(proposed)?;
    let parsed = aos_hub_model::cache::parse_cache_narinfo(0, hash, text, 0)
        .context("narinfo is missing cache metadata")?;
    let extension = match parsed.compression.as_str() {
        "none" => {
            ensure!(
                nar_hash == file_hash && nar_size == file_size,
                "uncompressed NAR file and archive identity differ"
            );
            "nar"
        }
        "zstd" => "nar.zst",
        "xz" => "nar.xz",
        _ => anyhow::bail!("narinfo uses unsupported compression"),
    };
    let expected_url = format!("nar/{hash}-sha256-{file_hash}.{extension}");
    ensure!(
        parsed.nar_url == expected_url,
        "narinfo URL does not identify its compressed FileHash"
    );
    let object = inventory
        .get(expected_url.as_str())
        .context("narinfo names a NAR outside the verified stage inventory")?;
    ensure!(
        object.sha256 == format!("sha256:{file_hash}") && object.byte_size == file_size,
        "narinfo FileHash/FileSize differ from the verified NAR inventory"
    );

    if let Some(current) = current {
        let old = metadata_fields(current)?;
        ensure!(
            required(&old, "StorePath")? == store_path
                && store::canonical_digest_hex(required(&old, "NarHash")?)? == nar_hash
                && required(&old, "NarSize")?.parse::<u64>()? == nar_size,
            "stage narinfo changes an existing uncompressed store identity"
        );
        ensure!(
            reference_set(&old) == reference_set(&fields),
            "stage narinfo changes existing store references"
        );
        let old =
            aos_hub_model::cache::parse_cache_narinfo(0, hash, std::str::from_utf8(current)?, 0)
                .context("existing narinfo is malformed")?;
        let signatures = parsed.signature.as_deref().unwrap_or_default();
        let signatures = signatures.lines().collect::<BTreeSet<_>>();
        ensure!(
            old.signature
                .as_deref()
                .unwrap_or_default()
                .lines()
                .all(|signature| signatures.contains(signature)),
            "stage narinfo removes an existing cache signature"
        );
    }
    Ok(())
}

/// Preserves the shared store root while admitting the standard cache marker.
///
/// # Errors
/// Returns an error for malformed fields or a changed store directory.
pub(super) fn validate_cache_info(current: Option<&[u8]>, proposed: &[u8]) -> Result<()> {
    let fields = metadata_fields(proposed)?;
    ensure!(
        fields
            .keys()
            .all(|key| matches!(*key, "StoreDir" | "WantMassQuery" | "Priority")),
        "stage cache info contains unsupported metadata"
    );
    let store_dir = required(&fields, "StoreDir")?;
    ensure!(
        store_dir == "/nix/store",
        "stage cache info changes the store root"
    );
    ensure!(
        matches!(required(&fields, "WantMassQuery")?, "0" | "1"),
        "stage cache info has invalid WantMassQuery"
    );
    required(&fields, "Priority")?.parse::<u32>()?;
    if let Some(current) = current {
        ensure!(
            required(&metadata_fields(current)?, "StoreDir")? == store_dir,
            "stage cache info changes an existing store root"
        );
    }
    Ok(())
}

fn metadata_fields(bytes: &[u8]) -> Result<BTreeMap<&str, &str>> {
    ensure!(
        bytes.len() <= MAX_NARINFO_BYTES,
        "stage cache metadata exceeds its byte limit"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let (key, value) = line
            .split_once(':')
            .context("invalid cache metadata line")?;
        let (key, value) = (key.trim(), value.trim());
        if key != "Sig" {
            ensure!(
                fields.insert(key, value).is_none(),
                "duplicate cache metadata field '{key}'"
            );
        }
    }
    Ok(fields)
}

fn required<'a>(fields: &BTreeMap<&str, &'a str>, name: &str) -> Result<&'a str> {
    fields
        .get(name)
        .copied()
        .with_context(|| format!("cache metadata is missing {name}"))
}

fn reference_set<'a>(fields: &BTreeMap<&str, &'a str>) -> BTreeSet<&'a str> {
    fields
        .get("References")
        .copied()
        .unwrap_or_default()
        .split_whitespace()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(file_hash: &str, signatures: &str) -> (String, Vec<u8>, StageObject) {
        let hash = "a".repeat(32);
        let url = format!("nar/{hash}-sha256-{file_hash}.nar.zst");
        let bytes = format!(
            "StorePath: /nix/store/{hash}-candidate\nURL: {url}\nCompression: zstd\nFileHash: sha256:{file_hash}\nFileSize: 7\nNarHash: sha256:{}\nNarSize: 100\nReferences: {}-dependency\n{signatures}",
            "2".repeat(64), "b".repeat(32),
        ).into_bytes();
        let object = StageObject {
            path: url,
            sha256: format!("sha256:{file_hash}"),
            byte_size: 7,
            kind: "cache".into(),
            media_type: "application/zstd".into(),
        };
        (format!("{hash}.narinfo"), bytes, object)
    }

    #[test]
    fn narinfo_binds_compressed_inventory_and_preserves_shared_identity() {
        let (path, old, _) = metadata(&"1".repeat(64), "Sig: old:signature\n");
        let (_, proposed, object) =
            metadata(&"3".repeat(64), "Sig: old:signature\nSig: new:signature\n");
        let inventory = BTreeMap::from([(object.path.as_str(), &object)]);

        validate_narinfo(&path, None, &proposed, &inventory).unwrap();
        validate_narinfo(&path, Some(&old), &proposed, &inventory).unwrap();
        assert!(validate_narinfo(&path, None, &proposed, &BTreeMap::new()).is_err());
        assert!(validate_narinfo(
            &format!("{}.narinfo", "b".repeat(32)),
            None,
            &proposed,
            &inventory
        )
        .is_err());

        for changed in [
            String::from_utf8(proposed.clone())
                .unwrap()
                .replace("NarSize: 100", "NarSize: 101"),
            String::from_utf8(proposed.clone())
                .unwrap()
                .replace(&"2".repeat(64), &"4".repeat(64)),
            String::from_utf8(proposed.clone())
                .unwrap()
                .replace("Sig: old:signature\n", ""),
            String::from_utf8(proposed.clone())
                .unwrap()
                .replace("FileSize: 7", "FileSize: 8"),
            format!(
                "{}FileHash: sha256:{}\n",
                String::from_utf8(proposed.clone()).unwrap(),
                "3".repeat(64)
            ),
        ] {
            assert!(validate_narinfo(&path, Some(&old), changed.as_bytes(), &inventory).is_err());
        }
    }

    #[test]
    fn cache_marker_keeps_the_existing_store_directory() {
        let old = b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n";
        let proposed = b"StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 30\n";

        validate_cache_info(None, proposed).unwrap();
        validate_cache_info(Some(old), proposed).unwrap();
        assert!(validate_cache_info(Some(b"StoreDir: /other/store\n"), proposed).is_err());
        assert!(validate_cache_info(
            None,
            b"StoreDir: /other/store\nWantMassQuery: 1\nPriority: 40\n"
        )
        .is_err());
        assert!(validate_cache_info(
            None,
            b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: bad\n"
        )
        .is_err());
    }
}

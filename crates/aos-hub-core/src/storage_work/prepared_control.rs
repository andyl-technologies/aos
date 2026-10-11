//! Frames prepared registry control bytes separately from their signed plan.
//!
//! The body is a four-byte big-endian plan length, the ordinary signed JSON
//! plan, then its exact hash-bound control bytes. The ordinary plan and response
//! limits remain unchanged. Packs, NARs and images are never control bodies.
//!
//! ```text
//! u32_be(plan_length) || signed_plan_json || exact_control_bytes
//! ```

use aos_registry_surface::{keymap, object, object_bundle, pack_index};
use sha2::{Digest as _, Sha256};

use super::{StorageWorkError, StorageWorkOperation, MAX_METADATA_BYTES, MAX_PLAN_BYTES};

/// Media type for a signed plan followed by its prepared control bytes.
pub const CONTENT_TYPE: &str = "application/vnd.aos.prepared-storage-control.v1";

/// Largest control representation already accepted by the staged revision schema.
pub const MAX_CONTROL_BYTES: usize =
    aos_registry_surface::staging::wire::MAX_DECODED_REVISION_BYTES;

/// Maximum complete frame; the JSON plan keeps its existing independent limit.
pub const MAX_FRAME_BYTES: usize = 4 + MAX_PLAN_BYTES + MAX_CONTROL_BYTES;

/// Reports whether a canonical mutable registry control path is supported.
#[must_use]
pub fn admitted_path(path: &str) -> bool {
    super::valid_relative_path(path, false)
        && keymap::is_mutable_path(path)
        && (matches!(
            path,
            "HEAD"
                | "info/refs"
                | "nix-cache-info"
                | "objects/info/packs"
                | "objects/info/alternates"
                | "tuf/timestamp.json"
        ) || super::admitted_narinfo_path(path)
            || keymap::is_loose_git_object_path(path)
            || keymap::is_git_pack_index_path(path)
            || keymap::is_release_object_info_path(path)
            || path.starts_with("channels/")
            || bundle_name(path).is_some()
            || (path.starts_with("web/")
                && [".json", ".html", ".css", ".js"]
                    .iter()
                    .any(|suffix| path.ends_with(suffix))))
}

/// Returns the existing semantic limit for one control representation.
#[must_use]
pub fn maximum_body_bytes(path: &str) -> usize {
    if keymap::is_git_pack_index_path(path) {
        pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES as usize
    } else if keymap::is_loose_git_object_path(path) {
        object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES as usize
    } else if bundle_name(path) == Some("all") {
        object_bundle::MAX_AGGREGATE_BUNDLE_BYTES
    } else if bundle_name(path).is_some() {
        object_bundle::MAX_BUNDLE_BYTES
    } else if path == "tuf/timestamp.json" {
        // Staged timestamp binding already bounds the complete TUF metadata set.
        8 * 1024 * 1024
    } else {
        MAX_METADATA_BYTES
    }
}

fn bundle_name(path: &str) -> Option<&str> {
    let name = path.strip_prefix("objects/aos-index-v1/")?;
    (name == "all" || object_bundle::shard_path(name).is_ok()).then_some(name)
}

/// Encodes a frame without changing the ordinary signed-plan format.
///
/// # Errors
/// Returns an error if either independent wire limit is exceeded.
pub fn encode_frame(plan: &[u8], control: &[u8]) -> Result<Vec<u8>, StorageWorkError> {
    if plan.is_empty() || plan.len() > MAX_PLAN_BYTES || control.len() > MAX_CONTROL_BYTES {
        return Err(StorageWorkError::InvalidPlan);
    }
    let length = u32::try_from(plan.len()).map_err(|_| StorageWorkError::InvalidPlan)?;
    let mut frame = Vec::with_capacity(4 + plan.len() + control.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(plan);
    frame.extend_from_slice(control);
    Ok(frame)
}

/// Borrows a frame's signed plan and exact control body without copying either.
///
/// # Errors
/// Returns an error for a truncated prefix, invalid length or exceeded wire limit.
pub fn split_frame(frame: &[u8]) -> Result<(&[u8], &[u8]), StorageWorkError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(StorageWorkError::InvalidPlan)?
        .try_into()
        .map_err(|_| StorageWorkError::InvalidPlan)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_PLAN_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(StorageWorkError::InvalidPlan);
    }
    let end = 4 + length;
    let plan = frame.get(4..end).ok_or(StorageWorkError::InvalidPlan)?;
    let control = frame.get(end..).ok_or(StorageWorkError::InvalidPlan)?;
    if control.len() > MAX_CONTROL_BYTES {
        return Err(StorageWorkError::InvalidPlan);
    }
    Ok((plan, control))
}

/// Checks the control body's exact identity committed by the authenticated plan.
///
/// # Errors
/// Returns an error for another operation, changed size or digest, or an oversized body.
pub fn validate_body(
    operation: &StorageWorkOperation,
    control: &[u8],
) -> Result<(), StorageWorkError> {
    let (path, size, sha256) = match operation {
        StorageWorkOperation::VerifyPreparedGitIndex {
            path, size, sha256, ..
        }
        | StorageWorkOperation::PutPreparedControl { path, size, sha256 } => (path, size, sha256),
        _ => return Err(StorageWorkError::InvalidPlan),
    };
    if control.len() as u64 != *size
        || control.len() > maximum_body_bytes(path)
        || hex::encode(Sha256::digest(control)) != *sha256
    {
        return Err(StorageWorkError::InvalidPlan);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_preserves_plan_limits_and_binds_exact_control_bytes() {
        let control = b"StoreDir: /nix/store\n";
        let operation = StorageWorkOperation::PutPreparedControl {
            path: "nix-cache-info".into(),
            size: control.len() as u64,
            sha256: hex::encode(Sha256::digest(control)),
        };
        let frame = encode_frame(b"{}", control).unwrap();
        let (plan, body) = split_frame(&frame).unwrap();
        assert_eq!(plan, b"{}");
        assert_eq!(body, control);
        assert!(validate_body(&operation, body).is_ok());
        assert!(validate_body(&operation, b"StoreDir: /wrong/dir\n").is_err());
        assert!(validate_body(&operation, &control[..control.len() - 1]).is_err());
        assert!(split_frame(&frame[..3]).is_err());
        assert!(split_frame(&[0, 16, 0, 1]).is_err());
        assert!(encode_frame(&vec![0; MAX_PLAN_BYTES + 1], control).is_err());
    }

    #[test]
    fn prepared_control_paths_exclude_artifact_bodies_and_noncanonical_bundles() {
        for path in [
            "nix-cache-info",
            "objects/info/alternates",
            "objects/aos-index-v1/all",
        ] {
            assert!(admitted_path(path), "{path}");
        }
        for path in ["nar/large.nar.zst", "images/system.qcow2", "objects/pack/pack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.pack", "oci/blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "objects/aos-index-v1/invalid"] {
            assert!(!admitted_path(path), "{path}");
        }
    }
}

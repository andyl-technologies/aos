//! Records original sealed inode obligations independently of serving authority.
//!
//! Version 3 snapshots add `[[exposures.backings]]` records. These observations
//! must be rechecked against native custody before recovery, reuse or retirement;
//! decoding a record grants neither a descriptor nor physical release.
//!
//! ```toml
//! [[exposures.backings]]
//! kind = "index"
//! hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
//! filesystem_uuid = "0123456789abcdef0123456789abcdef"
//! device = "0000000000000007"
//! inode = "0000000000000064"
//! project_id = 79
//! uid = 840
//! gid = 845
//! mode = 256
//! size = 512
//! allocated = 8192
//! verity_algorithm = 1
//! verity_digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
//! ```

use super::{ExposureRecord, PinRecord, StoreFailure, capacity, digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Distinguishes structural indexes from typed whole-file backing obligations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExposureBackingKind {
    /// A sealed structural index of this exposure's canonical root.
    Index,
    /// Whole-file backing selected by an inline chunk identity.
    Inline,
    /// Whole-file backing selected by an object manifest identity.
    Manifest,
}

/// Records the original native incarnation protected before descriptor disclosure.
///
/// This is bounded custody policy, not a content lookup index or proof of current
/// native state. The physical owner must verify the actual original inode and
/// synchronize this record before acknowledging its grant. A pathname, metadata
/// row or caller-supplied field cannot substitute for that native observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureBackingRecord {
    /// Structural-index or typed whole-file role of this original inode.
    pub kind: ExposureBackingKind,
    /// Canonical root hash for an index, or typed file-content digest otherwise.
    pub hash: String,
    /// Lowercase hexadecimal UUID of the original quota filesystem.
    pub filesystem_uuid: String,
    /// Nonzero native device identity, encoded as 16 lowercase hexadecimal digits.
    #[serde(with = "native_number")]
    pub device: u64,
    /// Nonzero original inode number, encoded as 16 lowercase hexadecimal digits.
    #[serde(with = "native_number")]
    pub inode: u64,
    /// Nonzero original project assignment bound to the physical owner.
    pub project_id: u32,
    /// Original inode owner, distinct from the receiving worker's identity.
    pub uid: u32,
    /// Original inode group.
    pub gid: u32,
    /// Original permission and special bits, without file-type bits.
    pub mode: u16,
    /// Complete logical file length, independently of allocation or manifest size.
    pub size: u64,
    /// Observed allocated inode bytes, including verity metadata.
    ///
    /// This is not project charge or a proof that kernel references have closed.
    pub allocated: u64,
    /// Actual kernel fs-verity digest algorithm identifier.
    pub verity_algorithm: u16,
    /// Lowercase hexadecimal kernel measurement of the permanently sealed inode.
    pub verity_digest: String,
}

pub(super) fn validate(exposure: &ExposureRecord, pins: &[PinRecord]) -> Result<(), StoreFailure> {
    if exposure.backings.is_empty() {
        return Ok(());
    }
    let mut keys = BTreeSet::new();
    let mut inodes = BTreeSet::new();
    let mut indexes = 0;
    let owner = exposure.pin_owner();
    for binding in &exposure.backings {
        let digest_length = match binding.verity_algorithm {
            1 => 64,
            2 => 128,
            _ => return Err(capacity()),
        };
        if !digest(&binding.hash)
            || !hex(&binding.filesystem_uuid, 32)
            || !hex(&binding.verity_digest, digest_length)
            || binding.device == 0
            || binding.inode == 0
            || binding.size > i64::MAX as u64
            || binding.allocated > i64::MAX as u64
            || binding.project_id == 0
            || binding.mode & !0o7777 != 0
            || binding.mode & 0o222 != 0
            || !keys.insert((binding.kind, &binding.hash))
            || !inodes.insert((&binding.filesystem_uuid, binding.device, binding.inode))
        {
            return Err(capacity());
        }
        match binding.kind {
            ExposureBackingKind::Index => {
                indexes += 1;
                if binding.hash != exposure.root || binding.size == 0 {
                    return Err(capacity());
                }
            }
            ExposureBackingKind::Inline | ExposureBackingKind::Manifest => {
                if !pins
                    .iter()
                    .any(|pin| pin.owner == owner && pin.hash == binding.hash)
                {
                    return Err(capacity());
                }
            }
        }
    }
    if indexes != 1 {
        return Err(capacity());
    }
    Ok(())
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

// TOML integers are signed; native inode and device identities use all 64 bits.
mod native_number {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:016x}"))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if !super::hex(&value, 16) {
            return Err(D::Error::custom("expected 16 lowercase hexadecimal digits"));
        }
        u64::from_str_radix(&value, 16).map_err(D::Error::custom)
    }
}

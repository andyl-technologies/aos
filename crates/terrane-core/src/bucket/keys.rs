//! Validates relative keys against the closed bucket registry.
//!
//! ```text
//! objects/pack/ab/abcdef0123456789abcdef0123456789.pack
//! refs/heads/_/main
//! logs/refs/heads/_/main/00000000000000000001
//! ```

use crate::refs::{RefClass, RefName, RefWriteMode};
use alloc::string::{String, ToString};
use core::fmt;

/// Identifies a key's fixed write discipline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mutability {
    /// Bytes are immutable after first installation.
    Immutable,
    /// Installation must fail when any value already exists.
    CreateOnce,
    /// Replacement requires comparison of the complete observed value.
    CompareAndSwap,
}

/// Reports an unregistered or unsafe bucket key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyError;

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unregistered bucket key")
    }
}

impl core::error::Error for KeyError {}

/// Holds a validated relative bucket key and its fixed mutability class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BucketKey {
    key: String,
    class: Mutability,
}

impl BucketKey {
    /// Parses a key under the registered layout.
    ///
    /// # Errors
    /// Returns [`KeyError`] for unsafe components or an unregistered shape.
    pub fn parse(key: &str) -> Result<Self, KeyError> {
        let parts: alloc::vec::Vec<_> = key.split('/').collect();
        if parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.contains('\\')
                || part.contains('\0')
        }) {
            return Err(KeyError);
        }
        let class = match parts.as_slice() {
            ["CAPABILITIES"] => Mutability::CompareAndSwap,
            ["objects", "pack", fanout, file] => {
                let id = file
                    .strip_suffix(".pack")
                    .or_else(|| file.strip_suffix(".idx"))
                    .ok_or(KeyError)?;
                if !hex(id, 32) || *fanout != &id[..2] {
                    return Err(KeyError);
                }
                Mutability::Immutable
            }
            ["objects", "index", generation, "MANIFEST"] if decimal(generation) => {
                Mutability::Immutable
            }
            ["objects", "index", generation, file] if decimal(generation) => {
                let shard = file
                    .strip_suffix(".idx")
                    .or_else(|| file.strip_suffix(".flt"))
                    .ok_or(KeyError)?;
                if !decimal(shard) {
                    return Err(KeyError);
                }
                Mutability::Immutable
            }
            ["refs", ..] => {
                let name = RefName::parse(key).map_err(|_| KeyError)?;
                let minimum = match name.class() {
                    RefClass::Notes => 5,
                    RefClass::Conflicts => 5,
                    _ => 4,
                };
                if parts.len() < minimum {
                    return Err(KeyError);
                }
                if name.class() == RefClass::Notes
                    && !matches!(parts[2], "profiles" | "completeness" | "memos")
                {
                    return Err(KeyError);
                }
                if name.class() == RefClass::Conflicts && !sequence(parts[parts.len() - 1]) {
                    return Err(KeyError);
                }
                match name.class().write_mode() {
                    RefWriteMode::PutIfAbsent => Mutability::CreateOnce,
                    RefWriteMode::CompareAndSwap => Mutability::CompareAndSwap,
                }
            }
            ["logs", "refs", ..] => {
                let (ref_key, suffix) = key
                    .strip_prefix("logs/")
                    .ok_or(KeyError)?
                    .rsplit_once('/')
                    .ok_or(KeyError)?;
                Self::parse(ref_key)?;
                let name = RefName::parse(ref_key).map_err(|_| KeyError)?;
                if let Some((seq, candidate)) = suffix.split_once(':') {
                    if !branch(name.class()) || !sequence(seq) || !hex(candidate, 64) {
                        return Err(KeyError);
                    }
                } else if name.class() != RefClass::Heads || !sequence(suffix) {
                    return Err(KeyError);
                }
                Mutability::CreateOnce
            }
            ["gc", "lease"] => Mutability::CompareAndSwap,
            ["gc", "cycle", cycle] if decimal(cycle) => Mutability::CreateOnce,
            ["gc", cycle, "roots"] if decimal(cycle) => Mutability::CreateOnce,
            ["gc", cycle, "state"] if decimal(cycle) => Mutability::CompareAndSwap,
            ["gc", cycle, "mark", shard] if decimal(cycle) && digest_shard(shard) => {
                Mutability::CreateOnce
            }
            ["gc", cycle, "mark", shard, revision]
                if decimal(cycle) && digest_shard(shard) && decimal(revision) =>
            {
                Mutability::CreateOnce
            }
            ["trash", cycle, id] if decimal(cycle) && hex(id, 32) => Mutability::CreateOnce,
            _ => return Err(KeyError),
        };
        Ok(Self {
            key: key.to_string(),
            class,
        })
    }

    /// Returns the relative key without a leading slash.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// Returns the key's fixed write discipline.
    #[must_use]
    pub const fn mutability(&self) -> Mutability {
        self.class
    }

    /// Returns the filesystem-private stable lock name for this logical key.
    #[must_use]
    pub fn lock_name(&self) -> String {
        alloc::format!(
            ".terrane-locks/{}",
            blake3::hash(self.key.as_bytes()).to_hex()
        )
    }

    /// Formats the registered, zero-padded reflog key for a tenant branch.
    ///
    /// # Errors
    /// Returns [`KeyError`] for a nonbranch, unsafe name, or zero sequence.
    pub fn reflog(name: &str, seq: u64) -> Result<Self, KeyError> {
        let name_key = Self::parse(name)?;
        if !name_key.as_str().starts_with("refs/heads/") || seq == 0 {
            return Err(KeyError);
        }
        Self::parse(&alloc::format!("logs/{name}/{seq:020}"))
    }

    /// Formats a create-once proposal sibling for a registered branch.
    ///
    /// # Errors
    /// Rejects unsafe names, nonbranch classes, and a zero sequence.
    pub fn reflog_candidate(name: &str, seq: u64, candidate: &[u8; 32]) -> Result<Self, KeyError> {
        let candidate: String = candidate
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        Self::parse(&alloc::format!("logs/{name}/{seq:020}:{candidate}"))
    }
}

fn branch(class: RefClass) -> bool {
    matches!(
        class,
        RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
    )
}

fn digest_shard(value: &str) -> bool {
    decimal(value) && value.parse::<u8>().is_ok()
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && (value == "0" || !value.starts_with('0')) && value.parse::<u64>().is_ok()
}

fn sequence(value: &str) -> bool {
    value.len() == 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|seq| seq > 0)
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn registry_rejects_unknown_paths_and_requires_tenant_and_padding() {
        for key in [
            "objects/loose/hash",
            "refs/heads/main",
            "refs/heads/_/.",
            "logs/refs/heads/_/main/1",
            "refs/notes/unknown/_/main",
            "objects/index/01/MANIFEST",
        ] {
            assert!(BucketKey::parse(key).is_err(), "{key}");
        }
        assert_eq!(
            BucketKey::reflog("refs/heads/_/main", 1).unwrap().as_str(),
            "logs/refs/heads/_/main/00000000000000000001"
        );
        assert_eq!(
            BucketKey::parse("refs/tags/_/release")
                .unwrap()
                .mutability(),
            Mutability::CreateOnce
        );
        assert_eq!(
            BucketKey::parse("refs/heads/tenant/main")
                .unwrap()
                .mutability(),
            Mutability::CompareAndSwap
        );
    }

    #[test]
    fn candidates_are_registered_siblings_for_exact_branch_classes() {
        for name in [
            "refs/heads/_/main",
            "refs/jobs/_/build",
            "refs/conflicts/_/main/00000000000000000001",
            "refs/derived/_/shared",
        ] {
            let key = BucketKey::reflog_candidate(name, 1, &[17; 32]).unwrap();
            assert!(
                key.as_str()
                    .ends_with(&alloc::format!("/00000000000000000001:{}", "11".repeat(32)))
            );
            assert_eq!(key.mutability(), Mutability::CreateOnce);
        }
        for name in ["refs/tags/_/release", "refs/notes/memos/_/memo"] {
            assert!(BucketKey::reflog_candidate(name, 1, &[17; 32]).is_err());
        }
        let key = BucketKey::reflog_candidate("refs/heads/_/main", 1, &[171; 32]).unwrap();
        assert!(BucketKey::parse(&key.as_str().to_uppercase()).is_err());
        assert!(BucketKey::reflog_candidate("refs/heads/_/main", 0, &[17; 32]).is_err());
        assert!(BucketKey::parse("logs/refs/jobs/_/build/00000000000000000001").is_err());
        assert!(
            BucketKey::parse(&alloc::format!(
                "logs/refs/heads/_/main/00000000000000000001/{}",
                "11".repeat(32)
            ))
            .is_err()
        );
    }

    #[test]
    fn gc_state_and_checkpoint_revisions_keep_the_registered_write_classes() {
        assert_eq!(
            BucketKey::parse("gc/1/state").unwrap().mutability(),
            Mutability::CompareAndSwap
        );
        assert_eq!(
            BucketKey::parse("gc/1/mark/255/0").unwrap().mutability(),
            Mutability::CreateOnce
        );
        for key in [
            "gc/01/state",
            "gc/1/mark/256/0",
            "gc/1/mark/1/00",
            "gc/1/marks/00",
        ] {
            assert!(BucketKey::parse(key).is_err(), "{key}");
        }
    }
}

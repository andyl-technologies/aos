//! Validates relative keys against the closed bucket registry.
//!
//! ```text
//! objects/pack/ab/abcdef0123456789abcdef0123456789.pack
//! refs/heads/_/main:record
//! logs/refs/heads/_/main/00000000000000000001:legacy
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
    /// Parses a key under the registered current and read-only legacy layouts.
    ///
    /// Unsuffixed refs and numbered logs are registered for version-1 access;
    /// callers must enforce the selected layout before reading or writing them.
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
            ["publication", "SELECTED-HISTORY" | "PORTABLE"] => Mutability::CompareAndSwap,
            ["publication", "snapshots", selector] => {
                let (revision, operation) = selector.split_once(':').ok_or(KeyError)?;
                if !decimal(revision) || !hex(operation, 64) {
                    return Err(KeyError);
                }
                Mutability::CreateOnce
            }
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
            ["refs", ..] => ref_class(key.strip_suffix(":record").unwrap_or(key))?,
            ["logs", "refs", ..] => {
                let (ref_key, suffix) = key
                    .strip_prefix("logs/")
                    .ok_or(KeyError)?
                    .rsplit_once('/')
                    .ok_or(KeyError)?;
                ref_class(ref_key)?;
                let name = RefName::parse(ref_key).map_err(|_| KeyError)?;
                if let Some((seq, candidate)) = suffix.split_once(':') {
                    if !sequence(seq)
                        || (candidate == "legacy" && name.class() != RefClass::Heads)
                        || (candidate != "legacy" && (!branch(name.class()) || !hex(candidate, 64)))
                    {
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
            // Classification grants no ordinary-write authority over this protected intent.
            ["gc", cycle, "delete", pack, operation]
                if decimal(cycle) && hex(pack, 32) && hex(operation, 64) =>
            {
                Mutability::CompareAndSwap
            }
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

    /// Formats a version-2 migrated numbered-log key for a tenant branch.
    ///
    /// # Errors
    /// Returns [`KeyError`] for a nonbranch, unsafe name, or zero sequence.
    pub fn reflog(name: &str, seq: u64) -> Result<Self, KeyError> {
        let name_key = Self::parse(name)?;
        if !name_key.as_str().starts_with("refs/heads/") || seq == 0 {
            return Err(KeyError);
        }
        Self::parse(&alloc::format!("logs/{name}/{seq:020}:legacy"))
    }

    /// Formats a version-2 ref or advisory-sidecar record leaf.
    ///
    /// # Errors
    /// Rejects unsafe names and unregistered ref classes or namespace shapes.
    pub fn ref_record(name: &str) -> Result<Self, KeyError> {
        ref_class(name)?;
        Self::parse(&alloc::format!("{name}:record"))
    }

    /// Formats a version-1 numbered log for explicit legacy read-only access.
    ///
    /// # Errors
    /// Rejects unsafe names, non-head classes, and zero sequences.
    pub fn legacy_reflog(name: &str, seq: u64) -> Result<Self, KeyError> {
        ref_class(name)?;
        if RefName::parse(name).map_err(|_| KeyError)?.class() != RefClass::Heads || seq == 0 {
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

fn ref_class(key: &str) -> Result<Mutability, KeyError> {
    let name = RefName::parse(key).map_err(|_| KeyError)?;
    let parts: alloc::vec::Vec<_> = key.split('/').collect();
    let minimum = match name.class() {
        RefClass::Notes | RefClass::Conflicts => 5,
        _ => 4,
    };
    if parts.len() < minimum
        || (name.class() == RefClass::Notes
            && !matches!(parts[2], "profiles" | "completeness" | "memos"))
        || (name.class() == RefClass::Conflicts && !sequence(parts[parts.len() - 1]))
    {
        return Err(KeyError);
    }
    Ok(match name.class().write_mode() {
        RefWriteMode::PutIfAbsent => Mutability::CreateOnce,
        RefWriteMode::CompareAndSwap => Mutability::CompareAndSwap,
    })
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
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u64>().is_ok()
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
    fn publication_payload_keys_preserve_mutability_and_control_separation() {
        for name in ["SELECTED-HISTORY", "PORTABLE"] {
            assert_eq!(
                BucketKey::parse(&alloc::format!("publication/{name}"))
                    .unwrap()
                    .mutability(),
                Mutability::CompareAndSwap
            );
        }

        let operation = "ab".repeat(32);
        for revision in ["0", "1", "18446744073709551615"] {
            let key = alloc::format!("publication/snapshots/{revision}:{operation}");
            assert_eq!(
                BucketKey::parse(&key).unwrap().mutability(),
                Mutability::CreateOnce
            );
        }
        for revision in ["", "+1", "01", "-1", "18446744073709551616"] {
            let key = alloc::format!("publication/snapshots/{revision}:{operation}");
            assert!(BucketKey::parse(&key).is_err(), "{key}");
        }
        for operation in ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33)] {
            let key = alloc::format!("publication/snapshots/0:{operation}");
            assert!(BucketKey::parse(&key).is_err(), "{key}");
        }

        // Ordinary payload key validation never exposes protected control.
        for key in [
            "publication/commits/0".into(),
            alloc::format!("publication/transactions/{operation}"),
            alloc::format!("publication/guards/{operation}"),
            alloc::format!("publication/lineage/{operation}"),
            "publication/STATE".into(),
            "publication/CURRENT".into(),
            "backend-registration.cbor".into(),
            "publication/snapshots/0".into(),
            alloc::format!("publication/snapshots/0:{operation}:extra"),
        ] {
            assert!(BucketKey::parse(&key).is_err(), "{key}");
        }
    }

    #[test]
    fn registry_decimal_segments_reject_plus_aliases_and_preserve_boundaries() {
        for key in [
            "objects/index/+1/MANIFEST",
            "gc/+1/state",
            "gc/cycle/+1",
            "gc/1/mark/+1/0",
        ] {
            assert!(BucketKey::parse(key).is_err(), "{key}");
        }
        for key in [
            "objects/index/0/MANIFEST",
            "objects/index/18446744073709551615/MANIFEST",
            "gc/0/state",
            "gc/cycle/18446744073709551615",
            "gc/1/mark/255/0",
        ] {
            assert!(BucketKey::parse(key).is_ok(), "{key}");
        }
        assert!(BucketKey::parse("objects/index/18446744073709551616/MANIFEST").is_err());
    }

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
            "logs/refs/heads/_/main/00000000000000000001:legacy"
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

    #[test]
    fn v2_suffixes_preserve_ref_grammar_and_disjoint_legacy_logs() {
        for name in ["refs/heads/_/a", "refs/heads/_/a/b"] {
            let key = BucketKey::ref_record(name).unwrap();
            assert_eq!(key.as_str(), alloc::format!("{name}:record"));
            assert_eq!(key.mutability(), Mutability::CompareAndSwap);
            assert!(BucketKey::parse(name).is_ok());
        }
        assert_eq!(
            BucketKey::reflog("refs/heads/_/a", 1).unwrap().as_str(),
            "logs/refs/heads/_/a/00000000000000000001:legacy"
        );
        assert_eq!(
            BucketKey::legacy_reflog("refs/heads/_/a", 1)
                .unwrap()
                .as_str(),
            "logs/refs/heads/_/a/00000000000000000001"
        );
        for key in [
            "refs/heads/_/a:record:record",
            "refs/heads/_/a:legacy",
            "logs/refs/jobs/_/a/00000000000000000001:legacy",
            "logs/refs/heads/_/a/00000000000000000000:legacy",
        ] {
            assert!(BucketKey::parse(key).is_err(), "{key}");
        }
    }

    #[test]
    fn protected_delete_operations_require_canonical_cas_keys() {
        let pack = "ab".repeat(16);
        let operation = "cd".repeat(32);
        for cycle in ["0", "1", "18446744073709551615"] {
            let key = alloc::format!("gc/{cycle}/delete/{pack}/{operation}");
            assert_eq!(
                BucketKey::parse(&key).unwrap().mutability(),
                Mutability::CompareAndSwap
            );
        }

        for cycle in ["+1", "01", "-1", "18446744073709551616"] {
            assert!(
                BucketKey::parse(&alloc::format!("gc/{cycle}/delete/{pack}/{operation}")).is_err()
            );
        }
        for invalid_pack in [
            "AB".repeat(16),
            "ab".repeat(15),
            "ab".repeat(17),
            "g".repeat(32),
        ] {
            assert!(
                BucketKey::parse(&alloc::format!("gc/1/delete/{invalid_pack}/{operation}"))
                    .is_err()
            );
        }
        for invalid_operation in [
            "CD".repeat(32),
            "c".repeat(63),
            "c".repeat(65),
            "g".repeat(64),
        ] {
            assert!(
                BucketKey::parse(&alloc::format!("gc/1/delete/{pack}/{invalid_operation}"))
                    .is_err()
            );
        }
        for key in [
            alloc::format!("gc/1/delete/{pack}"),
            alloc::format!("gc/1/delete/{pack}/{operation}/extra"),
            alloc::format!("gc/1/delete/{pack}/{operation}:record"),
            alloc::format!(".terrane-creation/{operation}"),
        ] {
            assert!(BucketKey::parse(&key).is_err(), "{key}");
        }
    }
}

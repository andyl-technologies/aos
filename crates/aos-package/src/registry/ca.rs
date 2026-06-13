//! The `ca/` trust map: blessed content addresses for store paths.
//!
//! A registry's signed tree names store paths by their input-addressed (IA)
//! hashes, which promise *how* a path was built but not *what bits* it
//! contains. The `ca/` directory closes that gap (RFC-0005): it maps every
//! IA store-path hash in a published closure to one or more **blessed**
//! content addresses, so a consumer can validate the exact bytes of every
//! closure member against data covered by the registry signature instead of
//! trusting cache-served narinfos.
//!
//! The map is sharded into at most 1024 bucket files named by the first two
//! nixbase32 characters of the IA hash. Each bucket holds sorted lines of
//! whitespace-separated tokens — the IA hash followed by one type-tagged
//! entry per blessed realisation:
//!
//! ```text
//! r4q1m2kp8v3x nar:sha256:1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy:1048576
//! r4z9w2n3p7c5 nar:sha256:0c7n5whyvfyqap5jr6xj2omimi80wabqy9v5cxpfwpji2j91kjex:393216
//! ```
//!
//! Entry types are dispatched on the first `:`-separated segment. `nar:`
//! carries the SHA-256 of the uncompressed NAR (52-char nixbase32) and its
//! size in bytes. Unrecognised types are preserved for forward
//! compatibility but cannot satisfy validation on their own. Lines starting
//! with `#` and blank lines are ignored.
//!
//! [`CaMap`] is the consumer-side read model (loaded with the registry
//! cache); [`upsert_entry`] / [`remove_entry`] are the producer-side
//! mutators used by `apr publish` and `apr ca`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use aos_core::nar::cache::normalize_sha256_nix32;

/// Name of the trust-map directory at the registry tree root.
pub const CA_DIR: &str = "ca";

/// Nix's custom base32 alphabet (omits `e`, `o`, `t`, `u`).
const NIX_BASE32_ALPHABET: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// Length of a SHA-256 digest in nixbase32 characters.
const SHA256_NIX32_LEN: usize = 52;

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// One blessed content-address entry for an input-addressed store path.
///
/// Serialized as a single whitespace-free token (see the module docs for
/// the grammar). Multiple entries on one line mean multiple blessed
/// realisations of the same IA path (non-reproducible rebuilds, independent
/// builders).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaEntry {
    /// SHA-256 over the uncompressed NAR of the path as built, plus the
    /// NAR's size in bytes: `nar:sha256:<52-char-nixbase32>:<size>`.
    Nar {
        /// SHA-256 digest of the uncompressed NAR, nixbase32-encoded
        /// (52 chars, no `sha256:` prefix).
        sha256_nix32: String,
        /// Size of the uncompressed NAR in bytes.
        nar_size: u64,
    },
    /// An entry of a type this build does not understand (e.g. a future
    /// `ca:` Nix CA-store entry), preserved verbatim for round-tripping.
    Unknown(String),
}

impl CaEntry {
    /// Parse one entry token.
    ///
    /// A token whose type tag is recognised but malformed is an error — the
    /// map is signed data and silent corruption must fail loudly. A token
    /// with an unrecognised type tag parses as [`CaEntry::Unknown`].
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed `nar:` token (wrong field count,
    /// non-`sha256` algorithm, digest that is not 52 nixbase32 chars, or an
    /// unparsable size).
    pub fn parse(token: &str) -> Result<Self> {
        let Some(rest) = token.strip_prefix("nar:") else {
            return Ok(Self::Unknown(token.to_string()));
        };

        let mut fields = rest.split(':');
        let (algo, digest, size) =
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(algo), Some(digest), Some(size), None) => (algo, digest, size),
                _ => bail!("malformed ca entry '{token}': expected nar:sha256:<hash>:<size>"),
            };
        if algo != "sha256" {
            bail!("malformed ca entry '{token}': unsupported algorithm '{algo}'");
        }
        if digest.len() != SHA256_NIX32_LEN
            || !digest.chars().all(|ch| NIX_BASE32_ALPHABET.contains(ch))
        {
            bail!("malformed ca entry '{token}': digest is not 52-char nixbase32");
        }
        let nar_size: u64 = size
            .parse()
            .with_context(|| format!("malformed ca entry '{token}': bad size"))?;

        Ok(Self::Nar {
            sha256_nix32: digest.to_string(),
            nar_size,
        })
    }

    /// Build a `nar:` entry from a SHA-256 NAR hash in any of the accepted
    /// forms (`sha256:<hex>`, SRI `sha256-<base64>`, or `sha256:<nix32>`)
    /// plus the uncompressed NAR size.
    ///
    /// # Errors
    ///
    /// Returns an error if `nar_hash` cannot be normalised to a nixbase32
    /// SHA-256 digest.
    pub fn from_nar_hash(nar_hash: &str, nar_size: u64) -> Result<Self> {
        let normalized = normalize_sha256_nix32(nar_hash);
        let digest = normalized
            .strip_prefix("sha256:")
            .filter(|digest| {
                digest.len() == SHA256_NIX32_LEN
                    && digest.chars().all(|ch| NIX_BASE32_ALPHABET.contains(ch))
            })
            .ok_or_else(|| {
                anyhow::anyhow!("cannot derive a nixbase32 SHA-256 digest from '{nar_hash}'")
            })?;
        Ok(Self::Nar {
            sha256_nix32: digest.to_string(),
            nar_size,
        })
    }

    /// Whether this is a `nar:` entry matching the given NAR hash (any
    /// accepted SHA-256 form) and exact size.
    pub fn matches_nar(&self, nar_hash: &str, nar_size: u64) -> bool {
        match self {
            Self::Nar {
                sha256_nix32,
                nar_size: blessed_size,
            } => {
                *blessed_size == nar_size
                    && normalize_sha256_nix32(nar_hash)
                        .strip_prefix("sha256:")
                        .map(|digest| digest == sha256_nix32)
                        .unwrap_or(false)
            }
            Self::Unknown(_) => false,
        }
    }

    /// The NAR hash in the codebase's canonical `sha256:<nix32>` form, for
    /// `nar:` entries.
    pub fn nar_hash(&self) -> Option<String> {
        match self {
            Self::Nar { sha256_nix32, .. } => Some(format!("sha256:{sha256_nix32}")),
            Self::Unknown(_) => None,
        }
    }

    /// The uncompressed NAR size, for `nar:` entries.
    pub fn nar_size(&self) -> Option<u64> {
        match self {
            Self::Nar { nar_size, .. } => Some(*nar_size),
            Self::Unknown(_) => None,
        }
    }
}

impl fmt::Display for CaEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nar {
                sha256_nix32,
                nar_size,
            } => write!(f, "nar:sha256:{sha256_nix32}:{nar_size}"),
            Self::Unknown(raw) => f.write_str(raw),
        }
    }
}

// ---------------------------------------------------------------------------
// Bucket files
// ---------------------------------------------------------------------------

/// The bucket file name for an IA store-path hash: its first two
/// characters.
///
/// # Errors
///
/// Returns an error if the hash is shorter than two ASCII characters or
/// contains characters outside the nixbase32 alphabet (which would escape
/// the fixed 1024-bucket namespace).
pub fn bucket_name(ia_hash: &str) -> Result<&str> {
    let prefix = ia_hash.get(..2).ok_or_else(|| {
        anyhow::anyhow!("store path hash '{ia_hash}' is too short for a ca/ bucket name")
    })?;
    if !prefix.chars().all(|ch| NIX_BASE32_ALPHABET.contains(ch)) {
        bail!("store path hash '{ia_hash}' is not nixbase32; refusing to derive a ca/ bucket");
    }
    Ok(prefix)
}

/// Absolute path of the bucket file holding `ia_hash` under `registry_dir`.
///
/// # Errors
///
/// Returns an error if `ia_hash` cannot name a bucket (see [`bucket_name`]).
pub fn bucket_path(registry_dir: &Path, ia_hash: &str) -> Result<PathBuf> {
    Ok(registry_dir.join(CA_DIR).join(bucket_name(ia_hash)?))
}

/// Parse one bucket file's content into per-hash entry lists.
///
/// Blank lines and `#` comments are skipped (same lexical rules as
/// `closures/` files). Later duplicate lines for the same hash merge into
/// the earlier ones.
///
/// # Errors
///
/// Returns an error for a line without entries or with a malformed
/// known-type entry token.
pub fn parse_bucket(content: &str) -> Result<BTreeMap<String, Vec<CaEntry>>> {
    let mut map: BTreeMap<String, Vec<CaEntry>> = BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let ia_hash = tokens.next().expect("non-empty line has a first token");
        let entries: Vec<CaEntry> = tokens.map(CaEntry::parse).collect::<Result<_>>()?;
        if entries.is_empty() {
            bail!("ca entry line for '{ia_hash}' has no content addresses");
        }
        let slot = map.entry(ia_hash.to_string()).or_default();
        for entry in entries {
            if !slot.contains(&entry) {
                slot.push(entry);
            }
        }
    }

    Ok(map)
}

/// Serialize per-hash entry lists into bucket file content: one sorted line
/// per hash, entries sorted within the line, LF-terminated.
pub fn serialize_bucket(entries: &BTreeMap<String, Vec<CaEntry>>) -> String {
    let mut out = String::new();
    for (ia_hash, list) in entries {
        let mut list = list.clone();
        list.sort();
        out.push_str(ia_hash);
        for entry in &list {
            out.push(' ');
            out.push_str(&entry.to_string());
        }
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Consumer read model
// ---------------------------------------------------------------------------

/// The loaded `ca/` trust map of one registry.
///
/// Distinguishes "the registry publishes no map at all" (legacy registry;
/// [`CaMap::is_present`] is `false`) from "the map exists but has no entry
/// for a hash" (malformed or downgrade-stripped registry — a hard failure
/// when enforcement is on).
#[derive(Debug, Default)]
pub struct CaMap {
    entries: BTreeMap<String, Vec<CaEntry>>,
    present: bool,
}

impl CaMap {
    /// Load the full trust map from a registry's `ca/` directory.
    ///
    /// A missing `ca/` directory is not an error — it yields an absent map
    /// ([`CaMap::is_present`] returns `false`). Subdirectories and hidden
    /// files are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or one of its bucket files cannot
    /// be read, or a bucket file is malformed.
    pub fn load(registry_dir: &Path) -> Result<Self> {
        let ca_dir = registry_dir.join(CA_DIR);
        if !ca_dir.is_dir() {
            return Ok(Self::default());
        }

        let mut entries = BTreeMap::new();
        for entry in
            std::fs::read_dir(&ca_dir).with_context(|| format!("reading {}", ca_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading ca bucket {}", path.display()))?;
            let bucket = parse_bucket(&content)
                .with_context(|| format!("parsing ca bucket {}", path.display()))?;
            for (ia_hash, list) in bucket {
                // A line must live in the bucket its hash maps to; a misfiled
                // line (e.g. from a botched merge of concurrent publishes)
                // would be trusted by consumers but invisible to `apr ca
                // revoke` and publish conflict detection, which only ever
                // touch the computed bucket. Reject it loudly.
                match bucket_name(&ia_hash) {
                    Ok(expected) if expected == name => {}
                    Ok(expected) => bail!(
                        "ca bucket {} contains entry for {ia_hash}, which belongs in bucket '{expected}'",
                        path.display(),
                    ),
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("invalid hash key in ca bucket {}", path.display())
                        });
                    }
                }
                let slot: &mut Vec<CaEntry> = entries.entry(ia_hash).or_default();
                for item in list {
                    if !slot.contains(&item) {
                        slot.push(item);
                    }
                }
            }
        }

        Ok(Self {
            entries,
            present: true,
        })
    }

    /// Whether the registry publishes a `ca/` directory at all.
    pub fn is_present(&self) -> bool {
        self.present
    }

    /// The blessed entries for an IA store-path hash, if mapped.
    pub fn get(&self, ia_hash: &str) -> Option<&[CaEntry]> {
        self.entries.get(ia_hash).map(|list| list.as_slice())
    }

    /// Number of mapped IA hashes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all `(ia_hash, entries)` pairs in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[CaEntry])> {
        self.entries
            .iter()
            .map(|(hash, list)| (hash.as_str(), list.as_slice()))
    }
}

// ---------------------------------------------------------------------------
// Transaction-level enforcement policy
// ---------------------------------------------------------------------------

/// Per-path blessed-content lookup for one install/upgrade transaction.
///
/// Each closure member is attributed to the **single registry that
/// resolved it** (closures resolve within one registry), and trust
/// decisions are made per path against *that* registry's map — never a
/// cross-registry union. Enforcement is therefore per-source-registry:
///
/// - The path's registry publishes a map → the path is **enforced**. A
///   missing blessed entry is a hard failure (a gap in a published map is
///   indistinguishable from a stripping attack, RFC §2.8), independent of
///   what any *other* involved registry does.
/// - The path's registry publishes no map (legacy) → the path falls back
///   to the unauthenticated narinfo hash with a warning.
///
/// Built via [`RegistrySet::trust_context`].
///
/// [`RegistrySet::trust_context`]: crate::registry::RegistrySet::trust_context
#[derive(Debug, Default)]
pub struct TrustContext<'a> {
    /// Member store-path hash → every registry map that attributed it.
    ///
    /// A hash can be contributed by more than one registry (input-addressed
    /// hashes are shared content). Tracking *all* of them — rather than a
    /// single last-write-wins slot — keeps enforcement from being disabled
    /// by a legacy (no-map) registry that happens to also carry a path a
    /// mapped registry blesses: presence is sticky across attributions.
    by_hash: BTreeMap<String, Vec<&'a CaMap>>,
}

impl<'a> TrustContext<'a> {
    /// Create an empty context.
    pub fn new() -> Self {
        Self {
            by_hash: BTreeMap::new(),
        }
    }

    /// Attribute a closure-member store-path hash to a source registry's
    /// trust map. Multiple registries may attribute the same hash.
    pub fn insert(&mut self, store_path_hash: String, map: &'a CaMap) {
        self.by_hash.entry(store_path_hash).or_default().push(map);
    }

    /// Whether *any* registry that carries this path publishes a trust map,
    /// so a missing blessed entry is a hard failure. Sticky: a legacy
    /// registry attributing the same hash cannot turn this off.
    pub fn enforced(&self, store_path_hash: &str) -> bool {
        self.by_hash
            .get(store_path_hash)
            .map(|maps| maps.iter().any(|map| map.is_present()))
            .unwrap_or(false)
    }

    /// Whether any attributed registry publishes a trust map.
    pub fn any_present(&self) -> bool {
        self.by_hash
            .values()
            .any(|maps| maps.iter().any(|map| map.is_present()))
    }

    /// The blessed entries for a path, unioned across the attributing
    /// registries that publish a map. Empty when none maps it.
    pub fn blessed(&self, store_path_hash: &str) -> Vec<CaEntry> {
        let mut out: Vec<CaEntry> = Vec::new();
        if let Some(maps) = self.by_hash.get(store_path_hash) {
            for map in maps {
                if let Some(entries) = map.get(store_path_hash) {
                    for entry in entries {
                        if !out.contains(entry) {
                            out.push(entry.clone());
                        }
                    }
                }
            }
        }
        out
    }

    /// Enforce closure totality (RFC §2.4 step 2, §2.8): every member that
    /// any mapped registry carries must have a blessed entry. This runs over
    /// the **whole closure**, not just downloaded members, so a stripped or
    /// partial map fails loudly even when the gap falls on a path already
    /// present in the local store.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first member with no blessed entry.
    pub fn enforce_totality(&self) -> Result<()> {
        for hash in self.by_hash.keys() {
            if self.enforced(hash) && self.blessed(hash).is_empty() {
                bail!(
                    "no ca/ trust-map entry for closure member {hash}; refusing to proceed \
                     (the registry may be malformed or its trust map stripped)"
                );
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Producer mutations
// ---------------------------------------------------------------------------

/// Outcome of [`upsert_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// The hash had no line; one was created with this entry.
    Inserted,
    /// The exact entry was already blessed; nothing changed.
    AlreadyPresent,
    /// The hash is mapped to different entries and `bless` was set, so the
    /// new entry was appended alongside them.
    Blessed,
    /// The hash is mapped to different entries and `bless` was not set;
    /// nothing was written. Carries the existing entries for diagnostics.
    Conflict(Vec<CaEntry>),
}

/// Insert a blessed entry for `ia_hash` into the registry's `ca/` map.
///
/// An exact duplicate is a no-op. A *different* existing entry set is the
/// signal this map exists to catch, so it is only appended to when `bless`
/// is explicitly set; otherwise the conflict is reported and the file is
/// left untouched.
///
/// # Errors
///
/// Returns an error if the bucket file cannot be read, parsed, or written,
/// or if `ia_hash` cannot name a bucket.
pub fn upsert_entry(
    registry_dir: &Path,
    ia_hash: &str,
    entry: CaEntry,
    bless: bool,
) -> Result<UpsertOutcome> {
    let path = bucket_path(registry_dir, ia_hash)?;
    let mut bucket = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading ca bucket {}", path.display()))?;
        parse_bucket(&content).with_context(|| format!("parsing ca bucket {}", path.display()))?
    } else {
        BTreeMap::new()
    };

    let outcome = match bucket.get_mut(ia_hash) {
        None => {
            bucket.insert(ia_hash.to_string(), vec![entry]);
            UpsertOutcome::Inserted
        }
        Some(existing) if existing.contains(&entry) => return Ok(UpsertOutcome::AlreadyPresent),
        Some(existing) => {
            if !bless {
                return Ok(UpsertOutcome::Conflict(existing.clone()));
            }
            existing.push(entry);
            UpsertOutcome::Blessed
        }
    };

    std::fs::create_dir_all(path.parent().expect("bucket path has a parent"))?;
    std::fs::write(&path, serialize_bucket(&bucket))
        .with_context(|| format!("writing ca bucket {}", path.display()))?;
    Ok(outcome)
}

/// Remove one blessed entry (revocation), or the whole line when `entry`
/// is `None`.
///
/// Returns `true` when something was removed. Removing the last entry of a
/// line removes the line; an empty bucket file is deleted.
///
/// # Errors
///
/// Returns an error if the bucket file cannot be read, parsed, written, or
/// removed, or if `ia_hash` cannot name a bucket.
pub fn remove_entry(registry_dir: &Path, ia_hash: &str, entry: Option<&CaEntry>) -> Result<bool> {
    let path = bucket_path(registry_dir, ia_hash)?;
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading ca bucket {}", path.display()))?;
    let mut bucket =
        parse_bucket(&content).with_context(|| format!("parsing ca bucket {}", path.display()))?;

    let removed = match (bucket.get_mut(ia_hash), entry) {
        (None, _) => false,
        (Some(_), None) => {
            bucket.remove(ia_hash);
            true
        }
        (Some(existing), Some(target)) => {
            let before = existing.len();
            existing.retain(|candidate| candidate != target);
            let removed = existing.len() != before;
            if existing.is_empty() {
                bucket.remove(ia_hash);
            }
            removed
        }
    };

    if !removed {
        return Ok(false);
    }

    if bucket.is_empty() {
        std::fs::remove_file(&path)
            .with_context(|| format!("removing empty ca bucket {}", path.display()))?;
    } else {
        std::fs::write(&path, serialize_bucket(&bucket))
            .with_context(|| format!("writing ca bucket {}", path.display()))?;
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A valid 52-char nixbase32 digest for fixtures.
    pub(crate) const DIGEST_A: &str = "1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";
    const DIGEST_B: &str = "0c7n5whyvfyqap5jr6xj21mimi80wabqy9v5cxpfwpji2j91kjcx";

    fn nar_entry(digest: &str, size: u64) -> CaEntry {
        CaEntry::Nar {
            sha256_nix32: digest.to_string(),
            nar_size: size,
        }
    }

    #[test]
    fn entry_parse_roundtrip() {
        let token = format!("nar:sha256:{DIGEST_A}:1048576");
        let entry = CaEntry::parse(&token).unwrap();
        assert_eq!(entry, nar_entry(DIGEST_A, 1048576));
        assert_eq!(entry.to_string(), token);
    }

    #[test]
    fn entry_parse_unknown_type_preserved() {
        let token = "ca:fixed:r:sha256:abcdef";
        let entry = CaEntry::parse(token).unwrap();
        assert_eq!(entry, CaEntry::Unknown(token.to_string()));
        assert_eq!(entry.to_string(), token);
    }

    #[test]
    fn entry_parse_rejects_malformed_nar() {
        // Wrong field count.
        assert!(CaEntry::parse("nar:sha256:abc").is_err());
        // Bad algorithm.
        assert!(CaEntry::parse(&format!("nar:md5:{DIGEST_A}:1")).is_err());
        // Digest not nixbase32 (contains 'e').
        let bad = format!("nar:sha256:{}:1", DIGEST_A.replace('1', "e"));
        assert!(CaEntry::parse(&bad).is_err());
        // Bad size.
        assert!(CaEntry::parse(&format!("nar:sha256:{DIGEST_A}:big")).is_err());
        // Trailing field.
        assert!(CaEntry::parse(&format!("nar:sha256:{DIGEST_A}:1:2")).is_err());
    }

    #[test]
    fn entry_from_nar_hash_accepts_hex_and_matches() {
        // sha256 of empty string.
        let hex = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let entry = CaEntry::from_nar_hash(hex, 7).unwrap();
        assert!(entry.matches_nar(hex, 7));
        assert!(!entry.matches_nar(hex, 8));
        // The nix32 digest of the empty-string sha256, computed by Nix.
        assert_eq!(
            entry.nar_hash().unwrap(),
            "sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73",
        );
    }

    #[test]
    fn entry_from_nar_hash_rejects_garbage() {
        assert!(CaEntry::from_nar_hash("sha256:nothex", 1).is_err());
        assert!(CaEntry::from_nar_hash("md5:abc", 1).is_err());
    }

    #[test]
    fn bucket_name_takes_two_nixbase32_chars() {
        assert_eq!(bucket_name("r4q1m2kp8v3x").unwrap(), "r4");
        assert!(bucket_name("r").is_err());
        assert!(bucket_name("../escape").is_err());
        assert!(bucket_name("E4UPPER").is_err());
    }

    #[test]
    fn bucket_parse_serialize_roundtrip_sorted() {
        let content = format!(
            "# comment\n\nzz999 nar:sha256:{DIGEST_A}:2\naa111 nar:sha256:{DIGEST_B}:1 nar:sha256:{DIGEST_A}:3\n"
        );
        let bucket = parse_bucket(&content).unwrap();
        assert_eq!(bucket.len(), 2);
        assert_eq!(bucket["aa111"].len(), 2);

        let serialized = serialize_bucket(&bucket);
        let lines: Vec<&str> = serialized.lines().collect();
        // Sorted by IA hash, entries sorted within the line.
        assert!(lines[0].starts_with("aa111 "));
        assert!(lines[1].starts_with("zz999 "));
        assert_eq!(parse_bucket(&serialized).unwrap(), bucket);
    }

    #[test]
    fn bucket_parse_rejects_bare_hash_line() {
        assert!(parse_bucket("aa111\n").is_err());
    }

    #[test]
    fn upsert_and_load() {
        let tmp = TempDir::new().unwrap();
        let hash = "r4q1m2kp8v3x";

        let outcome = upsert_entry(tmp.path(), hash, nar_entry(DIGEST_A, 10), false).unwrap();
        assert_eq!(outcome, UpsertOutcome::Inserted);

        // Exact duplicate is a no-op.
        let outcome = upsert_entry(tmp.path(), hash, nar_entry(DIGEST_A, 10), false).unwrap();
        assert_eq!(outcome, UpsertOutcome::AlreadyPresent);

        // Different bits without --bless: conflict, nothing written.
        let outcome = upsert_entry(tmp.path(), hash, nar_entry(DIGEST_B, 11), false).unwrap();
        assert_eq!(
            outcome,
            UpsertOutcome::Conflict(vec![nar_entry(DIGEST_A, 10)])
        );

        // With bless: appended.
        let outcome = upsert_entry(tmp.path(), hash, nar_entry(DIGEST_B, 11), true).unwrap();
        assert_eq!(outcome, UpsertOutcome::Blessed);

        let map = CaMap::load(tmp.path()).unwrap();
        assert!(map.is_present());
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(hash).unwrap().len(), 2);

        // The bucket file is named by the 2-char prefix.
        assert!(tmp.path().join(CA_DIR).join("r4").exists());
    }

    #[test]
    fn remove_entry_revokes_and_cleans_up() {
        let tmp = TempDir::new().unwrap();
        let hash = "r4q1m2kp8v3x";
        upsert_entry(tmp.path(), hash, nar_entry(DIGEST_A, 10), false).unwrap();
        upsert_entry(tmp.path(), hash, nar_entry(DIGEST_B, 11), true).unwrap();

        // Revoke one entry: line keeps the other.
        assert!(remove_entry(tmp.path(), hash, Some(&nar_entry(DIGEST_A, 10))).unwrap());
        let map = CaMap::load(tmp.path()).unwrap();
        assert_eq!(map.get(hash).unwrap(), &[nar_entry(DIGEST_B, 11)]);

        // Revoking the last entry removes line and empty bucket file.
        assert!(remove_entry(tmp.path(), hash, None).unwrap());
        assert!(!tmp.path().join(CA_DIR).join("r4").exists());

        // Removing something absent reports false.
        assert!(!remove_entry(tmp.path(), hash, None).unwrap());
    }

    #[test]
    fn camap_absent_dir_is_not_present() {
        let tmp = TempDir::new().unwrap();
        let map = CaMap::load(tmp.path()).unwrap();
        assert!(!map.is_present());
        assert!(map.is_empty());
        assert!(map.get("anything").is_none());
    }

    #[test]
    fn trust_context_enforces_per_source_registry() {
        let with_map = TempDir::new().unwrap();
        upsert_entry(
            with_map.path(),
            "r4q1m2kp8v3x",
            nar_entry(DIGEST_A, 10),
            false,
        )
        .unwrap();
        let without_map = TempDir::new().unwrap();
        std::fs::create_dir_all(without_map.path()).unwrap();

        let present = CaMap::load(with_map.path()).unwrap();
        let absent = CaMap::load(without_map.path()).unwrap();

        // A path from the mapped registry is enforced and blessed; a path
        // from the legacy registry is not enforced — independently, even in
        // the same transaction (the per-registry fix).
        let mut ctx = TrustContext::new();
        ctx.insert("r4q1m2kp8v3x".to_string(), &present);
        ctx.insert("legacypath0000".to_string(), &absent);

        assert!(ctx.enforced("r4q1m2kp8v3x"));
        assert_eq!(ctx.blessed("r4q1m2kp8v3x").len(), 1);
        assert!(!ctx.enforced("legacypath0000"));
        assert!(ctx.blessed("legacypath0000").is_empty());
        assert!(ctx.any_present());
        // Totality passes: every mapped member is covered.
        ctx.enforce_totality().unwrap();

        // A mapped registry missing an entry for one of its own members is a
        // stripping signature — totality fails regardless of the legacy one.
        let mut stripped = TrustContext::new();
        stripped.insert("r4q1m2kp8v3x".to_string(), &present);
        stripped.insert("unmapped000000".to_string(), &present);
        assert!(stripped.enforced("unmapped000000"));
        assert!(stripped.enforce_totality().is_err());

        let empty = TrustContext::new();
        assert!(!empty.any_present());
        empty.enforce_totality().unwrap();
    }

    #[test]
    fn trust_context_legacy_cannot_shadow_a_mapped_registry() {
        // A path blessed by a mapped registry stays enforced even when a
        // legacy (no-map) registry also attributes the same hash — and
        // regardless of attribution order (last-write-wins would break it).
        let mapped = TempDir::new().unwrap();
        upsert_entry(
            mapped.path(),
            "r4q1m2kp8v3x",
            nar_entry(DIGEST_A, 10),
            false,
        )
        .unwrap();
        let legacy = TempDir::new().unwrap();
        std::fs::create_dir_all(legacy.path()).unwrap();

        let present = CaMap::load(mapped.path()).unwrap();
        let absent = CaMap::load(legacy.path()).unwrap();

        // Legacy attributes the shared hash LAST.
        let mut ctx = TrustContext::new();
        ctx.insert("r4q1m2kp8v3x".to_string(), &present);
        ctx.insert("r4q1m2kp8v3x".to_string(), &absent);
        assert!(ctx.enforced("r4q1m2kp8v3x"));
        assert_eq!(ctx.blessed("r4q1m2kp8v3x"), vec![nar_entry(DIGEST_A, 10)]);
        ctx.enforce_totality().unwrap();

        // Legacy attributes FIRST — same outcome.
        let mut ctx = TrustContext::new();
        ctx.insert("r4q1m2kp8v3x".to_string(), &absent);
        ctx.insert("r4q1m2kp8v3x".to_string(), &present);
        assert!(ctx.enforced("r4q1m2kp8v3x"));
        ctx.enforce_totality().unwrap();
    }
}

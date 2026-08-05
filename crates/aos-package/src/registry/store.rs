//! The `store/` realisation graph: blessed bytes, content addresses, and
//! dependency edges for every published store path.
//!
//! A registry's signed tree names store paths by their input-addressed (IA)
//! hashes, which promise *how* a path was built but not *what bits* it
//! contains. The `store/` graph closes that gap (RFC-0005): one file per IA
//! store path records, for every blessed build, its exact NAR bytes, its
//! content-addressed (CA) realisation, and the realisations of its direct
//! dependencies. The node is a Nix-style realisation, so the realisation
//! graph *is* the closure graph - content addresses on the nodes, dependency
//! CA pins on the edges - and a consumer validates exact bytes against signed
//! data instead of trusting cache-served narinfos.
//!
//! # Layout
//!
//! One file per IA store path, named by the IA hash, sharded git-style:
//!
//! ```text
//! store/<first-2-of-ia>/<ia-hash>
//! ```
//!
//! # File format
//!
//! A sequence of realisation records. A header line (`ca:`/`nar:`) starts a
//! record; `ia:` lines are its dependency edges:
//!
//! ```text
//! ca:sha256:<ca-hash> nar:sha256:<nar-hash>:<size>
//!   ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
//!   ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
//! ```
//!
//! An input-addressed-only path carries no content address - the header is
//! just the NAR and edges are bare IA hashes:
//!
//! ```text
//! nar:sha256:<nar-hash>:<size>
//!   ia:sha256:<dep-ia>
//! ```
//!
//! The token prefix (`ca:`/`nar:` vs `ia:`) disambiguates header from edge, so
//! indentation is conventional, not significant. Blank/whitespace-only lines
//! and trailing whitespace are ignored; `#` starts a comment. All hashes are
//! nixbase32 SHA-256; the path's own IA hash is the filename, not repeated.
//!
//! [`StoreMap`] is the consumer read model (loaded with the registry cache);
//! [`upsert_realisation`] / [`remove_realisations`] are the producer mutators
//! used by `apr publish` and `apr store`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use aos_core::nar::cache::normalize_sha256_nix32;

/// Name of the realisation-graph directory at the registry tree root.
pub const STORE_DIR: &str = "store";

/// Nix's custom base32 alphabet (omits `e`, `o`, `t`, `u`).
const NIX_BASE32_ALPHABET: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// Length of a SHA-256 digest in nixbase32 characters.
const SHA256_NIX32_LEN: usize = 52;

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Validate a 52-char nixbase32 SHA-256 digest (no `sha256:` prefix).
fn is_nix32_digest(s: &str) -> bool {
    s.len() == SHA256_NIX32_LEN && s.chars().all(|ch| NIX_BASE32_ALPHABET.contains(ch))
}

/// Validate an input-addressed store-path hash for use as a filename, shard,
/// or edge reference: nixbase32 and at least two characters (so it can be
/// sharded). A real Nix store-path hash is exactly 32 nixbase32 characters,
/// but the length is not pinned here because the same predicate also guards
/// the 52-char nixbase32 CA digests reused as edge pins; restricting to the
/// nixbase32 alphabet is what blocks path-traversal characters (`/`, `.`).
fn is_store_hash(s: &str) -> bool {
    s.len() >= 2 && s.chars().all(|ch| NIX_BASE32_ALPHABET.contains(ch))
}

/// Parse a `sha256:<52-char-nix32>` content-hash token into its bare digest.
fn parse_sha256(token: &str) -> Result<String> {
    let digest = token
        .strip_prefix("sha256:")
        .filter(|d| is_nix32_digest(d))
        .ok_or_else(|| anyhow::anyhow!("expected sha256:<52-char-nixbase32>, got '{token}'"))?;
    Ok(digest.to_string())
}

/// Parse the `sha256:<store-hash>` form used for IA references in edges.
fn parse_ia_ref(token: &str) -> Result<String> {
    let hash = token
        .strip_prefix("sha256:")
        .filter(|h| is_store_hash(h))
        .ok_or_else(|| anyhow::anyhow!("expected sha256:<store-path-hash>, got '{token}'"))?;
    Ok(hash.to_string())
}

/// Normalise any accepted SHA-256 form (`sha256:<hex>`, SRI, or nixbase32) to
/// the bare nixbase32 digest used in the graph.
///
/// # Errors
///
/// Returns an error if `hash` cannot be reduced to a nixbase32 SHA-256.
pub fn normalize_digest(hash: &str) -> Result<String> {
    parse_sha256(&normalize_sha256_nix32(hash))
        .with_context(|| format!("cannot derive a nixbase32 SHA-256 digest from '{hash}'"))
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// The exact uncompressed NAR bytes of one build: SHA-256 digest plus size.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NarBytes {
    /// Nixbase32 SHA-256 of the uncompressed NAR (no `sha256:` prefix).
    pub sha256_nix32: String,
    /// Uncompressed NAR size in bytes.
    pub size: u64,
}

impl NarBytes {
    /// Build from any accepted SHA-256 form plus a size.
    ///
    /// # Errors
    ///
    /// Returns an error if `nar_hash` is not a SHA-256 in an accepted form.
    pub fn from_hash(nar_hash: &str, size: u64) -> Result<Self> {
        Ok(Self {
            sha256_nix32: normalize_digest(nar_hash)?,
            size,
        })
    }

    /// The NAR hash in the codebase's canonical `sha256:<nix32>` form.
    pub fn nar_hash(&self) -> String {
        format!("sha256:{}", self.sha256_nix32)
    }

    /// Whether this matches the given NAR hash (any accepted form) and size.
    pub fn matches(&self, nar_hash: &str, size: u64) -> bool {
        self.size == size
            && normalize_sha256_nix32(nar_hash)
                .strip_prefix("sha256:")
                .map(|d| d == self.sha256_nix32)
                .unwrap_or(false)
    }
}

/// A direct dependency edge: the dependency's IA hash, optionally pinned to a
/// specific CA realisation (present only when the dep has more than one).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepEdge {
    /// Dependency input-addressed store-path hash.
    pub dep_ia: String,
    /// Pinned dependency CA realisation (nixbase32 digest), if any.
    pub dep_ca: Option<String>,
}

/// One blessed build of a store path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Realisation {
    /// Exact NAR bytes of this build.
    pub nar: NarBytes,
    /// Content address of this realisation (nixbase32 digest); `None` for an
    /// input-addressed-only record.
    pub ca: Option<String>,
    /// Direct dependency edges.
    pub deps: Vec<DepEdge>,
}

impl Realisation {
    /// The CA realisation hash in canonical `sha256:<nix32>` form, if any.
    pub fn ca_hash(&self) -> Option<String> {
        self.ca.as_ref().map(|d| format!("sha256:{d}"))
    }
}

/// All blessed builds of one IA store path (one `store/` file).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreEntry {
    /// Realisations in stable sorted order.
    pub realisations: Vec<Realisation>,
}

impl StoreEntry {
    /// Direct dependency IA hashes (the closure edges), deduped in first-seen
    /// order. Invariant across realisations of one path, so taken from all.
    pub fn dep_ias(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for r in &self.realisations {
            for e in &r.deps {
                if seen.insert(e.dep_ia.clone()) {
                    out.push(e.dep_ia.clone());
                }
            }
        }
        out
    }

    /// The blessed NAR byte-sets across all realisations, deduped.
    pub fn blessed_nars(&self) -> Vec<NarBytes> {
        let mut out: Vec<NarBytes> = Vec::new();
        for r in &self.realisations {
            if !out.contains(&r.nar) {
                out.push(r.nar.clone());
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Parsing / serialization
// ---------------------------------------------------------------------------

/// Parse one `store/` file's text into a [`StoreEntry`].
///
/// # Errors
///
/// Returns an error for a malformed header or edge token, or an `ia:` edge
/// line with no preceding realisation header.
pub fn parse_entry(content: &str) -> Result<StoreEntry> {
    let mut realisations: Vec<Realisation> = Vec::new();

    for raw in content.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let first = tokens.next().expect("non-empty line has a first token");

        if first.starts_with("ia:") {
            // Dependency edge of the current realisation.
            let edge = parse_edge(first)?;
            let current = realisations.last_mut().ok_or_else(|| {
                anyhow::anyhow!("dependency edge before any realisation: '{line}'")
            })?;
            current.deps.push(edge);
            // An edge line carries exactly one edge.
            if tokens.next().is_some() {
                bail!("unexpected extra token on dependency edge line: '{line}'");
            }
        } else if first.starts_with("ca:") || first.starts_with("nar:") {
            // New realisation header: optional ca token, then a nar token.
            let (ca, nar_token) = if let Some(ca) = first.strip_prefix("ca:") {
                let nar = tokens.next().ok_or_else(|| {
                    anyhow::anyhow!("realisation header missing nar: token: '{line}'")
                })?;
                (Some(parse_ia_ref(ca)?), nar)
            } else {
                (None, first)
            };
            let nar = parse_nar_token(nar_token)?;
            if tokens.next().is_some() {
                bail!("unexpected extra token on realisation header: '{line}'");
            }
            realisations.push(Realisation {
                nar,
                ca,
                deps: Vec::new(),
            });
        } else {
            bail!("unrecognised store line (expected ca:/nar:/ia:): '{line}'");
        }
    }

    Ok(StoreEntry { realisations })
}

/// Strip a `#` comment (to end of line) from a raw line.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Parse a `nar:sha256:<hash>:<size>` token.
fn parse_nar_token(token: &str) -> Result<NarBytes> {
    let rest = token
        .strip_prefix("nar:")
        .ok_or_else(|| anyhow::anyhow!("expected nar:sha256:<hash>:<size>, got '{token}'"))?;
    // rest = sha256:<digest>:<size>
    let (algo, tail) = rest
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("malformed nar token '{token}'"))?;
    if algo != "sha256" {
        bail!("unsupported nar hash algorithm in '{token}'");
    }
    let (digest, size) = tail
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("nar token '{token}' missing size"))?;
    if !is_nix32_digest(digest) {
        bail!("nar token '{token}' digest is not 52-char nixbase32");
    }
    let size: u64 = size
        .parse()
        .with_context(|| format!("nar token '{token}' has a bad size"))?;
    Ok(NarBytes {
        sha256_nix32: digest.to_string(),
        size,
    })
}

/// Parse an `ia:sha256:<dep-ia>[/ca:sha256:<dep-ca>]` edge. The IA reference
/// is a store-path hash; the optional CA pin is a 52-char SHA-256 digest.
fn parse_edge(token: &str) -> Result<DepEdge> {
    let rest = token
        .strip_prefix("ia:")
        .ok_or_else(|| anyhow::anyhow!("expected ia:sha256:<hash>, got '{token}'"))?;
    let (ia_part, ca_part) = match rest.split_once("/ca:") {
        Some((ia, ca)) => (ia, Some(ca)),
        None => (rest, None),
    };
    let dep_ia = parse_ia_ref(ia_part)
        .with_context(|| format!("malformed dependency IA in edge '{token}'"))?;
    let dep_ca = match ca_part {
        Some(ca) => Some(
            parse_ia_ref(ca)
                .with_context(|| format!("malformed dependency CA pin in edge '{token}'"))?,
        ),
        None => None,
    };
    Ok(DepEdge { dep_ia, dep_ca })
}

/// Serialize a [`StoreEntry`] to its text form (records and edges sorted for
/// stable diffs).
pub fn serialize_entry(entry: &StoreEntry) -> String {
    let mut realisations = entry.realisations.clone();
    realisations.sort();

    let mut out = String::new();
    for r in &realisations {
        match &r.ca {
            Some(ca) => out.push_str(&format!(
                "ca:sha256:{ca} nar:sha256:{}:{}\n",
                r.nar.sha256_nix32, r.nar.size
            )),
            None => out.push_str(&format!(
                "nar:sha256:{}:{}\n",
                r.nar.sha256_nix32, r.nar.size
            )),
        }
        let mut deps = r.deps.clone();
        deps.sort();
        for e in &deps {
            match &e.dep_ca {
                Some(ca) => out.push_str(&format!("  ia:sha256:{}/ca:sha256:{ca}\n", e.dep_ia)),
                None => out.push_str(&format!("  ia:sha256:{}\n", e.dep_ia)),
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Sharded paths
// ---------------------------------------------------------------------------

/// The 2-char shard prefix for an IA hash.
///
/// # Errors
///
/// Returns an error if the hash is shorter than two characters or is not
/// nixbase32 (which would let it escape the shard namespace via `/` or `.`).
pub fn shard(ia_hash: &str) -> Result<&str> {
    if !is_store_hash(ia_hash) {
        bail!("'{ia_hash}' is not a nixbase32 store-path hash; refusing to derive a shard");
    }
    Ok(&ia_hash[..2])
}

/// Absolute path of the `store/` file for `ia_hash` under `registry_dir`.
///
/// # Errors
///
/// Returns an error if `ia_hash` cannot be sharded (see [`shard`]).
pub fn entry_path(registry_dir: &Path, ia_hash: &str) -> Result<PathBuf> {
    Ok(registry_dir
        .join(STORE_DIR)
        .join(shard(ia_hash)?)
        .join(ia_hash))
}

// ---------------------------------------------------------------------------
// Consumer read model
// ---------------------------------------------------------------------------

/// The loaded realisation graph of one registry.
///
/// Distinguishes "the registry publishes no graph at all" (legacy;
/// [`StoreMap::is_present`] is `false`) from "the graph exists but has no
/// record for a hash" (malformed or downgrade-stripped - a hard failure when
/// enforcement is on).
#[derive(Debug, Default)]
pub struct StoreMap {
    entries: BTreeMap<String, StoreEntry>,
    present: bool,
}

impl StoreMap {
    /// Load the full graph from a registry's `store/` directory.
    ///
    /// A missing `store/` directory yields an absent map. The filename of
    /// each `store/<prefix>/<ia>` file is its key, and must live under the
    /// shard its hash maps to (a misfiled record would be consumer-trusted
    /// but invisible to producer mutations, so it is rejected).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or a record file cannot be read, a
    /// record is malformed, or a file is misfiled relative to its shard.
    pub fn load(registry_dir: &Path) -> Result<Self> {
        let store_dir = registry_dir.join(STORE_DIR);
        if !store_dir.is_dir() {
            return Ok(Self::default());
        }

        let mut entries = BTreeMap::new();
        for shard_entry in std::fs::read_dir(&store_dir)
            .with_context(|| format!("reading {}", store_dir.display()))?
        {
            let shard_path = shard_entry?.path();
            if !shard_path.is_dir() {
                continue;
            }
            let shard_name = shard_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            for file_entry in std::fs::read_dir(&shard_path)
                .with_context(|| format!("reading {}", shard_path.display()))?
            {
                let path = file_entry?.path();
                if path.is_dir() {
                    continue;
                }
                let Some(ia) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if ia.starts_with('.') {
                    continue;
                }
                match shard(ia) {
                    Ok(expected) if expected == shard_name => {}
                    Ok(expected) => bail!(
                        "store record {} is misfiled; '{ia}' belongs in shard '{expected}'",
                        path.display(),
                    ),
                    Err(err) => {
                        return Err(err)
                            .with_context(|| format!("invalid record name {}", path.display()));
                    }
                }
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading store record {}", path.display()))?;
                let entry = parse_entry(&content)
                    .with_context(|| format!("parsing store record {}", path.display()))?;
                entries.insert(ia.to_string(), entry);
            }
        }

        Ok(Self {
            entries,
            present: true,
        })
    }

    /// Whether the registry publishes a `store/` graph at all.
    pub fn is_present(&self) -> bool {
        self.present
    }

    /// The record for an IA store-path hash, if published.
    pub fn get(&self, ia_hash: &str) -> Option<&StoreEntry> {
        self.entries.get(ia_hash)
    }

    /// Direct dependency IA hashes for a path (empty if absent or leaf).
    pub fn direct_deps(&self, ia_hash: &str) -> Vec<String> {
        self.entries
            .get(ia_hash)
            .map(StoreEntry::dep_ias)
            .unwrap_or_default()
    }

    /// Blessed NAR byte-sets for a path (empty if absent).
    pub fn blessed_nars(&self, ia_hash: &str) -> Vec<NarBytes> {
        self.entries
            .get(ia_hash)
            .map(StoreEntry::blessed_nars)
            .unwrap_or_default()
    }

    /// Every store-path hash reachable from `root` by walking dependency
    /// edges (root included), in no particular order.
    ///
    /// This is the **whole closure** the graph records — including anonymous,
    /// non-package members (system libraries, intermediate paths) — so it is
    /// the correct basis for trust enforcement and totality, which must cover
    /// every byte that gets imported, not just the published packages.
    pub fn reachable(&self, root: &str) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![root.to_string()];
        let mut out = Vec::new();
        while let Some(hash) = stack.pop() {
            if !seen.insert(hash.clone()) {
                continue;
            }
            stack.extend(self.direct_deps(&hash));
            out.push(hash);
        }
        out
    }

    /// Number of published store paths.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the graph has no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over `(ia_hash, entry)` in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &StoreEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Hashes the exact signed `store/` subgraph reachable from `roots`.
    ///
    /// The canonical object maps each IA hash to the canonical text form of
    /// its complete realization record. Missing records fail closed, so a
    /// stripped graph cannot acquire an attestation identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the graph is absent or any reachable member has
    /// no record.
    pub fn realization_subset_hash(&self, roots: &[String]) -> Result<String> {
        if !self.present {
            bail!("cannot attest config modules from a registry without a store graph");
        }
        let mut members = BTreeMap::new();
        for root in roots {
            for ia in self.reachable(root) {
                let entry = self.entries.get(&ia).with_context(|| {
                    format!("signed store graph has no record for reachable member {ia}")
                })?;
                if entry.realisations.is_empty() {
                    bail!("signed store graph has an empty record for reachable member {ia}");
                }
                members.insert(ia, serialize_entry(entry));
            }
        }
        Ok(crate::graph_compile::reproject::hash_cjson(
            &serde_json::to_value(members).context("serializing signed store subset")?,
        ))
    }
}

// ---------------------------------------------------------------------------
// Per-transaction trust context
// ---------------------------------------------------------------------------

/// Per-path blessed-bytes lookup for one install/upgrade transaction.
///
/// Each closure member is attributed to the registry that resolved it, and
/// trust decisions are made per path against *that* registry's graph - never
/// a cross-registry union. Enforcement is therefore per-source-registry:
///
/// - The path's registry publishes a graph → the path is **enforced**: a
///   missing record/`nar:` is a hard failure (a gap in a published graph is
///   indistinguishable from a stripping attack, RFC-0005 §2.6), independent of
///   what any *other* involved registry does.
/// - The path's registry publishes no graph (legacy) → the path falls back to
///   the unauthenticated narinfo hash with a warning.
///
/// Built via [`RegistrySet::trust_context`](crate::registry::RegistrySet::trust_context).
#[derive(Debug, Default)]
pub struct TrustContext<'a> {
    /// Member store-path hash → every registry graph that attributed it.
    ///
    /// A hash may be contributed by more than one registry (IA hashes are
    /// shared content). Tracking *all* of them - not a single last-write-wins
    /// slot - keeps enforcement from being disabled by a legacy (no-graph)
    /// registry that also carries a path a mapped registry blesses: presence
    /// is sticky across attributions.
    by_hash: BTreeMap<String, Vec<&'a StoreMap>>,
}

impl<'a> TrustContext<'a> {
    /// Create an empty context.
    pub fn new() -> Self {
        Self {
            by_hash: BTreeMap::new(),
        }
    }

    /// Attribute a closure-member store-path hash to a source registry's
    /// graph. Multiple registries may attribute the same hash.
    pub fn insert(&mut self, store_path_hash: String, map: &'a StoreMap) {
        self.by_hash.entry(store_path_hash).or_default().push(map);
    }

    /// Whether *any* registry that carries this path publishes a graph, so a
    /// missing record is a hard failure. Sticky: a legacy registry attributing
    /// the same hash cannot turn this off.
    pub fn enforced(&self, store_path_hash: &str) -> bool {
        self.by_hash
            .get(store_path_hash)
            .map(|maps| maps.iter().any(|m| m.is_present()))
            .unwrap_or(false)
    }

    /// Whether any attributed registry publishes a graph.
    pub fn any_present(&self) -> bool {
        self.by_hash
            .values()
            .any(|maps| maps.iter().any(|m| m.is_present()))
    }

    /// The blessed NAR byte-sets for a path, unioned across the attributing
    /// registries that publish a graph. Empty when none maps it.
    pub fn blessed_nars(&self, store_path_hash: &str) -> Vec<NarBytes> {
        let mut out: Vec<NarBytes> = Vec::new();
        if let Some(maps) = self.by_hash.get(store_path_hash) {
            for map in maps {
                for nar in map.blessed_nars(store_path_hash) {
                    if !out.contains(&nar) {
                        out.push(nar);
                    }
                }
            }
        }
        out
    }

    /// Enforce closure totality (RFC-0005 §2.6): every member that any mapped
    /// registry carries must have a blessed NAR. Runs over the **whole
    /// closure**, not just downloaded members, so a stripped or partial graph
    /// fails loudly even when the gap falls on an already-local path.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first member with no blessed NAR.
    pub fn enforce_totality(&self) -> Result<()> {
        for hash in self.by_hash.keys() {
            if self.enforced(hash) && self.blessed_nars(hash).is_empty() {
                bail!(
                    "no store/ record for closure member {hash}; refusing to proceed \
                     (the registry may be malformed or its realisation graph stripped)"
                );
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Producer mutations
// ---------------------------------------------------------------------------

/// Outcome of [`upsert_realisation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// The path had no record; one was created with this realisation.
    Created,
    /// An identical realisation was already present; nothing changed.
    AlreadyPresent,
    /// A new realisation was added alongside existing ones (`bless` set).
    Blessed,
    /// The path is mapped to different content and `bless` was not set;
    /// nothing was written. Carries the existing realisations for diagnostics.
    Conflict(Vec<Realisation>),
}

/// Insert a realisation for `ia_hash` into the registry's `store/` graph.
///
/// An identical realisation is a no-op. A realisation that differs from what
/// is recorded is the signal this graph exists to catch, so it is only added
/// when `bless` is explicitly set; otherwise the conflict is reported and the
/// file is left untouched.
///
/// "Differs" is judged by the NAR bytes: a record may legitimately hold
/// several realisations of the *same* bytes (e.g. adding a CA realisation to
/// an existing IA-only record, or a new CA realisation of the same NAR), but
/// a realisation whose NAR differs from every recorded one means the path's
/// content changed — the mismatch to catch, regardless of whether either side
/// carries a `ca`.
///
/// # Errors
///
/// Returns an error if the record file cannot be read, parsed, or written, or
/// if `ia_hash` cannot be sharded.
pub fn upsert_realisation(
    registry_dir: &Path,
    ia_hash: &str,
    realisation: Realisation,
    bless: bool,
) -> Result<UpsertOutcome> {
    let path = entry_path(registry_dir, ia_hash)?;
    let mut entry = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading store record {}", path.display()))?;
        parse_entry(&content).with_context(|| format!("parsing store record {}", path.display()))?
    } else {
        StoreEntry::default()
    };

    if entry.realisations.contains(&realisation) {
        return Ok(UpsertOutcome::AlreadyPresent);
    }
    let outcome = if entry.realisations.is_empty() {
        UpsertOutcome::Created
    } else {
        // The path's bytes must not silently change. If the new realisation's
        // NAR matches one already recorded, this is an additive refinement
        // (e.g. attaching a CA realisation to the same bytes) — allow it. If
        // the NAR differs from every recorded one, the content diverged — the
        // mismatch this graph exists to catch — refuse unless `--bless`. This
        // holds whether or not either side carries a `ca`, so an IA-only
        // record re-published in CA mode with different bytes still conflicts.
        let same_bytes = entry.realisations.iter().any(|r| r.nar == realisation.nar);
        if !same_bytes && !bless {
            return Ok(UpsertOutcome::Conflict(entry.realisations.clone()));
        }
        UpsertOutcome::Blessed
    };
    entry.realisations.push(realisation);

    write_entry(&path, &entry)?;
    Ok(outcome)
}

/// Remove one realisation (by CA hash, or all when `ca` is `None`).
///
/// Returns `true` when something was removed. Removing the last realisation
/// removes the record file.
///
/// # Errors
///
/// Returns an error if the record file cannot be read, parsed, written, or
/// removed, or if `ia_hash` cannot be sharded.
pub fn remove_realisations(registry_dir: &Path, ia_hash: &str, ca: Option<&str>) -> Result<bool> {
    let path = entry_path(registry_dir, ia_hash)?;
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading store record {}", path.display()))?;
    let mut entry = parse_entry(&content)
        .with_context(|| format!("parsing store record {}", path.display()))?;

    let before = entry.realisations.len();
    match ca {
        None => entry.realisations.clear(),
        Some(target) => {
            // Accept a bare or `sha256:`-prefixed CA store hash.
            let target = target.strip_prefix("sha256:").unwrap_or(target);
            entry
                .realisations
                .retain(|r| r.ca.as_deref() != Some(target));
        }
    }
    if entry.realisations.len() == before {
        return Ok(false);
    }

    if entry.realisations.is_empty() {
        std::fs::remove_file(&path)
            .with_context(|| format!("removing empty store record {}", path.display()))?;
    } else {
        write_entry(&path, &entry)?;
    }
    Ok(true)
}

/// Write a record, creating its shard directory.
fn write_entry(path: &Path, entry: &StoreEntry) -> Result<()> {
    std::fs::create_dir_all(path.parent().expect("store record path has a parent"))?;
    std::fs::write(path, serialize_entry(entry))
        .with_context(|| format!("writing store record {}", path.display()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // 52-char nixbase32 SHA-256 content digests (nar:/ca:).
    pub(crate) const D_A: &str = "1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy";
    pub(crate) const D_B: &str = "0c7n5whyvfyqap5jr6xj21mimi80wabqy9v5cxpfwpji2j91kjcx";
    pub(crate) const D_C: &str = "47xzgayn52idl4q3660qphz1wibz372fiv3q7jz8k7njhsdsfiwv";
    // Store-path hashes (ia:, filenames) - short nixbase32, as in fixtures.
    const DEP_IA: &str = "r4q1m2kp8v3x";

    fn nar(d: &str, size: u64) -> NarBytes {
        NarBytes {
            sha256_nix32: d.to_string(),
            size,
        }
    }

    #[test]
    fn parse_ia_only_record() {
        let text = format!("nar:sha256:{D_A}:1024\n\tia:sha256:{DEP_IA}\n");
        let e = parse_entry(&text).unwrap();
        assert_eq!(e.realisations.len(), 1);
        assert_eq!(e.realisations[0].nar, nar(D_A, 1024));
        assert!(e.realisations[0].ca.is_none());
        assert_eq!(e.realisations[0].deps.len(), 1);
        assert_eq!(e.realisations[0].deps[0].dep_ia, DEP_IA);
        assert!(e.realisations[0].deps[0].dep_ca.is_none());
        assert_eq!(e.dep_ias(), vec![DEP_IA.to_string()]);
    }

    #[test]
    fn parse_ca_record_with_pinned_edges_and_comments() {
        let text = format!(
            "# header comment\n\
             ca:sha256:{D_C} nar:sha256:{D_A}:1024   # the build\n\
             \tia:sha256:{DEP_IA}/ca:sha256:{D_A}\n\
             \n\
             ca:sha256:{D_A} nar:sha256:{D_B}:1088\n\
             \tia:sha256:{DEP_IA}/ca:sha256:{D_C}\n"
        );
        let e = parse_entry(&text).unwrap();
        assert_eq!(e.realisations.len(), 2);
        let r0 = &e.realisations[0];
        assert_eq!(r0.ca.as_deref(), Some(D_C));
        assert_eq!(r0.nar, nar(D_A, 1024));
        assert_eq!(r0.deps[0].dep_ia, DEP_IA);
        assert_eq!(r0.deps[0].dep_ca.as_deref(), Some(D_A));
        // Round-trip (sorted).
        let reparsed = parse_entry(&serialize_entry(&e)).unwrap();
        let mut sorted = e.clone();
        sorted.realisations.sort();
        assert_eq!(reparsed, sorted);
    }

    #[test]
    fn parse_rejects_edge_without_header() {
        let text = format!("\tia:sha256:{DEP_IA}\n");
        assert!(parse_entry(&text).is_err());
    }

    #[test]
    fn parse_rejects_bad_tokens() {
        assert!(parse_entry("nar:sha256:short:1\n").is_err());
        assert!(parse_entry(&format!("nar:md5:{D_A}:1\n")).is_err());
        assert!(parse_entry(&format!("nar:sha256:{D_A}:notanumber\n")).is_err());
        assert!(parse_entry("bogus:token\n").is_err());
    }

    #[test]
    fn shard_takes_two_nixbase32_chars() {
        assert_eq!(shard("r4q1m2kp8v3x").unwrap(), "r4");
        assert!(shard("r").is_err()); // too short
        assert!(shard("Euppercase").is_err()); // 'E'/'u' are not nixbase32
        assert!(shard("hello000000000000").is_err()); // 'e'/'o' are not nixbase32
        assert!(shard("../escape").is_err()); // path traversal
        assert!(shard("a/b").is_err());
    }

    #[test]
    fn upsert_load_roundtrip_and_conflict() {
        let tmp = TempDir::new().unwrap();
        let ia = "r4q1m2kp8v3x";
        let r1 = Realisation {
            nar: nar(D_A, 10),
            ca: Some(D_C.to_string()),
            deps: vec![],
        };

        assert_eq!(
            upsert_realisation(tmp.path(), ia, r1.clone(), false).unwrap(),
            UpsertOutcome::Created
        );
        assert_eq!(
            upsert_realisation(tmp.path(), ia, r1.clone(), false).unwrap(),
            UpsertOutcome::AlreadyPresent
        );

        // Different bytes for the same path ⇒ conflict without bless.
        let r1_bad = Realisation {
            nar: nar(D_B, 11),
            ca: Some(D_C.to_string()),
            deps: vec![],
        };
        assert!(matches!(
            upsert_realisation(tmp.path(), ia, r1_bad.clone(), false).unwrap(),
            UpsertOutcome::Conflict(_)
        ));
        assert_eq!(
            upsert_realisation(tmp.path(), ia, r1_bad, true).unwrap(),
            UpsertOutcome::Blessed
        );

        // A new CA realisation of bytes ALREADY recorded (r1's nar) is an
        // additive refinement — no bless needed.
        let r2 = Realisation {
            nar: nar(D_A, 10),
            ca: Some(D_A.to_string()),
            deps: vec![],
        };
        assert_eq!(
            upsert_realisation(tmp.path(), ia, r2, false).unwrap(),
            UpsertOutcome::Blessed
        );

        let map = StoreMap::load(tmp.path()).unwrap();
        assert!(map.is_present());
        assert_eq!(map.len(), 1);
        assert!(tmp.path().join(STORE_DIR).join("r4").join(ia).exists());
        // r1 (D_A/D_C), r1_bad (D_B/D_C), r2 (D_A/D_A) ⇒ 3 realisations.
        assert_eq!(map.get(ia).unwrap().realisations.len(), 3);
    }

    #[test]
    fn remove_revokes_and_cleans_up() {
        let tmp = TempDir::new().unwrap();
        let ia = "r4q1m2kp8v3x";
        upsert_realisation(
            tmp.path(),
            ia,
            Realisation {
                nar: nar(D_A, 10),
                ca: Some(D_C.to_string()),
                deps: vec![],
            },
            false,
        )
        .unwrap();
        upsert_realisation(
            tmp.path(),
            ia,
            Realisation {
                nar: nar(D_B, 20),
                ca: Some(D_A.to_string()),
                deps: vec![],
            },
            true,
        )
        .unwrap();

        // Revoke one realisation by CA.
        assert!(remove_realisations(tmp.path(), ia, Some(&format!("sha256:{D_C}"))).unwrap());
        let map = StoreMap::load(tmp.path()).unwrap();
        assert_eq!(map.get(ia).unwrap().realisations.len(), 1);

        // Revoke the rest ⇒ file gone.
        assert!(remove_realisations(tmp.path(), ia, None).unwrap());
        assert!(!tmp.path().join(STORE_DIR).join("r4").join(ia).exists());
        assert!(!remove_realisations(tmp.path(), ia, None).unwrap());
    }

    #[test]
    fn load_rejects_misfiled_record() {
        let tmp = TempDir::new().unwrap();
        // Write a record under the wrong shard.
        let wrong = tmp.path().join(STORE_DIR).join("zz");
        std::fs::create_dir_all(&wrong).unwrap();
        std::fs::write(wrong.join("r4q1m2kp8v3x"), format!("nar:sha256:{D_A}:1\n")).unwrap();
        assert!(
            StoreMap::load(tmp.path())
                .unwrap_err()
                .to_string()
                .contains("misfiled")
        );
    }

    #[test]
    fn absent_dir_is_not_present() {
        let tmp = TempDir::new().unwrap();
        let map = StoreMap::load(tmp.path()).unwrap();
        assert!(!map.is_present());
        assert!(map.is_empty());
        assert!(map.get("anything").is_none());
        assert!(
            map.realization_subset_hash(&["anything".to_string()])
                .is_err()
        );
    }

    #[test]
    fn realization_subset_hash_is_order_independent_and_covers_dependencies() {
        let tmp = TempDir::new().unwrap();
        let root = "a4q1m2kp8v3x";
        upsert_realisation(
            tmp.path(),
            DEP_IA,
            Realisation {
                nar: nar(D_A, 10),
                ca: None,
                deps: vec![],
            },
            false,
        )
        .unwrap();
        upsert_realisation(
            tmp.path(),
            root,
            Realisation {
                nar: nar(D_B, 20),
                ca: None,
                deps: vec![DepEdge {
                    dep_ia: DEP_IA.to_string(),
                    dep_ca: None,
                }],
            },
            false,
        )
        .unwrap();

        let before = StoreMap::load(tmp.path()).unwrap();
        let forward = before
            .realization_subset_hash(&[root.to_string(), DEP_IA.to_string()])
            .unwrap();
        let reverse = before
            .realization_subset_hash(&[DEP_IA.to_string(), root.to_string()])
            .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.len(), 71);

        upsert_realisation(
            tmp.path(),
            DEP_IA,
            Realisation {
                nar: nar(D_C, 30),
                ca: None,
                deps: vec![],
            },
            true,
        )
        .unwrap();
        let after = StoreMap::load(tmp.path()).unwrap();
        assert_ne!(
            forward,
            after.realization_subset_hash(&[root.to_string()]).unwrap()
        );
        assert!(
            after
                .realization_subset_hash(&["missing0000".to_string()])
                .is_err()
        );

        let empty_root = "b4q1m2kp8v3x";
        let empty_path = tmp.path().join(STORE_DIR).join("b4");
        std::fs::create_dir_all(&empty_path).unwrap();
        std::fs::write(empty_path.join(empty_root), "").unwrap();
        let with_empty = StoreMap::load(tmp.path()).unwrap();
        assert!(
            with_empty
                .realization_subset_hash(&[empty_root.to_string()])
                .is_err()
        );
    }

    #[test]
    fn trust_context_enforces_per_source_registry() {
        let mapped = TempDir::new().unwrap();
        upsert_realisation(
            mapped.path(),
            "r4q1m2kp8v3x",
            Realisation {
                nar: nar(D_A, 10),
                ca: None,
                deps: vec![],
            },
            false,
        )
        .unwrap();
        let legacy = TempDir::new().unwrap();
        std::fs::create_dir_all(legacy.path()).unwrap();

        let present = StoreMap::load(mapped.path()).unwrap();
        let absent = StoreMap::load(legacy.path()).unwrap();

        // Enforced + blessed for a mapped path; not enforced for a legacy one.
        let mut ctx = TrustContext::new();
        ctx.insert("r4q1m2kp8v3x".to_string(), &present);
        ctx.insert("legacypath000".to_string(), &absent);
        assert!(ctx.enforced("r4q1m2kp8v3x"));
        assert_eq!(ctx.blessed_nars("r4q1m2kp8v3x"), vec![nar(D_A, 10)]);
        assert!(!ctx.enforced("legacypath000"));
        assert!(ctx.any_present());
        ctx.enforce_totality().unwrap();

        // A legacy registry attributing the same hash cannot shadow a mapped
        // one (presence is sticky), regardless of insert order.
        let mut sticky = TrustContext::new();
        sticky.insert("r4q1m2kp8v3x".to_string(), &absent);
        sticky.insert("r4q1m2kp8v3x".to_string(), &present);
        assert!(sticky.enforced("r4q1m2kp8v3x"));
        sticky.enforce_totality().unwrap();

        // A mapped registry missing a record for one of its members is a
        // stripping signature - totality fails.
        let mut stripped = TrustContext::new();
        stripped.insert("unmapped00000".to_string(), &present);
        assert!(stripped.enforced("unmapped00000"));
        assert!(stripped.enforce_totality().is_err());
    }
}

//! Pure-Rust thin packfile generation for RFC-0005 delta release transfer.
//!
//! libgit2's `PackBuilder` only emits self-contained packs, so it cannot
//! replace `git pack-objects --thin` (delta-encode the objects new in a release
//! against objects from a *previous* release that are not in the pack). This
//! module writes such a thin pack directly.
//!
//! # What it produces
//!
//! A SHA-256 packfile containing exactly the objects reachable from `to` but
//! not from `from`. Several construction strategies are tried (store-whole,
//! same-path delta, windowed delta) and the one with the smallest *zstd-wrapped*
//! size — the artifact actually transferred — is kept, so the choice can never
//! be worse than any single strategy. New blobs chosen for delta are stored as
//! `OBJ_REF_DELTA` (a 32-byte base OID + a copy/insert delta). The consumer
//! completes the pack with libgit2's pack-writer (`git index-pack --fix-thin`
//! semantics), which resolves the external bases from its own object store —
//! verified to work for SHA-256.
//!
//! # Pack wire format (SHA-256)
//!
//! ```text
//! "PACK" | u32 version=2 (BE) | u32 object-count (BE)
//! per object:
//!   varint type+size header  (type: 1=commit 2=tree 3=blob 4=tag 7=ref-delta)
//!   ref-delta only: 32-byte base OID
//!   zlib(object body | delta data)
//! trailer: 32-byte SHA-256 of all preceding bytes
//! ```

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// Minimum match length for the hash-chain fallback delta encoder.
const MATCH_WINDOW: usize = 16;

/// Largest base for which a suffix array is built; larger bases fall back to the
/// hash matcher (bounding O(n log n) index construction memory/time).
const SUFFIX_ARRAY_MAX_BASE: usize = 16 << 20;

/// Candidate bases considered per blob by the windowed strategy (same-path,
/// same-basename, and nearest-by-size neighbours).
const BASE_WINDOW: usize = 16;

/// zstd level used to *rank* candidate packs. Lower than the production level
/// for speed; the ordering between candidates is stable across levels.
const PROBE_LEVEL: i32 = 19;

/// zstd long-distance window log used for both ranking and production
/// ([`crate::registry::pack::ZSTD_LONG`]); the 128 MiB window is what lets zstd
/// dedup across pack objects, so it must be on when ranking.
const PROBE_WINDOW_LOG: u32 = 27;

/// git object type codes used in pack object headers.
const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_REF_DELTA: u8 = 7;

/// A pack-construction strategy. Each produces a complete, valid thin pack;
/// [`write_thin_pack`] builds one pack per strategy and keeps whichever has the
/// smallest zstd-wrapped size, so adding a strategy can only help.
#[derive(Clone, Copy, Debug)]
enum Strategy {
    /// Store every object whole and let the zstd-long wrapper dedup across
    /// them — best when new blobs resemble each other more than `from`.
    Whole,
    /// Delta each blob against the same-path blob in `from` — best for
    /// in-place edits, whose prior version (external to the pack) is the ideal
    /// base and which zstd cannot otherwise reach.
    SamePath,
    /// Delta each blob against the best of a window of candidate bases in
    /// `from` (same path, same basename, nearest size) — catches renames and
    /// new-but-similar files.
    Windowed,
}

/// Strategies tried for every release; the smallest zstd-wrapped result wins.
const STRATEGIES: [Strategy; 3] = [Strategy::Whole, Strategy::SamePath, Strategy::Windowed];

/// One object to pack, read into memory with its tip-tree path for base
/// selection.
struct Input {
    kind: git2::ObjectType,
    data: Vec<u8>,
    path: Option<String>,
}

/// Write a thin pack of the objects in `to` but not in `from` to `out_path`.
///
/// Equivalent to `git pack-objects --thin` over `to ^from`. Builds one
/// candidate pack per [`Strategy`] and writes whichever has the smallest
/// zstd-wrapped size — the artifact actually transferred — so the choice can
/// never be worse than any single strategy. Objects are read single-threaded
/// (libgit2's odb is not `Send`); the per-strategy delta search runs in
/// parallel with rayon.
///
/// # Errors
///
/// Returns an error if the repository cannot be opened, the commits cannot be
/// resolved, an object cannot be read, or the pack cannot be written.
pub(crate) fn write_thin_pack(
    repo_dir: &Path,
    from_commit: &str,
    to_commit: &str,
    out_path: &Path,
) -> Result<()> {
    let repo = git2::Repository::open(repo_dir)
        .with_context(|| format!("opening git repository at {}", repo_dir.display()))?;
    let from = repo
        .revparse_single(from_commit)
        .with_context(|| format!("resolving {from_commit}"))?
        .peel_to_commit()
        .with_context(|| format!("{from_commit} is not a commit"))?
        .id();
    let to = repo
        .revparse_single(to_commit)
        .with_context(|| format!("resolving {to_commit}"))?
        .peel_to_commit()
        .with_context(|| format!("{to_commit} is not a commit"))?
        .id();

    let from_objects = reachable_from(&repo, from)?;
    let to_objects = reachable_from(&repo, to)?;
    let pool = build_base_pool(&repo, from)?;
    let to_path_by_object = object_paths(&repo, to)?;
    let odb = repo.odb().context("opening object database")?;

    // Read phase (single-thread): load each to-pack object, and gather every
    // base any strategy might use (the windowed window is a superset).
    let mut inputs: Vec<Input> = Vec::new();
    let mut needed_bases: HashSet<git2::Oid> = HashSet::new();
    for oid in to_objects.difference(&from_objects) {
        let object = odb
            .read(*oid)
            .with_context(|| format!("reading object {oid}"))?;
        let kind = object.kind();
        let data = object.data().to_vec();
        let path = if matches!(kind, git2::ObjectType::Blob | git2::ObjectType::Tree) {
            to_path_by_object.get(oid).cloned()
        } else {
            None
        };
        if let Some(path) = &path {
            for base in pool.select(path, data.len()) {
                needed_bases.insert(base);
            }
        }
        inputs.push(Input { kind, data, path });
    }
    let mut base_data: HashMap<git2::Oid, Vec<u8>> = HashMap::with_capacity(needed_bases.len());
    for base in needed_bases {
        if let Ok(object) = odb.read(base) {
            base_data.insert(base, object.data().to_vec());
        }
    }

    // Precompute a suffix array per base (in parallel, once) so the delta
    // search finds optimal longest matches without rebuilding the index per
    // blob. Oversized bases are skipped (they fall back to the hash matcher).
    let base_index: HashMap<git2::Oid, Vec<u32>> = base_data
        .par_iter()
        .filter(|(_, data)| !data.is_empty() && data.len() <= SUFFIX_ARRAY_MAX_BASE)
        .map(|(oid, data)| (*oid, build_suffix_array(data)))
        .collect();

    // Build a candidate pack per strategy, then keep the one whose zstd-wrapped
    // size is smallest (the production transport artifact).
    let mut best: Option<Vec<u8>> = None;
    let mut best_len = usize::MAX;
    for strategy in STRATEGIES {
        let pack = build_pack(&inputs, strategy, &pool, &base_data, &base_index)?;
        let zlen = zstd_probe_len(&pack)
            .with_context(|| format!("ranking {strategy:?} pack candidate"))?;
        if zlen < best_len {
            best_len = zlen;
            best = Some(pack);
        }
    }
    let pack = best.context("no pack strategy produced output")?;

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(out_path, &pack).with_context(|| format!("writing {}", out_path.display()))?;
    Ok(())
}

/// Build one candidate pack under `strategy`, delta-searching objects in
/// parallel.
fn build_pack(
    inputs: &[Input],
    strategy: Strategy,
    pool: &BasePool,
    base_data: &HashMap<git2::Oid, Vec<u8>>,
    base_index: &HashMap<git2::Oid, Vec<u32>>,
) -> Result<Vec<u8>> {
    let entries = inputs
        .par_iter()
        .map(|input| encode_input(input, strategy, pool, base_data, base_index))
        .collect::<Result<Vec<_>>>()?;
    Ok(assemble_pack(&entries))
}

/// Encode one object under `strategy`: pick the smallest delta over the
/// strategy's candidate bases (when it beats storing the blob), else store the
/// object whole.
fn encode_input(
    input: &Input,
    strategy: Strategy,
    pool: &BasePool,
    base_data: &HashMap<git2::Oid, Vec<u8>>,
    base_index: &HashMap<git2::Oid, Vec<u32>>,
) -> Result<Vec<u8>> {
    if matches!(input.kind, git2::ObjectType::Blob | git2::ObjectType::Tree)
        && let Some(path) = &input.path
    {
        let bases = match strategy {
            Strategy::Whole => Vec::new(),
            Strategy::SamePath => pool.by_path.get(path).copied().into_iter().collect(),
            Strategy::Windowed => pool.select(path, input.data.len()),
        };
        let mut best: Option<(git2::Oid, Vec<u8>)> = None;
        for (index, base_oid) in bases.iter().enumerate() {
            let Some(base) = base_data.get(base_oid) else {
                continue;
            };
            let delta = encode_delta(
                base,
                &input.data,
                base_index.get(base_oid).map(Vec::as_slice),
            );
            if best.as_ref().is_none_or(|(_, b)| delta.len() < b.len()) {
                best = Some((*base_oid, delta));
            }
            // The same-path base (index 0) is usually optimal; stop early if it
            // already halves the blob.
            if index == 0
                && let Some((_, b)) = &best
                && b.len() * 2 < input.data.len()
            {
                break;
            }
        }
        if let Some((base_oid, delta)) = best
            && delta.len() < input.data.len()
        {
            return encode_entry(OBJ_REF_DELTA, &delta, Some(base_oid));
        }
    }
    encode_entry(type_code(input.kind)?, &input.data, None)
}

/// Compress `data` with the production zstd parameters and return its size,
/// for ranking candidate packs by their transport size.
fn zstd_probe_len(data: &[u8]) -> Result<usize> {
    let mut encoder =
        zstd::stream::write::Encoder::new(Vec::new(), PROBE_LEVEL).context("zstd encoder")?;
    encoder
        .long_distance_matching(true)
        .context("enabling zstd long-distance matching")?;
    encoder
        .window_log(PROBE_WINDOW_LOG)
        .context("setting zstd window log")?;
    encoder.write_all(data).context("zstd probe write")?;
    Ok(encoder.finish().context("zstd probe finish")?.len())
}

/// Enumerate every object reachable from `commit`: the commit and its
/// ancestors, plus each commit's tree, subtrees, and blobs.
fn reachable_from(repo: &git2::Repository, commit: git2::Oid) -> Result<HashSet<git2::Oid>> {
    let mut seen = HashSet::new();
    let mut revwalk = repo.revwalk().context("creating revwalk")?;
    revwalk.push(commit).context("seeding revwalk")?;
    for oid in revwalk {
        let commit_oid = oid?;
        seen.insert(commit_oid);
        let commit = repo
            .find_commit(commit_oid)
            .with_context(|| format!("reading commit {commit_oid}"))?;
        let tree = commit.tree().context("reading commit tree")?;
        collect_tree(repo, &tree, &mut seen)?;
    }
    Ok(seen)
}

/// Record every tree and blob OID reachable from `tree`.
fn collect_tree(
    repo: &git2::Repository,
    tree: &git2::Tree<'_>,
    seen: &mut HashSet<git2::Oid>,
) -> Result<()> {
    if !seen.insert(tree.id()) {
        return Ok(());
    }
    for entry in tree.iter() {
        match entry.kind() {
            Some(git2::ObjectType::Tree) => {
                let object = entry.to_object(repo)?;
                if let Some(subtree) = object.as_tree() {
                    collect_tree(repo, subtree, seen)?;
                }
            }
            Some(git2::ObjectType::Blob) => {
                seen.insert(entry.id());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Map each blob OID in `commit`'s tip tree to its path, for selecting a
/// to-pack blob's path when choosing candidate bases.
/// Map each blob and tree (sub)object in `commit`'s tip tree to its path (the
/// root tree maps to the empty path), for choosing same-path delta bases. Trees
/// are included because directory listings change incrementally between releases
/// and delta well against the previous release's same-path tree.
fn object_paths(repo: &git2::Repository, commit: git2::Oid) -> Result<HashMap<git2::Oid, String>> {
    let mut map = HashMap::new();
    let tree = repo.find_commit(commit)?.tree()?;
    map.insert(tree.id(), String::new());
    tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        if matches!(
            entry.kind(),
            Some(git2::ObjectType::Blob | git2::ObjectType::Tree)
        ) && let Ok(name) = entry.name()
        {
            map.insert(entry.id(), format!("{root}{name}"));
        }
        git2::TreeWalkResult::Ok
    })
    .context("walking tip tree")?;
    Ok(map)
}

/// Candidate delta-base pool: the blobs in `from`'s tip tree, indexed by path,
/// basename, and size, so [`BasePool::select`] can offer a bounded window of
/// plausible bases per to-pack blob.
struct BasePool {
    by_path: HashMap<String, git2::Oid>,
    by_basename: HashMap<String, Vec<usize>>,
    /// `(oid, size)` for every candidate blob.
    entries: Vec<(git2::Oid, usize)>,
    /// Indices into `entries`, sorted ascending by size.
    size_sorted: Vec<usize>,
}

impl BasePool {
    /// Candidate bases for a blob at `path` of `size` bytes: the same-path blob
    /// first (usually optimal), then same-basename and nearest-by-size
    /// neighbours, deduplicated and capped.
    fn select(&self, path: &str, size: usize) -> Vec<git2::Oid> {
        let mut out: Vec<git2::Oid> = Vec::new();
        let mut seen: HashSet<git2::Oid> = HashSet::new();
        let push = |oid: git2::Oid, out: &mut Vec<git2::Oid>, seen: &mut HashSet<git2::Oid>| {
            if seen.insert(oid) {
                out.push(oid);
            }
        };

        if let Some(&oid) = self.by_path.get(path) {
            push(oid, &mut out, &mut seen);
        }
        if let Some(indices) = self.by_basename.get(basename(path)) {
            for &i in indices.iter().take(BASE_WINDOW) {
                push(self.entries[i].0, &mut out, &mut seen);
            }
        }
        let pivot = self
            .size_sorted
            .partition_point(|&i| self.entries[i].1 < size);
        let lo = pivot.saturating_sub(BASE_WINDOW);
        let hi = (pivot + BASE_WINDOW).min(self.size_sorted.len());
        for &i in &self.size_sorted[lo..hi] {
            push(self.entries[i].0, &mut out, &mut seen);
        }

        out.truncate(BASE_WINDOW * 2);
        out
    }
}

/// Build the [`BasePool`] from `from`'s tip tree, reading only object headers
/// (not bodies) for sizes.
fn build_base_pool(repo: &git2::Repository, from: git2::Oid) -> Result<BasePool> {
    let odb = repo.odb().context("opening object database")?;
    let tree = repo.find_commit(from)?.tree()?;
    // (path, oid) for the root tree plus every blob and subtree.
    let mut objects: Vec<(String, git2::Oid)> = vec![(String::new(), tree.id())];
    tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        if matches!(
            entry.kind(),
            Some(git2::ObjectType::Blob | git2::ObjectType::Tree)
        ) && let Ok(name) = entry.name()
        {
            objects.push((format!("{root}{name}"), entry.id()));
        }
        git2::TreeWalkResult::Ok
    })
    .context("walking base tree")?;

    let mut by_path = HashMap::new();
    let mut by_basename: HashMap<String, Vec<usize>> = HashMap::new();
    let mut entries: Vec<(git2::Oid, usize)> = Vec::new();
    for (path, oid) in objects {
        let size = odb.read_header(oid).map(|(size, _)| size).unwrap_or(0);
        let index = entries.len();
        entries.push((oid, size));
        by_basename
            .entry(basename(&path).to_string())
            .or_default()
            .push(index);
        by_path.insert(path, oid);
    }
    let mut size_sorted: Vec<usize> = (0..entries.len()).collect();
    size_sorted.sort_by_key(|&i| entries[i].1);
    Ok(BasePool {
        by_path,
        by_basename,
        entries,
        size_sorted,
    })
}

/// The final path component of `path` (its basename).
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Map a git2 object kind to its pack type code.
fn type_code(kind: git2::ObjectType) -> Result<u8> {
    Ok(match kind {
        git2::ObjectType::Commit => OBJ_COMMIT,
        git2::ObjectType::Tree => OBJ_TREE,
        git2::ObjectType::Blob => OBJ_BLOB,
        git2::ObjectType::Tag => OBJ_TAG,
        other => bail!("cannot pack object of type {other:?}"),
    })
}

/// Encode one pack entry: the type+size header, an optional 32-byte ref-delta
/// base OID, and the deflated body.
///
/// The body is deflated at level 0 (a valid zlib stream of stored blocks,
/// equivalent to `git pack-objects --compression=0`). The pack is not the final
/// transfer artifact — it is wrapped with `zstd --long` ([`crate::registry::pack::zstd_compress`]),
/// whose 128 MiB window compresses across objects far better than per-object
/// zlib could, so we leave the bytes uncompressed here and let zstd do the work.
fn encode_entry(obj_type: u8, body: &[u8], base: Option<git2::Oid>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_obj_header(&mut out, obj_type, body.len());
    if let Some(base) = base {
        out.extend_from_slice(base.as_bytes());
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::none());
    encoder.write_all(body).context("deflating pack entry")?;
    out.extend_from_slice(&encoder.finish().context("finishing zlib stream")?);
    Ok(out)
}

/// Assemble the full packfile from encoded entries, appending the SHA-256
/// trailer.
fn assemble_pack(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        pack.extend_from_slice(entry);
    }
    let digest = Sha256::digest(&pack);
    pack.extend_from_slice(&digest);
    pack
}

/// Write a pack object header: type in bits 4-6 of the first byte, size as a
/// little-endian base-128 varint (4 low bits in the first byte, then 7 bits
/// per continuation byte).
fn write_obj_header(out: &mut Vec<u8>, obj_type: u8, size: usize) {
    let mut size = size;
    let mut byte = (obj_type << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    while size > 0 {
        out.push(byte | 0x80);
        byte = (size & 0x7f) as u8;
        size >>= 7;
    }
    out.push(byte);
}

/// Encode a git binary delta that reconstructs `target` from `base`.
///
/// Output: base size varint, target size varint, then copy (from base) and
/// insert (literal) instructions. When `sa` is the base's suffix array the
/// encoder finds the optimal longest match at every position (smallest deltas);
/// otherwise (oversized base) it falls back to a 16-byte hash-index matcher.
fn encode_delta(base: &[u8], target: &[u8], sa: Option<&[u32]>) -> Vec<u8> {
    let mut out = Vec::new();
    write_size_varint(&mut out, base.len());
    write_size_varint(&mut out, target.len());
    match sa {
        Some(sa) => emit_with_suffix_array(&mut out, base, target, sa),
        None => emit_with_hash(&mut out, base, target),
    }
    out
}

/// Emit copy/insert instructions using the base's suffix array for an optimal
/// longest match at each target position.
fn emit_with_suffix_array(out: &mut Vec<u8>, base: &[u8], target: &[u8], sa: &[u32]) {
    let mut pending: Vec<u8> = Vec::new();
    let mut j = 0;
    while j < target.len() {
        let (off, len) = suffix_longest_match(sa, base, &target[j..]);
        // Take the copy only when it encodes smaller than the literals it
        // replaces (short matches with a wide offset are not worth it).
        if len >= 4 && copy_encoded_len(off, len) < len {
            flush_inserts(out, &mut pending);
            emit_copy(out, off, len);
            j += len;
        } else {
            pending.push(target[j]);
            j += 1;
        }
    }
    flush_inserts(out, &mut pending);
}

/// Emit copy/insert instructions using a 16-byte hash index of the base (the
/// fallback when no suffix array was built).
fn emit_with_hash(out: &mut Vec<u8>, base: &[u8], target: &[u8]) {
    let mut index: HashMap<&[u8], Vec<usize>> = HashMap::new();
    if base.len() >= MATCH_WINDOW {
        for i in 0..=base.len() - MATCH_WINDOW {
            index.entry(&base[i..i + MATCH_WINDOW]).or_default().push(i);
        }
    }
    let mut pending: Vec<u8> = Vec::new();
    let mut j = 0;
    while j < target.len() {
        let mut best_off = 0;
        let mut best_len = 0;
        if j + MATCH_WINDOW <= target.len()
            && let Some(offsets) = index.get(&target[j..j + MATCH_WINDOW])
        {
            for &off in offsets {
                let mut len = MATCH_WINDOW;
                while off + len < base.len()
                    && j + len < target.len()
                    && base[off + len] == target[j + len]
                {
                    len += 1;
                }
                if len > best_len {
                    best_len = len;
                    best_off = off;
                }
            }
        }
        if best_len >= MATCH_WINDOW {
            flush_inserts(out, &mut pending);
            emit_copy(out, best_off, best_len);
            j += best_len;
        } else {
            pending.push(target[j]);
            j += 1;
        }
    }
    flush_inserts(out, &mut pending);
}

/// Build the suffix array of `base` (rank-doubling, O(n log^2 n)).
fn build_suffix_array(base: &[u8]) -> Vec<u32> {
    let n = base.len();
    let mut sa: Vec<u32> = (0..n as u32).collect();
    if n <= 1 {
        return sa;
    }
    let mut rank: Vec<i32> = base.iter().map(|&b| b as i32).collect();
    let mut next = vec![0i32; n];
    let mut k = 1usize;
    loop {
        let key = |i: usize| -> (i32, i32) { (rank[i], if i + k < n { rank[i + k] } else { -1 }) };
        sa.sort_unstable_by(|&a, &b| key(a as usize).cmp(&key(b as usize)));
        next[sa[0] as usize] = 0;
        for w in 1..n {
            let prev = sa[w - 1] as usize;
            let cur = sa[w] as usize;
            next[cur] = next[prev] + i32::from(key(prev) != key(cur));
        }
        rank.copy_from_slice(&next);
        if rank[sa[n - 1] as usize] as usize == n - 1 {
            break;
        }
        k <<= 1;
    }
    sa
}

/// Longest substring of `base` that is a prefix of `target`, returned as
/// `(offset, len)`. The maximal match is at one of the two suffix-array
/// neighbours of `target`'s insertion point.
fn suffix_longest_match(sa: &[u32], base: &[u8], target: &[u8]) -> (usize, usize) {
    let mut lo = 0usize;
    let mut hi = sa.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if base[sa[mid] as usize..] < *target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut best = (0usize, 0usize);
    for cand in [lo.wrapping_sub(1), lo] {
        if cand < sa.len() {
            let off = sa[cand] as usize;
            let len = common_prefix_len(&base[off..], target);
            if len > best.1 {
                best = (off, len);
            }
        }
    }
    best
}

/// Length of the common prefix of `a` and `b`.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let max = a.len().min(b.len());
    let mut i = 0;
    while i < max && a[i] == b[i] {
        i += 1;
    }
    i
}

/// Encoded byte length of a copy instruction for `(offset, len)` (opcode plus
/// the nonzero offset and size bytes), used to reject copies smaller wins.
fn copy_encoded_len(offset: usize, len: usize) -> usize {
    let mut bytes = 1; // opcode
    let mut o = offset as u32;
    while o > 0 {
        bytes += 1;
        o >>= 8;
    }
    let mut s = (len as u32) & 0x00ff_ffff;
    while s > 0 {
        bytes += 1;
        s >>= 8;
    }
    bytes
}

/// Write a base-128 varint (LSB first) for a delta size header.
fn write_size_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Emit pending literal bytes as insert instructions (chunks of <= 127 bytes).
fn flush_inserts(out: &mut Vec<u8>, pending: &mut Vec<u8>) {
    for chunk in pending.chunks(127) {
        out.push(chunk.len() as u8); // opcode 1..=127, high bit clear = insert
        out.extend_from_slice(chunk);
    }
    pending.clear();
}

/// Emit copy instructions for `len` bytes from base `off`, splitting on the
/// 24-bit copy-size limit.
fn emit_copy(out: &mut Vec<u8>, mut off: usize, mut len: usize) {
    while len > 0 {
        let chunk = len.min(0x00ff_ffff);
        let mut opcode: u8 = 0x80;
        let mut operands = Vec::new();
        let o = off as u32;
        for b in 0..4 {
            let byte = ((o >> (8 * b)) & 0xff) as u8;
            if byte != 0 {
                opcode |= 1 << b;
                operands.push(byte);
            }
        }
        let s = chunk as u32;
        for b in 0..3 {
            let byte = ((s >> (8 * b)) & 0xff) as u8;
            if byte != 0 {
                opcode |= 1 << (4 + b);
                operands.push(byte);
            }
        }
        out.push(opcode);
        out.extend_from_slice(&operands);
        off += chunk;
        len -= chunk;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference delta applier, used to round-trip the encoder.
    fn apply_delta(base: &[u8], delta: &[u8]) -> Vec<u8> {
        let mut i = 0;
        let read_varint = |delta: &[u8], i: &mut usize| -> usize {
            let mut value = 0usize;
            let mut shift = 0;
            loop {
                let byte = delta[*i];
                *i += 1;
                value |= ((byte & 0x7f) as usize) << shift;
                shift += 7;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            value
        };
        let _base_size = read_varint(delta, &mut i);
        let target_size = read_varint(delta, &mut i);
        let mut out = Vec::with_capacity(target_size);
        while i < delta.len() {
            let opcode = delta[i];
            i += 1;
            if opcode & 0x80 != 0 {
                let mut off = 0usize;
                for b in 0..4 {
                    if opcode & (1 << b) != 0 {
                        off |= (delta[i] as usize) << (8 * b);
                        i += 1;
                    }
                }
                let mut size = 0usize;
                for b in 0..3 {
                    if opcode & (1 << (4 + b)) != 0 {
                        size |= (delta[i] as usize) << (8 * b);
                        i += 1;
                    }
                }
                if size == 0 {
                    size = 0x10000;
                }
                out.extend_from_slice(&base[off..off + size]);
            } else {
                let n = opcode as usize;
                out.extend_from_slice(&delta[i..i + n]);
                i += n;
            }
        }
        out
    }

    fn roundtrip(base: &[u8], target: &[u8]) {
        // Exercise both the hash fallback and the suffix-array encoder.
        let sa = build_suffix_array(base);
        for delta in [
            encode_delta(base, target, None),
            encode_delta(base, target, Some(&sa)),
        ] {
            assert_eq!(
                apply_delta(base, &delta),
                target,
                "delta round-trip mismatch"
            );
        }
    }

    #[test]
    fn delta_roundtrips_identical() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(20);
        roundtrip(&data, &data);
    }

    #[test]
    fn delta_roundtrips_small_edit() {
        let base = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let mut target = base.clone();
        target.splice(50..60, b"CHANGED!!!".iter().copied());
        target.extend_from_slice(b"trailing addition");
        roundtrip(&base, &target);
    }

    #[test]
    fn delta_roundtrips_disjoint() {
        roundtrip(
            b"completely different base content here",
            b"unrelated target data entirely",
        );
    }

    #[test]
    fn delta_roundtrips_empty_base() {
        roundtrip(b"", b"new content with no base at all");
    }

    #[test]
    fn obj_header_encodes_type_and_size() {
        // blob (3) of size 0x0f fits in one byte: type<<4 | size.
        let mut out = Vec::new();
        write_obj_header(&mut out, OBJ_BLOB, 0x0f);
        assert_eq!(out, vec![(OBJ_BLOB << 4) | 0x0f]);
        // size 0x10 needs a continuation byte.
        let mut out = Vec::new();
        write_obj_header(&mut out, OBJ_BLOB, 0x10);
        assert_eq!(out, vec![(OBJ_BLOB << 4) | 0x80, 0x01]);
    }

    /// Deterministic, registry-like file content; `version > 0` perturbs a few
    /// lines to model an incremental edit.
    /// A deterministic per-`(seed, line)` value, so unchanged lines stay
    /// byte-identical across versions while distinct files have distinct
    /// content.
    fn line_val(seed: usize, line: usize) -> u64 {
        let mut h = (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (line as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        h ^= h >> 29;
        h
    }

    fn gen_file(seed: usize, version: usize) -> Vec<u8> {
        let mut s = String::new();
        for line in 0..120 {
            if version > 0 && line % 30 == 7 {
                s.push_str(&format!(
                    "edited line {line} v{version}: {:016x}\n",
                    line_val(seed, line)
                ));
            } else {
                s.push_str(&format!(
                    "field_{line} = \"{:016x}-{:016x}\"\n",
                    line_val(seed, line),
                    line_val(seed, line + 1000)
                ));
            }
        }
        s.into_bytes()
    }

    /// Compare our thin pack against `git pack-objects --thin` on a realistic
    /// two-release fixture, both wrapped with the production zstd flags. Prints
    /// raw and zstd sizes; run with:
    ///   cargo test -p aos-package --lib thinpack::tests::bench_thin_pack -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_thin_pack_size_vs_git() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let tmp = tempfile::TempDir::new().unwrap();
        let repo = tmp.path().join("reg");
        std::fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        git(&["init", "-q", "--object-format=sha256"]);
        git(&["config", "user.email", "a@example.com"]);
        git(&["config", "user.name", "a"]);
        git(&["config", "commit.gpgsign", "false"]);

        let pkgs = repo.join("packages");
        std::fs::create_dir_all(&pkgs).unwrap();
        for i in 0..200 {
            std::fs::write(pkgs.join(format!("pkg-{i:03}.toml")), gen_file(i, 0)).unwrap();
        }
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "v1"]);
        let v1 = git(&["rev-parse", "HEAD"]);

        for i in (0..200).step_by(4) {
            std::fs::write(pkgs.join(format!("pkg-{i:03}.toml")), gen_file(i, 1)).unwrap();
        }
        std::fs::rename(pkgs.join("pkg-001.toml"), pkgs.join("pkg-001-renamed.toml")).unwrap();
        for i in 200..205 {
            std::fs::write(pkgs.join(format!("pkg-{i:03}.toml")), gen_file(i, 0)).unwrap();
        }
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "v2"]);
        let v2 = git(&["rev-parse", "HEAD"]);

        // Our pack.
        let ours = tmp.path().join("ours.pack");
        write_thin_pack(&repo, &v1, &v2, &ours).unwrap();

        // git's pack (same tuning the producer used historically).
        let mut child = Command::new("git")
            .args([
                "-C",
                repo.to_str().unwrap(),
                "pack-objects",
                "--thin",
                "--stdout",
                "--compression=0",
                "--window=350",
                "--depth=50",
            ])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{v2}\n^{v1}\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git pack-objects: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let git_pack = tmp.path().join("git.pack");
        std::fs::write(&git_pack, &out.stdout).unwrap();

        let zst = |p: &std::path::Path| -> u64 {
            let dst = format!("{}.zst", p.display());
            let o = Command::new("zstd")
                .args([
                    "--ultra",
                    "-22",
                    "--long=27",
                    "-q",
                    "-f",
                    "-o",
                    &dst,
                    p.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "zstd: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            std::fs::metadata(&dst).unwrap().len()
        };

        let (our_raw, git_raw) = (
            std::fs::metadata(&ours).unwrap().len(),
            std::fs::metadata(&git_pack).unwrap().len(),
        );
        let (our_z, git_z) = (zst(&ours), zst(&git_pack));
        println!("[bench] raw  pack: ours={our_raw} git={git_raw}");
        println!(
            "[bench] zstd pack: ours={our_z} git={git_z}  (ours/git = {:.3}x)",
            our_z as f64 / git_z as f64
        );
    }
}

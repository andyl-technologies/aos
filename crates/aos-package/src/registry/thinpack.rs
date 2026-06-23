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
//! not from `from`. Each new blob that has a same-path counterpart in `from` is
//! stored as an `OBJ_REF_DELTA` against that counterpart (a 32-byte base OID +
//! a zlib-compressed copy/insert delta); everything else is stored whole. The
//! consumer completes the pack with libgit2's pack-writer (`git index-pack
//! --fix-thin` semantics), which resolves the external bases from its own
//! object store — verified to work for SHA-256.
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
use sha2::{Digest, Sha256};

/// Minimum match length (and base-index window) for the delta encoder.
const MATCH_WINDOW: usize = 16;

/// git object type codes used in pack object headers.
const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_REF_DELTA: u8 = 7;

/// Write a thin pack of the objects in `to` but not in `from` to `out_path`.
///
/// Equivalent to `git pack-objects --thin` over `to ^from`. New blobs are
/// delta-encoded against the same-path blob in `from` when one exists; all
/// other objects (commits, trees, tags, and blobs without a base) are stored
/// whole.
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

    // Same-path blob bases: a blob new in `to` is delta-encoded against the
    // blob at the same path in `from`'s tip tree, which the consumer has.
    let from_blob_by_path = tip_blob_paths(&repo, from)?;
    let to_path_by_blob = invert_blob_paths(&repo, to)?;

    let odb = repo.odb().context("opening object database")?;
    let mut entries: Vec<Vec<u8>> = Vec::new();

    for oid in to_objects.difference(&from_objects) {
        let object = odb
            .read(*oid)
            .with_context(|| format!("reading object {oid}"))?;
        let kind = object.kind();
        let data = object.data();

        if kind == git2::ObjectType::Blob
            && let Some(path) = to_path_by_blob.get(oid)
            && let Some(base_oid) = from_blob_by_path.get(path)
            && let Ok(base) = odb.read(*base_oid)
        {
            let delta = encode_delta(base.data(), data);
            // Only worth a ref-delta if it actually beats storing the blob.
            if delta.len() < data.len() {
                entries.push(encode_entry(OBJ_REF_DELTA, &delta, Some(*base_oid))?);
                continue;
            }
        }
        entries.push(encode_entry(type_code(kind)?, data, None)?);
    }

    let pack = assemble_pack(&entries);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(out_path, &pack).with_context(|| format!("writing {}", out_path.display()))?;
    Ok(())
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

/// Map each path in `commit`'s tip tree to its blob OID.
fn tip_blob_paths(
    repo: &git2::Repository,
    commit: git2::Oid,
) -> Result<HashMap<String, git2::Oid>> {
    let mut map = HashMap::new();
    let tree = repo.find_commit(commit)?.tree()?;
    tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob)
            && let Ok(name) = entry.name()
        {
            map.insert(format!("{root}{name}"), entry.id());
        }
        git2::TreeWalkResult::Ok
    })
    .context("walking tip tree")?;
    Ok(map)
}

/// Map each blob OID in `commit`'s tip tree to its path (inverse of
/// [`tip_blob_paths`], for base selection).
fn invert_blob_paths(
    repo: &git2::Repository,
    commit: git2::Oid,
) -> Result<HashMap<git2::Oid, String>> {
    Ok(tip_blob_paths(repo, commit)?
        .into_iter()
        .map(|(path, oid)| (oid, path))
        .collect())
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
/// insert (literal) instructions.
fn encode_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_size_varint(&mut out, base.len());
    write_size_varint(&mut out, target.len());

    // Index the base by its MATCH_WINDOW-byte windows.
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
                // Verify the window (guard against hash-map equality on a
                // colliding slice is unnecessary — keys are the bytes), then
                // extend the match as far as possible.
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
            flush_inserts(&mut out, &mut pending);
            emit_copy(&mut out, best_off, best_len);
            j += best_len;
        } else {
            pending.push(target[j]);
            j += 1;
        }
    }
    flush_inserts(&mut out, &mut pending);
    out
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
        let delta = encode_delta(base, target);
        assert_eq!(
            apply_delta(base, &delta),
            target,
            "delta round-trip mismatch"
        );
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
    fn gen_file(seed: usize, version: usize) -> Vec<u8> {
        let mut s = String::new();
        for line in 0..120 {
            if version > 0 && line % 30 == 7 {
                s.push_str(&format!(
                    "changed[{seed}:{line}] v{version} xyzzy-{}\n",
                    seed * 7 + line
                ));
            } else {
                s.push_str(&format!(
                    "name = \"pkg-{seed}\"\nline {line} = stable value {} foo bar baz\n",
                    (seed * 131 + line * 17) % 1000
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

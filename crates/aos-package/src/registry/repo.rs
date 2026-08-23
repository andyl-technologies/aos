//! git2-backed SHA-256 repository operations for the apm/apr registry.
//!
//! This module is the single seam between the registry code and libgit2. It
//! replaces the historical shell-outs to the `git` CLI: local object and ref
//! access, the `git://` and `ssh://` smart-transport fetch, tag resolution,
//! fast-forward checks, and tree extraction all run through libgit2 (built
//! with `-DEXPERIMENTAL_SHA256=ON`). The registry is SHA-256-only, so every
//! repository this module opens or creates uses the SHA-256 object format.
//!
//! libgit2 speaks only the *smart* HTTP protocol, but AOS registries are
//! served as a static *dumb*-HTTP(S) object tree; that transport lives in the
//! sibling [`crate::registry::dumb_http`] module and is dispatched from
//! [`fetch`] by URL scheme.
//!
//! # Blocking and async
//!
//! libgit2 is synchronous. Each public function here is `async` only as a
//! convenience for the (async) registry call sites: the libgit2 work runs on a
//! [`tokio::task::spawn_blocking`] worker so it never stalls the runtime. A
//! fresh [`git2::Repository`] handle is opened per call — opening a bare repo
//! is cheap and keeps the non-`Send` handle confined to one blocking closure.

use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_core::output::TransferProgress;

use crate::registry::dumb_http;

/// Open the SHA-256 repository at `repo_dir` on the current thread.
///
/// Registry repositories are bare, but [`git2::Repository::open`] also accepts
/// a non-bare repository directory (as the registry's own tests create), so it
/// is used in preference to the bare-only opener.
///
/// # Errors
///
/// Returns an error if no git repository exists at `repo_dir` or it cannot be
/// opened.
fn open(repo_dir: &Path) -> Result<git2::Repository> {
    git2::Repository::open(repo_dir)
        .with_context(|| format!("opening git repository at {}", repo_dir.display()))
}

/// Resolve a hex object id to a [`git2::Oid`] using the repository's hash
/// algorithm.
///
/// [`git2::Oid::from_str`] assumes SHA-1 and rejects 64-character SHA-256 ids,
/// so a SHA-256 id must be resolved through the repository. The object must
/// already exist, which holds for every caller — fast-forward checks and
/// signature reads operate on fetched commits, and refs are set immediately
/// after their target object is written.
fn resolve_oid(repo: &git2::Repository, hex: &str) -> Result<git2::Oid> {
    let object = repo
        .revparse_single(hex)
        .with_context(|| format!("resolving object {hex}"))?;
    Ok(object.id())
}

/// Run a blocking libgit2 closure on a `spawn_blocking` worker.
///
/// The closure receives the path it was given so it can open its own
/// repository handle; nothing `!Send` crosses the await point.
async fn blocking<T, F>(repo_dir: &Path, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Path) -> Result<T> + Send + 'static,
{
    let dir = repo_dir.to_path_buf();
    tokio::task::spawn_blocking(move || f(&dir))
        .await
        .context("git worker task panicked")?
}

/// `true` if a git repository already exists at `repo_dir`.
pub(crate) fn exists(repo_dir: &Path) -> bool {
    repo_dir.join("HEAD").exists()
}

/// Initialize a bare SHA-256 repository at `repo_dir` if one does not exist.
///
/// Mirrors the historical `git init --bare --object-format=sha256`. Existing
/// repositories are left untouched.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or libgit2 cannot
/// initialize the repository.
pub(crate) async fn init_bare_sha256(repo_dir: &Path) -> Result<()> {
    if exists(repo_dir) {
        return Ok(());
    }
    blocking(repo_dir, |dir| {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut opts = git2::RepositoryInitOptions::new();
        opts.bare(true)
            .mkpath(true)
            .object_format(git2::ObjectFormat::Sha256);
        git2::Repository::init_opts(dir, &opts).with_context(|| {
            format!(
                "git init --bare --object-format=sha256 at {}",
                dir.display()
            )
        })?;
        Ok(())
    })
    .await
}

/// Resolve a revspec to the hex OID of the commit it names (peeling tags).
///
/// Equivalent to `git rev-parse <spec>^{commit}`.
///
/// # Errors
///
/// Returns an error if the spec does not resolve or does not peel to a commit.
pub(crate) async fn rev_parse_commit(repo_dir: &Path, spec: &str) -> Result<String> {
    let spec = spec.to_string();
    blocking(repo_dir, move |dir| {
        let repo = open(dir)?;
        let object = repo
            .revparse_single(&spec)
            .with_context(|| format!("resolving {spec}"))?;
        let commit = object
            .peel_to_commit()
            .with_context(|| format!("{spec} does not name a commit"))?;
        Ok(commit.id().to_string())
    })
    .await
}

/// Resolve a revspec to a raw hex OID without peeling.
///
/// Equivalent to `git rev-parse <spec>`.
///
/// # Errors
///
/// Returns an error if the spec does not resolve.
pub(crate) async fn rev_parse(repo_dir: &Path, spec: &str) -> Result<String> {
    let spec = spec.to_string();
    blocking(repo_dir, move |dir| rev_parse_blocking(dir, &spec)).await
}

/// Synchronous form of [`rev_parse`] for sync callers (tag-chain verification).
///
/// # Errors
///
/// Returns an error if the spec does not resolve.
pub(crate) fn rev_parse_blocking(repo_dir: &Path, spec: &str) -> Result<String> {
    let repo = open(repo_dir)?;
    let object = repo
        .revparse_single(spec)
        .with_context(|| format!("resolving {spec}"))?;
    Ok(object.id().to_string())
}

/// Read the raw body of the object named by `spec` (no `<type> <size>\0`
/// header). For a tag spec this is exactly `git cat-file -p <tag>` output.
///
/// # Errors
///
/// Returns an error if the spec does not resolve or the object cannot be read.
pub(crate) fn object_body_blocking(repo_dir: &Path, spec: &str) -> Result<Vec<u8>> {
    let repo = open(repo_dir)?;
    let object = repo
        .revparse_single(spec)
        .with_context(|| format!("resolving {spec}"))?;
    let odb = repo.odb().context("opening object database")?;
    let raw = odb
        .read(object.id())
        .with_context(|| format!("reading object {spec}"))?;
    Ok(raw.data().to_vec())
}

/// List all tag short-names in the repository (`git tag -l`).
///
/// # Errors
///
/// Returns an error if the tag references cannot be enumerated.
pub(crate) async fn tag_names(repo_dir: &Path) -> Result<Vec<String>> {
    blocking(repo_dir, |dir| {
        let repo = open(dir)?;
        let names = repo.tag_names(None).context("listing tags")?;
        let mut out = Vec::new();
        for name in names.iter() {
            if let Ok(Some(name)) = name {
                out.push(name.to_string());
            }
        }
        Ok(out)
    })
    .await
}

/// Hash and write a tag object, returning its hex OID.
///
/// Equivalent to `git hash-object -w -t tag --stdin`. The object is written
/// into the repository's object database so later resolution can reach it.
///
/// # Errors
///
/// Returns an error if the bytes cannot be written to the object database.
pub(crate) async fn hash_tag_object(repo_dir: &Path, bytes: &[u8]) -> Result<String> {
    let bytes = bytes.to_vec();
    blocking(repo_dir, move |dir| {
        let repo = open(dir)?;
        let odb = repo.odb().context("opening object database")?;
        let oid = odb
            .write(git2::ObjectType::Tag, &bytes)
            .context("writing tag object")?;
        Ok(oid.to_string())
    })
    .await
}

/// `true` when `descendant` is a strict descendant of `ancestor`, or they are
/// the same commit. Mirrors `git merge-base --is-ancestor <ancestor>
/// <descendant>` (used for fast-forward enforcement).
///
/// # Errors
///
/// Returns an error if either OID is malformed or the graph walk fails.
pub(crate) async fn is_ancestor(repo_dir: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let ancestor = ancestor.to_string();
    let descendant = descendant.to_string();
    blocking(repo_dir, move |dir| {
        is_ancestor_blocking(dir, &ancestor, &descendant)
    })
    .await
}

/// Synchronous form of [`is_ancestor`] for sync callers (downgrade detection).
///
/// # Errors
///
/// Returns an error if either OID is malformed or the graph walk fails.
pub(crate) fn is_ancestor_blocking(
    repo_dir: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool> {
    let repo = open(repo_dir)?;
    let ancestor_oid = resolve_oid(&repo, ancestor)?;
    let descendant_oid = resolve_oid(&repo, descendant)?;
    if ancestor_oid == descendant_oid {
        return Ok(true);
    }
    repo.graph_descendant_of(descendant_oid, ancestor_oid)
        .with_context(|| format!("checking ancestry of {ancestor}..{descendant}"))
}

/// The object kind of `commit:tree_path`, or `None` if the path is absent.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved.
pub(crate) async fn path_object_kind(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
) -> Result<Option<git2::ObjectType>> {
    let commit = commit.to_string();
    let tree_path = tree_path.to_string();
    blocking(repo_dir, move |dir| {
        let repo = open(dir)?;
        let tree = commit_tree(&repo, &commit)?;
        match tree.get_path(Path::new(&tree_path)) {
            Ok(entry) => Ok(entry.kind()),
            Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("looking up {commit}:{tree_path}")),
        }
    })
    .await
}

/// Read the bytes of the blob at `commit:tree_path`.
///
/// Returns `None` when the path is absent from the commit (the historical
/// `git show` "missing path" case). Mirrors `git show <commit>:<path>`.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved, or the path names a
/// non-blob object.
pub(crate) async fn read_blob_at(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
) -> Result<Option<Vec<u8>>> {
    let commit = commit.to_string();
    let tree_path = tree_path.to_string();
    blocking(repo_dir, move |dir| {
        read_blob_at_blocking(dir, &commit, &tree_path)
    })
    .await
}

/// Synchronous form of [`read_blob_at`] for sync callers (trust-roster load).
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved, or the path names a
/// non-blob object.
pub(crate) fn read_blob_at_blocking(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
) -> Result<Option<Vec<u8>>> {
    let repo = open(repo_dir)?;
    let tree = commit_tree(&repo, commit)?;
    let entry = match tree.get_path(Path::new(tree_path)) {
        Ok(entry) => entry,
        Err(e) if e.code() == git2::ErrorCode::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("looking up {commit}:{tree_path}"));
        }
    };
    if entry.kind() != Some(git2::ObjectType::Blob) {
        bail!("{commit}:{tree_path} is not a file");
    }
    let object = entry
        .to_object(&repo)
        .with_context(|| format!("reading {commit}:{tree_path}"))?;
    let blob = object
        .as_blob()
        .with_context(|| format!("{commit}:{tree_path} is not a blob"))?;
    Ok(Some(blob.content().to_vec()))
}

/// `true` when `commit:tree_path` resolves to an object (`git cat-file -e`).
///
/// Synchronous, for TUF metadata presence checks.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved.
pub(crate) fn tree_path_exists_blocking(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
) -> Result<bool> {
    let repo = open(repo_dir)?;
    let tree = commit_tree(&repo, commit)?;
    match tree.get_path(Path::new(tree_path)) {
        Ok(_) => Ok(true),
        Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("looking up {commit}:{tree_path}")),
    }
}

/// List every blob path in `commit`'s tree, recursively.
///
/// Equivalent to `git ls-tree -r --name-only <commit>`. Paths use `/`
/// separators relative to the tree root.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved or the walk fails.
pub(crate) fn list_tree_paths_blocking(repo_dir: &Path, commit: &str) -> Result<Vec<String>> {
    let repo = open(repo_dir)?;
    let tree = commit_tree(&repo, commit)?;
    let mut paths = Vec::new();
    tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob) {
            if let Ok(name) = entry.name() {
                paths.push(format!("{root}{name}"));
            }
        }
        git2::TreeWalkResult::Ok
    })
    .with_context(|| format!("walking tree of {commit}"))?;
    Ok(paths)
}

/// Extract the directory tree at `commit:tree_path` into `output_dir`.
///
/// Replaces `git archive <commit> <tree_path>/ | tar -x --strip-components=1`.
/// `output_dir` is removed first so deletions in the registry propagate. When
/// `tree_path` is absent, `create_empty_when_absent` selects between creating
/// an empty `output_dir` (historical `packages/` behavior) and leaving none
/// (required for `store/`, where presence is meaningful).
///
/// Regular files, executable files, and symlinks are reproduced with their git
/// file modes; nested directories are created as needed.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved or the filesystem writes
/// fail.
pub(crate) async fn extract_tree_dir(
    repo_dir: &Path,
    commit: &str,
    tree_path: &str,
    output_dir: &Path,
    create_empty_when_absent: bool,
) -> Result<()> {
    let commit = commit.to_string();
    let tree_path = tree_path.to_string();
    let output_dir = output_dir.to_path_buf();
    blocking(repo_dir, move |dir| {
        if output_dir.exists() {
            std::fs::remove_dir_all(&output_dir)
                .with_context(|| format!("cleaning {}", output_dir.display()))?;
        }
        let repo = open(dir)?;
        let tree = commit_tree(&repo, &commit)?;
        let entry = match tree.get_path(Path::new(&tree_path)) {
            Ok(entry) => entry,
            Err(e) if e.code() == git2::ErrorCode::NotFound => {
                if create_empty_when_absent {
                    std::fs::create_dir_all(&output_dir)
                        .with_context(|| format!("creating {}", output_dir.display()))?;
                }
                return Ok(());
            }
            Err(e) => return Err(e).with_context(|| format!("looking up {commit}:{tree_path}")),
        };
        let object = entry
            .to_object(&repo)
            .with_context(|| format!("reading {commit}:{tree_path}"))?;
        let subtree = object
            .as_tree()
            .with_context(|| format!("{commit}:{tree_path} is not a directory"))?;
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("creating {}", output_dir.display()))?;
        write_tree_recursive(&repo, subtree, &output_dir)?;
        Ok(())
    })
    .await
}

/// Recursively materialize `tree` under `dest`, preserving git file modes.
fn write_tree_recursive(repo: &git2::Repository, tree: &git2::Tree, dest: &Path) -> Result<()> {
    for entry in tree.iter() {
        let name = entry.name().context("non-UTF-8 tree entry name")?;
        let path = dest.join(name);
        match entry.kind() {
            Some(git2::ObjectType::Tree) => {
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("creating {}", path.display()))?;
                let object = entry.to_object(repo)?;
                let subtree = object
                    .as_tree()
                    .ok_or_else(|| anyhow::anyhow!("tree entry {name} is not a tree"))?;
                write_tree_recursive(repo, subtree, &path)?;
            }
            Some(git2::ObjectType::Blob) => {
                let content = read_blob_content(repo, entry.id())
                    .with_context(|| format!("reading blob for {}", path.display()))?;
                let filemode = entry.filemode();
                if filemode == 0o120000 {
                    let target = std::str::from_utf8(&content)
                        .with_context(|| format!("symlink target for {name} is not UTF-8"))?;
                    std::os::unix::fs::symlink(target, &path)
                        .with_context(|| format!("creating symlink {}", path.display()))?;
                } else {
                    let mode = if filemode == 0o100755 { 0o755 } else { 0o644 };
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(mode)
                        .open(&path)
                        .with_context(|| format!("creating {}", path.display()))?;
                    use std::io::Write;
                    file.write_all(&content)
                        .with_context(|| format!("writing {}", path.display()))?;
                }
            }
            // git links (submodules) and other kinds do not occur in registry
            // trees; skip them rather than fail.
            _ => {}
        }
    }
    Ok(())
}

/// Read blob bytes directly from the object database.
///
/// libgit2's experimental SHA-256 support can construct a zero-length
/// `git2::Blob` view for a non-empty blob received in a pack, particularly
/// when the object is delta-compressed. The lower-level ODB reader resolves
/// the same packed object correctly and also exposes its actual object kind,
/// so extraction uses that representation and fails closed on a type mismatch.
fn read_blob_content(repo: &git2::Repository, oid: git2::Oid) -> Result<Vec<u8>> {
    let odb = repo.odb().context("opening object database")?;
    let object = odb
        .read(oid)
        .with_context(|| format!("reading object {oid}"))?;
    if object.kind() != git2::ObjectType::Blob {
        bail!(
            "tree entry {oid} resolved to {:?}, not a blob",
            object.kind()
        );
    }
    Ok(object.data().to_vec())
}

/// Map every semver-parseable tag's annotated tag-object OID to its version.
///
/// Lightweight tags (which have no tag object) are skipped.
///
/// # Errors
///
/// Returns an error if tags cannot be listed.
pub(crate) async fn semver_tag_object_map(
    repo_dir: &Path,
) -> Result<BTreeMap<String, semver::Version>> {
    blocking(repo_dir, |dir| {
        let repo = open(dir)?;
        let names = repo.tag_names(None).context("listing tags")?;
        let mut map = BTreeMap::new();
        for name in names.iter() {
            let Ok(Some(name)) = name else {
                continue;
            };
            let Ok(version) = semver::Version::parse(name) else {
                continue;
            };
            let Ok(object) = repo.revparse_single(&format!("{name}^{{tag}}")) else {
                continue;
            };
            map.insert(object.id().to_string(), version);
        }
        Ok(map)
    })
    .await
}

/// Extract the SSHSIG signature and signed payload of a commit.
///
/// Returns `(signature, signed_payload)` exactly as `git verify-commit`
/// computes them: the signature is the armored SSH signature block from the
/// commit's `gpgsig` header, and the payload is the commit object with that
/// header removed. Returns `None` if the commit carries no signature.
///
/// This is synchronous: the registry signature-verification path is sync, and
/// opening a bare repo plus reading one object is cheap.
///
/// # Errors
///
/// Returns an error if the commit OID cannot be resolved.
pub(crate) fn commit_signature(
    repo_dir: &Path,
    commit: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let repo = open(repo_dir)?;
    let oid = resolve_oid(&repo, commit)?;
    // NOTE: git2's `extract_signature` returns NotFound for SHA-256 commits
    // (libgit2's experimental SHA-256 support does not implement it), so the
    // `gpgsig` header is parsed out of the raw commit object directly — the
    // same approach `tag_signature` uses for annotated tags.
    let odb = repo.odb().context("opening object database")?;
    let raw = odb
        .read(oid)
        .with_context(|| format!("reading commit object {commit}"))?;
    Ok(split_commit_signature(raw.data()))
}

/// Split a raw commit object into `(signature, signed_payload)`.
///
/// Mirrors how `git verify-commit` works: the signature is the value of the
/// `gpgsig` header (continuation lines de-indented by one space, yielding the
/// armored SSH signature), and the signed payload is the commit object with the
/// entire `gpgsig` header removed. Returns `None` if the commit is unsigned.
fn split_commit_signature(raw: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // The header block ends at the first blank line; the message follows.
    let sep = find_subslice(raw, b"\n\n")?;
    let header = &raw[..sep];
    let rest = &raw[sep..]; // "\n\n" + message, preserved byte-for-byte

    let mut signed_header: Vec<u8> = Vec::new();
    let mut signature: Vec<u8> = Vec::new();
    let mut in_gpgsig = false;
    let mut found = false;
    let mut first_kept = true;

    for line in header.split(|&b| b == b'\n') {
        if in_gpgsig && line.first() == Some(&b' ') {
            // Continuation line of the gpgsig header: de-indent one space.
            signature.push(b'\n');
            signature.extend_from_slice(&line[1..]);
            continue;
        }
        in_gpgsig = false;
        // SHA-256 repos name the header `gpgsig-sha256`; SHA-1 repos use
        // `gpgsig`. The signed payload is the commit with the header removed
        // either way.
        if let Some(value) = line
            .strip_prefix(b"gpgsig-sha256 ")
            .or_else(|| line.strip_prefix(b"gpgsig "))
        {
            found = true;
            in_gpgsig = true;
            signature.extend_from_slice(value);
            continue;
        }
        if !first_kept {
            signed_header.push(b'\n');
        }
        signed_header.extend_from_slice(line);
        first_kept = false;
    }

    if !found {
        return None;
    }
    let mut signed = signed_header;
    signed.extend_from_slice(rest);
    Some((signature, signed))
}

/// Extract the SSHSIG signature and signed payload of an annotated tag.
///
/// Git appends the armored SSH signature to the tag object body; the signed
/// payload is the tag object up to (and excluding) the signature block.
/// Returns `None` if the tag is lightweight or unsigned.
///
/// # Errors
///
/// Returns an error if the tag does not resolve to a tag object.
pub(crate) fn tag_signature(repo_dir: &Path, tag: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let repo = open(repo_dir)?;
    let object = repo
        .revparse_single(&format!("{tag}^{{tag}}"))
        .with_context(|| format!("resolving tag object {tag}"))?;
    let odb = repo.odb().context("opening object database")?;
    let raw = odb
        .read(object.id())
        .with_context(|| format!("reading tag object {tag}"))?;
    Ok(split_tag_signature(raw.data()))
}

/// SSH signature armor markers used to split a signed tag object body.
const SSH_SIG_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
const SSH_SIG_END: &[u8] = b"-----END SSH SIGNATURE-----";

/// Split a raw tag object into `(signature, signed_payload)`.
///
/// Mirrors git's tag verification: the signed payload is everything before the
/// armored signature block, and the signature is the block itself (through its
/// trailing newline). Returns `None` if no signature block is present.
fn split_tag_signature(raw: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let begin = find_subslice(raw, SSH_SIG_BEGIN)?;
    let end_marker = find_subslice(&raw[begin..], SSH_SIG_END)? + begin;
    let mut sig_end = end_marker + SSH_SIG_END.len();
    if raw.get(sig_end) == Some(&b'\n') {
        sig_end += 1;
    }
    let payload = raw[..begin].to_vec();
    let signature = raw[begin..sig_end].to_vec();
    Some((signature, payload))
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Resolve a commit revspec to its [`git2::Tree`].
fn commit_tree<'a>(repo: &'a git2::Repository, commit: &str) -> Result<git2::Tree<'a>> {
    let object = repo
        .revparse_single(commit)
        .with_context(|| format!("resolving {commit}"))?;
    let commit = object
        .peel_to_commit()
        .with_context(|| format!("{commit} does not name a commit"))?;
    commit.tree().context("reading commit tree")
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Fetch `refspecs` from `url` into the repository at `repo_dir`.
///
/// Dispatches by URL scheme: `git://` and `ssh://` use libgit2's smart
/// transport, while `http(s)://` registries (served as a static dumb-HTTP
/// object tree, which libgit2 cannot read) use the pure-Rust loose-object
/// walker in [`crate::registry::dumb_http`].
///
/// `url` must already be normalized (no `git+` prefix).
///
/// # Errors
///
/// Returns an error if the transport fails or a requested ref is unavailable.
pub(crate) async fn fetch(repo_dir: &Path, url: &str, refspecs: &[String]) -> Result<()> {
    fetch_with_progress(repo_dir, url, refspecs, None).await
}

/// Fetches refs while reporting aggregate network bytes to the caller.
///
/// # Errors
///
/// Returns an error under the same transport and ref-resolution conditions as
/// [`fetch`].
pub(crate) async fn fetch_with_progress(
    repo_dir: &Path,
    url: &str,
    refspecs: &[String],
    progress: Option<TransferProgress>,
) -> Result<()> {
    if url.starts_with("http://") || url.starts_with("https://") {
        return match progress.as_ref() {
            Some(progress) => {
                dumb_http::fetch_with_progress(repo_dir, url, refspecs, Some(progress)).await
            }
            None => dumb_http::fetch(repo_dir, url, refspecs).await,
        };
    }
    let url = url.to_string();
    let refspecs = refspecs.to_vec();
    blocking(repo_dir, move |dir| {
        let repo = open(dir)?;
        let mut remote = repo
            .remote_anonymous(&url)
            .with_context(|| format!("creating remote for {url}"))?;
        let mut callbacks = git2::RemoteCallbacks::new();
        callbacks.credentials(credentials);
        if let Some(progress) = progress {
            let previous = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            callbacks.transfer_progress(move |stats| {
                let received = stats.received_bytes() as u64;
                let previous = previous.swap(received, std::sync::atomic::Ordering::Relaxed);
                progress.inc(received.saturating_sub(previous));
                true
            });
        }
        let mut options = git2::FetchOptions::new();
        options.remote_callbacks(callbacks);
        options.download_tags(git2::AutotagOption::None);
        let refs: Vec<&str> = refspecs.iter().map(String::as_str).collect();
        remote
            .fetch(&refs, Some(&mut options), None)
            .with_context(|| format!("git fetch {url}"))?;
        Ok(())
    })
    .await
}

/// libgit2 credential callback for `ssh://` transports.
///
/// Tries the ssh-agent for the requested username, falling back to the
/// default key. `git://` and `http(s)://` never invoke this. Username/password
/// (HTTP basic) and default-credential requests are declined.
pub(crate) fn credentials(
    _url: &str,
    username: Option<&str>,
    allowed: git2::CredentialType,
) -> std::result::Result<git2::Cred, git2::Error> {
    if allowed.contains(git2::CredentialType::SSH_KEY) {
        let user = username.unwrap_or("git");
        return git2::Cred::ssh_key_from_agent(user);
    }
    if allowed.contains(git2::CredentialType::USERNAME) {
        return git2::Cred::username(username.unwrap_or("git"));
    }
    Err(git2::Error::from_str(
        "no supported credential type available",
    ))
}

/// Local refs the smart fetch writes; re-exported for the dumb-HTTP path so
/// both transports land fetched refs in the same place.
pub(crate) fn set_reference(repo_dir: &Path, refname: &str, oid_hex: &str) -> Result<()> {
    let repo = open(repo_dir)?;
    let oid = resolve_oid(&repo, oid_hex)?;
    repo.reference(refname, oid, true, "apm dumb-http fetch")
        .with_context(|| format!("writing ref {refname}"))?;
    Ok(())
}

/// Returns the on-disk object database used by the repository.
///
/// Resolving the path through libgit2 is required because bare repositories
/// store objects below `<repo>/objects`, while authoring worktrees store them
/// below `<repo>/.git/objects`.
///
/// # Errors
///
/// Returns an error when `repo_dir` is not an accessible Git repository.
pub(crate) fn objects_dir(repo_dir: &Path) -> Result<PathBuf> {
    let repo = open(repo_dir)?;
    Ok(repo.path().join("objects"))
}

/// Index downloaded packfiles into the repository's object store.
///
/// Each entry of `packs` is the raw bytes of a `.pack` file. libgit2's pack
/// indexer (equivalent to `git index-pack`) regenerates the `.idx` and
/// verifies the pack, so objects become addressable by their true content
/// hash — a tampered pack yields objects under unexpected ids that the graph
/// walk in [`missing_objects_blocking`] simply will not find under the ids it
/// expects. The `.idx` therefore never has to be downloaded or trusted.
///
/// # Errors
///
/// Returns an error if a pack cannot be written or fails indexing/verification.
pub(crate) fn index_packs_blocking(repo_dir: &Path, packs: &[Vec<u8>]) -> Result<()> {
    use std::io::Write as _;
    let repo = open(repo_dir)?;
    let odb = repo.odb().context("opening object database")?;
    for pack in packs {
        let mut writer = odb.packwriter().context("creating pack writer")?;
        writer.write_all(pack).context("writing pack data")?;
        writer.commit().context("indexing pack")?;
    }
    Ok(())
}

/// Walk the object graph reachable from `targets` over the *local* object
/// store and return the hex OIDs that are referenced but absent.
///
/// Traversal uses libgit2 objects (commit -> tree + parents, tree -> entries,
/// tag -> target), so every OID originates from git2 and is never parsed from
/// a hex string. Objects already present — whether in a pack or loose — are
/// traversed in place with no network access; the returned set is the frontier
/// the caller must download (loose) before walking can continue past it.
///
/// # Errors
///
/// Returns an error if a target cannot be resolved (other than not-found) or an
/// object read fails for a reason other than absence.
pub(crate) fn missing_objects_blocking(repo_dir: &Path, targets: &[String]) -> Result<Vec<String>> {
    use std::collections::HashSet;
    let repo = open(repo_dir)?;
    let mut missing: HashSet<String> = HashSet::new();
    let mut visited: HashSet<git2::Oid> = HashSet::new();
    let mut stack: Vec<git2::Oid> = Vec::new();

    for hex in targets {
        match repo.revparse_single(hex) {
            Ok(object) => stack.push(object.id()),
            Err(e) if e.code() == git2::ErrorCode::NotFound => {
                missing.insert(hex.clone());
            }
            Err(e) => return Err(e).with_context(|| format!("resolving {hex}")),
        }
    }

    while let Some(oid) = stack.pop() {
        if !visited.insert(oid) {
            continue;
        }
        let object = match repo.find_object(oid, None) {
            Ok(object) => object,
            Err(e) if e.code() == git2::ErrorCode::NotFound => {
                missing.insert(oid.to_string());
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("reading object {oid}")),
        };
        match object.kind() {
            Some(git2::ObjectType::Commit) => {
                if let Some(commit) = object.as_commit() {
                    stack.push(commit.tree_id());
                    for parent in commit.parent_ids() {
                        stack.push(parent);
                    }
                }
            }
            Some(git2::ObjectType::Tree) => {
                if let Some(tree) = object.as_tree() {
                    for entry in tree.iter() {
                        stack.push(entry.id());
                    }
                }
            }
            Some(git2::ObjectType::Tag) => {
                if let Some(tag) = object.as_tag() {
                    stack.push(tag.target_id());
                }
            }
            // Blobs are leaves; anything else carries no references we follow.
            _ => {}
        }
    }
    Ok(missing.into_iter().collect())
}

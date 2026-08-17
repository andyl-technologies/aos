//! Git-native registry object-store helpers.
//!
//! These helpers own the static dumb-HTTP object layout used by the target
//! registry: a bare sha256 repository, root loose-object store, per-release
//! pack directories, and relative `objects/info/alternates`.
//!
//! The published origin is a plain byte tree any static file host can
//! serve. Stock `git clone` works against it through the dumb-HTTP
//! protocol, which requires every reachable object to exist loose in the
//! root `objects/` store ([`ensure_loose_completeness`]) and up-to-date
//! `info/refs` metadata ([`refresh_server_info`]). Per-release pack
//! directories under `releases/<X>/<Y>/<Z>/objects/` carry the optimized
//! transfer artifacts and are stitched into the root store via relative
//! alternates ([`write_alternates`]).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Initialize `dir` as a bare sha256 git repository and point `HEAD` at the
/// default channel branch.
///
/// # Errors
///
/// Returns an error if libgit2 cannot initialize the repository or the sha256
/// format guard fails.
pub fn init_bare_sha256(dir: &Path, default_channel: &str) -> Result<()> {
    if default_channel.is_empty() || default_channel.contains('/') {
        bail!("default channel must be a single non-empty ref segment");
    }

    let mut opts = git2::RepositoryInitOptions::new();
    opts.bare(true)
        .mkpath(true)
        .object_format(git2::ObjectFormat::Sha256)
        .initial_head(&format!("refs/heads/{default_channel}"));
    git2::Repository::init_opts(dir, &opts).with_context(|| {
        format!(
            "git init --bare --object-format=sha256 for {}",
            dir.display()
        )
    })?;
    assert_sha256(dir)?;
    Ok(())
}

/// Map a semver release to its per-release object directory.
///
/// `1.0.0-beta+exp.sha` maps to `1/0/0-beta+exp.sha/objects`.
pub fn release_object_dir(version: &semver::Version) -> PathBuf {
    let mut third = version.patch.to_string();
    if !version.pre.is_empty() {
        third.push('-');
        third.push_str(&version.pre.to_string());
    }
    if !version.build.is_empty() {
        third.push('+');
        third.push_str(&version.build.to_string());
    }

    PathBuf::from(version.major.to_string())
        .join(version.minor.to_string())
        .join(third)
        .join("objects")
}

/// Convert a 64-hex sha256 object id to the loose-object `xx/rest` path.
///
/// # Errors
///
/// Returns an error when `oid` is not exactly 64 ASCII hex characters.
pub fn loose_object_path(oid: &str) -> Result<PathBuf> {
    if oid.len() != 64 || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected 64-character sha256 object id, got '{oid}'");
    }
    Ok(PathBuf::from(&oid[..2]).join(&oid[2..]))
}

/// Prepare the pack-only directory for a release and validate that `revspec`
/// is known to the root git object store.
///
/// The canonical sha256 bare repo already writes loose objects under its root
/// `objects/` directory. This helper creates the per-release pack scaffold that
/// later pack generation fills.
///
/// # Errors
///
/// Returns an error if the repository is not sha256, a non-empty `revspec`
/// is unknown to the object store, or the scaffold directories cannot be
/// created.
pub fn write_release_objects(repo: &Path, version: &semver::Version, revspec: &str) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    if !revspec.is_empty() {
        let repository = open_git_dir(&git_dir)?;
        repository
            .revparse_single(revspec)
            .with_context(|| format!("revspec {revspec} is unknown to {}", git_dir.display()))?;
    }

    let objects_dir = git_dir.join("releases").join(release_object_dir(version));
    fs::create_dir_all(objects_dir.join("info"))
        .with_context(|| format!("creating {}", objects_dir.join("info").display()))?;
    fs::create_dir_all(objects_dir.join("pack"))
        .with_context(|| format!("creating {}", objects_dir.join("pack").display()))?;
    Ok(())
}

/// Ensure every reachable object has a canonical loose copy in the root
/// `/objects/` store.
///
/// Enumerates every object reachable from the repository's refs (including
/// objects that live only in per-release pack alternates) and writes each into
/// `objects/xx/rest`, so dumb-HTTP clients and Hub indexers can fetch the full
/// graph. The stored-block zlib representation is canonical across compressor
/// versions, making the immutable URL identify stable wire bytes as well as the
/// decompressed Git object.
///
/// # Errors
///
/// Returns an error if a reachable object cannot be read or a loose object
/// cannot be written.
pub fn ensure_loose_completeness(repo: &Path) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    let repository = open_git_dir(&git_dir)?;
    let odb = repository.odb().context("opening object database")?;
    let objects_dir = git_dir.join("objects");

    // Every reachable object (including those living only in per-release pack
    // alternates) is read from the object database and written canonically in
    // the root store. We write the loose file directly rather than via
    // `Odb::write`, which is a no-op when the object already exists in a pack
    // and preserves producer-dependent zlib bytes when it exists loose.
    for oid in reachable_objects(&repository)? {
        let loose = objects_dir.join(loose_object_path(&oid.to_string())?);
        let object = odb
            .read(oid)
            .with_context(|| format!("reading reachable object {oid}"))?;
        write_loose_object_file(&loose, object.kind(), object.data())
            .with_context(|| format!("materializing loose git object {oid}"))?;
    }

    Ok(())
}

/// Write a single loose git object to `path` (`objects/<2>/<62>`).
///
/// The on-disk loose format is the zlib-compressed `"<type> <size>\0<body>"`
/// pre-image whose SHA-256 is the object id; the write is atomic via a temp
/// file rename.
fn write_loose_object_file(path: &Path, kind: git2::ObjectType, data: &[u8]) -> Result<()> {
    let type_str = match kind {
        git2::ObjectType::Blob => "blob",
        git2::ObjectType::Commit => "commit",
        git2::ObjectType::Tree => "tree",
        git2::ObjectType::Tag => "tag",
        other => bail!("unsupported git object type {other:?}"),
    };
    let mut content = format!("{type_str} {}\0", data.len()).into_bytes();
    content.extend_from_slice(data);
    let compressed = canonical_zlib(&content);
    if compressed.len() as u64
        > aos_registry_surface::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES
    {
        bail!(
            "loose object exceeds the {}-byte publication limit",
            aos_registry_surface::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES
        );
    }

    if fs::read(path).is_ok_and(|existing| existing == compressed) {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &compressed).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

/// Encodes bytes as a deterministic zlib stream of uncompressed DEFLATE
/// blocks. This intentionally trades a small static-origin storage cost for a
/// representation independent of zlib library versions and tuning.
fn canonical_zlib(content: &[u8]) -> Vec<u8> {
    const MAX_STORED_BLOCK: usize = u16::MAX as usize;
    let block_count = content.len().div_ceil(MAX_STORED_BLOCK).max(1);
    let mut encoded = Vec::with_capacity(content.len() + block_count * 5 + 6);
    // CM=DEFLATE, 32 KiB window, fastest/no-compression level. The pair is
    // divisible by 31 as required by RFC 1950.
    encoded.extend_from_slice(&[0x78, 0x01]);

    if content.is_empty() {
        encoded.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    } else {
        let last = content.len().div_ceil(MAX_STORED_BLOCK) - 1;
        for (index, block) in content.chunks(MAX_STORED_BLOCK).enumerate() {
            encoded.push(u8::from(index == last));
            let length = block.len() as u16;
            encoded.extend_from_slice(&length.to_le_bytes());
            encoded.extend_from_slice(&(!length).to_le_bytes());
            encoded.extend_from_slice(block);
        }
    }
    encoded.extend_from_slice(&adler32(content).to_be_bytes());
    encoded
}

fn adler32(content: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in content {
        a = (a + u32::from(*byte)) % MODULUS;
        b = (b + a) % MODULUS;
    }
    (b << 16) | a
}

/// Enumerate every object reachable from the repository's refs — the
/// equivalent of `git rev-list --objects --all`: commits, their trees and
/// blobs, and annotated tag objects. Objects living only in the per-release
/// pack alternates are reached through the object database.
fn reachable_objects(repo: &git2::Repository) -> Result<Vec<git2::Oid>> {
    let mut seen: HashSet<git2::Oid> = HashSet::new();
    let mut out: Vec<git2::Oid> = Vec::new();

    let mut revwalk = repo.revwalk().context("creating revwalk")?;
    for reference in repo.references().context("listing references")? {
        let reference = reference?;
        if let Some(oid) = reference.target() {
            // push() peels tags to their commit; ignore non-committish refs.
            let _ = revwalk.push(oid);
        }
    }
    for oid in revwalk {
        let commit_oid = oid?;
        if seen.insert(commit_oid) {
            out.push(commit_oid);
        }
        let commit = repo
            .find_commit(commit_oid)
            .with_context(|| format!("reading commit {commit_oid}"))?;
        let tree = commit.tree().context("reading commit tree")?;
        if seen.insert(tree.id()) {
            out.push(tree.id());
        }
        collect_tree(repo, &tree, &mut seen, &mut out)?;
    }

    // revwalk only yields commits; record the annotated tag objects in each
    // refs/tags chain as well.
    for reference in repo
        .references_glob("refs/tags/*")
        .context("listing tags")?
    {
        let reference = reference?;
        let Some(mut oid) = reference.target() else {
            continue;
        };
        while let Ok(object) = repo.find_object(oid, None) {
            if object.kind() != Some(git2::ObjectType::Tag) {
                break;
            }
            if seen.insert(oid) {
                out.push(oid);
            }
            let Some(tag) = object.as_tag() else { break };
            oid = tag.target_id();
        }
    }

    Ok(out)
}

/// Recursively record every tree and blob OID under `tree`.
fn collect_tree(
    repo: &git2::Repository,
    tree: &git2::Tree<'_>,
    seen: &mut HashSet<git2::Oid>,
    out: &mut Vec<git2::Oid>,
) -> Result<()> {
    for entry in tree.iter() {
        let oid = entry.id();
        match entry.kind() {
            Some(git2::ObjectType::Tree) => {
                if seen.insert(oid) {
                    out.push(oid);
                    let object = entry
                        .to_object(repo)
                        .with_context(|| format!("reading tree {oid}"))?;
                    if let Some(subtree) = object.as_tree() {
                        collect_tree(repo, subtree, seen, out)?;
                    }
                }
            }
            Some(git2::ObjectType::Blob) => {
                if seen.insert(oid) {
                    out.push(oid);
                }
            }
            // Submodule gitlinks and other kinds are not stored here.
            _ => {}
        }
    }
    Ok(())
}

/// Regenerate dumb-HTTP metadata (`info/refs` and `objects/info/packs`).
///
/// This is the producer counterpart to [`crate::registry::dumb_http`]: it
/// writes the same layout `git update-server-info` would, which that reader
/// consumes.
///
/// - `info/refs`: a `<oid>\t<refname>` line per ref, plus a peeled
///   `<commit-oid>\t<refname>^{}` line for each annotated tag.
/// - `objects/info/packs`: a `P <pack-name>.pack` line per pack.
///
/// # Errors
///
/// Returns an error if the repository cannot be read or the metadata files
/// cannot be written.
pub fn refresh_server_info(repo: &Path) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    let repository = open_git_dir(&git_dir)?;

    // info/refs
    let mut ref_lines: Vec<String> = Vec::new();
    for reference in repository.references().context("listing references")? {
        let reference = reference?;
        let Ok(name) = reference.name() else {
            continue;
        };
        if name == "HEAD" {
            continue;
        }
        let Some(oid) = reference.target() else {
            continue; // skip symbolic refs
        };
        ref_lines.push(format!("{oid}\t{name}"));
        if let Ok(object) = repository.find_object(oid, None)
            && object.kind() == Some(git2::ObjectType::Tag)
            && let Ok(peeled) = object.peel(git2::ObjectType::Commit)
        {
            ref_lines.push(format!("{}\t{name}^{{}}", peeled.id()));
        }
    }
    ref_lines.sort();
    let info_dir = git_dir.join("info");
    fs::create_dir_all(&info_dir).with_context(|| format!("creating {}", info_dir.display()))?;
    let mut info_refs = ref_lines.join("\n");
    if !info_refs.is_empty() {
        info_refs.push('\n');
    }
    fs::write(info_dir.join("refs"), info_refs)
        .with_context(|| format!("writing {}", info_dir.join("refs").display()))?;

    // objects/info/packs
    let pack_dir = git_dir.join("objects").join("pack");
    let mut packs: Vec<String> = Vec::new();
    if pack_dir.exists() {
        for entry in
            fs::read_dir(&pack_dir).with_context(|| format!("reading {}", pack_dir.display()))?
        {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("pack-")
                && name.ends_with(".pack")
            {
                packs.push(name.to_string());
            }
        }
    }
    packs.sort();
    let mut packs_body = String::new();
    for pack in packs {
        packs_body.push_str("P ");
        packs_body.push_str(&pack);
        packs_body.push('\n');
    }
    let objects_info = git_dir.join("objects").join("info");
    fs::create_dir_all(&objects_info)
        .with_context(|| format!("creating {}", objects_info.display()))?;
    fs::write(objects_info.join("packs"), packs_body)
        .with_context(|| format!("writing {}", objects_info.join("packs").display()))?;

    Ok(())
}

/// Write root `objects/info/alternates` with one relative release object dir
/// per line, sorted newest to oldest.
///
/// The entries intentionally use a single `../` so the file is host-independent
/// for both local and dumb-HTTP access.
///
/// # Errors
///
/// Returns an error if the git directory cannot be resolved or the
/// alternates file cannot be written.
pub fn write_alternates(repo: &Path, releases: &[semver::Version]) -> Result<()> {
    let git_dir = repo_git_dir(repo)?;
    let mut sorted = releases.to_vec();
    sorted.sort_by(|a, b| b.cmp(a));

    let info_dir = git_dir.join("objects").join("info");
    fs::create_dir_all(&info_dir).with_context(|| format!("creating {}", info_dir.display()))?;

    let mut out = String::new();
    for version in sorted {
        out.push_str("../releases/");
        out.push_str(&release_object_dir(&version).to_string_lossy());
        out.push_str("/\n");
    }

    fs::write(info_dir.join("alternates"), out)
        .with_context(|| format!("writing {}", info_dir.join("alternates").display()))?;
    Ok(())
}

/// Assert that `repo` is a sha256 git repository.
///
/// # Errors
///
/// Returns an error if the repository cannot be inspected or if its object
/// format is not exactly `sha256`.
pub fn assert_sha256(repo: &Path) -> Result<()> {
    let git_dir = repo_git_dir(repo)?;
    let repository = open_git_dir(&git_dir)?;
    // SHA-256 repositories record `extensions.objectformat = sha256` in config.
    let format = repository
        .config()
        .and_then(|cfg| cfg.get_string("extensions.objectformat"))
        .unwrap_or_default();
    if format != "sha256" {
        bail!(
            "registry repo {} uses object format '{}', expected sha256",
            repo.display(),
            if format.is_empty() { "sha1" } else { &format },
        );
    }
    Ok(())
}

/// Resolve a registry path to the git directory that stores served objects.
///
/// Bare published registries use `repo` itself. Local producer checkouts use
/// their `.git` directory, which is the byte tree mirrored for dumb HTTP.
///
/// # Errors
///
/// Returns an error when `repo` is neither a bare repository nor inside a
/// work tree that `git rev-parse --absolute-git-dir` can resolve.
pub fn repo_git_dir(repo: &Path) -> Result<PathBuf> {
    if repo.join("objects").is_dir() && repo.join("HEAD").exists() {
        return Ok(repo.to_path_buf());
    }

    let repository = git2::Repository::open(repo)
        .with_context(|| format!("resolving git dir for {}", repo.display()))?;
    Ok(repository.path().to_path_buf())
}

/// Open the bare git directory at `git_dir` directly (it is already the
/// resolved object-store directory from [`repo_git_dir`]).
fn open_git_dir(git_dir: &Path) -> Result<git2::Repository> {
    git2::Repository::open(git_dir)
        .with_context(|| format!("opening git repository at {}", git_dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read as _, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Component;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    /// Run a git CLI command with `--git-dir <git_dir>` (test-only helper).
    fn run_git_dir(git_dir: &Path, args: &[&str]) -> Result<String> {
        let output = crate::testutil::git_command(git_dir)
            .arg("--git-dir")
            .arg(git_dir)
            .args(args)
            .output()
            .with_context(|| format!("running git {} in {}", args.join(" "), git_dir.display()))?;
        if !output.status.success() {
            bail!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim(),
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    #[test]
    fn release_object_dir_mapping() {
        assert_eq!(
            release_object_dir(&v("1.0.0")),
            PathBuf::from("1/0/0/objects")
        );
        assert_eq!(
            release_object_dir(&v("1.1.2")),
            PathBuf::from("1/1/2/objects")
        );
        assert_eq!(
            release_object_dir(&v("1.1.0-alpha.1")),
            PathBuf::from("1/1/0-alpha.1/objects"),
        );
        assert_eq!(
            release_object_dir(&v("1.0.0-beta+exp.sha.5114f85")),
            PathBuf::from("1/0/0-beta+exp.sha.5114f85/objects"),
        );
    }

    #[test]
    fn loose_object_path_split() {
        let oid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            loose_object_path(oid).unwrap(),
            PathBuf::from("01/23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        );
        assert!(loose_object_path("abc").is_err());
        assert!(
            loose_object_path("zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",)
                .is_err()
        );
    }

    #[test]
    fn alternates_are_relative_and_newest_first() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo.git");
        init_bare_sha256(&repo, "stable").unwrap();
        write_alternates(&repo, &[v("1.0.0"), v("1.2.0"), v("1.1.2")]).unwrap();
        let content = fs::read_to_string(repo.join("objects/info/alternates")).unwrap();
        assert_eq!(
            content,
            "../releases/1/2/0/objects/\n../releases/1/1/2/objects/\n../releases/1/0/0/objects/\n",
        );
        assert!(!content.contains("://"));
    }

    #[test]
    fn assert_sha256_rejects_sha1() {
        let tmp = TempDir::new().unwrap();
        let sha1 = tmp.path().join("sha1.git");
        let sha256 = tmp.path().join("sha256.git");
        let sha256_worktree = tmp.path().join("sha256-worktree");

        let sha1_status = crate::testutil::git_command(tmp.path())
            .args(["init", "--bare"])
            .arg(&sha1)
            .status()
            .unwrap();
        assert!(sha1_status.success());
        assert!(assert_sha256(&sha1).is_err());

        init_bare_sha256(&sha256, "stable").unwrap();
        assert_eq!(repo_git_dir(&sha256).unwrap(), sha256);
        assert_sha256(&sha256).unwrap();
        assert_eq!(
            fs::read_to_string(sha256.join("HEAD")).unwrap(),
            "ref: refs/heads/stable\n"
        );

        let worktree_status = crate::testutil::git_command(tmp.path())
            .args(["init", "--object-format=sha256"])
            .arg(&sha256_worktree)
            .status()
            .unwrap();
        assert!(worktree_status.success());
        assert_sha256(&sha256_worktree).unwrap();
        assert!(repo_git_dir(&sha256_worktree).unwrap().ends_with(".git"));
    }

    #[test]
    fn write_release_objects_creates_pack_scaffold() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo.git");
        init_bare_sha256(&repo, "stable").unwrap();

        write_release_objects(&repo, &v("1.2.3"), "").unwrap();
        let dir = repo.join("releases/1/2/3/objects");
        assert!(dir.join("info").is_dir());
        assert!(dir.join("pack").is_dir());
    }

    #[test]
    fn canonical_zlib_is_stable_and_handles_multiple_stored_blocks() {
        let content = (0..=u16::MAX)
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let encoded = canonical_zlib(&content);
        assert_eq!(&encoded[..2], &[0x78, 0x01]);
        assert_eq!(encoded, canonical_zlib(&content));

        let mut decoded = Vec::new();
        flate2::read::ZlibDecoder::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn loose_object_writer_rejects_bytes_above_the_whole_upload_limit() {
        let tmp = TempDir::new().unwrap();
        let data = vec![
            0_u8;
            aos_registry_surface::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES as usize
        ];

        let error = write_loose_object_file(
            &tmp.path().join("oversized"),
            git2::ObjectType::Blob,
            &data,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("publication limit"));
    }

    #[test]
    fn ensure_loose_completeness_materializes_packed_reachable_objects() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo.git");
        let work = tmp.path().join("work");
        init_bare_sha256(&repo, "stable").unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("registry.toml"), "[registry]\nname = \"test\"\n").unwrap();

        let add = crate::testutil::git_command(tmp.path())
            .arg("--git-dir")
            .arg(&repo)
            .arg("--work-tree")
            .arg(&work)
            .args(["add", "registry.toml"])
            .status()
            .unwrap();
        assert!(add.success());
        let commit = crate::testutil::git_command(tmp.path())
            .arg("--git-dir")
            .arg(&repo)
            .arg("--work-tree")
            .arg(&work)
            .args(["commit", "-m", "init"])
            .status()
            .unwrap();
        assert!(commit.success());

        run_git_dir(&repo, &["repack", "-ad"]).unwrap();
        run_git_dir(&repo, &["prune-packed"]).unwrap();

        let oids = run_git_dir(&repo, &["rev-list", "--objects", "--all"])
            .unwrap()
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(!oids.is_empty());
        assert!(
            oids.iter().any(|oid| {
                !repo
                    .join("objects")
                    .join(loose_object_path(oid).unwrap())
                    .exists()
            }),
            "test setup should leave at least one reachable object packed only",
        );

        ensure_loose_completeness(&repo).unwrap();

        for oid in oids {
            assert!(
                repo.join("objects")
                    .join(loose_object_path(&oid).unwrap())
                    .exists(),
                "{oid} should have a root loose object copy",
            );
        }
    }

    #[test]
    fn dumb_http_clone_reads_static_sha256_repo() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo.git");
        let work = tmp.path().join("work");
        let clone = tmp.path().join("clone");
        init_bare_sha256(&repo, "stable").unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("registry.toml"), "[registry]\nname = \"test\"\n").unwrap();

        let add = crate::testutil::git_command(tmp.path())
            .arg("--git-dir")
            .arg(&repo)
            .arg("--work-tree")
            .arg(&work)
            .args(["add", "registry.toml"])
            .status()
            .unwrap();
        assert!(add.success());
        let commit = crate::testutil::git_command(tmp.path())
            .arg("--git-dir")
            .arg(&repo)
            .arg("--work-tree")
            .arg(&work)
            .args(["commit", "-m", "init"])
            .status()
            .unwrap();
        assert!(commit.success());

        write_alternates(&repo, &[]).unwrap();
        ensure_loose_completeness(&repo).unwrap();
        refresh_server_info(&repo).unwrap();

        let Some(server) = StaticServer::start(repo) else {
            eprintln!("skipping dumb-HTTP clone test: local TCP bind is unavailable");
            return;
        };
        let output = crate::testutil::git_command(tmp.path())
            .env("GIT_SMART_HTTP", "0")
            .arg("clone")
            .arg(&server.url)
            .arg(&clone)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            fs::read_to_string(clone.join("registry.toml")).unwrap(),
            "[registry]\nname = \"test\"\n",
        );
    }

    struct StaticServer {
        url: String,
        stop: Option<mpsc::Sender<()>>,
    }

    impl StaticServer {
        fn start(root: PathBuf) -> Option<Self> {
            let listener = match TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => listener,
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    return None;
                }
                Err(err) => panic!("binding local static test server failed: {err}"),
            };
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = mpsc::channel();

            thread::spawn(move || {
                loop {
                    if rx.try_recv().is_ok() {
                        break;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => handle_static_request(stream, &root),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });

            Some(Self {
                url: format!("http://{addr}/"),
                stop: Some(tx),
            })
        }
    }

    impl Drop for StaticServer {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    fn handle_static_request(mut stream: TcpStream, root: &Path) {
        let mut first = String::new();
        {
            let mut reader = BufReader::new(&mut stream);
            if reader.read_line(&mut first).is_err() {
                return;
            }
        }

        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("");
        let request_path = parts.next().unwrap_or("/");
        let url_path = request_path.split('?').next().unwrap_or("/");
        let decoded = percent_decode(url_path.trim_start_matches('/'));
        let rel = PathBuf::from(decoded);
        if rel
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            write_response(&mut stream, "403 Forbidden", &[], method == "HEAD");
            return;
        }

        let path = root.join(rel);
        match fs::read(&path) {
            Ok(body) if path.is_file() && (method == "GET" || method == "HEAD") => {
                write_response(&mut stream, "200 OK", &body, method == "HEAD");
            }
            _ => write_response(
                &mut stream,
                "404 Not Found",
                b"not found\n",
                method == "HEAD",
            ),
        }
    }

    fn write_response(stream: &mut TcpStream, status: &str, body: &[u8], head_only: bool) {
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        );
        if !head_only {
            let _ = stream.write_all(body);
        }
    }

    fn percent_decode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                    if let Ok(value) = u8::from_str_radix(hex, 16) {
                        out.push(value);
                        i += 3;
                        continue;
                    }
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

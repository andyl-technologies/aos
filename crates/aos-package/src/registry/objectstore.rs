//! Git-native registry object-store helpers.
//!
//! These helpers own the static dumb-HTTP object layout used by the target
//! registry: a bare sha256 repository, root loose-object store, per-release
//! pack directories, and relative `objects/info/alternates`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Initialize `dir` as a bare sha256 git repository and point `HEAD` at the
/// default channel branch.
///
/// # Errors
///
/// Returns an error if initialization or the sha256 format guard fails.
pub fn init_bare_sha256(dir: &Path, default_channel: &str) -> Result<()> {
    if default_channel.is_empty() || default_channel.contains('/') {
        bail!("default channel must be a single non-empty ref segment");
    }

    crate::git_support::init_sha256(dir, true, default_channel)?;
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
pub fn write_release_objects(repo: &Path, version: &semver::Version, revspec: &str) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    if !revspec.is_empty() {
        let repo = crate::git_support::open(&git_dir)?;
        crate::git_support::resolve_commit_oid(&repo, revspec)
            .with_context(|| format!("validating revspec '{revspec}'"))?;
    }

    let objects_dir = git_dir.join("releases").join(release_object_dir(version));
    fs::create_dir_all(objects_dir.join("info"))
        .with_context(|| format!("creating {}", objects_dir.join("info").display()))?;
    fs::create_dir_all(objects_dir.join("pack"))
        .with_context(|| format!("creating {}", objects_dir.join("pack").display()))?;
    Ok(())
}

/// Ensure every reachable object has a loose copy in the root `/objects/` store.
///
/// Every object reachable from refs is written into the root loose-object store
/// and then checked for a loose `objects/xx/rest` file.
///
/// # Errors
///
/// Returns an error if pack unpacking fails or any reachable object remains
/// missing as a loose object.
pub fn ensure_loose_completeness(repo: &Path) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    let repo = crate::git_support::open(&git_dir)?;
    crate::git_support::ensure_loose_objects(&repo)?;
    let objects = reachable_objects(&repo)?;
    let mut missing = Vec::new();
    for oid in objects {
        let loose = git_dir.join("objects").join(loose_object_path(&oid)?);
        if !loose.exists() {
            missing.push(oid.to_string());
        }
    }

    if !missing.is_empty() {
        bail!(
            "reachable objects are not present loose in root store: {}",
            missing.join(", "),
        );
    }

    Ok(())
}

/// Regenerate dumb-HTTP metadata (`info/refs` and `objects/info/packs`).
///
/// # Errors
///
/// Returns an error if metadata files cannot be written.
pub fn refresh_server_info(repo: &Path) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    let repo = crate::git_support::open(&git_dir)?;
    crate::git_support::refresh_server_info(&repo)?;
    Ok(())
}

/// Write root `objects/info/alternates` with one relative release object dir
/// per line, sorted newest to oldest.
///
/// The entries intentionally use a single `../` so the file is host-independent
/// for both local and dumb-HTTP access.
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
    let opened = crate::git_support::open(&git_dir)?;
    if let Err(err) = crate::git_support::assert_sha256(&opened) {
        bail!(
            "registry repo {} is not a sha256 repository: {err}",
            repo.display(),
        );
    }
    Ok(())
}

/// Resolve a registry path to the git directory that stores served objects.
///
/// Bare published registries use `repo` itself. Local producer checkouts use
/// their `.git` directory, which is the byte tree mirrored for dumb HTTP.
pub fn repo_git_dir(repo: &Path) -> Result<PathBuf> {
    if repo.join("objects").is_dir() && repo.join("HEAD").exists() {
        return Ok(repo.to_path_buf());
    }

    let opened = crate::git_support::open(repo)
        .with_context(|| format!("resolving git dir for {}", repo.display()))?;
    Ok(crate::git_support::git_dir(&opened))
}

fn reachable_objects(repo: &git2::Repository) -> Result<Vec<String>> {
    let mut objects = std::collections::BTreeSet::new();
    let mut refs = repo.references().context("listing refs")?;
    for reference in &mut refs {
        let reference = reference.context("reading ref")?;
        if let Some(oid) = reference
            .target()
            .or_else(|| reference.resolve().ok()?.target())
        {
            objects.insert(oid.to_string());
        }
    }

    let mut walk = repo.revwalk().context("creating git revwalk")?;
    walk.push_glob("refs/*").context("walking refs")?;
    for oid in walk {
        let oid = oid?;
        objects.insert(oid.to_string());
        let commit = repo.find_commit(oid)?;
        collect_tree_objects(repo, &commit.tree()?, &mut objects)?;
    }
    Ok(objects.into_iter().collect())
}

fn collect_tree_objects(
    repo: &git2::Repository,
    tree: &git2::Tree<'_>,
    objects: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    objects.insert(tree.id().to_string());
    for entry in tree {
        objects.insert(entry.id().to_string());
        if entry.kind() == Some(git2::ObjectType::Tree) {
            collect_tree_objects(repo, &repo.find_tree(entry.id())?, objects)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Component;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
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

        git2::Repository::init_bare(&sha1).unwrap();
        assert!(assert_sha256(&sha1).is_err());

        init_bare_sha256(&sha256, "stable").unwrap();
        assert_eq!(repo_git_dir(&sha256).unwrap(), sha256);
        assert_sha256(&sha256).unwrap();
        assert_eq!(
            fs::read_to_string(sha256.join("HEAD")).unwrap(),
            "ref: refs/heads/stable\n"
        );

        crate::git_support::init_sha256(&sha256_worktree, false, "master").unwrap();
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
    fn dumb_http_clone_reads_static_sha256_repo() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo.git");
        let clone = tmp.path().join("clone");
        init_bare_sha256(&repo, "stable").unwrap();
        let opened = crate::git_support::open(&repo).unwrap();
        let blob = opened.blob(b"[registry]\nname = \"test\"\n").unwrap();
        let mut builder = opened.treebuilder(None).unwrap();
        builder
            .insert("registry.toml", blob, git2::FileMode::Blob.into())
            .unwrap();
        let tree = opened.find_tree(builder.write().unwrap()).unwrap();
        let sig = git2::Signature::now("AOS Test", "aos@example.invalid").unwrap();
        opened
            .commit(Some("refs/heads/stable"), &sig, &sig, "init", &tree, &[])
            .unwrap();

        write_alternates(&repo, &[]).unwrap();
        ensure_loose_completeness(&repo).unwrap();
        refresh_server_info(&repo).unwrap();

        let Some(server) = StaticServer::start(repo) else {
            eprintln!("skipping dumb-HTTP clone test: local TCP bind is unavailable");
            return;
        };
        git2::Repository::clone(&server.url, &clone).unwrap();
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

//! Git-native registry object-store helpers.
//!
//! These helpers own the static dumb-HTTP object layout used by the target
//! registry: a bare sha256 repository, root loose-object store, per-release
//! pack directories, and relative `objects/info/alternates`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};

use crate::gitcmd;

/// Initialize `dir` as a bare sha256 git repository and point `HEAD` at the
/// default channel branch.
///
/// # Errors
///
/// Returns an error if `git init`, `git symbolic-ref`, or the sha256 format
/// guard fails.
pub fn init_bare_sha256(dir: &Path, default_channel: &str) -> Result<()> {
    if default_channel.is_empty() || default_channel.contains('/') {
        bail!("default channel must be a single non-empty ref segment");
    }

    let output = gitcmd::hermetic()
        .args(["init", "--bare", "--object-format=sha256"])
        .arg(dir)
        .output()
        .with_context(|| format!("running git init for {}", dir.display()))?;
    if !output.status.success() {
        bail!(
            "git init --bare --object-format=sha256 failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    run_git_dir(
        dir,
        &[
            "symbolic-ref",
            "HEAD",
            &format!("refs/heads/{default_channel}"),
        ],
    )?;
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
        run_git_dir(&git_dir, &["rev-list", "--objects", revspec])?;
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
/// Full packs found under the root repo and per-release pack dirs are unpacked
/// into the root object store, then every object reachable from refs is checked
/// for a loose `objects/xx/rest` file.
///
/// # Errors
///
/// Returns an error if pack unpacking fails or any reachable object remains
/// missing as a loose object.
pub fn ensure_loose_completeness(repo: &Path) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;

    for pack in full_pack_files(&git_dir)? {
        unpack_pack(&git_dir, &pack).with_context(|| format!("unpacking {}", pack.display()))?;
    }

    let objects = run_git_dir(&git_dir, &["rev-list", "--objects", "--all"])?;
    let mut missing = Vec::new();
    for line in objects.lines() {
        let Some(oid) = line.split_whitespace().next() else {
            continue;
        };
        let loose = git_dir.join("objects").join(loose_object_path(oid)?);
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
/// Returns an error if `git update-server-info` fails.
pub fn refresh_server_info(repo: &Path) -> Result<()> {
    assert_sha256(repo)?;
    let git_dir = repo_git_dir(repo)?;
    run_git_dir(&git_dir, &["update-server-info"])?;
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
    let format = run_git_dir(&git_dir, &["rev-parse", "--show-object-format"])?;
    if format.trim() != "sha256" {
        bail!(
            "registry repo {} uses object format '{}', expected sha256",
            repo.display(),
            format.trim(),
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

    let output = gitcmd::hermetic()
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .with_context(|| format!("resolving git dir for {}", repo.display()))?;

    if !output.status.success() {
        bail!(
            "git rev-parse --absolute-git-dir failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        bail!("git rev-parse --absolute-git-dir returned an empty path");
    }
    Ok(PathBuf::from(path))
}

fn run_git_dir(repo: &Path, args: &[&str]) -> Result<String> {
    let output = gitcmd::hermetic()
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), repo.display()))?;

    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn unpack_pack(repo: &Path, pack: &Path) -> Result<()> {
    let pack_file = fs::File::open(pack).with_context(|| format!("opening {}", pack.display()))?;
    let output = gitcmd::hermetic()
        .arg("--git-dir")
        .arg(repo)
        .arg("unpack-objects")
        .arg("-r")
        .stdin(Stdio::from(pack_file))
        .output()
        .context("running git unpack-objects")?;

    if !output.status.success() {
        bail!(
            "git unpack-objects failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    Ok(())
}

fn full_pack_files(repo: &Path) -> Result<Vec<PathBuf>> {
    let mut packs = Vec::new();
    collect_full_packs(&repo.join("objects").join("pack"), &mut packs)?;
    collect_full_packs(&repo.join("releases"), &mut packs)?;
    Ok(packs)
}

fn collect_full_packs(dir: &Path, packs: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_full_packs(&path, packs)?;
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("pack-") && name.ends_with(".pack") {
                packs.push(path);
            }
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

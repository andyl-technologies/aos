//! Git-native registry object-store helpers.
//!
//! These helpers own the static dumb-HTTP object layout used by the target
//! registry: a bare sha256 repository, root loose-object store, per-release
//! pack directories, and relative `objects/info/alternates`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

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

    let output = Command::new("git")
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
        &["symbolic-ref", "HEAD", &format!("refs/heads/{default_channel}")],
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
pub fn write_release_objects(
    repo: &Path,
    version: &semver::Version,
    revspec: &str,
) -> Result<()> {
    assert_sha256(repo)?;
    if !revspec.is_empty() {
        run_git_dir(repo, &["rev-list", "--objects", revspec])?;
    }

    let objects_dir = repo.join("releases").join(release_object_dir(version));
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

    for pack in full_pack_files(repo)? {
        unpack_pack(repo, &pack)
            .with_context(|| format!("unpacking {}", pack.display()))?;
    }

    let objects = run_git_dir(repo, &["rev-list", "--objects", "--all"])?;
    let mut missing = Vec::new();
    for line in objects.lines() {
        let Some(oid) = line.split_whitespace().next() else {
            continue;
        };
        let loose = repo.join("objects").join(loose_object_path(oid)?);
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
    run_git_dir(repo, &["update-server-info"])?;
    Ok(())
}

/// Write root `objects/info/alternates` with one relative release object dir
/// per line, sorted newest to oldest.
///
/// The entries intentionally use a single `../` so the file is host-independent
/// for both local and dumb-HTTP access.
pub fn write_alternates(repo: &Path, releases: &[semver::Version]) -> Result<()> {
    let mut sorted = releases.to_vec();
    sorted.sort_by(|a, b| b.cmp(a));

    let info_dir = repo.join("objects").join("info");
    fs::create_dir_all(&info_dir)
        .with_context(|| format!("creating {}", info_dir.display()))?;

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
    let format = if repo.join(".git").exists() {
        run_git_worktree(repo, &["rev-parse", "--show-object-format"])?
    } else {
        run_git_dir(repo, &["rev-parse", "--show-object-format"])?
    };
    if format.trim() != "sha256" {
        bail!(
            "registry repo {} uses object format '{}', expected sha256",
            repo.display(),
            format.trim(),
        );
    }
    Ok(())
}

fn run_git_dir(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
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

fn run_git_worktree(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
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
    let pack_file = fs::File::open(pack)
        .with_context(|| format!("opening {}", pack.display()))?;
    let output = Command::new("git")
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

    for entry in fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
    {
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
    use tempfile::TempDir;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn release_object_dir_mapping() {
        assert_eq!(release_object_dir(&v("1.0.0")), PathBuf::from("1/0/0/objects"));
        assert_eq!(release_object_dir(&v("1.1.2")), PathBuf::from("1/1/2/objects"));
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
        assert!(loose_object_path(
            "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .is_err());
    }

    #[test]
    fn alternates_are_relative_and_newest_first() {
        let tmp = TempDir::new().unwrap();
        write_alternates(tmp.path(), &[v("1.0.0"), v("1.2.0"), v("1.1.2")]).unwrap();
        let content = fs::read_to_string(tmp.path().join("objects/info/alternates")).unwrap();
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

        let sha1_status = Command::new("git")
            .args(["init", "--bare"])
            .arg(&sha1)
            .status()
            .unwrap();
        assert!(sha1_status.success());
        assert!(assert_sha256(&sha1).is_err());

        init_bare_sha256(&sha256, "stable").unwrap();
        assert_sha256(&sha256).unwrap();
        assert_eq!(fs::read_to_string(sha256.join("HEAD")).unwrap(), "ref: refs/heads/stable\n");

        let worktree_status = Command::new("git")
            .args(["init", "--object-format=sha256"])
            .arg(&sha256_worktree)
            .status()
            .unwrap();
        assert!(worktree_status.success());
        assert_sha256(&sha256_worktree).unwrap();
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
}

//! Pack and thin-delta helpers for the git-native registry.
//!
//! Producer-side helpers that build the per-release transfer artifacts served
//! from the static origin: self-contained libgit2 full packs at `X.Y.0`
//! anchors ([`full_pack`]) and pure-Rust thin delta packs between nearby
//! releases ([`thin_delta`], with bases chosen by [`scheme_deltas`]). The
//! matching consumer-side selection logic lives in
//! [`fetch`](crate::registry::fetch).
//!
//! Thin packs are generated with stored zlib entries, equivalent to
//! `git pack-objects --compression=0`, so the zstd transport wrapper
//! ([`zstd_compress`]) can compress the whole delta stream with a
//! long-distance window. Full packs are indexed with libgit2's indexer so stock
//! dumb-HTTP Git can consume them; AOS consumers index full and thin packs with
//! libgit2's pack writer ([`index_pack`]), regenerating and verifying indexes
//! locally.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use tokio::process::Command;

use crate::registry::thinpack;

/// Compression level used for the zstd transport wrapper.
pub const ZSTD_LEVEL: &str = "-22";
/// Long-distance window used by producer and consumer.
pub const ZSTD_LONG: &str = "27";

/// Kind of a semver release for the guaranteed delta scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseKind {
    /// `X.0.0`
    Major,
    /// `X.Y.0`, where `Y > 0`.
    Minor,
    /// `X.Y.Z`, where `Z > 0`.
    Patch,
}

/// Classify a release by its semver triple.
pub fn release_kind(version: &semver::Version) -> ReleaseKind {
    if version.minor == 0 && version.patch == 0 {
        ReleaseKind::Major
    } else if version.patch == 0 {
        ReleaseKind::Minor
    } else {
        ReleaseKind::Patch
    }
}

/// Return the guaranteed delta bases for `release`, newest to oldest.
///
/// The returned versions are selected only from `published`; missing bases are
/// skipped and duplicate bases are collapsed.
pub fn scheme_deltas(
    release: &semver::Version,
    published: &[semver::Version],
) -> Vec<semver::Version> {
    let mut bases = Vec::new();
    match release_kind(release) {
        ReleaseKind::Major => {
            if release.major > 0 {
                push_if_published(
                    &mut bases,
                    published,
                    semver::Version::new(release.major - 1, 0, 0),
                );
            }
        }
        ReleaseKind::Minor => {
            if release.minor > 0 {
                push_if_published(
                    &mut bases,
                    published,
                    semver::Version::new(release.major, release.minor - 1, 0),
                );
            }
            push_if_published(
                &mut bases,
                published,
                semver::Version::new(release.major, 0, 0),
            );
        }
        ReleaseKind::Patch => {
            for offset in 1..=3 {
                if release.patch >= offset {
                    push_if_published(
                        &mut bases,
                        published,
                        semver::Version::new(release.major, release.minor, release.patch - offset),
                    );
                }
            }
            push_if_published(
                &mut bases,
                published,
                semver::Version::new(release.major, release.minor, 0),
            );
        }
    }
    bases
}

/// Generate a self-contained full pack over `release_commit`.
///
/// # Errors
///
/// Returns an error if the commit cannot be resolved or the pack cannot be
/// built or written.
pub async fn full_pack(repo: &Path, release_commit: &str, out_dir: &Path) -> Result<PathBuf> {
    tokio::fs::create_dir_all(out_dir)
        .await
        .with_context(|| format!("creating {}", out_dir.display()))?;
    let repo = repo.to_path_buf();
    let commit = release_commit.to_string();
    let out_dir = out_dir.to_path_buf();
    tokio::task::spawn_blocking(move || full_pack_blocking(&repo, &commit, &out_dir))
        .await
        .context("full-pack task panicked")?
}

/// Build a self-contained pack of everything reachable from `release_commit`
/// with libgit2's pack builder and indexer, named `pack-<hash>.pack` after its
/// trailing checksum.
fn full_pack_blocking(repo: &Path, release_commit: &str, out_dir: &Path) -> Result<PathBuf> {
    let repository = git2::Repository::open(repo)
        .with_context(|| format!("opening git repository at {}", repo.display()))?;
    let oid = repository
        .revparse_single(release_commit)
        .with_context(|| format!("resolving {release_commit}"))?
        .peel_to_commit()
        .with_context(|| format!("{release_commit} is not a commit"))?
        .id();

    let mut builder = repository.packbuilder().context("creating pack builder")?;
    let mut revwalk = repository.revwalk().context("creating revwalk")?;
    revwalk.push(oid).context("seeding pack revwalk")?;
    builder
        .insert_walk(&mut revwalk)
        .context("inserting objects into pack")?;
    builder
        .write(out_dir, 0)
        .with_context(|| format!("writing full pack into {}", out_dir.display()))?;
    let hash = builder
        .name()
        .context("reading full-pack name")?
        .ok_or_else(|| anyhow::anyhow!("libgit2 did not report a full-pack name"))?;
    let path = out_dir.join(format!("pack-{hash}.pack"));
    if !path.exists() {
        bail!(
            "libgit2 indexed full pack but did not write {}",
            path.display()
        );
    }
    Ok(path)
}

/// Generate a thin delta pack from `from_commit` to `to_commit`.
///
/// The output filename is `delta-<from_semver>.pack`. The pack references base
/// objects it does not contain; consumers complete it with
/// [`index_pack_fix_thin`].
///
/// # Errors
///
/// Returns an error if the output directory cannot be created or the pack
/// cannot be generated.
pub async fn thin_delta(
    repo: &Path,
    from_commit: &str,
    to_commit: &str,
    from_semver: &semver::Version,
    out_dir: &Path,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(out_dir)
        .await
        .with_context(|| format!("creating {}", out_dir.display()))?;
    let out = out_dir.join(format!("delta-{from_semver}.pack"));
    let repo = repo.to_path_buf();
    let from = from_commit.to_string();
    let to = to_commit.to_string();
    let out_path = out.clone();
    tokio::task::spawn_blocking(move || thinpack::write_thin_pack(&repo, &from, &to, &out_path))
        .await
        .context("thin-pack task panicked")??;
    Ok(out)
}

/// Compress `path` with zstd, producing `<path>.zst`.
///
/// Uses the module's fixed ultra level ([`ZSTD_LEVEL`]) and long-distance
/// window ([`ZSTD_LONG`]), optionally with a trained dictionary.
///
/// # Errors
///
/// Returns an error if the `zstd` command cannot be run or exits non-zero.
pub async fn zstd_compress(path: &Path, dict: Option<&Path>) -> Result<PathBuf> {
    let mut out = path.as_os_str().to_os_string();
    out.push(".zst");
    let out = PathBuf::from(out);

    let mut cmd = Command::new("zstd");
    cmd.arg("--ultra")
        .arg(ZSTD_LEVEL)
        .arg(format!("--long={ZSTD_LONG}"));
    if let Some(dict) = dict {
        cmd.arg("-D").arg(dict);
    }
    cmd.arg("-f").arg("-o").arg(&out).arg(path);

    run_status(cmd, "zstd compress").await?;
    Ok(out)
}

/// Decompress a `.zst` file, stripping the `.zst` suffix.
///
/// # Errors
///
/// Returns an error if `path` has no filename, does not end in `.zst`, or
/// the `zstd` command fails.
pub async fn zstd_decompress(path: &Path, dict: Option<&Path>) -> Result<PathBuf> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        bail!("zstd path has no filename: {}", path.display());
    };
    let Some(stripped) = name.strip_suffix(".zst") else {
        bail!("zstd path does not end in .zst: {}", path.display());
    };
    let out = path.with_file_name(stripped);

    let mut cmd = Command::new("zstd");
    cmd.arg("-d").arg(format!("--long={ZSTD_LONG}"));
    if let Some(dict) = dict {
        cmd.arg("-D").arg(dict);
    }
    cmd.arg("-f").arg("-o").arg(&out).arg(path);

    run_status(cmd, "zstd decompress").await?;
    Ok(out)
}

/// Complete a thin pack with bases from `repo`.
///
/// libgit2's pack writer indexes the pack and resolves any thin deltas against
/// the repository's existing objects (the `git index-pack --fix-thin`
/// behavior).
///
/// # Errors
///
/// Returns an error if the pack cannot be read or indexed (e.g. a base object
/// is missing from `repo`).
pub async fn index_pack_fix_thin(repo: &Path, pack: &Path) -> Result<()> {
    index_pack(repo, pack).await
}

/// Index a pack into `repo`'s object store via libgit2's pack writer, which
/// regenerates and verifies the index (and resolves thin deltas against the
/// repository's objects, so it also completes thin packs).
///
/// # Errors
///
/// Returns an error if the pack cannot be read, is corrupt, or references base
/// objects absent from `repo`.
pub async fn index_pack(repo: &Path, pack: &Path) -> Result<()> {
    let repo = repo.to_path_buf();
    let pack = pack.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::{Read as _, Write as _};
        let repository = git2::Repository::open(&repo)
            .with_context(|| format!("opening git repository at {}", repo.display()))?;
        let odb = repository.odb().context("opening object database")?;
        let mut input =
            std::fs::File::open(&pack).with_context(|| format!("opening {}", pack.display()))?;
        let mut writer = odb.packwriter().context("creating pack writer")?;
        let mut buf = [0u8; 128 * 1024];
        loop {
            let n = input
                .read(&mut buf)
                .with_context(|| format!("reading {}", pack.display()))?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n]).context("writing pack data")?;
        }
        writer.commit().context("indexing pack")?;
        Ok(())
    })
    .await
    .context("index-pack task panicked")?
}

/// Train a zstd dictionary over a release line's delta packs.
///
/// # Errors
///
/// Returns an error if `packs` is empty or `zstd --train` fails.
pub async fn train_dictionary(packs: &[PathBuf], out: &Path) -> Result<PathBuf> {
    if packs.is_empty() {
        bail!("cannot train a zstd dictionary without input packs");
    }

    let mut cmd = Command::new("zstd");
    cmd.arg("--train");
    for pack in packs {
        cmd.arg(pack);
    }
    cmd.arg("-o").arg(out);
    run_status(cmd, "zstd --train").await?;
    Ok(out.to_path_buf())
}

/// Append `candidate` to `bases` if it is published and not already present.
fn push_if_published(
    bases: &mut Vec<semver::Version>,
    published: &[semver::Version],
    candidate: semver::Version,
) {
    if published.iter().any(|v| *v == candidate) && !bases.contains(&candidate) {
        bases.push(candidate);
    }
}

/// Run a command and fail with its stderr if it exits non-zero.
async fn run_status(mut cmd: Command, label: &str) -> Result<()> {
    let output = cmd
        .output()
        .await
        .with_context(|| format!("running {label}"))?;
    if !output.status.success() {
        bail!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn release_kind_classifies_triple() {
        assert_eq!(release_kind(&v("1.0.0")), ReleaseKind::Major);
        assert_eq!(release_kind(&v("1.1.0")), ReleaseKind::Minor);
        assert_eq!(release_kind(&v("1.1.1")), ReleaseKind::Patch);
    }

    #[test]
    fn scheme_deltas_first_major_is_empty() {
        assert!(scheme_deltas(&v("1.0.0"), &[]).is_empty());
    }

    #[test]
    fn scheme_deltas_next_major_uses_prior_major() {
        assert_eq!(scheme_deltas(&v("2.0.0"), &[v("1.0.0")]), vec![v("1.0.0")],);
    }

    #[test]
    fn scheme_deltas_minor_dedups_to_minor_base() {
        assert_eq!(scheme_deltas(&v("1.1.0"), &[v("1.0.0")]), vec![v("1.0.0")],);
    }

    #[test]
    fn scheme_deltas_minor_uses_last_minor_and_major() {
        assert_eq!(
            scheme_deltas(&v("1.2.0"), &[v("1.0.0"), v("1.1.0")]),
            vec![v("1.1.0"), v("1.0.0")],
        );
    }

    #[test]
    fn scheme_deltas_patch_collapses_to_minor_base() {
        assert_eq!(
            scheme_deltas(&v("1.1.2"), &[v("1.1.0"), v("1.1.1")]),
            vec![v("1.1.1"), v("1.1.0")],
        );
    }

    #[test]
    fn scheme_deltas_patch_full_fan() {
        assert_eq!(
            scheme_deltas(&v("1.1.3"), &[v("1.1.0"), v("1.1.1"), v("1.1.2")],),
            vec![v("1.1.2"), v("1.1.1"), v("1.1.0")],
        );
    }
}

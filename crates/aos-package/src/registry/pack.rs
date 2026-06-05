//! Pack and delta helpers for the git-native registry.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::process::Command;

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
/// Returns an error if the repository cannot be read or the pack cannot be written.
pub async fn full_pack(repo: &Path, release_commit: &str, out_dir: &Path) -> Result<PathBuf> {
    let repo = crate::git_support::open(repo)?;
    crate::git_support::write_full_pack(&repo, release_commit, out_dir)
}

/// Generate a delta pack from `from_commit` to `to_commit`.
///
/// The output filename is `delta-<from_semver>.pack`.
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
    let repo = crate::git_support::open(repo)?;
    crate::git_support::write_delta_pack(&repo, from_commit, to_commit, &out)?;
    Ok(out)
}

/// Compress `path` with zstd, producing `<path>.zst`.
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
pub async fn index_pack_fix_thin(repo: &Path, pack: &Path) -> Result<()> {
    let repo = crate::git_support::open(repo)?;
    crate::git_support::index_pack(&repo, pack)
}

/// Index a self-contained full pack.
pub async fn index_pack(repo: &Path, pack: &Path) -> Result<()> {
    let repo = crate::git_support::open(repo)?;
    crate::git_support::index_pack(&repo, pack)
}

/// Train a zstd dictionary over a release line's delta packs.
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

fn push_if_published(
    bases: &mut Vec<semver::Version>,
    published: &[semver::Version],
    candidate: semver::Version,
) {
    if published.iter().any(|v| *v == candidate) && !bases.contains(&candidate) {
        bases.push(candidate);
    }
}

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

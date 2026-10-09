//! Verified registry pack acquisition and decompression.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use tokio::process::Command;
/// Compression level used for the zstd transport wrapper.
pub const ZSTD_LEVEL: &str = "-22";
/// Long-distance window used by producer and consumer.
pub const ZSTD_LONG: &str = "27";

#[cfg(test)]

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

#[cfg(test)]

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

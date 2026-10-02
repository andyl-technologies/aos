//! Optimized release packs shared by every registry release adapter.

use std::fs::{self, File};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;

use crate::registry::{objectstore, pack};
use crate::registry_ops::release_commit;

/// Immutable pack artifacts generated for one signed registry release.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistryReleaseArtifacts {
    /// Full pack for a major or minor anchor.
    pub full_pack: Option<String>,
    /// Compressed thin deltas from all supported predecessor releases.
    pub deltas: Vec<String>,
}

/// Generate the pack artifacts for a release under
/// `.git/releases/<version>/`.
///
/// Major and minor releases get a self-contained full pack, recorded in
/// `info/packs` for dumb-HTTP fetchers. Every release also gets a
/// zstd-compressed thin delta from each prior release selected by the
/// delta scheme, so consumers on a supported base version can fetch a
/// compact incremental pack instead of the full history.
pub(crate) async fn write_release_artifacts(
    dir: &Path,
    published_before: &[semver::Version],
    version: &semver::Version,
    resume: bool,
    printer: &Printer,
) -> Result<RegistryReleaseArtifacts> {
    let commit = release_commit(dir, version)?;
    let release_objects = objectstore::repo_git_dir(dir)?
        .join("releases")
        .join(objectstore::release_object_dir(version));
    let pack_dir = release_objects.join("pack");
    let info_dir = release_objects.join("info");
    fs::create_dir_all(&pack_dir).with_context(|| format!("creating {}", pack_dir.display()))?;
    fs::create_dir_all(&info_dir).with_context(|| format!("creating {}", info_dir.display()))?;

    let full_pack = match pack::release_kind(version) {
        pack::ReleaseKind::Major | pack::ReleaseKind::Minor => {
            Some(write_full_pack_artifact(dir, &commit, &pack_dir, resume, printer).await?)
        }
        pack::ReleaseKind::Patch => None,
    };

    if let Some(full_pack) = &full_pack {
        fs::write(info_dir.join("packs"), format!("P {full_pack}\n"))
            .with_context(|| format!("writing {}", info_dir.join("packs").display()))?;
    }

    let mut deltas = Vec::new();
    for base in pack::scheme_deltas(version, published_before) {
        let base_commit = release_commit(dir, &base)?;
        deltas.push(
            write_delta_artifact(
                dir,
                &base,
                &base_commit,
                &commit,
                &pack_dir,
                resume,
                printer,
            )
            .await?,
        );
    }

    Ok(RegistryReleaseArtifacts { full_pack, deltas })
}

/// Generate (or, with `resume`, reuse) the full `pack-*.pack` for a
/// release commit, staging it in a tempdir before copying it and its
/// `.idx` into place.
async fn write_full_pack_artifact(
    dir: &Path,
    commit: &str,
    pack_dir: &Path,
    resume: bool,
    printer: &Printer,
) -> Result<String> {
    if let Some(existing) = existing_full_pack(pack_dir)? {
        if resume {
            let idx = pack_dir.join(existing.trim_end_matches(".pack").to_string() + ".idx");
            if !idx.exists() {
                bail!(
                    "full pack {existing} exists but its index {} is missing; rerun without --resume to regenerate it",
                    idx.display()
                );
            }
            printer.info(&format!("Full pack {existing} already exists; resuming."));
            return Ok(existing);
        }
        bail!("full pack {existing} already exists; pass --resume to reuse it");
    }

    let private_staging = objectstore::repo_git_dir(dir)?.join("apr/release-artifacts");
    fs::create_dir_all(&private_staging)?;
    let tmp = tempfile::Builder::new()
        .prefix(".tmp-full-pack-")
        .tempdir_in(&private_staging)
        .with_context(|| format!("creating full-pack tempdir in {}", pack_dir.display()))?;
    let pack_path = pack::full_pack(dir, commit, tmp.path()).await?;
    let pack_name = file_name_string(&pack_path)?;
    let idx_path = pack_path.with_extension("idx");
    if !idx_path.exists() {
        bail!("full pack index was not generated: {}", idx_path.display());
    }
    let idx_name = file_name_string(&idx_path)?;
    install_immutable(&idx_path, &pack_dir.join(idx_name), &private_staging)?;
    install_immutable(&pack_path, &pack_dir.join(&pack_name), &private_staging)?;
    printer.success(&format!("Generated full pack {pack_name}."));
    Ok(pack_name)
}

/// Generate (or, with `resume`, reuse) the `delta-<base>.pack.zst` thin
/// pack carrying the objects needed to go from `base_commit` to
/// `target_commit`.
async fn write_delta_artifact(
    dir: &Path,
    base: &semver::Version,
    base_commit: &str,
    target_commit: &str,
    pack_dir: &Path,
    resume: bool,
    printer: &Printer,
) -> Result<String> {
    let artifact_name = format!("delta-{base}.pack.zst");
    let dest = pack_dir.join(&artifact_name);
    if dest.exists() {
        if resume {
            printer.info(&format!(
                "Delta pack {artifact_name} already exists; resuming."
            ));
            return Ok(artifact_name);
        }
        bail!("delta pack {artifact_name} already exists; pass --resume to reuse it");
    }

    let private_staging = objectstore::repo_git_dir(dir)?.join("apr/release-artifacts");
    fs::create_dir_all(&private_staging)?;
    let tmp = tempfile::Builder::new()
        .prefix(".tmp-delta-pack-")
        .tempdir_in(&private_staging)
        .with_context(|| format!("creating delta-pack tempdir in {}", pack_dir.display()))?;
    let delta = pack::thin_delta(dir, base_commit, target_commit, base, tmp.path()).await?;
    let compressed = pack::zstd_compress(&delta, None).await?;
    install_immutable(&compressed, &dest, &private_staging)?;
    printer.success(&format!("Generated delta pack {artifact_name}."));
    Ok(artifact_name)
}

/// Find an already-generated full pack in `pack_dir`; more than one is an
/// error because `info/packs` records exactly one.
fn existing_full_pack(pack_dir: &Path) -> Result<Option<String>> {
    if !pack_dir.exists() {
        return Ok(None);
    }
    let mut packs = Vec::new();
    for entry in
        fs::read_dir(pack_dir).with_context(|| format!("reading {}", pack_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("pack-") && name.ends_with(".pack") {
            packs.push(name.to_string());
        }
    }
    packs.sort();
    if packs.len() > 1 {
        bail!(
            "multiple full packs already exist in {}: {}",
            pack_dir.display(),
            packs.join(", "),
        );
    }
    Ok(packs.into_iter().next())
}

fn file_name_string(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("path has no UTF-8 filename: {}", path.display()))
}

fn install_immutable(source: &Path, destination: &Path, staging: &Path) -> Result<()> {
    if destination.exists() {
        if super::sha256_file(source)? != super::sha256_file(destination)? {
            bail!(
                "release artifact already exists with different bytes: {}",
                destination.display()
            );
        }
        return Ok(());
    }
    let temporary = tempfile::NamedTempFile::new_in(staging)?;
    fs::copy(source, temporary.path())?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(destination)?;
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

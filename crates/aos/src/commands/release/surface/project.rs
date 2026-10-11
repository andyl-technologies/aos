//! Projection of a captured release bundle into the machine surface layout.
//!
//! A bundle groups its members by producer (`registry/`, `cache/`, `packages/`,
//! `images/`, ...); consumers read a machine surface rooted at the registry.
//! The projection is derived from the signed manifest's artifact records:
//!
//! ```text
//! bundle member                          surface path
//! release-plan.json                      (control input, not published)
//! registry/<p>                           <p>
//! cache/nix-cache-info                   nix-cache-info
//! cache/narinfo/<h>.narinfo  (narinfo)   <h>.narinfo
//! NAR authenticated by a narinfo         the narinfo's URL (nar/<file-hash>.nar[.zst|.xz])
//! any other artifact at <p>              releases/<tuf role>/<version>/<p>
//! signed manifest envelope               releases/<tuf role>/<version>/release-manifest.json
//! ```
//!
//! Package, source, and closure NARs are published once at the URL their
//! signed narinfo names, so Nix substituters and qualification executors read
//! the same object. Several bundle members may project to one surface path
//! only when their bytes are identical (one store path planned under several
//! artifact ids).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::{ArtifactKind, ArtifactRecord, ArtifactRelation, BundlePath};
use aos_release::manifest::ReleaseManifestV1;
use aos_release::tuf::TufRole;
use aos_release::verify::CapturedFile;

use crate::commands::release::capture;

/// Bundle member that stays a control input and is never published.
const PLAN_MEMBER: &str = "release-plan.json";

/// Upper bound on one narinfo read while deriving NAR surface paths.
const MAX_NARINFO_BYTES: usize = 1024 * 1024;

/// One bundle member placed at its surface path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands::release) struct ProjectedObject {
    /// Bundle-relative source path.
    pub(in crate::commands::release) bundle_path: String,
    /// Surface-relative destination path.
    pub(in crate::commands::release) surface_path: String,
}

/// Complete bundle-to-surface mapping of one release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::commands::release) struct Projection {
    /// Every published member, one entry per distinct surface path.
    pub(in crate::commands::release) objects: Vec<ProjectedObject>,
    /// Surface path of each artifact id, including duplicates.
    pub(in crate::commands::release) by_artifact: BTreeMap<String, String>,
    /// Surface path of the signed manifest envelope.
    pub(in crate::commands::release) manifest_path: String,
}

/// A composed surface whose additions were verified independently.
///
/// `step publish --surface` admits only the exact verified additions (TUF
/// metadata, public manifest, release record); every other overlay file must
/// carry the bytes the projection already places at that path.
pub(in crate::commands::release) struct Overlay<'a> {
    /// Root of the composed surface tree.
    pub(in crate::commands::release) root: &'a Path,
    /// Exact identities of the verified additions.
    pub(in crate::commands::release) additions: &'a [CapturedFile],
}

/// A materialized surface tree that lives as long as this value.
pub(in crate::commands::release) struct ProjectedSurface {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl ProjectedSurface {
    /// Returns the surface root directory.
    pub(in crate::commands::release) fn root(&self) -> &Path {
        &self.root
    }
}

/// Returns the public path of a release's signed manifest envelope.
pub(in crate::commands::release) fn manifest_path(manifest: &ReleaseManifestV1) -> String {
    format!("{}/release-manifest.json", release_prefix(manifest))
}

fn release_prefix(manifest: &ReleaseManifestV1) -> String {
    format!(
        "releases/{}/{}",
        TufRole::for_release(manifest.release_class).as_str(),
        manifest.version
    )
}

/// Derives the projection from the manifest and the bundle's narinfo bytes.
///
/// # Errors
/// Returns an error for a narinfo that is unreadable or names a NAR whose
/// identity differs from the artifact it authenticates, a NAR without its
/// narinfo, or two different objects projected to one surface path.
pub(in crate::commands::release) fn plan_projection(
    bundle: &Path,
    manifest: &ReleaseManifestV1,
) -> Result<Projection> {
    let narinfo_urls = narinfo_urls(bundle, manifest)?;
    let by_id: BTreeMap<&str, &ArtifactRecord> = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    let prefix = release_prefix(manifest);
    let manifest_path = manifest_path(manifest);

    let mut by_artifact = BTreeMap::new();
    let mut by_surface: BTreeMap<String, &ArtifactRecord> = BTreeMap::new();
    let mut objects = Vec::new();
    for artifact in &manifest.artifacts {
        let Some(surface_path) = surface_path(artifact, &by_id, &narinfo_urls, &prefix)? else {
            continue;
        };
        BundlePath::parse(surface_path.clone())?;
        if surface_path == manifest_path {
            bail!(
                "release artifact {} collides with the manifest path",
                artifact.id
            );
        }
        by_artifact.insert(artifact.id.clone(), surface_path.clone());
        match by_surface.get(&surface_path) {
            Some(existing)
                if existing.sha256 == artifact.sha256
                    && existing.size_bytes == artifact.size_bytes => {}
            Some(existing) => bail!(
                "artifacts {} and {} project different bytes to {surface_path}",
                existing.id,
                artifact.id
            ),
            None => {
                by_surface.insert(surface_path.clone(), artifact);
                objects.push(ProjectedObject {
                    bundle_path: artifact.path.as_str().to_owned(),
                    surface_path,
                });
            }
        }
    }
    objects.sort_by(|left, right| left.surface_path.cmp(&right.surface_path));
    Ok(Projection {
        objects,
        by_artifact,
        manifest_path,
    })
}

/// Maps one artifact record to its surface path; `None` for control inputs.
fn surface_path(
    artifact: &ArtifactRecord,
    by_id: &BTreeMap<&str, &ArtifactRecord>,
    narinfo_urls: &BTreeMap<&str, NarLocation>,
    prefix: &str,
) -> Result<Option<String>> {
    let path = artifact.path.as_str();
    if path == PLAN_MEMBER {
        return Ok(None);
    }
    if let Some(rest) = path.strip_prefix("registry/") {
        return Ok(Some(rest.to_owned()));
    }
    if path == "cache/nix-cache-info" {
        return Ok(Some("nix-cache-info".to_owned()));
    }
    if artifact.kind == ArtifactKind::NarInfo {
        let name = path
            .strip_prefix("cache/narinfo/")
            .filter(|name| name.ends_with(".narinfo") && !name.contains('/'))
            .with_context(|| format!("narinfo {} is outside cache/narinfo/", artifact.id))?;
        return Ok(Some(name.to_owned()));
    }
    let authenticating = artifact
        .relationships
        .iter()
        .filter(|relationship| relationship.relation == ArtifactRelation::AuthenticatedBy)
        .filter(|relationship| {
            by_id
                .get(relationship.target.as_str())
                .is_some_and(|target| target.kind == ArtifactKind::NarInfo)
        })
        .map(|relationship| relationship.target.as_str())
        .collect::<Vec<_>>();
    match authenticating.as_slice() {
        [] => Ok(Some(format!("{prefix}/{path}"))),
        [narinfo] => {
            let location = narinfo_urls
                .get(narinfo)
                .with_context(|| format!("narinfo {narinfo} was not read"))?;
            if location.sha256 != artifact.sha256.hex() || location.size != artifact.size_bytes {
                bail!(
                    "NAR {} differs from the FileHash/FileSize of narinfo {narinfo}",
                    artifact.id
                );
            }
            Ok(Some(location.url.clone()))
        }
        _ => bail!(
            "NAR {} is authenticated by more than one narinfo",
            artifact.id
        ),
    }
}

/// Public location and compressed identity named by one narinfo.
struct NarLocation {
    url: String,
    sha256: String,
    size: u64,
}

/// Reads every narinfo member and returns the NAR location it names.
fn narinfo_urls<'a>(
    bundle: &Path,
    manifest: &'a ReleaseManifestV1,
) -> Result<BTreeMap<&'a str, NarLocation>> {
    let mut locations = BTreeMap::new();
    for artifact in manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::NarInfo)
    {
        let bytes = capture::control_file(&bundle.join(artifact.path.as_str()), "bundle narinfo")?;
        if bytes.len() > MAX_NARINFO_BYTES
            || aos_release::Sha256Digest::of_bytes(&bytes) != artifact.sha256
        {
            bail!("narinfo {} differs from its manifest record", artifact.id);
        }
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("narinfo {} is not UTF-8", artifact.id))?;
        let info = aos_core::nar::info::parse(text)
            .with_context(|| format!("parsing narinfo {}", artifact.id))?;
        if !info.url.starts_with("nar/") {
            bail!("narinfo {} URL is outside nar/", artifact.id);
        }
        BundlePath::parse(info.url.clone())?;
        let file_hash = info
            .file_hash
            .as_deref()
            .with_context(|| format!("narinfo {} has no FileHash", artifact.id))?;
        locations.insert(
            artifact.id.as_str(),
            NarLocation {
                url: info.url.clone(),
                sha256: aos_core::nar::cache::canonical_sha256_hex(file_hash)?,
                size: info
                    .file_size
                    .with_context(|| format!("narinfo {} has no FileSize", artifact.id))?,
            },
        );
    }
    Ok(locations)
}

/// Materializes the projected surface from a second, compared bundle capture.
///
/// The bundle is copied into a private snapshot and compared with the
/// verified capture before any member moves, so source mutation between
/// verification and publication cannot change the published bytes. `overlay`
/// adds a composed surface (TUF metadata, release record): each overlay file
/// is either one exact verified addition or identical to the projected object
/// at its path. The overlay is snapshotted too, so an addition that changed
/// after verification is rejected.
///
/// # Errors
/// Returns an error when the bundle changed, a member is missing, the
/// manifest path collides, or the overlay carries an unverified object,
/// lacks a verified addition, or disagrees with the projection.
pub(in crate::commands::release) fn materialize(
    bundle: &Path,
    verified_files: &[CapturedFile],
    projection: &Projection,
    manifest_bytes: &[u8],
    overlay: Option<&Overlay<'_>>,
) -> Result<ProjectedSurface> {
    let temporary = tempfile::Builder::new()
        .prefix("aos-release-surface-")
        .tempdir()?;
    let snapshot = temporary.path().join("bundle");
    let mut copied = capture::copy_ephemeral_surface_tree(bundle, &snapshot)?;
    copied.retain(|file| file.path.as_str() != "release-manifest.json");
    if copied != verified_files {
        bail!("release bundle changed between verification and publication capture");
    }

    let root = temporary.path().join("surface");
    fs::create_dir(&root)?;
    for object in &projection.objects {
        let source = snapshot.join(&object.bundle_path);
        let destination = root.join(&object.surface_path);
        create_parent(&destination)?;
        fs::rename(&source, &destination).with_context(|| {
            format!(
                "projecting {} to {}",
                object.bundle_path, object.surface_path
            )
        })?;
    }
    write_new(&root.join(&projection.manifest_path), manifest_bytes)?;

    if let Some(overlay) = overlay {
        let copy = temporary.path().join("overlay");
        let files = capture::copy_ephemeral_surface_tree(overlay.root, &copy)?;
        admit_overlay(&copy, &root, &files, overlay.additions)?;
    }
    Ok(ProjectedSurface {
        _temporary: temporary,
        root,
    })
}

/// Installs the exact verified additions and checks every other overlay file.
fn admit_overlay(
    overlay: &Path,
    root: &Path,
    files: &[CapturedFile],
    additions: &[CapturedFile],
) -> Result<()> {
    for addition in additions {
        match files.iter().find(|file| file.path == addition.path) {
            Some(file) if file == addition => {}
            Some(_) => bail!(
                "composed surface object {} changed after verification",
                addition.path.as_str()
            ),
            None => bail!(
                "composed surface lost its verified object {}",
                addition.path.as_str()
            ),
        }
    }
    for file in files {
        let relative = file.path.as_str();
        let verified = additions.iter().any(|addition| addition.path == file.path);
        if !verified && !root.join(relative).exists() {
            bail!("composed surface contains an unverified object {relative}");
        }
        merge_overlay_file(overlay, root, relative)?;
    }
    Ok(())
}

fn merge_overlay_file(overlay: &Path, root: &Path, relative: &str) -> Result<()> {
    let source = overlay.join(relative);
    let destination = root.join(relative);
    if destination.exists() {
        if fs::read(&source)? != fs::read(&destination)? {
            bail!("composed surface disagrees with the projected bundle at {relative}");
        }
        return Ok(());
    }
    create_parent(&destination)?;
    fs::rename(&source, &destination)
        .with_context(|| format!("installing composed surface object {relative}"))
}

fn create_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("projected surface path has no parent")?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    create_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("release bundle collides with {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_release::artifact::{ArtifactRelationship, Compression};
    use aos_release::digest::Sha256Digest;

    use super::*;

    fn record(id: &str, kind: ArtifactKind, path: &str, bytes: &[u8]) -> ArtifactRecord {
        ArtifactRecord {
            id: id.to_owned(),
            kind,
            platform: None,
            system_variant: None,
            image: None,
            path: BundlePath::parse(path).unwrap_or_else(|error| panic!("{error}")),
            size_bytes: bytes.len() as u64,
            sha256: Sha256Digest::of_bytes(bytes),
            media_type: "application/octet-stream".to_owned(),
            compression: Compression::None,
            derivation: None,
            output: None,
            store_path: None,
            nar_hash: None,
            relationships: Vec::new(),
        }
    }

    fn location(bytes: &[u8]) -> NarLocation {
        NarLocation {
            url: "nar/abc.nar.zst".to_owned(),
            sha256: Sha256Digest::of_bytes(bytes).hex(),
            size: bytes.len() as u64,
        }
    }

    #[test]
    fn artifact_records_select_their_surface_paths() -> Result<()> {
        let narinfo = record(
            "narinfo/abc",
            ArtifactKind::NarInfo,
            "cache/narinfo/abc.narinfo",
            b"i",
        );
        let mut nar = record(
            "package/aos",
            ArtifactKind::PackageNar,
            "packages/aos.nar.zst",
            b"nar",
        );
        nar.relationships.push(ArtifactRelationship {
            relation: ArtifactRelation::AuthenticatedBy,
            target: "narinfo/abc".to_owned(),
        });
        let registry = record(
            "registry/head",
            ArtifactKind::RegistryObject,
            "registry/HEAD",
            b"h",
        );
        let info = record(
            "cache/configuration",
            ArtifactKind::RegistryObject,
            "cache/nix-cache-info",
            b"c",
        );
        let image = record(
            "image/disk",
            ArtifactKind::Provenance,
            "images/aos/x86_64-linux/disk",
            b"d",
        );
        let plan = record(
            "control/plan",
            ArtifactKind::Provenance,
            "release-plan.json",
            b"p",
        );
        let artifacts = [narinfo, nar, registry, info, image, plan];
        let by_id: BTreeMap<_, _> = artifacts.iter().map(|a| (a.id.as_str(), a)).collect();
        let urls = BTreeMap::from([("narinfo/abc", location(b"nar"))]);
        let prefix = "releases/edge/2026.9.0-dev.20260929.1";
        let map = |index: usize| surface_path(&artifacts[index], &by_id, &urls, prefix);

        assert_eq!(map(0)?.as_deref(), Some("abc.narinfo"));
        assert_eq!(map(1)?.as_deref(), Some("nar/abc.nar.zst"));
        assert_eq!(map(2)?.as_deref(), Some("HEAD"));
        assert_eq!(map(3)?.as_deref(), Some("nix-cache-info"));
        assert_eq!(
            map(4)?.as_deref(),
            Some("releases/edge/2026.9.0-dev.20260929.1/images/aos/x86_64-linux/disk")
        );
        assert_eq!(map(5)?, None);
        Ok(())
    }

    #[test]
    fn nar_identity_must_match_its_narinfo() {
        let narinfo = record(
            "narinfo/abc",
            ArtifactKind::NarInfo,
            "cache/narinfo/abc.narinfo",
            b"i",
        );
        let mut nar = record(
            "package/aos",
            ArtifactKind::PackageNar,
            "packages/aos.nar.zst",
            b"nar",
        );
        nar.relationships.push(ArtifactRelationship {
            relation: ArtifactRelation::AuthenticatedBy,
            target: "narinfo/abc".to_owned(),
        });
        let artifacts = [narinfo, nar];
        let by_id: BTreeMap<_, _> = artifacts.iter().map(|a| (a.id.as_str(), a)).collect();
        let urls = BTreeMap::from([("narinfo/abc", location(b"other"))]);
        assert!(surface_path(&artifacts[1], &by_id, &urls, "releases/edge/1").is_err());
    }

    #[test]
    fn overlay_must_agree_with_projected_objects() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let overlay = temp.path().join("overlay");
        let root = temp.path().join("root");
        fs::create_dir_all(overlay.join("tuf"))?;
        fs::create_dir_all(&root)?;
        fs::write(overlay.join("tuf/timestamp.json"), b"ts")?;
        fs::write(overlay.join("HEAD"), b"head")?;
        fs::write(root.join("HEAD"), b"head")?;
        merge_overlay_file(&overlay, &root, "tuf/timestamp.json")?;
        merge_overlay_file(&overlay, &root, "HEAD")?;
        assert_eq!(fs::read(root.join("tuf/timestamp.json"))?, b"ts");

        fs::write(overlay.join("other"), b"one")?;
        fs::write(root.join("other"), b"two")?;
        assert!(merge_overlay_file(&overlay, &root, "other").is_err());
        Ok(())
    }

    #[test]
    fn overlay_admits_only_exact_verified_additions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let overlay = temp.path().join("overlay");
        let root = temp.path().join("root");
        fs::create_dir_all(overlay.join("tuf"))?;
        fs::create_dir_all(&root)?;
        fs::write(overlay.join("tuf/7.snapshot.json"), b"snapshot")?;
        fs::write(overlay.join("HEAD"), b"head")?;
        fs::write(root.join("HEAD"), b"head")?;
        let verified = |bytes: &[u8]| -> Result<CapturedFile> {
            Ok(CapturedFile {
                path: BundlePath::parse("tuf/7.snapshot.json")?,
                size_bytes: bytes.len() as u64,
                sha256: Sha256Digest::of_bytes(bytes),
            })
        };
        let files = |dir: &Path| capture::copy_ephemeral_surface_tree(dir, &temp.path().join("c"));

        // An identical projected object and an exact addition are admitted.
        let captured = files(&overlay)?;
        fs::remove_dir_all(temp.path().join("c"))?;
        admit_overlay(&overlay, &root, &captured, &[verified(b"snapshot")?])?;
        assert_eq!(fs::read(root.join("tuf/7.snapshot.json"))?, b"snapshot");

        // An addition whose bytes changed after verification is rejected.
        let fresh = temp.path().join("fresh");
        fs::create_dir_all(&fresh)?;
        assert!(admit_overlay(&overlay, &fresh, &captured, &[verified(b"other")?]).is_err());

        // An object that is neither verified nor projected is rejected.
        fs::write(overlay.join("tuf/7.snapshot.json"), b"snapshot")?;
        fs::write(overlay.join("tuf/unreviewed.json"), b"extra")?;
        let captured = files(&overlay)?;
        let fresh = temp.path().join("fresh-2");
        fs::create_dir_all(&fresh)?;
        fs::write(fresh.join("HEAD"), b"head")?;
        assert!(admit_overlay(&overlay, &fresh, &captured, &[verified(b"snapshot")?]).is_err());
        Ok(())
    }
}

//! Anonymous objects and retained predecessor inputs for qualification cases.
//!
//! Executors download every object a case exercises from the surface under
//! test, at the object's projected surface path, and verify its declared
//! length and SHA-256 before use. Image update cases additionally receive an
//! inventory of exact objects from the locally retained, offline-verified
//! predecessor bundle.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::artifact::ArtifactRecord;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::{
    QualificationObject, QualificationRetainedBundle, QualificationRetainedObject,
    QualificationTrustedKey,
};
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::qualification_evidence::QualificationPredecessor;
use aos_release::signing::TrustedEd25519Key;
use url::Url;

use super::capture;
use super::surface::project::Projection;

/// Control object id of the signed manifest envelope in executor requests.
const MANIFEST_ENVELOPE_ID: &str = "control/release-manifest-envelope";

/// A verified predecessor bundle retained on the coordinator.
pub(super) struct RetainedPredecessor {
    root: PathBuf,
    manifest_bytes: Vec<u8>,
    manifest: ManifestEnvelopeV1,
    trusted_keys: Vec<TrustedEd25519Key>,
}

/// Resolves the anonymous URLs of every object a case exercises.
///
/// Objects are served at their projected surface paths below the read-back
/// `base` (`<hub>/<registry>/` for a Hub, the origin root for a static
/// surface), so executors download exactly what consumers see.
pub(super) fn public_objects(
    base: &Url,
    projection: &Projection,
    manifest: &ManifestEnvelopeV1,
    manifest_bytes: &[u8],
    subjects: &[String],
) -> Result<Vec<QualificationObject>> {
    let subjects = subjects.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let artifact_ids = related_artifact_ids(&manifest.payload.artifacts, &subjects)?;
    if artifact_ids.contains(MANIFEST_ENVELOPE_ID) {
        bail!("manifest artifact id collides with the qualification control object");
    }
    let mut objects =
        manifest
            .payload
            .artifacts
            .iter()
            .filter(|artifact| artifact_ids.contains(artifact.id.as_str()))
            .map(|artifact| {
                Ok(QualificationObject {
                    artifact_id: artifact.id.clone(),
                    url: base
                        .join(projection.by_artifact.get(&artifact.id).with_context(|| {
                            format!("artifact {} is not published", artifact.id)
                        })?)?
                        .to_string(),
                    size_bytes: artifact.size_bytes,
                    sha256: artifact.sha256,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    let resolved = objects
        .iter()
        .map(|object| object.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    if resolved.len() != artifact_ids.len()
        || !artifact_ids.iter().all(|id| resolved.contains(id.as_str()))
    {
        bail!("qualification artifact graph does not resolve to the signed release artifacts");
    }
    objects.push(QualificationObject {
        artifact_id: MANIFEST_ENVELOPE_ID.to_owned(),
        url: base.join(&projection.manifest_path)?.to_string(),
        size_bytes: u64::try_from(manifest_bytes.len())?,
        sha256: Sha256Digest::of_bytes(manifest_bytes),
    });
    objects.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(objects)
}

/// Captures and verifies the predecessor bundle frozen in the plan.
pub(super) fn retained_predecessor(
    path: &Path,
    expected: &QualificationPredecessor,
    trusted_keys: &[TrustedEd25519Key],
) -> Result<RetainedPredecessor> {
    if !path.is_absolute() {
        bail!("qualification predecessor bundle path must be absolute");
    }
    let captured = capture::bundle(path)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        trusted_keys,
    )?;
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "predecessor release manifest")?;
    if manifest.payload.registry != expected.registry
        || summary.release_id != expected.release_id
        || summary.manifest_digest != expected.manifest_digest
    {
        bail!("retained predecessor bundle differs from the frozen release plan");
    }
    Ok(RetainedPredecessor {
        root: path.to_path_buf(),
        manifest_bytes: captured.manifest_bytes,
        manifest,
        trusted_keys: trusted_keys.to_vec(),
    })
}

/// Lists the retained predecessor objects an update case exercises.
pub(super) fn predecessor_bundle(
    retained: Option<&RetainedPredecessor>,
    case: &aos_release::qualification_evidence::QualificationCase,
) -> Result<Option<QualificationRetainedBundle>> {
    let Some(expected) = case.predecessor.as_ref() else {
        return Ok(None);
    };
    let retained = retained.context("qualification update case lacks a retained predecessor")?;
    if retained.manifest.payload.registry != expected.registry
        || retained.manifest.payload.release_id != expected.release_id
        || retained.manifest.payload_digest != expected.manifest_digest
    {
        bail!("qualification case differs from the verified predecessor bundle");
    }

    let subjects = case
        .subjects
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let artifact_ids = related_artifact_ids(&retained.manifest.payload.artifacts, &subjects)?;
    if artifact_ids.contains(MANIFEST_ENVELOPE_ID) {
        bail!("predecessor artifact id collides with the qualification control object");
    }
    let mut objects = retained
        .manifest
        .payload
        .artifacts
        .iter()
        .filter(|artifact| artifact_ids.contains(artifact.id.as_str()))
        .map(|artifact| {
            Ok(QualificationRetainedObject {
                artifact_id: artifact.id.clone(),
                source_path: retained
                    .root
                    .join(artifact.path.as_str())
                    .into_os_string()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("predecessor object path is not UTF-8"))?,
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    objects.push(QualificationRetainedObject {
        artifact_id: MANIFEST_ENVELOPE_ID.to_owned(),
        source_path: retained
            .root
            .join("release-manifest.json")
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("predecessor manifest path is not UTF-8"))?,
        size_bytes: u64::try_from(retained.manifest_bytes.len())?,
        sha256: Sha256Digest::of_bytes(&retained.manifest_bytes),
    });
    objects.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let mut trusted_keys = retained
        .trusted_keys
        .iter()
        .map(|key| QualificationTrustedKey {
            key_id: key.key_id.clone(),
            public_key_hex: hex::encode(key.public_key),
        })
        .collect::<Vec<_>>();
    trusted_keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    Ok(Some(QualificationRetainedBundle {
        bundle_path: retained
            .root
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("predecessor bundle path is not UTF-8"))?,
        objects,
        trusted_keys,
    }))
}

/// Closes a subject set over manifest relationships.
fn related_artifact_ids(
    artifacts: &[ArtifactRecord],
    subjects: &BTreeSet<&str>,
) -> Result<BTreeSet<String>> {
    let by_id = artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut pending = subjects
        .iter()
        .map(|subject| (*subject).to_owned())
        .collect::<Vec<_>>();
    let mut related = BTreeSet::new();

    while let Some(id) = pending.pop() {
        if !related.insert(id.clone()) {
            continue;
        }
        let artifact = by_id
            .get(id.as_str())
            .with_context(|| format!("qualification subject or relationship {id} is absent"))?;
        pending.extend(
            artifact
                .relationships
                .iter()
                .map(|relationship| relationship.target.clone()),
        );
    }

    Ok(related)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_release::artifact::{
        ArtifactKind, ArtifactRecord, ArtifactRelation, ArtifactRelationship, BundlePath,
        Compression,
    };
    use aos_release::platform::Platform;

    fn artifact(id: &str, targets: &[&str]) -> ArtifactRecord {
        ArtifactRecord {
            id: id.to_owned(),
            kind: ArtifactKind::PackageNar,
            platform: Some(Platform::X86_64Linux),
            system_variant: None,
            image: None,
            path: BundlePath::parse(format!("objects/{id}")).unwrap(),
            size_bytes: 1,
            sha256: Sha256Digest::of_bytes(id.as_bytes()),
            media_type: "application/x-nix-nar".to_owned(),
            compression: Compression::None,
            derivation: None,
            output: None,
            store_path: None,
            nar_hash: None,
            relationships: targets
                .iter()
                .map(|target| ArtifactRelationship {
                    relation: ArtifactRelation::Contains,
                    target: (*target).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn qualification_objects_close_transitive_manifest_relationships() -> Result<()> {
        let artifacts = [
            artifact("package/root", &["package/dependency", "source/root"]),
            artifact("package/dependency", &["narinfo/dependency"]),
            artifact("narinfo/dependency", &[]),
            artifact("source/root", &[]),
            artifact("unrelated", &[]),
        ];
        let subjects = BTreeSet::from(["package/root"]);

        assert_eq!(
            related_artifact_ids(&artifacts, &subjects)?,
            BTreeSet::from([
                "narinfo/dependency".to_owned(),
                "package/dependency".to_owned(),
                "package/root".to_owned(),
                "source/root".to_owned(),
            ])
        );
        Ok(())
    }
}

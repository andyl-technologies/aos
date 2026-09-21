//! Finalized Linux image-set validation and artifact projection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Component;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use aos_core::nar::cache::canonical_sha256_hex;
use aos_core::nix::NixRunner;
use aos_image_finalizer::assembly::UnsignedImageAssemblyV1;
use aos_image_finalizer::capture::capture_unsigned_assembly;
use aos_image_finalizer::result::{FinalizedImageKind, FinalizedImageSetV1};
use aos_release::artifact::{ArtifactKind, ArtifactRelation, ArtifactRelationship, Compression};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedArtifact, ReleasePlanV1};
use aos_release::platform::{MatrixCell, Platform};

use super::{ArtifactAttributes, PayloadBuilder};

pub(super) fn assemble(
    roots: &[PathBuf],
    plan: &ReleasePlanV1,
    nix: &NixRunner,
    payload: &mut PayloadBuilder,
) -> Result<()> {
    let expected_cells = plan
        .images
        .iter()
        .flat_map(|image| {
            image.platforms.iter().filter_map(move |cell| {
                matches!(cell.decision, MatrixCell::Artifact { .. })
                    .then_some((image.system_variant.as_str(), cell.platform))
            })
        })
        .collect::<BTreeSet<_>>();
    if roots.len() != expected_cells.len() {
        bail!("finalized image-set count differs from the planned image matrix");
    }
    let nar_hashes = planned_nar_hashes(plan, nix)?;
    let mut tool_nar_hashes = BTreeMap::new();
    let mut observed = BTreeSet::new();

    for root in roots {
        let assembly_bytes =
            super::read_canonical(&root.join("unsigned-image-assembly.json"), "image assembly")?;
        let assembly: UnsignedImageAssemblyV1 =
            canonical::from_slice(&assembly_bytes, "image assembly")?;
        if assembly.release_id != plan.release_id || assembly.version != plan.version {
            bail!("finalized image assembly differs from the release plan identity");
        }
        let set_bytes = super::read_canonical(
            &root.join("finalized-image-set.json"),
            "finalized image set",
        )?;
        let set: FinalizedImageSetV1 = canonical::from_slice(&set_bytes, "finalized image set")?;
        set.validate(&assembly)?;
        let key = (set.system_variant.as_str(), set.platform);
        if !expected_cells.contains(&key)
            || !observed.insert((set.system_variant.clone(), set.platform))
        {
            bail!("finalized image set is unplanned or duplicated");
        }

        let planned = planned_cell(plan, &set.system_variant, set.platform)?;
        let assembly_root = planned_assembly_root(planned)?;
        let recaptured =
            capture_unsigned_assembly(assembly_root, &plan.release_id, |executable| {
                tool_owner_nar_hash(executable, nix, &mut tool_nar_hashes)
            })?;
        if recaptured != assembly {
            bail!("finalized image control differs from its planned Nix assembly");
        }
        if planned.len() != set.artifacts.len() {
            bail!(
                "finalized {} {} artifact count differs from its plan",
                set.system_variant,
                set.platform
            );
        }
        let logical_id = planned
            .iter()
            .find(|artifact| local_id(&artifact.id) == "logical-disk")
            .map(|artifact| artifact.id.clone())
            .context("planned image cell lacks logical-disk artifact")?;
        let provenance_prefix = format!("provenance/image/{}/{}", set.system_variant, set.platform);
        let assembly_id = format!("{provenance_prefix}/unsigned-assembly");
        let finalized_id = format!("{provenance_prefix}/finalized-set");
        payload.copy(
            &root.join("unsigned-image-assembly.json"),
            assembly_id.clone(),
            ArtifactKind::Provenance,
            format!(
                "evidence/images/{}/{}/unsigned-image-assembly.json",
                set.system_variant, set.platform
            ),
            ArtifactAttributes {
                platform: Some(set.platform),
                expected: Some((
                    u64::try_from(assembly_bytes.len())?,
                    Sha256Digest::of_bytes(&assembly_bytes),
                )),
                ..ArtifactAttributes::plain("application/vnd.aos.image.unsigned-assembly.v2+json")
            },
        )?;
        payload.copy(
            &root.join("finalized-image-set.json"),
            finalized_id.clone(),
            ArtifactKind::Provenance,
            format!(
                "evidence/images/{}/{}/finalized-image-set.json",
                set.system_variant, set.platform
            ),
            ArtifactAttributes {
                platform: Some(set.platform),
                relationships: vec![ArtifactRelationship {
                    relation: ArtifactRelation::Finalizes,
                    target: assembly_id,
                }],
                expected: Some((
                    u64::try_from(set_bytes.len())?,
                    Sha256Digest::of_bytes(&set_bytes),
                )),
                ..ArtifactAttributes::plain("application/vnd.aos.image.finalized-set.v1+json")
            },
        )?;
        let mut matched = BTreeSet::new();
        for artifact in &set.artifacts {
            let planned = planned
                .iter()
                .find(|planned| local_id(&planned.id) == artifact.id)
                .with_context(|| {
                    format!(
                        "finalized image artifact {} has no exact planned id suffix",
                        artifact.id
                    )
                })?;
            if !matched.insert(planned.id.as_str()) {
                bail!("finalized image artifacts repeat planned id {}", planned.id);
            }
            let mut relationships = if matches!(
                artifact.kind,
                FinalizedImageKind::Raw
                    | FinalizedImageKind::Qcow2
                    | FinalizedImageKind::Vmdk
                    | FinalizedImageKind::Vhd
            ) {
                vec![ArtifactRelationship {
                    relation: ArtifactRelation::Encodes,
                    target: logical_id.clone(),
                }]
            } else {
                Vec::new()
            };
            relationships.push(ArtifactRelationship {
                relation: ArtifactRelation::Documents,
                target: finalized_id.clone(),
            });
            let (derivation, output, store_path, nar_hash) = nix_identity(planned, &nar_hashes)?;
            let attributes = ArtifactAttributes {
                platform: Some(set.platform),
                system_variant: Some(set.system_variant.clone()),
                media_type: media_type(artifact.kind).to_owned(),
                compression: compression(artifact.kind),
                derivation,
                output,
                store_path,
                nar_hash,
                relationships,
                expected: Some((artifact.size_bytes, artifact.sha256)),
            };
            payload.copy(
                &root.join(artifact.path.as_str()),
                planned.id.clone(),
                artifact_kind(artifact.kind),
                format!(
                    "images/{}/{}/{}",
                    set.system_variant, set.platform, artifact.id
                ),
                attributes,
            )?;
        }
    }
    if observed.len() != expected_cells.len() {
        bail!("finalized image sets do not cover the complete planned matrix");
    }
    Ok(())
}

fn planned_assembly_root(planned: &[PlannedArtifact]) -> Result<&Path> {
    planned
        .iter()
        .find(|artifact| local_id(&artifact.id) == "logical-disk")
        .and_then(|artifact| artifact.store_path.as_deref())
        .map(Path::new)
        .context("planned logical disk lacks its unsigned-assembly store identity")
}

fn tool_owner_nar_hash(
    executable: &str,
    nix: &NixRunner,
    cache: &mut BTreeMap<PathBuf, String>,
) -> Result<String> {
    let relative = Path::new(executable)
        .strip_prefix("/nix/store")
        .context("image tool executable is outside the Nix store")?;
    let Some(Component::Normal(owner)) = relative.components().next() else {
        bail!("image tool executable has no Nix store owner");
    };
    let owner = Path::new("/nix/store").join(owner);
    if let Some(hash) = cache.get(&owner) {
        return Ok(hash.clone());
    }
    let value = nix.path_info_json(std::slice::from_ref(&owner))?;
    let text = owner.to_str().context("image tool owner is not UTF-8")?;
    let hash = value
        .get(text)
        .and_then(|entry| entry.get("narHash"))
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("Nix omitted image tool NAR hash for {text}"))?
        .to_owned();
    cache.insert(owner, hash.clone());
    Ok(hash)
}

fn planned_cell<'a>(
    plan: &'a ReleasePlanV1,
    variant: &str,
    platform: Platform,
) -> Result<&'a [PlannedArtifact]> {
    let image = plan
        .images
        .iter()
        .find(|image| image.system_variant == variant)
        .context("finalized image variant is absent from the plan")?;
    let cell = image
        .platforms
        .iter()
        .find(|cell| cell.platform == platform)
        .context("finalized image platform is absent from the plan")?;
    match &cell.decision {
        MatrixCell::Artifact { artifact } => Ok(&artifact.artifacts),
        _ => bail!("finalized image resolves a non-artifact plan cell"),
    }
}

fn planned_nar_hashes(
    plan: &ReleasePlanV1,
    nix: &NixRunner,
) -> Result<BTreeMap<String, Sha256Digest>> {
    let paths = plan
        .images
        .iter()
        .flat_map(|image| &image.platforms)
        .filter_map(|cell| match &cell.decision {
            MatrixCell::Artifact { artifact } => Some(&artifact.artifacts),
            _ => None,
        })
        .flatten()
        .filter_map(|artifact| artifact.store_path.as_deref())
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(BTreeMap::new());
    }
    let value = nix.path_info_json(&paths)?;
    let object = value
        .as_object()
        .context("image Nix path-info response is not an object")?;
    paths
        .into_iter()
        .map(|path| {
            let text = path.to_str().context("image store path is not UTF-8")?;
            let hash = object
                .get(text)
                .and_then(|entry| entry.get("narHash"))
                .and_then(serde_json::Value::as_str)
                .with_context(|| format!("Nix omitted image NAR hash for {text}"))?;
            let digest = Sha256Digest::parse(&format!("sha256:{}", canonical_sha256_hex(hash)?))?;
            Ok((text.to_owned(), digest))
        })
        .collect()
}

fn nix_identity(
    artifact: &PlannedArtifact,
    nar_hashes: &BTreeMap<String, Sha256Digest>,
) -> Result<(
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Sha256Digest>,
)> {
    match (&artifact.derivation, &artifact.output, &artifact.store_path) {
        (Some(derivation), Some(output), Some(store_path)) => Ok((
            Some(derivation.clone()),
            Some(output.clone()),
            Some(store_path.clone()),
            Some(
                *nar_hashes
                    .get(store_path)
                    .with_context(|| format!("missing image NAR hash for {store_path}"))?,
            ),
        )),
        (None, None, None) => Ok((None, None, None, None)),
        _ => bail!("planned image artifact has an incomplete Nix identity"),
    }
}

fn local_id(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

const fn artifact_kind(kind: FinalizedImageKind) -> ArtifactKind {
    match kind {
        FinalizedImageKind::LogicalDisk => ArtifactKind::LogicalDisk,
        FinalizedImageKind::Raw => ArtifactKind::RawImage,
        FinalizedImageKind::Qcow2 => ArtifactKind::Qcow2Image,
        FinalizedImageKind::Vmdk => ArtifactKind::VmdkImage,
        FinalizedImageKind::Vhd => ArtifactKind::VhdImage,
        FinalizedImageKind::UkiA | FinalizedImageKind::UkiB => ArtifactKind::Uki,
        FinalizedImageKind::RecoveryUkiA | FinalizedImageKind::RecoveryUkiB => {
            ArtifactKind::RecoveryUki
        }
        FinalizedImageKind::RecoveryBundle => ArtifactKind::RecoveryBundle,
        FinalizedImageKind::Metadata => ArtifactKind::ImageMetadata,
    }
}

const fn compression(kind: FinalizedImageKind) -> Compression {
    match kind {
        FinalizedImageKind::Raw | FinalizedImageKind::RecoveryBundle => Compression::Zstd,
        _ => Compression::None,
    }
}

const fn media_type(kind: FinalizedImageKind) -> &'static str {
    match kind {
        FinalizedImageKind::LogicalDisk => "application/vnd.aos.logical-disk.raw",
        FinalizedImageKind::Raw => "application/vnd.aos.disk-image.raw+zstd",
        FinalizedImageKind::Qcow2 => "application/vnd.aos.disk-image.qcow2",
        FinalizedImageKind::Vmdk => "application/vnd.vmware.vmdk",
        FinalizedImageKind::Vhd => "application/vnd.microsoft.vhd",
        FinalizedImageKind::UkiA
        | FinalizedImageKind::UkiB
        | FinalizedImageKind::RecoveryUkiA
        | FinalizedImageKind::RecoveryUkiB => "application/vnd.aos.uki",
        FinalizedImageKind::RecoveryBundle => "application/vnd.aos.recovery-bundle.v1+tar+zstd",
        FinalizedImageKind::Metadata => "application/vnd.aos.image-metadata.v1+json",
    }
}

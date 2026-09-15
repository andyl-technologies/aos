//! Finalized OCI graph validation and projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use aos_oci_types::{
    ContainerRelease, ContainerSignatureInput, Descriptor, ImageIndex, ImageManifest, MediaType,
    CONTAINER_RELEASE_SIDECAR_PATH,
};
use aos_release::artifact::{ArtifactKind, ArtifactRelation, ArtifactRelationship, Compression};
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::platform::Platform;

use super::{ArtifactAttributes, PayloadBuilder};

struct GraphNode {
    descriptor: Descriptor,
    source: PathBuf,
    children: Vec<String>,
}

pub(super) fn assemble(
    root: &Path,
    registry: &Path,
    plan: &ReleasePlanV1,
    payload: &mut PayloadBuilder,
) -> Result<()> {
    let release_path = root.join("container-release.json");
    let release_bytes = super::super::capture::control_file(&release_path, "container release")?;
    let release = ContainerRelease::from_canonical_json(&release_bytes)
        .map_err(anyhow::Error::msg)
        .context("validating finalized container release")?;
    let input_path = root.join("signature-input.json");
    let input_bytes =
        super::super::capture::control_file(&input_path, "container signature input")?;
    let input = ContainerSignatureInput::from_canonical_json(&input_bytes)
        .map_err(anyhow::Error::msg)
        .context("validating finalized container signature input")?;
    input
        .validate_final_release(&release)
        .map_err(anyhow::Error::msg)
        .context("binding container release to its signature input")?;
    validate_plan_binding(&release, plan)?;
    let registry_bytes = super::super::capture::control_file(
        &registry.join(CONTAINER_RELEASE_SIDECAR_PATH),
        "registry container sidecar",
    )?;
    if registry_bytes != release_bytes {
        bail!("finalized container release differs from the registry sidecar");
    }

    let layout = root.join("layout");
    let roots = [
        &release.oci.index,
        &release.nix.closure,
        &release.evidence.sbom,
        &release.evidence.source,
        &release.evidence.license,
        &release.evidence.provenance,
        &release.evidence.signature,
    ];
    let mut graph = BTreeMap::new();
    for descriptor in roots {
        visit(&layout, descriptor, &mut graph)?;
    }
    require_exact_blob_set(&layout, &graph)?;

    let platform_manifests = release
        .oci
        .platform_manifests
        .iter()
        .map(|descriptor| {
            let platform = descriptor
                .platform
                .as_ref()
                .context("container platform manifest lacks a platform")?;
            Ok((descriptor.digest.to_string(), release_platform(platform)?))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let index_digest = release.oci.index.digest.to_string();
    let ids = graph
        .iter()
        .map(|(digest, node)| {
            let id = if digest == &index_digest {
                "container/index".to_owned()
            } else if let Some(platform) = platform_manifests.get(digest) {
                format!("container/manifest/{platform}")
            } else {
                format!("container/blob/{}", node.descriptor.digest.encoded())
            };
            (digest.clone(), id)
        })
        .collect::<BTreeMap<_, _>>();

    for (digest, node) in &graph {
        let platform = platform_manifests.get(digest).copied();
        let kind = if digest == &index_digest {
            ArtifactKind::OciIndex
        } else if node.descriptor.media_type.is_image_manifest() {
            ArtifactKind::OciManifest
        } else {
            ArtifactKind::OciBlob
        };
        let relationships =
            node.children
                .iter()
                .map(|child| {
                    Ok(ArtifactRelationship {
                        relation: ArtifactRelation::Contains,
                        target: ids.get(child).cloned().with_context(|| {
                            format!("OCI child {child} is absent from the graph")
                        })?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        let expected = (
            node.descriptor.size,
            Sha256Digest::parse(&node.descriptor.digest.to_string())?,
        );
        let attributes = ArtifactAttributes {
            platform,
            media_type: node.descriptor.media_type.to_string(),
            compression: descriptor_compression(node.descriptor.media_type),
            relationships,
            expected: Some(expected),
            ..ArtifactAttributes::plain(node.descriptor.media_type.as_str())
        };
        payload.copy(
            &node.source,
            ids[digest].clone(),
            kind,
            format!("oci/blobs/sha256/{}", node.descriptor.digest.encoded()),
            attributes,
        )?;
    }

    let release_attributes = ArtifactAttributes {
        relationships: vec![ArtifactRelationship {
            relation: ArtifactRelation::Contains,
            target: ids[&index_digest].clone(),
        }],
        ..ArtifactAttributes::plain("application/vnd.aos.container-release.v1+json")
    };
    payload.copy(
        &release_path,
        "provenance/container-release".to_owned(),
        ArtifactKind::Provenance,
        "oci/container-release.json".to_owned(),
        ArtifactAttributes {
            expected: Some((
                u64::try_from(release_bytes.len())?,
                Sha256Digest::of_bytes(&release_bytes),
            )),
            ..release_attributes
        },
    )?;
    payload.copy(
        &input_path,
        "provenance/container-signature-input".to_owned(),
        ArtifactKind::Provenance,
        "oci/signature-input.json".to_owned(),
        ArtifactAttributes::exact(
            "application/vnd.aos.container.signature-input.v1+json",
            &input_bytes,
        )?,
    )?;
    Ok(())
}

pub(super) fn require_absent(registry: &Path) -> Result<()> {
    let path = registry.join(CONTAINER_RELEASE_SIDECAR_PATH);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("checking registry container sidecar {}", path.display())),
        Ok(_) => bail!("finalized registry contains an unassembled container sidecar"),
    }
}

fn validate_plan_binding(release: &ContainerRelease, plan: &ReleasePlanV1) -> Result<()> {
    if release.identity.release != plan.version {
        bail!("container release identity differs from the release plan");
    }
    let publication = plan
        .packages
        .iter()
        .find(|package| package.name == release.identity.package)
        .and_then(|package| package.publication.as_ref())
        .context("container package is not publishable in the release plan")?;
    if publication.version != release.identity.package_version {
        bail!("container package version differs from the release plan");
    }

    let attribute = &release.nix.definition.attribute;
    let variant = attribute
        .strip_prefix("systems.")
        .and_then(|rest| rest.strip_suffix(".build.containers.aos"));
    match variant {
        Some(variant)
            if plan
                .images
                .iter()
                .any(|image| image.system_variant == variant) =>
        {
            Ok(())
        }
        Some(variant) => {
            bail!("container system variant '{variant}' is absent from the release plan")
        }
        None if attribute == "containerImages.aos" && plan.images.len() == 1 => Ok(()),
        None if attribute == "containerImages.aos" => {
            bail!("legacy container definitions require one planned system variant")
        }
        None => bail!("container release has an unsupported Nix definition attribute"),
    }
}

fn visit(
    layout: &Path,
    descriptor: &Descriptor,
    graph: &mut BTreeMap<String, GraphNode>,
) -> Result<()> {
    let digest = descriptor.digest.to_string();
    if let Some(existing) = graph.get(&digest) {
        if existing.descriptor.size != descriptor.size
            || existing.descriptor.media_type != descriptor.media_type
        {
            bail!("OCI digest {digest} has conflicting descriptor identities");
        }
        return Ok(());
    }
    let source = layout
        .join("blobs/sha256")
        .join(descriptor.digest.encoded());
    let metadata = fs::symlink_metadata(&source)
        .with_context(|| format!("reading OCI blob {}", source.display()))?;
    if !metadata.is_file() || metadata.len() != descriptor.size {
        bail!("OCI blob {digest} differs from its descriptor size");
    }
    let mut children = Vec::new();
    if descriptor.media_type.is_image_index() {
        let bytes = super::super::capture::control_file(&source, "OCI index")?;
        if Sha256Digest::of_bytes(&bytes) != Sha256Digest::parse(&digest)? {
            bail!("OCI index {digest} differs from its descriptor digest");
        }
        let index = ImageIndex::from_json(&bytes)
            .map_err(anyhow::Error::msg)
            .context("validating OCI index")?;
        children.extend(index.manifests.iter().map(|child| child.digest.to_string()));
        graph.insert(
            digest.clone(),
            GraphNode {
                descriptor: descriptor.clone(),
                source: source.clone(),
                children,
            },
        );
        for child in &index.manifests {
            visit(layout, child, graph)?;
        }
        return Ok(());
    }
    if descriptor.media_type.is_image_manifest() {
        let bytes = super::super::capture::control_file(&source, "OCI manifest")?;
        if Sha256Digest::of_bytes(&bytes) != Sha256Digest::parse(&digest)? {
            bail!("OCI manifest {digest} differs from its descriptor digest");
        }
        let manifest = ImageManifest::from_json(&bytes)
            .map_err(anyhow::Error::msg)
            .context("validating OCI manifest")?;
        children.push(manifest.config.digest.to_string());
        children.extend(manifest.layers.iter().map(|child| child.digest.to_string()));
        graph.insert(
            digest.clone(),
            GraphNode {
                descriptor: descriptor.clone(),
                source: source.clone(),
                children,
            },
        );
        visit(layout, &manifest.config, graph)?;
        for child in &manifest.layers {
            visit(layout, child, graph)?;
        }
        return Ok(());
    }

    graph.insert(
        digest,
        GraphNode {
            descriptor: descriptor.clone(),
            source,
            children,
        },
    );
    Ok(())
}

fn require_exact_blob_set(layout: &Path, graph: &BTreeMap<String, GraphNode>) -> Result<()> {
    let root = layout.join("blobs/sha256");
    let actual = fs::read_dir(&root)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                bail!("finalized OCI blob directory contains a non-file");
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("OCI blob name is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = graph
        .values()
        .map(|node| node.descriptor.digest.encoded().to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("finalized OCI layout contains missing or unreferenced blobs");
    }
    Ok(())
}

fn release_platform(platform: &aos_oci_types::Platform) -> Result<Platform> {
    match (platform.os.as_str(), platform.architecture.as_str()) {
        ("linux", "amd64") => Ok(Platform::X86_64Linux),
        ("linux", "arm64") => Ok(Platform::Aarch64Linux),
        _ => bail!(
            "container platform {}/{} is outside the release matrix",
            platform.os,
            platform.architecture
        ),
    }
}

fn descriptor_compression(media_type: MediaType) -> Compression {
    let value = media_type.as_str();
    if value.ends_with("+gzip") {
        Compression::Gzip
    } else if value.ends_with("+zstd") {
        Compression::Zstd
    } else {
        Compression::None
    }
}

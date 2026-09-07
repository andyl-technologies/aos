//! Finalized registry-surface capture.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context as _, Result};
use aos_package::registry::release::{FinalizedRegistryRelease, RegistryStaticSurfaceFile};
use aos_package::registry::static_upload::collect_static_origin_files;
use aos_release::artifact::{ArtifactKind, BundlePath};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;

use super::{ArtifactAttributes, PayloadBuilder};

pub(super) fn assemble(
    registry: &Path,
    result_path: &Path,
    plan: &ReleasePlanV1,
    plan_digest: Sha256Digest,
    payload: &mut PayloadBuilder,
) -> Result<()> {
    let bytes = super::read_canonical(result_path, "registry finalization result")?;
    let result: FinalizedRegistryRelease =
        canonical::from_slice(&bytes, "registry finalization result")?;
    if result.registry != plan.registry
        || result.release != plan.version
        || result.plan_digest != plan_digest.to_string()
    {
        bail!("registry finalization result differs from the release plan");
    }

    let expected = result
        .static_surface
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != result.static_surface.len() {
        bail!("registry finalization result repeats a static path");
    }
    let observed = collect_static_origin_files(registry)?;
    if observed.len() != expected.len() {
        bail!("finalized registry static surface cardinality changed");
    }
    for file in observed {
        let identity = expected
            .get(file.relative_path.as_str())
            .with_context(|| format!("unreviewed registry path {}", file.relative_path))?;
        validate_identity(identity, &file)?;
        let relative = format!("registry/{}", file.relative_path);
        BundlePath::parse(relative.clone())?;
        let id = format!(
            "registry/{}",
            Sha256Digest::of_bytes(file.relative_path.as_bytes()).hex()
        );
        let attributes = ArtifactAttributes {
            media_type: file.content_type.to_owned(),
            expected: Some((identity.byte_size, Sha256Digest::parse(&identity.sha256)?)),
            ..ArtifactAttributes::plain(file.content_type)
        };
        payload.copy(
            &file.source,
            id,
            ArtifactKind::RegistryObject,
            relative,
            attributes,
        )?;
    }

    payload.copy(
        result_path,
        "provenance/registry-finalization".to_owned(),
        ArtifactKind::Provenance,
        "evidence/registry-finalization.json".to_owned(),
        ArtifactAttributes::exact("application/vnd.aos.registry-finalization.v1+json", &bytes)?,
    )?;
    Ok(())
}

fn validate_identity(
    expected: &RegistryStaticSurfaceFile,
    observed: &aos_package::registry::static_upload::StaticOriginFile,
) -> Result<()> {
    if expected.class != format!("{:?}", observed.class).to_ascii_lowercase() {
        bail!("registry path {} changed publication class", expected.path);
    }
    Sha256Digest::parse(&expected.sha256)
        .with_context(|| format!("invalid registry digest for {}", expected.path))?;
    Ok(())
}

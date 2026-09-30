//! Nix profile verification before release image build and signing effects.
//!
//! Only the clean checkout frozen in the plan may supply the profile. Each
//! selected target is evaluated independently, so a target-specific override
//! cannot send an image's package manager to a different registry.
//!
//! When the staging surface is a Hub deployment, the baked Hub origin must be
//! that deployment's origin: the staging surface is the first deployment to
//! receive and serve the signed images. A static staging surface has no Hub
//! control origin, so only the registry binding applies.

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_release::artifact_profile::ArtifactProfile;
use aos_release::plan::{ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release::platform::MatrixCell;

/// Checks every image-producing platform against the exact release destination.
pub(super) fn require_plan(nix: &NixRunner, plan: &ReleasePlan) -> Result<()> {
    if !plan.images.iter().any(|image| {
        image
            .platforms
            .iter()
            .any(|cell| matches!(cell.decision, MatrixCell::Artifact { .. }))
    }) {
        return Ok(());
    }
    super::plan::require_planned_source(nix.root(), &plan.source)?;
    let staging_hub = plan
        .surfaces
        .iter()
        .find(|surface| surface.role == SurfaceRole::Staging && surface.kind == SurfaceKind::Hub);

    for image in &plan.images {
        if image.system_variant.is_empty()
            || !image
                .system_variant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("release image system variant is not a single Nix attribute name");
        }
        let attribute = format!("systems.{}.config.aos.release", image.system_variant);
        for cell in &image.platforms {
            if !matches!(cell.decision, MatrixCell::Artifact { .. }) {
                continue;
            }
            let value = nix.eval_json_for_target(&attribute, Some(cell.platform.as_str()))?;
            let profile: ArtifactProfile = serde_json::from_value(value)
                .context("decoding the image's Nix release artifact profile")?;
            profile.require_release(&plan.registry).with_context(|| {
                format!(
                    "release profile mismatch for {} on {}",
                    image.system_variant, cell.platform
                )
            })?;
            if let Some(staging) = staging_hub {
                profile.require_hub(&staging.origin).with_context(|| {
                    format!(
                        "release profile Hub mismatch for {} on {}",
                        image.system_variant, cell.platform
                    )
                })?;
            }
        }
    }
    Ok(())
}

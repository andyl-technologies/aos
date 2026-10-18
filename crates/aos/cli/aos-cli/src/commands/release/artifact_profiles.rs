//! Nix profile verification before release image build and signing effects.
//!
//! Only the clean checkout frozen in the plan may supply the profile. Each
//! selected target is evaluated independently, so a target-specific override
//! cannot send an image's package manager to a different registry.
//!
//! The baked Hub origin binds to the surface consumers will install from.
//! A plan with any production destination ships the same signed bytes to
//! production, so its images must bake the production Hub; staging exercises
//! them with an explicit cache override. A staging-only plan (every
//! destination on the staging surface) bakes the staging Hub instead, which
//! is what the `aos-experimental-staging` variant provides. A qualification
//! snapshot has no destinations at all: it stands in for the installed
//! predecessor of a later public release, so it bakes the production Hub
//! like the release it precedes. A static surface has no Hub control origin,
//! so only the registry binding applies.

use anyhow::{Context as _, Result, bail};
use aos_nix::NixRunner;
use aos_release_format::artifact_profile::ArtifactProfile;
use aos_release_format::plan::{ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release_format::platform::MatrixCell;
use aos_release_format::signing::SignerRole;

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
    let destination_surfaces: Vec<SurfaceRole> = plan
        .destinations
        .iter()
        .map(|destination| destination.surface)
        .collect();
    let consumer_role = consumer_role(&destination_surfaces);
    let consumer_hub = plan
        .surfaces
        .iter()
        .find(|surface| surface.role == consumer_role && surface.kind == SurfaceKind::Hub);
    let provenance_key_ids: Vec<String> = plan
        .signers
        .iter()
        .filter(|signer| signer.role == SignerRole::Provenance)
        .flat_map(|signer| signer.key_ids.iter().cloned())
        .collect();

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
            profile
                .require_root_owner_signers(&provenance_key_ids)
                .with_context(|| {
                    format!(
                        "release profile root-owner signer mismatch for {} on {}",
                        image.system_variant, cell.platform
                    )
                })?;
            if let Some(hub) = consumer_hub {
                profile.require_hub(&hub.origin).with_context(|| {
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

/// Selects the surface whose Hub the images must bake for these destinations.
///
/// Only a plan whose every destination is on staging consumes from staging.
/// A plan with a production destination, or a qualification snapshot with
/// none, bakes production.
fn consumer_role(destination_surfaces: &[SurfaceRole]) -> SurfaceRole {
    let staging_only = !destination_surfaces.is_empty()
        && destination_surfaces
            .iter()
            .all(|surface| *surface == SurfaceRole::Staging);
    if staging_only {
        SurfaceRole::Staging
    } else {
        SurfaceRole::Production
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_staging_only_plans_consume_from_the_staging_hub() {
        assert_eq!(consumer_role(&[]), SurfaceRole::Production);
        assert_eq!(consumer_role(&[SurfaceRole::Staging]), SurfaceRole::Staging);
        assert_eq!(
            consumer_role(&[SurfaceRole::Staging, SurfaceRole::Production]),
            SurfaceRole::Production
        );
        assert_eq!(
            consumer_role(&[SurfaceRole::Production]),
            SurfaceRole::Production
        );
    }
}

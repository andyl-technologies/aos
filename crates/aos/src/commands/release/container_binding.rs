//! Container identity and system-variant bindings shared by release steps.

use anyhow::{Context as _, Result, bail};
use aos_oci_types::ContainerRelease;
use aos_release::plan::{ImagePlan, ReleasePlan};

/// Checks the signed container against the frozen release and package matrix.
///
/// # Errors
///
/// Returns an error for an unplanned release, package, package version, or
/// system variant, or an ambiguous base-container definition.
pub(super) fn validate(release: &ContainerRelease, plan: &ReleasePlan) -> Result<()> {
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

    validate_image_attribute(&release.nix.definition.attribute, &plan.images)
}

fn validate_image_attribute(attribute: &str, images: &[ImagePlan]) -> Result<()> {
    let variant = attribute
        .strip_prefix("systems.")
        .and_then(|rest| rest.strip_suffix(".build.containers.aos"));
    match variant {
        Some(variant) if images.iter().any(|image| image.system_variant == variant) => Ok(()),
        Some(variant) => {
            bail!("container system variant '{variant}' is absent from the release plan")
        }
        // The retained base-container alias has no variant identity of its own.
        // A single planned image is required to bind it without ambiguity.
        None if attribute == "containerImages.aos" && images.len() == 1 => Ok(()),
        None if attribute == "containerImages.aos" => {
            bail!("legacy container definitions require one planned system variant")
        }
        None => bail!("container release has an unsupported Nix definition attribute"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn images(variants: &[&str]) -> Vec<ImagePlan> {
        variants
            .iter()
            .map(|variant| ImagePlan {
                system_variant: (*variant).to_owned(),
                platforms: Vec::new(),
            })
            .collect()
    }

    #[test]
    fn system_definition_requires_the_exact_planned_variant() {
        let images = images(&["server", "desktop"]);

        assert!(validate_image_attribute("systems.server.build.containers.aos", &images).is_ok());
        assert!(validate_image_attribute("systems.desktop.build.containers.aos", &images).is_ok());
        assert!(validate_image_attribute("systems.rescue.build.containers.aos", &images).is_err());
        assert!(
            validate_image_attribute("systems.server.build.containers.other", &images).is_err()
        );
    }

    #[test]
    fn base_container_alias_requires_one_unambiguous_planned_image() {
        assert!(validate_image_attribute("containerImages.aos", &images(&["server"])).is_ok());
        assert!(validate_image_attribute("containerImages.aos", &images(&[])).is_err());
        assert!(
            validate_image_attribute("containerImages.aos", &images(&["server", "desktop"]))
                .is_err()
        );
    }
}

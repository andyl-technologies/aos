//! Container identity and system-variant bindings shared by release steps.

use anyhow::{Context as _, Result, bail};
use aos_oci_types::ContainerRelease;
use aos_release::plan::{ImagePlan, ReleasePlan};
use aos_release::platform::Platform;

/// Checks the signed container against the frozen release and package matrix.
///
/// # Errors
///
/// Returns an error for an unplanned release, package, package version, or
/// system variant, an ambiguous base-container definition, or a platform
/// manifest outside the release matrix or on a platform the contract defers.
pub(super) fn validate(release: &ContainerRelease, plan: &ReleasePlan) -> Result<()> {
    // A deferred platform has no container claim, so nothing would qualify
    // its manifest. Reject the bundle here, before registry authoring.
    for descriptor in &release.oci.platform_manifests {
        let platform = descriptor
            .platform
            .as_ref()
            .context("container platform manifest lacks a platform")?;
        let platform = release_platform(platform)?;
        if plan.qualification.is_deferred(platform) {
            bail!("container carries a {platform} manifest, but the release defers {platform}");
        }
    }

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

/// Maps an OCI platform descriptor onto the closed release platform roster.
///
/// # Errors
///
/// Returns an error for any platform other than Linux amd64 or arm64.
pub(super) fn release_platform(platform: &aos_oci_types::Platform) -> Result<Platform> {
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

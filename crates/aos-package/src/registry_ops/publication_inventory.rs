//! Direct package-publication authority from evaluated Nix inventory.

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_release::inventory::{DerivationInventoryV1, DerivationPackage};
use aos_release::platform::Platform;

/// Evaluates and selects the one package whose primary output is being published.
pub(super) fn evaluate_package(
    store_path: &str,
    platform: &str,
) -> Result<(DerivationInventoryV1, DerivationPackage)> {
    let platform = parse_platform(platform)?;
    let release_platforms = Platform::ALL.map(Platform::as_str);
    let inventory: DerivationInventoryV1 =
        serde_json::from_value(NixRunner::new(0, true)?.eval_release_json(
            "releasePackageDerivations",
            Some(platform.as_str()),
            &release_platforms,
        )?)
        .with_context(|| format!("decoding evaluated {platform} package inventory"))?;
    if inventory.platform != platform {
        bail!("Nix derivation inventory returned the wrong target");
    }

    let package = select_package(&inventory, store_path)?.clone();
    Ok((inventory, package))
}

fn parse_platform(value: &str) -> Result<Platform> {
    Platform::ALL
        .into_iter()
        .find(|platform| platform.as_str() == value)
        .with_context(|| format!("unsupported package publication platform {value:?}"))
}

/// Selects exactly one primary package output from a validated inventory.
pub(super) fn select_package<'a>(
    inventory: &'a DerivationInventoryV1,
    store_path: &str,
) -> Result<&'a DerivationPackage> {
    inventory.validate()?;

    let mut matches = inventory.packages.iter().filter(|package| {
        package
            .outputs
            .iter()
            .any(|output| output.name == "out" && output.store_path == store_path)
    });
    let package = matches.next().with_context(|| {
        format!(
            "store path {store_path} is not the primary output of the evaluated {} package inventory",
            inventory.platform
        )
    })?;
    if matches.next().is_some() {
        bail!("evaluated package inventory assigns one primary output to multiple packages");
    }
    if package.publication.is_none() {
        bail!(
            "evaluated package '{}' lacks complete publication metadata",
            package.name
        );
    }

    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::select_package;
    use aos_release::inventory::{
        DERIVATION_INVENTORY_V1, DerivationInventoryV1, DerivationOutput, DerivationPackage,
        PackagePublicationMetadata,
    };
    use aos_release::platform::Platform;

    fn inventory() -> DerivationInventoryV1 {
        DerivationInventoryV1 {
            schema_version: DERIVATION_INVENTORY_V1.to_string(),
            platform: Platform::X86_64Linux,
            packages: vec![DerivationPackage {
                name: "demo".to_string(),
                publication: Some(PackagePublicationMetadata {
                    version: "1.2.3".to_string(),
                    description: "Demo package".to_string(),
                    homepage: None,
                    license_expression: "Apache-2.0".to_string(),
                    maintainers: vec!["AOS".to_string()],
                }),
                source_store_paths: vec![
                    "/nix/store/ssssssssssssssssssssssssssssssss-demo-source".to_string(),
                ],
                derivation: "/nix/store/dddddddddddddddddddddddddddddddd-demo.drv".to_string(),
                outputs: vec![DerivationOutput {
                    name: "out".to_string(),
                    derivation: None,
                    store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo".to_string(),
                }],
                contract: None,
            }],
        }
    }

    #[test]
    fn selects_only_the_exact_evaluated_primary_output() {
        let inventory = inventory();
        let selected = select_package(
            &inventory,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo",
        )
        .unwrap();

        assert_eq!(selected.name, "demo");
        assert!(
            select_package(
                &inventory,
                "/nix/store/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-demo"
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_a_primary_output_without_complete_publication_metadata() {
        let mut inventory = inventory();
        inventory.packages[0].publication = None;

        let error = select_package(
            &inventory,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo",
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("lacks complete publication metadata")
        );
    }
}

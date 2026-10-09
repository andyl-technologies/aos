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
    value
        .parse()
        .with_context(|| format!("unsupported package publication platform {value:?}"))
}

/// Selects declared ordinary subpackages from the same exact evaluated source build.
///
/// # Errors
/// Returns an error for invalid inventory metadata, missing subpackages, or
/// differences in their version, derivation, physical output, or payload root.
pub(super) fn publication_group(
    inventory: &DerivationInventoryV1,
    package: &DerivationPackage,
) -> Result<Vec<DerivationPackage>> {
    inventory.validate()?;
    let publication = package
        .publication
        .as_ref()
        .context("selected source package lacks publication metadata")?;
    let mut packages = vec![package.clone()];
    for (name, output) in &publication.output_packages {
        let selected = inventory
            .packages
            .iter()
            .find(|candidate| &candidate.name == name)
            .with_context(|| {
                format!("declared subpackage '{name}' is absent from the evaluated inventory")
            })?;
        let source = package
            .outputs
            .iter()
            .find(|candidate| &candidate.name == output)
            .context("declared subpackage output is absent from its source build")?;
        let primary = selected
            .outputs
            .iter()
            .find(|candidate| candidate.name == "out")
            .context("declared subpackage lacks its primary payload")?;
        let metadata = selected
            .publication
            .as_ref()
            .context("declared subpackage lacks publication metadata")?;
        if selected.derivation != package.derivation
            || metadata.version != publication.version
            || primary.store_path != source.store_path
            || primary.derivation != source.derivation
            || primary.output != source.output
        {
            bail!("declared subpackage '{name}' differs from the exact source build output");
        }
        packages.push(selected.clone());
    }
    Ok(packages)
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
    use super::{publication_group, select_package};
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
                    output_packages: Default::default(),
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
                    deployment: None,
                    name: "out".to_string(),
                    derivation: Some(
                        "/nix/store/dddddddddddddddddddddddddddddddd-demo.drv".to_string(),
                    ),
                    output: Some("out".to_string()),
                    store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo".to_string(),
                }],
                deployment: None,
                module_documentation: None,
                qualification: None,
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

    #[test]
    fn source_publication_selects_only_declared_exact_subpackages() {
        let mut inventory = inventory();
        let source = &mut inventory.packages[0];
        let mut tools = source.outputs[0].clone();
        tools.name = "tools".into();
        tools.output = Some("tools".into());
        tools.store_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo-tools".into();
        source.outputs.push(tools.clone());
        source
            .publication
            .as_mut()
            .unwrap()
            .output_packages
            .insert("demo-tools".into(), "tools".into());

        let mut subpackage = source.clone();
        subpackage.name = "demo-tools".into();
        tools.name = "out".into();
        subpackage.outputs = vec![tools];
        subpackage
            .publication
            .as_mut()
            .unwrap()
            .output_packages
            .clear();
        let mut independent = subpackage.clone();
        independent.name = "independent".into();
        inventory.packages.extend([subpackage, independent]);

        let source = &inventory.packages[0];
        let group = publication_group(&inventory, source).unwrap();

        assert_eq!(
            group
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["demo", "demo-tools"]
        );
        assert_eq!(group[1].outputs[0].output.as_deref(), Some("tools"));
        assert_eq!(
            publication_group(&inventory, &inventory.packages[2])
                .unwrap()
                .len(),
            1
        );

        inventory.packages[1].outputs[0].output = Some("out".into());

        assert!(publication_group(&inventory, &inventory.packages[0]).is_err());
    }

    #[test]
    fn source_publication_requires_every_declared_subpackage() {
        let mut inventory = inventory();
        let source = &mut inventory.packages[0];
        let mut tools = source.outputs[0].clone();
        tools.name = "tools".into();
        tools.output = Some("tools".into());
        tools.store_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-demo-tools".into();
        source.outputs.push(tools);
        source
            .publication
            .as_mut()
            .unwrap()
            .output_packages
            .insert("demo-tools".into(), "tools".into());

        let error = publication_group(&inventory, &inventory.packages[0]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("absent from the evaluated inventory")
        );
    }
}

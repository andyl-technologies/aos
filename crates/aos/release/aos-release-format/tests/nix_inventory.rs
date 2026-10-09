//! Exercises the Nix-to-Rust release inventory boundary from a source checkout.
//!
//! This opt-in integration check needs the repository's Nix evaluator and its
//! source inputs. It does not realize packages or generate a release plan.
//! Platforms the qualification contract defers must arrive fully blocked.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use aos_release_format::inventory::{DerivationInventoryV1, PackageInventoryV1};
use aos_release_format::platform::{MatrixCell, Platform};
use aos_release_format::qualification::QualificationContract;
use serde::de::DeserializeOwned;

fn evaluate<T: DeserializeOwned>(
    root: &Path,
    attribute: &str,
    target: Option<Platform>,
) -> Result<T> {
    let mut command = Command::new("nix-instantiate");
    command
        .current_dir(root)
        .args(["--eval", "--strict", "--json", "-A", attribute])
        .args([
            "--arg",
            "releasePlatforms",
            r#"["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]"#,
        ]);
    if let Some(target) = target {
        command.args(["--argstr", "crossSystem", target.as_str()]);
    }

    let output = command
        .output()
        .context("running the Nix inventory evaluator")?;
    ensure!(
        output.status.success(),
        "Nix evaluation failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).context("decoding the evaluated inventory")
}

#[test]
#[ignore = "requires the complete source checkout and Nix evaluation inputs"]
fn source_inventory_materializes_the_linux_release_and_retains_reviewed_deferrals() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let inventory: PackageInventoryV1 = evaluate(&root, "releasePackageInventory", None)?;
    let build_platform: String = evaluate(&root, "stdenv.buildPlatform.system", None)?;
    let derivations = Platform::ALL
        .into_iter()
        .map(|platform| {
            let target = (platform.as_str() != build_platform).then_some(platform);
            evaluate::<DerivationInventoryV1>(&root, "releasePackageDerivations", target)
        })
        .collect::<Result<Vec<_>>>()?;

    let packages = inventory.package_plan(&derivations)?;

    let contract: QualificationContract = evaluate(&root, "releaseQualification", None)?;
    let inventoried: BTreeSet<_> = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    let classified: BTreeSet<_> = contract
        .package_rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect();
    assert_eq!(inventoried, classified);

    for platform in Platform::LINUX {
        let cells = packages
            .iter()
            .flat_map(|package| &package.platforms)
            .filter(|cell| cell.platform == platform)
            .collect::<Vec<_>>();

        // A deferred platform ships nothing: the inventory blocks every
        // eligible cell with the shared deferral reason instead.
        if contract.is_deferred(platform) {
            assert!(cells.iter().all(|cell| match &cell.decision {
                MatrixCell::Artifact { .. } => false,
                MatrixCell::NotApplicable { .. } => true,
                MatrixCell::Blocked { required_work, .. } => {
                    required_work.starts_with("platform-release-deferred/v1: ")
                }
            }));
            assert!(
                cells
                    .iter()
                    .any(|cell| matches!(cell.decision, MatrixCell::Blocked { .. }))
            );
            continue;
        }

        assert!(
            cells
                .iter()
                .any(|cell| matches!(cell.decision, MatrixCell::Artifact { .. }))
        );
        assert!(
            !cells
                .iter()
                .any(|cell| matches!(cell.decision, MatrixCell::Blocked { .. }))
        );
    }
    assert!(
        Platform::LINUX
            .into_iter()
            .any(|platform| !contract.is_deferred(platform))
    );
    assert!(
        packages
            .iter()
            .flat_map(|package| &package.platforms)
            .any(|cell| {
                !cell.platform.supports_images()
                    && matches!(cell.decision, MatrixCell::NotApplicable { .. })
            })
    );
    Ok(())
}

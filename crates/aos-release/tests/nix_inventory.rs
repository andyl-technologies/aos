//! Exercises the Nix-to-Rust release inventory boundary from a source checkout.
//!
//! This opt-in integration check needs the repository's Nix evaluator and its
//! source inputs. It does not realize packages or generate a release plan.

use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use aos_release::inventory::{DerivationInventoryV1, PackageInventoryV1};
use aos_release::platform::{MatrixCell, Platform};
use serde::de::DeserializeOwned;

fn evaluate<T: DeserializeOwned>(
    root: &Path,
    attribute: &str,
    target: Option<Platform>,
) -> Result<T> {
    let mut command = Command::new("nix-instantiate");
    command
        .current_dir(root)
        .args(["--eval", "--strict", "--json", "-A", attribute]);
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
fn source_inventory_materializes_the_linux_release_and_retains_platform_blockers() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: PackageInventoryV1 = evaluate(&root, "releasePackageInventory", None)?;
    let derivations = Platform::ALL
        .into_iter()
        .map(|platform| {
            let target = (platform != Platform::X86_64Linux).then_some(platform);
            evaluate::<DerivationInventoryV1>(&root, "releasePackageDerivations", target)
        })
        .collect::<Result<Vec<_>>>()?;

    let packages = inventory.package_plan(&derivations)?;

    for platform in Platform::LINUX {
        let cells = packages
            .iter()
            .flat_map(|package| &package.platforms)
            .filter(|cell| cell.platform == platform)
            .collect::<Vec<_>>();
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
        packages
            .iter()
            .flat_map(|package| &package.platforms)
            .any(|cell| {
                !cell.platform.supports_images()
                    && matches!(cell.decision, MatrixCell::Blocked { .. })
            })
    );
    Ok(())
}

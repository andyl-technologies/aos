//! End-to-end checks for the Nix release inventory consumed by Rust.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aos_core::nix::NixRunner;
use aos_release::inventory::PackageInventoryV1;
use aos_release::platform::Platform;

const SEMANTIC_FIXTURE_EXPRESSION: &str = r#"
  import ./tests/build/fixtures/release-package-inventory-input.nix {
    releasePlatforms = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
  }
"#;

fn repository_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("resolving the repository root")
}

fn decode_and_validate(bytes: &[u8]) -> Result<PackageInventoryV1> {
    let inventory: PackageInventoryV1 =
        serde_json::from_slice(bytes).context("decoding the exact JSON bytes emitted by Nix")?;
    inventory.validate()?;

    Ok(inventory)
}

fn nix_runner() -> Result<NixRunner> {
    let command_environment = [
        ("AOS_TEST_ABILITY_NIX_STORE_DIR", "NIX_STORE_DIR"),
        ("AOS_TEST_ABILITY_NIX_STATE_DIR", "NIX_STATE_DIR"),
        ("AOS_TEST_ABILITY_NIX_LOG_DIR", "NIX_LOG_DIR"),
        ("AOS_TEST_ABILITY_NIX_REMOTE", "NIX_REMOTE"),
    ]
    .into_iter()
    .filter_map(|(source, target)| {
        std::env::var_os(source).map(|value| (OsString::from(target), value))
    });

    Ok(NixRunner::for_root(repository_root()?, 0, true)?
        .with_command_environment(command_environment))
}

#[test]
fn semantic_nix_input_crosses_the_rust_inventory_boundary() -> Result<()> {
    let nix = nix_runner()?;
    let bytes = nix.eval_expr_json_bytes(SEMANTIC_FIXTURE_EXPRESSION)?;
    let inventory = decode_and_validate(&bytes)?;

    assert_eq!(inventory.platforms, Platform::ALL);
    assert_eq!(inventory.packages.len(), 1);
    assert_eq!(inventory.packages[0].name, "public-fixture");

    Ok(())
}

#[test]
fn production_nix_inventory_crosses_the_rust_inventory_boundary() -> Result<()> {
    let nix = nix_runner()?;
    let release_platforms = Platform::ALL.map(Platform::as_str);
    let bytes = nix.eval_release_json_bytes("releasePackageInventory", None, &release_platforms)?;
    let inventory = decode_and_validate(&bytes)?;

    assert_eq!(inventory.platforms, Platform::ALL);
    assert!(!inventory.packages.is_empty());

    Ok(())
}

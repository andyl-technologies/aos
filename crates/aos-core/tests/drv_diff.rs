#![cfg(feature = "native-eval")]

use std::fs;

use anyhow::{Context, Result};
use aos_core::nix::diff::{DiffMode, diff_closure};
use aos_core::nix::{
    NixCli, NixEvalConfig, aos_nix_command, select_native_diff_candidate_with_config,
};

#[test]
fn native_diff_candidate_matches_cli_drv_closure_bytes() -> Result<()> {
    require_nix_instantiate()?;

    let temp_parent = std::env::temp_dir()
        .canonicalize()
        .context("canonicalizing temp directory")?;
    let temp = tempfile::Builder::new()
        .prefix("aos-drv-diff-")
        .tempdir_in(temp_parent)?;
    let default_nix = temp.path().join("default.nix");
    fs::write(
        &default_nix,
        r#"
        let
          builder = "${builtins.storeDir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          base = derivation {
            name = "aos-drv-diff-base";
            system = "x86_64-linux";
            inherit builder;
            args = [];
          };
          consumer = derivation {
            name = "aos-drv-diff-consumer";
            system = "x86_64-linux";
            inherit builder;
            args = [];
            input = "${base.out}";
          };
        in {
          pkgs = {
            inherit base consumer;
          };
        }
        "#,
    )?;

    let config = NixEvalConfig::with_store_dirs(
        temp.path()
            .join("store")
            .to_str()
            .context("store path is not utf-8")?,
        temp.path()
            .join("var/nix")
            .to_str()
            .context("state path is not utf-8")?,
        temp.path()
            .join("var/nix/log/nix")
            .to_str()
            .context("log path is not utf-8")?,
    )?;
    let oracle = NixCli::with_eval_config(0, config.clone());
    let candidate = select_native_diff_candidate_with_config(0, config)?;
    let report = diff_closure(
        &oracle,
        candidate.as_ref(),
        &default_nix,
        "pkgs.consumer",
        DiffMode::Byte,
    )?;

    assert_eq!(report.mode, DiffMode::Byte);
    assert!(
        report.oracle_root.is_some(),
        "oracle should produce a root drv path: {report:#?}"
    );
    assert!(
        report.candidate_root.is_some(),
        "candidate should produce a root drv path: {report:#?}"
    );
    assert_eq!(report.oracle_root, report.candidate_root);
    assert!(
        report.divergences.is_empty(),
        "drv closure diverged: {:#?}",
        report.divergences
    );

    Ok(())
}

fn require_nix_instantiate() -> Result<()> {
    let output = aos_nix_command("nix-instantiate")
        .arg("--version")
        .output()
        .context("running nix-instantiate --version")?;
    if !output.status.success() {
        anyhow::bail!(
            "nix-instantiate --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

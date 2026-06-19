#![cfg(feature = "native-eval")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aos_core::nix::diff::{DiffMode, DrvDiff, diff_closure};
use aos_core::nix::{
    DrvClosure, NixCli, NixEval, NixEvalConfig, aos_nix_command,
    select_native_diff_candidate_with_config,
};

#[test]
fn native_diff_candidate_matches_cli_drv_closure_in_all_modes() -> Result<()> {
    require_nix_instantiate()?;

    let fixture = DrvDiffFixture::new()?;
    let oracle = NixCli::with_eval_config(0, fixture.config.clone());
    let candidate = select_native_diff_candidate_with_config(0, fixture.config.clone())?;

    for mode in [DiffMode::Path, DiffMode::Byte, DiffMode::Structural] {
        let report = diff_closure(
            &oracle,
            candidate.as_ref(),
            &fixture.default_nix,
            "pkgs.consumer",
            mode,
        )?;

        assert_eq!(report.mode, mode);
        assert!(
            report.oracle_root.is_some(),
            "oracle should produce a root drv path in {mode:?} mode: {report:#?}"
        );
        assert!(
            report.candidate_root.is_some(),
            "candidate should produce a root drv path in {mode:?} mode: {report:#?}"
        );
        assert_eq!(report.oracle_root, report.candidate_root);
        assert!(
            report.divergences.is_empty(),
            "drv diff diverged in {mode:?} mode: {:#?}",
            report.divergences
        );
        if mode != DiffMode::Path {
            assert!(
                report.root_divergences.is_empty(),
                "root divergences in {mode:?} mode: {:#?}",
                report.root_divergences
            );
            assert!(
                report.contaminated_divergences.is_empty(),
                "contaminated divergences in {mode:?} mode: {:#?}",
                report.contaminated_divergences
            );
        }
    }

    Ok(())
}

#[test]
fn structural_mode_reports_real_drv_field_differences() -> Result<()> {
    require_nix_instantiate()?;

    let fixture = DrvDiffFixture::new()?;
    let oracle = NixCli::with_eval_config(0, fixture.config.clone());
    let native = select_native_diff_candidate_with_config(0, fixture.config.clone())?;
    let candidate = RootNameMutatingEval::new(native);
    let report = diff_closure(
        &oracle,
        &candidate,
        &fixture.default_nix,
        "pkgs.consumer",
        DiffMode::Structural,
    )?;

    assert_eq!(report.mode, DiffMode::Structural);
    assert_eq!(report.oracle_root, report.candidate_root);
    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { .. })),
        "structural mode should still record the byte divergence: {report:#?}"
    );
    assert!(
        report.divergences.iter().any(|diff| matches!(
            diff,
            DrvDiff::Structural { field, .. } if field == "environment"
        )),
        "structural mode should parse real drv bytes and report the changed field: {report:#?}"
    );
    assert_eq!(
        report.root_divergences.len(),
        1,
        "the mutated root drv should be the only root divergence: {report:#?}"
    );
    assert!(
        report.contaminated_divergences.is_empty(),
        "the root-only mutation should not contaminate inputs: {report:#?}"
    );

    Ok(())
}

struct DrvDiffFixture {
    _temp: tempfile::TempDir,
    default_nix: PathBuf,
    config: NixEvalConfig,
}

impl DrvDiffFixture {
    fn new() -> Result<Self> {
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

        Ok(Self {
            _temp: temp,
            default_nix,
            config,
        })
    }
}

struct RootNameMutatingEval {
    inner: Box<dyn NixEval>,
}

impl RootNameMutatingEval {
    fn new(inner: Box<dyn NixEval>) -> Self {
        Self { inner }
    }

    fn mutate_root_drv_name(
        &self,
        root: &Path,
        drvs: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<()> {
        const FROM: &[u8] = br#"("name","aos-drv-diff-consumer")"#;
        const TO: &[u8] = br#"("name","bos-drv-diff-consumer")"#;

        anyhow::ensure!(
            FROM.len() == TO.len(),
            "test mutation must preserve drv byte length"
        );

        let bytes = drvs
            .get_mut(root)
            .with_context(|| format!("finding root drv bytes for {}", root.display()))?;
        let offset = bytes
            .windows(FROM.len())
            .position(|window| window == FROM)
            .with_context(|| format!("finding root drv name marker in {}", root.display()))?;
        bytes[offset..offset + FROM.len()].copy_from_slice(TO);

        Ok(())
    }
}

impl NixEval for RootNameMutatingEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        self.inner.instantiate(file, attr)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        self.inner.instantiate_expr(expr)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let Some(closure) = self.inner.instantiate_closure(file, attr)? else {
            return Ok(None);
        };
        let (root, mut drvs) = closure.into_parts();
        self.mutate_root_drv_name(&root, &mut drvs)?;
        Ok(Some(DrvClosure::new(root, drvs)))
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        self.inner.eval_expr(expr)
    }

    fn name(&self) -> &'static str {
        "root-name-mutating"
    }
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

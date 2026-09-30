//! Independent installed-byte checks against the retained closed installation report.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;

use super::files;
use super::selection::{DirectReviewInstalledKind as Kind, DirectReviewSelection};

pub(super) fn measure(
    base: &Path,
    selection: &DirectReviewSelection,
) -> Result<Option<DirectWorkerInstallationMeasurement>> {
    let Some(selected) = &selection.documents.installation else {
        ensure!(
            selection.installed_files.is_empty(),
            "installed inputs lack a selected report"
        );
        return Ok(None);
    };
    let report: DirectWorkerInstallationReport = files::selected_document(base, selected)?;
    let mut observed = BTreeMap::new();
    for component in &selection.installed_files {
        let size = files::selected_installed_file(base, &component.file)?;
        ensure!(
            observed
                .insert(component.kind, (&component.file.sha256, size))
                .is_none(),
            "installed component selected more than once"
        );
    }

    let mut check = |kind, expected: &str, expected_size: Option<u64>| -> Result<()> {
        let (actual, size) = observed
            .remove(&kind)
            .ok_or_else(|| anyhow::anyhow!("installed component absent"))?;
        ensure!(
            actual == expected && expected_size.is_none_or(|expected| size == expected),
            "installed component differs from observed report"
        );
        Ok(())
    };
    check(Kind::SourceNar, &report.source_nar_sha256, None)?;
    check(Kind::DistributionNar, &report.distribution_nar_sha256, None)?;
    check(
        Kind::Wasm,
        &report.wasm_sha256,
        Some(report.wasm_byte_size.get()),
    )?;
    check(
        Kind::Shim,
        &report.shim_sha256,
        Some(report.shim_byte_size.get()),
    )?;
    check(Kind::RuntimeBindings, &report.runtime_bindings_sha256, None)?;
    if report.execution_kind == DirectWorkerExecutionKind::EmulatedExternal {
        check(
            Kind::Runner,
            report
                .runner_sha256
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("installed runner observation absent"))?,
            None,
        )?;
        check(
            Kind::RuntimeExecutable,
            report
                .runtime_executable_sha256
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("installed runtime observation absent"))?,
            None,
        )?;
    }
    ensure!(
        observed.is_empty(),
        "installed components exceed selected report"
    );

    Ok(Some(DirectWorkerInstallationMeasurement {
        observation_sha256: selected.sha256.clone(),
        report,
    }))
}

//! Deterministic systemd drop-in rendering from checked realizations.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::model::{PackagedUnitRealization, REALIZATION_SCHEMA};

pub(crate) const DROP_IN_FILE: &str = "overrides.conf";

pub(crate) struct RenderedUnit {
    pub(crate) source: PathBuf,
    pub(crate) drop_in: Vec<u8>,
}

pub(crate) fn validate_unit_name(name: &str) -> Result<()> {
    const SUFFIXES: &[&str] = &[
        ".service",
        ".socket",
        ".target",
        ".timer",
        ".path",
        ".mount",
        ".automount",
        ".swap",
        ".device",
    ];

    if name.is_empty() || name.len() > 255 || !SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
    {
        bail!("systemd realization contains an invalid unit name");
    }
    if !name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b':' | b'-')
    }) {
        bail!("systemd realization contains an invalid unit name");
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("systemd realization contains a non-relative unit file");
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("systemd realization unit file escapes its artifact");
    }
    Ok(())
}

pub(crate) fn render(realization: &PackagedUnitRealization) -> Result<RenderedUnit> {
    if realization.schema != REALIZATION_SCHEMA {
        bail!("systemd realization uses an unsupported schema");
    }
    validate_unit_name(&realization.systemd_unit.unit_name)?;
    validate_relative_path(&realization.source.unit_file)?;
    validate_receipt(
        &realization.revision_receipt,
        &realization.systemd_unit.unit_name,
    )?;
    validate_drop_in(&realization.drop_in_text, &realization.revision_receipt)?;

    let artifact_root = checked_store_root(&realization.source.artifact.store_path)?;
    let source = artifact_root.join(&realization.source.unit_file);
    let canonical_source = source
        .canonicalize()
        .with_context(|| format!("resolving packaged unit {}", source.display()))?;
    let canonical_root = artifact_root
        .canonicalize()
        .with_context(|| format!("resolving artifact root {}", artifact_root.display()))?;
    if !canonical_source.starts_with(&canonical_root) || !canonical_source.is_file() {
        bail!("packaged unit is not a regular file contained by its artifact");
    }

    Ok(RenderedUnit {
        source,
        drop_in: realization.drop_in_text.as_bytes().to_vec(),
    })
}

fn checked_store_root(store_path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(store_path);
    if !path.is_absolute() || !store_path.starts_with("/nix/store/") {
        bail!("artifact reference has an invalid store path");
    }
    Ok(path)
}

fn validate_receipt(receipt: &str, unit_name: &str) -> Result<()> {
    let expected = format!("/etc/aos/ability-revisions/{unit_name}/current");
    if receipt != expected {
        bail!("systemd realization contains a mismatched revision receipt path");
    }
    Ok(())
}

fn validate_drop_in(text: &str, receipt: &str) -> Result<()> {
    if text.is_empty() || text.len() > 1024 * 1024 || text.contains('\0') || !text.ends_with('\n') {
        bail!("systemd realization contains invalid drop-in text");
    }
    let expected = format!("Documentation=file:{receipt}");
    if text.lines().filter(|line| *line == expected).count() != 1 {
        bail!("systemd realization drop-in does not bind its revision receipt");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_drop_in, validate_receipt, validate_relative_path, validate_unit_name};

    #[test]
    fn unit_names_and_relative_paths_are_closed() {
        assert!(validate_unit_name("systemd-zram-setup@.service").is_ok());
        assert!(validate_unit_name("").is_err());
        assert!(validate_unit_name("../escape.service").is_err());
        assert!(validate_relative_path("lib/systemd/system/example.service").is_ok());
        assert!(validate_relative_path("../example.service").is_err());
        assert!(validate_relative_path("/example.service").is_err());
    }

    #[test]
    fn realization_binds_one_exact_receipt() {
        let receipt = "/etc/aos/ability-revisions/example.service/current";
        assert!(validate_receipt(receipt, "example.service").is_ok());
        assert!(validate_receipt(receipt, "other.service").is_err());
        assert!(
            validate_drop_in(
                "[Unit]\nDocumentation=file:/etc/aos/ability-revisions/example.service/current\n",
                receipt,
            )
            .is_ok()
        );
        assert!(validate_drop_in("[Unit]\n", receipt).is_err());
    }
}

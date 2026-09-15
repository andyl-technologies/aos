//! Deterministic systemd drop-in rendering from checked realizations.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_ability_model::{ResourceReference, RevisionId};
use aos_provider_protocol::{
    BoundNativeContext, RESOURCE_CONTEXT_SCHEMA, ResourceContext, native_context_digest,
};

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

pub(crate) fn render(
    realization: &PackagedUnitRealization,
    revision: RevisionId,
    contexts: &[ResourceContext],
) -> Result<RenderedUnit> {
    if realization.schema != REALIZATION_SCHEMA {
        bail!("systemd realization uses an unsupported schema");
    }
    validate_unit_name(&realization.source.unit_name)?;
    validate_relative_path(&realization.source.unit_file)?;
    if !realization.source.unit_name.ends_with(".service")
        && (!realization.drop_in.accepted_exit_statuses.is_empty()
            || !realization.drop_in.search_path.is_empty())
    {
        bail!("service-only drop-in fields were supplied for a non-service unit");
    }
    if realization
        .drop_in
        .accepted_exit_statuses
        .iter()
        .any(|status| !(0..=255).contains(status))
    {
        bail!("accepted exit status is outside 0..=255");
    }

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

    let mut body = String::from("[Unit]\n");
    body.push_str("Documentation=");
    body.push_str(&receipt_uri(&realization.source.unit_name, revision));
    body.push('\n');
    append_references(
        &mut body,
        "After",
        &realization.dependencies.after,
        contexts,
    )?;
    append_references(
        &mut body,
        "Before",
        &realization.dependencies.before,
        contexts,
    )?;
    append_references(
        &mut body,
        "Requires",
        &realization.dependencies.requires,
        contexts,
    )?;
    append_references(
        &mut body,
        "Wants",
        &realization.dependencies.wants,
        contexts,
    )?;

    let search_path = search_path(&realization.drop_in.search_path)?;
    if !realization.drop_in.accepted_exit_statuses.is_empty() || !search_path.is_empty() {
        body.push_str("\n[Service]\n");
    }
    if !realization.drop_in.accepted_exit_statuses.is_empty() {
        body.push_str("SuccessExitStatus=");
        body.push_str(
            &realization
                .drop_in
                .accepted_exit_statuses
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        );
        body.push('\n');
    }
    if !search_path.is_empty() {
        body.push_str("Environment=\"PATH=");
        body.push_str(&search_path);
        body.push_str("\"\n");
    }

    Ok(RenderedUnit {
        source,
        drop_in: body.into_bytes(),
    })
}

fn checked_store_root(store_path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(store_path);
    if !path.is_absolute() || !store_path.starts_with("/nix/store/") {
        bail!("artifact reference has an invalid store path");
    }
    Ok(path)
}

fn search_path(artifacts: &[aos_ability_model::ArtifactReference]) -> Result<String> {
    let mut entries = BTreeSet::new();
    for artifact in artifacts {
        let root = checked_store_root(&artifact.store_path)?;
        entries.insert(root.join("bin").to_string_lossy().into_owned());
        entries.insert(root.join("sbin").to_string_lossy().into_owned());
    }
    Ok(entries.into_iter().collect::<Vec<_>>().join(":"))
}

fn append_references(
    body: &mut String,
    directive: &str,
    references: &[ResourceReference],
    contexts: &[ResourceContext],
) -> Result<()> {
    let mut units = BTreeSet::new();
    for reference in references {
        if let Some(unit) = unit_for_reference(reference, contexts)? {
            units.insert(unit);
        }
    }
    if !units.is_empty() {
        body.push_str(directive);
        body.push('=');
        body.push_str(&units.into_iter().collect::<Vec<_>>().join(" "));
        body.push('\n');
    }
    Ok(())
}

fn unit_for_reference(
    reference: &ResourceReference,
    contexts: &[ResourceContext],
) -> Result<Option<String>> {
    let matches = contexts
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("systemd dependency does not have one exact admitted context");
    }
    let context = matches[0];
    if native_context_digest(&context.native_context)? != context.native_context_digest {
        bail!("systemd dependency context digest does not match");
    }
    let bound: BoundNativeContext =
        serde_json::from_value(context.native_context.as_json().clone())
            .context("decoding dependency native context")?;
    if bound.schema != RESOURCE_CONTEXT_SCHEMA || bound.resource_spec.resource != reference.resource
    {
        bail!("systemd dependency context is bound to another resource");
    }

    let realization = bound.resource_spec.realization.as_json();
    let schema = realization
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let unit = realization
        .get("unit_name")
        .or_else(|| {
            realization
                .get("source")
                .and_then(|source| source.get("unit_name"))
        })
        .and_then(serde_json::Value::as_str);
    if schema.starts_with("aos.systemd.") && unit.is_none() {
        bail!("systemd dependency realization omits its checked unit name");
    }
    if let Some(unit) = unit {
        validate_unit_name(unit)?;
    }
    Ok(unit.map(str::to_owned))
}

pub(crate) fn receipt_uri(unit_name: &str, revision: RevisionId) -> String {
    format!(
        "file:/etc/aos/ability-revisions/{unit_name}/sha256/{}",
        revision.0.hex()
    )
}

#[cfg(test)]
mod tests {
    use super::{receipt_uri, validate_relative_path, validate_unit_name};
    use aos_ability_model::RevisionId;
    use aos_contract::Sha256Digest;

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
    fn receipt_uri_uses_the_full_revision() {
        let digest = Sha256Digest::parse(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("digest parses");
        let uri = receipt_uri("example.service", RevisionId(digest));
        assert!(uri.ends_with(&format!("/sha256/{}", digest.hex())));
    }
}

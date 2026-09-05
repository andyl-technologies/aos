//! Validation of transparency statements and their bound package metadata.

use crate::provenance::{builder_id as provenance_builder_id, digest_map as provenance_digest_map};
use crate::registry_ops::provenance::{
    PACKAGE_PROVENANCE_BUILD_TYPE, PACKAGE_PROVENANCE_PREDICATE_TYPE,
    PACKAGE_PROVENANCE_STATEMENT_TYPE, PackageProvenanceTransparencyLogBody,
    PackageProvenanceTransparencyLogEntry,
};
use crate::registry_ops::uki::sha256_hex;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::path::Path;

pub(in crate::registry_ops) fn validate_package_provenance_transparency_statement(
    entry: &PackageProvenanceTransparencyLogEntry,
    statement: &Value,
    registry_name: &str,
    key_id: &str,
) -> Result<()> {
    if entry.body.statement.path != entry.body.provenance {
        bail!(
            "package transparency log entry {} statement path '{}' does not match provenance '{}'",
            entry.body.sequence,
            entry.body.statement.path,
            entry.body.provenance
        );
    }
    ensure_json_string(
        statement,
        "_type",
        PACKAGE_PROVENANCE_STATEMENT_TYPE,
        "statement _type",
    )?;
    ensure_json_string(
        statement,
        "predicateType",
        PACKAGE_PROVENANCE_PREDICATE_TYPE,
        "statement predicateType",
    )?;

    let predicate = json_object(&statement, "predicate")?;
    let build_definition = json_object(predicate, "buildDefinition")?;
    let run_details = json_object(predicate, "runDetails")?;
    let builder = json_object(run_details, "builder")?;
    ensure_json_string(
        builder,
        "id",
        &provenance_builder_id(registry_name, key_id),
        "runDetails.builder.id",
    )?;
    ensure_json_string(
        build_definition,
        "buildType",
        PACKAGE_PROVENANCE_BUILD_TYPE,
        "statement buildType",
    )?;
    let params = json_object(build_definition, "externalParameters")?;
    ensure_json_string(
        params,
        "package",
        &entry.body.package,
        "externalParameters.package",
    )?;
    ensure_json_string(
        params,
        "version",
        &entry.body.version,
        "externalParameters.version",
    )?;
    ensure_json_string(
        params,
        "platform",
        &entry.body.platform,
        "externalParameters.platform",
    )?;
    ensure_json_string(
        params,
        "store_path",
        &entry.body.store_path,
        "externalParameters.store_path",
    )?;
    ensure_json_string(
        params,
        "root_digest",
        entry
            .body
            .root_digest
            .as_deref()
            .or(entry.body.root_hash.as_deref())
            .context("package transparency entry missing root_digest")?,
        "externalParameters.root_digest",
    )?;
    ensure_json_optional_string(
        params,
        "root_hash",
        entry.body.root_hash.as_deref(),
        "externalParameters.root_hash",
    )?;
    ensure_json_optional_string(
        params,
        "root_hash_sig",
        entry.body.root_hash_sig.as_deref(),
        "externalParameters.root_hash_sig",
    )?;
    ensure_json_string(
        params,
        "provenance",
        &entry.body.provenance,
        "externalParameters.provenance",
    )?;

    let package_subject = provenance_statement_named_object(
        json_array(statement, "subject")?,
        &entry.body.store_path,
    )
    .with_context(|| {
        format!(
            "locating package subject '{}' for transparency log entry {}",
            entry.body.store_path, entry.body.sequence
        )
    })?;
    ensure_json_value(
        package_subject,
        "digest",
        &provenance_digest_map(&entry.body.nar_hash),
        "package subject digest",
    )?;

    let manifest_subject_name = format!(
        "aos:permissions-manifest:{}:{}:{}",
        entry.body.package, entry.body.version, entry.body.platform
    );
    let manifest_subject = provenance_statement_named_object(
        json_array(statement, "subject")?,
        &manifest_subject_name,
    )
    .with_context(|| {
        format!(
            "locating permissions manifest subject '{}' for transparency log entry {}",
            manifest_subject_name, entry.body.sequence
        )
    })?;
    let manifest_digest = sha256_digest_from_statement_digest(
        manifest_subject.get("digest").with_context(|| {
            format!("permissions manifest subject '{manifest_subject_name}' missing digest")
        })?,
        "permissions manifest subject digest",
    )?;
    let expected_measurement = crate::package_attestation::package_measurement_digest(
        &entry.body.package,
        &entry.body.version,
        entry
            .body
            .root_digest
            .as_deref()
            .or(entry.body.root_hash.as_deref())
            .context("package transparency entry missing root_digest")?,
        &manifest_digest,
    );
    if expected_measurement != entry.body.measurement {
        bail!(
            "package transparency log entry {} measurement does not match permissions manifest digest",
            entry.body.sequence
        );
    }

    let measurement_subject_name = format!(
        "aos:package-measurement:{}:{}:{}",
        entry.body.package, entry.body.version, entry.body.platform
    );
    let measurement_subject = provenance_statement_named_object(
        json_array(statement, "subject")?,
        &measurement_subject_name,
    )
    .with_context(|| {
        format!(
            "locating measurement subject '{}' for transparency log entry {}",
            measurement_subject_name, entry.body.sequence
        )
    })?;
    ensure_json_value(
        measurement_subject,
        "digest",
        &provenance_digest_map(&entry.body.measurement),
        "measurement subject digest",
    )?;

    if let Some(source) = &entry.body.source {
        let source_uri = format!("nix:{}", source.store_path);
        let dependencies = json_array(build_definition, "resolvedDependencies")?;
        let dependency =
            provenance_statement_named_uri(dependencies, &source_uri).with_context(|| {
                format!(
                    "locating source dependency '{}' for transparency log entry {}",
                    source_uri, entry.body.sequence
                )
            })?;
        ensure_json_value(
            dependency,
            "digest",
            &provenance_digest_map(&source.nar_hash),
            "source dependency digest",
        )?;
    }

    Ok(())
}

fn provenance_statement_named_object<'a>(objects: &'a [Value], name: &str) -> Result<&'a Value> {
    let mut matches = objects.iter().filter(|object| {
        object
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|actual| actual == name)
    });
    let value = matches
        .next()
        .with_context(|| format!("provenance statement missing object named '{name}'"))?;
    if matches.next().is_some() {
        bail!("provenance statement has duplicate object named '{name}'");
    }
    Ok(value)
}

fn provenance_statement_named_uri<'a>(objects: &'a [Value], uri: &str) -> Result<&'a Value> {
    let mut matches = objects.iter().filter(|object| {
        object
            .get("uri")
            .and_then(Value::as_str)
            .is_some_and(|actual| actual == uri)
    });
    let value = matches
        .next()
        .with_context(|| format!("provenance statement missing dependency uri '{uri}'"))?;
    if matches.next().is_some() {
        bail!("provenance statement has duplicate dependency uri '{uri}'");
    }
    Ok(value)
}

fn json_object<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .filter(|value| value.is_object())
        .with_context(|| format!("provenance statement missing object field '{key}'"))
}

fn json_array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("provenance statement missing array field '{key}'"))
}

fn ensure_json_string(object: &Value, key: &str, expected: &str, label: &str) -> Result<()> {
    let actual = object
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("provenance statement missing string field '{label}'"))?;
    if actual != expected {
        bail!("provenance statement {label} mismatch: expected '{expected}', got '{actual}'");
    }
    Ok(())
}

fn ensure_json_optional_string(
    object: &Value,
    key: &str,
    expected: Option<&str>,
    label: &str,
) -> Result<()> {
    let actual = object.get(key).and_then(Value::as_str);
    if actual != expected {
        bail!(
            "provenance statement {label} mismatch: expected '{}', got '{}'",
            expected.unwrap_or("<absent>"),
            actual.unwrap_or("<absent>")
        );
    }
    Ok(())
}

fn ensure_json_value(object: &Value, key: &str, expected: &Value, label: &str) -> Result<()> {
    let actual = object
        .get(key)
        .with_context(|| format!("provenance statement missing field '{label}'"))?;
    if actual != expected {
        bail!("provenance statement {label} mismatch");
    }
    Ok(())
}

fn sha256_digest_from_statement_digest(digest: &Value, label: &str) -> Result<String> {
    let sha256 = digest
        .get("sha256")
        .and_then(Value::as_str)
        .with_context(|| format!("provenance statement {label} missing sha256"))?;
    if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("provenance statement {label} has invalid sha256 digest '{sha256}'");
    }
    Ok(format!("sha256:{}", sha256.to_ascii_lowercase()))
}

pub(in crate::registry_ops) fn ensure_safe_package_provenance_statement_path(
    path: &str,
) -> Result<()> {
    ensure_safe_git_jsonl_index_path(path)?;
    if !path.starts_with("provenance/") || !path.ends_with(".intoto.jsonl") {
        bail!(
            "package provenance statement path '{path}' must use the generated provenance/*.intoto.jsonl layout"
        );
    }
    Ok(())
}

pub(in crate::registry_ops) fn ensure_safe_git_jsonl_index_path(path: &str) -> Result<()> {
    ensure_safe_git_index_path(path)?;
    if !path.ends_with(".jsonl") {
        bail!("package provenance statement path '{path}' must be a relative *.jsonl path");
    }
    Ok(())
}

pub(in crate::registry_ops) fn ensure_safe_git_index_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("git index path '{path}' must be relative and must not contain revspec punctuation");
    }
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) if !part.is_empty() => {}
            _ => {
                bail!(
                    "package provenance statement path '{path}' must not contain '.', '..', or prefixes"
                );
            }
        }
    }
    Ok(())
}

pub(in crate::registry_ops) fn package_provenance_transparency_entry_hash(
    body: &PackageProvenanceTransparencyLogBody,
) -> Result<String> {
    let payload = serde_json::to_vec(body)
        .context("serializing package transparency log entry body for hashing")?;
    Ok(format!("sha256:{}", sha256_hex(&payload)))
}

#[cfg(test)]
mod tests;

//! Package catalog TOML construction and platform metadata recording.
//!
//! Catalog entries are stored by package bucket and name:
//!
//! ```text
//! packages/<bucket>/<name>.toml
//!   [package]                    package identity
//!   [[versions]]                 one published version
//!   [versions.platforms.<name>]  per-platform artifact bindings
//! ```

use crate::registry_ops::images::PublishedImage;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::types::{FEATURE_IMAGE_ARTIFACT_CONTRACT_V1, PACKAGE_META_FORMAT};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeSet, HashSet};

/// Build package TOML content, merging with existing content if present.
///
/// A fresh file is rendered through the TOML value serializer; an existing
/// file is parsed and the version/platform entry is upserted, preserving
/// unrelated versions and platforms. Panics if an existing `versions` array
/// entry is not a table.
#[allow(clippy::too_many_arguments)]
pub(in crate::registry_ops) fn build_package_toml(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    image_infos: &[PublishedImage],
    source_info: Option<&StorePathInfo>,
) -> Result<String> {
    let desc = description.context("package description is required")?;
    let lic = license.context("package license is required")?;
    let maint = maintainer.context("package maintainer is required")?;
    let source_drv = source_info
        .map(|source| source.path.as_str())
        .unwrap_or_default();
    let source_nar_hash = source_info
        .map(|source| source.nar_hash.as_str())
        .unwrap_or_default();
    let mut platform_table =
        package_platform_table(info, image_infos, source_drv, source_nar_hash)?;
    if sysroot {
        let table = platform_table
            .as_table_mut()
            .context("new sysroot platform metadata is not a TOML table")?;
        record_feature_gate(table, FEATURE_IMAGE_ARTIFACT_CONTRACT_V1)?;
    }
    if existing.is_empty() {
        let mut package = toml::map::Map::new();
        package.insert("name".into(), toml::Value::String(name.to_string()));
        package.insert("description".into(), toml::Value::String(desc.to_string()));
        if sysroot {
            package.insert("sysroot".into(), toml::Value::Boolean(true));
        }
        if let Some(hp) = homepage {
            package.insert("homepage".into(), toml::Value::String(hp.to_string()));
        }
        package.insert("license".into(), toml::Value::String(lic.to_string()));
        package.insert("maintainer".into(), toml::Value::String(maint.to_string()));

        let mut version_table = toml::map::Map::new();
        version_table.insert("version".into(), toml::Value::String(version.to_string()));
        if let Some(prev) = previous {
            version_table.insert("previous".into(), toml::Value::String(prev.to_string()));
        }
        let mut platforms = toml::map::Map::new();
        platforms.insert(platform.to_string(), platform_table);
        version_table.insert("platforms".into(), toml::Value::Table(platforms));

        let mut root = toml::map::Map::new();
        root.insert("package".into(), toml::Value::Table(package));
        root.insert(
            "versions".into(),
            toml::Value::Array(vec![toml::Value::Table(version_table)]),
        );
        Ok(toml::to_string_pretty(&toml::Value::Table(root))?)
    } else {
        // Parse existing, add/update the version+platform entry.
        let mut toml_val: toml::Value =
            toml::from_str(existing).context("parsing existing package TOML")?;

        // Metadata describes the package across versions. Explicit values on
        // a later publication replace stale catalog values as well as the
        // historical placeholders emitted by older clients.
        if let Some(pkg) = toml_val.get_mut("package").and_then(|v| v.as_table_mut()) {
            if let Some(description) = description {
                pkg.insert(
                    "description".into(),
                    toml::Value::String(description.to_string()),
                );
            }
            if let Some(homepage) = homepage {
                pkg.insert("homepage".into(), toml::Value::String(homepage.to_string()));
            }
            if let Some(license) = license {
                pkg.insert("license".into(), toml::Value::String(license.to_string()));
            }
            if let Some(maintainer) = maintainer {
                pkg.insert(
                    "maintainer".into(),
                    toml::Value::String(maintainer.to_string()),
                );
            }
            if sysroot {
                pkg.insert("sysroot".into(), toml::Value::Boolean(true));
            }
        }

        // Ensure versions array exists.
        let versions = toml_val.get_mut("versions").and_then(|v| v.as_array_mut());

        if let Some(versions) = versions {
            // Find existing version entry.
            let existing_idx = versions.iter().position(|v| {
                v.get("version")
                    .and_then(|ver| ver.as_str())
                    .map(|ver| ver == version)
                    .unwrap_or(false)
            });

            if let Some(idx) = existing_idx {
                // Update existing version entry.
                let ver_entry = &mut versions[idx];
                let ver_table = ver_entry
                    .as_table_mut()
                    .context("existing package versions entry is not a TOML table")?;
                if let Some(prev) = previous {
                    ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
                }
                let platforms = ver_table
                    .entry("platforms")
                    .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
                platforms
                    .as_table_mut()
                    .context("existing package platforms metadata is not a TOML table")?
                    .insert(platform.to_string(), platform_table);
            } else {
                // Add new version entry.
                let mut ver_table = toml::map::Map::new();
                ver_table.insert("version".into(), toml::Value::String(version.to_string()));
                if let Some(prev) = previous {
                    ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
                }
                let mut platforms = toml::map::Map::new();
                platforms.insert(platform.to_string(), platform_table);
                ver_table.insert("platforms".into(), toml::Value::Table(platforms));
                versions.push(toml::Value::Table(ver_table));
            }
        } else {
            // No versions array yet - add one.
            let mut ver_table = toml::map::Map::new();
            ver_table.insert("version".into(), toml::Value::String(version.to_string()));
            if let Some(prev) = previous {
                ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
            }
            let mut platforms = toml::map::Map::new();
            platforms.insert(platform.to_string(), platform_table);
            ver_table.insert("platforms".into(), toml::Value::Table(platforms));

            toml_val
                .as_table_mut()
                .context("existing package metadata root is not a TOML table")?
                .insert(
                    "versions".into(),
                    toml::Value::Array(vec![toml::Value::Table(ver_table)]),
                );
        }

        Ok(toml::to_string_pretty(&toml_val)?)
    }
}

/// Records one non-`out` derivation output beside an authored platform entry.
///
/// Supplemental outputs retain their own store-graph roots without replacing
/// the installable output or duplicating package documentation and provenance.
///
/// # Errors
///
/// Returns an error when the output identity is invalid, the exact package
/// coordinate is absent, or an existing output name is bound to another path.
pub(crate) fn record_named_output(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    output: &str,
    store_path: &str,
) -> Result<String> {
    if output == "out"
        || output.is_empty()
        || output.len() > 256
        || !output
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        bail!("invalid supplemental Nix output name '{output}'");
    }
    if !store_path.starts_with("/nix/store/") {
        bail!("invalid supplemental store path '{store_path}'");
    }

    let mut document: toml::Value =
        toml::from_str(existing).context("parsing package TOML for supplemental output")?;
    let package_name = document
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .context("package TOML is missing package.name")?;
    if package_name != name {
        bail!("package TOML name '{package_name}' does not match '{name}'");
    }

    let versions = document
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .context("package TOML is missing versions")?;
    let mut matching_versions = versions.iter_mut().filter(|candidate| {
        candidate.get("version").and_then(toml::Value::as_str) == Some(version)
    });
    let version_entry = matching_versions
        .next()
        .with_context(|| format!("package {name} is missing version {version}"))?;
    if matching_versions.next().is_some() {
        bail!("package {name} repeats version {version}");
    }

    let platform_entry = version_entry
        .get_mut("platforms")
        .and_then(toml::Value::as_table_mut)
        .and_then(|platforms| platforms.get_mut(platform))
        .and_then(toml::Value::as_table_mut)
        .with_context(|| format!("package {name} {version} is missing platform {platform}"))?;
    platform_entry
        .get("store_path")
        .and_then(toml::Value::as_str)
        .context("package platform entry is missing store_path")?;

    let named_outputs = platform_entry
        .entry("named_outputs")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .context("package platform named_outputs is not a table")?;
    if let Some(previous) = named_outputs
        .get(output)
        .and_then(|value| value.get("store_path"))
        .and_then(toml::Value::as_str)
        && previous != store_path
    {
        bail!("package {name} {version} {platform} output {output} is already bound to {previous}");
    }
    let metadata = named_outputs
        .entry(output.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    metadata
        .as_table_mut()
        .context("named output metadata is not a table")?
        .insert(
            "store_path".to_string(),
            toml::Value::String(store_path.to_string()),
        );

    toml::to_string_pretty(&document).context("serializing package TOML with supplemental output")
}

/// Records native artifacts and declaration-derived resolution metadata with their feature gate.
///
/// # Errors
/// Returns an error when the exact package coordinate is missing or malformed,
/// an artifact locator is invalid, or feature gates cannot be merged.
pub(crate) fn record_native_artifacts(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    deployment: &crate::types::NativeArtifactMeta,
    documentation: Option<&crate::types::NativeArtifactMeta>,
    qualification: Option<&crate::types::NativeArtifactMeta>,
    version_requirement: Option<&str>,
    os_version: Option<&str>,
    dependencies: &[crate::deployment::model::ModuleDependency],
) -> Result<String> {
    aos_registry_surface::native_dependencies::check_version_requirement(
        version,
        version_requirement,
    )?;
    aos_registry_surface::native_dependencies::check_resolution_metadata(os_version, dependencies)?;
    deployment.validate()?;
    if let Some(documentation) = documentation {
        documentation.validate()?;
    }
    if let Some(qualification) = qualification {
        qualification.validate()?;
    }
    let mut document: toml::Value = toml::from_str(existing)?;
    if document
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        != Some(name)
    {
        bail!("native artifact package coordinate differs from catalog");
    }
    let entry = document
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .and_then(|versions| {
            versions.iter_mut().find(|candidate| {
                candidate.get("version").and_then(toml::Value::as_str) == Some(version)
            })
        })
        .and_then(|version| version.get_mut("platforms"))
        .and_then(toml::Value::as_table_mut)
        .and_then(|platforms| platforms.get_mut(platform))
        .and_then(toml::Value::as_table_mut)
        .with_context(|| format!("package {name} {version} is missing platform {platform}"))?;
    entry.insert("deployment".into(), toml::Value::try_from(deployment)?);
    if let Some(requirement) = version_requirement {
        entry.insert(
            "version_requirement".into(),
            toml::Value::String(requirement.into()),
        );
    } else {
        entry.remove("version_requirement");
    }
    if let Some(requirement) = os_version {
        entry.insert("osVersion".into(), toml::Value::String(requirement.into()));
    } else {
        entry.remove("osVersion");
    }
    if dependencies.is_empty() {
        entry.remove("module_dependencies");
    } else {
        entry.insert(
            "module_dependencies".into(),
            toml::Value::try_from(dependencies)?,
        );
    }
    if let Some(documentation) = documentation {
        entry.insert(
            "module_documentation".into(),
            toml::Value::try_from(documentation)?,
        );
    } else {
        entry.remove("module_documentation");
    }
    if let Some(qualification) = qualification {
        entry.insert(
            "qualification".into(),
            toml::Value::try_from(qualification)?,
        );
    } else {
        entry.remove("qualification");
    }
    // Republishing the native coordinate retires the former projection.
    entry.remove("documentation");
    entry.remove("contract");
    let features = BTreeSet::from([crate::types::FEATURE_NATIVE_PACKAGE_MODULES_V1.to_string()]);
    merge_feature_gate(entry, "requires-features", &features)?;
    merge_minimum_format(entry, "platform")?;
    let references = entry.remove("references");
    let mut gate = match references {
        Some(toml::Value::Table(gate)) => gate,
        Some(toml::Value::Array(hashes)) => {
            toml::map::Map::from_iter([("hashes".into(), toml::Value::Array(hashes))])
        }
        None => toml::map::Map::new(),
        Some(_) => bail!("platform references metadata is malformed"),
    };
    merge_feature_gate(&mut gate, "requires-features", &features)?;
    merge_minimum_format(&mut gate, "native references")?;
    entry.insert("references".into(), toml::Value::Table(gate));
    toml::to_string_pretty(&document).context("encoding native package catalog entry")
}

fn merge_feature_gate(
    table: &mut toml::map::Map<String, toml::Value>,
    key: &str,
    additions: &BTreeSet<String>,
) -> Result<()> {
    let values = table
        .entry(key)
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .with_context(|| format!("{key} metadata is not an array"))?;
    let mut merged = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("{key} contains a non-string feature"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    merged.extend(additions.iter().cloned());
    *values = merged.into_iter().map(toml::Value::String).collect();
    Ok(())
}

fn merge_minimum_format(
    table: &mut toml::map::Map<String, toml::Value>,
    label: &str,
) -> Result<()> {
    let existing = match table.get("min-format") {
        Some(value) => {
            let value = value
                .as_integer()
                .with_context(|| format!("{label} min-format metadata is not an integer"))?;
            u32::try_from(value)
                .with_context(|| format!("{label} min-format metadata is outside the u32 range"))?
        }
        None => 0,
    };
    let required = existing.max(PACKAGE_META_FORMAT);
    table.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(required)),
    );
    Ok(())
}

/// Preserves structural gates while declaring a newly authored registry feature.
///
/// # Errors
/// Rejects malformed feature arrays, reference tables, or format declarations.
pub(super) fn record_feature_gate(
    platform: &mut toml::map::Map<String, toml::Value>,
    feature: &str,
) -> Result<()> {
    let features = BTreeSet::from([feature.to_string()]);
    merge_feature_gate(platform, "requires-features", &features)?;
    merge_minimum_format(platform, "package platform")?;

    // The table representation makes readers that predate structural feature
    // gates reject the package before they can stage its payload.
    let prior_references = platform.remove("references");
    let mut reference_gate = match prior_references {
        Some(toml::Value::Array(hashes)) => {
            let mut gate = toml::map::Map::new();
            gate.insert("hashes".into(), toml::Value::Array(hashes));
            gate
        }
        Some(toml::Value::Table(gate)) => gate,
        Some(_) => bail!("package references metadata is neither a hash list nor a gate table"),
        None => {
            let mut gate = toml::map::Map::new();
            gate.insert("hashes".into(), toml::Value::Array(Vec::new()));
            gate
        }
    };
    merge_feature_gate(&mut reference_gate, "requires-features", &features)?;
    merge_minimum_format(&mut reference_gate, "package references")?;
    platform.insert("references".into(), toml::Value::Table(reference_gate));
    Ok(())
}

fn package_platform_table(
    info: &StorePathInfo,
    image_infos: &[PublishedImage],
    source_drv: &str,
    source_nar_hash: &str,
) -> Result<toml::Value> {
    let mut table = toml::map::Map::new();
    table.insert("store_path".into(), toml::Value::String(info.path.clone()));
    // No nar_hash/nar_size/references here: the output's content binding and
    // dependency edges live in the store/ realisation graph (RFC-0005), the
    // single authority. Sources and images keep their hashes below - they sit
    // outside the runtime closure the graph covers.
    table.insert(
        "closure_size".into(),
        toml::Value::Integer(info.closure_size as i64),
    );
    table.insert(
        "source_drv".into(),
        toml::Value::String(source_drv.to_string()),
    );
    table.insert(
        "source_nar_hash".into(),
        toml::Value::String(source_nar_hash.to_string()),
    );

    if !image_infos.is_empty() {
        let mut formats = HashSet::new();
        let first = &image_infos[0].delivery;
        for image in image_infos {
            image.recheck_for_commit()?;
            if !formats.insert(image.format.as_str()) {
                bail!(
                    "duplicate '{}' image encoding in one platform publication",
                    image.format
                );
            }
            if image.delivery.logical_image_id != first.logical_image_id
                || image.delivery.artifact_contract.schema != first.artifact_contract.schema
                || image.delivery.artifact_contract.artifacts != first.artifact_contract.artifacts
            {
                bail!(
                    "all image encodings in one platform publication must share one logical disk and artifact contract"
                );
            }
        }
        let images = image_infos
            .iter()
            .map(|image| {
                let mut entry = toml::map::Map::new();
                entry.insert("format".into(), toml::Value::String(image.format.clone()));
                entry.insert(
                    "store_path".into(),
                    toml::Value::String(image.store.path.clone()),
                );
                entry.insert(
                    "nar_hash".into(),
                    toml::Value::String(image.store.nar_hash.clone()),
                );
                let nar_size = i64::try_from(image.store.nar_size)
                    .context("image NAR size exceeds signed TOML integer range")?;
                entry.insert("nar_size".into(), toml::Value::Integer(nar_size));
                let delivery = toml::Value::try_from(&image.delivery)
                    .context("serializing image delivery contract")?;
                entry.insert("delivery".into(), delivery);
                Ok(toml::Value::Table(entry))
            })
            .collect::<Result<Vec<_>>>()?;
        table.insert("images".into(), toml::Value::Array(images));
    }

    Ok(toml::Value::Table(table))
}

#[cfg(test)]
mod tests;

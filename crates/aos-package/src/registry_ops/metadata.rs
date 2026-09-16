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
use crate::registry_ops::provenance::bind_documentation_provenance;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::types::{
    AttestationMeta, DocumentationArtifactMeta, FEATURE_ABILITIES_V1, FEATURE_ATTESTATION_V1,
    FEATURE_IMAGE_ARTIFACT_CONTRACT_V1, FEATURE_PACKAGE_DOCUMENTATION_V1, PACKAGE_META_FORMAT,
    PackageContractMeta, validate_attestation_meta, validate_documentation_artifact_meta,
};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeSet, HashSet};

/// Build package TOML content, merging with existing content if present.
///
/// A fresh file is rendered through the TOML value serializer; an existing
/// file is parsed and the version/platform entry is upserted, preserving
/// unrelated versions and platforms. Panics if an existing `versions` array
/// entry is not a table.
#[allow(clippy::too_many_arguments)]
pub(in crate::registry_ops) fn build_package_toml_with_documentation(
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
    documentation: Option<&DocumentationArtifactMeta>,
    documentation_attestation: Option<&AttestationMeta>,
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
        record_image_artifact_contract_gate(table)?;
    }
    if let Some(documentation) = documentation {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_documentation_platform_fields(table, documentation)?;
    }
    if let Some(attestation) = documentation_attestation {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_attestation_platform_fields(table, attestation)?;
    }
    if let Some(documentation) = documentation {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        let measurement = table
            .get("measurement")
            .and_then(toml::Value::as_str)
            .context("documented package platform is missing its measurement")?;
        let attestation = bind_documentation_provenance(
            AttestationMeta {
                root_digest: table
                    .get("root_digest")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                root_hash: table
                    .get("root_hash")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                root_hash_sig: table
                    .get("root_hash_sig")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                provenance: None,
                measurement: Some(measurement.to_string()),
            },
            name,
            platform,
            documentation,
        )?;
        table.insert(
            "provenance".into(),
            toml::Value::String(
                attestation
                    .provenance
                    .context("documented attestation is missing provenance")?,
            ),
        );
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
    if let Some(previous) = named_outputs.get(output).and_then(toml::Value::as_str)
        && previous != store_path
    {
        bail!("package {name} {version} {platform} output {output} is already bound to {previous}");
    }
    named_outputs.insert(
        output.to_string(),
        toml::Value::String(store_path.to_string()),
    );

    toml::to_string_pretty(&document).context("serializing package TOML with supplemental output")
}

/// Records an authenticated package contract and its fail-closed feature gates.
///
/// # Errors
///
/// Returns an error when the package coordinate is absent, contract metadata
/// is invalid, or structural reference gates cannot be merged safely.
pub(crate) fn record_package_contract(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    contract: &PackageContractMeta,
    package_document: &aos_ability_model::PackageDocument,
) -> Result<String> {
    crate::package_contract::validate_package_contract_meta(contract)?;
    let mut document: toml::Value =
        toml::from_str(existing).context("parsing package TOML for package contract")?;
    let platform_entry = document
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

    let features = package_document
        .required_features
        .iter()
        .map(|feature| feature.as_str().to_string())
        .collect::<BTreeSet<_>>();
    if !features.contains(FEATURE_ABILITIES_V1) {
        bail!(
            "package {name} {version} contract does not declare its authenticated ability feature"
        );
    }
    merge_feature_gate(platform_entry, "requires-features", &features)?;
    merge_minimum_format(platform_entry, "platform")?;

    let prior_references = platform_entry.remove("references");
    let mut reference_gate = match prior_references {
        Some(toml::Value::Array(hashes)) => {
            let mut gate = toml::map::Map::new();
            gate.insert("hashes".into(), toml::Value::Array(hashes));
            gate
        }
        Some(toml::Value::Table(gate)) => gate,
        Some(_) => bail!("platform references metadata is neither a hash list nor a gate table"),
        None => {
            let mut gate = toml::map::Map::new();
            gate.insert("hashes".into(), toml::Value::Array(Vec::new()));
            gate
        }
    };
    merge_feature_gate(&mut reference_gate, "requires-features", &features)?;
    merge_minimum_format(&mut reference_gate, "platform references")?;
    platform_entry.insert("references".into(), toml::Value::Table(reference_gate));
    platform_entry.insert(
        "contract".into(),
        toml::Value::try_from(contract).context("serializing package contract metadata")?,
    );

    toml::to_string_pretty(&document).context("serializing package TOML with package contract")
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

fn record_image_artifact_contract_gate(
    platform: &mut toml::map::Map<String, toml::Value>,
) -> Result<()> {
    let features = BTreeSet::from([FEATURE_IMAGE_ARTIFACT_CONTRACT_V1.to_string()]);
    merge_feature_gate(platform, "requires-features", &features)?;
    merge_minimum_format(platform, "sysroot platform")?;

    // The table representation makes readers that predate structural feature
    // gates reject the sysroot before they can stage its image payload.
    let prior_references = platform.remove("references");
    let mut reference_gate = match prior_references {
        Some(toml::Value::Array(hashes)) => {
            let mut gate = toml::map::Map::new();
            gate.insert("hashes".into(), toml::Value::Array(hashes));
            gate
        }
        Some(toml::Value::Table(gate)) => gate,
        Some(_) => bail!("sysroot references metadata is neither a hash list nor a gate table"),
        None => {
            let mut gate = toml::map::Map::new();
            gate.insert("hashes".into(), toml::Value::Array(Vec::new()));
            gate
        }
    };
    merge_feature_gate(&mut reference_gate, "requires-features", &features)?;
    merge_minimum_format(&mut reference_gate, "sysroot references")?;
    platform.insert("references".into(), toml::Value::Table(reference_gate));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn build_package_toml(
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
    build_package_toml_with_documentation(
        existing,
        name,
        version,
        platform,
        info,
        description,
        homepage,
        license,
        maintainer,
        sysroot,
        previous,
        image_infos,
        source_info,
        None,
        None,
    )
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

fn record_documentation_platform_fields(
    table: &mut toml::map::Map<String, toml::Value>,
    documentation: &DocumentationArtifactMeta,
) -> Result<()> {
    validate_documentation_artifact_meta(documentation)
        .context("validating package documentation metadata for publish")?;
    let feature = toml::Value::String(FEATURE_PACKAGE_DOCUMENTATION_V1.to_string());
    let features = table
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("platform requires-features metadata is not an array")?;
    if !features.contains(&feature) {
        features.push(feature.clone());
    }
    table.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );

    let references = table
        .entry("references")
        .or_insert_with(|| {
            let mut references = toml::map::Map::new();
            references.insert("hashes".into(), toml::Value::Array(Vec::new()));
            toml::Value::Table(references)
        })
        .as_table_mut()
        .context("platform references metadata is not a table")?;
    references.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );
    let reference_features = references
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("platform references requires-features metadata is not an array")?;
    if !reference_features.contains(&feature) {
        reference_features.push(feature);
    }
    table.insert(
        "documentation".into(),
        toml::Value::try_from(documentation)
            .context("serializing package documentation metadata")?,
    );
    Ok(())
}

fn record_attestation_platform_fields(
    table: &mut toml::map::Map<String, toml::Value>,
    attestation: &AttestationMeta,
) -> Result<()> {
    validate_attestation_meta(attestation)?;
    let feature = toml::Value::String(FEATURE_ATTESTATION_V1.to_string());
    for key in ["requires-features"] {
        let features = table
            .entry(key)
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .with_context(|| format!("platform {key} metadata is not an array"))?;
        if !features.contains(&feature) {
            features.push(feature.clone());
        }
    }
    let references = table
        .get_mut("references")
        .and_then(toml::Value::as_table_mut)
        .context("attested platform is missing structural references metadata")?;
    let reference_features = references
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("platform references requires-features metadata is not an array")?;
    if !reference_features.contains(&feature) {
        reference_features.push(feature);
    }
    if let Some(root_digest) = &attestation.root_digest {
        table.insert(
            "root_digest".into(),
            toml::Value::String(root_digest.clone()),
        );
    }
    if let Some(root_hash) = &attestation.root_hash {
        table.insert("root_hash".into(), toml::Value::String(root_hash.clone()));
    }
    if let Some(root_hash_sig) = &attestation.root_hash_sig {
        table.insert(
            "root_hash_sig".into(),
            toml::Value::String(root_hash_sig.clone()),
        );
    }
    table.insert(
        "provenance".into(),
        toml::Value::String(
            attestation
                .provenance
                .clone()
                .context("config-module attestation is missing provenance")?,
        ),
    );
    table.insert(
        "measurement".into(),
        toml::Value::String(
            attestation
                .measurement
                .clone()
                .context("config-module attestation is missing measurement")?,
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests;

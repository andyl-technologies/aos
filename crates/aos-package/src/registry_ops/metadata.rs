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

use crate::registry_ops::attestation::publish_attestation_meta;
use crate::registry_ops::images::PublishedImage;
use crate::registry_ops::mac::PublishExposeManifest;
use crate::registry_ops::provenance::bind_documentation_provenance;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::types::{
    AttestationMeta, ConfigModuleMeta, DocumentationArtifactMeta, ExposeArtifactMeta,
    FEATURE_ATTESTATION_V1, FEATURE_CAPABILITY_ROUTES_V1, FEATURE_CONFIG_MODULE_V1,
    FEATURE_CONFIG_V1, FEATURE_EBPF_NET_POLICY_V1, FEATURE_EXPOSE_ARTIFACT_V1, FEATURE_EXPOSE_V1,
    FEATURE_MAC_PROFILE_V1, FEATURE_NETWORK_POLICY_V1, FEATURE_OPTIONAL_CREDENTIALS_V1,
    FEATURE_PACKAGE_DOCUMENTATION_V1, FEATURE_PERMISSIONS_V1, FEATURE_RECOVERY_UKIS_V1,
    FEATURE_RELOAD_V1, FEATURE_REQUIRES_V1, FEATURE_UKI_SLOTS_V1, PACKAGE_META_FORMAT,
    validate_attestation_meta, validate_config_module_meta, validate_documentation_artifact_meta,
    validate_expose_artifact_meta,
};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fs;

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
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact_info: Option<&StorePathInfo>,
    expose_manifest_digest: Option<&str>,
    config_module: Option<&ConfigModuleMeta>,
    config_attestation: Option<&AttestationMeta>,
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
    let mut platform_table = package_platform_table(
        name,
        version,
        platform,
        info,
        image_infos,
        source_drv,
        source_nar_hash,
        expose_manifest,
        expose_artifact_info,
        expose_manifest_digest,
    )?;
    if let Some(documentation) = documentation {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_documentation_platform_fields(table, documentation)?;
    }
    if let Some(module) = config_module {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_config_module_platform_fields(table, name, module)?;
        record_attestation_platform_fields(
            table,
            config_attestation
                .context("config-module package is missing its publish provenance attestation")?,
        )?;
    } else if let Some(attestation) = documentation_attestation {
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
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact_info: Option<&StorePathInfo>,
    expose_manifest_digest: Option<&str>,
    config_module: Option<&ConfigModuleMeta>,
    config_attestation: Option<&AttestationMeta>,
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
        expose_manifest,
        expose_artifact_info,
        expose_manifest_digest,
        config_module,
        config_attestation,
        None,
        None,
    )
}

fn package_platform_table(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    image_infos: &[PublishedImage],
    source_drv: &str,
    source_nar_hash: &str,
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact_info: Option<&StorePathInfo>,
    expose_manifest_digest: Option<&str>,
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
        let first = &image_infos[0];
        for image in image_infos {
            image.recheck_for_commit()?;
            if !formats.insert(image.format.as_str()) {
                bail!(
                    "duplicate '{}' image encoding in one platform publication",
                    image.format
                );
            }
            if image.delivery.logical_image_id != first.delivery.logical_image_id
                || image.delivery.uki != first.delivery.uki
                || image.sb.signer_cert_sha256 != first.sb.signer_cert_sha256
                || image.sb.sbat != first.sb.sbat
                || image.sb.expected_pcr11 != first.sb.expected_pcr11
            {
                bail!(
                    "all image encodings in one platform publication must share one logical disk and UKI identity"
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
                if let Some(cert) = &image.sb.signer_cert_sha256 {
                    entry.insert(
                        "sb_signer_cert_sha256".into(),
                        toml::Value::String(cert.clone()),
                    );
                }
                if !image.sb.sbat.is_empty() {
                    let sbat = image
                        .sb
                        .sbat
                        .iter()
                        .map(|item| {
                            let mut row = toml::map::Map::new();
                            row.insert(
                                "component".into(),
                                toml::Value::String(item.component.clone()),
                            );
                            row.insert(
                                "generation".into(),
                                toml::Value::Integer(i64::from(item.generation)),
                            );
                            toml::Value::Table(row)
                        })
                        .collect::<Vec<_>>();
                    entry.insert("sbat".into(), toml::Value::Array(sbat));
                }
                if let Some(pcr11) = &image.sb.expected_pcr11 {
                    entry.insert("expected_pcr11".into(), toml::Value::String(pcr11.clone()));
                }
                if !image.sb.ukis.is_empty() {
                    entry.insert(
                        "ukis".into(),
                        toml::Value::try_from(&image.sb.ukis)
                            .context("serializing slot-specific UKI facts")?,
                    );
                }
                if !image.sb.recovery_ukis.is_empty() {
                    entry.insert(
                        "recovery_ukis".into(),
                        toml::Value::try_from(&image.sb.recovery_ukis)
                            .context("serializing recovery UKI facts")?,
                    );
                }
                if let Some(bundle) = &image.sb.recovery_bundle {
                    entry.insert(
                        "recovery_bundle".into(),
                        toml::Value::try_from(bundle)
                            .context("serializing recovery bundle manifest")?,
                    );
                }
                let root_image = image.directory.path.join("root.img");
                let root_verity = image.directory.path.join("root.verity");
                let root_hash = image.directory.path.join("root.roothash");
                let root_hash_sig = image.directory.path.join("root.roothash.p7s");
                // Recovery UKIs are only valid with the complete A/B verity
                // payload, including when its distributable disk encoding is
                // `raw`. Ordinary raw disk images may contain unrelated files
                // with these names and must not acquire a verity contract.
                let catalogs_verity =
                    matches!(image.format.as_str(), "ext4-verity" | "erofs-verity")
                        || !image.sb.recovery_ukis.is_empty();
                if catalogs_verity {
                    let verity_count = [&root_image, &root_verity, &root_hash, &root_hash_sig]
                        .iter()
                        .filter(|path| path.is_file())
                        .count();
                    if verity_count != 4 {
                        bail!("published image has an incomplete dm-verity artifact set");
                    }

                    let hash = fs::read_to_string(&root_hash)?;
                    let hash = hash.trim();
                    if hash.len() != 64
                        || !hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        bail!("published image has a malformed root.roothash");
                    }
                    entry.insert("root_image".into(), toml::Value::String("root.img".into()));
                    entry.insert(
                        "root_verity".into(),
                        toml::Value::String("root.verity".into()),
                    );
                    entry.insert(
                        "root_hash".into(),
                        toml::Value::String(format!("sha256:{hash}")),
                    );
                    entry.insert(
                        "root_hash_sig".into(),
                        toml::Value::String("root.roothash.p7s".into()),
                    );
                }
                Ok(toml::Value::Table(entry))
            })
            .collect::<Result<Vec<_>>>()?;
        table.insert("images".into(), toml::Value::Array(images));
        if image_infos.iter().any(|image| !image.sb.ukis.is_empty()) {
            let feature = toml::Value::String(FEATURE_UKI_SLOTS_V1.to_string());
            let features = table
                .entry("requires-features")
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .context("platform requires-features metadata is not an array")?;
            if !features.contains(&feature) {
                features.push(feature);
            }
            table.insert(
                "min-format".into(),
                toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
            );
        }
        if image_infos
            .iter()
            .any(|image| !image.sb.recovery_ukis.is_empty())
        {
            let feature = toml::Value::String(FEATURE_RECOVERY_UKIS_V1.to_string());
            let features = table
                .entry("requires-features")
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .context("platform requires-features metadata is not an array")?;
            if !features.contains(&feature) {
                features.push(feature);
            }
            table.insert(
                "min-format".into(),
                toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
            );
        }
    }

    if let Some(manifest) = expose_manifest {
        let artifact = expose_artifact_info
            .context("expose manifest requires rendered expose artifact metadata")?;
        let attestation = publish_attestation_meta(
            name,
            version,
            platform,
            info,
            manifest,
            expose_manifest_digest,
        )
        .with_context(|| format!("deriving package attestation metadata for package '{name}'"))?;
        table.insert(
            "min-format".into(),
            toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
        );
        let mut required_features = vec![
            toml::Value::String(FEATURE_EXPOSE_V1.to_string()),
            toml::Value::String(FEATURE_EXPOSE_ARTIFACT_V1.to_string()),
            toml::Value::String(FEATURE_PERMISSIONS_V1.to_string()),
            toml::Value::String(FEATURE_NETWORK_POLICY_V1.to_string()),
        ];
        if !manifest.expose.requires.is_empty() {
            required_features.push(toml::Value::String(FEATURE_REQUIRES_V1.to_string()));
        }
        if !manifest.expose.config.is_empty() {
            required_features.push(toml::Value::String(FEATURE_CONFIG_V1.to_string()));
        }
        if manifest.expose.config.has_optional_credentials() {
            required_features.push(toml::Value::String(
                FEATURE_OPTIONAL_CREDENTIALS_V1.to_string(),
            ));
        }
        if manifest.expose.config.has_unit_reconciliation() {
            required_features.push(toml::Value::String(FEATURE_RELOAD_V1.to_string()));
        }
        if !manifest.expose.provides.is_empty() || !manifest.expose.uses.is_empty() {
            required_features.push(toml::Value::String(
                FEATURE_CAPABILITY_ROUTES_V1.to_string(),
            ));
        }
        let ebpf_unit = format!("aos-pkg-{name}-ebpf.service");
        if manifest.expose.units.iter().any(|unit| unit == &ebpf_unit) {
            required_features.push(toml::Value::String(FEATURE_EBPF_NET_POLICY_V1.to_string()));
        }
        if manifest.mac.is_some() {
            required_features.push(toml::Value::String(FEATURE_MAC_PROFILE_V1.to_string()));
        }
        if attestation.is_some() {
            required_features.push(toml::Value::String(FEATURE_ATTESTATION_V1.to_string()));
        }
        table.insert(
            "requires-features".into(),
            toml::Value::Array(required_features.clone()),
        );
        let mut references = toml::map::Map::new();
        references.insert("hashes".into(), toml::Value::Array(Vec::new()));
        references.insert(
            "min-format".into(),
            toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
        );
        references.insert(
            "requires-features".into(),
            toml::Value::Array(required_features.clone()),
        );
        table.insert("references".into(), toml::Value::Table(references));
        table.insert(
            "expose".into(),
            toml::Value::try_from(&manifest.expose)
                .context("serializing expose manifest metadata")?,
        );
        let artifact = ExposeArtifactMeta {
            store_path: artifact.path.clone(),
            nar_hash: artifact.nar_hash.clone(),
            nar_size: artifact.nar_size,
        };
        validate_expose_artifact_meta(&artifact)?;
        table.insert(
            "expose_artifact".into(),
            toml::Value::try_from(&artifact).context("serializing expose artifact metadata")?,
        );
        table.insert(
            "permissions".into(),
            toml::Value::try_from(&manifest.permissions)
                .context("serializing permissions manifest metadata")?,
        );
        if let Some(attestation) = attestation {
            if let Some(root_digest) = attestation.root_digest {
                table.insert("root_digest".into(), toml::Value::String(root_digest));
            }
            if let Some(root_hash) = attestation.root_hash {
                table.insert("root_hash".into(), toml::Value::String(root_hash));
            }
            if let Some(root_hash_sig) = attestation.root_hash_sig {
                table.insert("root_hash_sig".into(), toml::Value::String(root_hash_sig));
            }
            if let Some(provenance) = attestation.provenance {
                table.insert("provenance".into(), toml::Value::String(provenance));
            }
            table.insert(
                "measurement".into(),
                toml::Value::String(
                    attestation
                        .measurement
                        .context("package attestation measurement missing")?,
                ),
            );
        }
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

/// Records a `config_module` block and its fail-closed format gates.
///
/// # Errors
///
/// Returns an error when the package name or `module` metadata is malformed,
/// including when a declaration escapes the package's private, owned, and
/// contributed roots, or when TOML serialization fails.
pub(crate) fn record_config_module_platform_fields(
    table: &mut toml::map::Map<String, toml::Value>,
    package_name: &str,
    module: &ConfigModuleMeta,
) -> Result<()> {
    validate_config_module_meta(package_name, module)
        .context("validating config-module metadata for publish")?;
    let feature = toml::Value::String(FEATURE_CONFIG_MODULE_V1.to_string());
    let required_features_value = table
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let required_features = required_features_value
        .as_array_mut()
        .context("platform requires-features metadata is not an array")?;
    if !required_features.contains(&feature) {
        required_features.push(feature.clone());
    }
    table.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );
    let references_value = table.entry("references").or_insert_with(|| {
        let mut references = toml::map::Map::new();
        references.insert("hashes".into(), toml::Value::Array(Vec::new()));
        toml::Value::Table(references)
    });
    let references = references_value
        .as_table_mut()
        .context("platform references metadata is not a table")?;
    references.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );
    let reference_features_value = references
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let reference_features = reference_features_value
        .as_array_mut()
        .context("platform references requires-features metadata is not an array")?;
    if !reference_features.contains(&feature) {
        reference_features.push(feature);
    }
    table.insert(
        "config_module".into(),
        toml::Value::try_from(module).context("serializing config-module metadata")?,
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
        .context("config-module platform is missing structural references metadata")?;
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

//! Package publication orchestration and its exclusive authoring-clone lock.

use crate::config::ApmConfig;
use crate::provenance::ProvenanceSigner;
use crate::registry::parse::ImageVerificationState;
use crate::registry::sb_certs::SbCertsToml;
use crate::registry::{objectstore, sb_certs, store};
use crate::registry_ops::attestation::{
    publish_config_attestation_meta, publish_documentation_attestation_meta,
};
use crate::registry_ops::config::{
    format_size, read_registry_toml, registry_content_addressed, resolve_registry_name,
};
use crate::registry_ops::config_modules::{
    parse_config_dependency_outputs, read_publish_config_module,
};
use crate::registry_ops::documentation::{
    derive_system_documentation, publish_package_documentation,
};
use crate::registry_ops::git::{
    commit_registry_paths, current_git_head, refresh_registry_object_store,
};
use crate::registry_ops::images::{PublishedImage, inspect_published_image};
use crate::registry_ops::mac::{
    infer_publish_expose_artifact, read_publish_expose_manifest, read_publish_manifest_digest,
};
use crate::registry_ops::metadata::build_package_toml_with_documentation;
use crate::registry_ops::provenance::{
    append_package_provenance_transparency_log, bind_documentation_provenance,
    publish_config_provenance_artifact_with_documentation,
    publish_documentation_provenance_artifact, publish_provenance_artifact_with_documentation,
    resolve_package_provenance_signer, validate_external_provenance_signer,
};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::store_paths::{
    first_letter, introspect_deriver, introspect_store_path, parse_store_path,
    resolve_publish_platform, validate_store_path_release_policy, write_store_files,
};
use crate::registry_ops::uki::sb_db_cert_path;
use crate::registry_ops::workflow::{current_git_branch, git_branch_entries};
use crate::types::{validate_package_name, validate_registry_name};
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// `apr publish <STORE_PATH>` — records a built Nix store path in the
/// registry.
///
/// Introspects the store path (NAR hash and size, closure size, direct
/// references, and the source derivation when known), writes or merges the
/// entry in `packages/<letter>/<name>.toml`, and regenerates the closure
/// adjacency file under `closures/`. Unless `--no-commit` is set, the
/// touched paths are committed (SSH-signed when `--key`/`--key-id` is
/// given) and the dumb-HTTP object store is refreshed.
///
/// Package name and version are parsed from the store path basename and can
/// be overridden. Platform is read from the output's AOS target-platform
/// marker, falling back to the producer's native platform for legacy outputs;
/// `--platform` may override only an unstamped output or agree with its stamp.
/// `--image-payload`, `--image-disk`,
/// `--image-info`, `--image-format`, and `--image-uki` groups attach explicit
/// cache artifacts and their exact canonical UKI to the platform entry;
/// `--sysroot` marks
/// the package as a system root, `--previous` records the predecessor
/// version for delta upgrades, and `--source-drv` records explicit source
/// provenance for prebuilt binaries whose deriver is not visible to Nix.
/// `--expose-manifest` records the RFC-0001 expose and permission metadata
/// rendered by the package builder. Exposed packages also emit DSSE-wrapped
/// provenance, so they must be published with `--key-id`; a raw `--key` has
/// no stable roster id for the DSSE builder identity.
///
/// `--config-module` publishes the package's config-only companion output.
/// `--config-base-lib` is required with it and records the exact options
/// library used by the restricted, no-IFD options-only evaluation. The signed
/// provenance binds the payload, config output, base lib, and (when present)
/// expose manifest in one statement.
/// `--documentation-base-lib` additionally extracts image-owned service
/// options selected by the base library's canonical Nix service catalog. It
/// changes documentation only and never grants package configuration authority.
///
/// # Errors
///
/// Fails when required package distribution metadata is missing, empty, or a
/// legacy placeholder; when the registry has no writable authoring clone;
/// when the package name is not safe for registry package paths; when the
/// platform name is not safe for package metadata; when the image arguments are not
/// given in triples or their files/metadata disagree, when the `nix path-info` /
/// `nix-store` queries fail for the store path, when `--expose-manifest`
/// cannot be parsed or validated, when the config output references a
/// derivation, when authored config metadata disagrees with the mechanically
/// evaluated/scanned interface, or when a file write, the commit, or the
/// object-store refresh fails. Policy-bearing internal components also fail
/// when published directly, and aggregate roots fail unless their restricted
/// component and corresponding source are direct runtime references.
///
#[allow(clippy::too_many_arguments)]
pub async fn publish(
    config: &ApmConfig,
    store_path: &str,
    name_override: Option<&str>,
    version_override: Option<&str>,
    platform_override: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    source_drv: Option<&str>,
    image_payload_paths: &[String],
    image_disk_paths: &[String],
    image_info_paths: &[String],
    image_formats: &[String],
    image_uki_paths: &[String],
    expose_manifest_path: Option<&str>,
    config_module_path: Option<&str>,
    config_base_lib_path: Option<&str>,
    documentation_base_lib_path: Option<&str>,
    config_dependencies: &[String],
    bless: bool,
    no_ca: bool,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let registry_dir = config.scope.registries_path().join(&registry_name);

    publish_to_registry_directory(
        config,
        &registry_dir,
        &registry_name,
        store_path,
        name_override,
        version_override,
        platform_override,
        description,
        homepage,
        license,
        maintainer,
        sysroot,
        previous,
        source_drv,
        image_payload_paths,
        image_disk_paths,
        image_info_paths,
        image_formats,
        image_uki_paths,
        expose_manifest_path,
        config_module_path,
        config_base_lib_path,
        documentation_base_lib_path,
        config_dependencies,
        bless,
        no_ca,
        no_commit,
        message,
        key,
        key_id,
        None,
        printer,
    )
    .await
}

/// Publishes one store output into an explicitly selected registry directory.
///
/// This is the package-materialization primitive used by an isolated release
/// transaction. The ordinary CLI resolves its configured authoring clone
/// before entering this function; release orchestration instead supplies its
/// private clone. Callers must hold the appropriate outer transaction lock.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_to_registry_directory(
    config: &ApmConfig,
    dir: &Path,
    name: &str,
    store_path: &str,
    name_override: Option<&str>,
    version_override: Option<&str>,
    platform_override: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    source_drv: Option<&str>,
    image_payload_paths: &[String],
    image_disk_paths: &[String],
    image_info_paths: &[String],
    image_formats: &[String],
    image_uki_paths: &[String],
    expose_manifest_path: Option<&str>,
    config_module_path: Option<&str>,
    config_base_lib_path: Option<&str>,
    documentation_base_lib_path: Option<&str>,
    config_dependencies: &[String],
    bless: bool,
    no_ca: bool,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    external_provenance_signer: Option<&mut dyn ProvenanceSigner>,
    printer: &Printer,
) -> Result<()> {
    let description = required_publish_metadata(description, "--description", "No description")?;
    let license = required_publish_metadata(license, "--license", "unknown")?;
    let maintainer = required_publish_metadata(maintainer, "--maintainer", "unknown")?;

    validate_registry_name(name)?;
    ensure_writable_registry_clone(name, dir)?;
    let require_signed_ukis =
        read_registry_toml(dir)?.is_some_and(|root| root.registry.require_signed_ukis);
    if let Some(name) = name_override {
        validate_package_name(name)?;
    }
    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config, dir, name, key, key_id,
        )?)
    } else {
        None
    };

    // Validate explicit image artifact groups.
    if image_payload_paths.len() != image_disk_paths.len()
        || image_payload_paths.len() != image_info_paths.len()
        || image_payload_paths.len() != image_formats.len()
        || image_payload_paths.len() != image_uki_paths.len()
    {
        bail!(
            "--image-payload, --image-disk, --image-info, --image-format, and --image-uki must be specified in groups ({} payloads, {} disks, {} metadata files, {} formats, {} UKIs)",
            image_payload_paths.len(),
            image_disk_paths.len(),
            image_info_paths.len(),
            image_formats.len(),
            image_uki_paths.len()
        );
    }
    if config_module_path.is_some() != config_base_lib_path.is_some() {
        bail!("--config-module and --config-base-lib must be specified together");
    }
    if config_module_path.is_none() && !config_dependencies.is_empty() {
        bail!("--config-dependency requires --config-module");
    }
    if !image_payload_paths.is_empty() && !sysroot {
        bail!("image artifact options are valid only with --sysroot");
    }

    printer.step(1, 4, "Introspecting store path...");
    let info = introspect_store_path(store_path)?;
    validate_store_path_release_policy(&info)?;
    let source_info = if let Some(source_drv) = source_drv {
        Some(
            introspect_store_path(source_drv)
                .with_context(|| format!("introspecting source derivation {source_drv}"))?,
        )
    } else {
        introspect_deriver(&info.path)?
    };

    let (parsed_name, parsed_version) = parse_store_path(&info.path);
    let pkg_name = name_override.unwrap_or(&parsed_name);
    let pkg_version = version_override.unwrap_or(&parsed_version);
    validate_package_name(pkg_name)?;
    let platform = resolve_publish_platform(&info.path, platform_override)?;
    let config_module_info = config_module_path
        .map(introspect_store_path)
        .transpose()
        .context("introspecting config-module store path")?;
    let config_base_lib_info = config_base_lib_path
        .map(introspect_store_path)
        .transpose()
        .context("introspecting config base-lib")?;
    let documentation_base_lib_info = documentation_base_lib_path
        .map(introspect_store_path)
        .transpose()
        .context("introspecting documentation base-lib")?;
    let config_dependency_outputs = parse_config_dependency_outputs(config_dependencies, &info)?;
    let config_module_bundle = match (config_module_info.as_ref(), config_base_lib_info.as_ref()) {
        (Some(output), Some(base_lib)) => Some(read_publish_config_module(
            output,
            base_lib,
            pkg_name,
            &info.path,
            &config_dependency_outputs,
        )?),
        (None, None) => None,
        _ => bail!("--config-module and --config-base-lib must be specified together"),
    };
    let config_module = config_module_bundle.as_ref().map(|bundle| &bundle.metadata);
    let system_documentation = documentation_base_lib_info
        .map(|base_lib| derive_system_documentation(base_lib, pkg_name))
        .transpose()?
        .flatten();
    // Bind the exact disk, canonical per-format metadata, and paired UKI
    // before catalog construction. Committed Secure Boot policy is enforced
    // below.
    let sb_db_cert = sb_db_cert_path(config, name);
    let mut image_infos: Vec<PublishedImage> = Vec::new();
    for ((((payload_path, disk_path), info_path), img_fmt), uki_path) in image_payload_paths
        .iter()
        .zip(image_disk_paths.iter())
        .zip(image_info_paths.iter())
        .zip(image_formats.iter())
        .zip(image_uki_paths.iter())
    {
        let payload_info = introspect_store_path(payload_path)?;
        let disk_info = introspect_store_path(disk_path)?;
        let metadata_info = introspect_store_path(info_path)?;
        image_infos.push(inspect_published_image(
            img_fmt,
            payload_info,
            disk_info,
            metadata_info,
            Path::new(uki_path),
            pkg_name,
            pkg_version,
            &platform,
            sb_db_cert.as_deref(),
        )?);
    }
    let sb_catalog = sb_certs::load_sb_certs_toml(dir)?;
    apply_publish_sb_policy(
        &mut image_infos,
        sb_catalog.as_ref(),
        sb_db_cert.is_some(),
        require_signed_ukis,
    )?;
    let expose_manifest = expose_manifest_path
        .map(|path| read_publish_expose_manifest(path, pkg_name))
        .transpose()?;
    let expose_artifact_info = expose_manifest_path
        .map(infer_publish_expose_artifact)
        .transpose()?;
    let expose_manifest_digest = expose_manifest_path
        .map(|path| read_publish_manifest_digest(Path::new(path)))
        .transpose()?;
    let documentation_declarations = config_module_bundle
        .as_ref()
        .into_iter()
        .flat_map(|bundle| bundle.declarations.iter().cloned())
        .chain(
            system_documentation
                .as_ref()
                .into_iter()
                .flat_map(|surface| surface.declarations.iter().cloned()),
        )
        .collect::<Vec<_>>();
    let documentation = publish_package_documentation(
        pkg_name,
        pkg_version,
        &platform,
        description,
        homepage,
        license,
        &info,
        source_info.as_ref(),
        config_module,
        config_module_bundle.as_ref().map(|bundle| &bundle.authored),
        system_documentation.as_ref(),
        expose_manifest.as_ref(),
        expose_artifact_info.as_ref(),
        &documentation_declarations,
    )?;
    let mut local_provenance_signer;
    let provenance_signer: &mut dyn ProvenanceSigner =
        if let Some(signer) = external_provenance_signer {
            validate_external_provenance_signer(dir, signer)?;
            signer
        } else {
            local_provenance_signer =
                resolve_package_provenance_signer(dir, name, signing_key.as_ref(), key_id)?;
            &mut local_provenance_signer
        };

    let _publish_lock = RegistryPublishLock::acquire(&dir)?;

    printer.step(2, 4, "Writing package TOML...");
    let letter = first_letter(pkg_name);
    let pkg_dir = dir.join("packages").join(&letter);
    std::fs::create_dir_all(&pkg_dir)?;

    let toml_path = pkg_dir.join(format!("{pkg_name}.toml"));

    // Read existing TOML if it exists, or create a new one.
    let content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        String::new()
    };

    let config_attestation = config_module
        .map(|module| {
            publish_config_attestation_meta(
                pkg_name,
                pkg_version,
                &platform,
                &info,
                module,
                expose_manifest_digest.as_deref(),
            )
        })
        .transpose()?
        .map(|attestation| {
            bind_documentation_provenance(attestation, pkg_name, &platform, &documentation.metadata)
        })
        .transpose()?;
    let documentation_attestation = if config_module.is_none() && expose_manifest.is_none() {
        Some(bind_documentation_provenance(
            publish_documentation_attestation_meta(pkg_name, pkg_version, &platform, &info)?,
            pkg_name,
            &platform,
            &documentation.metadata,
        )?)
    } else {
        None
    };
    let new_content = build_package_toml_with_documentation(
        &content,
        pkg_name,
        pkg_version,
        &platform,
        &info,
        Some(description),
        homepage,
        Some(license),
        Some(maintainer),
        sysroot,
        previous,
        &image_infos,
        source_info.as_ref(),
        expose_manifest.as_ref(),
        expose_artifact_info.as_ref(),
        expose_manifest_digest.as_deref(),
        config_module,
        config_attestation.as_ref(),
        Some(&documentation.metadata),
        documentation_attestation.as_ref(),
    )?;
    let provenance_artifact =
        if let (Some(module), Some(attestation)) = (config_module, config_attestation.as_ref()) {
            Some(
                publish_config_provenance_artifact_with_documentation(
                    &name,
                    pkg_name,
                    pkg_version,
                    &platform,
                    &info,
                    source_info.as_ref(),
                    module,
                    expose_manifest_digest.as_deref(),
                    attestation,
                    &documentation.metadata,
                    provenance_signer,
                )
                .await?,
            )
        } else {
            match (expose_manifest.as_ref(), expose_manifest_digest.as_deref()) {
                (Some(manifest), Some(manifest_digest)) => {
                    publish_provenance_artifact_with_documentation(
                        &name,
                        pkg_name,
                        pkg_version,
                        &platform,
                        &info,
                        source_info.as_ref(),
                        manifest,
                        manifest_digest,
                        &documentation.metadata,
                        provenance_signer,
                    )
                    .await?
                }
                _ => Some(
                    publish_documentation_provenance_artifact(
                        &name,
                        pkg_name,
                        pkg_version,
                        &platform,
                        &info,
                        source_info.as_ref(),
                        &documentation.metadata,
                        documentation_attestation.as_ref().context(
                            "documentation-only package is missing attestation metadata",
                        )?,
                        provenance_signer,
                    )
                    .await?,
                ),
            }
        };

    std::fs::write(&toml_path, &new_content)?;
    let provenance_path = if let Some(artifact) = &provenance_artifact {
        let path = dir.join(&artifact.path);
        let parent = path
            .parent()
            .with_context(|| format!("provenance path has no parent: {}", path.display()))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating provenance directory {}", parent.display()))?;
        std::fs::write(&path, &artifact.jsonl)
            .with_context(|| format!("writing provenance artifact {}", path.display()))?;
        Some(path)
    } else {
        None
    };

    printer.step(3, 4, "Computing realisation graph...");
    let content_addressed = registry_content_addressed(&dir) && !no_ca;
    let store_report = write_store_files(&dir, &info.path, content_addressed, bless, printer)
        .with_context(|| format!("writing store/ realisation graph for {}", info.path))?;
    let mut image_store_reports = Vec::with_capacity(image_infos.len() * 3);
    for image in &image_infos {
        for artifact in [&image.payload, &image.store, &image.info_store] {
            image_store_reports.push(
                write_store_files(&dir, &artifact.path, content_addressed, bless, printer)
                    .with_context(|| {
                        format!("writing store/ realisation graph for {}", artifact.path)
                    })?,
            );
        }
    }
    let expose_store_report = if let Some(artifact) = &expose_artifact_info {
        Some(
            write_store_files(&dir, &artifact.path, content_addressed, bless, printer)
                .with_context(|| {
                    format!(
                        "writing store/ realisation graph for expose artifact {}",
                        artifact.path
                    )
                })?,
        )
    } else {
        None
    };
    let config_store_report = if let Some(output) = &config_module_info {
        Some(
            write_store_files(&dir, &output.path, content_addressed, bless, printer).with_context(
                || {
                    format!(
                        "writing store/ realisation graph for config module {}",
                        output.path
                    )
                },
            )?,
        )
    } else {
        None
    };
    let documentation_store_report = write_store_files(
        &dir,
        &documentation.info.path,
        content_addressed,
        bless,
        printer,
    )
    .with_context(|| {
        format!(
            "writing store/ realisation graph for documentation {}",
            documentation.info.path
        )
    })?;
    let transparency_log_path = if let Some(artifact) = &provenance_artifact {
        let provenance_file_path = provenance_path
            .as_ref()
            .context("provenance artifact path missing before transparency log append")?;
        Some(append_package_provenance_transparency_log(
            &dir,
            pkg_name,
            pkg_version,
            &platform,
            &info,
            source_info.as_ref(),
            artifact,
            provenance_file_path,
        )?)
    } else {
        None
    };

    printer.step(4, 4, "Done.");
    printer.kv("Package", pkg_name);
    printer.kv("Version", pkg_version);
    printer.kv("Platform", &platform);
    printer.kv("Store path", &info.path);
    printer.kv("NAR hash", &info.nar_hash);
    printer.kv("NAR size", &format_size(info.nar_size));
    printer.kv("Closure size", &format_size(info.closure_size));
    printer.kv("Store graph", &store_report.summary());
    for (index, report) in image_store_reports.iter().enumerate() {
        printer.kv(
            &format!("Image artifact graph {}", index + 1),
            &report.summary(),
        );
    }
    if let Some(artifact) = &expose_artifact_info {
        printer.kv("Expose artifact", &artifact.path);
    }
    if let Some(report) = &expose_store_report {
        printer.kv("Expose artifact graph", &report.summary());
    }
    if let Some(output) = &config_module_info {
        printer.kv("Config module", &output.path);
    }
    if let Some(report) = &config_store_report {
        printer.kv("Config module graph", &report.summary());
    }
    printer.kv("Documentation", &documentation.info.path);
    printer.kv("Documentation graph", &documentation_store_report.summary());
    if let Some(artifact) = &provenance_artifact {
        printer.kv("Provenance", &artifact.path);
    }
    if let Some(path) = &transparency_log_path {
        printer.kv(
            "Transparency log",
            &path
                .strip_prefix(&dir)
                .unwrap_or(path)
                .display()
                .to_string(),
        );
    }
    if let Some(source_info) = &source_info {
        printer.kv("Source drv", &source_info.path);
    }
    if sysroot {
        printer.kv("Sysroot", "true");
    }
    if let Some(prev) = previous {
        printer.kv("Previous", prev);
    }
    for image in &image_infos {
        printer.kv(&format!("Image ({})", image.format), &image.store.path);
        printer.kv("  File", &image.delivery.filename);
        printer.kv("  SHA-256", &image.delivery.sha256);
        if let Some(cert) = &image.sb.signer_cert_sha256 {
            printer.kv(&format!("  SB signer cert ({})", image.format), cert);
        }
    }

    let mut committed = false;
    let mut commit_message = None;
    if !no_commit {
        let default_msg = format!("publish {pkg_name} {pkg_version} ({platform})");
        let msg = message.unwrap_or(&default_msg);
        let mut staged_paths = vec![toml_path.clone(), dir.join(store::STORE_DIR)];
        if let Some(path) = &provenance_path {
            staged_paths.push(path.clone());
        }
        if let Some(path) = &transparency_log_path {
            staged_paths.push(path.clone());
        }
        commit_registry_paths(
            &dir,
            msg,
            &staged_paths,
            signing_key.as_ref().map(|k| k.path()),
        )?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after publish")?;
        committed = true;
        commit_message = Some(msg.to_string());
        printer.success(&format!("Committed: {msg}"));
    } else {
        printer.info("Skipped commit (--no-commit).");
    }

    if printer.mode() == OutputMode::Json {
        let source = source_info.as_ref().map(|source| {
            serde_json::json!({
                "store_path": source.path.as_str(),
                "nar_hash": source.nar_hash.as_str(),
                "nar_size": source.nar_size,
            })
        });
        let images = image_infos
            .iter()
            .map(|image| {
                serde_json::json!({
                    "format": image.format.as_str(),
                    "store_path": image.store.path.as_str(),
                    "nar_hash": image.store.nar_hash.as_str(),
                    "nar_size": image.store.nar_size,
                    "delivery": &image.delivery,
                    "sb_signer_cert_sha256": image.sb.signer_cert_sha256,
                    "sbat": image.sb.sbat.iter().map(|item| serde_json::json!({
                        "component": item.component,
                        "generation": item.generation,
                    })).collect::<Vec<_>>(),
                    "expected_pcr11": image.sb.expected_pcr11,
                    "ukis": image.sb.ukis,
                    "recovery_ukis": image.sb.recovery_ukis,
                    "recovery_bundle": image.sb.recovery_bundle,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!({
            "action": "publish",
            "registry": name,
            "package": pkg_name,
            "version": pkg_version,
            "platform": platform,
            "store_path": info.path,
            "nar_hash": info.nar_hash,
            "nar_size": info.nar_size,
            "closure_size": info.closure_size,
            "store_graph": {
                "created": store_report.created,
                "blessed": store_report.blessed,
                "unchanged": store_report.unchanged,
                "content_addressed": store_report.content_addressed,
            },
            "expose_artifact": expose_artifact_info.as_ref().map(|artifact| serde_json::json!({
                "store_path": artifact.path.as_str(),
                "nar_hash": artifact.nar_hash.as_str(),
                "nar_size": artifact.nar_size,
            })),
            "expose_artifact_graph": expose_store_report.as_ref().map(|report| serde_json::json!({
                "created": report.created,
                "blessed": report.blessed,
                "unchanged": report.unchanged,
                "content_addressed": report.content_addressed,
            })),
            "provenance": provenance_artifact.as_ref().map(|artifact| artifact.path.as_str()),
            "transparency_log": transparency_log_path.as_ref().map(|path| {
                path.strip_prefix(&dir)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            }),
            "references": info.references,
            "source": source,
            "sysroot": sysroot,
            "previous": previous,
            "images": images,
            "package_file": toml_path
                .strip_prefix(&dir)
                .unwrap_or(&toml_path)
                .display()
                .to_string(),
            "committed": committed,
            "commit_message": commit_message,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
        }));
    }

    Ok(())
}

/// Materializes one canonical package-platform entry without committing it.
///
/// This is the narrow bridge used by an isolated registry release transaction.
/// It deliberately exposes neither producer key paths nor ordinary authoring
/// clone discovery; provenance is supplied by the caller's external adapter.
///
/// # Errors
///
/// Returns an error when package introspection, metadata validation,
/// provenance signing, documentation generation, or store-graph authoring
/// fails.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_canonical_release_entry(
    config: &ApmConfig,
    dir: &Path,
    registry: &str,
    store_path: &str,
    package: &str,
    version: &str,
    platform: &str,
    description: &str,
    homepage: Option<&str>,
    license: &str,
    maintainer: &str,
    provenance_signer: &mut dyn ProvenanceSigner,
    printer: &Printer,
) -> Result<()> {
    publish_to_registry_directory(
        config,
        dir,
        registry,
        store_path,
        Some(package),
        Some(version),
        Some(platform),
        Some(description),
        homepage,
        Some(license),
        Some(maintainer),
        false,
        None,
        None,
        &[],
        &[],
        &[],
        &[],
        &[],
        None,
        None,
        None,
        None,
        &[],
        false,
        false,
        true,
        None,
        None,
        None,
        Some(provenance_signer),
        printer,
    )
    .await
}

/// Returns required package distribution metadata after rejecting historical
/// placeholders that do not describe a package.
fn required_publish_metadata<'a>(
    value: Option<&'a str>,
    flag: &str,
    legacy_placeholder: &str,
) -> Result<&'a str> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{flag} is required and must not be empty"))?;
    if value.eq_ignore_ascii_case(legacy_placeholder) {
        bail!(
            "{flag} must describe the package, not use the legacy placeholder '{legacy_placeholder}'"
        );
    }
    Ok(value)
}

/// Validates metadata for the optional package attached to a release plan.
pub(in crate::registry_ops) fn validate_release_publish_metadata(
    store_path: Option<&str>,
    description: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
) -> Result<()> {
    if store_path.is_some() {
        required_publish_metadata(description, "--description", "No description")?;
        required_publish_metadata(license, "--license", "unknown")?;
        required_publish_metadata(maintainer, "--maintainer", "unknown")?;
    }
    Ok(())
}

/// Requires an authenticated roster identity for a package-bearing release.
pub(in crate::registry_ops) fn validate_release_publish_signing_identity(
    store_path: Option<&str>,
    key_id: Option<&str>,
) -> Result<()> {
    if store_path.is_some() && key_id.is_none() {
        bail!(
            "releasing a store path requires --key-id so package provenance is tied to keys.toml"
        );
    }
    Ok(())
}

fn apply_publish_sb_policy(
    images: &mut [PublishedImage],
    catalog: Option<&SbCertsToml>,
    has_db_cert: bool,
    require_signed_ukis: bool,
) -> Result<()> {
    for image in images {
        if require_signed_ukis {
            if image.sb.signer_cert_sha256.is_none()
                || image
                    .sb
                    .ukis
                    .iter()
                    .any(|uki| uki.sb_signer_cert_sha256.is_none())
            {
                bail!(
                    "registry [registry] require_signed_ukis = true refuses unsigned UKIs in '{}' image",
                    image.format
                );
            }
            if catalog.is_none() {
                bail!(
                    "registry [registry] require_signed_ukis = true requires a committed sb-certs.toml policy"
                );
            }
            if !has_db_cert {
                bail!(
                    "registry [registry] require_signed_ukis = true requires the matching registry sb-certs/db.pem for publish-time verification"
                );
            }
        }

        let signers = image
            .sb
            .signer_cert_sha256
            .iter()
            .map(String::as_str)
            .chain(
                image
                    .sb
                    .ukis
                    .iter()
                    .filter_map(|uki| uki.sb_signer_cert_sha256.as_deref()),
            );
        let signers = signers.chain(
            image
                .sb
                .recovery_ukis
                .iter()
                .map(|uki| uki.sb_signer_cert_sha256.as_str()),
        );
        for signer in signers {
            if let Some(catalog) = catalog {
                if !catalog.accepts_signer(signer) {
                    bail!(
                        "image UKI signer {signer} is not active in the committed sb-certs.toml policy"
                    );
                }
                if !has_db_cert {
                    bail!(
                        "committed Secure Boot policy requires the matching registry db.pem for publish-time verification"
                    );
                }
            }
        }
        if image.sb.signer_cert_sha256.is_some() && catalog.is_some() {
            image.delivery.uki.verification = ImageVerificationState::PolicyVerified;
        }
    }
    Ok(())
}

/// Require `dir` to be a git authoring clone; consumer-extracted registry
/// trees (plain files synced by `apm update`) cannot host publish commits
/// and are rejected with remediation steps.
pub(in crate::registry_ops) fn ensure_writable_registry_clone(
    name: &str,
    dir: &Path,
) -> Result<()> {
    if dir.join(".git").is_dir() {
        return Ok(());
    }

    bail!(
        "registry '{name}' has no writable local clone at {path}.\n\
         `{pkg} update --registry {name}` only syncs consumer metadata; it cannot create an \
         APR publishing worktree.\n\
         To publish, remove and re-add the registry without `--no-clone`, or author a new \
         local registry with `{reg} create {name}`.",
        path = dir.display(),
        reg = aos_core::invocation::package_registry_command(),
        pkg = aos_core::invocation::package_manager_command(),
    );
}

/// Exclusive on-disk lock (`.git/apr-publish.lock`) serializing publication
/// critical sections that update append-only registry state.
pub(in crate::registry_ops) struct RegistryPublishLock {
    pub(in crate::registry_ops) path: PathBuf,
    pub(in crate::registry_ops) owned: bool,
}

impl RegistryPublishLock {
    pub(in crate::registry_ops) fn acquire(dir: &Path) -> Result<Self> {
        Self::acquire_inner(dir, false)
    }

    pub(in crate::registry_ops) fn acquire_or_join_current_process(dir: &Path) -> Result<Self> {
        Self::acquire_inner(dir, true)
    }

    pub(in crate::registry_ops) fn acquire_inner(
        dir: &Path,
        join_current_process: bool,
    ) -> Result<Self> {
        let git_dir = objectstore::repo_git_dir(dir)?;
        let path = git_dir.join("apr-publish.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .or_else(|err| {
                if join_current_process && err.kind() == std::io::ErrorKind::AlreadyExists {
                    let content = fs::read_to_string(&path)?;
                    if content
                        .lines()
                        .any(|line| line.trim() == format!("pid={}", std::process::id()))
                    {
                        return Ok(OpenOptions::new().read(true).open(&path)?);
                    }
                }
                Err(err)
            })
            .with_context(|| {
                format!(
                    "acquiring publish lock {}; another publisher may be running",
                    path.display()
                )
            })?;
        let owned = file
            .metadata()
            .map(|metadata| metadata.len() == 0)
            .unwrap_or(false);
        if !owned {
            return Ok(Self { path, owned });
        }
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self { path, owned })
    }
}

impl Drop for RegistryPublishLock {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests;

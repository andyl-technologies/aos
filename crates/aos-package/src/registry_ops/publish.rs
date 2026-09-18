//! Package publication orchestration and its exclusive authoring-clone lock.

use crate::config::ApmConfig;
use crate::package_contract::{
    PackageContractCoordinate, ability_provenance_statement, canonical_nar_hash,
    contract_retention_digest,
};
use crate::provenance::{ProvenanceSigner, sign_statement_dsse_jsonl_external};
use crate::registry::parse::parse_package_file;
use crate::registry::{objectstore, store};
use crate::registry_ops::attestation::publish_documentation_attestation_meta;
use crate::registry_ops::config::{format_size, registry_content_addressed, resolve_registry_name};
use crate::registry_ops::documentation::publish_package_documentation;
use crate::registry_ops::git::{
    commit_registry_paths, current_git_head, refresh_registry_object_store,
};
use crate::registry_ops::images::{PublishedImage, inspect_published_image};
use crate::registry_ops::metadata::{
    build_package_toml, record_named_output, record_package_contract, record_package_documentation,
};
use crate::registry_ops::package_contract::{
    PackageContractSelectorRegistry, resolve_release_projection, resolve_store_artifact,
};
use crate::registry_ops::package_contract_transparency::append_package_contract_transparency_log;
use crate::registry_ops::provenance::{
    append_package_provenance_transparency_log, bind_documentation_provenance,
    publish_documentation_provenance_artifact, validate_external_provenance_signer,
};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::registry_ops::store_paths::{
    first_letter, introspect_deriver, introspect_store_path, parse_store_path,
    resolve_publish_platform, validate_store_path_release_policy, write_store_files,
};
use crate::registry_ops::workflow::{current_git_branch, git_branch_entries};
use crate::types::{
    PackageContractDocumentMeta, PackageContractMeta, validate_package_name, validate_registry_name,
};
use anyhow::{Context, Result, bail};
use aos_ability_model::VersionedDocument;
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use std::collections::BTreeSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// `apr publish <STORE_PATH>` — records a built Nix store path in the
/// registry.
///
/// Ordinary package publication selects the exact primary output from the
/// target's evaluated derivation inventory. Package metadata, generated
/// documentation, named outputs, and any package contract are authored from
/// that one record and committed atomically with the complete realization
/// graph.
///
/// Manual metadata, source overrides, and `--no-commit` apply only to sysroot
/// image entries. `--image-payload`, `--image-disk`,
/// `--image-info`, `--image-format`, and `--image-contract-schema` groups attach
/// disk bytes and an opaque provider-owned artifact contract to the platform entry;
/// `--sysroot` marks the package as a system root, and `--previous` records the
/// predecessor version for delta upgrades.
///
/// # Errors
///
/// Fails when the requested ordinary path is absent from the evaluated target
/// inventory, authenticated publication metadata is incomplete, the registry
/// has no writable authoring clone, or the registry tree is dirty. Sysroot
/// publication also fails when required manual metadata is absent or its image
/// argument groups disagree. Both modes fail when Nix introspection, file
/// authoring, signing, committing, or object-store refresh fails.
/// Policy-bearing internal components also fail
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
    image_contract_schemas: &[String],
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

    if !sysroot {
        return super::inventory_publish::publish_evaluated_package(
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
            previous,
            source_drv,
            bless,
            no_ca,
            no_commit,
            message,
            key,
            key_id,
            printer,
        )
        .await;
    }

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
        image_contract_schemas,
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
    image_contract_schemas: &[String],
    bless: bool,
    no_ca: bool,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    _external_provenance_signer: Option<&mut dyn ProvenanceSigner>,
    printer: &Printer,
) -> Result<()> {
    let description = required_publish_metadata(description, "--description", "No description")?;
    let license = required_publish_metadata(license, "--license", "unknown")?;
    let maintainer = required_publish_metadata(maintainer, "--maintainer", "unknown")?;

    validate_registry_name(name)?;
    ensure_writable_registry_clone(name, dir)?;
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
        || image_payload_paths.len() != image_contract_schemas.len()
    {
        bail!(
            "--image-payload, --image-disk, --image-info, --image-format, and --image-contract-schema must be specified in groups ({} payloads, {} disks, {} metadata files, {} formats, {} schemas)",
            image_payload_paths.len(),
            image_disk_paths.len(),
            image_info_paths.len(),
            image_formats.len(),
            image_contract_schemas.len()
        );
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
    // Bind the exact disk and provider-owned contract without interpreting
    // the selected provider's boot artifact schema.
    let mut image_infos: Vec<PublishedImage> = Vec::new();
    for ((((payload_path, disk_path), info_path), img_fmt), contract_schema) in image_payload_paths
        .iter()
        .zip(image_disk_paths.iter())
        .zip(image_info_paths.iter())
        .zip(image_formats.iter())
        .zip(image_contract_schemas.iter())
    {
        let payload_info = introspect_store_path(payload_path)?;
        let disk_info = introspect_store_path(disk_path)?;
        let metadata_info = introspect_store_path(info_path)?;
        image_infos.push(inspect_published_image(
            img_fmt,
            payload_info,
            disk_info,
            metadata_info,
            contract_schema,
            pkg_name,
            pkg_version,
            &platform,
        )?);
    }

    let letter = first_letter(pkg_name);
    let pkg_dir = dir.join("packages").join(&letter);

    // A preview has completed all derivation and validation work. Stop before
    // taking the publication lock or writing any registry state.
    if crate::dry_run::active() {
        let toml_path = pkg_dir.join(format!("{pkg_name}.toml"));
        printer.info(&format!(
            "Would publish {pkg_name} {pkg_version} ({platform}) to registry '{}'",
            dir.display()
        ));
        printer.kv("Would write", &toml_path.display().to_string());
        printer.kv(
            "Entry",
            if toml_path.exists() {
                "added to the existing package TOML"
            } else {
                "a new package TOML"
            },
        );
        printer.info("Dry run: nothing was written, signed, or committed.");
        return Ok(());
    }

    let _publish_lock = RegistryPublishLock::acquire_or_join_current_process(&dir)?;

    printer.step(2, 4, "Writing package TOML...");
    std::fs::create_dir_all(&pkg_dir)?;

    let toml_path = pkg_dir.join(format!("{pkg_name}.toml"));

    // Read existing TOML if it exists, or create a new one.
    let content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        String::new()
    };

    let new_content = build_package_toml(
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
    )?;

    std::fs::write(&toml_path, &new_content)?;

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
        printer.kv(
            "  Artifact contract",
            &image.delivery.artifact_contract.schema,
        );
    }

    let mut committed = false;
    let mut commit_message = None;
    if !no_commit {
        let default_msg = format!("publish {pkg_name} {pkg_version} ({platform})");
        let msg = message.unwrap_or(&default_msg);
        let staged_paths = vec![toml_path.clone(), dir.join(store::STORE_DIR)];
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
                    "artifact_contract": &image.delivery.artifact_contract,
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

/// Retains one supplemental output for an already-authored canonical entry.
///
/// The primary `out` publication owns package metadata, documentation, and
/// provenance. This operation adds only the named path binding and its complete
/// realisation graph.
///
/// # Errors
///
/// Returns an error when the package coordinate is absent or mismatched, the
/// output path fails publication policy, its target marker disagrees with the
/// release platform, or catalog/store-graph authoring fails.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_canonical_named_output(
    dir: &Path,
    registry: &str,
    store_path: &str,
    package: &str,
    version: &str,
    platform: &str,
    output: &str,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(registry)?;
    validate_package_name(package)?;
    ensure_writable_registry_clone(registry, dir)?;

    let info = introspect_store_path(store_path)?;
    validate_store_path_release_policy(&info)?;
    resolve_publish_platform(&info.path, Some(platform))?;

    let _publish_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(letter)
        .join(format!("{package}.toml"));
    let content = fs::read_to_string(&toml_path)
        .with_context(|| format!("reading primary package entry {}", toml_path.display()))?;
    let new_content =
        record_named_output(&content, package, version, platform, output, store_path)?;
    fs::write(&toml_path, new_content)
        .with_context(|| format!("writing supplemental output to {}", toml_path.display()))?;

    let content_addressed = registry_content_addressed(dir);
    write_store_files(dir, &info.path, content_addressed, false, printer).with_context(|| {
        format!("writing store/ realisation graph for named output {store_path}")
    })?;
    Ok(())
}

/// Publishes and signs the canonical RFC-0022 signed package ability publication output.
///
/// The operation decodes `package.json` canonically, binds it to the exact
/// primary package coordinate, inventories every distinct artifact's complete
/// Nix closure, signs a dedicated provenance statement, and records both the
/// named output and fail-closed feature gates.
///
/// # Errors
///
/// Returns an error when the primary coordinate is absent, any store or
/// manifest identity disagrees, closure introspection is incomplete, signing
/// fails, or registry metadata/store-graph authoring fails.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_package_contract(
    dir: &Path,
    registry: &str,
    store_path: &str,
    package: &str,
    version: &str,
    platform: &str,
    selectors: &PackageContractSelectorRegistry,
    provenance_signer: &mut dyn ProvenanceSigner,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(registry)?;
    validate_package_name(package)?;
    ensure_writable_registry_clone(registry, dir)?;
    validate_external_provenance_signer(dir, provenance_signer)?;

    let projection = introspect_store_path(store_path)?;
    validate_store_path_release_policy(&projection)?;
    resolve_publish_platform(&projection.path, Some(platform))?;
    if !projection.references.is_empty() {
        bail!("package contract document must be reference-free");
    }
    let projection_bytes = crate::package_contract::read_package_manifest(&projection.path)?;

    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(letter)
        .join(format!("{package}.toml"));
    let _publish_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    let content = fs::read_to_string(&toml_path)
        .with_context(|| format!("reading primary package entry {}", toml_path.display()))?;
    let parsed = parse_package_file(&content)?;
    let mut versions = parsed
        .versions
        .iter()
        .filter(|candidate| candidate.version == version);
    let version_entry = versions
        .next()
        .with_context(|| format!("package {package} is missing version {version}"))?;
    if versions.next().is_some() {
        bail!("package {package} repeats version {version}");
    }
    let platform_entry = version_entry
        .platforms
        .get(platform)
        .with_context(|| format!("package {package} {version} is missing platform {platform}"))?;
    let primary_path = &platform_entry.store_path;
    let primary = introspect_store_path(primary_path)?;
    validate_store_path_release_policy(&primary)?;
    let primary_nar_hash = canonical_nar_hash(&primary.nar_hash)?;
    let payload = resolve_store_artifact(&primary.path)?;
    let source_info = introspect_store_path(&platform_entry.source_drv)?;
    validate_store_path_release_policy(&source_info)?;
    let source = resolve_store_artifact(&platform_entry.source_drv)?;
    let (package_document, interface_bytes, selector_bindings) = resolve_release_projection(
        &projection.path,
        package,
        version,
        platform,
        &primary.path,
        &platform_entry.source_drv,
        selectors,
    )?;
    let manifest_bytes = aos_ability_model::encode_canonical(&package_document)?;
    let checked = aos_ability_validate::validate_ability_contract(
        aos_ability_validate::AbilityContractData::PackageSource {
            manifest: &manifest_bytes,
            retained_interfaces: &interface_bytes,
        },
    )
    .context("validating the resolved package contract")?;
    let aos_ability_validate::CheckedAbilityContract::PackageSource(checked) = checked else {
        bail!("resolved package contract returned another contract family");
    };
    let ability_reference = aos_doc_model::PackageAbilityReference::from_checked_contract(&checked)
        .context("deriving the signed package reference from the checked contract")?;
    let documentation = publish_package_documentation(
        package,
        version,
        platform,
        &parsed.package.description,
        parsed.package.homepage.as_deref(),
        &parsed.package.license,
        &primary,
        Some(&source_info),
        ability_reference,
    )?;
    let documentation_attestation = bind_documentation_provenance(
        publish_documentation_attestation_meta(package, version, platform, &primary)?,
        package,
        platform,
        &documentation.metadata,
    )?;
    let documentation_provenance = publish_documentation_provenance_artifact(
        registry,
        package,
        version,
        platform,
        &primary,
        Some(&source_info),
        &documentation.metadata,
        &documentation_attestation,
        provenance_signer,
    )
    .await?;

    let package_digest = package_document.content_digest()?;
    let mut contract = PackageContractMeta {
        document: PackageContractDocumentMeta {
            store_path: projection.path.clone(),
            nar_hash: canonical_nar_hash(&projection.nar_hash)?,
            nar_size: projection.nar_size,
            document_sha256: Sha256Digest::of_bytes(&projection_bytes).to_string(),
            document_size: projection_bytes.len() as u64,
            references: Vec::new(),
        },
        payload: payload.retention,
        source: source.retention,
        selectors: selector_bindings,
        provenance: "provenance/pending.contract.intoto.jsonl".to_string(),
    };
    let retention_digest = contract_retention_digest(&contract)?;
    contract.provenance = format!(
        "provenance/{}/{package}/{platform}/{}-{}.contract.intoto.jsonl",
        first_letter(package),
        package_digest.hex(),
        retention_digest.hex()
    );
    crate::package_contract::validate_package_contract_meta(&contract)?;

    let coordinate = PackageContractCoordinate {
        name: package,
        version,
        platform,
        store_path: &primary.path,
        nar_hash: &primary_nar_hash,
    };
    let statement =
        ability_provenance_statement(&coordinate, &contract, registry, provenance_signer.key_id())?;
    let provenance_jsonl =
        sign_statement_dsse_jsonl_external(&statement, provenance_signer).await?;
    let content = record_package_documentation(
        &content,
        package,
        version,
        platform,
        &documentation.metadata,
        &documentation_attestation,
    )?;
    let new_content = record_package_contract(
        &content,
        package,
        version,
        platform,
        &contract,
        &package_document,
    )?;

    fs::write(&toml_path, new_content)
        .with_context(|| format!("writing package contract to {}", toml_path.display()))?;
    let provenance_path = dir.join(&contract.provenance);
    let provenance_parent = provenance_path.parent().with_context(|| {
        format!(
            "package contract provenance path has no parent: {}",
            provenance_path.display()
        )
    })?;
    fs::create_dir_all(provenance_parent).with_context(|| {
        format!(
            "creating package contract provenance directory {}",
            provenance_parent.display()
        )
    })?;
    fs::write(&provenance_path, &provenance_jsonl).with_context(|| {
        format!(
            "writing package contract provenance {}",
            provenance_path.display()
        )
    })?;
    let documentation_provenance_path = dir.join(&documentation_provenance.path);
    let documentation_provenance_parent =
        documentation_provenance_path.parent().with_context(|| {
            format!(
                "package reference provenance path has no parent: {}",
                documentation_provenance_path.display()
            )
        })?;
    fs::create_dir_all(documentation_provenance_parent).with_context(|| {
        format!(
            "creating package reference provenance directory {}",
            documentation_provenance_parent.display()
        )
    })?;
    fs::write(
        &documentation_provenance_path,
        &documentation_provenance.jsonl,
    )
    .with_context(|| {
        format!(
            "writing package reference provenance {}",
            documentation_provenance_path.display()
        )
    })?;
    append_package_contract_transparency_log(
        dir,
        package,
        version,
        platform,
        &package_digest.to_string(),
        &retention_digest.to_string(),
        &contract.provenance,
        provenance_jsonl.as_bytes(),
    )?;

    let content_addressed = registry_content_addressed(dir);
    write_store_files(
        dir,
        &documentation.info.path,
        content_addressed,
        false,
        printer,
    )
    .with_context(|| {
        format!(
            "writing store/ realisation graph for package reference {}",
            documentation.info.path
        )
    })?;
    append_package_provenance_transparency_log(
        dir,
        package,
        version,
        platform,
        &primary,
        Some(&source_info),
        &documentation_provenance,
        &documentation_provenance_path,
    )?;
    write_store_files(dir, &projection.path, content_addressed, false, printer).with_context(
        || format!("writing store/ realisation graph for package contract {store_path}"),
    )?;
    let mut retained_paths = BTreeSet::new();
    for artifact in std::iter::once(&contract.payload)
        .chain(std::iter::once(&contract.source))
        .chain(contract.selectors.iter().map(|selector| &selector.artifact))
    {
        if !retained_paths.insert(&artifact.store_path) {
            continue;
        }
        write_store_files(dir, &artifact.store_path, content_addressed, false, printer)
            .with_context(|| {
                format!(
                    "writing store/ realisation graph for package contract artifact {}",
                    artifact.store_path
                )
            })?;
    }
    Ok(())
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

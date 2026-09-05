//! Staged package and store provenance validation before registry commits.

use crate::registry::store;
use crate::registry::store::NarBytes;
use crate::registry_ops::git::{git, git_raw, git_try, registry_relative_path};
use crate::registry_ops::provenance::statement::{
    ensure_safe_git_index_path, ensure_safe_git_jsonl_index_path,
    ensure_safe_package_provenance_statement_path,
    validate_package_provenance_transparency_statement,
};
use crate::registry_ops::provenance::{
    PACKAGE_PROVENANCE_TRANSPARENCY_LOG, PackageProvenanceTransparencyLogEntry,
    PackageTomlPlatformKey, StagedPackageProvenanceMeta, StagedPackageRfc0001Meta,
    ensure_package_provenance_transparency_bytes_extend_head,
    head_package_provenance_transparency_log, package_provenance_trusted_keys,
    parse_package_provenance_transparency_log,
};
use crate::registry_ops::store_paths::extract_hash;
use crate::registry_ops::uki::sha256_hex;
use crate::types::rfc0001_metadata_requires_provenance;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

fn git_index_file_bytes(dir: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    ensure_safe_git_jsonl_index_path(path)?;
    git_index_safe_file_bytes(dir, path)
}

fn git_index_safe_file_bytes(dir: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    ensure_safe_git_index_path(path)?;
    git_tree_file_bytes(dir, "", path)
}

pub(in crate::registry_ops) fn git_tree_file_bytes(
    dir: &Path,
    treeish: &str,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    let spec = if treeish.is_empty() {
        format!(":{path}")
    } else {
        format!("{treeish}:{path}")
    };
    let (exists, _, _) = git_try(dir, &["cat-file", "-e", &spec])?;
    if !exists {
        return Ok(None);
    }
    git_raw(dir, &["show", &spec]).map(Some)
}

pub(in crate::registry_ops) fn staged_package_provenance_transparency_validation_needed(
    dir: &Path,
) -> Result<bool> {
    let changed = git(dir, &["diff", "--cached", "--name-only"])?;
    let log_changed = changed
        .lines()
        .any(|line| line.trim() == PACKAGE_PROVENANCE_TRANSPARENCY_LOG);
    if log_changed {
        return Ok(true);
    }
    if !staged_package_toml_provenance_entries(dir)?.is_empty() {
        return Ok(true);
    }
    let provenance_statement_changed = changed.lines().any(|line| {
        let path = line.trim();
        path.starts_with("provenance/") && path.ends_with(".intoto.jsonl")
    });
    if provenance_statement_changed {
        return Ok(true);
    }
    let store_record_changed = changed
        .lines()
        .any(|line| line.trim().starts_with("store/"));
    if store_record_changed && !indexed_package_toml_provenance_entries(dir)?.is_empty() {
        return Ok(true);
    }
    Ok(false)
}

pub(in crate::registry_ops) fn validate_staged_package_provenance_transparency_log(
    dir: &Path,
) -> Result<()> {
    let log = git_index_file_bytes(dir, PACKAGE_PROVENANCE_TRANSPARENCY_LOG)?
        .context("staged package provenance transparency log is missing")?;
    if let Some(head_log) = head_package_provenance_transparency_log(dir)? {
        ensure_package_provenance_transparency_bytes_extend_head(
            dir,
            &log,
            &head_log,
            &format!("index:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}"),
        )?;
    }
    let log_text = std::str::from_utf8(&log)
        .context("decoding staged package provenance transparency log as UTF-8")?;
    let (_, _, entries) = parse_package_provenance_transparency_log(
        log_text,
        &format!("index:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}"),
    )?;
    validate_staged_package_toml_provenance_entries(dir, &entries)?;
    validate_staged_store_provenance_entries(dir, &entries)?;
    let (registry_name, trusted_keys) = package_provenance_trusted_keys(dir)?;
    for entry in &entries {
        ensure_safe_package_provenance_statement_path(&entry.body.statement.path)?;
        let statement_bytes =
            git_index_file_bytes(dir, &entry.body.statement.path)?.with_context(|| {
                format!(
                    "staged package provenance statement '{}' is missing",
                    entry.body.statement.path
                )
            })?;
        let actual = format!("sha256:{}", sha256_hex(&statement_bytes));
        if actual != entry.body.statement.jsonl_sha256 {
            bail!(
                "staged package provenance statement '{}' digest mismatch: expected '{}', got '{}'",
                entry.body.statement.path,
                entry.body.statement.jsonl_sha256,
                actual
            );
        }
        let statement_text = std::str::from_utf8(&statement_bytes).with_context(|| {
            format!(
                "decoding package provenance statement '{}' as UTF-8",
                entry.body.statement.path
            )
        })?;
        let (statement, key_id) =
            crate::provenance::verify_statement_dsse_jsonl(statement_text, &trusted_keys)
                .with_context(|| {
                    format!(
                        "verifying package provenance DSSE envelope '{}'",
                        entry.body.statement.path
                    )
                })?;
        crate::provenance::verify_key_allowed_for_transparency_sequence(
            &trusted_keys,
            &key_id,
            entry.body.sequence,
        )
        .with_context(|| {
            format!(
                "verifying package provenance key lifetime for '{}'",
                entry.body.statement.path
            )
        })?;
        validate_package_provenance_transparency_statement(
            entry,
            &statement,
            &registry_name,
            &key_id,
        )?;
    }
    Ok(())
}

fn validate_staged_package_toml_provenance_entries(
    dir: &Path,
    log_entries: &[PackageProvenanceTransparencyLogEntry],
) -> Result<()> {
    for meta in staged_package_toml_provenance_entries(dir)? {
        let entry = unique_staged_package_transparency_entry(log_entries, &meta)?;
        ensure_staged_package_matches_transparency_entry(&meta, entry)?;
    }
    Ok(())
}

pub(in crate::registry_ops) fn validate_staged_package_toml_provenance_requirements(
    dir: &Path,
) -> Result<()> {
    for path in staged_changed_paths(dir)? {
        if !is_package_toml_path(&path) {
            continue;
        }
        let Some(bytes) = git_index_safe_file_bytes(dir, &path)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding staged package metadata {path} as UTF-8"))?;
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing staged package metadata {path}"))?;
        for (key, platform_entry) in package_toml_platform_entries(&path, &value, "staged")? {
            ensure_staged_package_rfc0001_provenance(&path, &key, platform_entry)?;
        }
    }
    Ok(())
}

fn staged_package_toml_provenance_entries(dir: &Path) -> Result<Vec<StagedPackageProvenanceMeta>> {
    package_toml_provenance_entries_from_paths(dir, staged_changed_paths(dir)?, true)
}

fn indexed_package_toml_provenance_entries(dir: &Path) -> Result<Vec<StagedPackageProvenanceMeta>> {
    package_toml_provenance_entries_from_paths(dir, git_ls_files(dir, "packages")?, false)
}

fn head_package_toml_provenance_entries(dir: &Path) -> Result<Vec<StagedPackageProvenanceMeta>> {
    let mut metas = Vec::new();
    for path in git_ls_tree_files(dir, "HEAD", "packages")? {
        if !is_package_toml_path(&path) {
            continue;
        }
        let Some(bytes) = git_tree_file_bytes(dir, "HEAD", &path)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding HEAD package metadata {path} as UTF-8"))?;
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing HEAD package metadata {path}"))?;
        for (key, platform_entry) in package_toml_platform_entries(&path, &value, "HEAD")? {
            let Some(provenance) = platform_entry
                .get("provenance")
                .and_then(toml::Value::as_str)
            else {
                continue;
            };
            metas.push(StagedPackageProvenanceMeta {
                path: path.clone(),
                package: key.package.clone(),
                version: key.version.clone(),
                platform: key.platform.clone(),
                store_path: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "store_path",
                )?,
                source_drv: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_drv",
                )?,
                source_nar_hash: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_nar_hash",
                )?,
                root_digest: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_digest",
                )?,
                root_hash: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash",
                )?,
                root_hash_sig: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash_sig",
                )?,
                provenance: provenance.to_string(),
                measurement: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "measurement",
                )?,
            });
        }
    }
    Ok(metas)
}

fn package_toml_provenance_entries_from_paths(
    dir: &Path,
    paths: Vec<String>,
    check_downgrade: bool,
) -> Result<Vec<StagedPackageProvenanceMeta>> {
    let mut metas = Vec::new();
    for path in paths {
        if !is_package_toml_path(&path) {
            continue;
        }
        let Some(bytes) = git_index_safe_file_bytes(dir, &path)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding staged package metadata {path} as UTF-8"))?;
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing staged package metadata {path}"))?;
        let staged_entries = package_toml_platform_entries(&path, &value, "staged")?;
        if check_downgrade {
            ensure_staged_package_provenance_not_downgraded(dir, &path, &staged_entries)?;
        }
        for (key, platform_entry) in staged_entries {
            let Some(provenance) = platform_entry
                .get("provenance")
                .and_then(toml::Value::as_str)
            else {
                continue;
            };
            metas.push(StagedPackageProvenanceMeta {
                path: path.clone(),
                package: key.package.clone(),
                version: key.version.clone(),
                platform: key.platform.clone(),
                store_path: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "store_path",
                )?,
                source_drv: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_drv",
                )?,
                source_nar_hash: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_nar_hash",
                )?,
                root_digest: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_digest",
                )?,
                root_hash: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash",
                )?,
                root_hash_sig: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash_sig",
                )?,
                provenance: provenance.to_string(),
                measurement: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "measurement",
                )?,
            });
        }
    }
    Ok(metas)
}

fn ensure_staged_package_rfc0001_provenance(
    path: &str,
    key: &PackageTomlPlatformKey,
    entry: &toml::Value,
) -> Result<()> {
    let meta: StagedPackageRfc0001Meta = entry.clone().try_into().with_context(|| {
        format!(
            "parsing staged package metadata {path} {} {} {} RFC-0001 fields",
            key.package, key.version, key.platform
        )
    })?;
    let requires_provenance = rfc0001_metadata_requires_provenance(
        meta.expose.as_ref(),
        meta.expose_artifact.as_ref(),
        &meta.permissions,
        meta.bpf_lsm.as_ref(),
    );
    if !requires_provenance {
        return Ok(());
    }
    match entry.get("provenance") {
        Some(provenance) if provenance.is_str() => Ok(()),
        Some(_) => bail!(
            "staged package metadata {path} {} {} {} provenance must be a string",
            key.package,
            key.version,
            key.platform
        ),
        None => bail!(
            "staged package metadata {path} {} {} {} uses RFC-0001 exposed or permission metadata without attestation provenance",
            key.package,
            key.version,
            key.platform
        ),
    }
}

fn ensure_staged_package_provenance_not_downgraded(
    dir: &Path,
    path: &str,
    staged_entries: &[(PackageTomlPlatformKey, &toml::Value)],
) -> Result<()> {
    let staged_by_key = staged_entries
        .iter()
        .map(|(key, entry)| (key.clone(), *entry))
        .collect::<BTreeMap<_, _>>();
    for (key, entry) in &staged_by_key {
        if let Some(provenance) = entry.get("provenance")
            && !provenance.is_str()
        {
            bail!(
                "staged package metadata {path} {} {} {} provenance must be a string",
                key.package,
                key.version,
                key.platform
            );
        }
    }
    let Some(head_bytes) = git_tree_file_bytes(dir, "HEAD", path)? else {
        return Ok(());
    };
    let head_text = std::str::from_utf8(&head_bytes)
        .with_context(|| format!("decoding HEAD package metadata {path} as UTF-8"))?;
    let head_value: toml::Value = toml::from_str(head_text)
        .with_context(|| format!("parsing HEAD package metadata {path}"))?;
    for (key, head_entry) in package_toml_platform_entries(path, &head_value, "HEAD")? {
        let Some(head_provenance) = head_entry.get("provenance").and_then(toml::Value::as_str)
        else {
            continue;
        };
        let Some(staged_entry) = staged_by_key.get(&key) else {
            continue;
        };
        if staged_entry
            .get("provenance")
            .and_then(toml::Value::as_str)
            .is_none()
        {
            bail!(
                "staged package metadata {path} {} {} {} removes committed provenance '{}'",
                key.package,
                key.version,
                key.platform,
                head_provenance
            );
        }
    }
    Ok(())
}

fn package_toml_platform_entries<'a>(
    path: &str,
    value: &'a toml::Value,
    source: &str,
) -> Result<Vec<(PackageTomlPlatformKey, &'a toml::Value)>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let package = value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .with_context(|| format!("{source} package metadata {path} missing package.name"))?;
    let Some(versions_value) = value.get("versions") else {
        return Ok(entries);
    };
    let versions = versions_value
        .as_array()
        .with_context(|| format!("{source} package metadata {path} versions must be an array"))?;
    for version_entry in versions {
        let version = version_entry
            .get("version")
            .and_then(toml::Value::as_str)
            .with_context(|| {
                format!("{source} package metadata {path} has a version missing version")
            })?;
        let Some(platforms_value) = version_entry.get("platforms") else {
            continue;
        };
        let platforms = platforms_value.as_table().with_context(|| {
            format!("{source} package metadata {path} version {version} platforms must be a table")
        })?;
        for (platform, platform_entry) in platforms {
            let key = PackageTomlPlatformKey {
                package: package.to_string(),
                version: version.to_string(),
                platform: platform.to_string(),
            };
            if !seen.insert(key.clone()) {
                bail!(
                    "{source} package metadata {path} has duplicate {} {} {} platform entries",
                    key.package,
                    key.version,
                    key.platform
                );
            }
            entries.push((key, platform_entry));
        }
    }
    Ok(entries)
}

fn validate_staged_store_provenance_entries(
    dir: &Path,
    log_entries: &[PackageProvenanceTransparencyLogEntry],
) -> Result<()> {
    let changed_ias = staged_store_record_ia_hashes(dir)?;
    let package_metas = indexed_package_toml_provenance_entries(dir)?;
    for meta in &package_metas {
        validate_staged_store_record_for_package(dir, log_entries, meta)?;
    }

    if changed_ias.is_empty() {
        return Ok(());
    }

    let protected_roots = head_package_toml_provenance_entries(dir)?
        .into_iter()
        .map(|meta| extract_hash(&meta.store_path).to_string())
        .collect::<HashSet<_>>();
    for root_meta in &package_metas {
        let root_ia = extract_hash(&root_meta.store_path);
        if !protected_roots.contains(root_ia) {
            continue;
        }
        let reachable = staged_store_reachable_ias(dir, root_ia)?;
        for changed_ia in changed_ias.intersection(&reachable) {
            let mut bound = false;
            for meta in package_metas
                .iter()
                .filter(|meta| extract_hash(&meta.store_path) == changed_ia.as_str())
            {
                bound = true;
                validate_staged_store_record_for_package(dir, log_entries, meta)?;
            }
            if !bound {
                let record_path =
                    registry_relative_path(dir, &store::entry_path(dir, changed_ia)?)?;
                bail!(
                    "staged store record {record_path} changes a reachable dependency of provenanced package {} {} {} without its own package provenance transparency binding",
                    root_meta.package,
                    root_meta.version,
                    root_meta.platform
                );
            }
        }
    }
    Ok(())
}

fn validate_staged_store_record_for_package(
    dir: &Path,
    log_entries: &[PackageProvenanceTransparencyLogEntry],
    meta: &StagedPackageProvenanceMeta,
) -> Result<()> {
    let ia_hash = extract_hash(&meta.store_path);
    let entry = unique_staged_package_transparency_entry(log_entries, meta)?;
    ensure_staged_package_matches_transparency_entry(meta, entry)?;
    let record_path = registry_relative_path(dir, &store::entry_path(dir, ia_hash)?)?;
    let bytes = git_index_safe_file_bytes(dir, &record_path)?.with_context(|| {
        format!(
            "staged store record {record_path} for provenanced package {} {} {} is missing",
            meta.package, meta.version, meta.platform
        )
    })?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("decoding staged store record {record_path} as UTF-8"))?;
    let store_entry = store::parse_entry(text)
        .with_context(|| format!("parsing staged store record {record_path}"))?;
    let expected_nar = NarBytes::from_hash(&entry.body.nar_hash, entry.body.nar_size)
        .with_context(|| {
            format!(
                "normalizing transparency log NAR hash for {} {} {}",
                meta.package, meta.version, meta.platform
            )
        })?;
    let mut matched = false;
    for nar in store_entry.blessed_nars() {
        if nar == expected_nar {
            matched = true;
            continue;
        }
        bail!(
            "staged store record {record_path} blesses NAR sha256:{}:{} for provenanced package {} {} {}, but transparency log entry {} covers '{}:{}'",
            nar.sha256_nix32,
            nar.size,
            meta.package,
            meta.version,
            meta.platform,
            entry.body.sequence,
            entry.body.nar_hash,
            entry.body.nar_size
        );
    }
    if !matched {
        bail!(
            "staged store record {record_path} for provenanced package {} {} {} is missing transparency-log NAR '{}:{}'",
            meta.package,
            meta.version,
            meta.platform,
            entry.body.nar_hash,
            entry.body.nar_size
        );
    }
    Ok(())
}

fn staged_store_reachable_ias(dir: &Path, root_ia: &str) -> Result<HashSet<String>> {
    let mut reachable = HashSet::new();
    let mut stack = vec![root_ia.to_string()];
    while let Some(ia_hash) = stack.pop() {
        if !reachable.insert(ia_hash.clone()) {
            continue;
        }
        let Some(entry) = staged_store_entry(dir, &ia_hash)? else {
            continue;
        };
        stack.extend(entry.dep_ias());
    }
    Ok(reachable)
}

fn staged_store_entry(dir: &Path, ia_hash: &str) -> Result<Option<store::StoreEntry>> {
    let path = registry_relative_path(dir, &store::entry_path(dir, ia_hash)?)?;
    let Some(bytes) = git_index_safe_file_bytes(dir, &path)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("decoding staged store record {path} as UTF-8"))?;
    store::parse_entry(text)
        .map(Some)
        .with_context(|| format!("parsing staged store record {path}"))
}

fn staged_store_record_ia_hashes(dir: &Path) -> Result<HashSet<String>> {
    let mut hashes = HashSet::new();
    for path in staged_changed_paths(dir)? {
        let Some(ia_hash) = store_record_ia_hash_from_index_path(dir, &path)? else {
            continue;
        };
        hashes.insert(ia_hash);
    }
    Ok(hashes)
}

fn store_record_ia_hash_from_index_path(dir: &Path, path: &str) -> Result<Option<String>> {
    if !path.starts_with("store/") {
        return Ok(None);
    }
    ensure_safe_git_index_path(path)?;
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("staged store record path '{path}' must use store/<shard>/<hash>");
    }
    let ia_hash = parts[2];
    let expected = registry_relative_path(dir, &store::entry_path(dir, ia_hash)?)?;
    if path != expected {
        bail!("staged store record path '{path}' is misfiled; expected '{expected}'");
    }
    Ok(Some(ia_hash.to_string()))
}

fn unique_staged_package_transparency_entry<'a>(
    log_entries: &'a [PackageProvenanceTransparencyLogEntry],
    meta: &StagedPackageProvenanceMeta,
) -> Result<&'a PackageProvenanceTransparencyLogEntry> {
    let mut matches = log_entries
        .iter()
        .filter(|entry| entry.body.provenance == meta.provenance);
    let entry = matches.next().with_context(|| {
        format!(
            "staged package metadata {} declares provenance '{}' with no transparency log entry",
            meta.path, meta.provenance
        )
    })?;
    if matches.next().is_some() {
        bail!(
            "staged package metadata {} declares provenance '{}' with duplicate transparency log entries",
            meta.path,
            meta.provenance
        );
    }
    Ok(entry)
}

fn ensure_staged_package_matches_transparency_entry(
    meta: &StagedPackageProvenanceMeta,
    entry: &PackageProvenanceTransparencyLogEntry,
) -> Result<()> {
    ensure_staged_package_field(meta, "package", &entry.body.package, &meta.package)?;
    ensure_staged_package_field(meta, "version", &entry.body.version, &meta.version)?;
    ensure_staged_package_field(meta, "platform", &entry.body.platform, &meta.platform)?;
    ensure_staged_package_field(meta, "store_path", &entry.body.store_path, &meta.store_path)?;
    let entry_root_digest = entry
        .body
        .root_digest
        .as_deref()
        .or(entry.body.root_hash.as_deref())
        .context("package transparency entry missing root_digest")?;
    ensure_staged_package_field(meta, "root_digest", entry_root_digest, &meta.root_digest)?;
    ensure_staged_package_optional_field(
        meta,
        "root_hash",
        entry.body.root_hash.as_deref(),
        meta.root_hash.as_deref(),
    )?;
    ensure_staged_package_optional_field(
        meta,
        "root_hash_sig",
        entry.body.root_hash_sig.as_deref(),
        meta.root_hash_sig.as_deref(),
    )?;
    ensure_staged_package_field(
        meta,
        "measurement",
        &entry.body.measurement,
        &meta.measurement,
    )?;
    ensure_staged_package_source(meta, entry)
}

fn ensure_staged_package_source(
    meta: &StagedPackageProvenanceMeta,
    entry: &PackageProvenanceTransparencyLogEntry,
) -> Result<()> {
    if let Some(source) = &entry.body.source {
        ensure_staged_package_field(meta, "source_drv", &source.store_path, &meta.source_drv)?;
        ensure_staged_package_field(
            meta,
            "source_nar_hash",
            &source.nar_hash,
            &meta.source_nar_hash,
        )?;
        return Ok(());
    }
    if !meta.source_drv.is_empty() || !meta.source_nar_hash.is_empty() {
        bail!(
            "staged package metadata {} {} {} {} declares source metadata but transparency log entry has no source dependency",
            meta.path,
            meta.package,
            meta.version,
            meta.platform
        );
    }
    Ok(())
}

fn staged_changed_paths(dir: &Path) -> Result<Vec<String>> {
    Ok(git(dir, &["diff", "--cached", "--name-only"])?
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn git_ls_files(dir: &Path, pathspec: &str) -> Result<Vec<String>> {
    Ok(git(dir, &["ls-files", "--", pathspec])?
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn git_ls_tree_files(dir: &Path, treeish: &str, pathspec: &str) -> Result<Vec<String>> {
    let (ok, stdout, _) = git_try(
        dir,
        &["ls-tree", "-r", "--name-only", treeish, "--", pathspec],
    )?;
    if !ok {
        return Ok(Vec::new());
    }
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn is_package_toml_path(path: &str) -> bool {
    path.starts_with("packages/")
        && path.ends_with(".toml")
        && ensure_safe_git_index_path(path).is_ok()
}

fn staged_package_string_field(
    path: &str,
    package: &str,
    version: &str,
    platform: &str,
    entry: &toml::Value,
    field: &str,
) -> Result<String> {
    entry
        .get(field)
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
        .with_context(|| {
            format!("staged package metadata {path} {package} {version} {platform} missing {field}")
        })
}

fn staged_package_optional_string_field(
    path: &str,
    package: &str,
    version: &str,
    platform: &str,
    entry: &toml::Value,
    field: &str,
) -> Result<Option<String>> {
    match entry.get(field) {
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .with_context(|| {
                format!(
                    "staged package metadata {path} {package} {version} {platform} {field} must be a string"
                )
            }),
        None => Ok(None),
    }
}

fn ensure_staged_package_field(
    meta: &StagedPackageProvenanceMeta,
    field: &str,
    expected: &str,
    actual: &str,
) -> Result<()> {
    if expected != actual {
        bail!(
            "staged package metadata {} {} {} {} {field} mismatch: expected '{}', got '{}'",
            meta.path,
            meta.package,
            meta.version,
            meta.platform,
            expected,
            actual
        );
    }
    Ok(())
}

fn ensure_staged_package_optional_field(
    meta: &StagedPackageProvenanceMeta,
    field: &str,
    expected: Option<&str>,
    actual: Option<&str>,
) -> Result<()> {
    if expected != actual {
        bail!(
            "staged package metadata {} {} {} {} {field} mismatch: expected '{}', got '{}'",
            meta.path,
            meta.package,
            meta.version,
            meta.platform,
            expected.unwrap_or("<absent>"),
            actual.unwrap_or("<absent>")
        );
    }
    Ok(())
}

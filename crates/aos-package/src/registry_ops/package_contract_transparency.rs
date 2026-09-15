//! Append-only publication records for authenticated package contracts.
//!
//! The package contract and its retention catalog are authenticated by a DSSE
//! statement. This log binds that statement to an immutable publication
//! sequence so a retired roster key remains valid only for contracts published
//! before its recorded retirement boundary.

use crate::registry_ops::provenance::staged::git_tree_file_bytes;
use crate::registry_ops::provenance::{
    PACKAGE_PROVENANCE_TRANSPARENCY_LOG, package_provenance_trusted_keys,
    read_package_provenance_transparency_log_state,
};
use crate::registry_ops::uki::sha256_hex;
use crate::types::validate_attestation_provenance_ref;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub(crate) const PACKAGE_CONTRACT_TRANSPARENCY_LOG: &str = "transparency/package-contracts.jsonl";
const PACKAGE_CONTRACT_TRANSPARENCY_SCHEMA: &str =
    "https://andyl.com/aos/transparency/package-contract/v1";
const PACKAGE_CONTRACT_ENTRY_HASH_DOMAIN: &[u8] = b"aos.package-contract-transparency/v1\0";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageContractTransparencyEntry {
    body: PackageContractTransparencyBody,
    entry_hash: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageContractTransparencyBody {
    schema: String,
    sequence: u64,
    publication_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_entry_hash: Option<String>,
    package: String,
    version: String,
    platform: String,
    package_digest: String,
    retention_digest: String,
    provenance: String,
    statement_jsonl_sha256: String,
}

pub(in crate::registry_ops) fn append_package_contract_transparency_log(
    dir: &Path,
    package: &str,
    version: &str,
    platform: &str,
    package_digest: &str,
    retention_digest: &str,
    provenance: &str,
    statement_jsonl: &[u8],
) -> Result<PathBuf> {
    validate_attestation_provenance_ref(provenance)?;
    let path = dir.join(PACKAGE_CONTRACT_TRANSPARENCY_LOG);
    let current = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    ensure_extends_head(dir, &current)?;
    let (sequence, previous_entry_hash, entries) =
        parse_log(&current, &path.display().to_string())?;

    let old_next = read_package_provenance_transparency_log_state(
        &dir.join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG),
    )?
    .0;
    let contract_next = entries
        .last()
        .map_or(0, |entry| entry.body.publication_sequence.saturating_add(1));
    let publication_sequence = old_next.max(contract_next);
    let mut body = PackageContractTransparencyBody {
        schema: PACKAGE_CONTRACT_TRANSPARENCY_SCHEMA.to_string(),
        sequence,
        publication_sequence,
        previous_entry_hash,
        package: package.to_string(),
        version: version.to_string(),
        platform: platform.to_string(),
        package_digest: package_digest.to_string(),
        retention_digest: retention_digest.to_string(),
        provenance: provenance.to_string(),
        statement_jsonl_sha256: format!("sha256:{}", sha256_hex(statement_jsonl)),
    };

    if let Some(existing) = entries
        .iter()
        .find(|entry| entry.body.provenance == provenance)
    {
        body.sequence = existing.body.sequence;
        body.publication_sequence = existing.body.publication_sequence;
        body.previous_entry_hash = existing.body.previous_entry_hash.clone();
        if existing.body == body {
            return Ok(path);
        }
        bail!(
            "package contract provenance '{}' is already bound to different publication metadata",
            provenance
        );
    }

    let entry_hash = entry_hash(&body)?;
    let entry = PackageContractTransparencyEntry { body, entry_hash };
    let parent = path
        .parent()
        .with_context(|| format!("transparency log path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let line =
        serde_json::to_string(&entry).context("serializing package contract transparency entry")?;
    writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub(crate) fn package_contract_transparency_sequence(
    content: &[u8],
    source: &str,
    package: &str,
    version: &str,
    platform: &str,
    package_digest: &str,
    retention_digest: &str,
    provenance: &str,
    statement_jsonl: &[u8],
) -> Result<u64> {
    let (_, _, entries) = parse_log(content, source)?;
    let mut matches = entries.iter().filter(|entry| {
        entry.body.package == package
            && entry.body.version == version
            && entry.body.platform == platform
    });
    let entry = matches.next().with_context(|| {
        format!("package contract transparency entry missing for {package}@{version} ({platform})")
    })?;
    if matches.next().is_some() {
        bail!(
            "package contract transparency entry is ambiguous for {package}@{version} ({platform})"
        );
    }
    let expected_statement_digest = format!("sha256:{}", sha256_hex(statement_jsonl));
    if entry.body.package_digest != package_digest
        || entry.body.retention_digest != retention_digest
        || entry.body.provenance != provenance
        || entry.body.statement_jsonl_sha256 != expected_statement_digest
    {
        bail!(
            "package contract transparency entry does not match the authenticated contract publication"
        );
    }
    Ok(entry.body.publication_sequence)
}

pub(in crate::registry_ops) fn next_package_contract_publication_sequence(
    path: &Path,
) -> Result<u64> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let (_, _, entries) = parse_log(&bytes, &path.display().to_string())?;
    entries.last().map_or(Ok(0), |entry| {
        entry
            .body
            .publication_sequence
            .checked_add(1)
            .context("package contract publication sequence overflow")
    })
}

pub(in crate::registry_ops) fn staged_package_contract_transparency_validation_needed(
    dir: &Path,
) -> Result<bool> {
    let changed = crate::registry_ops::git::git(dir, &["diff", "--cached", "--name-only"])?;
    Ok(changed
        .lines()
        .any(|line| line.trim() == PACKAGE_CONTRACT_TRANSPARENCY_LOG))
}

pub(in crate::registry_ops) fn validate_staged_package_contract_transparency_log(
    dir: &Path,
) -> Result<()> {
    let bytes = git_tree_file_bytes(dir, "", PACKAGE_CONTRACT_TRANSPARENCY_LOG)?
        .context("staged package contract transparency log is missing")?;
    if let Some(head) = git_tree_file_bytes(dir, "HEAD", PACKAGE_CONTRACT_TRANSPARENCY_LOG)? {
        if !bytes.starts_with(&head) {
            bail!("staged package contract transparency log does not extend committed HEAD");
        }
        parse_log(&head, &format!("HEAD:{PACKAGE_CONTRACT_TRANSPARENCY_LOG}"))?;
    }

    let (_, _, entries) = parse_log(&bytes, PACKAGE_CONTRACT_TRANSPARENCY_LOG)?;
    let (_, trusted_keys) = package_provenance_trusted_keys(dir)?;
    for entry in &entries {
        let statement_bytes =
            git_tree_file_bytes(dir, "", &entry.body.provenance)?.with_context(|| {
                format!(
                    "staged package contract provenance '{}' is missing",
                    entry.body.provenance
                )
            })?;
        let actual_digest = format!("sha256:{}", sha256_hex(&statement_bytes));
        if actual_digest != entry.body.statement_jsonl_sha256 {
            bail!(
                "staged package contract provenance '{}' digest does not match transparency entry",
                entry.body.provenance
            );
        }
        let statement_jsonl = std::str::from_utf8(&statement_bytes).with_context(|| {
            format!(
                "decoding staged package contract provenance '{}'",
                entry.body.provenance
            )
        })?;
        let (statement, key_id) =
            crate::provenance::verify_statement_dsse_jsonl(statement_jsonl, &trusted_keys)?;
        crate::provenance::verify_key_allowed_for_package_contract_sequence(
            &trusted_keys,
            &key_id,
            entry.body.publication_sequence,
        )?;
        validate_statement_binding(entry, &statement)?;
    }
    Ok(())
}

fn parse_log(
    bytes: &[u8],
    source: &str,
) -> Result<(u64, Option<String>, Vec<PackageContractTransparencyEntry>)> {
    let content = std::str::from_utf8(bytes)
        .with_context(|| format!("decoding package contract transparency log {source}"))?;
    let mut next_sequence = 0u64;
    let mut next_publication_sequence = None;
    let mut previous_entry_hash = None;
    let mut entries = Vec::new();
    for (line_index, line) in content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let entry: PackageContractTransparencyEntry =
            serde_json::from_str(line).with_context(|| {
                format!(
                    "deserializing package contract transparency entry {} in {source}",
                    line_index + 1
                )
            })?;
        validate_attestation_provenance_ref(&entry.body.provenance).with_context(|| {
            format!(
                "validating package contract transparency provenance in entry {}",
                line_index + 1
            )
        })?;
        if entry.body.schema != PACKAGE_CONTRACT_TRANSPARENCY_SCHEMA {
            bail!(
                "package contract transparency entry {} has unsupported schema '{}'",
                line_index + 1,
                entry.body.schema
            );
        }
        if entry.body.sequence != next_sequence {
            bail!(
                "package contract transparency entry {} sequence mismatch: expected {}, got {}",
                line_index + 1,
                next_sequence,
                entry.body.sequence
            );
        }
        if entry.body.previous_entry_hash != previous_entry_hash {
            bail!(
                "package contract transparency entry {} previous hash mismatch",
                line_index + 1
            );
        }
        if let Some(expected) = next_publication_sequence {
            if entry.body.publication_sequence < expected {
                bail!(
                    "package contract transparency entry {} publication sequence goes backwards",
                    line_index + 1
                );
            }
        }
        let expected_hash = entry_hash(&entry.body)?;
        if entry.entry_hash != expected_hash {
            bail!(
                "package contract transparency entry {} hash mismatch",
                line_index + 1
            );
        }
        next_sequence = next_sequence
            .checked_add(1)
            .context("package contract transparency sequence overflow")?;
        next_publication_sequence = Some(
            entry
                .body
                .publication_sequence
                .checked_add(1)
                .context("package contract publication sequence overflow")?,
        );
        previous_entry_hash = Some(entry.entry_hash.clone());
        entries.push(entry);
    }
    Ok((next_sequence, previous_entry_hash, entries))
}

fn ensure_extends_head(dir: &Path, current: &[u8]) -> Result<()> {
    let Some(head) = git_tree_file_bytes(dir, "HEAD", PACKAGE_CONTRACT_TRANSPARENCY_LOG)? else {
        return Ok(());
    };
    if !current.starts_with(&head) {
        bail!(
            "package contract transparency log does not extend committed HEAD; restore the committed prefix before publishing"
        );
    }
    parse_log(&head, &format!("HEAD:{PACKAGE_CONTRACT_TRANSPARENCY_LOG}"))?;
    Ok(())
}

fn entry_hash(body: &PackageContractTransparencyBody) -> Result<String> {
    let mut payload = PACKAGE_CONTRACT_ENTRY_HASH_DOMAIN.to_vec();
    payload.extend(
        serde_json::to_vec(body).context("serializing package contract transparency body")?,
    );
    Ok(format!("sha256:{}", sha256_hex(&payload)))
}

fn validate_statement_binding(
    entry: &PackageContractTransparencyEntry,
    statement: &serde_json::Value,
) -> Result<()> {
    let subjects = statement
        .get("subject")
        .and_then(serde_json::Value::as_array)
        .context("package contract statement subject must be an array")?;
    let package_name = format!(
        "aos:package-contract:{}:{}:{}",
        entry.body.package, entry.body.version, entry.body.platform
    );
    let retention_name = format!(
        "aos:ability-retention:{}:{}:{}",
        entry.body.package, entry.body.version, entry.body.platform
    );
    validate_subject_digest(
        subjects,
        &package_name,
        &entry.body.package_digest,
        "package contract",
    )?;
    validate_subject_digest(
        subjects,
        &retention_name,
        &entry.body.retention_digest,
        "package contract retention",
    )?;

    let parameters = statement
        .pointer("/predicate/buildDefinition/externalParameters")
        .and_then(serde_json::Value::as_object)
        .context("package contract statement externalParameters must be an object")?;
    for (key, expected) in [
        ("package", entry.body.package.as_str()),
        ("version", entry.body.version.as_str()),
        ("platform", entry.body.platform.as_str()),
        ("provenance", entry.body.provenance.as_str()),
    ] {
        if parameters.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
            bail!(
                "package contract statement externalParameters.{key} does not match transparency entry"
            );
        }
    }
    Ok(())
}

fn validate_subject_digest(
    subjects: &[serde_json::Value],
    name: &str,
    digest: &str,
    label: &str,
) -> Result<()> {
    let mut matches = subjects
        .iter()
        .filter(|subject| subject.get("name").and_then(serde_json::Value::as_str) == Some(name));
    let subject = matches
        .next()
        .with_context(|| format!("{label} statement subject '{name}' is missing"))?;
    if matches.next().is_some() {
        bail!("{label} statement subject '{name}' is duplicated");
    }
    let expected = crate::provenance::digest_map(digest);
    if subject.get("digest") != Some(&expected) {
        bail!("{label} statement subject '{name}' digest does not match transparency entry");
    }
    Ok(())
}

#[cfg(test)]
mod tests;

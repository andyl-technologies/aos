//! in-toto/SLSA package provenance helpers.
//!
//! `apr publish` emits one JSONL statement per attested package root and
//! `apm install` verifies the same statement from the synced registry cache.
//! This module keeps the digest key semantics shared between producer and
//! consumer code: real 64-character SHA-256 hex payloads are exposed as
//! standard in-toto `sha256` digests, while Nix SRI/base32 NAR hashes retain
//! their original spelling under `nix:narHash`.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use aos_core::nar::cache::normalize_sha256_nix32;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security;
use crate::types::PackageMeta;

const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
const BUILD_TYPE: &str = "https://andyl.com/aos/apr-publish/v1";
const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const DSSE_SIGNATURE_NAMESPACE: &str = "aos-package-provenance-dsse-v1";
pub(crate) const PACKAGE_PROVENANCE_TRANSPARENCY_LOG: &str =
    "transparency/package-provenance.jsonl";
const PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA: &str =
    "https://andyl.com/aos/transparency/package-provenance/v1";

/// A trusted key that may verify package provenance DSSE envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedProvenanceKey {
    /// Stable key id from the committed registry `keys.toml` roster.
    pub key_id: String,
    /// Public key in `registry:Ed25519:<base64>` trust-line form.
    pub key: String,
    /// First transparency sequence that must not trust this key, if retired.
    pub retired_before_sequence: Option<u64>,
}

/// Returns an in-toto digest map for an AOS/Nix digest string.
pub(crate) fn digest_map(digest: &str) -> serde_json::Value {
    if let Some(hex) = sha256_hex_payload(digest) {
        serde_json::json!({ "sha256": hex })
    } else {
        serde_json::json!({ "nix:narHash": digest })
    }
}

/// Extracts a lowercase 64-character SHA-256 hex payload from a digest string.
pub(crate) fn sha256_hex_payload(digest: &str) -> Option<String> {
    let payload = digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("sha256-"))
        .unwrap_or(digest);
    if payload.len() == 64 && payload.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(payload.to_ascii_lowercase())
    } else {
        None
    }
}

/// Return the builder identity URI for a registry provenance key.
pub(crate) fn builder_id(registry_name: &str, key_id: &str) -> String {
    format!("https://andyl.com/aos/builders/{registry_name}/{key_id}")
}

/// Sign an in-toto/SLSA statement as a single-line DSSE JSONL envelope.
///
/// # Errors
///
/// Returns an error when the statement cannot be serialized, the key id is
/// empty, the DSSE payload cannot be signed, or the envelope cannot be
/// serialized.
pub(crate) fn sign_statement_dsse_jsonl(
    statement: &serde_json::Value,
    key_id: &str,
    key_path: &Path,
) -> Result<String> {
    if key_id.is_empty() {
        bail!("package provenance DSSE key id cannot be empty");
    }
    let payload =
        serde_json::to_vec(statement).context("serializing package provenance statement")?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, &payload);
    let signature = security::sign_payload_signature(key_path, DSSE_SIGNATURE_NAMESPACE, &pae)
        .with_context(|| format!("signing package provenance DSSE envelope with '{key_id}'"))?;
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(&payload),
        signatures: vec![DsseSignature {
            key_id: key_id.to_string(),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.as_bytes()),
        }],
    };
    let mut jsonl =
        serde_json::to_string(&envelope).context("serializing package provenance DSSE envelope")?;
    jsonl.push('\n');
    Ok(jsonl)
}

/// Decode and verify a DSSE-wrapped in-toto/SLSA statement.
///
/// Returns the decoded statement value and the roster key id whose signature
/// verified the envelope.
///
/// # Errors
///
/// Returns an error when the JSONL does not contain exactly one DSSE envelope,
/// the payload type is unsupported, the payload/signature encodings are invalid,
/// or no signature verifies against a trusted provenance key.
pub(crate) fn verify_statement_dsse_jsonl(
    jsonl: &str,
    trusted_keys: &[TrustedProvenanceKey],
) -> Result<(serde_json::Value, String)> {
    let envelope = parse_single_dsse_envelope(jsonl)?;
    if envelope.payload_type != DSSE_PAYLOAD_TYPE {
        bail!(
            "package provenance DSSE envelope has unsupported payloadType '{}'",
            envelope.payload_type
        );
    }
    if trusted_keys.is_empty() {
        bail!("package provenance DSSE verification has no trusted keys");
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(envelope.payload.as_bytes())
        .context("decoding package provenance DSSE payload")?;
    let pae = dsse_pae(&envelope.payload_type, &payload);
    let trusted_by_id = trusted_provenance_keys_by_id(trusted_keys)?;
    let mut attempted = HashSet::new();
    for signature in &envelope.signatures {
        if !attempted.insert(signature.key_id.as_str()) {
            continue;
        }
        let Some(trusted) = trusted_by_id.get(signature.key_id.as_str()) else {
            continue;
        };
        let signature_text = decode_dsse_signature(&signature.sig).with_context(|| {
            format!(
                "decoding package provenance signature '{}'",
                signature.key_id
            )
        })?;
        if security::verify_payload_signature(
            &pae,
            &signature_text,
            &trusted.key,
            DSSE_SIGNATURE_NAMESPACE,
        )
        .with_context(|| {
            format!(
                "verifying package provenance DSSE signature '{}'",
                signature.key_id
            )
        })? {
            let statement = serde_json::from_slice(&payload)
                .context("deserializing package provenance DSSE payload")?;
            return Ok((statement, signature.key_id.clone()));
        }
    }
    bail!("package provenance DSSE envelope has no valid signature from a trusted key");
}

/// Verifies a package's registry-hosted DSSE in-toto/SLSA provenance statement.
///
/// # Errors
///
/// Returns an error when the JSONL does not contain exactly one valid DSSE
/// envelope, the envelope is not signed by a trusted key, the statement has
/// the wrong in-toto/SLSA type, the builder identity does not match the
/// signing key, or any subject, dependency, or external parameter fails to
/// match the package metadata.
pub(crate) fn verify_package_statement(
    meta: &PackageMeta,
    registry_name: &str,
    jsonl: &str,
    trusted_keys: &[TrustedProvenanceKey],
) -> Result<String> {
    let (statement_value, key_id) = verify_statement_dsse_jsonl(jsonl, trusted_keys)
        .with_context(|| format!("verifying provenance DSSE for package '{}'", meta.name))?;
    let statement: ProvenanceStatement = serde_json::from_value(statement_value)
        .with_context(|| format!("parsing provenance for package '{}'", meta.name))?;

    if statement.statement_type != STATEMENT_TYPE {
        bail!(
            "package '{}' provenance statement has unsupported _type '{}'",
            meta.name,
            statement.statement_type
        );
    }
    if statement.predicate_type != PREDICATE_TYPE {
        bail!(
            "package '{}' provenance statement has unsupported predicateType '{}'",
            meta.name,
            statement.predicate_type
        );
    }
    if statement.predicate.build_definition.build_type != BUILD_TYPE {
        bail!(
            "package '{}' provenance statement has unsupported buildType '{}'",
            meta.name,
            statement.predicate.build_definition.build_type
        );
    }
    let expected_builder_id = builder_id(registry_name, &key_id);
    if statement.predicate.run_details.builder.id != expected_builder_id {
        bail!(
            "package '{}' provenance builder id mismatch: expected '{}', got '{}'",
            meta.name,
            expected_builder_id,
            statement.predicate.run_details.builder.id
        );
    }

    let attestation = &meta.attestation;
    let root_digest = attestation
        .root_digest
        .as_deref()
        .context("package provenance requires root_digest")?;
    let root_hash = attestation.root_hash.as_deref();
    let root_hash_sig = attestation.root_hash_sig.as_deref();
    if root_hash.is_some() != root_hash_sig.is_some() {
        bail!("package provenance root_hash and root_hash_sig must be declared together");
    }
    let provenance = attestation
        .provenance
        .as_deref()
        .context("package does not declare provenance")?;
    let measurement = attestation
        .measurement
        .as_deref()
        .context("package provenance requires measurement")?;

    let params = &statement.predicate.build_definition.external_parameters;
    ensure_eq("package", &params.package, &meta.name)?;
    ensure_eq("version", &params.version, &meta.version)?;
    ensure_eq("platform", &params.platform, &meta.platform)?;
    ensure_eq("store_path", &params.store_path, &meta.store_path)?;
    ensure_eq("root_digest", &params.root_digest, root_digest)?;
    ensure_optional_eq("root_hash", params.root_hash.as_deref(), root_hash)?;
    ensure_optional_eq(
        "root_hash_sig",
        params.root_hash_sig.as_deref(),
        root_hash_sig,
    )?;
    ensure_eq("provenance", &params.provenance, provenance)?;

    let package_subject = subject_named(&statement, &meta.store_path)
        .with_context(|| format!("locating package NAR subject for '{}'", meta.name))?;
    ensure_digest_matches("package NAR", &package_subject.digest, &meta.nar_hash)?;

    let manifest_subject_name = format!(
        "aos:permissions-manifest:{}:{}:{}",
        meta.name, meta.version, meta.platform
    );
    let manifest_subject = subject_named(&statement, &manifest_subject_name)
        .with_context(|| format!("locating permissions manifest subject for '{}'", meta.name))?;
    let manifest_digest = sha256_digest_from_map("permissions manifest", &manifest_subject.digest)?;

    let expected_measurement = crate::package_attestation::package_measurement_digest(
        &meta.name,
        &meta.version,
        root_digest,
        &manifest_digest,
    );
    if expected_measurement != measurement {
        bail!(
            "package '{}' provenance manifest digest does not match registry measurement",
            meta.name
        );
    }

    let measurement_subject_name = format!(
        "aos:package-measurement:{}:{}:{}",
        meta.name, meta.version, meta.platform
    );
    let measurement_subject = subject_named(&statement, &measurement_subject_name)
        .with_context(|| format!("locating package measurement subject for '{}'", meta.name))?;
    ensure_digest_matches(
        "package measurement",
        &measurement_subject.digest,
        measurement,
    )?;

    if !meta.source_drv.is_empty() {
        if meta.source_nar_hash.is_empty() {
            bail!(
                "package '{}' declares source_drv but no source_nar_hash for provenance",
                meta.name
            );
        }
        let source_uri = format!("nix:{}", meta.source_drv);
        let mut dependencies = statement
            .predicate
            .build_definition
            .resolved_dependencies
            .iter()
            .filter(|dependency| dependency.uri == source_uri);
        let dependency = dependencies.next().with_context(|| {
            format!(
                "package '{}' provenance missing source dependency {}",
                meta.name, source_uri
            )
        })?;
        if dependencies.next().is_some() {
            bail!(
                "package '{}' provenance has duplicate source dependency {}",
                meta.name,
                source_uri
            );
        }
        ensure_digest_matches(
            "source derivation NAR",
            &dependency.digest,
            &meta.source_nar_hash,
        )?;
    }

    Ok(key_id)
}

/// Verifies that a package provenance statement appears in the registry log.
///
/// # Errors
///
/// Returns an error when the transparency log is malformed, has a broken hash
/// chain, lacks exactly one entry for the package's provenance artifact, or the
/// entry does not match the package metadata and statement bytes.
pub(crate) fn verify_transparency_log_inclusion(
    meta: &PackageMeta,
    jsonl: &str,
    transparency_log: &str,
) -> Result<u64> {
    let provenance = meta
        .attestation
        .provenance
        .as_deref()
        .context("package does not declare provenance")?;
    let (_, _, entries) =
        parse_transparency_log(transparency_log, PACKAGE_PROVENANCE_TRANSPARENCY_LOG)?;
    let mut matches = entries
        .iter()
        .filter(|entry| entry.body.provenance == provenance);
    let entry = matches.next().with_context(|| {
        format!(
            "package '{}' provenance '{}' has no transparency log entry",
            meta.name, provenance
        )
    })?;
    if matches.next().is_some() {
        bail!(
            "package '{}' provenance '{}' has duplicate transparency log entries",
            meta.name,
            provenance
        );
    }

    ensure_eq("transparency package", &entry.body.package, &meta.name)?;
    ensure_eq("transparency version", &entry.body.version, &meta.version)?;
    ensure_eq(
        "transparency platform",
        &entry.body.platform,
        &meta.platform,
    )?;
    ensure_eq(
        "transparency store_path",
        &entry.body.store_path,
        &meta.store_path,
    )?;
    // The transparency entry preserves the NAR hash's original spelling; the
    // loaded meta uses the canonical `sha256:<nix32>` form. Compare by value.
    if normalize_sha256_nix32(&entry.body.nar_hash) != normalize_sha256_nix32(&meta.nar_hash) {
        bail!(
            "transparency nar_hash mismatch: expected '{}', got '{}'",
            meta.nar_hash,
            entry.body.nar_hash
        );
    }
    if entry.body.nar_size != meta.nar_size {
        bail!(
            "transparency nar_size mismatch: expected {}, got {}",
            meta.nar_size,
            entry.body.nar_size
        );
    }
    let expected_root_digest = meta
        .attestation
        .root_digest
        .as_deref()
        .context("package provenance requires root_digest")?;
    let log_root_digest = entry
        .body
        .root_digest
        .as_deref()
        .or(entry.body.root_hash.as_deref())
        .context("transparency entry missing root_digest")?;
    ensure_eq(
        "transparency root_digest",
        log_root_digest,
        expected_root_digest,
    )?;
    ensure_optional_eq(
        "transparency root_hash",
        entry.body.root_hash.as_deref(),
        meta.attestation.root_hash.as_deref(),
    )?;
    ensure_optional_eq(
        "transparency root_hash_sig",
        entry.body.root_hash_sig.as_deref(),
        meta.attestation.root_hash_sig.as_deref(),
    )?;
    let measurement = meta
        .attestation
        .measurement
        .as_deref()
        .context("package provenance requires measurement")?;
    ensure_eq(
        "transparency measurement",
        &entry.body.measurement,
        measurement,
    )?;
    ensure_source_matches_transparency_entry(meta, entry)?;
    ensure_eq(
        "transparency statement path",
        &entry.body.statement.path,
        provenance,
    )?;
    let actual_statement_sha256 = format!("sha256:{}", sha256_hex(jsonl.as_bytes()));
    ensure_eq(
        "transparency statement digest",
        &entry.body.statement.jsonl_sha256,
        &actual_statement_sha256,
    )?;
    Ok(entry.body.sequence)
}

/// Verifies that a provenance key may be used for a transparency sequence.
///
/// # Errors
///
/// Returns an error when the key id is not trusted, the trusted key set is
/// internally ambiguous, or the key was retired before the log entry sequence.
pub(crate) fn verify_key_allowed_for_transparency_sequence(
    trusted_keys: &[TrustedProvenanceKey],
    key_id: &str,
    sequence: u64,
) -> Result<()> {
    let trusted_by_id = trusted_provenance_keys_by_id(trusted_keys)?;
    let trusted = trusted_by_id
        .get(key_id)
        .with_context(|| format!("package provenance key id '{key_id}' is not trusted"))?;
    if let Some(retired_before_sequence) = trusted.retired_before_sequence {
        if sequence >= retired_before_sequence {
            bail!(
                "package provenance key id '{key_id}' was retired before transparency sequence {retired_before_sequence}; entry sequence {sequence} is not trusted"
            );
        }
    }
    Ok(())
}

/// Verifies the package provenance transparency log hash chain.
///
/// # Errors
///
/// Returns an error when the log cannot be parsed, has a sequence gap, or has a
/// broken previous-entry or entry-hash link.
pub(crate) fn validate_transparency_log(transparency_log: &str) -> Result<()> {
    parse_transparency_log(transparency_log, PACKAGE_PROVENANCE_TRANSPARENCY_LOG)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    #[serde(default)]
    signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseSignature {
    #[serde(rename = "keyid")]
    key_id: String,
    sig: String,
}

#[derive(Debug, Deserialize)]
struct ProvenanceStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    #[serde(default)]
    subject: Vec<ProvenanceSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: ProvenancePredicate,
}

#[derive(Debug, Deserialize)]
struct ProvenanceSubject {
    name: String,
    #[serde(default)]
    digest: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ProvenancePredicate {
    #[serde(rename = "buildDefinition")]
    build_definition: ProvenanceBuildDefinition,
    #[serde(rename = "runDetails")]
    run_details: ProvenanceRunDetails,
}

#[derive(Debug, Deserialize)]
struct ProvenanceBuildDefinition {
    #[serde(rename = "buildType")]
    build_type: String,
    #[serde(rename = "externalParameters")]
    external_parameters: ProvenanceExternalParameters,
    #[serde(default, rename = "resolvedDependencies")]
    resolved_dependencies: Vec<ProvenanceDependency>,
}

#[derive(Debug, Deserialize)]
struct ProvenanceExternalParameters {
    package: String,
    version: String,
    platform: String,
    store_path: String,
    root_digest: String,
    #[serde(default)]
    root_hash: Option<String>,
    #[serde(default)]
    root_hash_sig: Option<String>,
    provenance: String,
}

#[derive(Debug, Deserialize)]
struct ProvenanceDependency {
    uri: String,
    #[serde(default)]
    digest: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ProvenanceRunDetails {
    builder: ProvenanceBuilder,
}

#[derive(Debug, Deserialize)]
struct ProvenanceBuilder {
    id: String,
}

fn parse_single_dsse_envelope(jsonl: &str) -> Result<DsseEnvelope> {
    let mut lines = jsonl.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().context("provenance DSSE JSONL is empty")?;
    if lines.next().is_some() {
        bail!("provenance DSSE JSONL must contain exactly one envelope");
    }
    serde_json::from_str(line).context("deserializing provenance DSSE envelope")
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

fn trusted_provenance_keys_by_id<'a>(
    trusted_keys: &'a [TrustedProvenanceKey],
) -> Result<BTreeMap<&'a str, &'a TrustedProvenanceKey>> {
    let mut by_id = BTreeMap::new();
    let mut by_key = BTreeMap::new();
    for key in trusted_keys {
        if key.key_id.is_empty() {
            bail!("package provenance trusted key id cannot be empty");
        }
        if by_id.insert(key.key_id.as_str(), key).is_some() {
            bail!(
                "package provenance trusted key id '{}' is declared more than once",
                key.key_id
            );
        }
        if let Some(existing_id) = by_key.insert(key.key.as_str(), key.key_id.as_str()) {
            bail!(
                "package provenance trusted key material is declared by both '{}' and '{}'",
                existing_id,
                key.key_id
            );
        }
    }
    Ok(by_id)
}

fn decode_dsse_signature(encoded: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .context("decoding package provenance DSSE signature")?;
    String::from_utf8(bytes).context("package provenance DSSE signature is not UTF-8")
}

fn subject_named<'a>(
    statement: &'a ProvenanceStatement,
    name: &str,
) -> Result<&'a ProvenanceSubject> {
    let mut matches = statement
        .subject
        .iter()
        .filter(|subject| subject.name == name);
    let subject = matches
        .next()
        .with_context(|| format!("provenance missing subject {name}"))?;
    if matches.next().is_some() {
        bail!("provenance has duplicate subject {name}");
    }
    Ok(subject)
}

fn ensure_eq(kind: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("provenance {kind} mismatch: expected '{expected}', got '{actual}'");
    }
    Ok(())
}

fn ensure_optional_eq(kind: &str, actual: Option<&str>, expected: Option<&str>) -> Result<()> {
    if actual != expected {
        bail!(
            "provenance {kind} mismatch: expected '{}', got '{}'",
            expected.unwrap_or("<absent>"),
            actual.unwrap_or("<absent>")
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparencyLogEntry {
    body: TransparencyLogBody,
    entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparencyLogBody {
    schema: String,
    sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_entry_hash: Option<String>,
    package: String,
    version: String,
    platform: String,
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_hash_sig: Option<String>,
    provenance: String,
    measurement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<TransparencySource>,
    statement: TransparencyStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparencySource {
    store_path: String,
    nar_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparencyStatement {
    path: String,
    jsonl_sha256: String,
}

fn parse_transparency_log(
    content: &str,
    source: &str,
) -> Result<(u64, Option<String>, Vec<TransparencyLogEntry>)> {
    let mut next_sequence = 0u64;
    let mut previous_entry_hash: Option<String> = None;
    let mut entries = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: TransparencyLogEntry = serde_json::from_str(line).with_context(|| {
            format!(
                "deserializing package transparency log entry {} in {}",
                line_index + 1,
                source
            )
        })?;
        if entry.body.schema != PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA {
            bail!(
                "package transparency log entry {} has unsupported schema '{}'",
                line_index + 1,
                entry.body.schema
            );
        }
        if entry.body.sequence != next_sequence {
            bail!(
                "package transparency log entry {} sequence mismatch: expected {}, got {}",
                line_index + 1,
                next_sequence,
                entry.body.sequence
            );
        }
        if entry.body.previous_entry_hash != previous_entry_hash {
            bail!(
                "package transparency log entry {} previous hash mismatch",
                line_index + 1
            );
        }
        let expected_entry_hash = transparency_entry_hash(&entry.body).with_context(|| {
            format!(
                "hashing package transparency log entry {} in {}",
                line_index + 1,
                source
            )
        })?;
        if entry.entry_hash != expected_entry_hash {
            bail!(
                "package transparency log entry {} hash mismatch: expected '{}', got '{}'",
                line_index + 1,
                expected_entry_hash,
                entry.entry_hash
            );
        }
        previous_entry_hash = Some(entry.entry_hash.clone());
        next_sequence = next_sequence
            .checked_add(1)
            .context("package transparency log sequence overflow")?;
        entries.push(entry);
    }
    Ok((next_sequence, previous_entry_hash, entries))
}

fn ensure_source_matches_transparency_entry(
    meta: &PackageMeta,
    entry: &TransparencyLogEntry,
) -> Result<()> {
    match &entry.body.source {
        Some(source) => {
            ensure_eq(
                "transparency source_drv",
                &source.store_path,
                &meta.source_drv,
            )?;
            // Compare the source NAR hash by value: the entry keeps its
            // original spelling while the loaded meta is canonicalized.
            if normalize_sha256_nix32(&source.nar_hash)
                != normalize_sha256_nix32(&meta.source_nar_hash)
            {
                bail!(
                    "transparency source_nar_hash mismatch: expected '{}', got '{}'",
                    meta.source_nar_hash,
                    source.nar_hash
                );
            }
            Ok(())
        }
        None if meta.source_drv.is_empty() && meta.source_nar_hash.is_empty() => Ok(()),
        None => bail!(
            "package '{}' declares source metadata but transparency entry has no source dependency",
            meta.name
        ),
    }
}

fn transparency_entry_hash(body: &TransparencyLogBody) -> Result<String> {
    let payload = serde_json::to_vec(body)
        .context("serializing package transparency log entry body for hashing")?;
    Ok(format!("sha256:{}", sha256_hex(&payload)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ensure_digest_matches(
    kind: &str,
    digest: &BTreeMap<String, String>,
    expected: &str,
) -> Result<()> {
    if let Some(expected_hex) = sha256_hex_payload(expected) {
        let actual = digest
            .get("sha256")
            .with_context(|| format!("{kind} digest missing sha256 entry"))?;
        if actual.eq_ignore_ascii_case(&expected_hex) {
            return Ok(());
        }
        bail!("{kind} sha256 digest mismatch: expected '{expected_hex}', got '{actual}'");
    }

    let actual = digest
        .get("nix:narHash")
        .with_context(|| format!("{kind} digest missing nix:narHash entry"))?;
    // The statement records the NAR hash in its original spelling (typically
    // the SRI `sha256-<base64>` that `nix path-info` emits), while the loaded
    // registry meta normalizes it to the codebase's canonical `sha256:<nix32>`
    // form. Compare by value so the two encodings of the same digest agree.
    if normalize_sha256_nix32(actual) == normalize_sha256_nix32(expected) {
        return Ok(());
    }
    bail!("{kind} nix:narHash digest mismatch: expected '{expected}', got '{actual}'");
}

fn sha256_digest_from_map(kind: &str, digest: &BTreeMap<String, String>) -> Result<String> {
    let value = digest
        .get("sha256")
        .with_context(|| format!("{kind} digest missing sha256 entry"))?;
    let Some(hex) = sha256_hex_payload(value) else {
        bail!("{kind} digest sha256 entry must be 64 hex characters");
    };
    Ok(format!("sha256:{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::types::{AttestationMeta, PackageMeta};
    use tempfile::TempDir;

    const REGISTRY: &str = "aos-core";
    const KEY_ID: &str = "builder";
    const ROOT_HASH: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const MANIFEST_DIGEST: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    struct TestProvenanceKey {
        _tmp: TempDir,
        private_key: std::path::PathBuf,
        trusted_key: String,
    }

    impl TestProvenanceKey {
        fn trusted(&self) -> Vec<TrustedProvenanceKey> {
            vec![TrustedProvenanceKey {
                key_id: KEY_ID.to_string(),
                key: self.trusted_key.clone(),
                retired_before_sequence: None,
            }]
        }
    }

    fn test_key() -> TestProvenanceKey {
        let tmp = TempDir::new().unwrap();
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([42_u8; 32]);
        let private_key = tmp.path().join("builder_ed25519");
        fs::write(&private_key, keypair.to_openssh_private_key(REGISTRY)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        TestProvenanceKey {
            _tmp: tmp,
            private_key,
            trusted_key: keypair.trust_key_line(REGISTRY),
        }
    }

    fn signed_statement(statement: serde_json::Value, key: &TestProvenanceKey) -> String {
        sign_statement_dsse_jsonl(&statement, KEY_ID, &key.private_key).unwrap()
    }

    fn sample_meta() -> PackageMeta {
        let measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            ROOT_HASH,
            MANIFEST_DIGEST,
        );
        let measurement_hex = measurement.trim_start_matches("sha256:");
        PackageMeta {
            name: "webapp".to_string(),
            version: "1.0.0".to_string(),
            description: String::new(),
            homepage: None,
            license: "MIT".to_string(),
            maintainer: "test".to_string(),
            platform: "x86_64-linux".to_string(),
            store_path: "/nix/store/abc123-webapp-1.0.0".to_string(),
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            nar_size: 1,
            references: Vec::new(),
            source_drv: "/nix/store/srcdrv-webapp-1.0.0.drv".to_string(),
            source_nar_hash: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
            closure_size: 1,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: None,
            requires_features: Vec::new(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: AttestationMeta {
                root_digest: Some(ROOT_HASH.to_string()),
                root_hash: Some(ROOT_HASH.to_string()),
                root_hash_sig: Some("root.roothash.p7s".to_string()),
                provenance: Some(format!(
                    "provenance/w/webapp/x86_64-linux/{measurement_hex}.intoto.jsonl"
                )),
                measurement: Some(measurement),
            },
        }
    }

    fn statement_for(meta: &PackageMeta) -> serde_json::Value {
        let attestation = &meta.attestation;
        let measurement = attestation.measurement.as_deref().unwrap();
        let provenance = attestation.provenance.as_deref().unwrap();
        let root_digest = attestation.root_digest.as_deref().unwrap();
        let root_hash = attestation.root_hash.as_deref().unwrap();
        let root_hash_sig = attestation.root_hash_sig.as_deref().unwrap();
        let source_uri = format!("nix:{}", meta.source_drv);
        serde_json::json!({
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": meta.store_path.as_str(),
                    "digest": digest_map(&meta.nar_hash),
                },
                {
                    "name": format!(
                        "aos:permissions-manifest:{}:{}:{}",
                        meta.name, meta.version, meta.platform
                    ),
                    "digest": digest_map(MANIFEST_DIGEST),
                },
                {
                    "name": format!(
                        "aos:package-measurement:{}:{}:{}",
                        meta.name, meta.version, meta.platform
                    ),
                    "digest": digest_map(measurement),
                },
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPE,
                    "externalParameters": {
                        "package": meta.name.as_str(),
                        "version": meta.version.as_str(),
                        "platform": meta.platform.as_str(),
                        "store_path": meta.store_path.as_str(),
                        "root_digest": root_digest,
                        "root_hash": root_hash,
                        "root_hash_sig": root_hash_sig,
                        "provenance": provenance,
                    },
                    "resolvedDependencies": [
                        {
                            "uri": source_uri,
                            "digest": digest_map(&meta.source_nar_hash),
                        },
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": builder_id(REGISTRY, KEY_ID),
                    },
                },
            },
        })
    }

    fn non_verity_meta() -> PackageMeta {
        let root_digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            root_digest,
            MANIFEST_DIGEST,
        );
        let measurement_hex = measurement.trim_start_matches("sha256:");
        let mut meta = sample_meta();
        meta.attestation = AttestationMeta {
            root_digest: Some(root_digest.to_string()),
            root_hash: None,
            root_hash_sig: None,
            provenance: Some(format!(
                "provenance/w/webapp/x86_64-linux/{measurement_hex}.intoto.jsonl"
            )),
            measurement: Some(measurement),
        };
        meta
    }

    fn non_verity_statement_for(meta: &PackageMeta) -> serde_json::Value {
        let attestation = &meta.attestation;
        let measurement = attestation.measurement.as_deref().unwrap();
        let provenance = attestation.provenance.as_deref().unwrap();
        let root_digest = attestation.root_digest.as_deref().unwrap();
        serde_json::json!({
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": meta.store_path.as_str(),
                    "digest": digest_map(&meta.nar_hash),
                },
                {
                    "name": format!(
                        "aos:permissions-manifest:{}:{}:{}",
                        meta.name, meta.version, meta.platform
                    ),
                    "digest": digest_map(MANIFEST_DIGEST),
                },
                {
                    "name": format!(
                        "aos:package-measurement:{}:{}:{}",
                        meta.name, meta.version, meta.platform
                    ),
                    "digest": digest_map(measurement),
                },
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPE,
                    "externalParameters": {
                        "package": meta.name.as_str(),
                        "version": meta.version.as_str(),
                        "platform": meta.platform.as_str(),
                        "store_path": meta.store_path.as_str(),
                        "root_digest": root_digest,
                        "provenance": provenance,
                    },
                    "resolvedDependencies": [
                        {
                            "uri": format!("nix:{}", meta.source_drv),
                            "digest": digest_map(&meta.source_nar_hash),
                        },
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": builder_id(REGISTRY, KEY_ID),
                    },
                },
            },
        })
    }

    #[test]
    fn digest_map_uses_nix_nar_hash_for_sri_values() {
        let map = digest_map("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        assert_eq!(
            map["nix:narHash"].as_str(),
            Some("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );
        assert!(map.get("sha256").is_none());
    }

    #[test]
    fn digest_map_uses_sha256_for_hex_values() {
        let map =
            digest_map("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        assert_eq!(
            map["sha256"].as_str(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(map.get("nix:narHash").is_none());
    }

    #[test]
    fn ensure_digest_matches_accepts_equivalent_nar_hash_encodings() {
        // The provenance statement keeps the NAR hash in its `nix path-info`
        // SRI spelling, while the loaded registry meta normalizes it to the
        // canonical `sha256:<nix32>` form. Both encode the same digest and must
        // compare equal.
        let sri = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let nix32 = normalize_sha256_nix32(sri);
        assert_ne!(
            sri, nix32,
            "the two spellings must differ for the test to bite"
        );

        let digest = match digest_map(sri) {
            serde_json::Value::Object(map) => map
                .into_iter()
                .map(|(key, value)| {
                    (
                        key,
                        value
                            .as_str()
                            .expect("digest values are strings")
                            .to_string(),
                    )
                })
                .collect::<BTreeMap<String, String>>(),
            other => panic!("digest_map must return an object, got {other:?}"),
        };

        ensure_digest_matches("package NAR", &digest, &nix32)
            .expect("base32 meta hash must match an SRI statement digest");
    }

    #[test]
    fn verify_package_statement_accepts_bound_slsa_statement() {
        let key = test_key();
        let meta = sample_meta();
        let statement = signed_statement(statement_for(&meta), &key);

        verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap();
    }

    #[test]
    fn verify_statement_dsse_rejects_duplicate_trusted_key_material() {
        let key = test_key();
        let meta = sample_meta();
        let statement = signed_statement(statement_for(&meta), &key);
        let mut trusted = key.trusted();
        trusted.push(TrustedProvenanceKey {
            key_id: "alias".to_string(),
            key: key.trusted_key.clone(),
            retired_before_sequence: None,
        });

        let err = verify_statement_dsse_jsonl(&statement, &trusted).unwrap_err();

        assert!(format!("{err:#}").contains("trusted key material"));
    }

    #[test]
    fn retired_provenance_key_is_limited_by_transparency_sequence() {
        let key = test_key();
        let trusted = vec![TrustedProvenanceKey {
            key_id: KEY_ID.to_string(),
            key: key.trusted_key.clone(),
            retired_before_sequence: Some(3),
        }];

        verify_key_allowed_for_transparency_sequence(&trusted, KEY_ID, 2).unwrap();
        let err = verify_key_allowed_for_transparency_sequence(&trusted, KEY_ID, 3).unwrap_err();

        assert!(format!("{err:#}").contains("was retired before transparency sequence 3"));
    }

    #[test]
    fn verify_package_statement_accepts_non_verity_root_digest() {
        let key = test_key();
        let meta = non_verity_meta();
        let statement = signed_statement(non_verity_statement_for(&meta), &key);

        verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap();
    }

    #[test]
    fn verify_package_statement_rejects_unsigned_statement() {
        let key = test_key();
        let meta = sample_meta();
        let statement = format!(
            "{}\n",
            serde_json::to_string(&statement_for(&meta)).unwrap()
        );

        let err =
            verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap_err();

        assert!(format!("{err:#}").contains("deserializing provenance DSSE envelope"));
    }

    #[test]
    fn verify_package_statement_rejects_wrong_builder_identity() {
        let key = test_key();
        let meta = sample_meta();
        let mut statement = statement_for(&meta);
        statement["predicate"]["runDetails"]["builder"]["id"] =
            serde_json::json!(builder_id(REGISTRY, "other-key"));
        let statement = signed_statement(statement, &key);

        let err =
            verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap_err();

        assert!(err.to_string().contains("builder id mismatch"));
    }

    #[test]
    fn verify_package_statement_rejects_manifest_measurement_mismatch() {
        let key = test_key();
        let meta = sample_meta();
        let mut statement = statement_for(&meta);
        statement["subject"][1]["digest"]["sha256"] =
            serde_json::json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let statement = signed_statement(statement, &key);

        let err =
            verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap_err();

        assert!(
            err.to_string()
                .contains("manifest digest does not match registry measurement")
        );
    }

    #[test]
    fn verify_package_statement_rejects_source_digest_mismatch() {
        let key = test_key();
        let mut meta = sample_meta();
        let statement = signed_statement(statement_for(&meta), &key);
        meta.source_nar_hash = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_string();

        let err =
            verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap_err();

        assert!(
            err.to_string()
                .contains("source derivation NAR nix:narHash digest mismatch")
        );
    }

    #[test]
    fn verify_package_statement_rejects_duplicate_subjects() {
        let key = test_key();
        let meta = sample_meta();
        let mut statement = statement_for(&meta);
        let duplicate = statement["subject"][0].clone();
        statement["subject"].as_array_mut().unwrap().push(duplicate);
        let statement = signed_statement(statement, &key);

        let err =
            verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap_err();

        assert!(format!("{err:#}").contains("duplicate subject"));
    }

    #[test]
    fn verify_package_statement_rejects_duplicate_source_dependencies() {
        let key = test_key();
        let meta = sample_meta();
        let mut statement = statement_for(&meta);
        let duplicate =
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0].clone();
        statement["predicate"]["buildDefinition"]["resolvedDependencies"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        let statement = signed_statement(statement, &key);

        let err =
            verify_package_statement(&meta, REGISTRY, &statement, &key.trusted()).unwrap_err();

        assert!(err.to_string().contains("duplicate source dependency"));
    }
}

//! in-toto/SLSA package provenance helpers.
//!
//! `apr publish` emits one JSONL statement per attested package root and
//! `apm install` verifies the same statement from the synced registry cache.
//! This module keeps the digest key semantics shared between producer and
//! consumer code: real 64-character SHA-256 hex payloads are exposed as
//! standard in-toto `sha256` digests, while Nix SRI/base32 NAR hashes retain
//! their original spelling under `nix:narHash`.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::types::PackageMeta;

const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
const BUILD_TYPE: &str = "https://andyl.com/aos/apr-publish/v1";

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

/// Verifies a package's registry-hosted in-toto/SLSA provenance statement.
///
/// # Errors
///
/// Returns an error when the JSONL does not contain exactly one valid
/// statement, the statement has the wrong in-toto/SLSA type, or any subject,
/// dependency, or external parameter fails to match the package metadata.
pub(crate) fn verify_package_statement(meta: &PackageMeta, jsonl: &str) -> Result<()> {
    let statement = parse_single_statement(jsonl)
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

    let attestation = &meta.attestation;
    let root_hash = attestation
        .root_hash
        .as_deref()
        .context("package provenance requires root_hash")?;
    let root_hash_sig = attestation
        .root_hash_sig
        .as_deref()
        .context("package provenance requires root_hash_sig")?;
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
    ensure_eq("root_hash", &params.root_hash, root_hash)?;
    ensure_eq("root_hash_sig", &params.root_hash_sig, root_hash_sig)?;
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
        root_hash,
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

    Ok(())
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
    root_hash: String,
    root_hash_sig: String,
    provenance: String,
}

#[derive(Debug, Deserialize)]
struct ProvenanceDependency {
    uri: String,
    #[serde(default)]
    digest: BTreeMap<String, String>,
}

fn parse_single_statement(jsonl: &str) -> Result<ProvenanceStatement> {
    let mut lines = jsonl.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().context("provenance JSONL is empty")?;
    if lines.next().is_some() {
        bail!("provenance JSONL must contain exactly one statement");
    }
    serde_json::from_str(line).context("deserializing provenance statement")
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
    if actual == expected {
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
    use crate::types::{AttestationMeta, PackageMeta};

    const ROOT_HASH: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const MANIFEST_DIGEST: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

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

    fn statement_for(meta: &PackageMeta) -> String {
        let attestation = &meta.attestation;
        let measurement = attestation.measurement.as_deref().unwrap();
        let provenance = attestation.provenance.as_deref().unwrap();
        let root_hash = attestation.root_hash.as_deref().unwrap();
        let root_hash_sig = attestation.root_hash_sig.as_deref().unwrap();
        let source_uri = format!("nix:{}", meta.source_drv);
        let statement = serde_json::json!({
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
            },
        });
        format!("{}\n", serde_json::to_string(&statement).unwrap())
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
    fn verify_package_statement_accepts_bound_slsa_statement() {
        let meta = sample_meta();
        let statement = statement_for(&meta);

        verify_package_statement(&meta, &statement).unwrap();
    }

    #[test]
    fn verify_package_statement_rejects_manifest_measurement_mismatch() {
        let meta = sample_meta();
        let statement = statement_for(&meta).replace(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );

        let err = verify_package_statement(&meta, &statement).unwrap_err();

        assert!(
            err.to_string()
                .contains("manifest digest does not match registry measurement")
        );
    }

    #[test]
    fn verify_package_statement_rejects_source_digest_mismatch() {
        let mut meta = sample_meta();
        let statement = statement_for(&meta);
        meta.source_nar_hash = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_string();

        let err = verify_package_statement(&meta, &statement).unwrap_err();

        assert!(
            err.to_string()
                .contains("source derivation NAR nix:narHash digest mismatch")
        );
    }

    #[test]
    fn verify_package_statement_rejects_duplicate_subjects() {
        let meta = sample_meta();
        let mut statement: serde_json::Value =
            serde_json::from_str(statement_for(&meta).trim_end()).unwrap();
        let duplicate = statement["subject"][0].clone();
        statement["subject"].as_array_mut().unwrap().push(duplicate);
        let statement = format!("{}\n", serde_json::to_string(&statement).unwrap());

        let err = verify_package_statement(&meta, &statement).unwrap_err();

        assert!(format!("{err:#}").contains("duplicate subject"));
    }

    #[test]
    fn verify_package_statement_rejects_duplicate_source_dependencies() {
        let meta = sample_meta();
        let mut statement: serde_json::Value =
            serde_json::from_str(statement_for(&meta).trim_end()).unwrap();
        let duplicate =
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0].clone();
        statement["predicate"]["buildDefinition"]["resolvedDependencies"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        let statement = format!("{}\n", serde_json::to_string(&statement).unwrap());

        let err = verify_package_statement(&meta, &statement).unwrap_err();

        assert!(err.to_string().contains("duplicate source dependency"));
    }
}

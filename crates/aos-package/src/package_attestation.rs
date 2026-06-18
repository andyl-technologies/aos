//! Package-set TPM measurement for RFC-0001 runtime attestation.
//!
//! Activation writes an AOS package event log at
//! `/run/log/aos-packages.cel` and, on the live system root, extends PCR 15
//! through AOS-built `systemd-pcrextend`. The measured package tuple is:
//!
//! ```text
//! H(name || version || root-digest || manifest-digest)
//! ```
//!
//! The implementation uses a stable length-prefixed text encoding for the
//! tuple so a verifier can replay the event log without guessing separators.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{ApmMeta, InstalledMeta, PackageMeta};

const AOS_PACKAGE_CEL_REL: &str = "run/log/aos-packages.cel";
const PCR_EXTEND_ENV: &str = "AOS_SYSTEMD_PCREXTEND";
const PCR_INDEX: u8 = 15;
const PCR_BANK: &str = "sha256";
const PACKAGE_EVENT_TYPE: &str = "aos-package";
const PACKAGE_SET_EVENT_TYPE: &str = "aos-package-set";

/// Measures the activated exposed package set into PCR 15.
///
/// The event log is rooted at `root` so tests and image construction can
/// exercise the same code against an alternate filesystem. PCR extension runs
/// only for the live `/` root; non-live roots still get deterministic event
/// log contents.
///
/// # Errors
///
/// Returns an error if package metadata cannot be converted into measurement
/// events, the event log cannot be written, or live PCR extension fails.
pub(crate) fn measure_activated_packages(root: &Path, installed: &[InstalledMeta]) -> Result<()> {
    let events = measurement_events(root, installed)?;
    append_event_log(root, &events)?;
    if root == Path::new("/") {
        let pcrextend = trusted_systemd_pcrextend_path()?;
        extend_pcr15(&pcrextend, &events)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasurementEvent {
    event_type: &'static str,
    word: String,
    digest: String,
    package: Option<MeasuredPackage>,
    package_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasuredPackage {
    name: String,
    version: String,
    root_digest: String,
    manifest_digest: String,
}

#[derive(Serialize)]
struct EventLogRecord<'a> {
    format: &'static str,
    pcr: u8,
    bank: &'static str,
    event_type: &'static str,
    digest: &'a str,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_count: Option<usize>,
}

#[derive(Deserialize)]
struct OwnedEventLogRecord {
    format: String,
    pcr: u8,
    bank: String,
    event_type: String,
    digest: String,
    event: String,
    package: Option<String>,
    version: Option<String>,
    root_digest: Option<String>,
    manifest_digest: Option<String>,
    package_count: Option<usize>,
}

/// Result of replaying and validating the package attestation event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageEventLogVerification {
    /// Replayed PCR 15 value as lowercase SHA-256 hex.
    pub pcr15: String,
    /// Number of package tuple events validated against the registry catalog.
    pub package_count: usize,
}

#[derive(Debug)]
struct PendingPackageSet {
    remaining: usize,
    expected_digests: Vec<String>,
    next_digest: usize,
}

fn measurement_events(root: &Path, installed: &[InstalledMeta]) -> Result<Vec<MeasurementEvent>> {
    let mut packages = installed
        .iter()
        .filter_map(|entry| {
            let apm = entry.apm.as_ref()?;
            if !apm.explicit || apm.expose.is_none() {
                return None;
            }
            Some(measured_package(root, entry, apm))
        })
        .collect::<Result<Vec<_>>>()?;
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
            .then(left.root_digest.cmp(&right.root_digest))
    });

    let mut events = Vec::with_capacity(packages.len() + 1);
    let package_events = packages
        .into_iter()
        .map(package_event)
        .collect::<Result<Vec<_>>>()?;
    events.push(package_set_event(&package_events));
    events.extend(package_events);
    Ok(events)
}

fn measured_package(root: &Path, entry: &InstalledMeta, apm: &ApmMeta) -> Result<MeasuredPackage> {
    let root_digest = package_root_digest(entry, apm);
    let manifest_digest = package_manifest_digest(root, apm)?;
    let package = MeasuredPackage {
        name: apm.name.clone(),
        version: apm.version.clone(),
        root_digest,
        manifest_digest,
    };

    if let Some(expected) = &apm.attestation.measurement {
        let expected = canonical_digest(expected);
        let actual = package_measurement_digest(
            &package.name,
            &package.version,
            &package.root_digest,
            &package.manifest_digest,
        );
        if expected != actual {
            bail!(
                "attestation measurement for package '{}' does not match installed metadata",
                apm.name
            );
        }
    }

    Ok(package)
}

fn package_root_digest(entry: &InstalledMeta, apm: &ApmMeta) -> String {
    if let Some(root_hash) = &apm.attestation.root_hash {
        return canonical_digest(root_hash);
    }

    if let Some(expose) = &apm.expose
        && let Some(root_hash) = expose
            .images
            .iter()
            .find_map(|image| image.root_hash.as_deref())
    {
        return canonical_digest(root_hash);
    }

    canonical_digest(&entry.apm.as_ref().map_or_else(
        || entry.store_path.clone(),
        |apm| {
            if apm.source_nar_hash.is_empty() {
                entry.store_path.clone()
            } else {
                apm.source_nar_hash.clone()
            }
        },
    ))
}

fn package_manifest_digest(root: &Path, apm: &ApmMeta) -> Result<String> {
    if let Some(artifact) = &apm.expose_artifact {
        let manifest = Path::new(&artifact.store_path).join("manifest.json");
        if manifest.is_file() {
            let bytes = fs::read(&manifest)
                .with_context(|| format!("reading expose manifest {}", manifest.display()))?;
            return Ok(package_manifest_digest_bytes(&bytes));
        }
        if root == Path::new("/") {
            bail!(
                "exposed package '{}' is missing signed manifest at {}",
                apm.name,
                manifest.display()
            );
        }
    }

    let bytes = serde_json::to_vec(&apm.permissions)
        .with_context(|| format!("serializing permissions for package '{}'", apm.name))?;
    Ok(package_manifest_digest_bytes(&bytes))
}

/// Returns the RFC-0001 golden package measurement tuple digest.
pub(crate) fn package_measurement_digest(
    name: &str,
    version: &str,
    root_digest: &str,
    manifest_digest: &str,
) -> String {
    let package = MeasuredPackage {
        name: name.to_string(),
        version: version.to_string(),
        root_digest: canonical_digest(root_digest),
        manifest_digest: canonical_digest(manifest_digest),
    };
    format!("sha256:{}", digest_for_word(&package_tuple_word(&package)))
}

/// Returns the manifest digest format used in package measurement events.
pub(crate) fn package_manifest_digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_hex(bytes))
}

/// Replays and verifies the package event log against a quoted PCR 15 value
/// and registry golden measurements.
///
/// # Errors
///
/// Returns an error when the log is malformed, PCR replay does not match
/// `expected_pcr15`, or any package tuple is missing from or disagrees with
/// the registry catalog.
pub(crate) fn verify_package_event_log_against_catalog(
    event_log: &str,
    expected_pcr15: &str,
    catalog: &[PackageMeta],
) -> Result<PackageEventLogVerification> {
    let expected_pcr15 = parse_sha256_hex("expected PCR 15", expected_pcr15)?;
    let catalog = package_measurement_catalog(catalog)?;
    let mut pcr = [0u8; 32];
    let mut package_count = 0usize;
    let mut pending_package_set: Option<PendingPackageSet> = None;
    let mut saw_package_set = false;

    for (index, line) in event_log.lines().enumerate() {
        if line.trim().is_empty() {
            bail!("package event log contains a blank line at {}", index + 1);
        }
        let record: OwnedEventLogRecord = serde_json::from_str(line)
            .with_context(|| format!("parsing package event log line {}", index + 1))?;
        validate_event_record_shape(index + 1, &record)?;
        let event_digest = event_digest_hex(&record.event);
        let recorded_digest = parse_prefixed_sha256_hex("event digest", &record.digest)?;
        if recorded_digest != event_digest {
            bail!(
                "package event log line {} has an invalid event digest",
                index + 1
            );
        }
        extend_replayed_pcr(&mut pcr, &recorded_digest)?;

        match record.event_type.as_str() {
            PACKAGE_SET_EVENT_TYPE => {
                if pending_package_set
                    .as_ref()
                    .is_some_and(|pending| pending.remaining != 0)
                {
                    bail!(
                        "package event log line {} starts a package set before the previous set completed",
                        index + 1
                    );
                }
                saw_package_set = true;
                pending_package_set = Some(parse_package_set_record(index + 1, &record)?);
            }
            PACKAGE_EVENT_TYPE => {
                let Some(pending) = pending_package_set.as_mut() else {
                    bail!(
                        "package event log line {} appears before a package-set event",
                        index + 1
                    );
                };
                if pending.remaining == 0 {
                    bail!(
                        "package event log line {} exceeds the declared package_count",
                        index + 1
                    );
                }
                let expected_digest = pending
                    .expected_digests
                    .get(pending.next_digest)
                    .with_context(|| {
                        format!(
                            "package event log line {} exceeds the package-set digest list",
                            index + 1
                        )
                    })?;
                if expected_digest != &recorded_digest {
                    bail!(
                        "package event log line {} does not match the package-set digest list",
                        index + 1
                    );
                }
                pending.remaining -= 1;
                pending.next_digest += 1;
                verify_package_record(index + 1, &record, &recorded_digest, &catalog)?;
                package_count += 1;
            }
            _ => bail!(
                "package event log line {} has unsupported event_type '{}'",
                index + 1,
                record.event_type
            ),
        }
    }

    if !saw_package_set {
        bail!("package event log contains no package-set event");
    }
    if pending_package_set
        .as_ref()
        .is_some_and(|pending| pending.remaining != 0)
    {
        bail!("package event log ended before the declared package set completed");
    }

    let pcr15 = hex::encode(pcr);
    if pcr15 != expected_pcr15 {
        bail!("package event log replayed PCR 15 {pcr15}, expected {expected_pcr15}");
    }

    Ok(PackageEventLogVerification {
        pcr15,
        package_count,
    })
}

/// Replays only the PCR 15 digest for a package event log.
///
/// This is useful for tests and for quote integrations that need to compare a
/// live PCR value after separately validating package catalog membership.
///
/// # Errors
///
/// Returns an error when the event log is malformed or contains an invalid
/// event digest.
#[cfg(test)]
fn replay_package_event_log_pcr15(event_log: &str) -> Result<String> {
    let mut pcr = [0u8; 32];
    for (index, line) in event_log.lines().enumerate() {
        if line.trim().is_empty() {
            bail!("package event log contains a blank line at {}", index + 1);
        }
        let record: OwnedEventLogRecord = serde_json::from_str(line)
            .with_context(|| format!("parsing package event log line {}", index + 1))?;
        validate_event_record_shape(index + 1, &record)?;
        let event_digest = event_digest_hex(&record.event);
        let recorded_digest = parse_prefixed_sha256_hex("event digest", &record.digest)?;
        if recorded_digest != event_digest {
            bail!(
                "package event log line {} has an invalid event digest",
                index + 1
            );
        }
        extend_replayed_pcr(&mut pcr, &recorded_digest)?;
    }
    Ok(hex::encode(pcr))
}

fn package_event(package: MeasuredPackage) -> Result<MeasurementEvent> {
    let word = package_tuple_word(&package);
    let digest = format!("sha256:{}", digest_for_word(&word));
    Ok(MeasurementEvent {
        event_type: PACKAGE_EVENT_TYPE,
        word,
        digest,
        package: Some(package),
        package_count: None,
    })
}

fn package_set_event(package_events: &[MeasurementEvent]) -> MeasurementEvent {
    let digests = package_events
        .iter()
        .map(|event| event.digest.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let word = length_prefixed_word(
        "aos-package-set-v1",
        &[
            ("package-count", package_events.len().to_string()),
            ("package-digests", digests),
        ],
    );
    let digest = format!("sha256:{}", digest_for_word(&word));
    MeasurementEvent {
        event_type: PACKAGE_SET_EVENT_TYPE,
        word,
        digest,
        package: None,
        package_count: Some(package_events.len()),
    }
}

fn package_tuple_word(package: &MeasuredPackage) -> String {
    length_prefixed_word(
        "aos-package-v1",
        &[
            ("name", package.name.clone()),
            ("version", package.version.clone()),
            ("root-digest", package.root_digest.clone()),
            ("manifest-digest", package.manifest_digest.clone()),
        ],
    )
}

fn length_prefixed_word(schema: &str, fields: &[(&str, String)]) -> String {
    let mut word = String::from(schema);
    for (name, value) in fields {
        word.push('|');
        word.push_str(name);
        word.push('=');
        word.push_str(&value.len().to_string());
        word.push(':');
        word.push_str(value);
    }
    word
}

fn parse_length_prefixed_word(schema: &str, word: &str) -> Result<BTreeMap<String, String>> {
    if !word.starts_with(schema) {
        bail!("event word must start with schema '{schema}'");
    }
    let bytes = word.as_bytes();
    let mut fields = BTreeMap::new();
    let mut pos = schema.len();
    while pos < bytes.len() {
        if bytes[pos] != b'|' {
            bail!("event word field must start with '|'");
        }
        pos += 1;
        let name_start = pos;
        let Some(eq_rel) = bytes[pos..].iter().position(|byte| *byte == b'=') else {
            bail!("event word field is missing '='");
        };
        let eq = pos + eq_rel;
        let name = word
            .get(name_start..eq)
            .context("event word field name is not valid UTF-8")?;
        if name.is_empty() {
            bail!("event word field name must not be empty");
        }
        pos = eq + 1;
        let len_start = pos;
        let Some(colon_rel) = bytes[pos..].iter().position(|byte| *byte == b':') else {
            bail!("event word field is missing ':'");
        };
        let colon = pos + colon_rel;
        let len_text = word
            .get(len_start..colon)
            .context("event word field length is not valid UTF-8")?;
        let len = len_text
            .parse::<usize>()
            .context("event word field length is not a number")?;
        pos = colon + 1;
        let end = pos
            .checked_add(len)
            .context("event word field length overflows")?;
        let value = word
            .get(pos..end)
            .context("event word field value extends past the event word or splits UTF-8")?;
        if fields.insert(name.to_string(), value.to_string()).is_some() {
            bail!("event word contains duplicate field '{name}'");
        }
        pos = end;
    }
    Ok(fields)
}

fn package_measurement_catalog(
    catalog: &[PackageMeta],
) -> Result<BTreeMap<(String, String), (String, String)>> {
    let mut measurements = BTreeMap::new();
    for meta in catalog {
        let Some(measurement) = &meta.attestation.measurement else {
            continue;
        };
        let measurement = parse_sha256_hex("registry package measurement", measurement)?;
        let root_hash = meta
            .attestation
            .root_hash
            .as_deref()
            .map(|root_hash| parse_sha256_hex("registry package root_hash", root_hash))
            .transpose()?
            .unwrap_or_default();
        let key = (meta.name.clone(), meta.version.clone());
        let value = (measurement, root_hash);
        if let Some(existing) = measurements.insert(key.clone(), value.clone())
            && existing != value
        {
            bail!(
                "registry catalog has conflicting golden measurements for {} {}",
                key.0,
                key.1
            );
        }
    }
    Ok(measurements)
}

fn validate_event_record_shape(line: usize, record: &OwnedEventLogRecord) -> Result<()> {
    if record.format != "aos-package-cel-v1" {
        bail!(
            "package event log line {line} has unsupported format '{}'",
            record.format
        );
    }
    if record.pcr != PCR_INDEX {
        bail!(
            "package event log line {line} targets PCR {}, expected {PCR_INDEX}",
            record.pcr
        );
    }
    if record.bank != PCR_BANK {
        bail!(
            "package event log line {line} uses bank '{}', expected {PCR_BANK}",
            record.bank
        );
    }
    Ok(())
}

fn parse_package_set_record(
    line: usize,
    record: &OwnedEventLogRecord,
) -> Result<PendingPackageSet> {
    let fields = parse_length_prefixed_word("aos-package-set-v1", &record.event)
        .with_context(|| format!("parsing package-set event word on line {line}"))?;
    let count = fields
        .get("package-count")
        .with_context(|| format!("package-set event on line {line} is missing package-count"))?
        .parse::<usize>()
        .with_context(|| format!("package-set event on line {line} has invalid package-count"))?;
    let json_count = record
        .package_count
        .with_context(|| format!("package-set event on line {line} is missing package_count"))?;
    if json_count != count {
        bail!("package-set event on line {line} package_count does not match the measured word");
    }
    let digest_field = fields
        .get("package-digests")
        .with_context(|| format!("package-set event on line {line} is missing package-digests"))?;
    let expected_digests = if digest_field.is_empty() {
        Vec::new()
    } else {
        digest_field
            .split(',')
            .map(|digest| parse_prefixed_sha256_hex("package-set package digest", digest))
            .collect::<Result<Vec<_>>>()?
    };
    if expected_digests.len() != count {
        bail!(
            "package-set event on line {line} package-digests length does not match package-count"
        );
    }
    Ok(PendingPackageSet {
        remaining: count,
        expected_digests,
        next_digest: 0,
    })
}

fn verify_package_record(
    line: usize,
    record: &OwnedEventLogRecord,
    recorded_digest: &str,
    catalog: &BTreeMap<(String, String), (String, String)>,
) -> Result<()> {
    let package = record
        .package
        .as_deref()
        .with_context(|| format!("package event on line {line} is missing package"))?;
    let version = record
        .version
        .as_deref()
        .with_context(|| format!("package event on line {line} is missing version"))?;
    let root_digest = record
        .root_digest
        .as_deref()
        .with_context(|| format!("package event on line {line} is missing root_digest"))?;
    let manifest_digest = record
        .manifest_digest
        .as_deref()
        .with_context(|| format!("package event on line {line} is missing manifest_digest"))?;
    let expected_digest =
        package_measurement_digest(package, version, root_digest, manifest_digest);
    let expected_digest = parse_prefixed_sha256_hex("package event digest", &expected_digest)?;
    if expected_digest != recorded_digest {
        bail!("package event on line {line} does not match its tuple fields");
    }

    let key = (package.to_string(), version.to_string());
    let (catalog_measurement, catalog_root_hash) = catalog.get(&key).with_context(|| {
        format!("registry catalog has no golden measurement for {package} {version}")
    })?;
    if catalog_measurement != recorded_digest {
        bail!("package event on line {line} does not match the registry golden measurement");
    }
    if !catalog_root_hash.is_empty() {
        let root_digest = parse_prefixed_sha256_hex("package event root_digest", root_digest)?;
        if catalog_root_hash != &root_digest {
            bail!("package event on line {line} root digest does not match the registry catalog");
        }
    }
    Ok(())
}

fn extend_replayed_pcr(pcr: &mut [u8; 32], event_digest_hex: &str) -> Result<()> {
    let event_digest = hex::decode(event_digest_hex)
        .with_context(|| format!("decoding event digest {event_digest_hex}"))?;
    if event_digest.len() != 32 {
        bail!(
            "event digest {event_digest_hex} decoded to {} bytes, expected 32",
            event_digest.len()
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(*pcr);
    hasher.update(&event_digest);
    pcr.copy_from_slice(&hasher.finalize());
    Ok(())
}

fn event_digest_hex(event: &str) -> String {
    digest_for_word(event)
}

fn extend_pcr15(pcrextend: &Path, events: &[MeasurementEvent]) -> Result<()> {
    for event in events {
        let status = Command::new(pcrextend)
            .arg("--graceful")
            .arg(format!("--bank={PCR_BANK}"))
            .arg(format!("--pcr={PCR_INDEX}"))
            .arg(&event.word)
            .status()
            .with_context(|| format!("running {}", pcrextend.display()))?;
        if !status.success() {
            bail!(
                "{} failed to extend PCR {PCR_INDEX}: {status}",
                pcrextend.display()
            );
        }
    }
    Ok(())
}

fn append_event_log(root: &Path, events: &[MeasurementEvent]) -> Result<()> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    let parent = path
        .parent()
        .with_context(|| format!("event log path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    for event in events {
        let line = event_log_line(event)?;
        writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

fn event_log_line(event: &MeasurementEvent) -> Result<String> {
    let package = event.package.as_ref();
    let record = EventLogRecord {
        format: "aos-package-cel-v1",
        pcr: PCR_INDEX,
        bank: PCR_BANK,
        event_type: event.event_type,
        digest: &event.digest,
        event: &event.word,
        package: package.map(|package| package.name.as_str()),
        version: package.map(|package| package.version.as_str()),
        root_digest: package.map(|package| package.root_digest.as_str()),
        manifest_digest: package.map(|package| package.manifest_digest.as_str()),
        package_count: event.package_count,
    };
    serde_json::to_string(&record).context("serializing package measurement event")
}

fn trusted_systemd_pcrextend_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(PCR_EXTEND_ENV) {
        if path.is_empty() {
            bail!("{PCR_EXTEND_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/lib/systemd/systemd-pcrextend") {
            bail!("{PCR_EXTEND_ENV} must point to an absolute systemd-pcrextend binary");
        }
        return Ok(PathBuf::from(path));
    }

    #[cfg(test)]
    {
        return Ok(PathBuf::from(
            "/nix/store/hash-systemd-0/lib/systemd/systemd-pcrextend",
        ));
    }

    #[cfg(not(test))]
    {
        bail!("{PCR_EXTEND_ENV} is not configured for package-set measurement");
    }
}

fn rooted_absolute_path(root: &Path, path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("path must be absolute: {}", path.display());
    }
    Ok(root.join(path.strip_prefix("/").unwrap_or(path)))
}

fn canonical_digest(value: &str) -> String {
    let value = value.trim();
    let digest = value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("sha256-"));
    if let Some(digest) = digest
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return format!("sha256:{}", digest.to_ascii_lowercase());
    }
    value.to_string()
}

fn parse_sha256_hex(kind: &str, value: &str) -> Result<String> {
    let value = value.trim();
    let hex = value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("sha256-"))
        .unwrap_or(value);
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(hex.to_ascii_lowercase());
    }
    bail!("{kind} must be a 64-character SHA-256 hex digest");
}

fn parse_prefixed_sha256_hex(kind: &str, value: &str) -> Result<String> {
    let value = value.trim();
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{kind} must start with sha256:");
    };
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(hex.to_ascii_lowercase());
    }
    bail!("{kind} must be a 64-character SHA-256 hex digest");
}

fn digest_for_word(word: &str) -> String {
    digest_hex(word.as_bytes())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ApmMeta, AttestationMeta, ExposeArtifactMeta, ExposeMeta, HostPathMode, HostPathPermission,
        InstalledMeta, NetworkPermission, PACKAGE_META_FORMAT, PackageMeta, PermissionsMeta,
        SysrootImageEntry,
    };
    use tempfile::TempDir;

    fn installed_fixture(tmp: &TempDir, manifest: &[u8]) -> InstalledMeta {
        let artifact = tmp.path().join("artifact");
        fs::create_dir_all(artifact.join("units")).expect("artifact units");
        fs::write(artifact.join("manifest.json"), manifest).expect("manifest");
        InstalledMeta {
            store_path: "/nix/store/hash-web-1.0".into(),
            pushed_at: 1,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "web".into(),
                version: "1.0".into(),
                explicit: true,
                registry: "test".into(),
                installed_at: "2026-06-18T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: "sha256:nar".into(),
                expose: Some(ExposeMeta {
                    target: "aos-pkg-web.target".into(),
                    units: vec!["web.service".into()],
                    images: vec![SysrootImageEntry {
                        format: "ext4-verity".into(),
                        store_path: "/nix/store/image-web".into(),
                        nar_hash: "sha256:image".into(),
                        nar_size: 1,
                        sb_signer_cert_sha256: None,
                        sbat: Vec::new(),
                        expected_pcr11: None,
                        root_image: Some("root.img".into()),
                        root_verity: Some("root.verity".into()),
                        root_hash: Some(
                            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                .into(),
                        ),
                        root_hash_sig: Some("root.roothash.p7s".into()),
                    }],
                    requires: Vec::new(),
                    config: Default::default(),
                    provides: Vec::new(),
                    uses: Vec::new(),
                }),
                expose_artifact: Some(ExposeArtifactMeta {
                    store_path: artifact.display().to_string(),
                    nar_hash: "sha256:artifact".into(),
                    nar_size: manifest.len() as u64,
                }),
                permissions: PermissionsMeta {
                    network: Some(NetworkPermission::Private),
                    host_paths: vec![HostPathPermission {
                        path: "/var/lib/web".into(),
                        mode: HostPathMode::Rw,
                    }],
                    ..Default::default()
                },
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    fn catalog_meta(root_hash: &str, measurement: &str) -> PackageMeta {
        PackageMeta {
            name: "web".into(),
            version: "1.0".into(),
            description: "Web package".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/nix/store/hash-web-1.0".into(),
            nar_hash: "sha256:nar".into(),
            nar_size: 1,
            references: Vec::new(),
            source_drv: String::new(),
            source_nar_hash: "sha256:nar".into(),
            closure_size: 1,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: Some(PACKAGE_META_FORMAT),
            requires_features: vec!["attestation-v1".into()],
            expose: None,
            expose_artifact: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: AttestationMeta {
                root_hash: Some(root_hash.into()),
                root_hash_sig: Some("root.roothash.p7s".into()),
                provenance: None,
                measurement: Some(measurement.into()),
            },
        }
    }

    fn measured_fixture_log(tmp: &TempDir, manifest: &[u8]) -> (String, String, String) {
        let installed = installed_fixture(tmp, manifest);
        let apm = installed.apm.as_ref().expect("apm metadata");
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_digest = package_manifest_digest_bytes(manifest);
        let measurement =
            package_measurement_digest(&apm.name, &apm.version, root_hash, &manifest_digest);
        measure_activated_packages(tmp.path(), &[installed]).expect("measure packages");
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        (log, root_hash.into(), measurement)
    }

    #[test]
    fn package_measurement_includes_root_and_manifest_digests() {
        let tmp = TempDir::new().expect("tempdir");
        let installed = installed_fixture(&tmp, br#"{"permissions":{"network":"private"}}"#);

        let events = measurement_events(tmp.path(), &[installed]).expect("events");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
        let package = events[1].package.as_ref().expect("package event");
        assert_eq!(package.name, "web");
        assert_eq!(
            package.root_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            package.manifest_digest,
            format!(
                "sha256:{}",
                digest_hex(br#"{"permissions":{"network":"private"}}"#)
            )
        );
        assert!(events[1].word.contains("name=3:web"));
    }

    #[test]
    fn package_measurement_changes_when_manifest_changes() {
        let tmp = TempDir::new().expect("tempdir");
        let first = installed_fixture(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let first_digest = measurement_events(tmp.path(), &[first]).expect("first")[1]
            .digest
            .clone();
        let second = installed_fixture(&tmp, br#"{"permissions":{"network":"host"}}"#);
        let second_digest = measurement_events(tmp.path(), &[second]).expect("second")[1]
            .digest
            .clone();

        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn package_measurement_accepts_matching_registry_measurement() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let mut installed = installed_fixture(&tmp, manifest);
        let apm = installed.apm.as_mut().expect("apm metadata");
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_digest = package_manifest_digest_bytes(manifest);
        apm.attestation = AttestationMeta {
            root_hash: Some(root_hash.into()),
            root_hash_sig: Some("root.roothash.p7s".into()),
            provenance: None,
            measurement: Some(package_measurement_digest(
                &apm.name,
                &apm.version,
                root_hash,
                &manifest_digest,
            )),
        };

        measurement_events(tmp.path(), &[installed]).expect("matching measurement");
    }

    #[test]
    fn package_measurement_rejects_mismatched_registry_measurement() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let mut installed = installed_fixture(&tmp, manifest);
        let apm = installed.apm.as_mut().expect("apm metadata");
        apm.attestation = AttestationMeta {
            root_hash: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            root_hash_sig: Some("root.roothash.p7s".into()),
            provenance: None,
            measurement: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ),
        };

        let err = measurement_events(tmp.path(), &[installed]).unwrap_err();
        assert!(format!("{err:#}").contains("does not match installed metadata"));
    }

    #[test]
    fn measure_activated_packages_writes_event_log_under_root() {
        let tmp = TempDir::new().expect("tempdir");
        let installed = installed_fixture(&tmp, br#"{"permissions":{}}"#);

        measure_activated_packages(tmp.path(), &[installed]).expect("measure");

        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        assert!(log.contains("\"format\":\"aos-package-cel-v1\""));
        assert!(log.contains("\"event_type\":\"aos-package-set\""));
        assert!(log.contains("\"event_type\":\"aos-package\""));
        assert!(log.contains("\"package\":\"web\""));
    }

    #[test]
    fn package_event_log_verifier_accepts_catalog_match() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let verified =
            verify_package_event_log_against_catalog(&log, &pcr15, &catalog).expect("verify log");

        assert_eq!(verified.pcr15, pcr15);
        assert_eq!(verified.package_count, 1);
    }

    #[test]
    fn package_event_log_verifier_rejects_pcr_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let catalog = vec![catalog_meta(&root_hash, &measurement)];
        let wrong_pcr = "0000000000000000000000000000000000000000000000000000000000000000";

        let err = verify_package_event_log_against_catalog(&log, wrong_pcr, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("replayed PCR 15"));
    }

    #[test]
    fn package_event_log_verifier_rejects_catalog_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, _) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let catalog = vec![catalog_meta(
            &root_hash,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )];

        let err = verify_package_event_log_against_catalog(&log, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("registry golden measurement"));
    }

    #[test]
    fn package_event_log_verifier_rejects_empty_log() {
        let err = verify_package_event_log_against_catalog(
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            &[],
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("no package-set event"));
    }

    #[test]
    fn package_event_log_verifier_accepts_empty_package_set_event() {
        let tmp = TempDir::new().expect("tempdir");
        measure_activated_packages(tmp.path(), &[]).expect("measure empty package set");
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");

        let verified =
            verify_package_event_log_against_catalog(&log, &pcr15, &[]).expect("verify log");

        assert_eq!(verified.package_count, 0);
    }

    #[test]
    fn package_event_log_verifier_rejects_package_set_digest_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let mut lines = log.lines().collect::<Vec<_>>();
        let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
        let wrong_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let wrong_word = length_prefixed_word(
            "aos-package-set-v1",
            &[
                ("package-count", "1".to_string()),
                ("package-digests", wrong_digest.to_string()),
            ],
        );
        package_set["event"] = serde_json::Value::String(wrong_word.clone());
        package_set["digest"] =
            serde_json::Value::String(format!("sha256:{}", digest_for_word(&wrong_word)));
        let rewritten_set = serde_json::to_string(&package_set).expect("set json");
        lines[0] = &rewritten_set;
        let tampered = lines.join("\n") + "\n";
        let pcr15 = replay_package_event_log_pcr15(&tampered).expect("pcr replay");
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let err =
            verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("package-set digest list"));
    }

    #[test]
    fn package_event_log_verifier_rejects_package_set_count_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let mut lines = log.lines().collect::<Vec<_>>();
        let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
        package_set["package_count"] = serde_json::Value::from(0);
        let rewritten_set = serde_json::to_string(&package_set).expect("set json");
        lines[0] = &rewritten_set;
        let tampered = lines.join("\n") + "\n";
        let pcr15 = replay_package_event_log_pcr15(&tampered).expect("pcr replay");
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let err =
            verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("package_count does not match"));
    }

    #[test]
    fn empty_package_set_still_has_replayable_set_event() {
        let tmp = TempDir::new().expect("tempdir");

        let events = measurement_events(tmp.path(), &[]).expect("events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
        assert_eq!(events[0].package_count, Some(0));
    }
}

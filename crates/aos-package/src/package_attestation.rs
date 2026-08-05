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
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{ApmMeta, InstalledMeta, PackageMeta};

const AOS_PACKAGE_CEL_REL: &str = "run/log/aos-packages.cel";
const PCR_EXTEND_ENV: &str = "AOS_SYSTEMD_PCREXTEND";
const TPM2_CREATEEK_ENV: &str = "AOS_TPM2_CREATEEK";
const TPM2_CREATEAK_ENV: &str = "AOS_TPM2_CREATEAK";
const TPM2_READPUBLIC_ENV: &str = "AOS_TPM2_READPUBLIC";
const TPM2_QUOTE_ENV: &str = "AOS_TPM2_QUOTE";
const TPM2_PCRREAD_ENV: &str = "AOS_TPM2_PCRREAD";
const TPM2_CHECKQUOTE_ENV: &str = "AOS_TPM2_CHECKQUOTE";
const TPM2_FLUSHCONTEXT_ENV: &str = "AOS_TPM2_FLUSHCONTEXT";
const TPM2_TCTI_ENV: &str = "AOS_TPM2_TCTI";
const EVENT_LOG_FORMAT: &str = "aos-package-cel-v1";
const SHA256_DIGEST_SIZE: usize = 32;
const PCR_INDEX: u8 = 15;
const PCR_BANK: &str = "sha256";
const TCG_ALG_SHA256: u16 = 0x000b;
const TCG_EV_NO_ACTION: u32 = 0x00000003;
#[cfg(test)]
const TCG_EV_EVENT_TAG: u32 = 0x00000006;
const QUOTE_PCR_SELECTION: &str = "sha256:7,11,12,15";
const PCR_BASELINE_EVENT_TYPE: &str = "aos-pcr-baseline";
const PACKAGE_EVENT_TYPE: &str = "aos-package";
const PACKAGE_SET_EVENT_TYPE: &str = "aos-package-set";
const GENERATION_EVENT_TYPE: &str = "aos-generation-attestation";

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
    measure_activated_packages_inner(root, installed, root == Path::new("/"), None)
}

/// Measures a canonical generation-attestation record into the shared AOS
/// application-PCR event stream.
///
/// Returns `false` without mutating PCR 15 when the live system has no TPM.
/// The canonical record is still appended to the CEL so TPM-less systems keep
/// inspectable evidence. Once a TPM extension is attempted, its durable CEL
/// event is retained even if the helper reports failure so a retry can recover
/// safely from an ambiguous post-extension error.
///
/// # Errors
///
/// Returns an error if the event log cannot be updated or PCR 15 extension
/// fails through the AOS-built systemd helper.
pub(crate) fn measure_generation_attestation(
    root: &Path,
    generation_id: &str,
    activation_id: &str,
    canonical_record: &[u8],
) -> Result<bool> {
    let word = String::from_utf8(canonical_record.to_vec())
        .context("generation attestation canonical JSON is not UTF-8")?;
    let event = MeasurementEvent {
        event_type: GENERATION_EVENT_TYPE,
        digest: format!("sha256:{}", digest_for_word(&word)),
        word,
        extends_pcr: true,
        pcr_value: None,
        package: None,
        package_count: None,
        generation_id: Some(generation_id.to_string()),
        activation_id: Some(activation_id.to_string()),
    };
    let live_root = root == Path::new("/");
    let has_tpm = live_root && tpm2_tcti()?.is_some();
    let recovery = generation_measurement_recovery(root, &event)?;
    if recovery.found {
        if recovery.has_later_extends {
            bail!(
                "generation attestation {generation_id:?} is followed by newer PCR 15 events; automatic quote recovery is unsafe"
            );
        }
        if !has_tpm {
            return Ok(false);
        }
        let current = read_current_pcr15()?;
        if current.eq_ignore_ascii_case(&recovery.after) {
            return Ok(true);
        }
        if !current.eq_ignore_ascii_case(&recovery.before) {
            bail!(
                "generation attestation {generation_id:?} CEL recovery disagrees with live PCR 15"
            );
        }
        let pcrextend = trusted_systemd_pcrextend_path()?;
        extend_pcr15(&pcrextend, std::slice::from_ref(&event))?;
        return Ok(true);
    }

    let current_pcr = if has_tpm {
        Some(read_current_pcr15()?)
    } else {
        None
    };
    let needs_baseline = has_tpm && !event_log_has_records(root)?;
    if let Some(current) = current_pcr.as_deref()
        && !needs_baseline
        && !current.eq_ignore_ascii_case(&recovery.replayed)
    {
        bail!("generation attestation CEL prefix disagrees with live PCR 15");
    }
    let logged_events = if needs_baseline {
        vec![
            pcr_baseline_event(
                current_pcr
                    .as_deref()
                    .context("missing live PCR baseline")?,
            ),
            event.clone(),
        ]
    } else {
        vec![event.clone()]
    };
    append_event_log(root, &logged_events)?;
    if !has_tpm {
        return Ok(false);
    }
    let pcrextend = trusted_systemd_pcrextend_path()?;
    // Once extension has been attempted, its outcome is ambiguous: the TPM may
    // have committed the new PCR value even when the helper subsequently
    // reports failure. Keep the fsynced CEL event and the caller's durable
    // transaction marker so retry can compare live PCR 15 with the replayed
    // before/after values and either extend once or resume without extending.
    // Removing the event here could strand PCR 15 ahead of its only recovery
    // evidence.
    extend_pcr15(&pcrextend, std::slice::from_ref(&event))?;
    Ok(true)
}

struct GenerationMeasurementRecovery {
    found: bool,
    before: String,
    after: String,
    has_later_extends: bool,
    replayed: String,
}

fn generation_measurement_recovery(
    root: &Path,
    expected: &MeasurementEvent,
) -> Result<GenerationMeasurementRecovery> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    let log = match fs::read_to_string(&path) {
        Ok(log) => log,
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let mut pcr = [0_u8; 32];
    let mut found = false;
    let mut before = hex::encode(pcr);
    let mut after = before.clone();
    let mut has_later_extends = false;
    for (index, line) in log.lines().enumerate() {
        if line.trim().is_empty() {
            bail!("package event log contains a blank line at {}", index + 1);
        }
        let record: OwnedEventLogRecord = serde_json::from_str(line)
            .with_context(|| format!("parsing package event log line {}", index + 1))?;
        validate_event_record_shape(index + 1, &record)?;
        let recorded_digest = parse_prefixed_sha256_hex("event digest", &record.digest)?;
        if recorded_digest != event_digest_hex(&record.event) {
            bail!(
                "package event log line {} has an invalid event digest",
                index + 1
            );
        }
        if record.event_type == PCR_BASELINE_EVENT_TYPE {
            if found {
                bail!("PCR baseline follows generation attestation in the CEL");
            }
            let baseline = record
                .pcr_value
                .as_deref()
                .context("PCR baseline event has no pcr_value")?;
            let baseline = parse_prefixed_sha256_hex("PCR baseline value", baseline)?;
            pcr = parse_pcr_baseline_record(index + 1, &record, &baseline)?;
            continue;
        }
        let is_expected = record.event_type == GENERATION_EVENT_TYPE
            && record.activation_id.as_deref() == expected.activation_id.as_deref();
        if is_expected {
            if found {
                bail!("activation attestation appears more than once in the CEL");
            }
            if record.event != expected.word || record.digest != expected.digest {
                bail!("retained generation attestation CEL event disagrees with the transaction");
            }
            found = true;
            before = hex::encode(pcr);
        } else if found {
            has_later_extends = true;
        }
        extend_replayed_pcr(&mut pcr, &recorded_digest)?;
        if is_expected {
            after = hex::encode(pcr);
        }
    }
    Ok(GenerationMeasurementRecovery {
        found,
        before,
        after,
        has_later_extends,
        replayed: hex::encode(pcr),
    })
}

/// Returns whether the trusted TPM transport can address a local TPM.
///
/// # Errors
///
/// Returns an error when an explicitly configured TPM transport is invalid.
pub(crate) fn tpm_available() -> Result<bool> {
    Ok(tpm2_tcti()?.is_some())
}

fn measure_activated_packages_inner(
    root: &Path,
    installed: &[InstalledMeta],
    live_root: bool,
    pcrextend_override: Option<&Path>,
) -> Result<()> {
    let events = measurement_events(root, installed)?;
    // PCR 15 measurement requires a TPM. On systems without one — most VMs,
    // TPM-less hardware — the live baseline read and PCR extension are skipped:
    // the package event log is still written deterministically, but there is no
    // PCR to anchor it to, so the seed/activation path degrades gracefully
    // rather than failing the whole reconcile. Measured-boot systems (TPM
    // present) keep the full read-then-extend path. `tpm2_tcti` already encodes
    // presence detection (the `AOS_TPM2_TCTI` override, then `/dev/tpmrm0` /
    // `/dev/tpm0`). An explicit `pcrextend_override` forces the live path so
    // unit tests can exercise extension/rollback without a TPM.
    let measure_pcr = live_root && (pcrextend_override.is_some() || tpm2_tcti()?.is_some());
    let needs_baseline = measure_pcr && !event_log_has_records(root)?;
    let mut logged_events = Vec::with_capacity(events.len() + usize::from(measure_pcr));
    if needs_baseline {
        let pcr15 = read_current_pcr15()
            .context("reading current PCR 15 before first live package measurement")?;
        logged_events.push(pcr_baseline_event(&pcr15));
    }
    logged_events.extend(events.iter().cloned());
    let append = append_event_log(root, &logged_events)?;
    if measure_pcr {
        let pcrextend = match pcrextend_override {
            Some(path) => path.to_path_buf(),
            None => trusted_systemd_pcrextend_path()?,
        };
        if let Err(err) = extend_pcr15(&pcrextend, &events) {
            if let Err(rollback_err) = rollback_event_log_append(&append) {
                bail!(
                    "extending PCR 15 failed and rolling back the package event log also failed: {err:#}; rollback: {rollback_err:#}"
                );
            }
            return Err(err);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasurementEvent {
    event_type: &'static str,
    word: String,
    digest: String,
    extends_pcr: bool,
    pcr_value: Option<String>,
    package: Option<MeasuredPackage>,
    package_count: Option<usize>,
    generation_id: Option<String>,
    activation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasuredPackage {
    name: String,
    version: String,
    root_digest: String,
    manifest_digest: String,
}

#[derive(Serialize)]
struct EventDigestRecord<'a> {
    algorithm: &'static str,
    digest: &'a str,
}

#[derive(Serialize)]
struct EventLogRecord<'a> {
    format: &'static str,
    sequence_number: usize,
    pcr: u8,
    pcr_index: u8,
    bank: &'static str,
    digests: &'a [EventDigestRecord<'a>],
    event_type: &'static str,
    digest: &'a str,
    event_size: usize,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_value: Option<&'a str>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct OwnedEventDigestRecord {
    algorithm: String,
    digest: String,
}

#[derive(Default)]
struct OptionalEventField<T> {
    present: bool,
    value: Option<T>,
}

fn deserialize_optional_event_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<OptionalEventField<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(OptionalEventField {
        present: true,
        value: Some(T::deserialize(deserializer)?),
    })
}

#[derive(Deserialize)]
struct OwnedEventLogRecord {
    format: String,
    #[serde(default, deserialize_with = "deserialize_optional_event_field")]
    sequence_number: OptionalEventField<usize>,
    pcr: u8,
    #[serde(default, deserialize_with = "deserialize_optional_event_field")]
    pcr_index: OptionalEventField<u8>,
    bank: String,
    #[serde(default, deserialize_with = "deserialize_optional_event_field")]
    digests: OptionalEventField<Vec<OwnedEventDigestRecord>>,
    event_type: String,
    digest: String,
    #[serde(default, deserialize_with = "deserialize_optional_event_field")]
    event_size: OptionalEventField<usize>,
    event: String,
    pcr_value: Option<String>,
    package: Option<String>,
    version: Option<String>,
    root_digest: Option<String>,
    manifest_digest: Option<String>,
    package_count: Option<usize>,
    generation_id: Option<String>,
    activation_id: Option<String>,
}

/// Result of replaying and validating the package attestation event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageEventLogVerification {
    /// Replayed PCR 15 value as lowercase SHA-256 hex.
    pub pcr15: String,
    /// Number of package tuple events validated against the registry catalog.
    pub package_count: usize,
    /// Package tuples in the latest completed package-set measurement.
    pub current_packages: Vec<VerifiedPackageMeasurement>,
    /// Canonical record hashes keyed by activation identifier.
    pub generation_attestations: BTreeMap<String, String>,
    /// Ordered PCR-15 event digests preceding each activation record.
    pub generation_attestation_prefix_digests: BTreeMap<String, Vec<String>>,
}

/// One package tuple validated from the latest measured package set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPackageMeasurement {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Canonical root digest that was measured.
    pub root_digest: String,
    /// Canonical permission-manifest digest that was measured.
    pub manifest_digest: String,
    /// Package measurement digest extended into PCR 15.
    pub measurement: String,
}

/// A registry or image-seed golden package measurement catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PackageMeasurementCatalogEntry {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Expected package root digest.
    pub root_digest: String,
    /// Expected package measurement tuple.
    pub measurement: String,
}

/// Files produced by the local TPM quote agent primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PackageQuoteArtifacts {
    /// Verifier-supplied nonce, normalized to lowercase hex.
    pub nonce: String,
    /// PCR bank and selection quoted by the TPM.
    pub pcr_selection: &'static str,
    /// Endorsement-key public area file.
    pub ek_public: String,
    /// Endorsement-key TPM name file.
    pub ek_name: String,
    /// Endorsement-key TPM qualified name file.
    pub ek_qualified_name: String,
    /// Attestation-key public area file.
    pub ak_public: String,
    /// Attestation-key TPM name file.
    pub ak_name: String,
    /// Attestation-key TPM qualified name file.
    pub ak_qualified_name: String,
    /// TPM2B_ATTEST quote message file.
    pub quote_message: String,
    /// TPM signature over the quote message.
    pub quote_signature: String,
    /// Serialized quoted PCR values.
    pub quote_pcrs: String,
    /// Quoted PCR 15 value as lowercase SHA-256 hex.
    pub quoted_pcr15: String,
    /// SHA-256 fingerprints of the AK/EK identity artifacts.
    pub identity: PackageQuoteIdentityDigests,
    /// Non-fatal cleanup warnings from TPM context flushing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flush_warnings: Vec<String>,
}

/// SHA-256 fingerprints of the quote bundle's AK/EK identity artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageQuoteIdentityDigests {
    /// Digest of `ek.pub`.
    pub ek_public_sha256: String,
    /// Digest of `ek.name`.
    pub ek_name_sha256: String,
    /// Digest of `ek.qname`.
    pub ek_qualified_name_sha256: String,
    /// Digest of `ak.pub`.
    pub ak_public_sha256: String,
    /// Digest of `ak.name`.
    pub ak_name_sha256: String,
    /// Digest of `ak.qname`.
    pub ak_qualified_name_sha256: String,
}

/// Result of checking a TPM quote bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageQuoteVerification {
    /// Quoted Secure Boot policy PCR 7.
    pub quoted_pcr7: String,
    /// Quoted measured UKI PCR 11.
    pub quoted_pcr11: String,
    /// Quoted kernel-command-line PCR 12.
    pub quoted_pcr12: String,
    /// Quoted PCR 15 value as lowercase SHA-256 hex.
    pub quoted_pcr15: String,
    /// Whether the matched identity has recorded enrollment evidence.
    pub ak_ek_trusted: bool,
    /// Whether the quote bundle matched an explicit identity pin.
    pub identity_pinned: bool,
    /// Matched identity-pin label, when the catalog provided one.
    pub identity_label: Option<String>,
    /// Exact quote-bundle bytes that were signature-checked from the private snapshot.
    pub bundle: PackageQuoteBundleBinding,
}

/// Exact files from the race-free quote-bundle snapshot used by verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageQuoteBundleBinding {
    /// Hex-encoded TPM AK public area.
    pub ak_public: String,
    /// Hex-encoded TPM2B_ATTEST message.
    pub quote_message: String,
    /// Hex-encoded TPM signature.
    pub quote_signature: String,
    /// Hex-encoded serialized PCR selection and values.
    pub quote_pcrs: String,
}

/// Result of adding a quote identity to a verifier enrollment catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PackageQuoteEnrollmentResult {
    /// Human-readable fleet node or TPM label.
    pub label: String,
    /// Enrollment proof workflow used to authorize the identity.
    pub method: String,
    /// SHA-256 digest of the operator-supplied enrollment evidence.
    pub evidence_sha256: String,
    /// SHA-256 fingerprints of the enrolled AK/EK identity artifacts.
    pub identity: PackageQuoteIdentityDigests,
}

/// An explicit quote-bundle identity pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageQuoteIdentityPin {
    /// Human-readable fleet node or TPM label.
    #[serde(default)]
    label: Option<String>,
    /// Fingerprints captured for an expected quote bundle identity.
    identity: PackageQuoteIdentityDigests,
    /// Evidence that the identity was enrolled through an AK/EK proof workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enrollment: Option<PackageQuoteEnrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageQuoteEnrollment {
    /// Enrollment proof workflow.
    method: String,
    /// SHA-256 digest of the enrollment evidence transcript or certificate.
    evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageQuoteIdentityCatalog {
    /// Trust catalog schema version.
    version: u32,
    /// Pinned quote-bundle identities.
    anchors: Vec<PackageQuoteIdentityPin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageQuoteTrustMatch {
    label: String,
    ak_ek_trusted: bool,
}

#[derive(Debug)]
struct PendingPackageSet {
    remaining: usize,
    expected_digests: Vec<String>,
    next_digest: usize,
}

fn measurement_events(root: &Path, installed: &[InstalledMeta]) -> Result<Vec<MeasurementEvent>> {
    let mut packages = Vec::new();
    for entry in installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if !apm.explicit || apm.expose.is_none() {
            continue;
        }
        packages.push(measured_package(root, entry, apm)?);
    }
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
    if let Some(root_digest) = &apm.attestation.root_digest {
        return canonical_digest(root_digest);
    }

    if let Some(root_hash) = &apm.attestation.root_hash {
        return canonical_digest(root_hash);
    }

    if let Some(expose) = &apm.expose
        && let Some(root_hash) = expose
            .images
            .iter()
            .find(|image| image.root_hash_sig.is_some())
            .and_then(|image| image.root_hash.as_deref())
    {
        return canonical_digest(root_hash);
    }

    package_store_path_root_digest(&entry.store_path)
}

fn package_store_path_root_digest(store_path: &str) -> String {
    format!("sha256:{}", digest_hex(store_path.as_bytes()))
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
#[cfg(test)]
pub(crate) fn verify_package_event_log_against_catalog(
    event_log: &str,
    expected_pcr15: &str,
    catalog: &[PackageMeta],
) -> Result<PackageEventLogVerification> {
    let catalog = package_measurement_catalog_from_package_meta(catalog)?;
    verify_package_event_log_against_measurement_catalog(event_log, expected_pcr15, None, &catalog)
}

/// Replays and verifies the package event log against explicit catalog entries.
///
/// This is used by fleet verification paths that combine registry metadata
/// with image-seeded package metadata before checking a quoted PCR 15 value.
///
/// # Errors
///
/// Returns an error when the log is malformed, PCR replay does not match
/// `expected_pcr15`, or any package tuple is missing from or disagrees with
/// the supplied golden catalog.
pub(crate) fn verify_package_event_log_against_measurement_catalog(
    event_log: &str,
    expected_pcr15: &str,
    expected_baseline_pcr15: Option<&str>,
    catalog: &[PackageMeasurementCatalogEntry],
) -> Result<PackageEventLogVerification> {
    let expected_pcr15 = parse_sha256_hex("expected PCR 15", expected_pcr15)?;
    let expected_baseline_pcr15 = expected_baseline_pcr15
        .map(|pcr15| parse_sha256_hex("expected baseline PCR 15", pcr15))
        .transpose()?;
    let catalog = package_measurement_catalog(catalog)?;
    let mut pcr = [0u8; 32];
    let mut package_count = 0usize;
    let mut pending_package_set: Option<PendingPackageSet> = None;
    let mut pending_current_packages: Vec<VerifiedPackageMeasurement> = Vec::new();
    let mut current_packages: Vec<VerifiedPackageMeasurement> = Vec::new();
    let mut saw_baseline = false;
    let mut saw_package_set = false;
    let mut generation_attestations = BTreeMap::new();
    let mut generation_attestation_prefix_digests = BTreeMap::new();
    let mut extended_event_digests = Vec::new();

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
        match record.event_type.as_str() {
            PCR_BASELINE_EVENT_TYPE => {
                if index != 0 {
                    bail!("PCR baseline event must be the first package event log record");
                }
                if pending_package_set
                    .as_ref()
                    .is_some_and(|pending| pending.remaining != 0)
                {
                    bail!(
                        "package event log line {} resets PCR before the previous set completed",
                        index + 1
                    );
                }
                let Some(expected_baseline_pcr15) = expected_baseline_pcr15.as_deref() else {
                    bail!("PCR baseline event requires an expected baseline PCR 15 value");
                };
                pcr = parse_pcr_baseline_record(index + 1, &record, expected_baseline_pcr15)?;
                saw_baseline = true;
            }
            PACKAGE_SET_EVENT_TYPE => {
                extend_replayed_pcr(&mut pcr, &recorded_digest)?;
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
                let pending = parse_package_set_record(index + 1, &record)?;
                pending_current_packages = Vec::with_capacity(pending.remaining);
                if pending.remaining == 0 {
                    current_packages.clear();
                }
                pending_package_set = Some(pending);
            }
            PACKAGE_EVENT_TYPE => {
                extend_replayed_pcr(&mut pcr, &recorded_digest)?;
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
                let package =
                    verify_package_record(index + 1, &record, &recorded_digest, &catalog)?;
                pending_current_packages.push(package);
                package_count += 1;
                if pending.remaining == 0 {
                    current_packages = std::mem::take(&mut pending_current_packages);
                }
            }
            GENERATION_EVENT_TYPE => {
                let prefix = extended_event_digests.clone();
                extend_replayed_pcr(&mut pcr, &recorded_digest)?;
                let generation_id = record.generation_id.as_deref().with_context(|| {
                    format!(
                        "generation attestation event on line {} is missing generation_id",
                        index + 1
                    )
                })?;
                let activation_id = record.activation_id.as_deref().with_context(|| {
                    format!(
                        "generation attestation event on line {} is missing activation_id",
                        index + 1
                    )
                })?;
                let value: serde_json::Value =
                    serde_json::from_str(&record.event).with_context(|| {
                        format!("parsing generation attestation event on line {}", index + 1)
                    })?;
                if value.get("schema").and_then(serde_json::Value::as_str)
                    != Some("aos.gen-attestation/v1")
                    || value
                        .get("generation_id")
                        .and_then(serde_json::Value::as_str)
                        != Some(generation_id)
                    || value
                        .get("activation_id")
                        .and_then(serde_json::Value::as_str)
                        != Some(activation_id)
                {
                    bail!(
                        "generation attestation event on line {} has inconsistent identity",
                        index + 1
                    );
                }
                // `GenAttestation.quote` skips serialization while empty, so
                // the measured pre-quote record normally omits the field. An
                // explicit empty string is accepted for older CEL producers;
                // any non-empty or non-string value would measure quote bytes
                // into the record they are meant to authenticate.
                if value
                    .get("quote")
                    .is_some_and(|quote| quote.as_str() != Some(""))
                {
                    bail!(
                        "generation attestation event on line {} includes its quote in the measured record",
                        index + 1
                    );
                }
                if generation_attestations
                    .insert(
                        activation_id.to_string(),
                        format!("sha256:{recorded_digest}"),
                    )
                    .is_some()
                {
                    bail!("activation {activation_id} is measured more than once");
                }
                if generation_attestation_prefix_digests
                    .insert(activation_id.to_string(), prefix)
                    .is_some()
                {
                    bail!("activation {activation_id} has ambiguous CEL history");
                }
            }
            _ => bail!(
                "package event log line {} has unsupported event_type '{}'",
                index + 1,
                record.event_type
            ),
        }
        if record.event_type != PCR_BASELINE_EVENT_TYPE {
            extended_event_digests.push(format!("sha256:{recorded_digest}"));
        }
    }

    if !saw_package_set && generation_attestations.is_empty() {
        bail!("package event log contains no package-set event or generation attestation");
    }
    if expected_baseline_pcr15.is_some() && !saw_baseline {
        bail!("expected baseline PCR 15 was supplied but the event log has no PCR baseline event");
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
        current_packages,
        generation_attestations,
        generation_attestation_prefix_digests,
    })
}

/// Decodes a package event log from either AOS JSONL CEL or binary TCG events.
///
/// The binary form is the TCG `TCG_PCR_EVENT2` record layout used by measured
/// boot event logs. AOS stores its length-prefixed event word as the event
/// payload, accepts a single SHA-256 digest entry, and reconstructs the JSONL
/// profile used by the verifier.
///
/// # Errors
///
/// Returns an error when the bytes are neither UTF-8 JSONL CEL nor a
/// well-formed sequence of AOS package `TCG_PCR_EVENT2` records.
pub(crate) fn decode_package_event_log_bytes(bytes: &[u8]) -> Result<String> {
    match bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
    {
        Some(b'{') | None => String::from_utf8(bytes.to_vec())
            .context("decoding package event log as UTF-8 JSONL CEL"),
        Some(_) => decode_tcg_pcr_event2_log(bytes),
    }
}

/// Produces a TPM quote over the AOS package-attestation PCR set.
///
/// The quote covers PCRs 7, 11, 12, and 15 in the SHA-256 bank and writes the
/// EK public/name, AK public/name, quote message, quote signature, and quoted
/// PCR payload into `output_dir`.
///
/// # Errors
///
/// Returns an error if the nonce is not hex, the wrapper did not provide
/// trusted AOS-built tpm2-tools paths, the output directory cannot be written,
/// or any TPM command fails.
pub(crate) fn produce_package_quote(
    nonce_hex: &str,
    output_dir: &Path,
) -> Result<PackageQuoteArtifacts> {
    let nonce = parse_quote_nonce_hex(nonce_hex)?;
    create_private_quote_output_dir(output_dir)?;

    let createek = trusted_tpm2_tool_path(TPM2_CREATEEK_ENV, "tpm2_createek")?;
    let createak = trusted_tpm2_tool_path(TPM2_CREATEAK_ENV, "tpm2_createak")?;
    let readpublic = trusted_tpm2_tool_path(TPM2_READPUBLIC_ENV, "tpm2_readpublic")?;
    let quote = trusted_tpm2_tool_path(TPM2_QUOTE_ENV, "tpm2_quote")?;
    let flushcontext = trusted_tpm2_tool_path(TPM2_FLUSHCONTEXT_ENV, "tpm2_flushcontext")?;
    let tcti = tpm2_tcti()?;

    let work_dir = unique_quote_work_dir(output_dir)?;
    let ek_ctx = work_dir.join("ek.ctx");
    let ak_ctx = work_dir.join("ak.ctx");

    let ek_public = output_dir.join("ek.pub");
    let ek_name = output_dir.join("ek.name");
    let ek_qualified_name = output_dir.join("ek.qname");
    let ak_public = output_dir.join("ak.pub");
    let ak_name = output_dir.join("ak.name");
    let ak_qualified_name = output_dir.join("ak.qname");
    let quote_message = output_dir.join("quote.msg");
    let quote_signature = output_dir.join("quote.sig");
    let quote_pcrs = output_dir.join("quote.pcrs");

    let result = (|| -> Result<()> {
        run_tpm2_tool(
            &createek,
            &[
                os_arg("-c"),
                os_arg(&ek_ctx),
                os_arg("-G"),
                os_arg("rsa"),
                os_arg("-u"),
                os_arg(&ek_public),
            ],
            tcti.as_deref(),
        )
        .context("creating TPM endorsement key")?;
        run_tpm2_tool(
            &readpublic,
            &[
                os_arg("-c"),
                os_arg(&ek_ctx),
                os_arg("-o"),
                os_arg(&ek_public),
                os_arg("-n"),
                os_arg(&ek_name),
                os_arg("-q"),
                os_arg(&ek_qualified_name),
            ],
            tcti.as_deref(),
        )
        .context("recording endorsement-key public identity")?;
        run_tpm2_tool(
            &createak,
            &[
                os_arg("-C"),
                os_arg(&ek_ctx),
                os_arg("-c"),
                os_arg(&ak_ctx),
                os_arg("-G"),
                os_arg("rsa"),
                os_arg("-g"),
                os_arg("sha256"),
                os_arg("-s"),
                os_arg("rsassa"),
                os_arg("-u"),
                os_arg(&ak_public),
                os_arg("-n"),
                os_arg(&ak_name),
                os_arg("-q"),
                os_arg(&ak_qualified_name),
            ],
            tcti.as_deref(),
        )
        .context("creating TPM attestation key below endorsement key")?;
        run_tpm2_tool(
            &quote,
            &[
                os_arg("-c"),
                os_arg(&ak_ctx),
                os_arg("-l"),
                os_arg(QUOTE_PCR_SELECTION),
                os_arg("-q"),
                os_arg(&nonce),
                os_arg("-m"),
                os_arg(&quote_message),
                os_arg("-s"),
                os_arg(&quote_signature),
                os_arg("-o"),
                os_arg(&quote_pcrs),
                os_arg("-F"),
                os_arg("values"),
                os_arg("-g"),
                os_arg("sha256"),
            ],
            tcti.as_deref(),
        )
        .context("producing TPM quote")?;
        Ok(())
    })();

    let flush_warnings = if result.is_ok() {
        flush_quote_contexts(&flushcontext, &ak_ctx, &ek_ctx, tcti.as_deref())
    } else {
        let _ = flush_quote_contexts(&flushcontext, &ak_ctx, &ek_ctx, tcti.as_deref());
        Vec::new()
    };

    match fs::remove_dir_all(&work_dir) {
        Ok(()) => {}
        Err(err) if result.is_err() => {
            let _ = err;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("removing {}", work_dir.display()));
        }
    }

    result?;
    let quoted_pcr15 = quoted_pcr15_from_values_file(&quote_pcrs)?;
    let identity = quote_identity_digests(output_dir)?;

    Ok(PackageQuoteArtifacts {
        nonce,
        pcr_selection: QUOTE_PCR_SELECTION,
        ek_public: display_path(&ek_public),
        ek_name: display_path(&ek_name),
        ek_qualified_name: display_path(&ek_qualified_name),
        ak_public: display_path(&ak_public),
        ak_name: display_path(&ak_name),
        ak_qualified_name: display_path(&ak_qualified_name),
        quote_message: display_path(&quote_message),
        quote_signature: display_path(&quote_signature),
        quote_pcrs: display_path(&quote_pcrs),
        quoted_pcr15,
        identity,
        flush_warnings,
    })
}

/// Verifies a package attestation quote bundle and returns the quoted PCR 15.
///
/// This checks the quote signature, nonce, PCR selection, and event-log replay
/// input binding. When `trust_catalogs` is non-empty, this also requires the
/// bundle identity artifacts to match an explicit verifier-provided pin. This
/// does not replace AK certification or EK credential activation.
///
/// # Errors
///
/// Returns an error if the nonce is malformed, `tpm2_checkquote` is not
/// available through the trusted wrapper environment, quote verification fails,
/// the quote bundle's PCR values file cannot be parsed, or a requested identity
/// pin catalog does not match the quote bundle.
pub(crate) fn verify_attestation_quote_bundle(
    quote_dir: &Path,
    nonce_hex: &str,
    trust_catalogs: &[PathBuf],
) -> Result<PackageQuoteVerification> {
    let nonce = parse_quote_nonce_hex(nonce_hex)?;
    let checkquote = trusted_tpm2_tool_path(TPM2_CHECKQUOTE_ENV, "tpm2_checkquote")?;
    let snapshot_dir = private_quote_bundle_snapshot(quote_dir, !trust_catalogs.is_empty())?;
    let ak_public = snapshot_dir.join("ak.pub");
    let quote_message = snapshot_dir.join("quote.msg");
    let quote_signature = snapshot_dir.join("quote.sig");
    let quote_pcrs = snapshot_dir.join("quote.pcrs");

    let result = run_tpm2_tool(
        &checkquote,
        &[
            os_arg("-u"),
            os_arg(&ak_public),
            os_arg("-m"),
            os_arg(&quote_message),
            os_arg("-s"),
            os_arg(&quote_signature),
            os_arg("-f"),
            os_arg(&quote_pcrs),
            os_arg("-l"),
            os_arg(QUOTE_PCR_SELECTION),
            os_arg("-g"),
            os_arg("sha256"),
            os_arg("-q"),
            os_arg(&nonce),
        ],
        None,
    )
    .with_context(|| {
        format!(
            "verifying package attestation quote {}",
            quote_dir.display()
        )
    })
    .and_then(|()| {
        let quoted = quoted_pcrs_from_values_file(&quote_pcrs)?;
        let trust = verify_quote_bundle_trust(&snapshot_dir, trust_catalogs)?;
        Ok(PackageQuoteVerification {
            quoted_pcr7: quoted.pcr7,
            quoted_pcr11: quoted.pcr11,
            quoted_pcr12: quoted.pcr12,
            quoted_pcr15: quoted.pcr15,
            ak_ek_trusted: trust.as_ref().is_some_and(|anchor| anchor.ak_ek_trusted),
            identity_pinned: trust.is_some(),
            identity_label: trust.map(|anchor| anchor.label),
            bundle: PackageQuoteBundleBinding {
                ak_public: file_hex(&ak_public)?,
                quote_message: file_hex(&quote_message)?,
                quote_signature: file_hex(&quote_signature)?,
                quote_pcrs: file_hex(&quote_pcrs)?,
            },
        })
    });

    match fs::remove_dir_all(&snapshot_dir) {
        Ok(()) => {}
        Err(err) if result.is_err() => {
            let _ = err;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("removing {}", snapshot_dir.display()));
        }
    }

    result
}

fn read_current_pcr15() -> Result<String> {
    let pcrread = trusted_tpm2_tool_path(TPM2_PCRREAD_ENV, "tpm2_pcrread")?;
    let tcti = tpm2_tcti()?;
    let mut command = Command::new(&pcrread);
    command.arg(format!("{PCR_BANK}:{PCR_INDEX}"));
    if let Some(tcti) = tcti {
        command.env("TPM2TOOLS_TCTI", tcti);
    }
    let output = command
        .output()
        .with_context(|| format!("running {}", pcrread.display()))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}\nstdout:\n{}\nstderr:\n{}",
            pcrread.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_tpm2_pcrread_pcr15(&String::from_utf8_lossy(&output.stdout))
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
        if record.event_type == PCR_BASELINE_EVENT_TYPE {
            let expected = record
                .pcr_value
                .as_deref()
                .context("test PCR baseline record missing pcr_value")?;
            let expected = parse_prefixed_sha256_hex("test PCR baseline value", expected)?;
            pcr = parse_pcr_baseline_record(index + 1, &record, &expected)?;
        } else {
            extend_replayed_pcr(&mut pcr, &recorded_digest)?;
        }
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
        extends_pcr: true,
        pcr_value: None,
        package: Some(package),
        package_count: None,
        generation_id: None,
        activation_id: None,
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
        extends_pcr: true,
        pcr_value: None,
        package: None,
        package_count: Some(package_events.len()),
        generation_id: None,
        activation_id: None,
    }
}

fn pcr_baseline_event(pcr15: &str) -> MeasurementEvent {
    let pcr15 = canonical_digest(pcr15);
    let word = length_prefixed_word("aos-pcr-baseline-v1", &[("pcr-value", pcr15.clone())]);
    let digest = format!("sha256:{}", digest_for_word(&word));
    MeasurementEvent {
        event_type: PCR_BASELINE_EVENT_TYPE,
        word,
        digest,
        extends_pcr: false,
        pcr_value: Some(pcr15),
        package: None,
        package_count: None,
        generation_id: None,
        activation_id: None,
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

pub(crate) fn package_measurement_catalog_from_package_meta(
    catalog: &[PackageMeta],
) -> Result<Vec<PackageMeasurementCatalogEntry>> {
    Ok(catalog
        .iter()
        .filter_map(|meta| {
            let measurement = meta.attestation.measurement.as_ref()?;
            let root_digest = meta
                .attestation
                .root_digest
                .as_ref()
                .or(meta.attestation.root_hash.as_ref())?;
            Some(PackageMeasurementCatalogEntry {
                name: meta.name.clone(),
                version: meta.version.clone(),
                root_digest: root_digest.clone(),
                measurement: measurement.clone(),
            })
        })
        .collect::<Vec<_>>())
}

/// Returns a sorted, deduplicated, and digest-normalized golden measurement catalog.
///
/// # Errors
///
/// Returns an error if any digest is malformed or two entries for the same
/// package/version disagree on the expected measurement.
pub(crate) fn canonical_package_measurement_catalog(
    catalog: &[PackageMeasurementCatalogEntry],
) -> Result<Vec<PackageMeasurementCatalogEntry>> {
    let measurements = package_measurement_catalog(catalog)?;
    Ok(measurements
        .into_iter()
        .map(
            |((name, version), (measurement, root_digest))| PackageMeasurementCatalogEntry {
                name,
                version,
                root_digest,
                measurement: format!("sha256:{measurement}"),
            },
        )
        .collect())
}

fn package_measurement_catalog(
    catalog: &[PackageMeasurementCatalogEntry],
) -> Result<BTreeMap<(String, String), (String, String)>> {
    let mut measurements = BTreeMap::new();
    for entry in catalog {
        let measurement = parse_sha256_hex("registry package measurement", &entry.measurement)?;
        let root_digest = format!(
            "sha256:{}",
            parse_sha256_hex("registry package root digest", &entry.root_digest)?
        );
        let key = (entry.name.clone(), entry.version.clone());
        let value = (measurement, root_digest);
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

fn parse_tpm2_pcrread_pcr15(output: &str) -> Result<String> {
    for line in output.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix(&format!("{PCR_INDEX}:")) else {
            continue;
        };
        let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        return Ok(format!(
            "sha256:{}",
            parse_sha256_hex("PCR 15 value", value)?
        ));
    }
    bail!("tpm2_pcrread output did not contain PCR 15");
}

fn quoted_pcr15_from_values_file(path: &Path) -> Result<String> {
    Ok(quoted_pcrs_from_values_file(path)?.pcr15)
}

struct PackageQuotedPcrs {
    pcr7: String,
    pcr11: String,
    pcr12: String,
    pcr15: String,
}

fn quoted_pcrs_from_values_file(path: &Path) -> Result<PackageQuotedPcrs> {
    const SHA256_SIZE: usize = 32;
    const QUOTED_PCR_COUNT: usize = 4;

    let bytes =
        fs::read(path).with_context(|| format!("reading quoted PCR values {}", path.display()))?;
    let expected = SHA256_SIZE * QUOTED_PCR_COUNT;
    if bytes.len() != expected {
        bail!(
            "quoted PCR values file {} is {} bytes, expected {expected}",
            path.display(),
            bytes.len()
        );
    }
    let value = |index: usize| {
        let start = SHA256_SIZE * index;
        hex::encode(&bytes[start..start + SHA256_SIZE])
    };
    Ok(PackageQuotedPcrs {
        pcr7: value(0),
        pcr11: value(1),
        pcr12: value(2),
        pcr15: value(3),
    })
}

fn verify_quote_bundle_trust(
    quote_dir: &Path,
    trust_catalogs: &[PathBuf],
) -> Result<Option<PackageQuoteTrustMatch>> {
    if trust_catalogs.is_empty() {
        return Ok(None);
    }

    let identity = quote_identity_digests(quote_dir)?;
    let mut anchors = Vec::new();
    for catalog_path in trust_catalogs {
        let catalog = read_quote_identity_catalog(catalog_path)?;
        for anchor in catalog.anchors {
            validate_quote_identity_pin(&anchor).with_context(|| {
                format!(
                    "validating package quote identity pin from {}",
                    catalog_path.display()
                )
            })?;
            anchors.push(anchor);
        }
    }

    let mut pinned_match = None;
    for anchor in anchors {
        if anchor.identity == identity {
            let label = anchor
                .label
                .unwrap_or_else(|| format!("ak:{}", identity.ak_public_sha256));
            if anchor.enrollment.is_some() {
                return Ok(Some(PackageQuoteTrustMatch {
                    label,
                    ak_ek_trusted: true,
                }));
            }
            pinned_match.get_or_insert(label);
        }
    }

    if let Some(label) = pinned_match {
        return Ok(Some(PackageQuoteTrustMatch {
            label,
            ak_ek_trusted: false,
        }));
    }

    bail!("package attestation quote identity did not match any pinned identity");
}

/// Enrolls a quote bundle identity in a verifier trust catalog.
///
/// The supplied evidence file is an operator- or privacy-CA-produced proof that
/// the AK/EK identity is acceptable for the fleet. AOS records its digest in
/// the catalog so later quote verification can distinguish enrolled identities
/// from simple identity pins.
///
/// # Errors
///
/// Returns an error if the quote identity files cannot be read, the enrollment
/// method is unsupported, the evidence file is not a regular file, the catalog
/// is malformed, or the label or identity is already enrolled.
pub(crate) fn enroll_quote_identity(
    quote_dir: &Path,
    catalog_path: &Path,
    label: &str,
    method: &str,
    evidence_file: &Path,
) -> Result<PackageQuoteEnrollmentResult> {
    let identity = quote_identity_digests(quote_dir)?;
    let method = validate_quote_enrollment_method(method)?.to_string();
    let anchor = PackageQuoteIdentityPin {
        label: Some(label.to_string()),
        identity: identity.clone(),
        enrollment: Some(PackageQuoteEnrollment {
            method: method.clone(),
            evidence_sha256: enrollment_evidence_digest(evidence_file)?,
        }),
    };
    validate_quote_identity_pin(&anchor)?;

    let mut catalog = read_or_create_quote_identity_catalog(catalog_path)?;
    for existing in &catalog.anchors {
        validate_quote_identity_pin(existing).with_context(|| {
            format!(
                "validating existing package quote identity pin from {}",
                catalog_path.display()
            )
        })?;
    }
    if catalog
        .anchors
        .iter()
        .any(|existing| existing.label.as_deref() == Some(label))
    {
        bail!("package quote identity catalog already contains label '{label}'");
    }
    if catalog
        .anchors
        .iter()
        .any(|existing| existing.identity == identity)
    {
        bail!("package quote identity catalog already contains this AK/EK identity");
    }

    let enrollment = anchor
        .enrollment
        .as_ref()
        .context("enrollment missing after construction")?;
    let result = PackageQuoteEnrollmentResult {
        label: label.to_string(),
        method,
        evidence_sha256: enrollment.evidence_sha256.clone(),
        identity,
    };
    catalog.anchors.push(anchor);
    write_quote_identity_catalog(catalog_path, &catalog)?;
    Ok(result)
}

fn read_or_create_quote_identity_catalog(path: &Path) -> Result<PackageQuoteIdentityCatalog> {
    match fs::read_to_string(path) {
        Ok(content) => parse_quote_identity_catalog(path, &content),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(PackageQuoteIdentityCatalog {
            version: 1,
            anchors: Vec::new(),
        }),
        Err(err) => Err(err)
            .with_context(|| format!("reading package quote identity catalog {}", path.display())),
    }
}

fn read_quote_identity_catalog(path: &Path) -> Result<PackageQuoteIdentityCatalog> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading package quote identity catalog {}", path.display()))?;
    let catalog = parse_quote_identity_catalog(path, &content)?;
    if catalog.anchors.is_empty() {
        bail!(
            "package quote identity catalog {} does not contain any anchors",
            path.display()
        );
    }
    Ok(catalog)
}

fn parse_quote_identity_catalog(path: &Path, content: &str) -> Result<PackageQuoteIdentityCatalog> {
    let catalog: PackageQuoteIdentityCatalog = serde_json::from_str(content)
        .with_context(|| format!("parsing package quote identity catalog {}", path.display()))?;
    if catalog.version != 1 {
        bail!(
            "package quote identity catalog {} has unsupported version {}",
            path.display(),
            catalog.version
        );
    }
    Ok(catalog)
}

fn write_quote_identity_catalog(path: &Path, catalog: &PackageQuoteIdentityCatalog) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(catalog)
        .context("serializing package quote identity catalog")?;
    fs::write(path, format!("{content}\n"))
        .with_context(|| format!("writing package quote identity catalog {}", path.display()))
}

fn validate_quote_identity_pin(anchor: &PackageQuoteIdentityPin) -> Result<()> {
    if let Some(label) = &anchor.label
        && (label.is_empty() || label.chars().any(char::is_control))
    {
        bail!("package quote identity pin label must be non-empty printable text");
    }
    if let Some(enrollment) = &anchor.enrollment {
        validate_quote_enrollment_method(&enrollment.method)?;
        parse_prefixed_sha256_hex(
            "quote enrollment evidence_sha256",
            &enrollment.evidence_sha256,
        )?;
    }
    validate_quote_identity_digests(&anchor.identity)
}

fn validate_quote_enrollment_method(method: &str) -> Result<&'static str> {
    match method {
        "credential-activation" => Ok("credential-activation"),
        "privacy-ca" => Ok("privacy-ca"),
        "out-of-band" => Ok("out-of-band"),
        _ => bail!(
            "package quote enrollment method must be credential-activation, privacy-ca, or out-of-band"
        ),
    }
}

fn enrollment_evidence_digest(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("reading enrollment evidence metadata {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!(
            "enrollment evidence {} must be a regular file",
            path.display()
        );
    }
    file_sha256_digest(path)
}

fn quote_identity_digests(dir: &Path) -> Result<PackageQuoteIdentityDigests> {
    Ok(PackageQuoteIdentityDigests {
        ek_public_sha256: file_sha256_digest(&dir.join("ek.pub"))?,
        ek_name_sha256: file_sha256_digest(&dir.join("ek.name"))?,
        ek_qualified_name_sha256: file_sha256_digest(&dir.join("ek.qname"))?,
        ak_public_sha256: file_sha256_digest(&dir.join("ak.pub"))?,
        ak_name_sha256: file_sha256_digest(&dir.join("ak.name"))?,
        ak_qualified_name_sha256: file_sha256_digest(&dir.join("ak.qname"))?,
    })
}

fn file_sha256_digest(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(format!("sha256:{}", digest_hex(&bytes)))
}

fn file_hex(path: &Path) -> Result<String> {
    fs::read(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(hex::encode)
}

fn validate_quote_identity_digests(identity: &PackageQuoteIdentityDigests) -> Result<()> {
    for (kind, digest) in [
        ("ek_public_sha256", &identity.ek_public_sha256),
        ("ek_name_sha256", &identity.ek_name_sha256),
        (
            "ek_qualified_name_sha256",
            &identity.ek_qualified_name_sha256,
        ),
        ("ak_public_sha256", &identity.ak_public_sha256),
        ("ak_name_sha256", &identity.ak_name_sha256),
        (
            "ak_qualified_name_sha256",
            &identity.ak_qualified_name_sha256,
        ),
    ] {
        parse_prefixed_sha256_hex(kind, digest)?;
    }
    Ok(())
}

fn validate_event_record_shape(line: usize, record: &OwnedEventLogRecord) -> Result<()> {
    if record.format != EVENT_LOG_FORMAT {
        bail!(
            "package event log line {line} has unsupported format '{}'",
            record.format
        );
    }
    if let Some(sequence_number) = record.sequence_number.value
        && sequence_number != line
    {
        bail!(
            "package event log line {line} has sequence_number {sequence_number}, expected {line}"
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
    validate_pcr_event_fields(line, record)?;
    Ok(())
}

fn validate_pcr_event_fields(line: usize, record: &OwnedEventLogRecord) -> Result<()> {
    let has_pcr_event_fields =
        record.pcr_index.present || record.digests.present || record.event_size.present;
    if !has_pcr_event_fields {
        return Ok(());
    }
    let pcr_index = record
        .pcr_index
        .value
        .with_context(|| format!("package event log line {line} is missing pcr_index"))?;
    if pcr_index != PCR_INDEX {
        bail!("package event log line {line} has pcr_index {pcr_index}, expected {PCR_INDEX}");
    }
    let event_size = record
        .event_size
        .value
        .with_context(|| format!("package event log line {line} is missing event_size"))?;
    let actual_event_size = record.event.len();
    if event_size != actual_event_size {
        bail!(
            "package event log line {line} has event_size {event_size}, expected {actual_event_size}"
        );
    }
    let digests = record
        .digests
        .value
        .as_ref()
        .with_context(|| format!("package event log line {line} is missing digests"))?;
    if digests.len() != 1 {
        bail!(
            "package event log line {line} has {} digest entries, expected 1",
            digests.len()
        );
    }
    let digest = &digests[0];
    if digest.algorithm != PCR_BANK {
        bail!(
            "package event log line {line} uses digest algorithm '{}', expected {PCR_BANK}",
            digest.algorithm
        );
    }
    let canonical_digest = parse_prefixed_sha256_hex("event digest", &record.digest)?;
    let listed_digest = parse_prefixed_sha256_hex("event digest list entry", &digest.digest)?;
    if listed_digest != canonical_digest {
        bail!("package event log line {line} digest list does not match digest");
    }
    Ok(())
}

fn decode_tcg_pcr_event2_log(bytes: &[u8]) -> Result<String> {
    let mut reader = TcgEventReader::new(bytes);
    let mut lines = Vec::new();
    let mut sequence_number = 1usize;
    while !reader.is_empty() {
        let record_start = reader.position();
        let pcr_index = reader.read_u32("PCRIndex")?;
        let event_type = reader.read_u32("EventType")?;
        let digest_count = reader.read_u32("Digest count")?;
        if digest_count != 1 {
            bail!(
                "TCG package event record {sequence_number} has {digest_count} digest entries, expected 1"
            );
        }
        let algorithm = reader.read_u16("Digest algorithm")?;
        if algorithm != TCG_ALG_SHA256 {
            bail!(
                "TCG package event record {sequence_number} uses digest algorithm 0x{algorithm:04x}, expected SHA-256"
            );
        }
        let digest = reader.read_bytes("Digest", SHA256_DIGEST_SIZE)?;
        let event_size = reader.read_u32("EventSize")?;
        let event_size = usize::try_from(event_size)
            .context("TCG package event size does not fit this platform")?;
        let event = reader.read_bytes("Event", event_size)?;
        let word = std::str::from_utf8(event).with_context(|| {
            format!("TCG package event record {sequence_number} payload is not UTF-8")
        })?;
        let pcr_index = u8::try_from(pcr_index).with_context(|| {
            format!("TCG package event record {sequence_number} PCRIndex does not fit in u8")
        })?;
        let digest = format!("sha256:{}", hex::encode(digest));
        let line = event_log_line_from_tcg_event(
            sequence_number,
            pcr_index,
            event_type,
            &digest,
            word,
        )
        .with_context(|| {
            format!(
                "decoding TCG package event record {sequence_number} at byte offset {record_start}"
            )
        })?;
        lines.push(line);
        sequence_number += 1;
    }

    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(lines.join("\n") + "\n")
    }
}

struct TcgEventReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> TcgEventReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn position(&self) -> usize {
        self.position
    }

    fn read_u16(&mut self, field: &str) -> Result<u16> {
        let bytes = self.read_bytes(field, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self, field: &str) -> Result<u32> {
        let bytes = self.read_bytes(field, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, field: &str, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .with_context(|| format!("TCG package event {field} length overflows"))?;
        let bytes = self.bytes.get(self.position..end).with_context(|| {
            format!(
                "TCG package event ended while reading {field}: need {len} bytes at offset {}",
                self.position
            )
        })?;
        self.position = end;
        Ok(bytes)
    }
}

fn event_log_line_from_tcg_event(
    sequence_number: usize,
    pcr_index: u8,
    tcg_event_type: u32,
    digest: &str,
    word: &str,
) -> Result<String> {
    let event_type = event_type_from_word(word)?;
    let mut pcr_value = None;
    let mut package = None;
    let mut version = None;
    let mut root_digest = None;
    let mut manifest_digest = None;
    let mut package_count = None;

    match event_type {
        PCR_BASELINE_EVENT_TYPE => {
            if tcg_event_type != TCG_EV_NO_ACTION {
                bail!(
                    "AOS PCR baseline TCG event uses EventType 0x{tcg_event_type:08x}, expected EV_NO_ACTION"
                );
            }
            let fields = parse_length_prefixed_word("aos-pcr-baseline-v1", word)?;
            pcr_value = Some(required_event_word_field(&fields, "pcr-value")?);
        }
        PACKAGE_SET_EVENT_TYPE => {
            if tcg_event_type == TCG_EV_NO_ACTION {
                bail!("AOS package-set TCG event must not use EV_NO_ACTION");
            }
            let fields = parse_length_prefixed_word("aos-package-set-v1", word)?;
            let count = required_event_word_field(&fields, "package-count")?;
            package_count = Some(
                count
                    .parse::<usize>()
                    .context("AOS package-set TCG event has invalid package-count")?,
            );
        }
        PACKAGE_EVENT_TYPE => {
            if tcg_event_type == TCG_EV_NO_ACTION {
                bail!("AOS package TCG event must not use EV_NO_ACTION");
            }
            let fields = parse_length_prefixed_word("aos-package-v1", word)?;
            package = Some(required_event_word_field(&fields, "name")?);
            version = Some(required_event_word_field(&fields, "version")?);
            root_digest = Some(required_event_word_field(&fields, "root-digest")?);
            manifest_digest = Some(required_event_word_field(&fields, "manifest-digest")?);
        }
        _ => unreachable!("event_type_from_word returned unsupported event type"),
    }

    let digests = [EventDigestRecord {
        algorithm: PCR_BANK,
        digest,
    }];
    let record = EventLogRecord {
        format: EVENT_LOG_FORMAT,
        sequence_number,
        pcr: pcr_index,
        pcr_index,
        bank: PCR_BANK,
        digests: &digests,
        event_type,
        digest,
        event_size: word.len(),
        event: word,
        pcr_value: pcr_value.as_deref(),
        package: package.as_deref(),
        version: version.as_deref(),
        root_digest: root_digest.as_deref(),
        manifest_digest: manifest_digest.as_deref(),
        package_count,
        generation_id: None,
        activation_id: None,
    };
    serde_json::to_string(&record).context("serializing decoded TCG package event")
}

fn event_type_from_word(word: &str) -> Result<&'static str> {
    if word_has_schema(word, "aos-pcr-baseline-v1") {
        Ok(PCR_BASELINE_EVENT_TYPE)
    } else if word_has_schema(word, "aos-package-set-v1") {
        Ok(PACKAGE_SET_EVENT_TYPE)
    } else if word_has_schema(word, "aos-package-v1") {
        Ok(PACKAGE_EVENT_TYPE)
    } else {
        bail!("TCG package event payload does not use a supported AOS package schema");
    }
}

fn word_has_schema(word: &str, schema: &str) -> bool {
    word == schema || word.as_bytes().get(schema.len()) == Some(&b'|')
}

fn required_event_word_field(fields: &BTreeMap<String, String>, field: &str) -> Result<String> {
    fields
        .get(field)
        .cloned()
        .with_context(|| format!("AOS package TCG event is missing {field}"))
}

fn parse_pcr_baseline_record(
    line: usize,
    record: &OwnedEventLogRecord,
    expected_baseline_pcr15: &str,
) -> Result<[u8; 32]> {
    let fields = parse_length_prefixed_word("aos-pcr-baseline-v1", &record.event)
        .with_context(|| format!("parsing PCR baseline event word on line {line}"))?;
    let pcr_value = fields
        .get("pcr-value")
        .with_context(|| format!("PCR baseline event on line {line} is missing pcr-value"))?;
    let json_value = record
        .pcr_value
        .as_deref()
        .with_context(|| format!("PCR baseline event on line {line} is missing pcr_value"))?;
    if json_value != pcr_value {
        bail!("PCR baseline event on line {line} pcr_value does not match the measured word");
    }
    let pcr_value = parse_prefixed_sha256_hex("PCR baseline value", pcr_value)?;
    if pcr_value != expected_baseline_pcr15 {
        bail!("PCR baseline event on line {line} does not match the expected baseline PCR 15");
    }
    let bytes = hex::decode(&pcr_value)
        .with_context(|| format!("decoding PCR baseline value on line {line}"))?;
    let pcr: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("PCR baseline decoded to {} bytes", bytes.len())
    })?;
    Ok(pcr)
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
) -> Result<VerifiedPackageMeasurement> {
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
    let (catalog_measurement, catalog_root_digest) = catalog.get(&key).with_context(|| {
        format!("registry catalog has no golden measurement for {package} {version}")
    })?;
    if catalog_measurement != recorded_digest {
        bail!("package event on line {line} does not match the registry golden measurement");
    }
    if catalog_root_digest != &canonical_digest(root_digest) {
        bail!("package event on line {line} root digest does not match the registry catalog");
    }
    Ok(VerifiedPackageMeasurement {
        name: package.to_string(),
        version: version.to_string(),
        root_digest: canonical_digest(root_digest),
        manifest_digest: canonical_digest(manifest_digest),
        measurement: recorded_digest.to_string(),
    })
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
        if !event.extends_pcr {
            continue;
        }
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

fn run_tpm2_tool(tool: &Path, args: &[OsString], tcti: Option<&str>) -> Result<()> {
    let mut command = Command::new(tool);
    command.args(args);
    if let Some(tcti) = tcti {
        command.env("TPM2TOOLS_TCTI", tcti);
    }
    let output = command
        .output()
        .with_context(|| format!("running {}", tool.display()))?;
    if output.status.success() {
        return Ok(());
    }

    let args = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{} {} failed: {}\nstdout:\n{}\nstderr:\n{}",
        tool.display(),
        args,
        output.status,
        stdout.trim_end(),
        stderr.trim_end()
    );
}

fn flush_quote_contexts(
    flushcontext: &Path,
    ak_ctx: &Path,
    ek_ctx: &Path,
    tcti: Option<&str>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (label, context) in [("attestation-key", ak_ctx), ("endorsement-key", ek_ctx)] {
        if !context.exists() {
            continue;
        }
        if let Err(err) = run_tpm2_tool(flushcontext, &[os_arg(context)], tcti) {
            warnings.push(format!("flushing {label} TPM context: {err:#}"));
        }
    }
    warnings
}

fn event_log_has_records(root: &Path) -> Result<bool> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    match fs::read_to_string(&path) {
        Ok(log) => Ok(log.lines().any(|line| !line.trim().is_empty())),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

#[derive(Debug, Clone)]
struct EventLogAppend {
    path: PathBuf,
    previous_len: u64,
    created_file: bool,
}

fn append_event_log(root: &Path, events: &[MeasurementEvent]) -> Result<EventLogAppend> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    let (existing_lines, needs_separator, previous_len, created_file) =
        match fs::read_to_string(&path) {
            Ok(log) => {
                let previous_len = fs::metadata(&path)
                    .with_context(|| format!("reading metadata for {}", path.display()))?
                    .len();
                (
                    log.lines().count(),
                    !log.is_empty() && !log.ends_with('\n'),
                    previous_len,
                    false,
                )
            }
            Err(err) if err.kind() == ErrorKind::NotFound => (0, false, 0, true),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
    let parent = path
        .parent()
        .with_context(|| format!("event log path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    if needs_separator {
        writeln!(file).with_context(|| format!("writing {}", path.display()))?;
    }
    for (index, event) in events.iter().enumerate() {
        let line = event_log_line(existing_lines + index + 1, event)?;
        writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
    }
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    if created_file {
        File::open(parent)
            .with_context(|| format!("opening {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("syncing {}", parent.display()))?;
    }
    Ok(EventLogAppend {
        path,
        previous_len,
        created_file,
    })
}

fn rollback_event_log_append(append: &EventLogAppend) -> Result<()> {
    if append.created_file && append.previous_len == 0 {
        match fs::remove_file(&append.path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| format!("removing {}", append.path.display()));
            }
        }
    }
    let file = OpenOptions::new()
        .write(true)
        .open(&append.path)
        .with_context(|| format!("opening {}", append.path.display()))?;
    file.set_len(append.previous_len)
        .with_context(|| format!("truncating {}", append.path.display()))
}

fn event_log_line(sequence_number: usize, event: &MeasurementEvent) -> Result<String> {
    let package = event.package.as_ref();
    let digests = [EventDigestRecord {
        algorithm: PCR_BANK,
        digest: &event.digest,
    }];
    let record = EventLogRecord {
        format: EVENT_LOG_FORMAT,
        sequence_number,
        pcr: PCR_INDEX,
        pcr_index: PCR_INDEX,
        bank: PCR_BANK,
        digests: &digests,
        event_type: event.event_type,
        digest: &event.digest,
        event_size: event.word.len(),
        event: &event.word,
        pcr_value: event.pcr_value.as_deref(),
        package: package.map(|package| package.name.as_str()),
        version: package.map(|package| package.version.as_str()),
        root_digest: package.map(|package| package.root_digest.as_str()),
        manifest_digest: package.map(|package| package.manifest_digest.as_str()),
        package_count: event.package_count,
        generation_id: event.generation_id.as_deref(),
        activation_id: event.activation_id.as_deref(),
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

fn trusted_tpm2_tool_path(env_name: &str, bin_name: &str) -> Result<PathBuf> {
    let path = std::env::var(env_name).with_context(|| {
        format!("{env_name} is not configured for package attestation quote production")
    })?;
    validate_trusted_tpm2_tool_path(env_name, bin_name, &path)
}

fn tpm2_tcti() -> Result<Option<String>> {
    match std::env::var(TPM2_TCTI_ENV) {
        Ok(value) if value.is_empty() => bail!("{TPM2_TCTI_ENV} must not be empty"),
        Ok(value) => return Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => {}
        Err(err) => return Err(err).context("reading TPM2 TCTI override"),
    }

    for device in ["/dev/tpmrm0", "/dev/tpm0"] {
        if Path::new(device).exists() {
            return Ok(Some(format!("device:{device}")));
        }
    }

    Ok(None)
}

fn create_private_quote_output_dir(output_dir: &Path) -> Result<()> {
    if !output_dir.is_absolute() {
        bail!(
            "quote output directory must be an absolute path: {}",
            output_dir.display()
        );
    }
    match fs::symlink_metadata(output_dir) {
        Ok(_) => {
            bail!(
                "quote output directory must not already exist: {}",
                output_dir.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!("checking quote output directory {}", output_dir.display())
            });
        }
    }

    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .with_context(|| {
            format!(
                "quote output directory has no parent: {}",
                output_dir.display()
            )
        })?;
    let parent_meta = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "checking quote output directory parent {}",
            parent.display()
        )
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        bail!(
            "quote output directory parent must be a real directory: {}",
            parent.display()
        );
    }

    DirBuilder::new()
        .mode(0o700)
        .create(output_dir)
        .with_context(|| {
            format!(
                "creating private quote output directory {}",
                output_dir.display()
            )
        })?;
    fs::set_permissions(output_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing quote output directory {}", output_dir.display()))?;
    let metadata = fs::symlink_metadata(output_dir).with_context(|| {
        format!(
            "checking private quote output directory {}",
            output_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "quote output directory must be a real directory: {}",
            output_dir.display()
        );
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        bail!(
            "quote output directory must have mode 0700: {}",
            output_dir.display()
        );
    }
    Ok(())
}

fn validate_trusted_tpm2_tool_path(env_name: &str, bin_name: &str, path: &str) -> Result<PathBuf> {
    if path.is_empty() {
        bail!("{env_name} must not be empty");
    }
    let expected_suffix = format!("/bin/{bin_name}");
    if !path.starts_with('/') || !path.ends_with(&expected_suffix) {
        bail!("{env_name} must point to an absolute {bin_name} binary");
    }
    Ok(PathBuf::from(path))
}

fn parse_quote_nonce_hex(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("quote nonce must not be empty");
    }
    if value.len() % 2 != 0 {
        bail!("quote nonce must be an even-length hex string");
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("quote nonce must contain only hex characters");
    }
    Ok(value.to_ascii_lowercase())
}

fn private_quote_bundle_snapshot(quote_dir: &Path, include_identity: bool) -> Result<PathBuf> {
    let snapshot_dir = unique_temp_dir("aos-attest-verify")?;
    let mut members = vec!["ak.pub", "quote.msg", "quote.sig", "quote.pcrs"];
    if include_identity {
        members.extend(["ek.pub", "ek.name", "ek.qname", "ak.name", "ak.qname"]);
    }
    for name in members {
        let source = quote_dir.join(name);
        let target = snapshot_dir.join(name);
        fs::copy(&source, &target)
            .with_context(|| format!("copying quote bundle member {}", source.display()))?;
    }
    Ok(snapshot_dir)
}

fn unique_quote_work_dir(parent: &Path) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    unique_dir_under(
        parent,
        &format!(".aos-attest-quote-{}", std::process::id()),
        nanos,
    )
}

fn unique_temp_dir(prefix: &str) -> Result<PathBuf> {
    let root = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    unique_dir_under(&root, &format!("{prefix}-{}", std::process::id()), nanos)
}

fn unique_dir_under(parent: &Path, prefix: &str, nanos: u128) -> Result<PathBuf> {
    for attempt in 0..32u8 {
        let path = parent.join(format!("{prefix}-{nanos}-{attempt}"));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).with_context(|| format!("creating {}", path.display())),
        }
    }
    bail!(
        "could not allocate a unique directory under {}",
        parent.display()
    );
}

fn os_arg<T: AsRef<OsStr>>(value: T) -> OsString {
    value.as_ref().to_os_string()
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
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
                        ukis: Vec::new(),
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
                config_module: None,
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

    fn write_quote_identity_fixture(dir: &Path, seed: &str) {
        for name in [
            "ek.pub", "ek.name", "ek.qname", "ak.pub", "ak.name", "ak.qname",
        ] {
            fs::write(dir.join(name), format!("{seed}:{name}")).expect("identity member");
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
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: AttestationMeta {
                root_digest: Some(root_hash.into()),
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

    fn legacy_event_log_without_pcr_event_fields(log: &str) -> String {
        let lines = log
            .lines()
            .map(|line| {
                let mut record: serde_json::Value = serde_json::from_str(line).expect("record");
                let object = record.as_object_mut().expect("record object");
                object.remove("sequence_number");
                object.remove("pcr_index");
                object.remove("digests");
                object.remove("event_size");
                serde_json::to_string(&record).expect("legacy record")
            })
            .collect::<Vec<_>>();
        lines.join("\n") + "\n"
    }

    fn refresh_json_record_pcr_event_fields(record: &mut serde_json::Value) {
        let digest = record["digest"].as_str().expect("digest").to_string();
        let event_size = record["event"].as_str().expect("event").len();
        if record.get("event_size").is_some() {
            record["event_size"] = serde_json::Value::from(event_size);
        }
        if let Some(digests) = record
            .get_mut("digests")
            .and_then(|value| value.as_array_mut())
        {
            assert_eq!(digests.len(), 1);
            digests[0]["algorithm"] = serde_json::Value::String(PCR_BANK.into());
            digests[0]["digest"] = serde_json::Value::String(digest);
        }
    }

    fn tcg_pcr_event2_log_from_jsonl(log: &str) -> Vec<u8> {
        let mut binary = Vec::new();
        for (index, line) in log.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let record: OwnedEventLogRecord = serde_json::from_str(line).expect("record");
            validate_event_record_shape(index + 1, &record).expect("record shape");
            let event_type = match record.event_type.as_str() {
                PCR_BASELINE_EVENT_TYPE => TCG_EV_NO_ACTION,
                PACKAGE_SET_EVENT_TYPE | PACKAGE_EVENT_TYPE => TCG_EV_EVENT_TAG,
                other => panic!("unsupported event type {other}"),
            };
            let pcr_index = record.pcr_index.value.expect("pcr_index");
            let digest =
                parse_prefixed_sha256_hex("event digest", &record.digest).expect("event digest");
            let digest = hex::decode(digest).expect("event digest bytes");
            binary.extend_from_slice(&u32::from(pcr_index).to_le_bytes());
            binary.extend_from_slice(&event_type.to_le_bytes());
            binary.extend_from_slice(&1u32.to_le_bytes());
            binary.extend_from_slice(&TCG_ALG_SHA256.to_le_bytes());
            binary.extend_from_slice(&digest);
            binary.extend_from_slice(&(record.event.len() as u32).to_le_bytes());
            binary.extend_from_slice(record.event.as_bytes());
        }
        binary
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
    fn package_measurement_uses_store_path_digest_without_signed_root() {
        let tmp = TempDir::new().expect("tempdir");
        let mut installed = installed_fixture(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let expected_root_digest = package_store_path_root_digest(&installed.store_path);
        let apm = installed.apm.as_mut().expect("apm metadata");
        let image = apm
            .expose
            .as_mut()
            .expect("expose metadata")
            .images
            .first_mut()
            .expect("image metadata");
        image.root_hash = None;
        image.root_hash_sig = None;

        let events = measurement_events(tmp.path(), &[installed]).expect("events");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
        assert_eq!(events[0].package_count, Some(1));
        let package = events[1].package.as_ref().expect("package event");
        assert_eq!(package.root_digest, expected_root_digest);
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
            root_digest: Some(root_hash.into()),
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
            root_digest: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
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
        assert!(log.contains("\"sequence_number\":1"));
        assert!(log.contains("\"pcr_index\":15"));
        assert!(log.contains("\"digests\":[{\"algorithm\":\"sha256\""));
        assert!(log.contains("\"event_size\":"));
        assert!(log.contains("\"event_type\":\"aos-package-set\""));
        assert!(log.contains("\"event_type\":\"aos-package\""));
        assert!(log.contains("\"package\":\"web\""));

        let first: serde_json::Value =
            serde_json::from_str(log.lines().next().expect("first log line")).expect("json");
        assert_eq!(first["sequence_number"], serde_json::Value::from(1));
        assert_eq!(first["pcr_index"], serde_json::Value::from(PCR_INDEX));
        assert_eq!(first["digests"][0]["algorithm"], PCR_BANK);
        assert_eq!(first["digests"][0]["digest"], first["digest"]);
        assert_eq!(
            first["event_size"],
            serde_json::Value::from(first["event"].as_str().expect("event").len())
        );
    }

    #[test]
    fn measure_activated_packages_rolls_back_log_when_live_pcr_extend_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let installed = installed_fixture(&tmp, br#"{"permissions":{}}"#);
        let log_path = tmp.path().join(AOS_PACKAGE_CEL_REL);
        fs::create_dir_all(log_path.parent().expect("log parent")).expect("log parent");
        fs::write(&log_path, "existing\n").expect("existing log");
        let failing_pcrextend = tmp.path().join("systemd-pcrextend");
        fs::write(&failing_pcrextend, "").expect("failing pcrextend");

        let err = measure_activated_packages_inner(
            tmp.path(),
            &[installed],
            true,
            Some(&failing_pcrextend),
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("systemd-pcrextend"));
        assert_eq!(
            fs::read_to_string(&log_path).expect("log after rollback"),
            "existing\n"
        );
    }

    #[test]
    fn measure_activated_packages_skips_pcr_when_no_tpm() {
        // A live root with no TPM and no forced pcrextend must not fail: the
        // package event log is still written, but no baseline event is added
        // and no PCR extension is attempted. Self-skip on the rare build host
        // that exposes a real TPM, where the live path would (correctly) run.
        if tpm2_tcti().ok().flatten().is_some() {
            return;
        }
        let tmp = TempDir::new().expect("tempdir");
        let installed = installed_fixture(&tmp, br#"{"permissions":{}}"#);

        measure_activated_packages_inner(tmp.path(), &[installed], true, None)
            .expect("measure without a tpm succeeds");

        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        assert!(log.contains("\"event_type\":\"aos-package\""));
        assert!(!log.contains(PCR_BASELINE_EVENT_TYPE));
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
        assert_eq!(verified.current_packages.len(), 1);
        assert_eq!(verified.current_packages[0].name, "web");
        assert_eq!(verified.current_packages[0].version, "1.0");
        assert_eq!(verified.current_packages[0].root_digest, root_hash);
        assert_eq!(
            verified.current_packages[0].measurement,
            measurement.trim_start_matches("sha256:")
        );
    }

    #[test]
    fn package_event_log_decoder_accepts_jsonl_bytes() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, _, _) = measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);

        let decoded = decode_package_event_log_bytes(log.as_bytes()).expect("jsonl decode");

        assert_eq!(decoded, log);
    }

    #[test]
    fn package_event_log_decoder_accepts_tcg_pcr_event2_binary_profile() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let catalog = vec![catalog_meta(&root_hash, &measurement)];
        let binary = tcg_pcr_event2_log_from_jsonl(&log);

        let decoded = decode_package_event_log_bytes(&binary).expect("binary decode");
        let verified = verify_package_event_log_against_catalog(&decoded, &pcr15, &catalog)
            .expect("verify binary event log");

        assert_eq!(decoded, log);
        assert_eq!(verified.pcr15, pcr15);
        assert_eq!(verified.package_count, 1);
    }

    #[test]
    fn package_event_log_decoder_rejects_unsupported_tcg_digest_count() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, _, _) = measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let mut binary = tcg_pcr_event2_log_from_jsonl(&log);
        binary[8..12].copy_from_slice(&2u32.to_le_bytes());

        let err = decode_package_event_log_bytes(&binary).unwrap_err();

        assert!(format!("{err:#}").contains("digest entries"));
    }

    #[test]
    fn package_event_log_verifier_accepts_legacy_record_shape() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let legacy_log = legacy_event_log_without_pcr_event_fields(&log);
        let pcr15 = replay_package_event_log_pcr15(&legacy_log).expect("pcr replay");
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let verified = verify_package_event_log_against_catalog(&legacy_log, &pcr15, &catalog)
            .expect("verify legacy log");

        assert_eq!(verified.pcr15, pcr15);
        assert_eq!(verified.package_count, 1);
    }

    #[test]
    fn package_event_log_verifier_replays_from_pcr_baseline() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let installed = installed_fixture(&tmp, manifest);
        let apm = installed.apm.as_ref().expect("apm metadata");
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_digest = package_manifest_digest_bytes(manifest);
        let measurement =
            package_measurement_digest(&apm.name, &apm.version, root_hash, &manifest_digest);
        let baseline = format!("sha256:{}", "11".repeat(32));
        let mut events = vec![pcr_baseline_event(&baseline)];
        events.extend(measurement_events(tmp.path(), &[installed]).expect("events"));
        append_event_log(tmp.path(), &events).expect("append log");
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let catalog =
            package_measurement_catalog_from_package_meta(&[catalog_meta(root_hash, &measurement)])
                .expect("catalog");

        let verified = verify_package_event_log_against_measurement_catalog(
            &log,
            &pcr15,
            Some(&baseline),
            &catalog,
        )
        .expect("verify log");

        assert_eq!(verified.pcr15, pcr15);
        assert_eq!(verified.package_count, 1);
        assert_ne!(
            pcr15,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn append_event_log_continues_sequence_numbers() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let installed = installed_fixture(&tmp, manifest);
        let events = measurement_events(tmp.path(), &[installed]).expect("events");

        append_event_log(tmp.path(), &events[..1]).expect("append first event");
        append_event_log(tmp.path(), &events[1..]).expect("append remaining events");

        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        let sequence_numbers = log
            .lines()
            .map(|line| {
                let record: serde_json::Value = serde_json::from_str(line).expect("record json");
                record["sequence_number"].as_u64().expect("sequence number")
            })
            .collect::<Vec<_>>();
        assert_eq!(sequence_numbers, [1, 2]);
    }

    #[test]
    fn generation_attestation_event_is_replayable_and_identity_bound() {
        let tmp = TempDir::new().expect("tempdir");
        let record = serde_json::json!({
            "schema": "aos.gen-attestation/v1",
            "activation_id": format!("sha256:{}", "a".repeat(64)),
            "generation_id": "sha256:generation",
            "manifest_hash": "sha256:manifest",
            "inputs": {},
            "eval_mode": "pure-eval",
            "quote_status": "quoted"
        });
        let canonical = crate::graph_compile::reproject::canonical_json(&record);
        let activation_a = format!("sha256:{}", "a".repeat(64));
        assert!(
            !measure_generation_attestation(
                tmp.path(),
                "sha256:generation",
                &activation_a,
                canonical.as_bytes(),
            )
            .expect("measure fixture")
        );
        assert!(
            !measure_generation_attestation(
                tmp.path(),
                "sha256:generation",
                &activation_a,
                canonical.as_bytes(),
            )
            .expect("replay measured fixture idempotently")
        );
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("event log");
        assert_eq!(
            log.lines().count(),
            1,
            "retry must not duplicate the PCR event"
        );
        let digest = Sha256::digest(canonical.as_bytes());
        let mut pcr_hasher = Sha256::new();
        pcr_hasher.update([0_u8; 32]);
        pcr_hasher.update(digest);
        let expected_pcr = hex::encode(pcr_hasher.finalize());
        let verified =
            verify_package_event_log_against_measurement_catalog(&log, &expected_pcr, None, &[])
                .expect("verify generation event");
        assert_eq!(
            verified.generation_attestations.get(&activation_a),
            Some(&format!("sha256:{}", hex::encode(digest)))
        );

        let conflicting = canonical.replace("sha256:manifest", "sha256:other");
        let error = measure_generation_attestation(
            tmp.path(),
            "sha256:generation",
            &activation_a,
            conflicting.as_bytes(),
        )
        .expect_err("same activation id with different record must fail");
        assert!(error.to_string().contains("disagrees"));

        let activation_b = format!("sha256:{}", "b".repeat(64));
        let second = conflicting.replace(&activation_a, &activation_b);
        assert!(
            !measure_generation_attestation(
                tmp.path(),
                "sha256:generation",
                &activation_b,
                second.as_bytes(),
            )
            .expect("a new activation of the same generation must append")
        );
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("event log");
        assert_eq!(log.lines().count(), 2);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("replay repeated activation");
        let verified =
            verify_package_event_log_against_measurement_catalog(&log, &pcr15, None, &[])
                .expect("verify repeated activation events");
        assert_eq!(verified.generation_attestations.len(), 2);
        assert_eq!(
            verified
                .generation_attestation_prefix_digests
                .get(&activation_b)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn package_measurement_catalog_entries_round_trip_through_json() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let mut installed = installed_fixture(&tmp, manifest);
        let apm = installed.apm.as_mut().expect("apm metadata");
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_digest = package_manifest_digest_bytes(manifest);
        let measurement =
            package_measurement_digest(&apm.name, &apm.version, root_hash, &manifest_digest);

        measure_activated_packages(tmp.path(), &[installed]).expect("measure");
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let json = serde_json::to_string(&vec![PackageMeasurementCatalogEntry {
            name: "web".into(),
            version: "1.0".into(),
            root_digest: root_hash.into(),
            measurement,
        }])
        .expect("serialize catalog");
        let catalog =
            serde_json::from_str::<Vec<PackageMeasurementCatalogEntry>>(&json).expect("catalog");

        let verified =
            verify_package_event_log_against_measurement_catalog(&log, &pcr15, None, &catalog)
                .expect("verify seed catalog");

        assert_eq!(verified.package_count, 1);
    }

    #[test]
    fn canonical_package_measurement_catalog_dedupes_matching_entries() {
        let entry = PackageMeasurementCatalogEntry {
            name: "web".into(),
            version: "1.0".into(),
            root_digest: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .into(),
            measurement: "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                .into(),
        };

        let catalog = canonical_package_measurement_catalog(&[entry.clone(), entry])
            .expect("canonical catalog");

        assert_eq!(catalog.len(), 1);
        assert_eq!(
            catalog[0].root_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            catalog[0].measurement,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn canonical_package_measurement_catalog_rejects_conflicts() {
        let first = PackageMeasurementCatalogEntry {
            name: "web".into(),
            version: "1.0".into(),
            root_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            measurement: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
        };
        let second = PackageMeasurementCatalogEntry {
            measurement: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .into(),
            ..first.clone()
        };

        let err = canonical_package_measurement_catalog(&[first, second]).unwrap_err();

        assert!(format!("{err:#}").contains("conflicting golden measurements"));
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
    fn package_event_log_verifier_rejects_digest_list_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let mut lines = log.lines().collect::<Vec<_>>();
        let mut package: serde_json::Value = serde_json::from_str(lines[1]).expect("package event");
        package["digests"][0]["digest"] =
            serde_json::Value::String(format!("sha256:{}", "bb".repeat(32)));
        let rewritten_package = serde_json::to_string(&package).expect("package json");
        lines[1] = &rewritten_package;
        let tampered = lines.join("\n") + "\n";
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let err =
            verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("digest list does not match"));
    }

    #[test]
    fn package_event_log_verifier_rejects_partial_pcr_event_shape() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let mut lines = log.lines().collect::<Vec<_>>();
        let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
        package_set
            .as_object_mut()
            .expect("set event object")
            .remove("digests");
        let rewritten_set = serde_json::to_string(&package_set).expect("set json");
        lines[0] = &rewritten_set;
        let tampered = lines.join("\n") + "\n";
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let err =
            verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("missing digests"));
    }

    #[test]
    fn package_event_log_verifier_rejects_null_pcr_event_field() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let mut lines = log.lines().collect::<Vec<_>>();
        let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
        package_set["digests"] = serde_json::Value::Null;
        let rewritten_set = serde_json::to_string(&package_set).expect("set json");
        lines[0] = &rewritten_set;
        let tampered = lines.join("\n") + "\n";
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let err =
            verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("invalid type: null"));
    }

    #[test]
    fn package_event_log_verifier_rejects_sequence_number_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let (log, root_hash, measurement) =
            measured_fixture_log(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let mut lines = log.lines().collect::<Vec<_>>();
        let mut package_set: serde_json::Value = serde_json::from_str(lines[0]).expect("set event");
        package_set["sequence_number"] = serde_json::Value::from(2);
        let rewritten_set = serde_json::to_string(&package_set).expect("set json");
        lines[0] = &rewritten_set;
        let tampered = lines.join("\n") + "\n";
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let err =
            verify_package_event_log_against_catalog(&tampered, &pcr15, &catalog).unwrap_err();

        assert!(format!("{err:#}").contains("sequence_number"));
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
        assert!(verified.current_packages.is_empty());
    }

    #[test]
    fn package_event_log_verifier_reports_latest_package_set() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let installed = installed_fixture(&tmp, manifest);
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_digest = package_manifest_digest_bytes(manifest);
        let measurement = package_measurement_digest("web", "1.0", root_hash, &manifest_digest);
        measure_activated_packages(tmp.path(), &[installed]).expect("measure package set");
        measure_activated_packages(tmp.path(), &[]).expect("measure empty package set");
        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        let pcr15 = replay_package_event_log_pcr15(&log).expect("pcr replay");
        let catalog = vec![catalog_meta(&root_hash, &measurement)];

        let verified =
            verify_package_event_log_against_catalog(&log, &pcr15, &catalog).expect("verify log");

        assert_eq!(verified.package_count, 1);
        assert!(verified.current_packages.is_empty());
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
        refresh_json_record_pcr_event_fields(&mut package_set);
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

    #[test]
    fn quote_nonce_parser_normalizes_hex() {
        assert_eq!(parse_quote_nonce_hex("A0b1").expect("nonce"), "a0b1");
    }

    #[test]
    fn quote_nonce_parser_rejects_invalid_hex() {
        let odd = parse_quote_nonce_hex("abc").unwrap_err();
        assert!(format!("{odd:#}").contains("even-length"));

        let non_hex = parse_quote_nonce_hex("zz").unwrap_err();
        assert!(format!("{non_hex:#}").contains("only hex"));
    }

    #[test]
    fn quote_bundle_verifier_rejects_invalid_nonce_before_tools() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = verify_attestation_quote_bundle(tmp.path(), "zz", &[]).unwrap_err();

        assert!(format!("{err:#}").contains("only hex"));
    }

    #[test]
    fn quote_bundle_snapshot_copies_members_to_private_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for name in [
            "ak.pub",
            "quote.msg",
            "quote.sig",
            "quote.pcrs",
            "ek.pub",
            "ek.name",
            "ek.qname",
            "ak.name",
            "ak.qname",
        ] {
            fs::write(tmp.path().join(name), name).expect("bundle member");
        }

        let snapshot = private_quote_bundle_snapshot(tmp.path(), true).expect("snapshot");

        assert_ne!(snapshot.parent(), Some(tmp.path()));
        assert_eq!(
            fs::metadata(&snapshot)
                .expect("snapshot metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for name in [
            "ak.pub",
            "quote.msg",
            "quote.sig",
            "quote.pcrs",
            "ek.pub",
            "ek.name",
            "ek.qname",
            "ak.name",
            "ak.qname",
        ] {
            let copied = fs::read_to_string(snapshot.join(name)).expect("copied member");
            assert_eq!(copied, name);
        }
        fs::remove_dir_all(snapshot).expect("cleanup snapshot");
    }

    #[test]
    fn quote_identity_catalog_accepts_matching_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_quote_identity_fixture(tmp.path(), "node-a");
        let identity = quote_identity_digests(tmp.path()).expect("identity");
        let identity_file = tmp.path().join("identity.json");
        fs::write(
            &identity_file,
            serde_json::json!({
                "version": 1,
                "anchors": [{
                    "label": "node-a",
                    "identity": identity,
                }],
            })
            .to_string(),
        )
        .expect("identity catalog");

        let anchor =
            verify_quote_bundle_trust(tmp.path(), &[identity_file]).expect("pinned identity");

        assert_eq!(
            anchor,
            Some(PackageQuoteTrustMatch {
                label: "node-a".into(),
                ak_ek_trusted: false,
            })
        );
    }

    #[test]
    fn quote_identity_enrollment_writes_catalog_and_marks_trusted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_quote_identity_fixture(tmp.path(), "node-a");
        let catalog = tmp.path().join("quote-identity.json");
        let evidence = tmp.path().join("credential-activation.txt");
        fs::write(&evidence, "credential activation transcript").expect("evidence");

        let enrolled = enroll_quote_identity(
            tmp.path(),
            &catalog,
            "node-a",
            "credential-activation",
            &evidence,
        )
        .expect("enroll identity");

        assert_eq!(enrolled.label, "node-a");
        assert_eq!(enrolled.method, "credential-activation");
        assert!(enrolled.evidence_sha256.starts_with("sha256:"));

        let trust =
            verify_quote_bundle_trust(tmp.path(), &[catalog.clone()]).expect("enrolled identity");
        assert_eq!(
            trust,
            Some(PackageQuoteTrustMatch {
                label: "node-a".into(),
                ak_ek_trusted: true,
            })
        );
        let duplicate = enroll_quote_identity(
            tmp.path(),
            &catalog,
            "node-a-again",
            "credential-activation",
            &evidence,
        )
        .unwrap_err();
        assert!(format!("{duplicate:#}").contains("already contains this AK/EK identity"));
    }

    #[test]
    fn quote_identity_enrollment_wins_over_duplicate_legacy_pin() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_quote_identity_fixture(tmp.path(), "node-a");
        let identity = quote_identity_digests(tmp.path()).expect("identity");
        let legacy_pin = tmp.path().join("legacy-pin.json");
        fs::write(
            &legacy_pin,
            serde_json::json!({
                "version": 1,
                "anchors": [{
                    "label": "legacy-node-a",
                    "identity": identity,
                }],
            })
            .to_string(),
        )
        .expect("legacy pin catalog");
        let enrolled_catalog = tmp.path().join("enrolled.json");
        let evidence = tmp.path().join("credential-activation.txt");
        fs::write(&evidence, "credential activation transcript").expect("evidence");
        enroll_quote_identity(
            tmp.path(),
            &enrolled_catalog,
            "enrolled-node-a",
            "credential-activation",
            &evidence,
        )
        .expect("enroll identity");

        let trust = verify_quote_bundle_trust(tmp.path(), &[legacy_pin, enrolled_catalog])
            .expect("enrolled identity");

        assert_eq!(
            trust,
            Some(PackageQuoteTrustMatch {
                label: "enrolled-node-a".into(),
                ak_ek_trusted: true,
            })
        );
    }

    #[test]
    fn quote_identity_enrollment_rejects_unknown_method() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_quote_identity_fixture(tmp.path(), "node-a");
        let evidence = tmp.path().join("evidence.txt");
        fs::write(&evidence, "proof").expect("evidence");

        let err = enroll_quote_identity(
            tmp.path(),
            &tmp.path().join("quote-identity.json"),
            "node-a",
            "web-of-trust",
            &evidence,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("credential-activation"));
    }

    #[test]
    fn quote_identity_catalog_rejects_mismatched_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bundle = tmp.path().join("bundle");
        let enrolled = tmp.path().join("enrolled");
        fs::create_dir_all(&bundle).expect("bundle dir");
        fs::create_dir_all(&enrolled).expect("enrolled dir");
        write_quote_identity_fixture(&bundle, "node-a");
        write_quote_identity_fixture(&enrolled, "node-b");
        let identity = quote_identity_digests(&enrolled).expect("identity");
        let identity_file = tmp.path().join("identity.json");
        fs::write(
            &identity_file,
            serde_json::json!({
                "version": 1,
                "anchors": [{
                    "label": "node-b",
                    "identity": identity,
                }],
            })
            .to_string(),
        )
        .expect("identity catalog");

        let err = verify_quote_bundle_trust(&bundle, &[identity_file]).unwrap_err();

        assert!(format!("{err:#}").contains("did not match any pinned identity"));
    }

    #[test]
    fn quote_identity_catalog_validates_all_requested_files_before_matching() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_quote_identity_fixture(tmp.path(), "node-a");
        let identity = quote_identity_digests(tmp.path()).expect("identity");
        let matching_file = tmp.path().join("matching.json");
        let malformed_file = tmp.path().join("malformed.json");
        fs::write(
            &matching_file,
            serde_json::json!({
                "version": 1,
                "anchors": [{
                    "label": "node-a",
                    "identity": identity,
                }],
            })
            .to_string(),
        )
        .expect("matching identity catalog");
        let mut malformed_identity = quote_identity_digests(tmp.path()).expect("identity");
        malformed_identity.ak_public_sha256 = "sha256:not-a-digest".to_string();
        fs::write(
            &malformed_file,
            serde_json::json!({
                "version": 1,
                "anchors": [{
                    "label": "bad",
                    "identity": malformed_identity,
                }],
            })
            .to_string(),
        )
        .expect("malformed identity catalog");

        let err =
            verify_quote_bundle_trust(tmp.path(), &[matching_file, malformed_file]).unwrap_err();

        assert!(format!("{err:#}").contains("ak_public_sha256"));
    }

    #[test]
    fn trusted_tpm2_tool_path_requires_absolute_expected_binary() {
        let path = validate_trusted_tpm2_tool_path(
            "AOS_TPM2_QUOTE",
            "tpm2_quote",
            "/nix/store/hash-tpm2-tools-5.7/bin/tpm2_quote",
        )
        .expect("trusted path");
        assert_eq!(
            path,
            PathBuf::from("/nix/store/hash-tpm2-tools-5.7/bin/tpm2_quote")
        );

        let relative =
            validate_trusted_tpm2_tool_path("AOS_TPM2_QUOTE", "tpm2_quote", "bin/tpm2_quote")
                .unwrap_err();
        assert!(format!("{relative:#}").contains("absolute tpm2_quote"));

        let wrong = validate_trusted_tpm2_tool_path(
            "AOS_TPM2_QUOTE",
            "tpm2_quote",
            "/usr/bin/tpm2_pcrread",
        )
        .unwrap_err();
        assert!(format!("{wrong:#}").contains("absolute tpm2_quote"));
    }

    #[test]
    fn quote_pcr_values_extracts_pcr15() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("quote.pcrs");
        let mut values = Vec::new();
        values.extend([0x07; 32]);
        values.extend([0x0b; 32]);
        values.extend([0x0c; 32]);
        values.extend([0x15; 32]);
        fs::write(&path, values).expect("pcr values");

        let pcr15 = quoted_pcr15_from_values_file(&path).expect("quoted pcr15");

        assert_eq!(pcr15, "15".repeat(32));
    }

    #[test]
    fn quote_pcr_values_rejects_unexpected_size() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("quote.pcrs");
        fs::write(&path, [0u8; 31]).expect("pcr values");

        let err = quoted_pcr15_from_values_file(&path).unwrap_err();

        assert!(format!("{err:#}").contains("expected 128"));
    }

    #[test]
    fn tpm2_pcrread_parser_extracts_pcr15() {
        let output = format!(
            "sha256:\n  7: 0x{}\n  15: 0x{}\n",
            "07".repeat(32),
            "ab".repeat(32)
        );

        let pcr15 = parse_tpm2_pcrread_pcr15(&output).expect("pcr15");

        assert_eq!(pcr15, format!("sha256:{}", "ab".repeat(32)));
    }

    #[test]
    fn quote_output_dir_must_be_new_absolute_and_private() {
        let parent = tempfile::tempdir().expect("tempdir");
        let output_dir = parent.path().join("quote");

        create_private_quote_output_dir(&output_dir).expect("private output dir");
        let metadata = fs::symlink_metadata(&output_dir).expect("metadata");
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        let reused = create_private_quote_output_dir(&output_dir).unwrap_err();
        assert!(format!("{reused:#}").contains("must not already exist"));

        let relative = create_private_quote_output_dir(Path::new("relative-quote")).unwrap_err();
        assert!(format!("{relative:#}").contains("absolute path"));
    }

    #[test]
    fn quote_output_dir_rejects_symlink_parent() {
        let parent = tempfile::tempdir().expect("tempdir");
        let real_parent = parent.path().join("real");
        let link_parent = parent.path().join("link");
        fs::create_dir(&real_parent).expect("real parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).expect("symlink parent");

        let err = create_private_quote_output_dir(&link_parent.join("quote")).unwrap_err();
        assert!(format!("{err:#}").contains("parent must be a real directory"));
    }
}

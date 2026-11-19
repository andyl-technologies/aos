//! Package-set TPM measurement for runtime attestation.
//!
//! Activation writes an AOS package event log at
//! `/run/log/aos-packages.cel` and, on the live system root, extends PCR 15
//! through AOS-built TPM tools. The measured package tuple is:
//!
//! ```text
//! H(name || version || root-digest || manifest-digest)
//! ```
//!
//! The implementation uses a stable length-prefixed text encoding for the
//! tuple so a verifier can replay the event log without guessing separators.
//!
//! This module owns the shared event record types, generation measurement,
//! and trusted TPM tool invocation. Its submodules hold the rest:
//!
//! - `event_log` writes, decodes, replays, and verifies the package event log.
//! - `quote` produces TPM quotes and verifies quote bundles.
//! - `enrollment` maintains the catalog of enrolled quote identities.

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

#[cfg(test)]
use aos_deployment_format::inventory::{InstalledPackageRecord, PackageInventoryDetails};
use aos_registry_format::consumer::PackageMeta;
#[cfg(test)]
use aos_registry_format::measurement::native_package_binding_digest;
#[cfg(test)]
use aos_registry_format::measurement::package_manifest_digest_bytes;
use aos_registry_format::measurement::package_measurement_digest;

const AOS_PACKAGE_CEL_REL: &str = "run/log/aos-packages.cel";
const TPM2_PCREXTEND_ENV: &str = "AOS_TPM2_PCREXTEND";
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

mod enrollment;
mod event_log;
mod quote;
#[cfg(test)]
mod tests;

pub(crate) use enrollment::enroll_quote_identity;
pub(crate) use event_log::{
    canonical_package_measurement_catalog, decode_package_event_log_bytes,
    package_measurement_catalog_from_package_meta,
    verify_package_event_log_against_measurement_catalog,
};
pub(crate) use quote::{current_pcr11, produce_package_quote, verify_attestation_quote_bundle};

// The submodules share this module's record types, constants, and TPM tool
// helpers through `use super::*`; these globs give them, and the tests, each
// other's `pub(super)` helpers in return.
use enrollment::*;
use event_log::*;
use quote::*;

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
/// fails through the AOS-built TPM helper.
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
        let pcrextend = trusted_tpm2_tool_path(TPM2_PCREXTEND_ENV, "tpm2_pcrextend")?;
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
    let pcrextend = trusted_tpm2_tool_path(TPM2_PCREXTEND_ENV, "tpm2_pcrextend")?;
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
    let mut before = format!("sha256:{}", hex::encode(pcr));
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
            before = format!("sha256:{}", hex::encode(pcr));
        } else if found {
            has_later_extends = true;
        }
        extend_replayed_pcr(&mut pcr, &recorded_digest)?;
        if is_expected {
            after = format!("sha256:{}", hex::encode(pcr));
        }
    }
    Ok(GenerationMeasurementRecovery {
        found,
        before,
        after,
        has_later_extends,
        replayed: format!("sha256:{}", hex::encode(pcr)),
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
    /// Validated PCR 15 value that preceded the first AOS event, when the CEL
    /// records a live-TPM baseline.
    pub pcr15_baseline: Option<String>,
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
pub struct PackageQuoteArtifacts {
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
pub struct PackageQuoteIdentityDigests {
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

fn extend_pcr15(pcrextend: &Path, events: &[MeasurementEvent]) -> Result<()> {
    let tcti = tpm2_tcti()?;
    for event in events {
        if !event.extends_pcr {
            continue;
        }
        let digest = digest_for_word(&event.word);
        if event.digest != format!("sha256:{digest}") {
            bail!("PCR {PCR_INDEX} event digest differs from its exact recorded bytes");
        }
        // Hash the same bytes retained in the AOS CEL, then submit the digest.
        // Passing the full record as one argument exceeds exec's per-argument
        // limit for realistic generation graphs. This retains the same TPM
        // transition and keeps the complete event in AOS's authoritative log.
        let argument = OsString::from(format!("{PCR_INDEX}:{PCR_BANK}={digest}"));
        run_tpm2_tool(pcrextend, &[argument], tcti.as_deref())?;
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

fn trusted_tpm2_tool_path(env_name: &str, bin_name: &str) -> Result<PathBuf> {
    let path = std::env::var(env_name)
        .ok()
        .or_else(|| compiled_tpm2_tool_path(env_name).map(str::to_owned))
        .with_context(|| {
            format!("{env_name} is not configured for package attestation quote production")
        })?;
    validate_trusted_tpm2_tool_path(env_name, bin_name, &path)
}

fn compiled_tpm2_tool_path(env_name: &str) -> Option<&'static str> {
    match env_name {
        TPM2_CREATEEK_ENV => option_env!("AOS_TPM2_CREATEEK"),
        TPM2_CREATEAK_ENV => option_env!("AOS_TPM2_CREATEAK"),
        TPM2_READPUBLIC_ENV => option_env!("AOS_TPM2_READPUBLIC"),
        TPM2_QUOTE_ENV => option_env!("AOS_TPM2_QUOTE"),
        TPM2_PCRREAD_ENV => option_env!("AOS_TPM2_PCRREAD"),
        TPM2_PCREXTEND_ENV => option_env!("AOS_TPM2_PCREXTEND"),
        TPM2_CHECKQUOTE_ENV => option_env!("AOS_TPM2_CHECKQUOTE"),
        TPM2_FLUSHCONTEXT_ENV => option_env!("AOS_TPM2_FLUSHCONTEXT"),
        _ => None,
    }
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

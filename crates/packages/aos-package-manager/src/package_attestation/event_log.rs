//! Package canonical event log (CEL) encoding, replay, and verification.
//!
//! Activation appends one JSON record per line to the package event log. Each
//! record carries a length-prefixed event word and its SHA-256 digest, and
//! replaying the digests in order reproduces PCR 15:
//!
//! ```text
//! {"format":"aos-package-cel-v1","sequence_number":0,"event_type":"aos-pcr-baseline",...}
//! {"format":"aos-package-cel-v1","sequence_number":1,"event_type":"aos-package",...}
//! ```
//!
//! This module also decodes binary TCG PCR event logs into the same line
//! format and checks replayed package events against a signed measurement
//! catalog.

use super::*;

#[cfg(test)]
pub(super) fn measurement_events(
    root: &Path,
    installed: &[InstalledPackageRecord],
) -> Result<Vec<MeasurementEvent>> {
    let mut packages = Vec::new();
    for entry in installed {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        if !apm.explicit || apm.deployment.is_none() {
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

#[cfg(test)]
pub(super) fn measured_package(
    _root: &Path,
    _entry: &InstalledPackageRecord,
    apm: &PackageInventoryDetails,
) -> Result<MeasuredPackage> {
    let root_digest = package_root_digest(apm)?;
    let manifest_digest = package_manifest_digest(apm)?;
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

#[cfg(test)]
pub(super) fn package_root_digest(apm: &PackageInventoryDetails) -> Result<String> {
    let root = apm.attestation.root_digest.as_ref().with_context(|| {
        format!(
            "package '{}' has no authenticated payload root digest",
            apm.name
        )
    })?;
    Ok(aos_core::Sha256Digest::parse(root)?.to_string())
}

#[cfg(test)]
pub(super) fn package_manifest_digest(apm: &PackageInventoryDetails) -> Result<String> {
    let deployment = apm.deployment.as_ref().with_context(|| {
        format!(
            "package '{}' has no authenticated native deployment envelope",
            apm.name
        )
    })?;
    native_package_binding_digest(
        deployment,
        apm.module_documentation.as_ref(),
        apm.qualification.as_ref(),
    )
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
                let sequence = value.get("sequence").and_then(serde_json::Value::as_u64);
                let content = value.get("content").and_then(serde_json::Value::as_str);
                let expected_generation = match (sequence, content) {
                    (Some(sequence), Some(content)) if sequence > 0 => {
                        aos_core::Sha256Digest::parse(content)?;
                        Some(format!("{sequence}:{content}"))
                    }
                    _ => None,
                };
                if value.get("schema").and_then(serde_json::Value::as_str)
                    != Some(crate::attestation::native::GENERATION_SCHEMA)
                    || expected_generation.as_deref() != Some(generation_id)
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
                // Native evidence measures the record before attaching quote
                // bytes. A nonempty quote would authenticate itself and must
                // never enter the generation's measured CEL record.
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
        pcr15_baseline: expected_baseline_pcr15,
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
pub(super) fn replay_package_event_log_pcr15(event_log: &str) -> Result<String> {
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

#[cfg(test)]
pub(super) fn package_event(package: MeasuredPackage) -> Result<MeasurementEvent> {
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

#[cfg(test)]
pub(super) fn package_set_event(package_events: &[MeasurementEvent]) -> MeasurementEvent {
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

pub(super) fn pcr_baseline_event(pcr15: &str) -> MeasurementEvent {
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

#[cfg(test)]
pub(super) fn package_tuple_word(package: &MeasuredPackage) -> String {
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

pub(super) fn length_prefixed_word(schema: &str, fields: &[(&str, String)]) -> String {
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

pub(super) fn parse_length_prefixed_word(
    schema: &str,
    word: &str,
) -> Result<BTreeMap<String, String>> {
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

pub(super) fn package_measurement_catalog(
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

pub(super) fn validate_event_record_shape(line: usize, record: &OwnedEventLogRecord) -> Result<()> {
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

pub(super) fn validate_pcr_event_fields(line: usize, record: &OwnedEventLogRecord) -> Result<()> {
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

pub(super) fn decode_tcg_pcr_event2_log(bytes: &[u8]) -> Result<String> {
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

pub(super) struct TcgEventReader<'a> {
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

pub(super) fn event_log_line_from_tcg_event(
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

pub(super) fn event_type_from_word(word: &str) -> Result<&'static str> {
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

pub(super) fn word_has_schema(word: &str, schema: &str) -> bool {
    word == schema || word.as_bytes().get(schema.len()) == Some(&b'|')
}

pub(super) fn required_event_word_field(
    fields: &BTreeMap<String, String>,
    field: &str,
) -> Result<String> {
    fields
        .get(field)
        .cloned()
        .with_context(|| format!("AOS package TCG event is missing {field}"))
}

pub(super) fn parse_pcr_baseline_record(
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

pub(super) fn parse_package_set_record(
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

pub(super) fn verify_package_record(
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

pub(super) fn extend_replayed_pcr(pcr: &mut [u8; 32], event_digest_hex: &str) -> Result<()> {
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

pub(super) fn event_digest_hex(event: &str) -> String {
    digest_for_word(event)
}

pub(super) fn event_log_has_records(root: &Path) -> Result<bool> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    match fs::read_to_string(&path) {
        Ok(log) => Ok(log.lines().any(|line| !line.trim().is_empty())),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

pub(super) fn append_event_log(root: &Path, events: &[MeasurementEvent]) -> Result<()> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    let (existing_lines, needs_separator, created_file) = match fs::read_to_string(&path) {
        Ok(log) => (
            log.lines().count(),
            !log.is_empty() && !log.ends_with('\n'),
            false,
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => (0, false, true),
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
    Ok(())
}

pub(super) fn event_log_line(sequence_number: usize, event: &MeasurementEvent) -> Result<String> {
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

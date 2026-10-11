//! Authenticated ARM root historical images with original Serial and Poll custody.
//!
//! The installed factory authenticates the complete signed source record. This
//! importer seals bounded privately materialized bytes, never a live peer or a
//! preparation certificate. Each fresh native owner still recaptures and audits.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Id, U64, canonical};

use super::*;
use crate::ProviderError;
use crate::gem5::{ArmRootCapturedImage, ArmRootHistoricalSource, ArmRootRunOutcome};
use crucible_node_contract::Validate;

const MAX_PREFIXES: usize = 512;
const MAX_RECEIPT_BYTES: usize = 16 * 1024 * 1024;

/// Supplies an inert complete ARM source record to an installed signed verifier.
#[derive(Clone, Debug)]
pub struct ArmRootArchiveImport {
    /// Retains the original capture identity.
    pub capture: Id,
    /// Retains typed original installed source and vanished route lineage.
    pub source: ArmRootHistoricalSource,
    /// Retains the original authentic saved-copy root, never a guessed sibling.
    pub source_supplementary_files_root: PathBuf,
    /// Retains the actual stopped native and common logical positions.
    pub boundary: Gem5Boundary,
    /// Retains every exact completed or refused original native wire body.
    pub original_outcomes: Vec<Vec<u8>>,
    /// Retains every actual original Ready, control request, reply and admin ACK body.
    pub control_history: crate::gem5::ArmRootControlHistory,
    /// Names the held successful or refused original subordinate Poll.
    pub pending: Option<Id>,
    /// Names the most recently acknowledged original Poll.
    pub last_acknowledged: Option<Id>,
    /// Retains the complete privately imported original role/name file roster.
    pub artifacts: Vec<Gem5ArchiveArtifact>,
}

/// Authenticates the complete ARM backend envelope beneath a signed world archive.
///
/// Implementations belong to installed host factories. Verification binds every
/// supplied source/cut/receipt/ACK/file field to the verified original node
/// continuation and its preparation/publication ancestry. Hashes alone are not
/// provenance and do not create execution or preparation authority.
pub trait ArmRootArchiveSourceVerifier {
    /// Verifies the signed original ARM record and compatible installed source.
    ///
    /// # Errors
    /// Refuses missing or altered signed ancestry, a foreign backend/model,
    /// substituted original receipt or asset fields and unsupported source scope.
    fn verify_archive(&self, source: &ArmRootArchiveImport) -> Result<(), ProviderError>;
}

impl ArmRootCapturedImage {
    /// Exports original model data and geometry for a signed backend envelope.
    ///
    /// The returned record is inert. An installed signed-source verifier must
    /// authenticate it again before historical import; it grants no authority.
    ///
    /// # Errors
    /// Refuses changed privately preserved files or unrepresentable source data.
    pub fn archive_record(&self) -> Result<ArmRootArchiveImport, ProviderError> {
        self.verify()?;
        let outcomes = original_wire_outcomes(self.control_history())?;
        let record = ArmRootArchiveImport {
            capture: self.capture.clone(),
            source: self.source.historical_source()?,
            source_supplementary_files_root: self.source_supplementary_files_root.clone(),
            boundary: self.boundary.clone(),
            original_outcomes: outcomes,
            control_history: self.control_history().clone(),
            pending: self.pending.clone(),
            last_acknowledged: self.last_acknowledged.clone(),
            artifacts: self
                .artifact_inventory()
                .map(|file| Gem5ArchiveArtifact {
                    role: file.role,
                    relative: file.relative.to_owned(),
                    artifact: file.artifact.clone(),
                })
                .collect(),
        };
        let completed = validate_outcomes(&record)?;
        validate_protocol_custody(&record, &completed)?;
        Ok(record)
    }

    /// Imports verified complete historical bytes without creating live authority.
    ///
    /// The verifier must authenticate the whole original ARM record. Imported
    /// bytes must occupy separate canonical private image/resource namespaces.
    /// Fresh restoration and current native byte closure remain mandatory.
    ///
    /// # Errors
    /// Rejects foreign installed models, altered ancestry or original custody,
    /// invalid native progress, unsafe/split geometry, missing/extra/changed files
    /// and bounded frame, count or cumulative byte credit exhaustion.
    pub fn import_authenticated_arm_archive(
        record: ArmRootArchiveImport,
        verifier: &dyn ArmRootArchiveSourceVerifier,
    ) -> Result<Self, ProviderError> {
        record.capture.validate()?;
        let source = record.source.installed_source()?;
        let completed = validate_outcomes(&record)?;
        validate_protocol_custody(&record, &completed)?;
        validate_preparation_source(&record, &source)?;
        validate_files(&record, &source)?;
        verifier.verify_archive(&record)?;
        // The installed verifier may do I/O. Remeasure the same complete private
        // census after provenance checks, rather than sealing stale path claims.
        validate_files(&record, &source)?;
        let mut image_files = Vec::new();
        let mut resource_files = Vec::new();
        for file in record.artifacts {
            let saved = CapturedFile {
                relative: file.relative,
                artifact: file.artifact,
            };
            match file.role {
                Gem5CapturedArtifactRole::Image => image_files.push(saved),
                Gem5CapturedArtifactRole::Resource => resource_files.push(saved),
            }
        }
        image_files.sort_by(|left, right| left.relative.cmp(&right.relative));
        resource_files.sort_by(|left, right| left.relative.cmp(&right.relative));
        record.control_history.validate()?;
        let native = Gem5CapturedModelImage {
            capture: record.capture,
            source,
            boundary: record.boundary,
            completed,
            pending: record.pending,
            last_acknowledged: record.last_acknowledged,
            source_supplementary_files_root: record.source_supplementary_files_root,
            image_files,
            resource_files,
        };
        let image = Self {
            native,
            history: record.control_history,
        };
        image.verify()?;
        image.materialized_supplementary_files_root()?;
        Ok(image)
    }
}

fn validate_outcomes(
    record: &ArmRootArchiveImport,
) -> Result<BTreeMap<Id, ArmRootRunOutcome>, ProviderError> {
    validate_boundary(&record.boundary)?;
    if record.original_outcomes.len() > MAX_PREFIXES {
        return Err(ProviderError::ResourceExhausted(
            "ARM archived original Poll count",
        ));
    }
    let mut total = 0usize;
    let mut completed = BTreeMap::new();
    let mut previous = None;
    let mut output_sequence = U64::new(0);
    for bytes in &record.original_outcomes {
        total = total
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_RECEIPT_BYTES)
            .ok_or(ProviderError::ResourceExhausted(
                "ARM archived original receipt bytes",
            ))?;
        let value = canonical::parse_json(bytes, crate::gem5::GEM5_NATIVE_FRAME_BYTES)?;
        let outcome =
            if value.get("kind").and_then(serde_json::Value::as_str) == Some("run_refused") {
                let raw: crate::gem5::Gem5RunRefusal = serde_json::from_value(value)
                    .map_err(|_| ProviderError::Frame("ARM archived refusal shape"))?;
                validate_original(&raw.original, &raw.boundary)?;
                let parsed = crate::gem5::parse_run_refusal_for_model(
                    bytes,
                    "crucible.gem5.arm-linux-native/1",
                    crate::gem5::Gem5ModelDialect::ArmLinux,
                    &diagnostic_policy(),
                    &raw.original,
                    &raw.boundary,
                )?;
                ArmRootRunOutcome::Refused {
                    refusal: parsed.receipt().clone(),
                    bytes: bytes.clone(),
                }
            } else {
                let prefix: crate::gem5::ArmRootPrefix = serde_json::from_value(value)
                    .map_err(|_| ProviderError::Frame("ARM archived typed Serial prefix shape"))?;
                validate_original(&prefix.original, &prefix.before)?;
                validate_boundary(&prefix.after)?;
                crate::gem5::arm_root_run::validate(
                    &prefix,
                    &prefix.original,
                    &prefix.before,
                    output_sequence,
                )?;
                output_sequence = prefix
                    .publications
                    .last()
                    .map(|body| body.output_id)
                    .unwrap_or(output_sequence);
                ArmRootRunOutcome::Completed {
                    prefix,
                    bytes: bytes.clone(),
                }
            };
        let (before, after) = cuts(&outcome);
        if previous.as_ref().is_some_and(|old| old != before) {
            return Err(ProviderError::Correlation(
                "ARM archived original native prefix gap",
            ));
        }
        if previous.is_none()
            && (before.ordinal.get() != 0
                || before.tick.get() != 0
                || before.logical_position.time_ps.get() != 0
                || before.logical_position.microstep.get() != 0)
        {
            return Err(ProviderError::Correlation(
                "ARM archived original prefix history truncated",
            ));
        }
        previous = Some(after.clone());
        let original = outcome.original();
        if completed
            .insert(original.operation.clone(), outcome)
            .is_some()
        {
            return Err(ProviderError::Conflict(
                "ARM archived duplicate original Poll identity",
            ));
        }
    }
    if previous
        .as_ref()
        .is_some_and(|last| last != &record.boundary)
        || (previous.is_none()
            && (record.boundary.ordinal.get() != 0
                || record.boundary.tick.get() != 0
                || record.boundary.logical_position.time_ps.get() != 0
                || record.boundary.logical_position.microstep.get() != 0))
    {
        return Err(ProviderError::Correlation(
            "ARM archived final cut differs from original history",
        ));
    }
    if let Some(pending) = &record.pending {
        let entry = completed.get(pending).ok_or(ProviderError::Correlation(
            "ARM archived pending original omitted",
        ))?;
        if cuts(entry).1 != &record.boundary || Some(pending) == record.last_acknowledged.as_ref() {
            return Err(ProviderError::Correlation(
                "ARM archived held Poll differs from cut or ACK",
            ));
        }
    }
    if record
        .last_acknowledged
        .as_ref()
        .is_some_and(|ack| !completed.contains_key(ack))
    {
        return Err(ProviderError::Correlation(
            "ARM archived last ACK original omitted",
        ));
    }
    Ok(completed)
}

fn cuts(outcome: &ArmRootRunOutcome) -> (&Gem5Boundary, &Gem5Boundary) {
    match outcome {
        ArmRootRunOutcome::Completed { prefix, .. } => (&prefix.before, &prefix.after),
        ArmRootRunOutcome::Refused { refusal, .. } => (&refusal.boundary, &refusal.boundary),
    }
}

fn validate_original(
    original: &crate::gem5::Gem5Run,
    before: &Gem5Boundary,
) -> Result<(), ProviderError> {
    original.operation.validate()?;
    validate_boundary(before)?;
    let range = original.exact_range.as_ref().ok_or(ProviderError::Frame(
        "ARM archived exact permission omitted",
    ))?;
    if original.kind != "run"
        || original.maximum_events.get() == 0
        || original.maximum_events.get() > 1_000_000
        || range.maximum_microsteps.get() != 1_000_000
        || range.start != before.logical_position
        || range.start >= range.limit
        || range.limit.microstep >= range.maximum_microsteps
        || original.exclusive_tick != range.limit.time_ps
    {
        return Err(ProviderError::Correlation(
            "ARM archived original exact permission differs",
        ));
    }
    Ok(())
}

fn validate_boundary(boundary: &Gem5Boundary) -> Result<(), ProviderError> {
    bounded_encoded_extent(boundary)?;
    boundary.logical_position.validate()?;
    if boundary.tick_ordinal > boundary.ordinal
        || boundary.logical_position.microstep.get() >= 1_000_000
        || boundary.logical_position.time_ps < boundary.tick
        || (boundary.has_next_event && boundary.next_tick < boundary.tick)
    {
        return Err(ProviderError::Correlation(
            "ARM archived native boundary differs",
        ));
    }
    boundary.next_reaction(U64::new(1_000_000))?;
    Ok(())
}

fn diagnostic_policy() -> crate::gem5::Gem5DiagnosticCreditPolicy {
    // These bounds belong to the measured fixed controller implementation; the
    // signed source profile binds that exact implementation before import.
    crate::gem5::Gem5DiagnosticCreditPolicy {
        schema: "crucible.gem5.diagnostic-credit-policy.v1".to_owned(),
        maximum_object_bytes: U64::new(64 * 1024 * 1024),
        maximum_total_bytes: U64::new(256 * 1024 * 1024),
        maximum_files: U64::new(1024),
        refusal_schema: "crucible.gem5.run-refused.v1".to_owned(),
    }
}

fn validate_files(
    record: &ArmRootArchiveImport,
    source: &crate::gem5::ArmRootLaunch,
) -> Result<(), ProviderError> {
    if record.artifacts.is_empty() || record.artifacts.len() > MAX_FILES {
        return Err(ProviderError::ResourceExhausted(
            "ARM archived complete artifact count",
        ));
    }
    crate::gem5::arm_root_source::validate_historical_route(
        &record.source_supplementary_files_root,
    )?;
    validate_supplementary_source_root(
        &record.source_supplementary_files_root,
        record
            .artifacts
            .iter()
            .filter(|file| file.role == Gem5CapturedArtifactRole::Image)
            .map(|file| file.relative.as_path()),
    )?;
    if record.source_supplementary_files_root.parent() != Some(record.source.image_root.as_path()) {
        return Err(ProviderError::Correlation(
            "ARM archived original saved-file route differs",
        ));
    }
    let mut names = BTreeSet::new();
    let mut roots = [None::<PathBuf>, None::<PathBuf>];
    let mut total = 0;
    let mut primary = 0usize;
    for file in &record.artifacts {
        let image = file.role == Gem5CapturedArtifactRole::Image;
        let index = usize::from(image);
        if file.relative.as_os_str().is_empty()
            || file.relative.as_os_str().len() > 4096
            || file
                .relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || !names.insert((image, file.relative.clone()))
            || !file.artifact.path.ends_with(&file.relative)
        {
            return Err(ProviderError::Frame(
                "ARM archived role/name geometry differs",
            ));
        }
        let root = file
            .artifact
            .path
            .ancestors()
            .nth(file.relative.components().count())
            .ok_or(ProviderError::Frame(
                "ARM archived materialized namespace omitted",
            ))?;
        validate_private_directory(root)?;
        if roots[index].as_ref().is_some_and(|old| old != root) {
            return Err(ProviderError::Correlation(
                "ARM archived materialized namespace split",
            ));
        }
        roots[index] = Some(root.to_owned());
        let limit = if image {
            primary += usize::from(file.relative.extension().is_some_and(|ext| ext == "dmtcp"));
            GEM5_MAX_IMAGE_BYTES
        } else {
            MAX_FILE_BYTES
        };
        let measured = measure_file_with_limit(&file.artifact.path, limit)?;
        if measured != file.artifact.content {
            return Err(ProviderError::Correlation(
                "ARM archived original artifact changed",
            ));
        }
        total = add_length(total, measured.length)?;
    }
    let resource_root = roots[0].as_ref().ok_or(ProviderError::Frame(
        "ARM archived resource namespace omitted",
    ))?;
    let image_root = roots[1]
        .as_ref()
        .ok_or(ProviderError::Frame("ARM archived image namespace omitted"))?;
    if primary != 1
        || resource_root.starts_with(image_root)
        || image_root.starts_with(resource_root)
    {
        return Err(ProviderError::Correlation(
            "ARM archived primary or namespace geometry differs",
        ));
    }
    for (image, root) in [(false, resource_root), (true, image_root)] {
        let actual = inventory(root, image)?;
        let expected: BTreeMap<_, _> = record
            .artifacts
            .iter()
            .filter(|file| (file.role == Gem5CapturedArtifactRole::Image) == image)
            .map(|file| (&file.relative, &file.artifact.content))
            .collect();
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|file| expected.get(&file.relative) != Some(&&file.artifact.content))
        {
            return Err(ProviderError::Correlation(
                "ARM archived complete namespace census differs",
            ));
        }
    }
    for (role, name) in [
        ("controller", "native-controller.py"),
        ("entrypoint", "native-controller-arm-root.py"),
        ("model", "native-controller-arm-root-model.py"),
        ("board_model", "native-controller-arm-model.py"),
        ("publication_model", "native-controller-models.py"),
        ("asset_checker", "native-model-assets.py"),
        ("auditor", "full-system-process-image-audit.py"),
        ("auditor_core", "process-image-audit-core.py"),
        ("kernel", "kernel.elf"),
        ("initramfs", "initrd.img"),
        ("firmware", "boot_v2.arm64"),
    ] {
        let expected = &source.artifact(role)?.content;
        if !record.artifacts.iter().any(|file| {
            file.role == Gem5CapturedArtifactRole::Resource
                && file.relative == Path::new(name)
                && &file.artifact.content == expected
        }) {
            return Err(ProviderError::Correlation(
                "ARM archived fixed guest/controller asset omitted",
            ));
        }
    }
    validate_configuration(record, source)
}

fn validate_configuration(
    record: &ArmRootArchiveImport,
    source: &crate::gem5::ArmRootLaunch,
) -> Result<(), ProviderError> {
    let installed = source.metadata["configuration_root"]
        .as_str()
        .ok_or(ProviderError::Frame("ARM source configuration omitted"))?;
    let root = Path::new(installed);
    let mut pending = vec![(root.to_owned(), 0usize)];
    let mut expected = BTreeMap::new();
    let mut total = 0u64;
    let mut directories = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        directories += 1;
        if directories > 8192 || depth > 32 {
            return Err(ProviderError::ResourceExhausted(
                "ARM source configuration depth",
            ));
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if kind.is_file() {
                if expected.len() >= 4096 {
                    return Err(ProviderError::ResourceExhausted(
                        "ARM source configuration files",
                    ));
                }
                let content = measure_file(&entry.path())?;
                total = total
                    .checked_add(content.length.get())
                    .filter(|total| *total <= 64 * 1024 * 1024)
                    .ok_or(ProviderError::ResourceExhausted(
                        "ARM source configuration bytes",
                    ))?;
                let relative = Path::new("configs").join(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|_| ProviderError::Frame("ARM source configuration escape"))?,
                );
                expected.insert(relative, content);
            } else {
                return Err(ProviderError::Frame(
                    "ARM source configuration has symbolic or special entry",
                ));
            }
        }
    }
    let actual: BTreeMap<_, _> = record
        .artifacts
        .iter()
        .filter(|file| {
            file.role == Gem5CapturedArtifactRole::Resource && file.relative.starts_with("configs")
        })
        .map(|file| (file.relative.clone(), file.artifact.content.clone()))
        .collect();
    if actual != expected {
        return Err(ProviderError::Correlation(
            "ARM archived fixed configuration tree differs",
        ));
    }
    Ok(())
}

// Counts serde wire bytes without allocating an attacker-sized second body.
fn bounded_encoded_extent(value: &impl serde::Serialize) -> Result<(), ProviderError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= crate::gem5::GEM5_NATIVE_FRAME_BYTES)
                .ok_or_else(|| std::io::Error::other("ARM archived native frame credit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Counter(0), value)
        .map_err(|_| ProviderError::ResourceExhausted("ARM archived native frame credit"))
}

fn original_wire_outcomes(
    history: &crate::gem5::ArmRootControlHistory,
) -> Result<Vec<Vec<u8>>, ProviderError> {
    history.validate()?;
    let mut request = None;
    let mut seen = BTreeMap::new();
    let mut output = Vec::new();
    for packet in &history.packets {
        let body = canonical::parse_json(&packet.bytes, crate::gem5::GEM5_NATIVE_FRAME_BYTES)?;
        match packet.kind {
            crate::gem5::ArmRootControlKind::Request => request = Some(body),
            crate::gem5::ArmRootControlKind::Ready => {
                request = None;
            }
            crate::gem5::ArmRootControlKind::Response => {
                let original = request.take().ok_or(ProviderError::Correlation(
                    "ARM historical reply original omitted",
                ))?;
                if original.get("kind").and_then(serde_json::Value::as_str) != Some("run") {
                    continue;
                }
                let permission: crate::gem5::Gem5Run = serde_json::from_value(original)
                    .map_err(|_| ProviderError::Frame("ARM historical original run shape"))?;
                if body.get("original")
                    != Some(
                        &serde_json::to_value(&permission).map_err(|_| {
                            ProviderError::Frame("ARM historical permission encoding")
                        })?,
                    )
                {
                    return Err(ProviderError::Correlation(
                        "ARM original reply changed permission",
                    ));
                }
                if let Some(bytes) = seen.get(&permission.operation) {
                    if bytes != &packet.bytes {
                        return Err(ProviderError::Correlation(
                            "ARM original run retry changed native bytes",
                        ));
                    }
                } else {
                    seen.insert(permission.operation, packet.bytes.clone());
                    output.push(packet.bytes.clone());
                }
            }
        }
    }
    Ok(output)
}

fn validate_protocol_custody(
    record: &ArmRootArchiveImport,
    completed: &BTreeMap<Id, ArmRootRunOutcome>,
) -> Result<(), ProviderError> {
    if original_wire_outcomes(&record.control_history)? != record.original_outcomes {
        return Err(ProviderError::Correlation(
            "ARM archived outcomes differ from actual control bodies",
        ));
    }
    let mut request = None;
    let mut pending = None;
    let mut acknowledged = None;
    for packet in &record.control_history.packets {
        let body = canonical::parse_json(&packet.bytes, crate::gem5::GEM5_NATIVE_FRAME_BYTES)?;
        match packet.kind {
            crate::gem5::ArmRootControlKind::Request => request = Some(body),
            crate::gem5::ArmRootControlKind::Ready => {
                request = None;
            }
            crate::gem5::ArmRootControlKind::Response => {
                let original = request.take().ok_or(ProviderError::Correlation(
                    "ARM control receipt original omitted",
                ))?;
                let kind = original.get("kind").and_then(serde_json::Value::as_str);
                if !matches!(kind, Some("run" | "acknowledge" | "ack_refused")) {
                    continue;
                }
                let operation: Id = serde_json::from_value(
                    original
                        .get("operation")
                        .cloned()
                        .ok_or(ProviderError::Frame("ARM actual operation body omitted"))?,
                )
                .map_err(|_| ProviderError::Frame("ARM actual operation identity"))?;
                let outcome = completed.get(&operation).ok_or(ProviderError::Correlation(
                    "ARM control operation tombstone omitted",
                ))?;
                if kind == Some("run") {
                    if acknowledged.as_ref() != Some(&operation) {
                        pending = Some(operation);
                    }
                    continue;
                }
                let refused = matches!(outcome, ArmRootRunOutcome::Refused { .. });
                if (kind == Some("ack_refused")) != refused
                    || (pending.as_ref() != Some(&operation)
                        && acknowledged.as_ref() != Some(&operation))
                    || body
                        != serde_json::json!({"kind":if refused {"refusal_acknowledged"} else {"acknowledged"},"operation":operation})
                {
                    return Err(ProviderError::Correlation(
                        "ARM actual original ACK class or custody differs",
                    ));
                }
                pending = None;
                acknowledged = Some(operation);
            }
        }
    }
    if pending != record.pending || acknowledged != record.last_acknowledged {
        return Err(ProviderError::Correlation(
            "ARM original pending or ACK history omitted",
        ));
    }
    Ok(())
}

fn validate_preparation_source(
    record: &ArmRootArchiveImport,
    source: &crate::gem5::ArmRootLaunch,
) -> Result<(), ProviderError> {
    record.control_history.validate()?;
    let selection = crate::gem5::arm_root_process::selection(source)?;
    for (number, session) in record.control_history.sessions.iter().enumerate() {
        let transcript = canonical::parse_json(
            &session.transcript_bytes,
            crate::gem5::GEM5_NATIVE_FRAME_BYTES,
        )?;
        if transcript.get("profile")
            != Some(
                &serde_json::to_value(&record.source.profile)
                    .map_err(|_| ProviderError::Frame("ARM historical profile encoding"))?,
            )
            || transcript.get("owner")
                != Some(
                    &serde_json::to_value(&record.source.owner)
                        .map_err(|_| ProviderError::Frame("ARM historical owner encoding"))?,
                )
        {
            return Err(ProviderError::Correlation(
                "ARM historical preparation source differs",
            ));
        }
        if number + 1 == record.control_history.sessions.len()
            && (transcript.get("incarnation")
                != Some(
                    &serde_json::to_value(&record.source.incarnation)
                        .map_err(|_| ProviderError::Frame("ARM historical incarnation encoding"))?,
                )
                || transcript.get("generation")
                    != Some(
                        &serde_json::to_value(record.source.generation).map_err(|_| {
                            ProviderError::Frame("ARM historical generation encoding")
                        })?,
                    )
                || transcript.get("source_scope")
                    != Some(&serde_json::to_value(source.scope()?).map_err(|_| {
                        ProviderError::Frame("ARM historical source scope encoding")
                    })?))
        {
            return Err(ProviderError::Correlation(
                "ARM original preparation source scope differs",
            ));
        }
        let packet = record
            .control_history
            .packets
            .iter()
            .find(|packet| {
                packet.kind == crate::gem5::ArmRootControlKind::Ready
                    && session.packet.verify(&packet.bytes).is_ok()
            })
            .ok_or(ProviderError::Correlation("ARM preparation Ready omitted"))?;
        let ready: crate::gem5::Gem5ArmNativeReady = serde_json::from_value(canonical::parse_json(
            &packet.bytes,
            crate::gem5::GEM5_NATIVE_FRAME_BYTES,
        )?)
        .map_err(|_| ProviderError::Frame("ARM historical Ready shape"))?;
        ready.validate_selection(
            &selection,
            &source.owner,
            &ready.incarnation,
            ready.generation,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "arm_root_archive_tests.rs"]
mod tests;

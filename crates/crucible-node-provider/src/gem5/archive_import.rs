//! Authenticated historical image import without fresh native execution authority.
//!
//! Installed host factories verify a signed complete native source record. The
//! portable fields below are inert data until that verification and independent
//! bounded artifact checks succeed. Fresh reconstruction still needs its own
//! actual live closure certificate and exact-profile qualification.

use std::collections::BTreeSet;

use super::*;

const MAX_PREFIXES: usize = 65_536;
const MAX_RECEIPT_BYTES: usize = 256 * 1024 * 1024;

/// Retains one owned historical artifact with its original reconstruction role.
#[derive(Clone, Debug)]
pub struct Gem5ArchiveArtifact {
    /// Selects the original image or runtime-resource namespace.
    pub role: Gem5CapturedArtifactRole,
    /// Retains a bounded, normal path relative to that namespace.
    pub relative: PathBuf,
    /// Pins already privately materialized bytes and their original identity.
    pub artifact: Gem5LaunchArtifact,
}

/// Supplies inert complete historical native state to an installed verifier.
#[derive(Clone, Debug)]
pub struct Gem5ArchiveImport {
    /// Retains the original capture identity without assigning a new attempt.
    pub capture: Id,
    /// Retains original owner scope and source layout with measured installed tools.
    ///
    /// Installed artifact paths may change only while preserving content identity.
    /// The original resource root remains part of source lineage and the controlled
    /// DMTCP path mapping; import never accesses that historical host path.
    pub source: Gem5Launch,
    /// Retains the actual original stopped native and coordinator positions.
    pub boundary: Gem5Boundary,
    /// Retains all original native prefix receipts, including acknowledged entries.
    pub completed: Vec<Gem5Completion>,
    /// Names the original held native prefix, or no outstanding prefix.
    pub pending: Option<Id>,
    /// Names the most recently acknowledged original native prefix.
    pub last_acknowledged: Option<Id>,
    /// Retains the complete role-qualified original immutable artifact roster.
    pub artifacts: Vec<Gem5ArchiveArtifact>,
}

/// Authenticates complete historical source lineage under installed host policy.
///
/// Implementations belong to trusted installed host factories. They bind an
/// opaque authenticated archive source to the entire supplied native record,
/// including its original scope, cut, prefix/ACK ledger and artifact geometry.
/// Content references or caller-supplied expected values alone are insufficient.
pub trait Gem5ArchiveSourceVerifier {
    /// Verifies the signed original record and matching installed implementation.
    ///
    /// # Errors
    /// Refuses unsigned, changed, omitted, foreign or unsupported source state,
    /// substituted capture identities, and incompatible installed implementations.
    fn verify_archive(&self, source: &Gem5ArchiveImport) -> Result<(), ProviderError>;
}

impl Gem5CapturedImage {
    /// Imports an authenticated historical seal without creating live authority.
    ///
    /// Files must already reside in owned canonical private archive storage. The
    /// installed verifier must authenticate the complete original record, not
    /// merely its syntax. Fresh native restoration, unchanged-cut live closure,
    /// and execution qualification remain mandatory separate steps.
    ///
    /// # Errors
    /// Rejects unverified source lineage, invalid original continuation geometry,
    /// unsafe names, duplicate or missing artifacts, altered bytes, linked files,
    /// mismatched installed assets, and finite inventory or receipt limits.
    pub fn import_authenticated_archive(
        source: Gem5ArchiveImport,
        verifier: &dyn Gem5ArchiveSourceVerifier,
    ) -> Result<Self, ProviderError> {
        validate_archive(&source)?;
        verifier.verify_archive(&source)?;
        // The verifier can perform installed-policy I/O. Recheck owned bytes
        // afterwards so qualification never seals a changed materialization.
        validate_archive_files(&source)?;

        let mut image_files = Vec::new();
        let mut resource_files = Vec::new();
        for file in source.artifacts {
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
        Ok(Self {
            capture: source.capture,
            source: source.source,
            boundary: source.boundary,
            completed: source
                .completed
                .into_iter()
                .map(|entry| (entry.operation.clone(), entry))
                .collect(),
            pending: source.pending,
            last_acknowledged: source.last_acknowledged,
            image_files,
            resource_files,
        })
    }
}

fn validate_archive(source: &Gem5ArchiveImport) -> Result<(), ProviderError> {
    source.capture.validate()?;
    source.source.owner.validate()?;
    source.source.incarnation.validate()?;
    if source.source.generation.get() == 0
        || source.source.timeout.is_zero()
        || !source.source.resource_root.is_absolute()
        || source.source.process_images.is_none()
        || !matches!(source.source.guest_isa.as_str(), "x86_64" | "aarch64")
        || source.completed.len() > MAX_PREFIXES
        || source.artifacts.is_empty()
        || source.artifacts.len() > MAX_FILES
    {
        return Err(ProviderError::Frame("invalid gem5 historical source scope"));
    }
    validate_boundary(&source.boundary)?;
    let mut original_ids = BTreeSet::new();
    let mut bytes = 0usize;
    for receipt in &source.completed {
        if !original_ids.insert(receipt.operation.clone()) {
            return Err(ProviderError::Conflict("duplicate gem5 historical prefix"));
        }
        validate_boundary(&receipt.before)?;
        validate_boundary(&receipt.after)?;
        if receipt.original.kind != "run"
            || receipt.original.maximum_events.get() == 0
            || receipt.original.maximum_events.get() > 10_000_000
        {
            return Err(ProviderError::Frame("invalid gem5 historical prefix scope"));
        }
        super::super::process::validate_completion(&receipt.before, &receipt.original, receipt)?;
        let length = encoded_length(receipt)?;
        bytes = bytes
            .checked_add(length)
            .filter(|total| *total <= MAX_RECEIPT_BYTES)
            .ok_or(ProviderError::ResourceExhausted(
                "gem5 historical prefix receipts",
            ))?;
        if length > super::super::GEM5_NATIVE_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "gem5 historical native frame",
            ));
        }
    }
    let mut ordered: Vec<_> = source.completed.iter().collect();
    ordered.sort_by(|left, right| {
        (
            left.before.ordinal,
            left.before.logical_position,
            left.after.ordinal,
            left.after.logical_position,
            &left.operation,
        )
            .cmp(&(
                right.before.ordinal,
                right.before.logical_position,
                right.after.ordinal,
                right.after.logical_position,
                &right.operation,
            ))
    });
    let mut previous = None;
    let mut output_sequence = 0u64;
    for receipt in &ordered {
        if previous.is_some_and(|old: &Gem5Completion| old.after != receipt.before) {
            return Err(ProviderError::Correlation(
                "gem5 historical continuation has a gap",
            ));
        }
        for publication in &receipt.publications {
            output_sequence =
                output_sequence
                    .checked_add(1)
                    .ok_or(ProviderError::ResourceExhausted(
                        "gem5 historical output sequence",
                    ))?;
            if publication.output_id.get() != output_sequence {
                return Err(ProviderError::Correlation(
                    "gem5 historical output FIFO differs",
                ));
            }
        }
        previous = Some(*receipt);
    }
    if let Some(last) = ordered.last() {
        if last.after != source.boundary {
            return Err(ProviderError::Correlation(
                "gem5 historical stopped cut differs",
            ));
        }
    } else if source.pending.is_some()
        || source.last_acknowledged.is_some()
        || source.boundary.ordinal.get() != 0
    {
        return Err(ProviderError::Correlation(
            "gem5 historical prefix ledger omitted",
        ));
    }
    if source.pending.as_ref().is_some_and(|pending| {
        source
            .completed
            .iter()
            .find(|receipt| &receipt.operation == pending)
            .is_none_or(|receipt| receipt.after != source.boundary)
    }) {
        return Err(ProviderError::Correlation(
            "gem5 pending prefix differs from saved cut",
        ));
    }
    if source
        .pending
        .as_ref()
        .is_some_and(|pending| !original_ids.contains(pending))
        || source
            .last_acknowledged
            .as_ref()
            .is_some_and(|ack| !original_ids.contains(ack))
        || (source.pending.is_some() && source.pending == source.last_acknowledged)
    {
        return Err(ProviderError::Correlation(
            "gem5 historical ACK inventory differs",
        ));
    }
    validate_archive_files(source)
}

fn validate_boundary(boundary: &Gem5Boundary) -> Result<(), ProviderError> {
    encoded_length(boundary)?;
    boundary.logical_position.validate()?;
    if boundary.tick_ordinal > boundary.ordinal
        || (boundary.has_next_event && boundary.next_tick < boundary.tick)
        || boundary.logical_position.time_ps < boundary.tick
        || boundary
            .inventory
            .get("native_tick")
            .and_then(serde_json::Value::as_str)
            != Some(boundary.tick.get().to_string().as_str())
    {
        return Err(ProviderError::Correlation(
            "invalid gem5 historical native boundary",
        ));
    }
    Ok(())
}

fn validate_archive_files(source: &Gem5ArchiveImport) -> Result<(), ProviderError> {
    let mut names = BTreeSet::new();
    let mut total = 0;
    let mut primary = 0usize;
    for file in &source.artifacts {
        if file.relative.as_os_str().is_empty()
            || file.relative.as_os_str().len() > 4096
            || file
                .relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || !names.insert((
                matches!(file.role, Gem5CapturedArtifactRole::Image),
                file.relative.clone(),
            ))
        {
            return Err(ProviderError::Frame(
                "invalid gem5 historical artifact geometry",
            ));
        }
        let parent = file
            .artifact
            .path
            .parent()
            .ok_or(ProviderError::Frame("gem5 archive file has no parent"))?;
        validate_private_directory(parent)?;
        let limit = match file.role {
            Gem5CapturedArtifactRole::Image => {
                primary += usize::from(
                    file.relative
                        .extension()
                        .is_some_and(|extension| extension == "dmtcp"),
                );
                GEM5_MAX_IMAGE_BYTES
            }
            Gem5CapturedArtifactRole::Resource => MAX_FILE_BYTES,
        };
        let measured = measure_file_with_limit(&file.artifact.path, limit)?;
        if measured != file.artifact.content {
            return Err(ProviderError::Correlation(
                "gem5 imported artifact bytes changed",
            ));
        }
        total = add_length(total, measured.length)?;
    }
    if primary != 1 {
        return Err(ProviderError::Correlation(
            "gem5 imported primary image omitted or duplicated",
        ));
    }
    for (name, asset) in [
        ("native-owner.py", &source.source.owner_script),
        ("native-owner-model.py", &source.source.model_script),
        ("guest.elf", &source.source.guest),
    ] {
        if !source.artifacts.iter().any(|file| {
            file.role == Gem5CapturedArtifactRole::Resource
                && file.relative == Path::new(name)
                && file.artifact.content == asset.content
        }) {
            return Err(ProviderError::Correlation(
                "gem5 historical guest/controller asset omitted",
            ));
        }
    }
    let tools = source
        .source
        .process_images
        .as_ref()
        .ok_or(ProviderError::Frame("gem5 image tools omitted"))?;
    for asset in [
        &source.source.executable,
        &source.source.owner_script,
        &source.source.model_script,
        &source.source.guest,
        &tools.launcher,
        &tools.restarter,
        &tools.reconstruction_executable,
        &tools.resource_helper,
    ] {
        if measure_file(&asset.path)? != asset.content {
            return Err(ProviderError::Correlation(
                "gem5 imported installed asset differs",
            ));
        }
    }
    Ok(())
}

// Measures serde wire extent without allocating a receipt-sized temporary.
fn encoded_length(value: &impl serde::Serialize) -> Result<usize, ProviderError> {
    struct Counter {
        length: usize,
        exhausted: bool,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match self.length.checked_add(bytes.len()) {
                Some(length) if length <= super::super::GEM5_NATIVE_FRAME_BYTES => {
                    self.length = length;
                    Ok(bytes.len())
                }
                _ => {
                    self.exhausted = true;
                    Err(std::io::Error::other("historical native frame limit"))
                }
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        length: 0,
        exhausted: false,
    };
    if let Err(error) = serde_json::to_writer(&mut counter, value) {
        return Err(if counter.exhausted {
            ProviderError::ResourceExhausted("gem5 historical native frame")
        } else {
            crucible_node_contract::ContractError::from(error).into()
        });
    }
    Ok(counter.length)
}

#[cfg(test)]
#[path = "archive_import_tests.rs"]
mod tests;

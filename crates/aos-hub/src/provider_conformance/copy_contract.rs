//! Read-only projection of complete retained versionless copy experiments.
//!
//! The projection correlates the actual report with its private journal and
//! requires every current probe phase. It supplies observed transport facts;
//! it installs no runtime profile, cohort, credential or provider permission.
//!
//! ```text
//! {version: 1, report_sha256, original_sha256, executable_sha256,
//!  endpoint, bucket, private_staging_prefix,
//!  private_policy: DirectPrivateStagePolicyRef, policy_review_sha256,
//!  provider_contract: {contract_id, evidence_digest,
//!    versioned_conditional_range_read: false,
//!    versioned_multipart_complete: false, maximum_copy_read_range_bytes: "8388608",
//!    private_incomplete_upload: true,
//!    completed_upload_rejects_late_parts: true, abort_closes_upload_id: true,
//!    upload_part_checksum_enforced: true, versioned_empty_put: false,
//!    protected_versionless: {strong_conditional_range_read: true,
//!                            positive_multipart_complete: true}}}
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{ensure, Context as _, Result};
use serde_json::{json, Value};

use super::journal::{digest, read, write_new};
use super::model::{Intent, Observation, Phase, Report, ResponseCommitment, ResultKind};

fn same_document(left: &impl serde::Serialize, right: &impl serde::Serialize) -> Result<bool> {
    Ok(serde_json::to_vec(left)? == serde_json::to_vec(right)?)
}

fn phase_observations<'a>(
    report: &'a Report,
    phase: Phase,
    count: usize,
    positive: bool,
    statuses: &[u16],
) -> Result<Vec<&'a Observation>> {
    let observations = report
        .observations
        .iter()
        .filter(|value| value.phase == phase)
        .collect::<Vec<_>>();
    ensure!(
        observations.len() == count
            && observations
                .iter()
                .all(
                    |value| matches!(value.result, ResultKind::Positive) == positive
                        && statuses.contains(&value.status)
                ),
        "copy contract lacks a complete exact provider phase"
    );
    Ok(observations)
}

fn validate(report: &Report, journal: &Path) -> Result<u64> {
    ensure!(
        report.original.version == 1
            && report.original.source_kind == "operator_core_s3surface_http"
            && report.original.executable_sha256 == super::journal::executable_digest()?
            && report.original.package_version == env!("CARGO_PKG_VERSION")
            && report.cleanup_state == "retained_known_objects"
            && !report.observations.is_empty()
            && report.observations.len() < 96,
        "copy contract source or complete report differs"
    );
    let original_bytes = read(&journal.join("original.json"), 64 * 1024, true)?;
    let original: super::model::Original = serde_json::from_slice(&original_bytes)?;
    ensure!(
        same_document(&original, &report.original)?,
        "copy report original differs from journal"
    );
    ensure!(
        serde_json::to_vec(&original)? == original_bytes,
        "copy journal original is noncanonical"
    );
    let status: Value = serde_json::from_str(&super::journal::status(journal)?)?;
    ensure!(
        status["unknown_operation_ids"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && status["observations"] == serde_json::to_value(&report.observations)?,
        "copy journal is partial, unknown or differs from report"
    );

    let mut operation_ids = BTreeSet::new();
    let mut maximum_read_range = 0;
    for (index, observed) in report.observations.iter().enumerate() {
        let intent: Intent = serde_json::from_slice(&read(
            &journal.join(format!("{index:03}.intent.json")),
            64 * 1024,
            true,
        )?)?;
        let response: ResponseCommitment = serde_json::from_slice(&read(
            &journal.join(format!("{index:03}.response.json")),
            64 * 1024,
            true,
        )?)?;
        ensure!(
            operation_ids.insert(&observed.operation_id)
                && intent.operation_id == observed.operation_id
                && intent.phase == observed.phase
                && response.operation_id == observed.operation_id
                && response.phase == observed.phase
                && response.status == observed.status
                && response.response_bytes == observed.response_bytes
                && response.response_sha256 == observed.response_sha256
                && response.provider_request_id == observed.provider_request_id,
            "copy phase intent/received reply/observation correlation differs"
        );
        if observed.phase == Phase::SourceRangeRead {
            ensure!(
                observed.status == 206
                    && intent.key
                        == report
                            .source
                            .key
                            .strip_prefix(&format!("{}/", report.original.private_staging_prefix))
                            .context("source range escaped selected scope")?
                    && intent.source_etag.as_deref() == Some(&report.source.etag)
                    && intent.first_byte.is_some()
                    && intent.size > 0
                    && observed.actual_size == Some(intent.size)
                    && observed.actual_sha256 == intent.expected_sha256,
                "copy report range lacks exact conditional content geometry"
            );
            // This bound describes bytes actually read under the retained condition.
            // Multipart writer geometry is not evidence of source Read capability.
            maximum_read_range = maximum_read_range.max(intent.size);
        }
        if observed.phase == Phase::RejectWrongConditionalRange {
            ensure!(
                intent
                    .source_etag
                    .as_ref()
                    .is_some_and(|tag| tag != &report.source.etag)
                    && intent.first_byte == Some(0)
                    && intent.size == 65536,
                "copy negative range lacks a distinct exact condition"
            );
        }
    }
    // Refuse gaps or trailing unknown effects instead of accepting only a
    // completed prefix from a larger retained journal.
    for entry in std::fs::read_dir(journal)? {
        let name = entry?.file_name();
        let name = name.to_str().context("non-text copy journal entry")?;
        if name == "original.json" {
            continue;
        }
        let (index, kind) = name.split_once('.').context("foreign copy journal entry")?;
        let index: usize = index.parse()?;
        ensure!(
            index < report.observations.len()
                && matches!(kind, "intent.json" | "response.json" | "observation.json"),
            "copy journal contains a gap, unknown tail or foreign entry"
        );
    }

    let mut expected_observations = 0;
    for (phase, count) in [
        (Phase::CreateSource, 1),
        (Phase::UploadSourcePart, 2),
        (Phase::CompleteSource, 1),
        (Phase::SourceHead, 1),
        (Phase::SourceFullRead, 1),
        (Phase::SourceRangeRead, 2),
        (Phase::CreateStreamedCopy, 1),
        (Phase::UploadStreamedCopyPart, 2),
        (Phase::CompleteStreamedCopy, 1),
        (Phase::StreamedCopyHead, 1),
        (Phase::StreamedCopyFullRead, 1),
        (Phase::CreateProviderCopy, 1),
        (Phase::ProviderCopyPart, 2),
        (Phase::CompleteProviderCopy, 1),
        (Phase::ProviderCopyHead, 1),
        (Phase::ProviderCopyFullRead, 1),
        (Phase::SourceFinalRead, 1),
        (Phase::CreateAbort, 1),
        (Phase::Abort, 1),
    ] {
        phase_observations(report, phase, count, true, &[200, 204, 206])?;
        expected_observations += count;
    }
    for (phase, statuses, code) in [
        (Phase::RejectBadChecksum, &[400][..], "BadDigest"),
        (
            Phase::RejectWrongConditionalRange,
            &[412][..],
            "PreconditionFailed",
        ),
        (Phase::LatePartAfterComplete, &[404][..], "NoSuchUpload"),
        (Phase::LatePartAfterAbort, &[404][..], "NoSuchUpload"),
    ] {
        let observed = phase_observations(report, phase, 1, false, statuses)?;
        ensure!(
            observed[0]
                .error_code
                .as_deref()
                .is_some_and(|actual| actual == code
                    || (phase == Phase::RejectBadChecksum
                        && matches!(actual, "InvalidDigest" | "ChecksumMismatch"))),
            "copy contract negative provider code differs"
        );
        expected_observations += 1;
    }
    for phase in [Phase::AnonymousIncompleteRead, Phase::AnonymousRead] {
        phase_observations(report, phase, 1, false, &[401, 403, 404])?;
        expected_observations += 1;
    }
    ensure!(
        report.observations.len() == expected_observations,
        "copy report includes unrecognized phase population"
    );
    for object in [&report.source, &report.streamed_copy, &report.provider_copy] {
        ensure!(
            object.provider_version.is_none()
                && object.size == report.original.expected_size
                && object.sha256 == report.original.expected_sha256
                && object.key.starts_with(&format!(
                    "{}/.aos-direct-qualification/{}/",
                    report.original.private_staging_prefix, report.original.run_id
                )),
            "copy report is not exact versionless content in the selected private scope"
        );
        aos_hub_core::surface_write::strong_if_match_etag(&object.etag)?;
    }
    for phase in [
        Phase::SourceFullRead,
        Phase::StreamedCopyFullRead,
        Phase::ProviderCopyFullRead,
        Phase::SourceFinalRead,
    ] {
        let observed = phase_observations(report, phase, 1, true, &[200])?;
        ensure!(
            observed[0].actual_size == Some(report.original.expected_size)
                && observed[0].actual_sha256.as_deref() == Some(&report.original.expected_sha256),
            "copy report full read lacks actual size or SHA equality"
        );
    }
    ensure!(
        maximum_read_range > 0 && maximum_read_range <= 20 * 1024 * 1024,
        "copy observed source range exceeds the supported explicit bound"
    );
    Ok(maximum_read_range)
}

pub(super) fn project(report_file: &Path, journal: &Path, output: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(journal)?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0,
            "copy journal must have private owned custody"
        );
    }
    let bytes = read(report_file, 256 * 1024, true)?;
    let report: Report = serde_json::from_slice(&bytes)?;
    ensure!(
        serde_json::to_vec(&report)? == bytes,
        "copy report is noncanonical"
    );
    let maximum_read_range = validate(&report, journal)?;
    let parent = output
        .parent()
        .context("copy contract output parent absent")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0,
            "copy contract output must have private owned custody"
        );
    }
    #[cfg(not(unix))]
    anyhow::bail!("copy contract private output requires Unix custody");
    let report_sha256 = digest(&bytes);
    let selected = json!({
        "version": 1, "report_sha256": report_sha256,
        "original_sha256": digest(&serde_json::to_vec(&report.original)?),
        "executable_sha256": report.original.executable_sha256,
        "endpoint": report.original.endpoint, "bucket": report.original.bucket,
        "private_staging_prefix": report.original.private_staging_prefix,
        "private_policy": report.original.policy,
        "policy_review_sha256": report.original.policy_review_sha256,
        "provider_contract": {
            "contract_id": "aos.operator-s3.protected-copy.v1",
            "evidence_digest": report_sha256,
            "versioned_conditional_range_read": false, "versioned_multipart_complete": false,
            "private_incomplete_upload": true, "completed_upload_rejects_late_parts": true,
            "abort_closes_upload_id": true, "upload_part_checksum_enforced": true,
            "versioned_empty_put": false,
            "maximum_copy_read_range_bytes": maximum_read_range.to_string(),
            "protected_versionless": {"strong_conditional_range_read": true,
                "positive_multipart_complete": true}
        }
    });
    write_new(output, &selected)
}

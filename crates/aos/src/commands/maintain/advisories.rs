//! Local CVE/advisory projection from a verified, explicitly selected evidence bundle.
//!
//! Reproduction verifies semantic agreement with the supplied evidence. It does
//! not grant that evidence independent source authority, import it into a Hub or
//! advance current package status. This read has no provider network effects.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{Result, ensure};
use aos_assessment::bundle::{AssessmentBundleV1, BUNDLE_MANIFEST_V1};
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::advisories::{AdvisoryQueryV1, lookup_assessment};
use aos_assessment_runtime::ports::Clock;
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};

use crate::cli::{Cli, MaintainAdvisoryArgs, MaintainArgs};

/// Reads the same historical advisory projection rendered by the hosted CLI.
///
/// # Errors
/// Returns an error for unsafe or excessive input files, malformed/tampered
/// evidence, changed bundle scope, absent subject or excessive response size.
pub fn run_advisory(
    cli: &Cli,
    args: &MaintainArgs,
    command: &MaintainAdvisoryArgs,
    printer: &Printer,
) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&command.evidence_input)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16 * 1024 * 1024,
        "assessment evidence input must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let bundle = AssessmentBundleV1::from_slice(&bytes)?;
    let manifest_digest = Sha256Digest::of_canonical(BUNDLE_MANIFEST_V1, &bundle.manifest)?;
    let resource_scope = format!("local-bundle-{}", manifest_digest.hex());
    ensure!(
        command
            .resource_scope
            .as_ref()
            .is_none_or(|scope| scope == &resource_scope),
        "advisory evidence bundle changed; restart pagination"
    );
    let query = AdvisoryQueryV1 {
        schema: "aos.assessment-advisory-query/v1".into(),
        advisory_id: command.advisory_id.clone(),
        resource_scope: command.resource_scope.clone(),
        assessment_digest: Some(bundle.assessment.digest()?),
        subject_ref: command.subject_ref.clone(),
        after_record: command
            .after_record
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()?,
        limit: command.limit,
    };
    let page = lookup_assessment(
        &query,
        &bundle.input,
        &bundle.data,
        &bundle.assessment,
        resource_scope,
        PhysicalClock.now()?,
    )?;
    if cli.json || args.jsonl || printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "schema_version":"aos.assessment-cli/v1", "kind":"assessment-advisory",
            "execution":{"mode":"local", "context":"bundle-reproduction", "manifest_digest":manifest_digest},
            "data":page,
        }));
    } else {
        printer.info("Local evidence reproduction; independent source authority is not established by reproduction.");
        crate::commands::assessment_presentation::render_advisory(printer, &page);
    }
    Ok(())
}

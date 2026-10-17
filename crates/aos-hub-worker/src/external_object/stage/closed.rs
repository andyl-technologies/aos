//! Exact retained closure selection and conditional provider response checks.
//!
//! A guard stamp identifies the journal incarnation. An S3 version is retained
//! only from the actual positive closure response; a versionless receipt selects
//! the current object by its original strong ETag, not a historical version.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::external_object::stage::{
    ExternalStageOperation as Operation, ExternalStageOutcome as Outcome,
};

use super::super::protocol::digest;
use super::protocol::{Receipt, Turn};

/// Retains a bounded actual response version without inventing a null version.
pub(super) fn response_version(value: Option<&str>) -> Result<Option<String>> {
    match value {
        None | Some("null") => Ok(None),
        Some(value) => {
            ensure!(
                aos_hub_core::storage_work::valid_provider_version(value),
                "stage provider version malformed"
            );
            Ok(Some(value.to_owned()))
        }
    }
}

/// Checks the exact positive closure returned by the addressed physical journal.
pub(super) fn validate_projection(turn: &Turn, closed: &Receipt) -> Result<()> {
    turn.intent.validate()?;
    closed.validate()?;
    let Operation::VerifyClosedStage {
        upload_id,
        close_receipt_digest,
    } = &turn.intent.operation
    else {
        anyhow::bail!("closure projection requires verification");
    };
    ensure!(
        closed.turn.intent.context == turn.intent.context
            && closed.turn.intent.scope()? == turn.intent.scope()?
            && closed.turn.expected_incarnation == turn.expected_incarnation
            && digest(closed)? == *close_receipt_digest,
        "verification closure projection changed"
    );
    ensure!(
        matches!(
            (&closed.turn.intent.operation, &closed.outcome),
            (Operation::CompleteStage { .. }, Outcome::Closed { .. })
                | (Operation::CreateStage, Outcome::EmptyClosed { .. })
        ),
        "verification requires a positive stage closure"
    );
    let expected_upload = match &closed.turn.intent.operation {
        Operation::CompleteStage { upload_id, .. } => Some(upload_id),
        Operation::CreateStage => None,
        _ => anyhow::bail!("verification closure operation differs"),
    };
    ensure!(
        upload_id.as_ref() == expected_upload,
        "verification provider UploadId changed"
    );
    closure_etag(closed)?;
    Ok(())
}

pub(super) fn closure_etag(closed: &Receipt) -> Result<String> {
    let etag = match &closed.outcome {
        Outcome::Closed { etag, .. } | Outcome::EmptyClosed { etag, .. } => etag,
        _ => anyhow::bail!("stage source is not positively closed"),
    };
    aos_hub_core::surface_write::strong_if_match_etag(etag)
}

/// Checks acknowledged response identity before consuming any object bytes.
pub(super) fn validate_response(
    closed: &Receipt,
    etag: Option<&str>,
    version: Option<&str>,
) -> Result<()> {
    closed.validate()?;
    let actual = aos_hub_core::surface_write::strong_if_match_etag(
        etag.ok_or_else(|| anyhow::anyhow!("verified source ETag absent"))?,
    )?;
    ensure!(
        actual == closure_etag(closed)?,
        "verified source ETag changed"
    );
    let actual_version = response_version(version)?;
    if let Some(expected) = &closed.provider_version {
        ensure!(
            actual_version.as_ref() == Some(expected),
            "verified source provider version changed"
        );
    }
    Ok(())
}

/// Holds the unpolled body owner across every response identity refusal.
pub(super) fn select_response<R>(
    reader: R,
    closed: &Receipt,
    status: u16,
    etag: Option<&str>,
    version: Option<&str>,
) -> Result<R> {
    ensure!(status == 200, "conditional verification not acknowledged");
    validate_response(closed, etag, version)?;
    Ok(reader)
}

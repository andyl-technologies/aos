//! Canonical scalar/document checks for one joined retained-session snapshot.
//!
//! Optional child rows are selected by their non-null session keys, so a
//! malformed document cannot masquerade as an absent intent or receipt.

use super::super::*;

/// Retains the original per-document column order from one joined session read.
pub(super) struct RetainedDocuments {
    pub(super) complete: Option<Row>,
    pub(super) abort: Option<Row>,
    pub(super) stage: Option<Row>,
    pub(super) completion: Option<Row>,
}

impl RetainedDocuments {
    /// Selects optional documents by their independent non-null session keys.
    ///
    /// # Errors
    /// Refuses malformed presence markers or an incomplete joined projection.
    pub(super) fn from_joined(row: &Row) -> Result<Self> {
        // Document slices preserve the former readers' column order. The final
        // four columns mark row presence independently of document validity.
        Ok(Self {
            complete: optional_row(row, 27, 5, 52)?,
            abort: optional_row(row, 32, 8, 53)?,
            stage: optional_row(row, 40, 5, 54)?,
            completion: optional_row(row, 45, 7, 55)?,
        })
    }
}

fn optional_row(row: &Row, start: usize, count: usize, marker: usize) -> Result<Option<Row>> {
    if row.get::<Option<String>>(marker)?.is_none() {
        return Ok(None);
    }
    let values = (start..start + count)
        .map(|index| {
            row.value(index)
                .cloned()
                .context("direct retained projection absent")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(Row::new(values)))
}

/// Checks the retained Complete document against its duplicated SQL scalars.
///
/// # Errors
/// Refuses malformed originals, changed scalar pins or invalid admission bindings.
pub(super) fn complete(
    row: Option<&Row>,
    deployment: &str,
    admission: &DirectUploadAdmission,
) -> Result<Option<DirectCompleteRequest>> {
    let Some(row) = row else {
        return Ok(None);
    };
    let intent: DirectCompleteRequest = document(&row.get::<String>(3)?)?;
    validate_complete(admission, &intent, deployment)?;
    ensure!(
        row.get::<String>(0)? == intent.operation_id
            && row.get::<i64>(1)? == integer(intent.expected_resource_version)?
            && row.get::<String>(2)? == intent.fingerprint()?
            && row.get::<i64>(4)? > 0,
        "retained direct complete scalar mismatch"
    );
    Ok(Some(intent))
}

/// Checks the retained Abort original and its optional terminal receipt.
///
/// # Errors
/// Refuses changed ownership, operation pins or inconsistent terminal progress.
pub(super) fn abort(
    row: Option<&Row>,
    admission: &DirectUploadAdmission,
) -> Result<Option<DirectAbortRequest>> {
    let Some(row) = row else {
        return Ok(None);
    };
    let intent: DirectAbortRequest = document(&row.get::<String>(3)?)?;
    intent.session.validate()?;
    ensure!(
        intent.session.session_id == admission.session_id
            && intent.session.logical_fingerprint == admission.logical_fingerprint
            && valid_direct_digest(&intent.operation_id)
            && integer(intent.expected_resource_version)? > 0
            && row.get::<String>(0)? == intent.operation_id
            && row.get::<i64>(1)? == integer(intent.expected_resource_version)?
            && row.get::<String>(2)? == digest(&intent)?
            && row.get::<i64>(4)? > 0,
        "retained direct abort original mismatch"
    );
    let receipt: Option<String> = row.get(5)?;
    let settled: Option<i64> = row.get(6)?;
    let admitted: i64 = row.get(4)?;
    ensure!(
        receipt.is_some() == settled.is_some()
            && receipt.is_some() == (row.get::<String>(7)? == "aborted")
            && receipt
                .as_ref()
                .is_none_or(|digest| valid_direct_digest(digest))
            && settled.is_none_or(|time| time >= admitted),
        "retained direct abort terminal receipt changed"
    );
    Ok(Some(intent))
}

/// Checks the verified stage receipt against the original admission.
///
/// # Errors
/// Refuses malformed evidence, changed scalar pins or unrelated originals.
pub(super) fn stage(
    row: Option<&Row>,
    deployment: &str,
    admission: &DirectUploadAdmission,
) -> Result<Option<DirectVerifiedStageEvidence>> {
    let Some(row) = row else {
        return Ok(None);
    };
    let evidence: DirectVerifiedStageEvidence = document(&row.get::<String>(3)?)?;
    evidence.validate_against(admission, deployment)?;
    ensure!(
        row.get::<String>(0)? == evidence.operation_id
            && row.get::<String>(1)? == evidence.logical_fingerprint
            && row.get::<String>(2)? == digest(&evidence)?
            && row.get::<i64>(4)? > 0,
        "retained direct stage scalar mismatch"
    );
    Ok(Some(evidence))
}

/// Checks the terminal completion receipt against the original admission.
///
/// # Errors
/// Refuses malformed evidence, changed scalar pins or invalid terminal progress.
pub(super) fn completion(
    row: Option<&Row>,
    deployment: &str,
    admission: &DirectUploadAdmission,
) -> Result<Option<DirectCompletionEvidence>> {
    let Some(row) = row else {
        return Ok(None);
    };
    let evidence: DirectCompletionEvidence = document(&row.get::<String>(3)?)?;
    evidence.validate_against(admission, deployment)?;
    ensure!(
        row.get::<String>(0)? == evidence.operation_id
            && row.get::<String>(1)? == evidence.logical_fingerprint
            && row.get::<String>(2)? == digest(&evidence)?
            && row.get::<i64>(4)? > 0
            && row.get::<i64>(5)? > 1,
        "retained direct completion scalar mismatch"
    );
    Ok(Some(evidence))
}

/// Checks final guard originals and terminal progress in the selected snapshot.
///
/// # Errors
/// Refuses missing receipts, changed guard bindings or mismatched committed progress.
pub(super) fn final_guards(
    row: Option<&Row>,
    session: &Row,
    deployment: &str,
    admission: &DirectUploadAdmission,
    complete: Option<&DirectCompleteRequest>,
    evidence: Option<&DirectCompletionEvidence>,
) -> Result<Vec<DirectFinalGuardRecord>> {
    let Some(evidence) = evidence else {
        return Ok(Vec::new());
    };
    let complete = complete.context("direct final receipt Complete original absent")?;
    let row = row.context("direct final receipts absent")?;
    let guards: Vec<DirectFinalGuardRecord> = document(&row.get::<String>(6)?)?;
    validate_final_guards(admission, complete, evidence, &guards, deployment)?;
    ensure!(
        session.get::<String>(21)? == "committed"
            && session.get::<Option<i64>>(26)? == Some(row.get::<i64>(4)?)
            && session.get::<i64>(25)? == row.get::<i64>(5)?,
        "direct terminal receipt resulting progress changed"
    );
    Ok(guards)
}

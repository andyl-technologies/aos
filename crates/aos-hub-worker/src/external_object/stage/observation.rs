//! Private do-e2e observations of genuine internal verification work.
//!
//! Prepared requests are not dispatch receipts. These records cannot replace
//! current Native authorization, physical provider evidence or complete windows.
//!
//! Private records use the following closed tagged shapes. Turn, Receipt and
//! floor fields retain their existing wire formats:
//!
//! ```text
//! {kind: "started", projection: Projection}
//! {kind: "prepared", prepared: {projection, turn, closure, floor,
//!   directPermissionExpiresAt, providerBucket, providerFullKey, providerUrl,
//!   requiredHeaders}}
//! {kind: "terminal", version: 1, attemptId, status, result}
//! {kind: "incomplete", version: 1, attemptId, reason}
//! ```
//! Terminal status is positive, error or dropped; only positive carries a result.

use std::cell::Cell;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectRequiredHeader, WireInteger};
use aos_hub_core::storage_authority::external_object::stage::ExternalStageResult;
use aos_hub_core::storage_authority::lease::EpochLeaseFloor;
use serde::{Deserialize, Serialize};

use super::{
    closed,
    protocol::{Receipt, Turn},
};
use crate::direct_upload::verification_observation::{
    bytes_digest, emit, Projection, MAX_RECORD_BYTES,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Prepared {
    pub projection: Projection,
    pub turn: Turn,
    pub closure: Receipt,
    pub floor: EpochLeaseFloor,
    pub direct_permission_expires_at: Option<WireInteger>,
    pub provider_bucket: String,
    pub provider_full_key: String,
    pub provider_url: String,
    pub required_headers: Vec<DirectRequiredHeader>,
}

impl Prepared {
    pub(super) fn validate(&self) -> Result<()> {
        self.projection.validate()?;
        let work = &self.projection.work;
        self.turn.intent.validate()?;
        closed::validate_projection(&self.turn, &self.closure)?;
        ensure!(
            self.turn.intent.operation_id == work.operation_id
                && self.turn.intent.context == work.context
                && self.turn.intent.operation == work.operation
                && self.closure.result()? == self.projection.job.closed_result
                && self.provider_full_key == work.context.stage_key()?
                && self.floor.full_key == self.provider_full_key,
            "prepared verification changed actual work or closure"
        );
        let placement = work.context.placement.public_ref(&work.deployment_id)?;
        let manifest = self
            .projection
            .job
            .complete
            .manifests
            .iter()
            .find(|manifest| manifest.placement == placement)
            .ok_or_else(|| anyhow::anyhow!("selected Complete manifest absent"))?;
        ensure!(
            matches!(&self.closure.turn.intent.operation,
            aos_hub_core::storage_authority::external_object::stage::ExternalStageOperation::CompleteStage {
                manifest: retained, .. } if retained == manifest),
            "closed stage differs from actual Complete manifest"
        );
        let url = url::Url::parse(&self.provider_url)?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && self.provider_url.len() <= 8192
                && url.path() == format!("/{}/{}", self.provider_bucket, self.provider_full_key),
            "prepared provider target differs"
        );
        let query = url.query_pairs().collect::<Vec<_>>();
        let one = |name: &str| -> Result<Option<String>> {
            let values = query
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.to_string())
                .collect::<Vec<_>>();
            ensure!(values.len() <= 1, "prepared signing query repeats a field");
            Ok(values.into_iter().next())
        };
        let signed = one("X-Amz-SignedHeaders")?
            .ok_or_else(|| anyhow::anyhow!("prepared signed headers absent"))?;
        ensure!(
            one("X-Amz-Algorithm")?.as_deref() == Some("AWS4-HMAC-SHA256")
                && signed.split(';').any(|name| name == "host")
                && signed.split(';').any(|name| name == "if-match")
                && one("versionId")? == self.closure.provider_version,
            "prepared conditional signing or version differs"
        );
        ensure!(
            self.required_headers.len() == 1
                && self.required_headers[0].name == "if-match"
                && self.required_headers[0].value == closed::closure_etag(&self.closure)?,
            "prepared strong If-Match differs"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TerminalStatus {
    Positive,
    Error,
    Dropped,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum Record {
    Started {
        projection: Projection,
    },
    Prepared {
        prepared: Prepared,
    },
    Terminal {
        version: u32,
        attempt_id: String,
        status: TerminalStatus,
        result: Option<ExternalStageResult>,
    },
    Incomplete {
        version: u32,
        attempt_id: String,
        reason: String,
    },
}

pub(crate) struct Attempt {
    projection: Projection,
    ended: Cell<bool>,
}

impl Attempt {
    pub(crate) fn new(projection: Projection) -> Result<Self> {
        projection.validate()?;
        ensure!(
            serde_json::to_vec(&Record::Started {
                projection: projection.clone()
            })?
            .len()
                <= MAX_RECORD_BYTES,
            "verification snapshot exceeds bound"
        );
        emit(&Record::Started {
            projection: projection.clone(),
        });
        Ok(Self {
            projection,
            ended: Cell::new(false),
        })
    }

    pub(super) fn prepared(
        &self,
        turn: &Turn,
        closure: &Receipt,
        floor: &EpochLeaseFloor,
        direct_permission_expires_at: Option<WireInteger>,
        provider_bucket: &str,
        provider_full_key: &str,
        provider_url: &str,
        required_headers: &[DirectRequiredHeader],
    ) {
        let prepared = Prepared {
            projection: self.projection.clone(),
            turn: turn.clone(),
            closure: closure.clone(),
            floor: floor.clone(),
            direct_permission_expires_at,
            provider_bucket: provider_bucket.into(),
            provider_full_key: provider_full_key.into(),
            provider_url: provider_url.into(),
            required_headers: required_headers.to_vec(),
        };
        if prepared.validate().is_ok() {
            emit(&Record::Prepared { prepared });
        } else {
            emit(&Record::Incomplete {
                version: 1,
                attempt_id: self.projection.attempt_id.clone(),
                reason: "prepared_projection_refused".into(),
            });
        }
    }

    pub(crate) fn finish(&self, result: &Result<ExternalStageResult>) {
        self.ended.set(true);
        emit(&Record::Terminal {
            version: 1,
            attempt_id: self.projection.attempt_id.clone(),
            status: if result.is_ok() {
                TerminalStatus::Positive
            } else {
                TerminalStatus::Error
            },
            result: result.as_ref().ok().cloned(),
        });
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.ended.get() {
            emit(&Record::Terminal {
                version: 1,
                attempt_id: self.projection.attempt_id.clone(),
                status: TerminalStatus::Dropped,
                result: None,
            });
        }
    }
}

/// Checks only canonical captured shapes; it grants no current authorization.
pub(super) fn decode_record(bytes: &[u8]) -> Result<Record> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RECORD_BYTES,
        "observation record exceeds bound"
    );
    let record: Record = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&record)? == bytes,
        "observation is not canonical"
    );
    match &record {
        Record::Started { projection } => projection.validate()?,
        Record::Prepared { prepared } => prepared.validate()?,
        Record::Terminal {
            version,
            attempt_id,
            status,
            result,
        } => {
            ensure!(
                *version == 1
                    && attempt_id.len() == 32
                    && attempt_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && (matches!(status, TerminalStatus::Positive) == result.is_some()),
                "observation terminal shape differs"
            );
        }
        Record::Incomplete { .. } => anyhow::bail!("observation records incomplete capture"),
    }
    Ok(record)
}

pub(super) fn projection_digest(projection: &Projection) -> Result<String> {
    Ok(bytes_digest(&serde_json::to_vec(projection)?))
}

/// One captured attempt, including explicit absence of preparation or terminal.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ObservedAttempt {
    projection: Projection,
    prepared: Option<Prepared>,
    terminal: Option<Record>,
    complete_observation: bool,
}

/// Decodes every bounded row without treating captured shapes as permission.
pub(super) fn decode_window(rows: &[Vec<u8>]) -> Result<Vec<ObservedAttempt>> {
    ensure!(
        !rows.is_empty() && rows.len() <= 32,
        "verification window bound differs"
    );
    let mut attempts = Vec::<ObservedAttempt>::new();
    for row in rows {
        match decode_record(row)? {
            Record::Started { projection } => {
                ensure!(
                    !attempts
                        .iter()
                        .any(|attempt| attempt.projection.attempt_id == projection.attempt_id),
                    "verification attempt identifier repeated"
                );
                attempts.push(ObservedAttempt {
                    projection,
                    prepared: None,
                    terminal: None,
                    complete_observation: false,
                });
            }
            Record::Prepared { prepared } => {
                let attempt = attempts
                    .iter_mut()
                    .find(|attempt| attempt.projection.attempt_id == prepared.projection.attempt_id)
                    .ok_or_else(|| anyhow::anyhow!("prepared attempt has no original"))?;
                ensure!(
                    attempt.prepared.is_none()
                        && attempt.terminal.is_none()
                        && projection_digest(&attempt.projection)?
                            == projection_digest(&prepared.projection)?,
                    "prepared attempt repeated or changed original"
                );
                attempt.prepared = Some(prepared);
            }
            terminal @ Record::Terminal { .. } => {
                let Record::Terminal {
                    attempt_id,
                    result,
                    status,
                    ..
                } = &terminal
                else {
                    unreachable!();
                };
                let attempt = attempts
                    .iter_mut()
                    .find(|attempt| attempt.projection.attempt_id == *attempt_id)
                    .ok_or_else(|| anyhow::anyhow!("terminal attempt has no original"))?;
                ensure!(attempt.terminal.is_none(), "terminal attempt repeated");
                if let Some(result) = result {
                    let work = &attempt.projection.work;
                    let intent = super::protocol::Intent {
                        operation_id: work.operation_id.clone(),
                        context: work.context.clone(),
                        operation: work.operation.clone(),
                    };
                    ensure!(
                        result.version == 1
                            && result.operation_id == work.operation_id
                            && result.intent_digest == intent.fingerprint()?
                            && crate::direct_upload::verification_observation::digest_string(
                                &result.receipt_digest
                            )
                            && matches!(&result.outcome,
                            aos_hub_core::storage_authority::external_object::stage::ExternalStageOutcome::Verified {
                                sha256, byte_size, close_receipt_digest, .. }
                            if sha256 == &work.context.intent.expected_sha256
                                && byte_size == &work.context.intent.byte_size
                                && close_receipt_digest == &attempt.projection.job.closed_result.receipt_digest),
                        "verification positive differs from original integrity checks"
                    );
                }
                attempt.complete_observation =
                    attempt.prepared.is_some() && !matches!(status, TerminalStatus::Dropped);
                attempt.terminal = Some(terminal);
            }
            Record::Incomplete { .. } => anyhow::bail!("incomplete verification capture"),
        }
    }
    Ok(attempts)
}

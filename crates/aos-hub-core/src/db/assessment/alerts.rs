//! Atomic attention admission, exact-episode acknowledgements and event replay.
//!
//! Assessment reducers operate only on the operation's selected subject/profile
//! pairs. Every prior revision is checked in the same transaction as profile
//! heads, preventing concurrent acknowledgement or refresh from losing audit.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use aos_assessment::input::{EvaluationData, ScanInputV1};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::alerts::{
    Acknowledgement, AssessmentAlertV1, AttentionState, IssueFamily,
};
use aos_assessment_runtime::events::{AssessmentEventPayload, AssessmentEventV1};
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};

use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

use super::scans::profile_name;

const ALERT_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 262_144,
    max_depth: 16,
    max_items: 16_384,
    max_string_bytes: 4096,
};

impl Database {
    /// Reads one exact retained issue after the service authorizes the resource.
    ///
    /// # Errors
    /// Returns an error for malformed retained state or unavailable persistence.
    pub async fn assessment_alert(
        &self,
        registry_id: i64,
        issue_key: Sha256Digest,
    ) -> Result<Option<AssessmentAlertV1>> {
        self.backend
            .query_opt(
                "SELECT alert_json FROM assessment_alerts WHERE registry_id = ?1 AND issue_key = ?2",
                &vals![@slice registry_id, issue_key.to_string()],
            )
            .await?
            .map(|row| decode_alert(&row.get::<Vec<u8>>(0)?))
            .transpose()
    }

    /// Reads a finite attention page in stable issue-key order.
    ///
    /// Resolved and retired records remain available as audit history. The
    /// service binds its opaque cursor to the authorized registry and filters.
    ///
    /// # Errors
    /// Returns an error for invalid page bounds, malformed records or persistence.
    pub async fn assessment_alert_page(
        &self,
        registry_id: i64,
        after_issue: &str,
        limit: u32,
    ) -> Result<Vec<AssessmentAlertV1>> {
        if !(1..=100).contains(&limit) {
            bail!("assessment alert page requires a limit between one and one hundred");
        }
        if !after_issue.is_empty() {
            Sha256Digest::parse(after_issue)?;
        }
        self.backend
            .query(
                "SELECT alert_json FROM assessment_alerts
                 WHERE registry_id = ?1 AND issue_key > ?2 ORDER BY issue_key LIMIT ?3",
                &vals![@slice registry_id, after_issue, limit],
            )
            .await?
            .iter()
            .map(|row| decode_alert(&row.get::<Vec<u8>>(0)?))
            .collect()
    }

    /// Acknowledges an authorized exact open episode without resolving it.
    ///
    /// The caller rechecks current acknowledgement permission. The transaction
    /// fences the resource authorization revision and complete alert revision;
    /// replay after a reopening cannot acknowledge its new episode.
    ///
    /// # Errors
    /// Returns an error for absent issues, stale authority/episode/revision,
    /// invalid acknowledgement history or unavailable persistence.
    pub async fn acknowledge_assessment_alert(
        &self,
        registry_id: i64,
        authorization_revision: u64,
        expected_sequence: u64,
        mut acknowledgement: Acknowledgement,
    ) -> Result<AssessmentAlertV1> {
        let previous = self
            .assessment_alert(registry_id, acknowledgement.issue_key)
            .await?
            .context("assessment issue is absent")?;
        acknowledgement.acknowledged_at = self.assessment_database_time().await?;
        let updated = previous.acknowledge(expected_sequence, acknowledgement)?;
        let mut statements = vec![Statement::new(
            "UPDATE assessment_alerts SET alert_json = ?4, transition_sequence = ?5, updated_at = ?6
             WHERE registry_id = ?1 AND issue_key = ?2 AND transition_sequence = ?3
               AND EXISTS(SELECT 1 FROM assessment_resources WHERE registry_id = ?1 AND authorization_revision = ?7)",
            vals![registry_id, updated.issue_key.to_string(), expected_sequence, encode_alert(&updated)?,
                updated.sequence, updated.updated_at.unix_seconds(), authorization_revision],
        ).expecting(1)];
        statements.extend(
            self.assessment_event_statements(
                registry_id,
                vec![AssessmentEventPayload::Acknowledged {
                    alert: Box::new(updated.clone()),
                }],
                &updated.updated_at,
            )
            .await?,
        );
        self.backend.checked_batch(&statements).await?;
        Ok(updated)
    }

    /// Reads bounded ordered event replay after an exclusive resource sequence.
    ///
    /// The service reauthorizes each watch poll and binds the replay cursor to
    /// the current tenant/resource. Sequence zero requests retained history.
    ///
    /// # Errors
    /// Returns an error for invalid cursor/limits, corrupt rows or persistence.
    pub async fn assessment_event_page(
        &self,
        registry_id: i64,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<AssessmentEventV1>> {
        if after_sequence > 9_007_199_254_740_991 || !(1..=100).contains(&limit) {
            bail!("assessment event replay exceeds portable page bounds");
        }
        self.backend
            .query(
                "SELECT payload_json FROM assessment_events
                 WHERE registry_id = ?1 AND event_sequence > ?2 ORDER BY event_sequence LIMIT ?3",
                &vals![@slice registry_id, after_sequence, limit],
            )
            .await?
            .iter()
            .map(|row| AssessmentEventV1::from_slice(&row.get::<Vec<u8>>(0)?))
            .collect()
    }

    pub(super) async fn assessment_attention_statements(
        &self,
        registry_id: i64,
        scan_id: &str,
        input: &ScanInputV1,
        data: &EvaluationData,
        assessment: &PackageAssessmentV1,
        now: &Timestamp,
    ) -> Result<Vec<CheckedStatement>> {
        let rows = self
            .backend
            .query(
                "SELECT alert.subject_ref, alert.alert_json FROM assessment_alerts AS alert
             JOIN assessment_scan_targets AS target ON target.subject_ref = alert.subject_ref
               AND target.profile = alert.profile
             WHERE alert.registry_id = ?1 AND target.scan_id = ?2
             ORDER BY alert.subject_ref, alert.issue_key LIMIT 100001",
                &vals![@slice registry_id, scan_id],
            )
            .await?;
        if rows.len() > 100_000 {
            bail!("assessment attention exceeds the admitted reduction limit");
        }
        let mut prior = BTreeMap::<String, Vec<AssessmentAlertV1>>::new();
        for row in rows {
            prior
                .entry(row.get(0)?)
                .or_default()
                .push(decode_alert(&row.get::<Vec<u8>>(1)?)?);
        }
        let digest = assessment.digest()?;
        let mut statements = Vec::new();
        let mut events = Vec::new();
        for projected in aos_assessment_runtime::attention::project(input, data, assessment)? {
            let existing = prior.remove(&projected.subject_ref).unwrap_or_default();
            for change in aos_assessment_runtime::alerts::reduce(
                &existing,
                &projected.issues,
                &projected.proofs,
                digest,
                now,
            )? {
                let alert = change.alert;
                let values = vals![
                    registry_id,
                    alert.issue_key.to_string(),
                    projected.subject_ref,
                    profile_name(alert.issue.profile),
                    alert.issue.context_digest.to_string(),
                    family_name(alert.issue.family),
                    state_name(alert.state),
                    alert.episode,
                    alert.sequence,
                    encode_alert(&alert)?,
                    digest.to_string(),
                    now.unix_seconds()
                ];
                if let Some(sequence) = change.previous_sequence {
                    let mut values = values;
                    values.extend(vals![sequence]);
                    statements.push(Statement::new(
                        "UPDATE assessment_alerts SET subject_ref = ?3, profile = ?4, context_digest = ?5,
                             family = ?6, attention_state = ?7, episode = ?8, transition_sequence = ?9,
                             alert_json = ?10, assessment_digest = ?11, updated_at = ?12
                         WHERE registry_id = ?1 AND issue_key = ?2 AND transition_sequence = ?13",
                        values,
                    ).expecting(1));
                } else {
                    statements.push(Statement::new(
                        "INSERT INTO assessment_alerts(registry_id, issue_key, subject_ref, profile, context_digest,
                             family, attention_state, episode, transition_sequence, alert_json, assessment_digest, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                        values,
                    ).expecting(1));
                }
                if let Some(transition) = change.event {
                    events.push(AssessmentEventPayload::Alert {
                        transition,
                        alert: Box::new(alert),
                    });
                }
            }
        }
        events.push(AssessmentEventPayload::ScanCompleted {
            scan_id: scan_id.into(),
            assessment_digest: digest,
        });
        statements.extend(
            self.assessment_event_statements(registry_id, events, now)
                .await?,
        );
        Ok(statements)
    }

    async fn assessment_event_statements(
        &self,
        registry_id: i64,
        payloads: Vec<AssessmentEventPayload>,
        now: &Timestamp,
    ) -> Result<Vec<CheckedStatement>> {
        // Initializing an empty allocator conveys no event authority. Allocation
        // itself shares the checked transaction with every event and mutation.
        self.backend
            .execute(
                "INSERT INTO assessment_event_sequences(registry_id, current_sequence)
             VALUES (?1, 0) ON CONFLICT(registry_id) DO NOTHING",
                &vals![@slice registry_id],
            )
            .await?;
        let sequence: u64 = self
            .backend
            .query_opt(
                "SELECT current_sequence FROM assessment_event_sequences WHERE registry_id = ?1",
                &vals![@slice registry_id],
            )
            .await?
            .context("assessment event sequence is absent")?
            .get(0)?;
        let last = sequence
            .checked_add(payloads.len() as u64)
            .filter(|value| *value <= 9_007_199_254_740_991)
            .context("assessment event sequence exhausted")?;
        let mut statements = vec![
            Statement::new(
                "UPDATE assessment_event_sequences SET current_sequence = ?3
             WHERE registry_id = ?1 AND current_sequence = ?2",
                vals![registry_id, sequence, last],
            )
            .expecting(1),
        ];
        for (offset, payload) in payloads.into_iter().enumerate() {
            let (kind, issue, episode, digest) = match &payload {
                AssessmentEventPayload::Alert { alert, .. } => (
                    "alert.transition",
                    Some(alert.issue_key.to_string()),
                    Some(alert.episode),
                    alert.assessment_digest,
                ),
                AssessmentEventPayload::Acknowledged { alert } => (
                    "alert.acknowledged",
                    Some(alert.issue_key.to_string()),
                    Some(alert.episode),
                    alert.assessment_digest,
                ),
                AssessmentEventPayload::ScanCompleted {
                    assessment_digest, ..
                } => ("scan.completed", None, None, *assessment_digest),
            };
            let event = AssessmentEventV1 {
                schema: "aos.assessment-event/v1".into(),
                event_id: uuid::Uuid::new_v4().simple().to_string(),
                sequence: sequence + offset as u64 + 1,
                occurred_at: now.clone(),
                payload,
            };
            statements.push(Statement::new(
                "INSERT INTO assessment_events(registry_id, event_sequence, event_id, event_kind,
                     issue_key, episode, assessment_digest, payload_json, occurred_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                vals![registry_id, event.sequence, event.event_id, kind, issue, episode, digest.to_string(),
                    event.to_bytes()?, now.unix_seconds()],
            ).expecting(1));
        }
        Ok(statements)
    }
}

fn decode_alert(bytes: &[u8]) -> Result<AssessmentAlertV1> {
    let value: serde_json::Value = ALERT_LIMITS.decode(bytes, "assessment alert")?;
    super::objects::reject_null(&value)?;
    let alert: AssessmentAlertV1 = serde_json::from_value(value)?;
    alert.validate()?;
    Ok(alert)
}

fn encode_alert(alert: &AssessmentAlertV1) -> Result<Vec<u8>> {
    alert.validate()?;
    let mut count = BoundedWriter::new(
        ALERT_LIMITS.max_bytes as u64,
        "assessment alert exceeds limit",
    );
    serde_json::to_writer(&mut count, alert)?;
    let value = serde_json::to_value(alert)?;
    ALERT_LIMITS.check_value(&value, "assessment alert")?;
    let bytes = aos_contract::canonical::to_vec(&value)?;
    if bytes.len() > ALERT_LIMITS.max_bytes {
        bail!("canonical assessment alert exceeds limit");
    }
    Ok(bytes)
}

fn family_name(family: IssueFamily) -> &'static str {
    match family {
        IssueFamily::Vulnerability => "vulnerability",
        IssueFamily::PackageUpdate => "package-update",
        IssueFamily::Coverage => "coverage",
        IssueFamily::SourceHealth => "source-health",
    }
}

fn state_name(state: AttentionState) -> &'static str {
    match state {
        AttentionState::Open => "open",
        AttentionState::Resolved => "resolved",
        AttentionState::Retired => "retired",
    }
}

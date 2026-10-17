//! Sanitized physical source failure facts, distinct from package applicability.
//!
//! The enclosing event binds these facts to an authorized registry and clock.
//! It carries no source URL, query text, credential, account or raw error body.
//!
//! ```json
//! {
//!   "kind": "source-failed",
//!   "failure": {
//!     "scanId": "scan-1",
//!     "provider": "github-tags",
//!     "operationDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!     "planDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!     "attempt": 1,
//!     "code": "execution-failed"
//!   }
//! }
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::provider::{ProviderWorkPlanV1, ProviderWorkResultV1, provider_result_indicates_outage};
use crate::validation::text;

/// Names the bounded reason one admitted source invocation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFailureCode {
    /// The executor did not return admissible evidence for the issued work.
    ExecutionFailed,
    /// A validated provider response imposed rate limiting.
    RateLimited,
    /// A validated provider response permits a later retry.
    RetryableResponse,
    /// The source invocation retained explicit outage uncertainty.
    SourceUnavailable,
}

/// Records one exact settled source attempt without exposing installation secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceFailureV1 {
    /// Original immutable logical scan identity.
    pub scan_id: String,
    /// Installed public source profile name.
    pub provider: String,
    /// Exact credential-free typed question commitment.
    pub operation_digest: Sha256Digest,
    /// Exact immutable issued plan commitment.
    pub plan_digest: Sha256Digest,
    /// Original physical attempt number; never an implicit retry allowance.
    pub attempt: u32,
    /// Admitted compact response receipt, absent when execution was uncertain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_digest: Option<Sha256Digest>,
    /// Sanitized outcome, independent of finding severity or applicability.
    pub code: SourceFailureCode,
    /// Validated rate-limit/retry response status, when supplied by the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Original source-imposed retry boundary; this does not reserve new work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<Timestamp>,
}

impl SourceFailureV1 {
    /// Projects a validated outage receipt without exposing source request text.
    ///
    /// Healthy responses produce no failure facts. Reproduction of the receipt
    /// establishes its exact issued-plan association, not independent source trust.
    ///
    /// # Errors
    /// Returns an error for mismatched receipts or invalid immutable failure facts.
    pub fn from_result(
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
    ) -> Result<Option<Self>> {
        result.validate_for(plan, &result.completed_at)?;
        if !provider_result_indicates_outage(result) {
            return Ok(None);
        }
        let (code, status, retry_at) = match &result.retry {
            Some(retry) if matches!(retry.status, 403 | 429) => (
                SourceFailureCode::RateLimited,
                Some(retry.status),
                Some(retry.not_before.clone()),
            ),
            Some(retry) if (500..=599).contains(&retry.status) => (
                SourceFailureCode::RetryableResponse,
                Some(retry.status),
                Some(retry.not_before.clone()),
            ),
            _ => (SourceFailureCode::SourceUnavailable, None, None),
        };
        let value = Self {
            scan_id: plan.claim.scan_id.clone(),
            provider: plan.operation.provider().into(),
            operation_digest: plan.operation.digest()?,
            plan_digest: plan.digest()?,
            attempt: plan.claim.attempt,
            receipt_digest: Some(Sha256Digest::of_canonical(
                "aos.provider-work-result/v1",
                result,
            )?),
            code,
            status,
            retry_at,
        };
        value.validate()?;
        Ok(Some(value))
    }

    /// Projects execution uncertainty for one exact already admitted plan.
    ///
    /// # Errors
    /// Returns an error for invalid plan commitments or failure bounds.
    pub fn from_failed_execution(plan: &ProviderWorkPlanV1) -> Result<Self> {
        let value = Self {
            scan_id: plan.claim.scan_id.clone(),
            provider: plan.operation.provider().into(),
            operation_digest: plan.operation.digest()?,
            plan_digest: plan.digest()?,
            attempt: plan.claim.attempt,
            receipt_digest: None,
            code: SourceFailureCode::ExecutionFailed,
            status: None,
            retry_at: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates closed source identities and immutable outcome associations.
    ///
    /// # Errors
    /// Returns an error for unsafe identities, invalid attempts, unsupported
    /// source names or outcome/status/receipt inconsistencies.
    pub fn validate(&self) -> Result<()> {
        text(&self.scan_id, 128, "source failure scan identity")?;
        ensure!(
            matches!(
                self.provider.as_str(),
                "github-releases"
                    | "github-tags"
                    | "go-releases"
                    | "repology"
                    | "osv"
                    | "nvd"
                    | "cisa-kev"
            ) && (1..=100).contains(&self.attempt),
            "invalid source failure provider or attempt"
        );
        match self.code {
            SourceFailureCode::ExecutionFailed => ensure!(
                self.receipt_digest.is_none() && self.status.is_none() && self.retry_at.is_none(),
                "uncertain source failure claims a response receipt"
            ),
            SourceFailureCode::RateLimited => ensure!(
                self.receipt_digest.is_some()
                    && matches!(self.status, Some(403 | 429))
                    && self.retry_at.is_some(),
                "rate limit failure lacks exact response facts"
            ),
            SourceFailureCode::RetryableResponse => ensure!(
                self.receipt_digest.is_some()
                    && self
                        .status
                        .is_some_and(|status| (500..=599).contains(&status))
                    && self.retry_at.is_some(),
                "retryable source failure lacks exact response facts"
            ),
            SourceFailureCode::SourceUnavailable => ensure!(
                self.receipt_digest.is_some() && self.status.is_none() && self.retry_at.is_none(),
                "source uncertainty includes unsupported response facts"
            ),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AssessmentEventPayload, AssessmentEventV1};
    use crate::notifications::NotificationSummaryV1;

    fn event() -> Result<AssessmentEventV1> {
        Ok(AssessmentEventV1 {
            schema: "aos.assessment-event/v1".into(),
            event_id: "source-failure".into(),
            sequence: 1,
            occurred_at: Timestamp::parse("2026-10-10T00:00:00Z")?,
            payload: AssessmentEventPayload::SourceFailed {
                failure: Box::new(SourceFailureV1 {
                    scan_id: "scan-1".into(),
                    provider: "github-tags".into(),
                    operation_digest: Sha256Digest::of_bytes("operation"),
                    plan_digest: Sha256Digest::of_bytes("plan"),
                    attempt: 1,
                    receipt_digest: None,
                    code: SourceFailureCode::ExecutionFailed,
                    status: None,
                    retry_at: None,
                }),
            },
        })
    }

    #[test]
    fn source_failure_is_closed_and_requires_grouped_attention_for_callback_fanout() -> Result<()> {
        let event = event()?;
        assert_eq!(AssessmentEventV1::from_slice(&event.to_bytes()?)?, event);
        assert!(NotificationSummaryV1::from_event(&event).is_err());
        let mut document = serde_json::to_value(&event)?;
        document["payload"]["failure"]["requestUrl"] =
            serde_json::json!("https://example.org/private");
        assert!(AssessmentEventV1::from_slice(&serde_json::to_vec(&document)?).is_err());
        Ok(())
    }

    #[test]
    fn source_failure_cannot_fabricate_response_identity_status_or_unbounded_retry() -> Result<()> {
        let mut event = event()?;
        let AssessmentEventPayload::SourceFailed { failure } = &mut event.payload else {
            anyhow::bail!("fixture payload");
        };
        for attempt in [0, 101] {
            failure.attempt = attempt;
            assert!(failure.validate().is_err());
        }
        failure.attempt = 100;
        failure.validate()?;
        failure.provider = "https://private.example".into();
        assert!(failure.validate().is_err());
        failure.provider = "github-tags".into();
        failure.receipt_digest = Some(Sha256Digest::of_bytes("receipt"));
        assert!(failure.validate().is_err());
        failure.code = SourceFailureCode::RateLimited;
        failure.status = Some(200);
        failure.retry_at = Some(Timestamp::from_unix_seconds(
            event.occurred_at.unix_seconds() + 86401,
        )?);
        assert!(failure.validate().is_err());
        failure.status = Some(429);
        failure.validate()?;
        assert!(event.validate().is_err());
        let AssessmentEventPayload::SourceFailed { failure } = &mut event.payload else {
            anyhow::bail!("fixture payload");
        };
        failure.code = SourceFailureCode::RetryableResponse;
        assert!(failure.validate().is_err());
        failure.status = Some(503);
        failure.retry_at = Some(event.occurred_at.clone());
        assert_eq!(AssessmentEventV1::from_slice(&event.to_bytes()?)?, event);
        Ok(())
    }
}

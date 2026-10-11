//! Atomic local provider quota, outage history and exact attempt receipts.
//!
//! A source budget retains consumed reservations before any physical call.
//! Expired unsettled work is conservatively failed once. Day rollover resets
//! allowance without clearing cooldowns, circuits or unexpired replay fences.
//!
//! The original local budget fields remain readable; added fields default to
//! empty history. Budget files have this protected, closed JSON shape:
//!
//! ```json
//! {
//!   "day": 20736, "requests": 1, "nextEligibleAt": 1791590420,
//!   "failureCount": 1, "circuitUntil": 0, "attempts": {}
//! }
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::provider::{
    ProviderWorkPlanV1, ProviderWorkResultV1, WorkOutcome, provider_backoff_jitter,
    provider_backoff_seconds, provider_result_indicates_outage,
};

use super::super::*;

const RECEIPT_RETENTION_SECONDS: u64 = 86_400;
const MAX_RETAINED_ATTEMPTS: usize = 2048;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceBudget {
    day: u64,
    requests: u32,
    next_eligible_at: u64,
    #[serde(default)]
    failure_count: u32,
    #[serde(default)]
    circuit_until: u64,
    #[serde(default)]
    attempts: BTreeMap<String, SourceAttempt>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceAttempt {
    plan_digest: Sha256Digest,
    expires_at: u64,
    jitter: u32,
    receipt: Option<SourceReceipt>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum SourceReceipt {
    Result { digest: Sha256Digest },
    Uncertain,
}

impl SourceBudget {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.requests <= 1000 && self.failure_count <= 20,
            "local source budget exceeds its installed counters"
        );
        ensure!(
            self.attempts.len() <= MAX_RETAINED_ATTEMPTS,
            "local source attempt retention is exhausted"
        );
        for (id, attempt) in &self.attempts {
            ensure!(
                id.len() == 64
                    && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && attempt.jitter <= 20,
                "local source attempt has an invalid commitment"
            );
        }
        Ok(())
    }

    fn record_outage(&mut self, now: u64, jitter: u32, retry_at: u64) {
        let delay = provider_backoff_seconds(self.failure_count, jitter);
        self.next_eligible_at = self
            .next_eligible_at
            .max(retry_at)
            .max(now.saturating_add(u64::from(delay)));
        if self.failure_count >= 4 {
            self.circuit_until = self
                .circuit_until
                .max(retry_at)
                .max(now.saturating_add(u64::from(delay.max(300))));
        }
        self.failure_count = (self.failure_count + 1).min(20);
    }

    fn recover_expired(&mut self, now: u64) -> bool {
        let mut expired = self
            .attempts
            .iter()
            .filter_map(|(id, attempt)| {
                (attempt.receipt.is_none() && attempt.expires_at <= now).then_some((
                    attempt.expires_at,
                    id.clone(),
                    attempt.jitter,
                ))
            })
            .collect::<Vec<_>>();
        expired.sort();
        for (expires_at, id, jitter) in &expired {
            self.record_outage(*expires_at, *jitter, 0);
            if let Some(attempt) = self.attempts.get_mut(id) {
                attempt.receipt = Some(SourceReceipt::Uncertain);
            }
        }
        let before = self.attempts.len();
        self.attempts.retain(|_, attempt| {
            now <= attempt.expires_at.saturating_add(RECEIPT_RETENTION_SECONDS)
        });
        !expired.is_empty() || before != self.attempts.len()
    }

    fn require_eligible(&self, now: u64) -> Result<()> {
        ensure!(
            now >= self.next_eligible_at && now >= self.circuit_until,
            "local assessment source cooldown has not elapsed"
        );
        Ok(())
    }
}

fn budget_filename(provider: &str) -> Result<String> {
    let key = match provider {
        "github-releases" | "github-tags" => "github",
        "go-releases" | "repology" | "osv" | "nvd" | "cisa-kev" => provider,
        _ => bail!("unsupported local assessment source quota request"),
    };
    Ok(format!("assessment-budget-{key}.json"))
}

fn attempt_key(plan: &ProviderWorkPlanV1) -> String {
    Sha256Digest::separated("aos.local-provider-attempt/v1", &plan.plan_id).hex()
}

impl StateStore {
    pub(super) fn require_settled_source_unlocked(
        &self,
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
    ) -> Result<()> {
        let budget = self.read_source_budget(&budget_filename(plan.operation.provider())?)?;
        let attempt = budget
            .attempts
            .get(&attempt_key(plan))
            .context("conditional source reservation is absent")?;
        let receipt = SourceReceipt::Result {
            digest: Sha256Digest::of_canonical("aos.local-provider-receipt/v1", result)?,
        };
        ensure!(
            attempt.plan_digest == plan.digest()? && attempt.receipt.as_ref() == Some(&receipt),
            "conditional observation lacks exact durable source settlement"
        );
        Ok(())
    }

    fn read_source_budget(&self, filename: &str) -> Result<SourceBudget> {
        let budget: SourceBudget =
            read_optional(&self.root.join(filename), "assessment source budget")?
                .unwrap_or_default();
        budget.validate()?;
        Ok(budget)
    }

    // Legacy Repology and shared acquisitions take this same host-wide lock.
    pub(in crate::commands::maintain::state) fn check_assessment_source_health_unlocked(
        &self,
        provider: &str,
        now: u64,
    ) -> Result<()> {
        let filename = budget_filename(provider)?;
        let mut budget = self.read_source_budget(&filename)?;
        if budget.recover_expired(now) {
            atomic_write(&self.root, &filename, &budget)?;
        }
        budget.require_eligible(now)
    }

    pub(in crate::commands::maintain) fn claim_assessment_source(
        &self,
        plan: &ProviderWorkPlanV1,
        now: &Timestamp,
    ) -> Result<()> {
        plan.validate_at(now)?;
        ensure!(
            plan.deployment_id == "local" && plan.claim.attempt == 1,
            "provider reservation is outside the installed local scope"
        );
        let requests = plan.budget_reservation.requests;
        let provider = plan.operation.provider();
        let filename = budget_filename(provider)?;
        let key = attempt_key(plan);
        let plan_digest = plan.digest()?;
        let jitter = provider_backoff_jitter(&plan.claim)?;
        self.with_provider_lock(|| {
            let mut budget = self.read_source_budget(&filename)?;
            if budget.recover_expired(now.unix_seconds()) {
                atomic_write(&self.root, &filename, &budget)?;
            }
            // A retained attempt never authorizes a second physical execution,
            // regardless of whether its original result has settled.
            ensure!(
                !budget.attempts.contains_key(&key),
                "local provider attempt is already consumed"
            );
            budget.require_eligible(now.unix_seconds())?;
            ensure!(
                budget.attempts.len() < MAX_RETAINED_ATTEMPTS,
                "local source attempt retention is exhausted"
            );
            let day = now.unix_seconds() / 86400;
            if budget.day != day {
                budget.day = day;
                budget.requests = 0;
            }
            ensure!(
                budget
                    .requests
                    .checked_add(requests)
                    .is_some_and(|count| count <= 1000),
                "local assessment source quota is unavailable"
            );
            if provider == "repology" {
                ensure!(requests == 1, "Repology requires a single physical request");
                self.claim_repology_request_unlocked(now.unix_seconds())?;
            }
            budget.requests += requests;
            budget.next_eligible_at = budget.next_eligible_at.max(
                now.unix_seconds()
                    .saturating_add(if provider == "nvd" { 6 } else { 0 }),
            );
            budget.attempts.insert(
                key.clone(),
                SourceAttempt {
                    plan_digest,
                    expires_at: plan.expires_at.unix_seconds(),
                    jitter,
                    receipt: None,
                },
            );
            atomic_write(&self.root, &filename, &budget)
        })
    }

    pub(in crate::commands::maintain) fn settle_assessment_source(
        &self,
        plan: &ProviderWorkPlanV1,
        result: Option<&ProviderWorkResultV1>,
        now: &Timestamp,
    ) -> Result<()> {
        if let Some(result) = result {
            result.validate_for(plan, &result.completed_at)?;
            ensure!(
                &result.completed_at <= now,
                "local provider result completed in the future"
            );
        }
        let receipt = match result {
            Some(result) => SourceReceipt::Result {
                digest: Sha256Digest::of_canonical("aos.local-provider-receipt/v1", result)?,
            },
            None => SourceReceipt::Uncertain,
        };
        let filename = budget_filename(plan.operation.provider())?;
        let key = attempt_key(plan);
        self.with_provider_lock(|| {
            let mut budget = self.read_source_budget(&filename)?;
            let attempt = budget
                .attempts
                .get(&key)
                .context("local source reservation is absent")?;
            ensure!(
                attempt.plan_digest == plan.digest()?,
                "local source reservation commitment changed"
            );
            if let Some(existing) = &attempt.receipt {
                ensure!(
                    existing == &receipt,
                    "local source attempt already has a different receipt"
                );
                return Ok(());
            }
            ensure!(
                now.unix_seconds() < attempt.expires_at,
                "local source reservation expired before settlement"
            );
            let jitter = attempt.jitter;
            if result.is_none_or(provider_result_indicates_outage) {
                let retry_at = result
                    .and_then(|result| result.retry.as_ref())
                    .map_or(0, |retry| retry.not_before.unix_seconds());
                budget.record_outage(now.unix_seconds(), jitter, retry_at);
            } else if result.is_some_and(|result| {
                matches!(
                    result.outcome,
                    WorkOutcome::Observed | WorkOutcome::NotModified
                )
            }) {
                budget.failure_count = 0;
                if budget.circuit_until <= now.unix_seconds() {
                    budget.circuit_until = 0;
                }
            }
            if let Some(attempt) = budget.attempts.get_mut(&key) {
                attempt.receipt = Some(receipt);
            }
            atomic_write(&self.root, &filename, &budget)
        })
    }
}

#[cfg(test)]
mod tests;

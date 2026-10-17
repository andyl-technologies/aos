//! Fresh coordinator confirmation immediately before a Worker callback effect.
//!
//! A signed plan alone does not prove that its reviewer remains authorized.
//! Physical Workers ask the coordinator about the exact retained claim, using a
//! compact challenge. A positive grant permits dispatch for at most five seconds
//! and requires authority through the full 20-second Worker invocation timeout.

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::NotificationWorkPlanV1;
use crate::validation::{decode, encoded, text};

/// Names the separately authenticated current-effect confirmation endpoint.
pub const NOTIFICATION_EFFECT_PATH: &str = "/internal/assessment/notification-effect/v1";

/// Challenges the coordinator about one exact retained claim without copying event bodies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationEffectQueryV1 {
    /// Exact supported query discriminator.
    pub schema: String,
    /// Installed deployment incarnation.
    pub deployment_id: String,
    /// Installed logical coordinator identity.
    pub issuer: String,
    /// Installed physical notification executor identity.
    pub audience: String,
    /// Exact non-reusable registry authorization scope.
    pub resource_scope: String,
    /// Exact immutable work proof retained at claim admission.
    pub plan_digest: Sha256Digest,
    /// Exact live outbox attempt fence.
    pub claim_token: String,
    /// Fresh unpredictable challenge containing at least 32 bounded ASCII characters.
    pub nonce: String,
    /// Physical query issue time; a query expires after five seconds.
    pub issued_at: Timestamp,
}

impl NotificationEffectQueryV1 {
    /// Validates a bounded fresh challenge before any coordinator persistence lookup.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, malformed scope or stale/future queries.
    pub fn validate_at(&self, now: &Timestamp) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-notification-effect-query/v1",
            "invalid notification effect query schema"
        );
        for value in [
            &self.deployment_id,
            &self.issuer,
            &self.audience,
            &self.resource_scope,
            &self.claim_token,
        ] {
            text(value, 128, "notification effect scope")?;
        }
        ensure!(
            (32..=128).contains(&self.nonce.len())
                && self
                    .nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "notification effect challenge is invalid"
        );
        ensure!(
            self.issued_at <= *now && now.elapsed_since(&self.issued_at)? < 5,
            "notification effect challenge is stale or future dated"
        );
        encoded(self)?;
        Ok(())
    }

    /// Requires the exact plan scope and unpredictable live attempt association.
    ///
    /// # Errors
    /// Returns an error for another resource, work commitment, claim or service pairing.
    pub fn require_plan(&self, plan: &NotificationWorkPlanV1) -> Result<()> {
        ensure!(
            self.deployment_id == plan.deployment_id
                && self.issuer == plan.issuer
                && self.audience == plan.audience
                && self.resource_scope == plan.body.resource_scope
                && self.plan_digest == plan.digest()?
                && self.claim_token == plan.claim_token,
            "notification effect challenge differs from the retained exact plan"
        );
        Ok(())
    }

    /// Computes the challenge commitment bound into the positive coordinator grant.
    ///
    /// # Errors
    /// Returns an error for invalid scope or serialization bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate_at(&self.issued_at)?;
        Sha256Digest::of_canonical("aos.assessment-notification-effect-query/v1", self)
    }

    /// Decodes one authenticated fresh challenge under shared envelope limits.
    ///
    /// # Errors
    /// Returns an error for unknown fields, excessive envelopes or expired challenges.
    pub fn from_slice(bytes: &[u8], now: &Timestamp) -> Result<Self> {
        let query: Self = decode(bytes, "notification effect query")?;
        query.validate_at(now)?;
        Ok(query)
    }
}

/// Confirms current reviewer, destination and live attempt authority for immediate dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationEffectGrantV1 {
    /// Exact supported grant discriminator.
    pub schema: String,
    /// Commitment to the complete original physical challenge.
    pub query_digest: Sha256Digest,
    /// Exact retained plan independently checked by the coordinator.
    pub plan_digest: Sha256Digest,
    /// Exact attempt fence checked against every pinned outbox member.
    pub claim_token: String,
    /// Original physical challenge nonce.
    pub nonce: String,
    /// Coordinator database time after successful current-authority checks.
    pub checked_at: Timestamp,
    /// Exclusive latest dispatch time, at most five seconds after the current check.
    pub dispatch_by: Timestamp,
    /// Original full physical claim deadline; this grant cannot extend it.
    pub plan_deadline: Timestamp,
}

impl NotificationEffectGrantV1 {
    /// Constructs compact grant facts after the host has checked current SQL authority.
    ///
    /// This constructor does not authorize an effect or inspect a database. A host
    /// signs its output only after checking the retained plan and live IAM/review fences.
    ///
    /// # Errors
    /// Returns an error for wrong/stale challenges or insufficient full invocation authority.
    pub fn from_current_check(
        query: &NotificationEffectQueryV1,
        plan: &NotificationWorkPlanV1,
        checked_at: Timestamp,
    ) -> Result<Self> {
        query.validate_at(&checked_at)?;
        query.require_plan(plan)?;
        plan.validate_at(&checked_at)?;
        let last_dispatch = plan
            .deadline
            .unix_seconds()
            .checked_sub(20)
            .ok_or_else(|| {
                anyhow::anyhow!("notification effect lacks full invocation authority")
            })?;
        let dispatch_by = Timestamp::from_unix_seconds(
            checked_at
                .unix_seconds()
                .saturating_add(5)
                .min(last_dispatch),
        )?;
        let grant = Self {
            schema: "aos.assessment-notification-effect-grant/v1".into(),
            query_digest: query.digest()?,
            plan_digest: query.plan_digest,
            claim_token: query.claim_token.clone(),
            nonce: query.nonce.clone(),
            checked_at: checked_at.clone(),
            dispatch_by,
            plan_deadline: plan.deadline.clone(),
        };
        grant.validate_for(query, plan, &checked_at)?;
        Ok(grant)
    }

    /// Verifies exact challenge association and fresh authority through the whole invocation.
    ///
    /// # Errors
    /// Returns an error for an unrelated challenge, altered deadline or expired dispatch grant.
    pub fn validate_for(
        &self,
        query: &NotificationEffectQueryV1,
        plan: &NotificationWorkPlanV1,
        now: &Timestamp,
    ) -> Result<()> {
        query.validate_at(&self.checked_at)?;
        query.require_plan(plan)?;
        plan.validate_at(now)?;
        ensure!(
            self.schema == "aos.assessment-notification-effect-grant/v1"
                && self.query_digest == query.digest()?
                && self.plan_digest == query.plan_digest
                && self.claim_token == query.claim_token
                && self.nonce == query.nonce
                && self.plan_deadline == plan.deadline
                && self.checked_at <= *now
                && *now < self.dispatch_by
                && self.dispatch_by.unix_seconds()
                    <= self.checked_at.unix_seconds().saturating_add(5)
                && self.dispatch_by.unix_seconds().saturating_add(20)
                    <= self.plan_deadline.unix_seconds(),
            "notification current-effect grant is unrelated, extended or expired"
        );
        encoded(self)?;
        Ok(())
    }
}

//! Bounded physical notification attempts and deterministic coordinator retry policy.

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::{CallbackSignature, NotificationBodyV1};
use crate::ports::{Clock, RuntimeBounds};
use crate::validation::{decode, encoded, text};

/// Describes an independently installed registered destination and signing-key version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationDestinationV1 {
    /// Exact destination discriminator.
    pub schema: String,
    /// Registered destination identity, unrelated to any source-provider identity.
    pub destination_reference: String,
    /// Exact reviewed registered destination revision.
    pub revision: u64,
    /// Exact non-reusable resource incarnation permitted to disclose events.
    pub resource_scope: String,
    /// Administratively registered HTTPS callback; redirects are forbidden.
    pub url: String,
    /// Immutable signing-key version resolved by the executor.
    pub secret_version_reference: String,
    /// Digest checked against the resolved key before any private callback.
    pub credential_fingerprint: Sha256Digest,
    /// Exclusive independently installed grant deadline.
    pub expires_at: Timestamp,
}

impl NotificationDestinationV1 {
    /// Decodes the closed registered-destination projection under shared envelope limits.
    ///
    /// # Errors
    /// Returns an error for unknown fields, malformed destination or envelope bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let destination: Self = decode(bytes, "registered notification destination")?;
        destination.validate()?;
        Ok(destination)
    }

    /// Checks the exact public HTTPS destination and immutable credential identity.
    ///
    /// Transport implementations additionally pin public DNS addresses and prevent
    /// redirects; syntactic URL validation alone does not authorize network access.
    ///
    /// # Errors
    /// Returns an error for invalid schema, revision, URL or credential reference.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-notification-destination/v1"
                && self.revision > 0
                && self.revision <= 9_007_199_254_740_991,
            "invalid notification destination schema/revision"
        );
        for value in [
            &self.destination_reference,
            &self.resource_scope,
            &self.secret_version_reference,
        ] {
            text(value, 128, "notification destination scope")?;
        }
        text(&self.url, 2048, "registered notification URL")?;
        let url = url::Url::parse(&self.url)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "notification destination requires registered HTTPS without userinfo or fragments"
        );
        match url
            .host()
            .ok_or_else(|| anyhow::anyhow!("notification destination lacks a host"))?
        {
            url::Host::Ipv4(address) => ensure!(
                aos_contract::network_address::is_global_ip(address.into()),
                "notification IP literal is not public"
            ),
            url::Host::Ipv6(address) => ensure!(
                aos_contract::network_address::is_global_ip(address.into()),
                "notification IP literal is not public"
            ),
            url::Host::Domain(host) => ensure!(
                host.contains('.')
                    && !host.ends_with(".localhost")
                    && !host.ends_with(".local")
                    && !host.ends_with(".internal"),
                "notification hostname is not a public DNS name"
            ),
        }
        encoded(self)?;
        Ok(())
    }

    /// Computes the exact destination commitment reviewed by the subscription.
    ///
    /// # Errors
    /// Returns an error for malformed destination content or serialization limits.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Sha256Digest::of_canonical("aos.assessment-notification-destination/v1", self)
    }
}

/// Carries one separately authenticated, quota-admitted physical callback attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationWorkPlanV1 {
    /// Exact notification work discriminator.
    pub schema: String,
    /// Installed deployment identity.
    pub deployment_id: String,
    /// Independently installed coordinator identity.
    pub issuer: String,
    /// Independently installed physical executor identity.
    pub audience: String,
    /// Unpredictable exact outbox claim token.
    pub claim_token: String,
    /// Physical attempt number from one through twenty.
    pub attempt: u8,
    /// Exact quota reservation commitment; an uncertain effect never refunds it.
    pub reservation_digest: Sha256Digest,
    /// Immutable registered destination identity.
    pub destination_reference: String,
    /// Exact independently installed destination commitment.
    pub destination_digest: Sha256Digest,
    /// Immutable compact body, including pinned digest membership.
    pub body: NotificationBodyV1,
    /// Exact commitment to that body.
    pub body_digest: Sha256Digest,
    /// Coordinator admission time, used as the signed callback attempt timestamp.
    pub issued_at: Timestamp,
    /// Exclusive authority/lease deadline, at most sixty seconds after admission.
    pub deadline: Timestamp,
}

impl NotificationWorkPlanV1 {
    /// Validates the complete bounded attempt before destination or key resolution.
    ///
    /// # Errors
    /// Returns an error for malformed identity, altered body, expired authority or limits.
    pub fn validate_at(&self, now: &Timestamp) -> Result<()> {
        ensure!(
            self.schema == "aos.assessment-notification-work/v1"
                && (1..=20).contains(&self.attempt),
            "invalid notification work schema/attempt"
        );
        for value in [
            &self.deployment_id,
            &self.issuer,
            &self.audience,
            &self.claim_token,
            &self.destination_reference,
        ] {
            text(value, 128, "notification work scope")?;
        }
        ensure!(
            self.issued_at <= *now
                && *now < self.deadline
                && self.deadline.elapsed_since(&self.issued_at)? <= 60,
            "notification work is expired or exceeds its authority window"
        );
        ensure!(
            self.body.digest()? == self.body_digest && self.body.to_bytes()?.len() <= 131_072,
            "notification work body changed or exceeds physical limit"
        );
        encoded(self)?;
        Ok(())
    }

    /// Decodes authenticated bounded work without accepting arbitrary HTTP requests.
    ///
    /// # Errors
    /// Returns an error for unknown fields, invalid scope, expiry or body commitment.
    pub fn from_slice(bytes: &[u8], now: &Timestamp) -> Result<Self> {
        let value: Self = decode(bytes, "notification work")?;
        value.validate_at(now)?;
        Ok(value)
    }

    /// Checks exact installed destination, resource and authority through the whole attempt.
    ///
    /// # Errors
    /// Returns an error for changed destination, credential revision, scope or grant expiry.
    pub fn require_destination(&self, destination: &NotificationDestinationV1) -> Result<()> {
        ensure!(
            destination.destination_reference == self.destination_reference
                && destination.digest()? == self.destination_digest
                && destination.resource_scope == self.body.resource_scope
                && destination.expires_at >= self.deadline,
            "notification destination grant differs from the reviewed work"
        );
        Ok(())
    }

    /// Returns the immutable attempt identity pinned before the first physical effect.
    ///
    /// # Errors
    /// Returns an error if bounded serialization fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        encoded(self)?;
        Sha256Digest::of_canonical("aos.assessment-notification-work/v1", self)
    }
}

/// Distinguishes destination acceptance from retryable and permanent transport outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryOutcome {
    /// The destination accepted the HTTP request; downstream action is unconfirmed.
    Accepted,
    /// Network, throttling or temporary server failure permits a new bounded attempt.
    Retryable,
    /// Destination/configuration failure requires a new explicit review.
    PermanentFailure,
}

/// Records compact delivery facts without response bodies or resolved credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationWorkReceiptV1 {
    /// Exact receipt discriminator.
    pub schema: String,
    /// Exact admitted attempt commitment.
    pub plan_digest: Sha256Digest,
    /// Immutable body commitment retained through retries.
    pub body_digest: Sha256Digest,
    /// Exact fence whose currentness the coordinator checks before receipt admission.
    pub claim_token: String,
    /// Destination acceptance or bounded failure class.
    pub outcome: DeliveryOutcome,
    /// Actual HTTP status, absent for network failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Optional bounded server-requested retry delay, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u32>,
    /// Physical attempt completion time.
    pub completed_at: Timestamp,
}

impl NotificationWorkReceiptV1 {
    /// Encodes structurally valid receipt facts without asserting journal authority.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, malformed status or contradictory outcome.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.schema == "aos.assessment-notification-receipt/v1",
            "invalid notification receipt schema"
        );
        text(&self.claim_token, 128, "notification receipt claim")?;
        ensure!(
            self.status
                .is_none_or(|status| (100..=599).contains(&status)),
            "invalid notification HTTP status"
        );
        let expected = match self.status {
            Some(200..=299) => DeliveryOutcome::Accepted,
            Some(408 | 425 | 429 | 500..=599) | None => DeliveryOutcome::Retryable,
            _ => DeliveryOutcome::PermanentFailure,
        };
        ensure!(
            self.outcome == expected
                && self.retry_after_seconds.is_none_or(
                    |seconds| seconds <= 3600 && self.outcome == DeliveryOutcome::Retryable
                ),
            "notification receipt contradicts transport facts"
        );
        encoded(self)
    }

    /// Decodes a closed immutable receipt without granting delivery authority.
    ///
    /// # Errors
    /// Returns an error for unknown fields, contradictory facts or envelope limits.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let receipt: Self = decode(bytes, "notification receipt")?;
        receipt.to_bytes()?;
        Ok(receipt)
    }

    /// Computes the immutable receipt commitment retained by the coordinator.
    ///
    /// # Errors
    /// Returns an error for invalid receipt facts or serialization limits.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.to_bytes()?;
        Sha256Digest::of_canonical("aos.assessment-notification-receipt/v1", self)
    }

    /// Checks exact current attempt association and conservative status classification.
    ///
    /// # Errors
    /// Returns an error for unrelated plans, invalid status, forged acceptance or expiry.
    pub fn validate_for(&self, plan: &NotificationWorkPlanV1, now: &Timestamp) -> Result<()> {
        plan.validate_at(now)?;
        ensure!(
            self.schema == "aos.assessment-notification-receipt/v1"
                && self.plan_digest == plan.digest()?
                && self.body_digest == plan.body_digest
                && self.claim_token == plan.claim_token
                && self.completed_at >= plan.issued_at
                && self.completed_at <= *now,
            "notification receipt does not bind the current attempt"
        );
        self.to_bytes()?;
        Ok(())
    }
}

/// Sends only the installed exact destination under a separately admitted attempt.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait NotificationTransport: RuntimeBounds {
    /// Resolves and verifies the immutable destination key without exposing its bytes.
    ///
    /// # Errors
    /// Returns an error for revoked destination/key references, fingerprint mismatch or expiry.
    async fn sign_callback(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
    ) -> Result<CallbackSignature>;

    /// Sends one request with redirects disabled and a fifteen-second physical timeout.
    ///
    /// Implementations pin public DNS addresses and stream/discard a bounded response.
    /// They return only status and a clamped Retry-After delay; network failures
    /// return `(None, None)`. Structural or authorization failures return an error.
    /// The host durably pins the exact plan before invoking this effect.
    ///
    /// # Errors
    /// Returns an error for unsafe destination, changed grant or unavailable physical bounds.
    async fn post(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
        signature: &CallbackSignature,
    ) -> Result<(Option<u16>, Option<u32>)>;
}

/// Executes one already authenticated and durably pinned physical notification attempt.
///
/// # Errors
/// Returns an error for invalid/expired work, changed destination or transport authority.
pub async fn execute_notification<T: NotificationTransport, C: Clock>(
    transport: &T,
    clock: &C,
    destination: &NotificationDestinationV1,
    plan: &NotificationWorkPlanV1,
) -> Result<NotificationWorkReceiptV1> {
    plan.validate_at(&clock.now()?)?;
    plan.require_destination(destination)?;
    let body = plan.body.to_bytes()?;
    let signature = transport.sign_callback(destination, plan, &body).await?;
    plan.validate_at(&clock.now()?)?;
    let (status, retry_after) = transport.post(destination, plan, &body, &signature).await?;
    let outcome = match status {
        Some(200..=299) => DeliveryOutcome::Accepted,
        Some(408 | 425 | 429 | 500..=599) | None => DeliveryOutcome::Retryable,
        _ => DeliveryOutcome::PermanentFailure,
    };
    let receipt = NotificationWorkReceiptV1 {
        schema: "aos.assessment-notification-receipt/v1".into(),
        plan_digest: plan.digest()?,
        body_digest: plan.body_digest,
        claim_token: plan.claim_token.clone(),
        outcome,
        status,
        retry_after_seconds: retry_after
            .filter(|_| outcome == DeliveryOutcome::Retryable)
            .map(|seconds| seconds.min(3600)),
        completed_at: clock.now()?,
    };
    receipt.validate_for(plan, &clock.now()?)?;
    Ok(receipt)
}

/// Computes bounded exponential delay with deterministic per-delivery jitter.
///
/// # Errors
/// Returns an error for invalid attempt identity or a server delay above one hour.
pub fn retry_delay(
    delivery_id: &str,
    attempt: u8,
    retry_after_seconds: Option<u32>,
) -> Result<u32> {
    text(delivery_id, 128, "retry delivery identity")?;
    ensure!(
        (1..=20).contains(&attempt) && retry_after_seconds.is_none_or(|seconds| seconds <= 3600),
        "invalid notification retry bounds"
    );
    let digest = Sha256Digest::of_canonical(
        "aos.assessment-notification-retry/v1",
        &(delivery_id, attempt),
    )?
    .to_string();
    let jitter = u32::from_str_radix(&digest[digest.len() - 4..], 16)? % 21;
    let exponential = 20_u32
        .saturating_mul(1_u32 << u32::from(attempt.saturating_sub(1).min(8)))
        .min(3600);
    Ok(exponential
        .saturating_add(jitter)
        .min(3600)
        .max(retry_after_seconds.unwrap_or(0)))
}

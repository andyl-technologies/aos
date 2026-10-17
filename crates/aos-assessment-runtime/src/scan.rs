//! Durable scan requests, immutable terminal transitions and current-claim fences.
//!
//! Runtime records use `aos.scan-request/v1`; they are intentionally outside the
//! semantic `aos.scan-input/v1` digest. A database adapter supplies generations,
//! unpredictable claim tokens and atomic compare-and-swap, never a local map.

use anyhow::{Result, bail};
use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::{decode, encoded, sorted, text};

/// Identifies one closed request for durable scan execution.
pub const SCAN_REQUEST_V1: &str = "aos.scan-request/v1";

/// Selects a deployment's admitted placement without changing policy semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    /// Coordinates and executes on the current machine.
    Local,
    /// Coordinates and executes in the Native service.
    Native,
    /// Coordinates through HubDb and executes on Workers.
    Worker,
    /// Coordinates in Native SQL and executes scoped effects on Workers.
    Hybrid,
}

/// Bounds the whole operation independently of individual provider invocations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanLimits {
    /// Maximum pinned subjects, at most ten thousand.
    pub subjects: u32,
    /// Maximum component nodes, at most one hundred thousand.
    pub components: u32,
    /// Maximum dependency edges, at most one hundred thousand.
    pub edges: u32,
    /// Conservatively consumed provider attempts, including uncertain timeouts.
    pub provider_requests: u32,
    /// Maximum durable child tasks, including continuation pages.
    pub tasks: u32,
    /// Maximum accumulated normalized provider bytes, independent of raw evidence.
    pub normalized_bytes: u64,
    /// Maximum elapsed wall time before admission of new work stops.
    pub wall_seconds: u32,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            subjects: 10_000,
            components: 100_000,
            edges: 100_000,
            provider_requests: 4096,
            tasks: 8192,
            normalized_bytes: 256 * 1024 * 1024,
            wall_seconds: 3600,
        }
    }
}

impl ScanLimits {
    /// Validates deployment-tightenable hard operation ceilings.
    ///
    /// # Errors
    /// Returns an error for zero or excessive limits.
    pub fn validate(&self) -> Result<()> {
        let ceiling = Self::default();
        if self.subjects == 0
            || self.subjects > ceiling.subjects
            || self.components == 0
            || self.components > ceiling.components
            || self.edges > ceiling.edges
            || self.provider_requests > ceiling.provider_requests
            || self.tasks == 0
            || self.tasks > ceiling.tasks
            || self.normalized_bytes == 0
            || self.normalized_bytes > ceiling.normalized_bytes
            || self.wall_seconds == 0
            || self.wall_seconds > ceiling.wall_seconds
        {
            bail!("scan limits exceed the installed operation profile");
        }
        Ok(())
    }
}

/// Binds a bounded normalized selector to exact inventory, authority and policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanRequestV1 {
    /// Exact request schema discriminator.
    pub schema: String,
    /// Stable non-reusable registry resource incarnation.
    pub resource_scope: String,
    /// Exact authorization/tenant partition, independent of package spelling.
    pub authorization_partition: String,
    /// Current inventory revision, checked again at every head commit.
    pub inventory_revision: u64,
    /// Exact immutable normalized inventory.
    pub inventory_digest: Sha256Digest,
    /// Exact required decision policy.
    pub policy_digest: Sha256Digest,
    /// Sorted exact pinned subject identities, not a moving database query.
    pub subjects: Vec<String>,
    /// Independently committed profiles, sorted and unique.
    pub profiles: Vec<Profile>,
    /// Explicit acquisition intent; cached reads never imply refresh.
    pub freshness: FreshnessMode,
    /// Bounded origin class: manual, schedule, inventory, advisory or deadline.
    pub trigger: String,
    /// Authenticated actor reference or scoped coordinator identity.
    pub actor_ref: String,
    /// Scoped caller idempotency key; changed content is a conflict.
    pub idempotency_key: String,
    /// Request-wide resource ceilings.
    pub limits: ScanLimits,
}

impl ScanRequestV1 {
    /// Validates closed bounded scope before assigning durable work.
    ///
    /// # Errors
    /// Returns an error for incompatible schema, scope, profiles or hard limits.
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.schema != SCAN_REQUEST_V1
            || self.inventory_revision == 0
            || self.inventory_revision > 9_007_199_254_740_991
            || self.subjects.is_empty()
            || self.subjects.len() > self.limits.subjects as usize
            || self.profiles.is_empty()
            || self.profiles.len() > 3
            || !["manual", "schedule", "inventory", "advisory", "deadline"]
                .contains(&self.trigger.as_str())
        {
            bail!("invalid scan request schema or pinned scope");
        }
        for value in [
            &self.resource_scope,
            &self.authorization_partition,
            &self.actor_ref,
            &self.idempotency_key,
        ] {
            text(value, 128, "scan authority/idempotency reference")?;
        }
        for subject in &self.subjects {
            text(subject, 128, "pinned scan subject")?;
        }
        sorted(&self.subjects, "scan subjects")?;
        sorted(&self.profiles, "scan profiles")?;
        encoded(self)?;
        Ok(())
    }

    /// Decodes one bounded request before any provider or database mutation.
    ///
    /// # Errors
    /// Returns an error for malformed/ambiguous/incompatible JSON or invalid scope.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let request: Self = decode(bytes, "scan request")?;
        request.validate()?;
        Ok(request)
    }

    /// Computes the immutable execution-request identity.
    ///
    /// # Errors
    /// Returns an error for invalid scope or canonical serialization.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Sha256Digest::of_canonical(SCAN_REQUEST_V1, self)
    }
}

/// Records an operation's state independently of vulnerability outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanState {
    /// Awaits a durable coordinator claim.
    Queued,
    /// Runs admitted child work/evaluation.
    Running,
    /// Completed every requested profile with complete declared coverage.
    Succeeded,
    /// Retained useful results with explicit coverage gaps.
    Partial,
    /// Could not construct trustworthy assessment evidence.
    Failed,
    /// Fenced against subsequent result commits while cancellation drains.
    Cancelling,
    /// Completed cancellation without retracting admitted historical evidence.
    Cancelled,
    /// Lost the desired generation or inventory/policy authority fence.
    Superseded,
}

impl ScanState {
    /// Reports whether the operation's state is immutable.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Partial | Self::Failed | Self::Cancelled | Self::Superseded
        )
    }

    /// Checks a documented operation transition without reopening terminal work.
    ///
    /// # Errors
    /// Returns an error for an impossible transition or terminal mutation.
    pub fn transition(self, next: Self) -> Result<Self> {
        let allowed = matches!(
            (self, next),
            (
                Self::Queued,
                Self::Running | Self::Cancelling | Self::Superseded
            ) | (
                Self::Running,
                Self::Succeeded
                    | Self::Partial
                    | Self::Failed
                    | Self::Cancelling
                    | Self::Superseded
            ) | (Self::Cancelling, Self::Cancelled | Self::Superseded)
        );
        if !allowed {
            bail!("scan state transition is invalid or terminal");
        }
        Ok(next)
    }

    /// Returns the stable SQL/wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }
}

/// Pins one current task attempt to operation, inventory and desired generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskClaim {
    /// Durable operation identity.
    pub scan_id: String,
    /// Stable child identity across attempts.
    pub task_id: String,
    /// Exact immutable request content.
    pub request_digest: Sha256Digest,
    /// Desired coordinator generation.
    pub generation: u64,
    /// Current inventory revision.
    pub inventory_revision: u64,
    /// Unpredictable fresh attempt token supplied by the journal.
    pub claim_token: String,
    /// Exclusive lease expiry, supplied by authoritative database time.
    pub expires_at: Timestamp,
    /// Monotonic attempt number; retries acquire new allowance.
    pub attempt: u32,
}

impl TaskClaim {
    /// Validates a current claim's bounded shape and exclusive lease deadline.
    ///
    /// # Errors
    /// Returns an error for invalid identity, generation, attempt or expired lease.
    pub fn validate_at(&self, now: &Timestamp) -> Result<()> {
        for value in [&self.scan_id, &self.task_id, &self.claim_token] {
            text(value, 128, "scan claim identity")?;
        }
        if self.claim_token.len() < 32
            || self.generation == 0
            || self.inventory_revision == 0
            || self.generation > 9_007_199_254_740_991
            || self.inventory_revision > 9_007_199_254_740_991
            || self.attempt == 0
            || self.attempt > 100
            || now >= &self.expires_at
        {
            bail!("scan claim is invalid or expired");
        }
        Ok(())
    }
}

/// Tracks conservatively consumed request-wide work across durable checkpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanUsage {
    /// Reserved provider requests, never refunded after uncertain dispatch.
    pub provider_requests: u32,
    /// Admitted durable child tasks including failed attempts and continuations.
    pub tasks: u32,
    /// Admitted normalized bytes including superseded historical evidence.
    pub normalized_bytes: u64,
}

impl ScanUsage {
    /// Computes bounded monotonic usage before dispatch or evidence admission.
    ///
    /// # Errors
    /// Returns an error for arithmetic overflow or request-wide exhaustion.
    pub fn consume(&self, delta: &Self, limits: &ScanLimits) -> Result<Self> {
        limits.validate()?;
        let next = Self {
            provider_requests: self
                .provider_requests
                .checked_add(delta.provider_requests)
                .ok_or_else(|| anyhow::anyhow!("scan request usage overflow"))?,
            tasks: self
                .tasks
                .checked_add(delta.tasks)
                .ok_or_else(|| anyhow::anyhow!("scan task usage overflow"))?,
            normalized_bytes: self
                .normalized_bytes
                .checked_add(delta.normalized_bytes)
                .ok_or_else(|| anyhow::anyhow!("scan byte usage overflow"))?,
        };
        if next.provider_requests > limits.provider_requests
            || next.tasks > limits.tasks
            || next.normalized_bytes > limits.normalized_bytes
        {
            bail!("scan request-wide budget exhausted");
        }
        Ok(next)
    }
}

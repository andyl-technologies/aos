//! Typed separately authenticated provider work for bounded per-object fanout.
//!
//! `aos.provider-work-plan/v1` grants observation authority under installed
//! profiles. It grants no arbitrary HTTP or storage write authority. Raw source
//! bodies remain with the evidence port; the coordinator receives compact,
//! digest-bound projections in `aos.provider-work-result/v1`.

use anyhow::{Result, bail};
use aos_assessment::observation::{HttpValidators, SourceEvidenceRef};
use aos_assessment::security::SecurityIdentity;
use aos_assessment::time::Timestamp;
use aos_assessment_providers::osv::Query;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

mod auth;
mod capabilities;
mod executor;
mod page;
mod projection;
mod requests;

pub use auth::ProviderWorkAuth;
pub use capabilities::{CapabilityChallenge, ProviderCapabilitiesV1};
pub use executor::{SourceResponse, SourceTransport, execute_source};
pub use page::{AdvisoryRevisionReference, ProviderPageV1};
pub use projection::{
    NormalizedObject, ObjectProjection, ProviderUsage, ProviderWorkResultV1, WorkOutcome,
};
pub use requests::{SourceMethod, SourceRequest};

use crate::scan::TaskClaim;
use crate::validation::{decode, encoded, sorted, text};

/// Fixed independently authenticated provider execution route.
pub const PROVIDER_WORK_PATH: &str = "/_internal/assessment/v1/provider/execute";
/// Fixed capability route evaluated before issuing provider work.
pub const PROVIDER_CAPABILITIES_PATH: &str = "/_internal/assessment/v1/capabilities";
/// Header authenticating exact provider work bytes.
pub const PROVIDER_SIGNATURE_HEADER: &str = "x-aos-assessment-signature";
/// Closed version of the provider execution plan.
pub const PROVIDER_WORK_PLAN_V1: &str = "aos.provider-work-plan/v1";
/// Closed version of the compact execution response.
pub const PROVIDER_WORK_RESULT_V1: &str = "aos.provider-work-result/v1";

/// Tightenable hard per-invocation ceilings, independent of scan-wide quotas.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderLimits {
    /// Maximum decompressed response bytes, at most eight MiB.
    pub response_bytes: u64,
    /// Maximum aggregate source bytes, at most sixty-four MiB.
    pub source_bytes: u64,
    /// Maximum encoded compact result bytes, at most 256 KiB.
    pub result_bytes: u32,
    /// Maximum compact normalized records, at most 128.
    pub normalized_entries: u32,
    /// Maximum requests, at most ten and additionally reserved before execution.
    pub requests: u32,
    /// Maximum in-flight requests, at most four.
    pub concurrency: u32,
    /// Maximum connection establishment time, at most ten seconds.
    pub connect_seconds: u32,
    /// Maximum individual request time, at most forty-five seconds.
    pub request_seconds: u32,
}

impl Default for ProviderLimits {
    fn default() -> Self {
        Self {
            response_bytes: 8 * 1024 * 1024,
            source_bytes: 64 * 1024 * 1024,
            result_bytes: 256 * 1024,
            normalized_entries: 128,
            requests: 10,
            concurrency: 4,
            connect_seconds: 10,
            request_seconds: 45,
        }
    }
}

impl ProviderLimits {
    /// Checks whether an issued plan fits negotiated executor ceilings.
    ///
    /// # Errors
    /// Returns an error for invalid limits or a requested ceiling above the executor's.
    pub fn require_within(&self, available: &Self) -> Result<()> {
        self.validate()?;
        available.validate()?;
        if self.response_bytes > available.response_bytes
            || self.source_bytes > available.source_bytes
            || self.result_bytes > available.result_bytes
            || self.normalized_entries > available.normalized_entries
            || self.requests > available.requests
            || self.concurrency > available.concurrency
            || self.connect_seconds > available.connect_seconds
            || self.request_seconds > available.request_seconds
        {
            bail!("issued provider limits exceed negotiated executor capabilities");
        }
        Ok(())
    }

    /// Validates the installed profile's independent byte, item and time limits.
    ///
    /// # Errors
    /// Returns an error for zero, inconsistent or excessive limits.
    pub fn validate(&self) -> Result<()> {
        let maximum = Self::default();
        if self.response_bytes == 0
            || self.response_bytes > maximum.response_bytes
            || self.source_bytes < self.response_bytes
            || self.source_bytes > maximum.source_bytes
            || self.result_bytes == 0
            || self.result_bytes > maximum.result_bytes
            || self.normalized_entries == 0
            || self.normalized_entries > maximum.normalized_entries
            || self.requests == 0
            || self.requests > maximum.requests
            || self.concurrency == 0
            || self.concurrency > maximum.concurrency
            || self.concurrency > self.requests
            || self.connect_seconds == 0
            || self.connect_seconds > maximum.connect_seconds
            || self.request_seconds < self.connect_seconds
            || self.request_seconds > maximum.request_seconds
        {
            bail!("provider work exceeds installed byte/item/request/time ceilings");
        }
        Ok(())
    }
}

/// Grants conservatively spent quota for one scoped invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BudgetReservation {
    /// Shared provider/credential partition quota identity.
    pub source_budget: String,
    /// Current unique durable reservation identity; duplicates cannot renew it.
    pub reservation_id: String,
    /// Maximum provider calls covered by this already consumed allowance.
    pub requests: u32,
    /// Exclusive source-budget deadline, no later than the task lease.
    pub deadline: Timestamp,
}

/// Binds conditional validators to exact retained response bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CachedResponse {
    /// Exact prior admitted response and byte length.
    pub evidence: SourceEvidenceRef,
    /// Safe validators copied from that response's admitted observation.
    pub validators: HttpValidators,
    /// Exact compatible normalized prior observation.
    pub observation_digest: Sha256Digest,
    /// Exact admitted compact observation for source, validators and original time.
    pub observation: aos_assessment::observation::ProviderObservationV1,
}

/// Preserves one positional OSV continuation without null/empty placeholder tokens.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QueryContinuation {
    /// Zero-based original query position.
    pub position: u32,
    /// Exact provider token for that query alone.
    pub token: String,
}

/// Names admitted provider operations; endpoint selection belongs to profiles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderOperation {
    /// Reads one GitHub releases page.
    ObserveReleases {
        /// Owner/repository identity, with no extra path or credential.
        repository: String,
        /// Declared prefix stripped only by the shared parser.
        tag_prefix: String,
        /// One-based page position.
        page: u32,
    },
    /// Reads one GitHub tags page.
    ObserveTags {
        /// Owner/repository identity.
        repository: String,
        /// Exact admitted tag prefix.
        tag_prefix: String,
        /// One-based page position.
        page: u32,
    },
    /// Reads the installed Go release endpoint.
    ObserveGoReleases,
    /// Reads an exact Repology project under its shared global budget.
    ObserveRepology {
        /// Exact admitted project identity.
        project: String,
    },
    /// Executes bounded exact OSV queries with positional continuation.
    QueryOsv {
        /// Ordered original query positions; repeated identities are rejected.
        queries: Vec<Query>,
        /// Exact admitted per-query scope identities in the same original order.
        projects: Vec<String>,
        /// Prior source-bound continuation tokens, absent on the initial page.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        continuations: Vec<QueryContinuation>,
    },
    /// Retrieves full normalized OSV records named by admitted query pages.
    RetrieveAdvisories {
        /// Exact query/checkpoint scope whose pages supplied these IDs.
        project: String,
        /// Sorted unique source-native advisory IDs, at most ten per task.
        ids: Vec<String>,
    },
    /// Executes an exact versioned NVD CPE query.
    QueryNvd {
        /// Exact admitted query scope, derived from definition and current version.
        project: String,
        /// Explicit product/environment identity, never a guessed package name.
        identity: SecurityIdentity,
        /// Exact assessed upstream version.
        version: String,
        /// Original NVD pagination start position.
        start_index: u32,
    },
    /// Reads one NVD modification checkpoint page with explicit UTC boundaries.
    RefreshNvd {
        /// Inclusive original checkpoint start, including configured overlap.
        modified_start: Timestamp,
        /// Fixed upper checkpoint boundary.
        modified_end: Timestamp,
        /// Original provider start index.
        start_index: u32,
    },
    /// Projects one bounded KEV catalog slice beside the retained source bytes.
    RefreshKev {
        /// Next exact catalog record offset; Native issues every continuation.
        offset: u32,
    },
}

impl ProviderOperation {
    fn supports_project(&self, project: &str) -> bool {
        match self {
            Self::QueryOsv { projects, .. } => {
                projects.iter().any(|candidate| candidate == project)
            }
            Self::RetrieveAdvisories {
                project: candidate, ..
            }
            | Self::QueryNvd {
                project: candidate, ..
            }
            | Self::ObserveRepology { project: candidate } => candidate == project,
            Self::ObserveReleases { repository, .. } | Self::ObserveTags { repository, .. } => {
                repository == project
            }
            Self::ObserveGoReleases => project == "go",
            Self::RefreshNvd { .. } => project == "modifications",
            Self::RefreshKev { .. } => project == "catalog",
        }
    }

    /// Computes the source request identity before any execution effects.
    ///
    /// # Errors
    /// Returns an error for invalid source configuration or canonical bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        Sha256Digest::of_canonical("aos.provider-operation/v1", self)
    }

    /// Returns the installed provider profile used for quota and custody scope.
    #[must_use]
    pub fn provider(&self) -> &'static str {
        match self {
            Self::ObserveReleases { .. } => "github-releases",
            Self::ObserveTags { .. } => "github-tags",
            Self::ObserveGoReleases => "go-releases",
            Self::ObserveRepology { .. } => "repology",
            Self::QueryOsv { .. } | Self::RetrieveAdvisories { .. } => "osv",
            Self::QueryNvd { .. } | Self::RefreshNvd { .. } => "nvd",
            Self::RefreshKev { .. } => "cisa-kev",
        }
    }

    /// Returns the exact installed adapter identity needed by this operation.
    #[must_use]
    pub fn adapter_version(&self) -> &'static str {
        match self {
            Self::ObserveReleases { .. }
            | Self::ObserveTags { .. }
            | Self::ObserveGoReleases
            | Self::ObserveRepology { .. } => aos_assessment_providers::UPSTREAM_ADAPTER_VERSION,
            Self::QueryOsv { .. } | Self::RetrieveAdvisories { .. } => {
                aos_assessment_providers::osv::ADAPTER_VERSION
            }
            Self::QueryNvd { .. } | Self::RefreshNvd { .. } => {
                aos_assessment_providers::nvd::ADAPTER_VERSION
            }
            Self::RefreshKev { .. } => aos_assessment_providers::kev::ADAPTER_VERSION,
        }
    }

    /// Validates typed source configuration without resolving credentials or URLs.
    ///
    /// # Errors
    /// Returns an error for arbitrary paths, invalid identities, page bounds,
    /// duplicate queries, excessive requests or unsupported checkpoint windows.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ObserveReleases {
                repository,
                tag_prefix,
                page,
            }
            | Self::ObserveTags {
                repository,
                tag_prefix,
                page,
            } => {
                text(repository, 256, "GitHub repository")?;
                let parts = repository.split('/').collect::<Vec<_>>();
                if parts.len() != 2
                    || parts.iter().any(|part| {
                        part.is_empty()
                            || matches!(*part, "." | "..")
                            || !part
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
                    })
                    || *page == 0
                    || *page > 10_000
                    || tag_prefix.len() > 128
                    || tag_prefix.chars().any(char::is_control)
                {
                    bail!(
                        "GitHub work requires an exact owner/repository, prefix and bounded page"
                    );
                }
            }
            Self::ObserveGoReleases => {}
            Self::ObserveRepology { project } => {
                text(project, 128, "Repology project")?;
                if !project
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte))
                {
                    bail!("Repology project must not contain paths or query syntax");
                }
            }
            Self::QueryOsv {
                queries,
                projects,
                continuations,
            } => {
                if queries.is_empty()
                    || queries.len() > 64
                    || projects.len() != queries.len()
                    || continuations.len() > queries.len()
                    || continuations
                        .windows(2)
                        .any(|pair| pair[0].position >= pair[1].position)
                {
                    bail!("OSV work has invalid positional query scope");
                }
                for continuation in continuations {
                    if continuation.position as usize >= queries.len() {
                        bail!("OSV continuation has an unknown original position");
                    }
                    text(&continuation.token, 4096, "OSV continuation token")?;
                }
                let mut identities = std::collections::BTreeSet::new();
                for (index, query) in queries.iter().enumerate() {
                    text(&projects[index], 1024, "OSV query scope")?;
                    query.request(
                        continuations
                            .iter()
                            .find(|continuation| continuation.position as usize == index)
                            .map(|continuation| continuation.token.as_str()),
                    )?;
                    if !identities.insert(query.digest()?) {
                        bail!("duplicate OSV work query");
                    }
                }
            }
            Self::RetrieveAdvisories { project, ids } => {
                text(project, 1024, "OSV record query scope")?;
                if ids.is_empty() || ids.len() > 10 {
                    bail!("OSV record retrieval exceeds per-task calls");
                }
                sorted(ids, "OSV retrieval IDs")?;
                for id in ids {
                    text(id, 128, "OSV record ID")?;
                    if !id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_:.".contains(&byte))
                    {
                        bail!("invalid OSV retrieval ID");
                    }
                }
            }
            Self::QueryNvd {
                project,
                identity,
                version,
                start_index,
            } => {
                text(project, 1024, "NVD query scope")?;
                identity.validate()?;
                text(version, 256, "NVD assessed version")?;
                if !matches!(identity, SecurityIdentity::Cpe { .. })
                    || version.bytes().any(|byte| b"*?:\\".contains(&byte))
                    || *start_index > 10_000_000
                {
                    bail!("NVD work requires explicit CPE/version and bounded source position");
                }
            }
            Self::RefreshNvd {
                modified_start,
                modified_end,
                start_index,
            } => {
                let duration = modified_end.elapsed_since(modified_start)?;
                if duration == 0 || duration > 120 * 86400 || *start_index > 10_000_000 {
                    bail!("NVD modification window or page position is invalid");
                }
            }
            Self::RefreshKev { offset } => {
                if *offset >= 20_000 {
                    bail!("KEV projection offset exceeds catalog profile");
                }
            }
        }
        Ok(())
    }
}

/// Grants one short-lived scoped provider attempt without a full inventory body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderWorkPlanV1 {
    /// Exact closed plan discriminator.
    pub schema: String,
    /// Installed deployment identity.
    pub deployment_id: String,
    /// Installed coordinator service identity.
    pub issuer: String,
    /// Installed provider executor identity.
    pub audience: String,
    /// Stable immutable issued plan identity.
    pub plan_id: String,
    /// Exact current journal-issued operation/task/attempt fence.
    pub claim: TaskClaim,
    /// Explicit issuance time.
    pub issued_at: Timestamp,
    /// Exclusive expiry within sixty seconds and the current lease.
    pub expires_at: Timestamp,
    /// Unique unpredictable issued request nonce.
    pub nonce: String,
    /// Frozen inventory context, without copying its full graph.
    pub inventory_digest: Sha256Digest,
    /// Frozen decision policy context.
    pub policy_digest: Sha256Digest,
    /// Tenant/source authority partition validated by the executor.
    pub authorization_partition: String,
    /// Optional installed immutable credential reference; never credential bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Native-issued already reserved shared source allowance.
    pub budget_reservation: BudgetReservation,
    /// Optional exact retained prior bytes and conditional validators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ref: Option<CachedResponse>,
    /// Optional digest of the admitted previous source-bound continuation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<Sha256Digest>,
    /// Exact admitted prior page whose successor authorizes this source position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_ref: Option<ProviderPageV1>,
    /// Closed operation whose endpoint belongs to an installed source profile.
    pub operation: ProviderOperation,
    /// Exact required adapter version checked before any effect.
    pub adapter_version: String,
    /// Tightened per-task profile ceilings.
    pub limits: ProviderLimits,
}

impl ProviderWorkPlanV1 {
    /// Decodes a bounded closed plan and validates its current execution window.
    ///
    /// # Errors
    /// Returns an error for ambiguous/null-bearing JSON, unknown contracts,
    /// excessive scope or expiry. Authentication remains a separate prerequisite.
    pub fn from_slice(bytes: &[u8], now: &Timestamp) -> Result<Self> {
        let plan: Self = decode(bytes, "provider work plan")?;
        plan.validate_at(now)?;
        Ok(plan)
    }

    /// Validates current authority, bounds and adapter before provider effects.
    ///
    /// # Errors
    /// Returns an error for incompatible schema/profile, expiry, invalid claim,
    /// insufficient reservation or malformed source/cache identities.
    pub fn validate_at(&self, now: &Timestamp) -> Result<()> {
        self.claim.validate_at(now)?;
        self.operation.validate()?;
        self.limits.validate()?;
        let follows_page = match &self.operation {
            ProviderOperation::ObserveReleases { page, .. }
            | ProviderOperation::ObserveTags { page, .. } => *page > 1,
            ProviderOperation::QueryOsv { continuations, .. } => !continuations.is_empty(),
            ProviderOperation::QueryNvd { start_index, .. }
            | ProviderOperation::RefreshNvd { start_index, .. } => *start_index > 0,
            ProviderOperation::RefreshKev { offset } => *offset > 0,
            _ => false,
        };
        if follows_page && self.continuation.is_none() {
            bail!("noninitial provider work lacks an admitted source page");
        }
        match (&self.continuation, &self.continuation_ref) {
            (None, None) => {}
            (Some(digest), Some(page)) if page.digest()? == *digest => {
                if page.next.as_ref() != Some(&self.operation) {
                    bail!("provider plan differs from its exact admitted source successor");
                }
            }
            _ => bail!("provider continuation lacks its exact admitted prior page"),
        }
        for value in [
            &self.deployment_id,
            &self.issuer,
            &self.audience,
            &self.plan_id,
            &self.nonce,
            &self.authorization_partition,
            &self.budget_reservation.source_budget,
            &self.budget_reservation.reservation_id,
        ] {
            text(value, 128, "provider work authority reference")?;
        }
        if self.schema != PROVIDER_WORK_PLAN_V1
            || self.adapter_version != self.operation.adapter_version()
            || self.nonce.len() < 32
            || &self.issued_at > now
            || now >= &self.expires_at
            || self.expires_at.elapsed_since(&self.issued_at)? > 60
            || self.expires_at > self.claim.expires_at
            || self.budget_reservation.deadline < self.expires_at
            || self.budget_reservation.deadline > self.claim.expires_at
            || self.budget_reservation.requests == 0
            || self.budget_reservation.requests > 10
            || self.limits.requests > self.budget_reservation.requests
        {
            bail!("provider plan is incompatible, expired or outside its reservation");
        }
        if matches!(&self.operation, ProviderOperation::RetrieveAdvisories {ids, ..} if ids.len() > self.limits.requests as usize)
        {
            bail!("OSV record scope exceeds the current request allowance");
        }
        if let Some(reference) = &self.credential_ref {
            text(reference, 128, "installed credential reference")?;
        }
        if let Some(cache) = &self.cache_ref {
            text(&cache.evidence.origin, 128, "cached response origin")?;
            cache.observation.validate()?;
            if cache.evidence.byte_length > self.limits.response_bytes {
                bail!("cached response exceeds provider bound");
            }
            if cache.observation.digest()? != cache.observation_digest
                || cache.observation.provider != self.operation.provider()
                || !self.operation.supports_project(&cache.observation.project)
                || cache.observation.adapter_version != self.adapter_version
                || cache.observation.request_identity_digest != self.operation.digest()?
                || cache.observation.response_digest != cache.evidence.digest
                || cache.evidence.origin != self.operation.provider()
                || !cache.observation.source_refs.contains(&cache.evidence)
                || cache.observation.validators.as_ref() != Some(&cache.validators)
                || cache.observation.validated_at > self.issued_at
                || matches!(self.operation, ProviderOperation::QueryOsv { .. })
                || matches!(&self.operation, ProviderOperation::RetrieveAdvisories { ids, .. } if ids.len() != 1)
            {
                bail!("cached response differs from its admitted exact source request");
            }
            for value in [&cache.validators.etag, &cache.validators.last_modified]
                .into_iter()
                .flatten()
            {
                text(value, 1024, "cached HTTP validator")?;
            }
        }
        encoded(self)?;
        Ok(())
    }

    /// Computes the exact canonical issued plan identity.
    ///
    /// # Errors
    /// Returns an error for envelope limits or serialization; execution separately
    /// validates time and current journal authority.
    pub fn digest(&self) -> Result<Sha256Digest> {
        encoded(self)?;
        Sha256Digest::of_canonical(PROVIDER_WORK_PLAN_V1, self)
    }
}

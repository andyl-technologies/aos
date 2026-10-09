//! Digest-bound compact provider projections and exact result admission checks.

use anyhow::{Result, bail};
use aos_assessment::advisory::{AdvisoryRecordV1, KnownExploit};
use aos_assessment::discovery::UpstreamObservationV1;
use aos_assessment::observation::{ProviderCoverage, ProviderObservationV1};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use aos_contract::limits::BoundedWriter;
use serde::{Deserialize, Serialize};

use super::{PROVIDER_WORK_RESULT_V1, ProviderOperation, ProviderWorkPlanV1};
use crate::scan::TaskClaim;
use crate::validation::{encoded, sorted, text};

/// Carries one typed compact object; raw provider bodies are never an object kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "object",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum NormalizedObject {
    /// Exact normalized observation with byte custody references.
    Observation(ProviderObservationV1),
    /// Complete source-associated advisory revision.
    Advisory(AdvisoryRecordV1),
    /// Legacy-compatible complete upstream release observation.
    Upstream(UpstreamObservationV1),
    /// One attributed KEV catalog member.
    KnownExploit(KnownExploit),
    /// Source-bound query IDs and continuation; not a complete advisory snapshot.
    Page(super::ProviderPageV1),
}

impl NormalizedObject {
    /// Validates an inline object and computes its exact semantic object digest.
    ///
    /// # Errors
    /// Returns an error for invalid contracts or one record exceeding sixty-four KiB.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value = match self {
            Self::Observation(object) => {
                object.validate()?;
                bounded_value(object)?
            }
            Self::Advisory(object) => {
                object.validate()?;
                bounded_value(object)?
            }
            Self::Upstream(object) => {
                object.validate()?;
                Timestamp::from_unix_seconds(object.retrieved_at_unix)?;
                for candidate in &object.candidates {
                    if let Some(published) = candidate.published_at_unix {
                        Timestamp::from_unix_seconds(published)?;
                    }
                }
                bounded_value(object)?
            }
            Self::KnownExploit(object) => {
                if !aos_assessment::advisory::is_cve_id(&object.cve_id) {
                    bail!("invalid known-exploitation CVE identity");
                }
                text(&object.catalog_version, 128, "KEV catalog revision")?;
                Timestamp::parse(&format!("{}T00:00:00Z", object.date_added))?;
                bounded_value(object)?
            }
            Self::Page(object) => {
                object.validate()?;
                bounded_value(object)?
            }
        };
        if aos_contract::canonical::to_vec(&value)?.len() > 64 * 1024 {
            bail!("normalized object exceeds compact record limit");
        }
        match self {
            Self::Observation(object) => object.digest(),
            Self::Advisory(object) => object.digest(),
            Self::Upstream(object) => {
                Sha256Digest::of_canonical(aos_assessment::UPSTREAM_OBSERVATION_V1, object)
            }
            Self::KnownExploit(object) => {
                Sha256Digest::of_canonical("aos.known-exploit/v1", object)
            }
            Self::Page(object) => object.digest(),
        }
    }
}

fn bounded_value(object: &impl Serialize) -> Result<serde_json::Value> {
    let mut writer =
        BoundedWriter::new(64 * 1024, "normalized object exceeds compact record limit");
    serde_json::to_writer(&mut writer, object)?;
    Ok(serde_json::to_value(object)?)
}

/// Binds compact object bytes to the digest that the coordinator will admit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectProjection {
    /// Exact semantic object identity, checked against the inline content.
    pub digest: Sha256Digest,
    /// Typed bounded normalized object.
    pub object: NormalizedObject,
}

/// Reports the physical invocation outcome separately from assessment coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkOutcome {
    /// Completed one admitted observation/page question.
    Observed,
    /// Revalidated exact admitted cached bytes without replacing source identity.
    NotModified,
    /// Retained useful evidence and a visible limit/error/continuation.
    Partial,
    /// Could not establish the requested provider question.
    Failed,
}

/// Preserves independent physical usage counters for admission and telemetry.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderUsage {
    /// Conservatively consumed provider calls, including uncertain timeouts.
    pub requests: u32,
    /// Original encoded source transfer bytes.
    pub compressed_bytes: u64,
    /// Decoded source bytes before parsing/projection.
    pub decompressed_bytes: u64,
    /// Executor elapsed time, never part of a semantic assessment input.
    pub duration_milliseconds: u32,
}

/// Returns digest-bound compact evidence while raw bytes remain at admitted storage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderWorkResultV1 {
    /// Exact result schema discriminator.
    pub schema: String,
    /// Exact plan body association.
    pub plan_digest: Sha256Digest,
    /// Exact current attempt fence, echoed without authority to change it.
    pub claim: TaskClaim,
    /// Installed executor build identity.
    pub executor_build: String,
    /// Actual shared parser version used.
    pub adapter_version: String,
    /// Physical acquisition outcome, separate from pure matching.
    pub outcome: WorkOutcome,
    /// Typed bounded normalized objects, sorted by exact object digest.
    pub normalized_objects: Vec<ObjectProjection>,
    /// Sorted exact observation objects required by this projection.
    pub observation_refs: Vec<Sha256Digest>,
    /// Source completeness or visible uncertainty.
    pub coverage: ProviderCoverage,
    /// Optional exact source-bound next position requiring a new coordinator plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<Sha256Digest>,
    /// Physical usage checked against the current reservation and limits.
    pub usage: ProviderUsage,
    /// Executor completion time validated within the plan window.
    pub completed_at: Timestamp,
    /// Sorted stable sanitized diagnostic codes; raw response text is absent.
    pub diagnostics: Vec<String>,
}

impl ProviderWorkResultV1 {
    /// Checks exact association, object hashes and independent byte/item/time ceilings.
    ///
    /// # Errors
    /// Returns an error for a changed plan/claim, expired result, unsupported parser,
    /// missing/mismatched projections, changed cache identity or excessive usage.
    pub fn validate_for(&self, plan: &ProviderWorkPlanV1, now: &Timestamp) -> Result<()> {
        plan.validate_at(now)?;
        self.coverage.validate()?;
        text(&self.executor_build, 128, "provider executor build")?;
        if self.schema != PROVIDER_WORK_RESULT_V1
            || self.plan_digest != plan.digest()?
            || self.claim != plan.claim
            || self.adapter_version != plan.adapter_version
            || self.completed_at < plan.issued_at
            || self.completed_at >= plan.expires_at
            || &self.completed_at > now
            || self.normalized_objects.len() > plan.limits.normalized_entries as usize
            || self.observation_refs.len() > 128
            || self.diagnostics.len() > 128
            || self.usage.requests > plan.limits.requests
            || self.usage.decompressed_bytes > plan.limits.source_bytes
            || self.usage.compressed_bytes > plan.limits.source_bytes
            || self.usage.duration_milliseconds > 60_000
            || encoded(self)?.len() > plan.limits.result_bytes as usize
        {
            bail!("provider result differs from current plan, scope or physical limits");
        }
        if self
            .normalized_objects
            .windows(2)
            .any(|pair| pair[0].digest >= pair[1].digest)
        {
            bail!("provider object projections must be sorted and unique");
        }
        let mut observations = std::collections::BTreeSet::new();
        for projection in &self.normalized_objects {
            if projection.digest != projection.object.digest()? {
                bail!("provider projection digest differs from its inline bytes");
            }
            match &projection.object {
                NormalizedObject::Observation(observation) => {
                    if observation.provider != plan.operation.provider()
                        || observation.adapter_version != plan.adapter_version
                        || observation.request_identity_digest != plan.operation.digest()?
                        || observation.validated_at < plan.issued_at
                        || observation.validated_at > self.completed_at
                        || !plan.operation.supports_project(&observation.project)
                    {
                        bail!("normalized observation differs from its exact provider operation");
                    }
                    if self.outcome == WorkOutcome::NotModified {
                        let cache = plan
                            .cache_ref
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("304 lacks admitted prior response"))?;
                        if observation.response_digest != cache.evidence.digest
                            || !observation.source_refs.contains(&cache.evidence)
                            || observation.retrieved_at != cache.observation.retrieved_at
                        {
                            bail!("304 changed the exact retained response identity");
                        }
                    }
                }
                NormalizedObject::Advisory(record) => {
                    if record.provider != plan.operation.provider()
                        || !matches!(
                            plan.operation,
                            ProviderOperation::QueryOsv { .. }
                                | ProviderOperation::RetrieveAdvisories { .. }
                                | ProviderOperation::QueryNvd { .. }
                                | ProviderOperation::RefreshNvd { .. }
                        )
                        || matches!(&plan.operation, ProviderOperation::RetrieveAdvisories {ids, ..} if ids.binary_search(&record.id).is_err())
                    {
                        bail!("advisory projection is outside its admitted provider scope");
                    }
                }
                NormalizedObject::Upstream(observation) => {
                    let project = match &plan.operation {
                        ProviderOperation::ObserveReleases { repository, .. }
                        | ProviderOperation::ObserveTags { repository, .. } => repository.as_str(),
                        ProviderOperation::ObserveRepology { project } => project.as_str(),
                        ProviderOperation::ObserveGoReleases => "go",
                        _ => bail!("upstream projection is outside its operation scope"),
                    };
                    if observation.provider != plan.operation.provider()
                        || observation.project != project
                        || observation.adapter_version != plan.adapter_version
                        || observation.retrieved_at_unix < plan.issued_at.unix_seconds()
                        || observation.retrieved_at_unix > self.completed_at.unix_seconds()
                    {
                        bail!("upstream observation differs from its exact admitted source");
                    }
                    if self.outcome == WorkOutcome::NotModified
                        && plan.cache_ref.as_ref().is_none_or(|cache| {
                            observation.response_digest != cache.evidence.digest
                        })
                    {
                        bail!("304 upstream projection changed its retained response identity");
                    }
                }
                NormalizedObject::KnownExploit(_) => {
                    if !matches!(plan.operation, ProviderOperation::RefreshKev { .. }) {
                        bail!("known-exploitation projection is outside KEV work scope");
                    }
                }
                NormalizedObject::Page(page) => {
                    if page.operation != plan.operation {
                        bail!("source page changed the exact admitted operation");
                    }
                    if self.continuation == Some(projection.digest) && page.next.is_none() {
                        bail!("continuation points to an exhausted source page");
                    }
                }
            }
            if matches!(
                projection.object,
                NormalizedObject::Observation(_) | NormalizedObject::Upstream(_)
            ) {
                observations.insert(projection.digest);
            }
        }
        sorted(&self.observation_refs, "provider observation references")?;
        for projection in &self.normalized_objects {
            let source = match &projection.object {
                NormalizedObject::Advisory(record) => Some(record.source_digest),
                NormalizedObject::KnownExploit(record) => Some(record.source_digest),
                NormalizedObject::Page(page) => Some(page.source_digest),
                _ => None,
            };
            if let Some(source) = source
                && !self
                    .normalized_objects
                    .iter()
                    .any(|candidate| match &candidate.object {
                        NormalizedObject::Observation(observation) => observation
                            .source_refs
                            .iter()
                            .any(|reference| reference.digest == source),
                        NormalizedObject::Upstream(observation) => {
                            observation.response_digest == source
                        }
                        _ => false,
                    })
            {
                bail!("provider projection lacks its exact normalized source custody reference");
            }
        }
        if let ProviderCoverage::Partial { continuation, .. } = &self.coverage
            && continuation != &self.continuation
        {
            bail!("provider coverage differs from its retained continuation identity");
        }
        if let Some(continuation) = self.continuation
            && !self.normalized_objects.iter().any(|projection| {
                projection.digest == continuation
                    && matches!(&projection.object, NormalizedObject::Page(page) if page.next.is_some())
            })
        {
            bail!("provider continuation lacks its exact retained source page");
        }
        if self
            .observation_refs
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            != observations
        {
            bail!("provider result differs from required inline observation projections");
        }
        sorted(&self.diagnostics, "provider result diagnostics")?;
        for diagnostic in &self.diagnostics {
            text(diagnostic, 128, "provider diagnostic code")?;
        }
        if self.outcome == WorkOutcome::NotModified && plan.cache_ref.is_none() {
            bail!("304 observation lacks exact admitted cached bytes");
        }
        if self.outcome == WorkOutcome::Observed && !self.coverage.is_complete() {
            bail!("observed outcome lacks complete source coverage");
        }
        if self.outcome == WorkOutcome::Observed && self.continuation.is_some() {
            bail!("complete provider result retains an unconsumed source continuation");
        }
        if self.outcome == WorkOutcome::Observed && self.normalized_objects.is_empty() {
            bail!("observed outcome lacks normalized source evidence");
        }
        if self.outcome == WorkOutcome::Failed && self.diagnostics.is_empty() {
            bail!("failed provider outcome lacks a diagnostic");
        }
        Ok(())
    }
}

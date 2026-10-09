//! Shared physical acquisition, evidence custody and compact source normalization.
//!
//! Installed HTTP ports own credentials, bounded streaming and physical timers.
//! This executor owns request selection, parser dispatch, conditional evidence
//! identity and continuation semantics for every execution placement.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use aos_assessment::discovery::{ObservationCandidate, ObservationCoverage, UpstreamObservationV1};
use aos_assessment::observation::{
    HttpValidators, PROVIDER_OBSERVATION_V1, ProviderCoverage, ProviderObservationV1,
    SourceEvidenceRef,
};
use aos_assessment::time::Timestamp;
use aos_assessment_providers::{kev, nvd, osv, upstream};
use aos_contract::Sha256Digest;

use super::{
    AdvisoryRevisionReference, NormalizedObject, ObjectProjection, PROVIDER_WORK_RESULT_V1,
    ProviderOperation, ProviderPageV1, ProviderUsage, ProviderWorkPlanV1, ProviderWorkResultV1,
    QueryContinuation, SourceRequest, WorkOutcome,
};
use crate::ports::{Clock, EvidenceStore, RuntimeBounds};

/// Supplies one bounded HTTP response without exposing credentials or redirects.
#[derive(Clone, Debug)]
pub struct SourceResponse {
    /// Exact HTTP status, including conditional revalidation and source failures.
    pub status: u16,
    /// Decoded bytes streamed under the plan's independent response ceiling.
    pub body: Vec<u8>,
    /// Actual encoded bytes consumed by the transport, before any decompression.
    pub transferred_bytes: u64,
    /// Safe conditional validators from the final installed source response.
    pub validators: Option<HttpValidators>,
}

/// Executes only requests selected by an authenticated installed source profile.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SourceTransport: RuntimeBounds {
    /// Streams one request under the plan's physical byte and time limits.
    ///
    /// Implementations resolve scoped credential references independently,
    /// disable redirects and enforce connection, request and streaming limits.
    /// Conditional headers come exclusively from the admitted cache reference.
    ///
    /// # Errors
    /// Returns an error for unsupported profiles, revoked credentials, unsafe
    /// destinations, physical timeouts, unavailable sources or excessive bytes.
    async fn fetch(
        &self,
        plan: &ProviderWorkPlanV1,
        request: &SourceRequest,
    ) -> Result<SourceResponse>;
}

/// Acquires and normalizes one already authenticated, admitted provider attempt.
///
/// The caller rechecks journal authority before and after this operation.
/// Responses remain in evidence custody; only bounded semantic projections are
/// returned. OSV query IDs establish enumeration, never full-record coverage.
/// The coordinator must independently acquire and verify those revisions.
///
/// # Errors
/// Returns an error for expired plans, unsupported or malformed responses,
/// missing cached custody, conflicting evidence identities or physical limits.
pub async fn execute_source<T: SourceTransport, E: EvidenceStore, C: Clock>(
    transport: &T,
    evidence: &E,
    clock: &C,
    plan: &ProviderWorkPlanV1,
    executor_build: &str,
    observation_ttl_seconds: u32,
) -> Result<ProviderWorkResultV1> {
    plan.validate_at(&clock.now()?)?;
    if observation_ttl_seconds == 0 || observation_ttl_seconds > 86_400 {
        bail!("source observation TTL exceeds installed bounds");
    }
    let requests = plan.operation.source_requests()?;
    if requests.len() > plan.limits.requests as usize
        || requests.len() > plan.budget_reservation.requests as usize
    {
        bail!("source requests exceed the consumed reservation");
    }

    let mut usage = ProviderUsage::default();
    let mut objects = Vec::new();
    let mut diagnostics = BTreeSet::new();
    let mut continuation = None;
    let mut outcome = WorkOutcome::Observed;
    let mut coverage = complete();
    for request in requests {
        plan.validate_at(&clock.now()?)?;
        // No retries occur here: another physical invocation needs a newly
        // admitted quota reservation and attempt, including uncertain timeouts.
        usage.requests += 1;
        let response = transport.fetch(plan, &request).await?;
        let validated_at = clock.now()?;
        plan.validate_at(&validated_at)?;
        if response.body.len() as u64 > plan.limits.response_bytes {
            bail!("source response exceeds the per-response byte ceiling");
        }
        usage.compressed_bytes = usage
            .compressed_bytes
            .checked_add(response.transferred_bytes)
            .context("source transfer counter overflow")?;
        usage.decompressed_bytes = usage
            .decompressed_bytes
            .checked_add(response.body.len() as u64)
            .context("source decode counter overflow")?;
        if usage.compressed_bytes > plan.limits.source_bytes
            || usage.decompressed_bytes > plan.limits.source_bytes
        {
            bail!("source invocation exceeds aggregate byte ceilings");
        }

        let (bytes, source, retrieved_at, validators) = if response.status == 304 {
            let cache = plan
                .cache_ref
                .as_ref()
                .context("304 lacks admitted cache")?;
            if !response.body.is_empty() {
                bail!("conditional response contains unexpected source bytes");
            }
            let bytes = evidence
                .read(
                    &plan.authorization_partition,
                    cache.evidence.digest,
                    plan.limits.response_bytes,
                )
                .await?;
            if bytes.len() as u64 != cache.evidence.byte_length
                || Sha256Digest::of_bytes(&bytes) != cache.evidence.digest
            {
                bail!("conditional evidence custody differs from admitted bytes");
            }
            outcome = WorkOutcome::NotModified;
            (
                bytes,
                cache.evidence.clone(),
                cache.observation.retrieved_at.clone(),
                Some(cache.validators.clone()),
            )
        } else {
            let digest = evidence
                .retain(&plan.authorization_partition, &response.body)
                .await?;
            if digest != Sha256Digest::of_bytes(&response.body) {
                bail!("evidence custody returned a different source identity");
            }
            let source = SourceEvidenceRef {
                digest,
                byte_length: response.body.len() as u64,
                origin: plan.operation.provider().into(),
            };
            (
                response.body,
                source,
                validated_at.clone(),
                response.validators,
            )
        };
        let expires_at = Timestamp::from_unix_seconds(
            validated_at
                .unix_seconds()
                .checked_add(u64::from(observation_ttl_seconds))
                .context("source observation expiry overflow")?,
        )?;

        let mut projection = if response.status == 200 || response.status == 304 {
            normalize(plan, &request, &bytes, &retrieved_at)?
        } else {
            outcome = WorkOutcome::Failed;
            diagnostics.insert(format!("source-http-{}", response.status));
            Projection {
                objects: vec![],
                projects: operation_projects(&plan.operation),
                coverage: ProviderCoverage::Unknown {
                    reason: format!("source-http-{}", response.status),
                },
                continuation: None,
            }
        };
        if !projection.coverage.is_complete() {
            coverage = projection.coverage.clone();
            if outcome == WorkOutcome::Observed {
                outcome = WorkOutcome::Partial;
            }
        }
        if let Some(next) = projection.continuation
            && continuation
                .replace(next)
                .is_some_and(|previous| previous != next)
        {
            bail!("source invocation produced conflicting continuation identities");
        }
        let payload_digest =
            Sha256Digest::of_canonical("aos.provider-projection/v1", &projection.objects)?;
        for project in projection.projects {
            projection
                .objects
                .push(NormalizedObject::Observation(ProviderObservationV1 {
                    schema: PROVIDER_OBSERVATION_V1.into(),
                    provider: plan.operation.provider().into(),
                    project,
                    adapter_version: plan.adapter_version.clone(),
                    request_identity_digest: plan.operation.digest()?,
                    retrieved_at: retrieved_at.clone(),
                    validated_at: validated_at.clone(),
                    expires_at: expires_at.clone(),
                    response_digest: source.digest,
                    payload_digest,
                    validators: validators.clone(),
                    coverage: projection.coverage.clone(),
                    source_refs: vec![source.clone()],
                }));
        }
        objects.extend(projection.objects);
    }
    let completed_at = clock.now()?;
    usage.duration_milliseconds =
        u32::try_from(completed_at.elapsed_since(&plan.issued_at)? * 1000)?;
    let mut normalized_objects = objects
        .into_iter()
        .map(|object| {
            Ok(ObjectProjection {
                digest: object.digest()?,
                object,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    normalized_objects.sort_by_key(|projection| projection.digest);
    normalized_objects.dedup_by_key(|projection| projection.digest);
    let observation_refs = normalized_objects
        .iter()
        .filter_map(|projection| {
            matches!(
                projection.object,
                NormalizedObject::Observation(_) | NormalizedObject::Upstream(_)
            )
            .then_some(projection.digest)
        })
        .collect();
    let result = ProviderWorkResultV1 {
        schema: PROVIDER_WORK_RESULT_V1.into(),
        plan_digest: plan.digest()?,
        claim: plan.claim.clone(),
        executor_build: executor_build.into(),
        adapter_version: plan.adapter_version.clone(),
        outcome,
        normalized_objects,
        observation_refs,
        coverage,
        continuation,
        usage,
        completed_at,
        diagnostics: diagnostics.into_iter().collect(),
    };
    result.validate_for(plan, &clock.now()?)?;
    Ok(result)
}

struct Projection {
    objects: Vec<NormalizedObject>,
    projects: Vec<String>,
    coverage: ProviderCoverage,
    continuation: Option<Sha256Digest>,
}

fn normalize(
    plan: &ProviderWorkPlanV1,
    request: &SourceRequest,
    bytes: &[u8],
    retrieved_at: &Timestamp,
) -> Result<Projection> {
    let operation = &plan.operation;
    let source_digest = Sha256Digest::of_bytes(bytes);
    let mut projection = Projection {
        objects: vec![],
        projects: operation_projects(operation),
        coverage: complete(),
        continuation: None,
    };
    match operation {
        ProviderOperation::QueryOsv {
            queries, projects, ..
        } => {
            let pages = osv::batch_pages(bytes, request.original_positions.len())?;
            let continuations = pages
                .iter()
                .zip(&request.original_positions)
                .filter_map(|(page, position)| {
                    page.next_page_token
                        .as_ref()
                        .map(|token| QueryContinuation {
                            position: *position,
                            token: token.clone(),
                        })
                })
                .collect::<Vec<_>>();
            let next = (!continuations.is_empty()).then(|| ProviderOperation::QueryOsv {
                queries: queries.clone(),
                projects: projects.clone(),
                continuations,
            });
            projection.projects = request
                .original_positions
                .iter()
                .map(|position| projects[*position as usize].clone())
                .collect();
            // Every query page is persisted even if it is empty. Nonempty IDs
            // cannot become clean evidence before their full revisions exist.
            let needs_records = pages.iter().any(|page| !page.records.is_empty());
            for (page, position) in pages.into_iter().zip(&request.original_positions) {
                add_page(
                    &mut projection,
                    operation,
                    &projects[*position as usize],
                    source_digest,
                    page.records
                        .into_iter()
                        .map(|(id, modified)| AdvisoryRevisionReference { id, modified })
                        .collect(),
                    next.clone(),
                )?;
            }
            if needs_records && next.is_none() {
                projection.coverage = ProviderCoverage::Partial {
                    reason: "osv-full-records-required".into(),
                    continuation: None,
                };
            }
        }
        ProviderOperation::RetrieveAdvisories { ids, .. } => {
            let record = osv::record(bytes)?;
            // A source redirect or wrong record cannot substitute an advisory
            // with a different ID merely because it was included in the batch.
            let requested_id = request
                .url
                .path_segments()
                .and_then(Iterator::last)
                .context("OSV request lacks record ID")?;
            let decoded_id = ids
                .iter()
                .find(|id| {
                    let mut url = request.url.clone();
                    url.path_segments_mut()
                        .map(|mut segments| {
                            segments.pop().push(id);
                        })
                        .is_ok()
                        && url == request.url
                })
                .context("OSV request differs from admitted ID")?;
            if record.id != *decoded_id || requested_id.is_empty() {
                bail!("OSV returned a different full-record identity");
            }
            projection.objects.push(NormalizedObject::Advisory(record));
        }
        ProviderOperation::QueryNvd { start_index, .. }
        | ProviderOperation::RefreshNvd { start_index, .. } => {
            let page = nvd::page(bytes, u64::from(*start_index))?;
            let next = page
                .next_start_index
                .map(|position| {
                    let mut next = operation.clone();
                    match &mut next {
                        ProviderOperation::QueryNvd { start_index, .. }
                        | ProviderOperation::RefreshNvd { start_index, .. } => {
                            *start_index = u32::try_from(position)?
                        }
                        _ => bail!("NVD successor differs from source operation"),
                    }
                    Ok(next)
                })
                .transpose()?;
            let references = page
                .records
                .iter()
                .map(|record| AdvisoryRevisionReference {
                    id: record.id.clone(),
                    modified: record.modified.clone(),
                })
                .collect();
            projection
                .objects
                .extend(page.records.into_iter().map(NormalizedObject::Advisory));
            let project = projection.projects[0].clone();
            add_page(
                &mut projection,
                operation,
                &project,
                source_digest,
                references,
                next,
            )?;
        }
        ProviderOperation::RefreshKev { offset } => {
            if plan
                .continuation_ref
                .as_ref()
                .is_some_and(|page| page.source_digest != source_digest)
            {
                // A changed sort order across catalog revisions can skip CVEs.
                // Restarting is coordinator work, never a silent offset reuse.
                bail!("KEV catalog changed during retained source enumeration");
            }
            let records = kev::catalog(bytes)?;
            let start = *offset as usize;
            if start > records.len() {
                bail!("KEV continuation exceeds retained catalog");
            }
            let end = start.saturating_add(20).min(records.len());
            let references = records[start..end]
                .iter()
                .map(|record| AdvisoryRevisionReference {
                    id: record.cve_id.clone(),
                    modified: record.catalog_version.clone(),
                })
                .collect();
            projection.objects.extend(
                records[start..end]
                    .iter()
                    .cloned()
                    .map(NormalizedObject::KnownExploit),
            );
            let next = (end < records.len())
                .then_some(ProviderOperation::RefreshKev { offset: end as u32 });
            add_page(
                &mut projection,
                operation,
                "catalog",
                source_digest,
                references,
                next,
            )?;
        }
        _ => {
            let now = retrieved_at.unix_seconds();
            let (mut candidates, next) = match operation {
                ProviderOperation::ObserveReleases {
                    repository,
                    tag_prefix,
                    page,
                } => (
                    upstream::github_releases(bytes, tag_prefix, now)?,
                    github_next(bytes, *page)?.map(|page| ProviderOperation::ObserveReleases {
                        repository: repository.clone(),
                        tag_prefix: tag_prefix.clone(),
                        page,
                    }),
                ),
                ProviderOperation::ObserveTags {
                    repository,
                    tag_prefix,
                    page,
                } => (
                    upstream::github_tags(bytes, repository, tag_prefix, now)?,
                    github_next(bytes, *page)?.map(|page| ProviderOperation::ObserveTags {
                        repository: repository.clone(),
                        tag_prefix: tag_prefix.clone(),
                        page,
                    }),
                ),
                ProviderOperation::ObserveGoReleases => (upstream::go_releases(bytes, now)?, None),
                ProviderOperation::ObserveRepology { project } => (
                    upstream::repology(bytes, project, &BTreeSet::new())?
                        .into_iter()
                        .map(|candidate| ObservationCandidate {
                            raw_id: candidate.raw_id,
                            raw_version: candidate.raw_version,
                            published_at_unix: None,
                            first_observed_at_unix: now,
                            prerelease: false,
                            yanked: candidate.yanked,
                            release_url: None,
                            status: candidate.status,
                            vulnerable: candidate.vulnerable,
                            licenses: candidate.licenses,
                        })
                        .collect(),
                    None,
                ),
                _ => bail!("source operation has no installed normalization profile"),
            };
            candidates.sort_by(|left, right| left.raw_id.cmp(&right.raw_id));
            if candidates
                .windows(2)
                .any(|pair| pair[0].raw_id == pair[1].raw_id)
            {
                bail!("upstream source repeats candidate identities");
            }
            let project = projection.projects[0].clone();
            let upstream_coverage = if next.is_some() {
                ObservationCoverage::Truncated {
                    reason: "source-pagination-required".into(),
                }
            } else {
                ObservationCoverage::Complete
            };
            projection
                .objects
                .push(NormalizedObject::Upstream(UpstreamObservationV1 {
                    schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
                    provider: operation.provider().into(),
                    project: project.clone(),
                    retrieved_at_unix: now,
                    request_url: request.url.to_string(),
                    adapter_version: plan.adapter_version.clone(),
                    coverage: upstream_coverage,
                    response_digest: source_digest,
                    candidates,
                }));
            if next.is_some() {
                add_page(
                    &mut projection,
                    operation,
                    &project,
                    source_digest,
                    vec![],
                    next,
                )?;
            }
        }
    }
    Ok(projection)
}

fn add_page(
    projection: &mut Projection,
    operation: &ProviderOperation,
    project: &str,
    source_digest: Sha256Digest,
    mut records: Vec<AdvisoryRevisionReference>,
    next: Option<ProviderOperation>,
) -> Result<()> {
    records.sort();
    let page = ProviderPageV1 {
        schema: "aos.provider-page/v1".into(),
        operation: operation.clone(),
        project: project.into(),
        source_digest,
        records,
        next,
    };
    let digest = page.digest()?;
    // OSV has one exact successor containing all remaining original positions.
    // Only its first retained page is used as the continuation anchor.
    if page.next.is_some() && projection.continuation.is_none() {
        projection.continuation = Some(digest);
        projection.coverage = ProviderCoverage::Partial {
            reason: "source-pagination-required".into(),
            continuation: Some(digest),
        };
    }
    projection.objects.push(NormalizedObject::Page(page));
    Ok(())
}

fn operation_projects(operation: &ProviderOperation) -> Vec<String> {
    match operation {
        ProviderOperation::ObserveReleases { repository, .. }
        | ProviderOperation::ObserveTags { repository, .. } => vec![repository.clone()],
        ProviderOperation::ObserveGoReleases => vec!["go".into()],
        ProviderOperation::ObserveRepology { project }
        | ProviderOperation::RetrieveAdvisories { project, .. }
        | ProviderOperation::QueryNvd { project, .. } => vec![project.clone()],
        ProviderOperation::QueryOsv { projects, .. } => projects.clone(),
        ProviderOperation::RefreshNvd { .. } => vec!["modifications".into()],
        ProviderOperation::RefreshKev { .. } => vec!["catalog".into()],
    }
}

fn complete() -> ProviderCoverage {
    ProviderCoverage::Complete {
        proof: "installed-source-enumeration-exhausted".into(),
    }
}

fn github_next(bytes: &[u8], page: u32) -> Result<Option<u32>> {
    let count = upstream::github_page_length(bytes)?;
    if count > 20 {
        bail!("GitHub response exceeds the exact requested page size");
    }
    if count == 20 {
        Ok(Some(page.checked_add(1).context("GitHub page overflow")?))
    } else {
        Ok(None)
    }
}

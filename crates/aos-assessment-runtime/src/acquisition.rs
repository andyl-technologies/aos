//! Shared acquisition planning and source-chain assembly for all execution modes.
//!
//! Packages select installed providers through their immutable definitions.
//! [`AcquisitionPort`] admits each bounded physical invocation, including every
//! continuation and full OSV record retrieval. This module composes coverage
//! only after the entire source chain and exact advisory revisions are present.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

mod checkpoint;
use aos_assessment::advisory::{
    ADVISORY_SNAPSHOT_V1, AdvisoryRecordV1, AdvisorySnapshotSource, AdvisorySnapshotV1,
};
use aos_assessment::discovery::ObservationCoverage;
use aos_assessment::evaluator::ScopeGraph;
use aos_assessment::input::{CandidateHistory, EvaluationData, Profile, UpstreamBinding};
use aos_assessment::inventory::DiscoveryProvider;
use aos_assessment::observation::{ProviderCoverage, ProviderObservationV1, SourceEvidenceRef};
use aos_assessment::security::SecurityIdentity;
use aos_assessment::time::Timestamp;
use aos_assessment_providers::osv::Query;
use aos_contract::Sha256Digest;
pub use checkpoint::AcquisitionCheckpointV1;

use crate::ports::{EvidenceStore, RuntimeBounds};
use crate::provider::{NormalizedObject, ProviderOperation, ProviderPageV1, ProviderWorkResultV1};

/// Admits one scoped invocation and its result through the deployment journal.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AcquisitionPort: RuntimeBounds {
    /// Checks current operation authority before beginning another source question.
    ///
    /// Hosts may reject cancellation or a lost local process lease immediately.
    /// Implementations still fence individual physical reservations and results.
    ///
    /// # Errors
    /// Returns an error when the operation may no longer acquire evidence.
    async fn require_current(&self) -> Result<()> {
        Ok(())
    }

    /// Reads a previously journal-admitted acquisition cursor, if present.
    ///
    /// # Errors
    /// Returns an error for unavailable custody or an invalid retained checkpoint.
    async fn acquisition_checkpoint(&self) -> Result<Option<AcquisitionCheckpointV1>> {
        Ok(None)
    }

    /// Pins a bounded acquisition cursor before releasing a host quantum.
    ///
    /// # Errors
    /// Returns an error for unsupported persistence, lost authority or failed custody.
    async fn save_acquisition_checkpoint(&self, _: &AcquisitionCheckpointV1) -> Result<()> {
        bail!("acquisition host cannot retain a resumable checkpoint")
    }

    /// Executes exact work after reserving quota and checking current authority.
    ///
    /// Implementations validate the result against their issued plan, retain
    /// custody, and admit the result before returning it. Every continuation is
    /// a new invocation; neither this interface nor the driver retries failures.
    ///
    /// # Errors
    /// Returns an error for stale authority, exhausted budgets, unavailable
    /// sources, invalid continuations or failed result admission. A resumable
    /// host returns [`AcquisitionPaused`] before another physical effect when its
    /// invocation quantum is exhausted; this never becomes incomplete coverage.
    async fn invoke(
        &self,
        operation: &ProviderOperation,
        previous: Option<&ProviderPageV1>,
    ) -> Result<ProviderWorkResultV1>;
}

/// Requests journal-backed continuation before another physical source effect.
///
/// Hosts preserve independently admitted results and release their current
/// coordinator lease. The next invocation reconstructs the same source chain
/// from those immutable results without reserving their quota again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquisitionPaused;

impl std::fmt::Display for AcquisitionPaused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("assessment acquisition requires another bounded invocation")
    }
}

impl std::error::Error for AcquisitionPaused {}

/// Describes one deduplicated provider question and its exact component consumers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AcquisitionJob {
    /// Typed source operation derived from immutable package declarations.
    pub operation: ProviderOperation,
    /// Exact component instances that share this upstream question.
    pub component_refs: Vec<String>,
}

/// Plans source questions for the selected subjects without network effects.
///
/// Runtime and containment edges follow the same graph as deterministic
/// assessment; build-only dependencies do not introduce vulnerability scope.
/// Unsupported mappings remain evaluator-visible gaps instead of guessed URLs.
///
/// # Errors
/// Returns an error for invalid closure/selection, conflicting query scopes,
/// absent definitions or more than 4096 distinct initial provider questions.
pub fn plan_acquisition(
    data: &EvaluationData,
    subjects: &[String],
    profiles: &[Profile],
) -> Result<Vec<AcquisitionJob>> {
    data.inventory.validate()?;
    let graph = ScopeGraph::new(data)?;
    let definitions = data
        .definitions
        .iter()
        .map(|definition| Ok((definition.digest()?, definition)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut selected = BTreeMap::new();
    for subject in subjects {
        for component in graph.components(subject)? {
            selected.insert(component.component_ref.as_str(), component);
        }
    }
    let mut jobs = BTreeMap::<Sha256Digest, AcquisitionJob>::new();
    let mut scopes = BTreeMap::new();
    for component in selected.into_values() {
        let definition = definitions
            .get(&component.scan_definition_digest)
            .context("acquisition component definition is absent")?;
        let declaration = definition
            .components
            .iter()
            .find(|declared| declared.component_id == component.component_id)
            .context("acquisition component is absent from its definition")?;
        if profiles.contains(&Profile::Updates) || profiles.contains(&Profile::LicenseSignals) {
            for provider in declaration
                .discovery
                .primary
                .iter()
                .chain(&declaration.discovery.advisors)
            {
                let operation = match provider {
                    DiscoveryProvider::GithubReleases {
                        repository,
                        tag_prefix,
                    } => ProviderOperation::ObserveReleases {
                        repository: repository.clone(),
                        tag_prefix: tag_prefix.clone(),
                        page: 1,
                    },
                    DiscoveryProvider::GithubTags {
                        repository,
                        tag_prefix,
                    } => ProviderOperation::ObserveTags {
                        repository: repository.clone(),
                        tag_prefix: tag_prefix.clone(),
                        page: 1,
                    },
                    DiscoveryProvider::GoReleases => ProviderOperation::ObserveGoReleases,
                    DiscoveryProvider::Repology { project } => ProviderOperation::ObserveRepology {
                        project: project.clone(),
                    },
                };
                insert_job(&mut jobs, operation, &component.component_ref)?;
            }
        }
        if !profiles.contains(&Profile::Vulnerabilities) {
            continue;
        }
        for mapping in &component.security.advisory_sources {
            for identity in &component.security.identities {
                let version = &component.current.comparison_version;
                let project =
                    mapping
                        .project
                        .clone()
                        .unwrap_or(aos_assessment::findings::query_scope(
                            &mapping.provider,
                            identity,
                            version,
                        )?);
                let operation = match (mapping.provider.as_str(), identity) {
                    ("nvd", SecurityIdentity::Cpe { .. }) => ProviderOperation::QueryNvd {
                        project: project.clone(),
                        identity: identity.clone(),
                        version: version.clone(),
                        start_index: 0,
                    },
                    ("osv", SecurityIdentity::Ecosystem { ecosystem, name }) => osv_operation(
                        &project,
                        Query::Ecosystem {
                            ecosystem: ecosystem.clone(),
                            name: name.clone(),
                            version: version.clone(),
                        },
                    ),
                    ("osv", SecurityIdentity::Purl { value }) => osv_operation(
                        &project,
                        Query::Purl {
                            value: value.clone(),
                        },
                    ),
                    ("osv", SecurityIdentity::Git { commit, .. }) => osv_operation(
                        &project,
                        Query::Git {
                            commit: commit.clone(),
                        },
                    ),
                    _ => continue,
                };
                let digest = operation.digest()?;
                if scopes
                    .insert((mapping.provider.clone(), project), digest)
                    .is_some_and(|previous| previous != digest)
                {
                    bail!(
                        "declared advisory query scope maps to conflicting product/version questions"
                    );
                }
                insert_job(&mut jobs, operation, &component.component_ref)?;
            }
        }
    }
    for job in jobs.values_mut() {
        job.component_refs.sort();
        job.component_refs.dedup();
    }
    Ok(jobs.into_values().collect())
}

fn osv_operation(project: &str, query: Query) -> ProviderOperation {
    ProviderOperation::QueryOsv {
        queries: vec![query],
        projects: vec![project.into()],
        continuations: vec![],
    }
}

fn insert_job(
    jobs: &mut BTreeMap<Sha256Digest, AcquisitionJob>,
    operation: ProviderOperation,
    component: &str,
) -> Result<()> {
    let digest = operation.digest()?;
    jobs.entry(digest)
        .or_insert_with(|| AcquisitionJob {
            operation,
            component_refs: vec![],
        })
        .component_refs
        .push(component.into());
    if jobs.len() > 4096 {
        bail!("acquisition exceeds the bounded initial source question count");
    }
    Ok(())
}

/// Refreshes declared source questions while preserving positive cached evidence.
///
/// A failed refresh marks an existing source incomplete and retains its records.
/// Initial failures leave an explicit missing-source gap. Source chains are
/// bounded to 64 pages and OSV IDs require exact full modification revisions.
/// This function never turns HTTP success, IDs alone or a partial page into a
/// clean coverage claim.
///
/// # Errors
/// Returns an error for invalid planning, custody failure, conflicting normalized
/// revisions or an invalid assembled closure. Individual source failures become
/// bounded diagnostics and conservative coverage gaps.
pub async fn acquire<P: AcquisitionPort, E: EvidenceStore>(
    port: &P,
    evidence: &E,
    partition: &str,
    data: &mut EvaluationData,
    subjects: &[String],
    profiles: &[Profile],
) -> Result<Vec<String>> {
    let jobs = plan_acquisition(data, subjects, profiles)?;
    acquire_jobs(port, evidence, partition, data, jobs, subjects, profiles).await
}

/// Acquires only missing, incomplete or expired exact declared source questions.
///
/// Freshness uses explicit evaluation time and the pinned policy. Unsupported
/// or partially enumerated answers never suppress a refresh.
///
/// # Errors
/// Returns an error for invalid planning, future evidence, custody failure or
/// an inconsistent assembled closure; source failures remain visible gaps.
pub async fn acquire_stale<P: AcquisitionPort, E: EvidenceStore>(
    port: &P,
    evidence: &E,
    partition: &str,
    data: &mut EvaluationData,
    subjects: &[String],
    profiles: &[Profile],
    now: &Timestamp,
) -> Result<Vec<String>> {
    let mut jobs = Vec::new();
    for job in plan_acquisition(data, subjects, profiles)? {
        if !job_is_fresh(data, &job, now)? {
            jobs.push(job);
        }
    }
    acquire_jobs(port, evidence, partition, data, jobs, subjects, profiles).await
}

fn job_is_fresh(data: &EvaluationData, job: &AcquisitionJob, now: &Timestamp) -> Result<bool> {
    let projects = match &job.operation {
        ProviderOperation::QueryOsv { projects, .. } => Some(("osv", projects.clone())),
        ProviderOperation::QueryNvd { project, .. } => Some(("nvd", vec![project.clone()])),
        _ => None,
    };
    if let Some((provider, projects)) = projects {
        let Some(snapshot) = &data.advisory_snapshot else {
            return Ok(false);
        };
        for project in projects {
            let Some(source) = snapshot
                .sources
                .iter()
                .find(|source| source.provider == provider && source.project == project)
            else {
                return Ok(false);
            };
            if !source.observation.coverage.is_complete()
                || !source.observation.is_fresh_at(now)?
                || now.elapsed_since(&source.observation.validated_at)?
                    > data.policy.advisory_max_age_seconds
            {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    for component in &job.component_refs {
        let Some(binding) = data.upstream.iter().find(|binding| {
            &binding.component_ref == component
                && matches_upstream(
                    &job.operation,
                    &binding.observation.provider,
                    &binding.observation.project,
                )
        }) else {
            return Ok(false);
        };
        let acquired = Timestamp::from_unix_seconds(binding.validated_at_unix())?;
        if binding.observation.coverage != ObservationCoverage::Complete
            || now.elapsed_since(&acquired)? >= data.policy.upstream_max_age_seconds
            || binding
                .expires_at_unix()
                .is_some_and(|expires| now.unix_seconds() >= expires)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn acquire_jobs<P: AcquisitionPort, E: EvidenceStore>(
    port: &P,
    evidence: &E,
    partition: &str,
    data: &mut EvaluationData,
    mut jobs: Vec<AcquisitionJob>,
    subjects: &[String],
    profiles: &[Profile],
) -> Result<Vec<String>> {
    let mut position = 0;
    let mut source_progress = None;
    let mut diagnostics = BTreeSet::new();
    if let Some(checkpoint) = port.acquisition_checkpoint().await? {
        checkpoint.require_scope(partition, data, subjects, profiles)?;
        position = checkpoint.position;
        jobs = checkpoint.jobs;
        source_progress = checkpoint.source;
        diagnostics.extend(checkpoint.diagnostics);
        *data = checkpoint.data;
    }
    if profiles.contains(&Profile::Vulnerabilities) && data.advisory_snapshot.is_none() {
        data.advisory_snapshot = Some(AdvisorySnapshotV1 {
            schema: ADVISORY_SNAPSHOT_V1.into(),
            sources: vec![],
            exploit_catalog: None,
        });
    }
    for (index, job) in jobs.iter().enumerate().skip(position) {
        port.require_current().await?;
        let advisory = matches!(
            job.operation,
            ProviderOperation::QueryOsv { .. } | ProviderOperation::QueryNvd { .. }
        );
        let chain = match collect_chain(port, &job.operation, source_progress.take()).await {
            ChainOutcome::Settled(chain) => chain,
            ChainOutcome::Paused(source) => {
                let checkpoint = AcquisitionCheckpointV1::new(
                    partition,
                    data.clone(),
                    jobs.clone(),
                    (subjects, profiles),
                    (index, source),
                    diagnostics.iter().cloned().collect(),
                );
                port.save_acquisition_checkpoint(&checkpoint).await?;
                return Err(AcquisitionPaused.into());
            }
        };
        if !chain.complete {
            diagnostics.insert("source-acquisition-incomplete".into());
        }
        if advisory && !chain.observations.is_empty() {
            install_advisories(data, chain)?;
        } else if chain.complete
            || (!advisory
                && chain
                    .objects
                    .iter()
                    .any(|object| matches!(object, NormalizedObject::Upstream(_))))
        {
            install_upstream(data, evidence, partition, job, chain).await?;
        } else {
            if advisory {
                mark_cached_advisory_incomplete(data, &job.operation);
            } else {
                for binding in &mut data.upstream {
                    if job.component_refs.contains(&binding.component_ref)
                        && matches_upstream(
                            &job.operation,
                            &binding.observation.provider,
                            &binding.observation.project,
                        )
                    {
                        binding.observation.coverage = ObservationCoverage::Truncated {
                            reason: "source-acquisition-incomplete".into(),
                        };
                    }
                }
            }
        }
    }
    data.advisories = data
        .advisories
        .iter()
        .map(|record| Ok((record.digest()?, record.clone())))
        .collect::<Result<BTreeMap<_, _>>>()?
        .into_values()
        .collect();
    data.upstream
        .sort_by(|left, right| left.component_ref.cmp(&right.component_ref));
    if let Some(snapshot) = &mut data.advisory_snapshot {
        snapshot.sources.sort_by(|left, right| {
            (&left.provider, &left.project).cmp(&(&right.provider, &right.project))
        });
        snapshot.validate()?;
    }
    Ok(diagnostics.into_iter().collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceChain {
    initial: ProviderOperation,
    operation: ProviderOperation,
    previous: Option<ProviderPageV1>,
    page_position: u32,
    enumeration_complete: bool,
    record_offset: usize,
    observations: Vec<ProviderObservationV1>,
    objects: Vec<NormalizedObject>,
    revisions: BTreeMap<String, String>,
    complete: bool,
    normalized_bytes: usize,
}

enum ChainOutcome {
    Settled(SourceChain),
    Paused(SourceChain),
}

async fn collect_chain<P: AcquisitionPort>(
    port: &P,
    initial: &ProviderOperation,
    progress: Option<SourceChain>,
) -> ChainOutcome {
    let mut chain = progress.unwrap_or_else(|| SourceChain {
        initial: initial.clone(),
        operation: initial.clone(),
        previous: None,
        page_position: 0,
        enumeration_complete: false,
        record_offset: 0,
        observations: vec![],
        objects: vec![],
        revisions: BTreeMap::new(),
        complete: false,
        normalized_bytes: 0,
    });
    // Retain positive evidence after a source failure. A cooperative yield
    // instead retains the exact next cursor without publishing partial coverage.
    match collect_chain_into(port, initial, &mut chain).await {
        Ok(()) => chain.complete = true,
        Err(error) if error.is::<AcquisitionPaused>() => return ChainOutcome::Paused(chain),
        Err(_) => {}
    }
    ChainOutcome::Settled(chain)
}

async fn collect_chain_into<P: AcquisitionPort>(
    port: &P,
    initial: &ProviderOperation,
    chain: &mut SourceChain,
) -> Result<()> {
    for position in chain.page_position..64 {
        if chain.enumeration_complete {
            break;
        }
        let operation = chain.operation.clone();
        let result = port.invoke(&operation, chain.previous.as_ref()).await?;
        account_result(chain, &result)?;
        let mut page = None;
        for projection in result.normalized_objects {
            if projection.object.digest()? != projection.digest {
                bail!("acquisition result object identity changed");
            }
            match projection.object {
                NormalizedObject::Observation(observation) => {
                    if observation.request_identity_digest != operation.digest()? {
                        bail!("acquisition observation differs from the exact issued operation");
                    }
                    chain.observations.push(observation);
                }
                NormalizedObject::Page(source_page) => {
                    if source_page.operation != operation || page.replace(source_page).is_some() {
                        bail!("single-query acquisition returned conflicting pages");
                    }
                }
                object => chain.objects.push(object),
            }
        }
        if let Some(source_page) = &page {
            for record in &source_page.records {
                if chain
                    .revisions
                    .get(&record.id)
                    .is_some_and(|previous| previous != &record.modified)
                {
                    bail!("source changed an advisory revision during enumeration");
                }
                chain
                    .revisions
                    .insert(record.id.clone(), record.modified.clone());
            }
        }
        let next = page.as_ref().and_then(|page| page.next.clone());
        if let Some(next) = next {
            operation.require_successor(&next)?;
            if position == 63 {
                bail!("source chain exceeds its page count ceiling");
            }
            chain.previous = page;
            chain.operation = next;
            chain.page_position = position + 1;
            continue;
        }
        let osv_ids = matches!(initial, ProviderOperation::QueryOsv { .. })
            && matches!(&result.coverage, ProviderCoverage::Partial { reason, continuation: None } if reason == "osv-full-records-required");
        if !result.coverage.is_complete() && !osv_ids {
            bail!("source did not prove enumeration completeness");
        }
        if matches!(
            initial,
            ProviderOperation::QueryOsv { .. } | ProviderOperation::QueryNvd { .. }
        ) && page.is_none()
        {
            bail!("advisory enumeration lacks its retained source-bound page");
        }
        chain.enumeration_complete = true;
        break;
    }
    if let ProviderOperation::QueryOsv { projects, .. } = initial {
        let ids = chain.revisions.keys().cloned().collect::<Vec<_>>();
        for ids in ids[chain.record_offset..].chunks(10) {
            let operation = ProviderOperation::RetrieveAdvisories {
                project: projects[0].clone(),
                ids: ids.to_vec(),
            };
            let result = port.invoke(&operation, None).await?;
            account_result(chain, &result)?;
            for projection in result.normalized_objects {
                if projection.object.digest()? != projection.digest {
                    bail!("retrieved OSV object identity changed");
                }
                match projection.object {
                    NormalizedObject::Advisory(record) => {
                        if chain.revisions.get(&record.id) != Some(&record.modified) {
                            bail!(
                                "OSV full record differs from the exact enumerated modification revision"
                            );
                        }
                        chain.objects.push(NormalizedObject::Advisory(record));
                    }
                    NormalizedObject::Observation(observation) => {
                        chain.observations.push(observation)
                    }
                    _ => bail!("OSV record retrieval returned an incompatible object"),
                }
            }
            if !result.coverage.is_complete() {
                bail!("OSV full-record retrieval is incomplete");
            }
            chain.record_offset += ids.len();
        }
    }
    Ok(())
}

fn account_result(chain: &mut SourceChain, result: &ProviderWorkResultV1) -> Result<()> {
    let bytes = crate::validation::encoded(result)?;
    chain.normalized_bytes = chain
        .normalized_bytes
        .checked_add(bytes.len())
        .filter(|length| *length <= 16 * 1024 * 1024)
        .context("source chain exceeds its aggregate compact byte ceiling")?;
    // Validate every object before accepting any member of this invocation.
    for projection in &result.normalized_objects {
        if projection.object.digest()? != projection.digest {
            bail!("source chain received an inconsistent object projection");
        }
    }
    let sources = chain
        .observations
        .iter()
        .flat_map(|observation| observation.source_refs.iter().map(|source| source.digest))
        .chain(
            result
                .normalized_objects
                .iter()
                .filter_map(|projection| {
                    if let NormalizedObject::Observation(observation) = &projection.object {
                        Some(observation)
                    } else {
                        None
                    }
                })
                .flat_map(|observation| observation.source_refs.iter().map(|source| source.digest)),
        )
        .collect::<BTreeSet<_>>();
    if sources.len() > 128 {
        bail!("source chain exceeds its aggregate custody reference ceiling");
    }
    Ok(())
}

fn merge_observations(chain: &SourceChain, payload: Sha256Digest) -> Result<ProviderObservationV1> {
    let mut observation = chain
        .observations
        .first()
        .cloned()
        .context("source chain lacks observations")?;
    let mut sources = BTreeMap::<Sha256Digest, SourceEvidenceRef>::new();
    for member in &chain.observations {
        member.validate()?;
        if member.provider != observation.provider || member.project != observation.project {
            bail!("source chain crossed its original provider/query scope");
        }
        observation.retrieved_at = observation.retrieved_at.min(member.retrieved_at.clone());
        observation.validated_at = observation.validated_at.min(member.validated_at.clone());
        observation.expires_at = observation.expires_at.min(member.expires_at.clone());
        for source in &member.source_refs {
            if sources
                .insert(source.digest, source.clone())
                .is_some_and(|previous| previous != *source)
            {
                bail!("source chain has conflicting evidence custody receipts");
            }
        }
    }
    if sources.len() > 128 {
        bail!("source chain exceeds its exact custody reference ceiling");
    }
    observation.source_refs = sources.into_values().collect();
    observation.payload_digest = payload;
    observation.validators = None;
    observation.request_identity_digest = chain.initial.digest()?;
    observation.coverage = if chain.complete {
        ProviderCoverage::Complete {
            proof: "exhausted-source-chain-and-full-revisions".into(),
        }
    } else {
        ProviderCoverage::Partial {
            reason: "source-acquisition-incomplete".into(),
            continuation: None,
        }
    };
    observation.validate()?;
    Ok(observation)
}

fn install_advisories(data: &mut EvaluationData, chain: SourceChain) -> Result<()> {
    let mut records = BTreeMap::<String, AdvisoryRecordV1>::new();
    for object in &chain.objects {
        if let NormalizedObject::Advisory(record) = object
            && (chain.revisions.get(&record.id) != Some(&record.modified)
                || records
                    .insert(record.id.clone(), record.clone())
                    .is_some_and(|previous| previous != *record))
        {
            bail!("full advisory records conflict with the enumerated source revisions");
        }
    }
    if chain.complete && !records.keys().eq(chain.revisions.keys()) {
        bail!("advisory enumeration lacks one or more exact full records");
    }
    let previous = data
        .advisory_snapshot
        .as_ref()
        .and_then(|snapshot| {
            snapshot.sources.iter().find(|source| {
                chain.observations.first().is_some_and(|observation| {
                    source.provider == observation.provider && source.project == observation.project
                })
            })
        })
        .cloned();
    let mut digests = records
        .values()
        .map(AdvisoryRecordV1::digest)
        .collect::<Result<Vec<_>>>()?;
    if !chain.complete
        && let Some(previous) = &previous
    {
        digests.extend(previous.record_digests.iter().copied());
    }
    digests.sort();
    digests.dedup();
    let mut observation = merge_observations(
        &chain,
        Sha256Digest::of_canonical("aos.advisory-record-set/v1", &digests)?,
    )?;
    if !chain.complete
        && let Some(previous) = previous
    {
        observation
            .source_refs
            .extend(previous.observation.source_refs);
        observation.source_refs.sort();
        observation.source_refs.dedup();
        observation.retrieved_at = observation
            .retrieved_at
            .min(previous.observation.retrieved_at);
        observation.validated_at = observation
            .validated_at
            .min(previous.observation.validated_at);
        observation.expires_at = observation.expires_at.min(previous.observation.expires_at);
        observation.validate()?;
    }
    let source = AdvisorySnapshotSource {
        provider: observation.provider.clone(),
        project: observation.project.clone(),
        observation,
        record_digests: digests,
    };
    let snapshot = data
        .advisory_snapshot
        .as_mut()
        .context("advisory snapshot is absent")?;
    snapshot.sources.retain(|previous| {
        (previous.provider.as_str(), previous.project.as_str())
            != (source.provider.as_str(), source.project.as_str())
    });
    snapshot.sources.push(source);
    let mut all = data
        .advisories
        .iter()
        .map(|record| Ok((record.digest()?, record.clone())))
        .collect::<Result<BTreeMap<_, _>>>()?;
    for record in records.into_values() {
        all.insert(record.digest()?, record);
    }
    let referenced = snapshot
        .sources
        .iter()
        .flat_map(|source| &source.record_digests)
        .copied()
        .collect::<BTreeSet<_>>();
    data.advisories = all
        .into_iter()
        .filter_map(|(digest, record)| referenced.contains(&digest).then_some(record))
        .collect();
    Ok(())
}

async fn install_upstream<E: EvidenceStore>(
    data: &mut EvaluationData,
    evidence: &E,
    partition: &str,
    job: &AcquisitionJob,
    chain: SourceChain,
) -> Result<()> {
    let pages = chain
        .objects
        .iter()
        .filter_map(|object| {
            if let NormalizedObject::Upstream(observation) = object {
                Some(observation)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut observation = pages
        .first()
        .cloned()
        .cloned()
        .context("upstream chain lacks candidate evidence")?;
    let mut candidates = BTreeMap::new();
    let cached = if chain.complete {
        vec![]
    } else {
        data.upstream
            .iter()
            .filter(|binding| {
                job.component_refs.contains(&binding.component_ref)
                    && matches_upstream(
                        &job.operation,
                        &binding.observation.provider,
                        &binding.observation.project,
                    )
            })
            .collect::<Vec<_>>()
    };
    let mut retained_candidates = BTreeMap::new();
    for binding in &cached {
        observation.retrieved_at_unix = observation
            .retrieved_at_unix
            .max(binding.observation.retrieved_at_unix);
        for candidate in &binding.observation.candidates {
            retained_candidates.insert(candidate.raw_id.clone(), candidate.clone());
        }
    }
    for page in pages {
        for candidate in &page.candidates {
            if candidates
                .insert(candidate.raw_id.clone(), candidate.clone())
                .is_some_and(|previous| previous != *candidate)
            {
                bail!("upstream source changed candidate identity during enumeration");
            }
        }
    }
    retained_candidates.extend(candidates);
    if retained_candidates.len() > 2000 {
        bail!("upstream source chain exceeds its candidate count ceiling");
    }
    observation.candidates = retained_candidates.into_values().collect();
    let mut history = data
        .history
        .iter()
        .map(|entry| {
            (
                (
                    entry.provider.clone(),
                    entry.project.clone(),
                    entry.raw_id.clone(),
                ),
                entry.first_observed_at.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for candidate in &mut observation.candidates {
        let key = (
            observation.provider.clone(),
            observation.project.clone(),
            candidate.raw_id.clone(),
        );
        let acquired = Timestamp::from_unix_seconds(candidate.first_observed_at_unix)?;
        let first = history.entry(key).or_insert_with(|| acquired.clone());
        *first = first.clone().min(acquired);
        candidate.first_observed_at_unix = first.unix_seconds();
    }
    data.history = history
        .into_iter()
        .map(
            |((provider, project, raw_id), first_observed_at)| CandidateHistory {
                provider,
                project,
                raw_id,
                first_observed_at,
            },
        )
        .collect();
    observation.coverage = if chain.complete {
        ObservationCoverage::Complete
    } else {
        ObservationCoverage::Truncated {
            reason: "source-acquisition-incomplete".into(),
        }
    };
    let mut source_refs = chain
        .observations
        .iter()
        .flat_map(|observation| observation.source_refs.clone())
        .collect::<Vec<_>>();
    for binding in cached {
        source_refs.extend(binding.source_refs.clone());
    }
    source_refs.sort();
    source_refs.dedup();
    let bundle = aos_contract::canonical::to_vec(&crate::source_chain::SourceChainCustodyV1 {
        schema: "aos.source-chain-custody/v1".into(),
        operation: chain.initial.clone(),
        sources: source_refs.clone(),
    })?;
    crate::source_chain::SourceChainCustodyV1::from_slice(&bundle)?;
    let digest = evidence.retain(partition, &bundle).await?;
    if digest != Sha256Digest::of_bytes(&bundle) {
        bail!("upstream chain custody returned a different retained identity");
    }
    observation.response_digest = digest;
    source_refs.push(SourceEvidenceRef {
        digest,
        byte_length: bundle.len() as u64,
        origin: observation.provider.clone(),
    });
    source_refs.sort();
    source_refs.dedup();
    observation.validate()?;
    // Only primary discovery feeds selection. Advisor observations remain
    // separate source questions and cannot replace a primary upstream binding.
    for component_ref in &job.component_refs {
        let component = data
            .inventory
            .components
            .iter()
            .find(|component| &component.component_ref == component_ref)
            .context("acquisition component is absent")?;
        let definition = data
            .definitions
            .iter()
            .find(|definition| definition.digest().ok() == Some(component.scan_definition_digest))
            .context("component definition is absent")?;
        let declared = definition
            .components
            .iter()
            .find(|declared| declared.component_id == component.component_id)
            .context("component declaration is absent")?;
        if !declared
            .discovery
            .primary
            .as_ref()
            .is_some_and(|provider| primary_matches(provider, &job.operation))
        {
            continue;
        }
        data.upstream
            .retain(|binding| &binding.component_ref != component_ref);
        data.upstream.push(UpstreamBinding {
            // Partial chains retain candidates for visibility, but cannot renew
            // a complete/current conclusion from the subset they revalidated.
            page_observations: if chain.complete {
                chain.observations.clone()
            } else {
                vec![]
            },
            source_refs: source_refs.clone(),
            component_ref: component_ref.clone(),
            observation: observation.clone(),
            response_byte_length: bundle.len() as u64,
        });
    }
    Ok(())
}

fn primary_matches(provider: &DiscoveryProvider, operation: &ProviderOperation) -> bool {
    match (provider, operation) {
        (
            DiscoveryProvider::GithubReleases {
                repository: left,
                tag_prefix: a,
            },
            ProviderOperation::ObserveReleases {
                repository: right,
                tag_prefix: b,
                ..
            },
        )
        | (
            DiscoveryProvider::GithubTags {
                repository: left,
                tag_prefix: a,
            },
            ProviderOperation::ObserveTags {
                repository: right,
                tag_prefix: b,
                ..
            },
        ) => left == right && a == b,
        (DiscoveryProvider::GoReleases, ProviderOperation::ObserveGoReleases) => true,
        (
            DiscoveryProvider::Repology { project: left },
            ProviderOperation::ObserveRepology { project: right },
        ) => left == right,
        _ => false,
    }
}

fn matches_upstream(operation: &ProviderOperation, provider: &str, project: &str) -> bool {
    match operation {
        ProviderOperation::ObserveReleases { repository, .. } => {
            provider == "github-releases" && repository == project
        }
        ProviderOperation::ObserveTags { repository, .. } => {
            provider == "github-tags" && repository == project
        }
        ProviderOperation::ObserveGoReleases => provider == "go-releases" && project == "go",
        ProviderOperation::ObserveRepology { project: declared } => {
            provider == "repology" && declared == project
        }
        _ => false,
    }
}

fn mark_cached_advisory_incomplete(data: &mut EvaluationData, operation: &ProviderOperation) {
    let (provider, projects) = match operation {
        ProviderOperation::QueryOsv { projects, .. } => ("osv", projects.clone()),
        ProviderOperation::QueryNvd { project, .. } => ("nvd", vec![project.clone()]),
        _ => return,
    };
    if let Some(snapshot) = &mut data.advisory_snapshot {
        for source in &mut snapshot.sources {
            if source.provider == provider && projects.contains(&source.project) {
                source.observation.coverage = ProviderCoverage::Unknown {
                    reason: "source-acquisition-incomplete".into(),
                };
            }
        }
    }
}

//! Foreground upstream adapters and repository-bound discovery snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::time::UNIX_EPOCH;

use anyhow::{Context as _, Result, bail};
use aos_contract::{Sha256Digest, canonical};
use aos_maintain::DISCOVERY_SNAPSHOT_V1;
use aos_maintain::discovery::{
    AdvisoryFinding, AdvisoryKind, DiscoverySnapshotV1, ObservationCandidate, ObservationCoverage,
    UnitDiscovery, UpstreamObservationV1, select_unit,
};
use aos_maintain::envelope::InventoryEnvelopeV1;
use aos_maintain::inventory::DiscoveryProvider;
use futures_util::StreamExt as _;
use reqwest::header::{ACCEPT, LINK, USER_AGENT};
use serde_json::Value;
use url::Url;

use super::state::StateStore;

const ADAPTER_VERSION: &str = "aos-maintain-providers/v1";
const OBSERVATION_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const MAX_GITHUB_PAGES: u32 = 10;
const MAX_REPOLOGY_FALLBACK_REQUESTS: usize = 1_000;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const USER_AGENT_VALUE: &str =
    "aos-maintain/0.1 (+https://github.com/andyl-technologies/aos/issues)";
const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";

/// Returns a completed snapshot plus non-fatal advisory diagnostics.
pub(super) struct ScanOutcome {
    pub(super) snapshot: DiscoverySnapshotV1,
    pub(super) warnings: Vec<String>,
    pub(super) advisory_newer: u64,
    pub(super) advisory_vulnerable: u64,
    pub(super) advisory_license_change: u64,
    pub(super) repology_fallbacks: u64,
}

/// Evaluates every declared direct provider and records bounded observations.
pub(super) async fn scan(
    envelope: &InventoryEnvelopeV1,
    store: &StateStore,
    offline: bool,
    token_env: &str,
    repology_fallback: bool,
    repology_limit: usize,
) -> Result<ScanOutcome> {
    if repology_limit > MAX_REPOLOGY_FALLBACK_REQUESTS {
        bail!("Repology fallback request limit exceeds {MAX_REPOLOGY_FALLBACK_REQUESTS}");
    }
    let evaluated_at = super::state::now_unix()?;
    let envelope_digest =
        Sha256Digest::of_canonical(aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1, envelope)?;
    let cached = store.read_discovery()?;
    let cached_matches = cached
        .as_ref()
        .is_some_and(|snapshot| snapshot.inventory_envelope_digest == envelope_digest);
    let mut observations = if cached_matches {
        cached
            .as_ref()
            .map(|snapshot| snapshot.observations.clone())
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let mut warnings = Vec::new();
    let github_token = if offline {
        None
    } else {
        read_optional_token(token_env)?
    };
    let mut repology_by_project = observations
        .values()
        .filter(|observation| observation.provider == "repology")
        .map(|observation| (observation.project.clone(), observation.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut repology_requests = 0_usize;
    let mut repology_fallbacks = 0_u64;
    let mut last_repology_request = None;
    let mut fallback_limit_reported = false;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let same_origin = attempt.previous().first().is_none_or(|initial| {
                initial.scheme() == attempt.url().scheme()
                    && initial.host_str() == attempt.url().host_str()
                    && initial.port_or_known_default() == attempt.url().port_or_known_default()
            });
            if attempt.previous().len() >= 5 || !same_origin {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .context("constructing upstream HTTP client")?;

    let mut units = Vec::with_capacity(envelope.inventory.units.len());
    for unit in &envelope.inventory.units {
        let mut primary = BTreeMap::new();
        for (component_id, component) in &unit.components {
            let key = observation_key(unit.unit_id.as_str(), component_id.as_str(), "primary");
            let fresh_primary = observations
                .get(&key)
                .filter(|observation| observation_is_fresh(observation, evaluated_at))
                .cloned();
            let observation = if offline {
                observations.get(&key).cloned()
            } else if fresh_primary.is_some() {
                fresh_primary
            } else {
                match &component.primary {
                    Some(DiscoveryProvider::GithubReleases {
                        repository,
                        tag_prefix,
                    }) => match github_releases(
                        &client,
                        store,
                        repository,
                        tag_prefix,
                        &component.current.upstream_id,
                        evaluated_at,
                        github_token.as_deref(),
                    )
                    .await
                    {
                        Ok(observation) => {
                            observations.insert(key.clone(), observation.clone());
                            Some(observation)
                        }
                        Err(error) => {
                            warnings.push(format!(
                                "{} {} primary discovery failed: {error:#}",
                                unit.unit_id, component_id
                            ));
                            None
                        }
                    },
                    Some(DiscoveryProvider::GithubTags {
                        repository,
                        tag_prefix,
                    }) => match github_tags(
                        &client,
                        store,
                        repository,
                        tag_prefix,
                        &component.current.upstream_id,
                        evaluated_at,
                        github_token.as_deref(),
                    )
                    .await
                    {
                        Ok(observation) => {
                            observations.insert(key.clone(), observation.clone());
                            Some(observation)
                        }
                        Err(error) => {
                            warnings.push(format!(
                                "{} {} primary discovery failed: {error:#}",
                                unit.unit_id, component_id
                            ));
                            None
                        }
                    },
                    Some(DiscoveryProvider::Repology { .. }) => {
                        warnings.push(format!(
                            "{} {} declares advisory-only Repology as primary",
                            unit.unit_id, component_id
                        ));
                        None
                    }
                    None => None,
                }
            };
            if let Some(observation) = observation {
                primary.insert(component_id.to_string(), observation);
            }

            if !offline {
                for (index, advisor) in component.advisors.iter().enumerate() {
                    if let DiscoveryProvider::Repology { project } = advisor {
                        let advisor_key = observation_key(
                            unit.unit_id.as_str(),
                            component_id.as_str(),
                            &format!("advisor-{index}"),
                        );
                        let observed = if let Some(observation) = repology_by_project
                            .get(project)
                            .filter(|observation| observation_is_fresh(observation, evaluated_at))
                        {
                            Ok(observation.clone())
                        } else {
                            let result =
                                paced_repology(&client, store, project, &mut last_repology_request)
                                    .await;
                            if let Ok(observation) = &result {
                                repology_by_project.insert(project.clone(), observation.clone());
                            }
                            result
                        };
                        match observed {
                            Ok(observation) => {
                                observations.insert(advisor_key, observation);
                            }
                            Err(error) => warnings.push(format!(
                                "{} {} Repology advisory failed: {error:#}",
                                unit.unit_id, component_id
                            )),
                        }
                    }
                }
            }

            let has_repology_advisor = component
                .advisors
                .iter()
                .any(|advisor| matches!(advisor, DiscoveryProvider::Repology { .. }));
            if !offline && repology_fallback && !has_repology_advisor {
                let project = unit.family.as_str();
                let fallback_key = observation_key(
                    unit.unit_id.as_str(),
                    component_id.as_str(),
                    "fallback-repology",
                );
                let cached_fallback = observations
                    .get(&fallback_key)
                    .filter(|observation| observation_is_fresh(observation, evaluated_at))
                    .cloned()
                    .or_else(|| {
                        repology_by_project
                            .get(project)
                            .filter(|observation| observation_is_fresh(observation, evaluated_at))
                            .cloned()
                    });
                let observed = if let Some(observation) = cached_fallback {
                    Some(observation)
                } else if repology_requests < repology_limit {
                    repology_requests += 1;
                    match paced_repology(&client, store, project, &mut last_repology_request).await
                    {
                        Ok(observation) => {
                            repology_by_project.insert(project.to_string(), observation.clone());
                            Some(observation)
                        }
                        Err(error) => {
                            warnings.push(format!(
                                "{} {} Repology fallback failed: {error:#}",
                                unit.unit_id, component_id
                            ));
                            None
                        }
                    }
                } else {
                    if !fallback_limit_reported {
                        warnings.push(format!(
                            "Repology fallback stopped after {repology_limit} uncached requests"
                        ));
                        fallback_limit_reported = true;
                    }
                    None
                };
                if let Some(observation) = observed {
                    repology_fallbacks += 1;
                    observations.insert(fallback_key, observation);
                }
            }
        }
        units.push(select_unit(
            unit,
            &primary,
            evaluated_at,
            OBSERVATION_MAX_AGE_SECONDS,
        )?);
    }
    units.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));

    let mut snapshot = DiscoverySnapshotV1 {
        schema: DISCOVERY_SNAPSHOT_V1.to_string(),
        inventory_envelope_digest: envelope_digest,
        observations,
        units,
        evaluated_at_unix: evaluated_at,
    };
    snapshot.validate()?;
    let advisory = repology_advisory_summary(
        envelope,
        &snapshot.observations,
        &mut snapshot.units,
        &mut warnings,
    );
    snapshot.validate()?;
    Ok(ScanOutcome {
        snapshot,
        warnings,
        advisory_newer: advisory.newer,
        advisory_vulnerable: advisory.vulnerable,
        advisory_license_change: advisory.license_change,
        repology_fallbacks,
    })
}

#[derive(Default)]
struct AdvisorySummary {
    newer: u64,
    vulnerable: u64,
    license_change: u64,
}

fn repology_advisory_summary(
    envelope: &InventoryEnvelopeV1,
    observations: &BTreeMap<String, UpstreamObservationV1>,
    units: &mut [UnitDiscovery],
    warnings: &mut Vec<String>,
) -> AdvisorySummary {
    let mut summary = AdvisorySummary::default();
    for unit in &envelope.inventory.units {
        for (component_id, component) in &unit.components {
            let observation_prefix = format!("{}/{component_id}/", unit.unit_id);
            let Some(observation) = observations
                .iter()
                .find(|(key, observation)| {
                    key.starts_with(&observation_prefix) && observation.provider == "repology"
                })
                .map(|(_, observation)| observation)
            else {
                continue;
            };
            let current = observation
                .candidates
                .iter()
                .filter(|candidate| candidate.raw_version == component.current.comparison_version)
                .collect::<Vec<_>>();
            if current
                .iter()
                .any(|candidate| candidate.vulnerable == Some(true))
            {
                summary.vulnerable += 1;
                push_advisory(
                    units,
                    unit.unit_id.as_str(),
                    AdvisoryFinding {
                        component: component_id.to_string(),
                        provider: "repology".to_string(),
                        project: observation.project.clone(),
                        kind: AdvisoryKind::VulnerableCurrent,
                        current_version: component.current.comparison_version.clone(),
                        candidate_versions: vec![component.current.comparison_version.clone()],
                        current_licenses: Vec::new(),
                        candidate_licenses: Vec::new(),
                    },
                );
                warnings.push(format!(
                    "{} {} current version {} is reported vulnerable by Repology",
                    unit.unit_id, component_id, component.current.comparison_version
                ));
            }

            let newest = observation
                .candidates
                .iter()
                .filter(|candidate| candidate.status.as_deref() == Some("newest"))
                .collect::<Vec<_>>();
            if newest
                .iter()
                .any(|candidate| candidate.raw_version != component.current.comparison_version)
            {
                summary.newer += 1;
                let candidate_versions = newest
                    .iter()
                    .map(|candidate| candidate.raw_version.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let versions = candidate_versions.join(", ");
                push_advisory(
                    units,
                    unit.unit_id.as_str(),
                    AdvisoryFinding {
                        component: component_id.to_string(),
                        provider: "repology".to_string(),
                        project: observation.project.clone(),
                        kind: AdvisoryKind::NewerVersion,
                        current_version: component.current.comparison_version.clone(),
                        candidate_versions,
                        current_licenses: Vec::new(),
                        candidate_licenses: Vec::new(),
                    },
                );
                warnings.push(format!(
                    "{} {} has newer Repology advisory versions: {versions}",
                    unit.unit_id, component_id
                ));
            }

            let current_licenses = unanimous_licenses(&current);
            let newest_licenses = unanimous_licenses(&newest);
            if let Some((current_licenses, newest_licenses)) = current_licenses
                .zip(newest_licenses)
                .filter(|(current, newest)| current != newest)
            {
                summary.license_change += 1;
                push_advisory(
                    units,
                    unit.unit_id.as_str(),
                    AdvisoryFinding {
                        component: component_id.to_string(),
                        provider: "repology".to_string(),
                        project: observation.project.clone(),
                        kind: AdvisoryKind::LicenseChange,
                        current_version: component.current.comparison_version.clone(),
                        candidate_versions: newest
                            .iter()
                            .map(|candidate| candidate.raw_version.clone())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect(),
                        current_licenses: current_licenses.into_iter().collect(),
                        candidate_licenses: newest_licenses.into_iter().collect(),
                    },
                );
                warnings.push(format!(
                    "{} {} has differing current/newest Repology license sets",
                    unit.unit_id, component_id
                ));
            }
        }
    }
    summary
}

fn push_advisory(units: &mut [UnitDiscovery], unit_id: &str, finding: AdvisoryFinding) {
    if let Some(unit) = units.iter_mut().find(|unit| unit.unit_id == unit_id) {
        unit.advisories.push(finding);
        unit.advisories.sort_by(|left, right| {
            (left.component.as_str(), left.kind).cmp(&(right.component.as_str(), right.kind))
        });
    }
}

fn unanimous_licenses(candidates: &[&ObservationCandidate]) -> Option<BTreeSet<String>> {
    if candidates.is_empty()
        || candidates
            .iter()
            .any(|candidate| candidate.licenses.is_empty())
    {
        return None;
    }

    let mut reported = candidates
        .iter()
        .map(|candidate| candidate.licenses.iter().cloned().collect::<BTreeSet<_>>());
    let first = reported.next()?;
    reported.all(|licenses| licenses == first).then_some(first)
}

fn observation_is_fresh(observation: &UpstreamObservationV1, now_unix: u64) -> bool {
    now_unix >= observation.retrieved_at_unix
        && now_unix.saturating_sub(observation.retrieved_at_unix) <= OBSERVATION_MAX_AGE_SECONDS
}

async fn paced_repology(
    client: &reqwest::Client,
    store: &StateStore,
    project: &str,
    last_request: &mut Option<tokio::time::Instant>,
) -> Result<UpstreamObservationV1> {
    if let Some(last_request) = last_request {
        tokio::time::sleep_until(*last_request + std::time::Duration::from_secs(1)).await;
    }
    *last_request = Some(tokio::time::Instant::now());
    repology(client, store, project, super::state::now_unix()?).await
}

async fn github_releases(
    client: &reqwest::Client,
    store: &StateStore,
    repository: &str,
    tag_prefix: &str,
    current_identity: &str,
    retrieved_at: u64,
    token: Option<&str>,
) -> Result<UpstreamObservationV1> {
    validate_github_repository(repository)?;
    let api_base = github_api_base_url()?;
    let mut candidates = Vec::new();
    let mut response_bytes = Vec::new();
    let mut coverage = ObservationCoverage::Truncated {
        reason: "github-page-limit".to_string(),
    };
    let mut first_url = None;

    for page in 1..=MAX_GITHUB_PAGES {
        let url = api_base
            .join(&format!(
                "repos/{repository}/releases?per_page=100&page={page}"
            ))
            .context("constructing GitHub releases URL")?
            .to_string();
        if first_url.is_none() {
            first_url = Some(url.clone());
        }
        let mut request = client
            .get(&url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ACCEPT, "application/vnd.github+json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.context("requesting GitHub releases")?;
        let status = response.status();
        let has_next = response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(|link| link.contains("rel=\"next\"")));
        if !status.is_success() {
            bail!("GitHub releases returned HTTP {status}");
        }
        let bytes = bounded_body(response).await?;
        append_page(&mut response_bytes, &bytes)?;
        let value = canonical::parse_json(&bytes, "GitHub releases response")?;
        let entries = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("GitHub releases response is not an array"))?;
        for entry in entries {
            let raw_id = required_string(entry, "tag_name", "GitHub release")?;
            if raw_id.len() > 512 {
                bail!("GitHub release identity is oversized");
            }
            let Some(raw_version) = normalized_github_tag(&raw_id, tag_prefix) else {
                continue;
            };
            let first_key = format!(
                "github-releases:{}:{repository}:{}:{raw_id}",
                repository.len(),
                raw_id.len()
            );
            let first_observed = store.record_first_observed(&first_key, retrieved_at)?;
            candidates.push(ObservationCandidate {
                raw_id: raw_id.clone(),
                raw_version: raw_version.to_string(),
                published_at_unix: github_release_timestamp(entry)?,
                first_observed_at_unix: first_observed,
                prerelease: entry
                    .get("prerelease")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                yanked: entry.get("draft").and_then(Value::as_bool).unwrap_or(false),
                release_url: entry
                    .get("html_url")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                status: None,
                vulnerable: None,
                licenses: Vec::new(),
            });
        }
        if candidates
            .iter()
            .any(|candidate| candidate.raw_id == current_identity)
        {
            coverage = ObservationCoverage::ThroughCurrent {
                identity: current_identity.to_string(),
            };
            break;
        }
        if !has_next {
            coverage = ObservationCoverage::Complete;
            break;
        }
    }
    candidates.sort_by(|left, right| left.raw_id.cmp(&right.raw_id));
    if candidates
        .windows(2)
        .any(|pair| pair[0].raw_id == pair[1].raw_id)
    {
        bail!("GitHub returned duplicate release identities");
    }
    let observation = UpstreamObservationV1 {
        schema: aos_maintain::UPSTREAM_OBSERVATION_V1.to_string(),
        provider: "github-releases".to_string(),
        project: repository.to_string(),
        retrieved_at_unix: retrieved_at,
        request_url: first_url.ok_or_else(|| anyhow::anyhow!("GitHub request was not issued"))?,
        adapter_version: ADAPTER_VERSION.to_string(),
        coverage,
        response_digest: store.store_provider_response(&response_bytes)?,
        candidates,
    };
    observation.validate()?;
    Ok(observation)
}

fn github_release_timestamp(entry: &Value) -> Result<Option<u64>> {
    let Some(timestamp) = entry.get("published_at").and_then(Value::as_str) else {
        return Ok(None);
    };
    let system_time =
        humantime::parse_rfc3339(timestamp).context("parsing GitHub release publication time")?;
    let seconds = system_time
        .duration_since(UNIX_EPOCH)
        .context("GitHub release publication time predates the Unix epoch")?
        .as_secs();
    Ok(Some(seconds))
}

async fn github_tags(
    client: &reqwest::Client,
    store: &StateStore,
    repository: &str,
    tag_prefix: &str,
    current_identity: &str,
    retrieved_at: u64,
    token: Option<&str>,
) -> Result<UpstreamObservationV1> {
    validate_github_repository(repository)?;
    let api_base = github_api_base_url()?;
    let mut candidates = Vec::new();
    let mut response_bytes = Vec::new();
    let mut coverage = ObservationCoverage::Truncated {
        reason: "github-page-limit".to_string(),
    };
    let mut first_url = None;

    for page in 1..=MAX_GITHUB_PAGES {
        let url = api_base
            .join(&format!("repos/{repository}/tags?per_page=100&page={page}"))
            .context("constructing GitHub tags URL")?
            .to_string();
        if first_url.is_none() {
            first_url = Some(url.clone());
        }
        let mut request = client
            .get(&url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ACCEPT, "application/vnd.github+json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.context("requesting GitHub tags")?;
        let status = response.status();
        let has_next = response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(|link| link.contains("rel=\"next\"")));
        if !status.is_success() {
            bail!("GitHub tags returned HTTP {status}");
        }
        let bytes = bounded_body(response).await?;
        append_page(&mut response_bytes, &bytes)?;
        let value = canonical::parse_json(&bytes, "GitHub tags response")?;
        let entries = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("GitHub tags response is not an array"))?;
        for entry in entries {
            let raw_id = required_string(entry, "name", "GitHub tag")?;
            if raw_id.len() > 512 {
                bail!("GitHub tag identity is oversized");
            }
            let Some(raw_version) = normalized_github_tag(&raw_id, tag_prefix) else {
                continue;
            };
            let first_key = format!(
                "github-tags:{}:{repository}:{}:{raw_id}",
                repository.len(),
                raw_id.len()
            );
            let first_observed = store.record_first_observed(&first_key, retrieved_at)?;
            candidates.push(ObservationCandidate {
                raw_id: raw_id.clone(),
                raw_version: raw_version.to_string(),
                published_at_unix: None,
                first_observed_at_unix: first_observed,
                prerelease: false,
                yanked: false,
                release_url: github_release_url(repository, &raw_id).ok(),
                status: None,
                vulnerable: None,
                licenses: Vec::new(),
            });
        }
        if candidates
            .iter()
            .any(|candidate| candidate.raw_id == current_identity)
        {
            coverage = ObservationCoverage::ThroughCurrent {
                identity: current_identity.to_string(),
            };
            break;
        }
        if !has_next {
            coverage = ObservationCoverage::Complete;
            break;
        }
    }
    candidates.sort_by(|left, right| left.raw_id.cmp(&right.raw_id));
    if candidates
        .windows(2)
        .any(|pair| pair[0].raw_id == pair[1].raw_id)
    {
        bail!("GitHub returned duplicate tag identities");
    }
    let observation = UpstreamObservationV1 {
        schema: aos_maintain::UPSTREAM_OBSERVATION_V1.to_string(),
        provider: "github-tags".to_string(),
        project: repository.to_string(),
        retrieved_at_unix: retrieved_at,
        request_url: first_url.ok_or_else(|| anyhow::anyhow!("GitHub request was not issued"))?,
        adapter_version: ADAPTER_VERSION.to_string(),
        coverage,
        response_digest: store.store_provider_response(&response_bytes)?,
        candidates,
    };
    observation.validate()?;
    Ok(observation)
}

fn github_api_base_url() -> Result<Url> {
    let configured =
        env::var("GITHUB_API_URL").unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_string());
    parse_github_api_base_url(&configured)
}

fn parse_github_api_base_url(configured: &str) -> Result<Url> {
    let mut url = Url::parse(configured).context("parsing GITHUB_API_URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("GITHUB_API_URL must be an uncredentialed HTTPS base URL");
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn normalized_github_tag<'a>(tag: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        Some(tag)
    } else {
        tag.strip_prefix(prefix)
            .filter(|version| !version.is_empty())
    }
}

fn read_optional_token(variable: &str) -> Result<Option<String>> {
    if variable.is_empty()
        || variable.len() > 128
        || !variable
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("GitHub discovery token environment variable name is invalid");
    }
    let Some(value) = std::env::var_os(variable) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("GitHub discovery token is not UTF-8"))?;
    if value.is_empty()
        || value.len() > 4096
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("GitHub discovery token is invalid");
    }
    Ok(Some(value))
}

async fn repology(
    client: &reqwest::Client,
    store: &StateStore,
    project: &str,
    retrieved_at: u64,
) -> Result<UpstreamObservationV1> {
    store.claim_repology_request(retrieved_at)?;
    let mut url = Url::parse("https://repology.org/api/v1/project/")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("Repology URL cannot accept path segments"))?
        .pop_if_empty()
        .push(project);
    let response = client
        .get(url.clone())
        .header(USER_AGENT, USER_AGENT_VALUE)
        .send()
        .await
        .context("requesting Repology project")?;
    let status = response.status();
    if !status.is_success() {
        bail!("Repology returned HTTP {status}");
    }
    let bytes = bounded_body(response).await?;
    let value = canonical::parse_json(&bytes, "Repology response")?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Repology response is not an array"))?;
    let mut candidates = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        let repository = entry
            .get("repo")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let original_version = entry
            .get("origversion")
            .and_then(Value::as_str)
            .unwrap_or(version);
        let raw_id = format!("{repository}:{original_version}:{index}");
        let first_key = format!(
            "repology:{}:{project}:{}:{repository}:{}:{original_version}",
            project.len(),
            repository.len(),
            original_version.len()
        );
        let first_observed = store.record_first_observed(&first_key, retrieved_at)?;
        let mut licenses = entry
            .get("licenses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        licenses.sort();
        licenses.dedup();
        candidates.push(ObservationCandidate {
            raw_id,
            raw_version: version.to_string(),
            published_at_unix: None,
            first_observed_at_unix: first_observed,
            prerelease: false,
            yanked: matches!(
                entry.get("status").and_then(Value::as_str),
                Some("ignored" | "incorrect" | "untrusted")
            ),
            release_url: None,
            status: entry
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string),
            vulnerable: entry.get("vulnerable").and_then(Value::as_bool),
            licenses,
        });
    }
    candidates.sort_by(|left, right| left.raw_id.cmp(&right.raw_id));
    let observation = UpstreamObservationV1 {
        schema: aos_maintain::UPSTREAM_OBSERVATION_V1.to_string(),
        provider: "repology".to_string(),
        project: project.to_string(),
        retrieved_at_unix: retrieved_at,
        request_url: url.to_string(),
        adapter_version: ADAPTER_VERSION.to_string(),
        coverage: ObservationCoverage::Complete,
        response_digest: store.store_provider_response(&bytes)?,
        candidates,
    };
    observation.validate()?;
    Ok(observation)
}

async fn bounded_body(response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("provider response exceeds byte limit");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading provider response")?;
        append_response(&mut bytes, &chunk)?;
    }
    Ok(bytes)
}

fn append_response(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if output.len().saturating_add(bytes.len()) > MAX_RESPONSE_BYTES {
        bail!("provider response exceeds byte limit");
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_page(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u64::try_from(bytes.len()).context("provider page length does not fit u64")?;
    append_response(output, &length.to_be_bytes())?;
    append_response(output, bytes)
}

fn required_string(value: &Value, field: &str, label: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{label} lacks string field {field}"))
}

fn validate_github_repository(repository: &str) -> Result<()> {
    let mut parts = repository.split('/');
    let owner = parts.next();
    let name = parts.next();
    if owner.is_none_or(|part| part.is_empty() || matches!(part, "." | ".."))
        || name.is_none_or(|part| part.is_empty() || matches!(part, "." | ".."))
        || parts.next().is_some()
        || repository.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        })
    {
        bail!("GitHub repository must use safe owner/name syntax");
    }
    Ok(())
}

fn github_release_url(repository: &str, tag: &str) -> Result<String> {
    let mut url = Url::parse("https://github.com/")?;
    let mut path = url
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("GitHub URL cannot accept path segments"))?;
    for part in repository.split('/') {
        path.push(part);
    }
    path.push("releases").push("tag").push(tag);
    drop(path);
    Ok(url.to_string())
}

fn observation_key(unit: &str, component: &str, role: &str) -> String {
    format!("{unit}/{component}/{role}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_repository_and_release_urls_are_structural() -> Result<()> {
        validate_github_repository("madler/zlib")?;
        assert!(validate_github_repository("madler/zlib/extra").is_err());
        assert!(validate_github_repository("madler/../zlib").is_err());
        assert_eq!(
            github_release_url("madler/zlib", "release/1.0")?,
            "https://github.com/madler/zlib/releases/tag/release%2F1.0"
        );
        Ok(())
    }

    #[test]
    fn response_accumulation_is_bounded() {
        let mut output = vec![0_u8; MAX_RESPONSE_BYTES];
        assert!(append_response(&mut output, &[1]).is_err());
    }

    #[test]
    fn github_tag_prefix_is_an_exact_candidate_boundary() {
        assert_eq!(normalized_github_tag("v2.3.4", "v"), Some("2.3.4"));
        assert_eq!(normalized_github_tag("release-2.3.4", "v"), None);
        assert_eq!(normalized_github_tag("v", "v"), None);
        assert_eq!(normalized_github_tag("2.3.4", ""), Some("2.3.4"));
    }

    #[test]
    fn github_release_publication_time_is_optional_and_bounded() -> Result<()> {
        let published = serde_json::json!({"published_at": "2026-08-29T12:34:56Z"});
        assert_eq!(github_release_timestamp(&published)?, Some(1_788_006_896));
        assert_eq!(github_release_timestamp(&serde_json::json!({}))?, None);
        assert!(
            github_release_timestamp(&serde_json::json!({
                "published_at": "not-a-timestamp"
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn license_advisories_require_unanimous_nonempty_reports() {
        let mut first = advisory_candidate("repo-a", &["MIT"]);
        let second = advisory_candidate("repo-b", &["MIT"]);
        assert_eq!(
            unanimous_licenses(&[&first, &second]),
            Some(BTreeSet::from(["MIT".to_string()]))
        );

        first.licenses = vec!["Apache-2.0".to_string()];
        assert_eq!(unanimous_licenses(&[&first, &second]), None);

        first.licenses.clear();
        assert_eq!(unanimous_licenses(&[&first, &second]), None);
        assert_eq!(unanimous_licenses(&[&first]), None);
    }

    #[test]
    fn github_api_base_is_https_and_preserves_enterprise_paths() -> Result<()> {
        assert_eq!(
            parse_github_api_base_url("https://github.example/api/v3")?
                .join("repos/owner/project/tags")?
                .as_str(),
            "https://github.example/api/v3/repos/owner/project/tags"
        );
        assert!(parse_github_api_base_url("http://github.example/api/v3").is_err());
        assert!(parse_github_api_base_url("https://token@github.example/api/v3").is_err());
        assert!(parse_github_api_base_url("https://github.example/api/v3?token=x").is_err());
        Ok(())
    }

    fn advisory_candidate(repository: &str, licenses: &[&str]) -> ObservationCandidate {
        ObservationCandidate {
            raw_id: repository.to_string(),
            raw_version: "1.0".to_string(),
            published_at_unix: None,
            first_observed_at_unix: 1,
            prerelease: false,
            yanked: false,
            release_url: None,
            status: Some("newest".to_string()),
            vulnerable: Some(false),
            licenses: licenses
                .iter()
                .map(|license| (*license).to_string())
                .collect(),
        }
    }
}

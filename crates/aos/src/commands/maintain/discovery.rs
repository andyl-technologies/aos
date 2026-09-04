//! Foreground upstream adapters and repository-bound discovery snapshots.

use std::collections::BTreeMap;
use std::env;

use anyhow::{Context as _, Result, bail};
use aos_contract::{Sha256Digest, canonical};
use aos_maintain::DISCOVERY_SNAPSHOT_V1;
use aos_maintain::discovery::{
    DiscoverySnapshotV1, ObservationCandidate, ObservationCoverage, UpstreamObservationV1,
    select_unit,
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
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const USER_AGENT_VALUE: &str =
    "aos-maintain/0.1 (+https://github.com/andyl-technologies/aos/issues)";
const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";

/// Returns a completed snapshot plus non-fatal advisory diagnostics.
pub(super) struct ScanOutcome {
    pub(super) snapshot: DiscoverySnapshotV1,
    pub(super) warnings: Vec<String>,
}

/// Evaluates every declared direct provider and records bounded observations.
pub(super) async fn scan(
    envelope: &InventoryEnvelopeV1,
    store: &StateStore,
    offline: bool,
    token_env: &str,
) -> Result<ScanOutcome> {
    let evaluated_at = super::state::now_unix()?;
    let envelope_digest =
        Sha256Digest::of_canonical(aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1, envelope)?;
    let cached = store.read_discovery()?;
    let cached_matches = cached
        .as_ref()
        .is_some_and(|snapshot| snapshot.inventory_envelope_digest == envelope_digest);
    let mut observations = if offline && cached_matches {
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
    let mut repology_by_project: BTreeMap<String, UpstreamObservationV1> = BTreeMap::new();
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
            let observation = if offline {
                observations.get(&key).cloned()
            } else {
                match &component.primary {
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
                        let observed = if let Some(observation) = repology_by_project.get(project) {
                            Ok(observation.clone())
                        } else {
                            let result = repology(&client, store, project, evaluated_at).await;
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
        }
        units.push(select_unit(
            unit,
            &primary,
            evaluated_at,
            OBSERVATION_MAX_AGE_SECONDS,
        )?);
    }
    units.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));

    let snapshot = DiscoverySnapshotV1 {
        schema: DISCOVERY_SNAPSHOT_V1.to_string(),
        inventory_envelope_digest: envelope_digest,
        observations,
        units,
        evaluated_at_unix: evaluated_at,
    };
    snapshot.validate()?;
    Ok(ScanOutcome { snapshot, warnings })
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
        let Some(version) = entry
            .get("origversion")
            .or_else(|| entry.get("version"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let repository = entry
            .get("repo")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let raw_id = format!("{repository}:{version}:{index}");
        let first_key = format!(
            "repology:{}:{project}:{}:{repository}:{}:{version}",
            project.len(),
            repository.len(),
            version.len()
        );
        let first_observed = store.record_first_observed(&first_key, retrieved_at)?;
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
}

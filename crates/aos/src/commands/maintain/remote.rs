//! Explicit, exact-ref GitHub publication and read-only PR observation.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use aos_maintain::PACKAGE_UPDATE_PR_OBSERVATION_V1;
use aos_maintain::PACKAGE_UPDATE_PR_PUBLICATION_V1;
use aos_maintain::envelope::GitObjectId;
use aos_maintain::presentation::PullRequestDraft;
use aos_maintain::remote::{PullRequestObservationV1, PullRequestPublicationV1, RemoteCheck};
use aos_maintain::run::PackageUpdateRunV1;
use base64::Engine as _;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

use super::inventory::RepositoryCoordinates;
use super::state;

const GITHUB_API: &str = "https://api.github.com";
const MAX_REMOTE_BODY: usize = 2 * 1024 * 1024;
const MAX_REMOTE_PAGES: u32 = 10;
const REMOTE_PAGE_SIZE: usize = 100;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PublicationRequest<'a> {
    schema: &'static str,
    run_id: &'a str,
    remote: &'a str,
    branch: &'a str,
    base_branch: &'a str,
    head: &'a str,
    expected_remote_head: Option<&'a str>,
    evidence_digest: Sha256Digest,
    title: &'a str,
    body: &'a str,
    token_environment: &'a str,
}

pub(super) fn publication_request_digest(
    coordinates: &RepositoryCoordinates,
    run: &PackageUpdateRunV1,
    draft: &PullRequestDraft,
    expected_remote_head: Option<&str>,
    token_environment: &str,
) -> Result<Sha256Digest> {
    validate_environment_name(token_environment)?;
    let request = PublicationRequest {
        schema: "aos.package-update-publication-request/v1",
        run_id: run.run_id.as_str(),
        remote: &coordinates.canonical_remote,
        branch: &draft.branch,
        base_branch: &draft.base_branch,
        head: &draft.head,
        expected_remote_head,
        evidence_digest: draft.evidence_digest,
        title: &draft.title,
        body: &draft.body,
        token_environment,
    };
    Sha256Digest::of_canonical("aos.package-update-publication-request/v1", &request)
}

pub(super) fn default_branch(coordinates: &RepositoryCoordinates) -> Result<String> {
    let output = sanitized_git(&coordinates.root)?
        .args(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        .output()
        .context("resolving origin's default branch")?;
    if !output.status.success() {
        bail!(
            "origin/HEAD is unavailable; set it explicitly with `git remote set-head origin --auto`"
        );
    }
    let value = String::from_utf8(output.stdout).context("origin/HEAD is not UTF-8")?;
    let branch = value
        .trim()
        .strip_prefix("origin/")
        .ok_or_else(|| anyhow::anyhow!("origin/HEAD does not name an origin branch"))?;
    validate_ref_component(branch, "base branch")?;
    Ok(branch.to_string())
}

pub(super) async fn publish(
    coordinates: &RepositoryCoordinates,
    run: &PackageUpdateRunV1,
    draft: &PullRequestDraft,
    expected_remote_head: Option<&str>,
    token_environment: &str,
) -> Result<PullRequestPublicationV1> {
    validate_environment_name(token_environment)?;
    let token = secret_from_environment(token_environment)?;
    verify_candidate(run, draft, token_environment)?;

    let actual_remote_head = remote_head(coordinates, &run.branch, &token)?;
    let already_published = actual_remote_head.as_deref() == Some(draft.head.as_str());
    if !already_published && actual_remote_head.as_deref() != expected_remote_head {
        bail!(
            "remote branch changed since preview; inspect it and create a new publication request"
        );
    }
    if !already_published && let Some(previous) = &actual_remote_head {
        let status = sanitized_git(Path::new(&run.worktree))?
            .args(["merge-base", "--is-ancestor", previous, &draft.head])
            .status()
            .context("verifying publication is fast-forward")?;
        if !status.success() {
            bail!("candidate is not a fast-forward of the expected remote branch");
        }
    }

    if !already_published {
        let lease = match expected_remote_head {
            Some(head) => format!("--force-with-lease=refs/heads/{}:{head}", run.branch),
            None => format!("--force-with-lease=refs/heads/{}:", run.branch),
        };
        let refspec = format!("{}:refs/heads/{}", draft.head, run.branch);
        let status = authenticated_git(
            Path::new(&run.worktree),
            &coordinates.canonical_remote,
            &token,
        )?
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "push",
            &lease,
            &coordinates.canonical_remote,
            &refspec,
        ])
        .status()
        .context("publishing exact candidate branch")?;
        if !status.success() {
            bail!("Git could not atomically publish the exact candidate branch");
        }
    }
    if remote_head(coordinates, &run.branch, &token)?.as_deref() != Some(draft.head.as_str()) {
        bail!("remote branch does not contain the exact candidate after push");
    }

    let (owner, repository) = github_repository(&coordinates.canonical_remote)?;
    let client = github_client(&token)?;
    let pull = reconcile_pull_request(&client, owner, repository, draft).await?;
    if pull.head.sha != draft.head || pull.base.reference != draft.base_branch {
        bail!("GitHub returned a pull request with an unexpected head or base");
    }

    let head = git_object(run, draft.head.clone())?;
    let previous_remote_head = expected_remote_head
        .map(str::to_string)
        .map(|value| git_object(run, value))
        .transpose()?;
    let publication = PullRequestPublicationV1 {
        schema: PACKAGE_UPDATE_PR_PUBLICATION_V1.to_string(),
        run_id: run.run_id.clone(),
        remote: coordinates.canonical_remote.clone(),
        branch: run.branch.clone(),
        base_branch: draft.base_branch.clone(),
        head,
        previous_remote_head,
        evidence_digest: draft.evidence_digest,
        pull_request_number: pull.number,
        pull_request_url: pull.html_url,
        published_at_unix: state::now_unix()?,
    };
    publication.validate()?;
    Ok(publication)
}

pub(super) async fn observe(
    publication: &PullRequestPublicationV1,
    authorization_check: &str,
    token_environment: &str,
) -> Result<PullRequestObservationV1> {
    publication.validate()?;
    if authorization_check.is_empty() || authorization_check.len() > 256 {
        bail!("authorization check name is empty or oversized");
    }
    validate_environment_name(token_environment)?;
    let token = secret_from_environment(token_environment)?;
    let (owner, repository) = github_repository(&publication.remote)?;
    let client = github_client(&token)?;
    let pull: PullResponse = get_json(
        &client,
        &format!(
            "/repos/{owner}/{repository}/pulls/{}",
            publication.pull_request_number
        ),
        None,
    )
    .await?;
    if pull.number != publication.pull_request_number
        || pull.head.sha != publication.head.value
        || pull.head.reference != publication.branch
        || pull.base.reference != publication.base_branch
    {
        bail!("pull request no longer matches the exact published head and base");
    }

    let check_runs = all_check_runs(&client, owner, repository, &publication.head.value).await?;
    let statuses = all_statuses(&client, owner, repository, &publication.head.value).await?;
    let reviews = all_reviews(&client, owner, repository, publication.pull_request_number).await?;

    let mut checks = BTreeMap::<(String, String), RemoteCheck>::new();
    for check in check_runs {
        let conclusion = check.conclusion.unwrap_or_else(|| "pending".to_string());
        let key = ("check-run".to_string(), check.name.clone());
        let candidate = RemoteCheck {
            name: check.name,
            source: "check-run".to_string(),
            conclusion,
        };
        if checks.insert(key, candidate).is_some() {
            bail!("GitHub returned an ambiguous duplicate check-run context");
        }
    }
    for status in statuses {
        let key = ("commit-status".to_string(), status.context.clone());
        let candidate = RemoteCheck {
            name: status.context,
            source: "commit-status".to_string(),
            conclusion: status.state,
        };
        if checks.insert(key, candidate).is_some() {
            bail!("GitHub returned an ambiguous duplicate commit-status context");
        }
    }
    let checks = checks.into_values().collect::<Vec<_>>();
    let succeeded = |value: &str| matches!(value, "success" | "neutral" | "skipped");
    let checks_succeeded =
        !checks.is_empty() && checks.iter().all(|check| succeeded(&check.conclusion));
    let authorization_succeeded = checks
        .iter()
        .any(|check| check.name == authorization_check && check.conclusion == "success");

    let (approvals, changes_requested) = latest_review_counts(reviews)?;
    let merge_commit = pull
        .merged
        .then_some(pull.merge_commit_sha)
        .flatten()
        .map(|value| GitObjectId {
            algorithm: publication.head.algorithm,
            value,
        });
    let observation = PullRequestObservationV1 {
        schema: PACKAGE_UPDATE_PR_OBSERVATION_V1.to_string(),
        run_id: publication.run_id.clone(),
        pull_request_number: publication.pull_request_number,
        head: publication.head.clone(),
        base_branch: publication.base_branch.clone(),
        authorization_check: authorization_check.to_string(),
        authorization_succeeded,
        checks,
        approvals,
        changes_requested,
        mergeable: pull.mergeable.unwrap_or(false),
        checks_succeeded,
        merged: pull.merged,
        merge_commit,
        observed_at_unix: state::now_unix()?,
    };
    observation.validate()?;
    Ok(observation)
}

fn latest_review_counts(reviews: Vec<ReviewResponse>) -> Result<(u32, u32)> {
    let mut latest_reviews = BTreeMap::new();
    for review in reviews {
        if let Some(user) = review.user {
            let state = review.state.to_ascii_uppercase();
            if latest_reviews
                .get(&user.id)
                .is_none_or(|(id, _): &(u64, String)| *id < review.id)
            {
                latest_reviews.insert(user.id, (review.id, state));
            }
        }
    }
    let approvals = latest_reviews
        .values()
        .filter(|(_, state)| state == "APPROVED")
        .count()
        .try_into()
        .context("approval count overflow")?;
    let changes_requested = latest_reviews
        .values()
        .filter(|(_, state)| state == "CHANGES_REQUESTED")
        .count()
        .try_into()
        .context("review count overflow")?;
    Ok((approvals, changes_requested))
}

fn verify_candidate(
    run: &PackageUpdateRunV1,
    draft: &PullRequestDraft,
    _token_environment: &str,
) -> Result<()> {
    let root = Path::new(&run.worktree);
    let output = sanitized_git(root)?
        .args(["status", "--porcelain=v2", "-z"])
        .output()
        .context("checking candidate worktree cleanliness")?;
    if !output.status.success() || !output.stdout.is_empty() {
        bail!("candidate worktree is not clean");
    }
    let head = git_text_without(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let branch = git_text_without(root, &["branch", "--show-current"])?;
    if head != draft.head || branch != run.branch || draft.branch != run.branch {
        bail!("publication draft no longer matches the exact candidate branch");
    }
    Ok(())
}

fn remote_head(
    coordinates: &RepositoryCoordinates,
    branch: &str,
    token: &str,
) -> Result<Option<String>> {
    validate_ref_component(branch, "source branch")?;
    let reference = format!("refs/heads/{branch}");
    let output = authenticated_git(&coordinates.root, &coordinates.canonical_remote, token)?
        .args([
            "ls-remote",
            "--heads",
            &coordinates.canonical_remote,
            &reference,
        ])
        .output()
        .context("querying exact remote branch")?;
    if !output.status.success() {
        bail!("Git could not query the exact remote branch");
    }
    let value = String::from_utf8(output.stdout).context("remote branch response is not UTF-8")?;
    let mut lines = value.lines();
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        bail!("remote returned more than one exact branch");
    }
    let (head, returned_ref) = line
        .split_once('\t')
        .ok_or_else(|| anyhow::anyhow!("remote branch response is malformed"))?;
    if returned_ref != reference {
        bail!("remote returned an unexpected branch");
    }
    Ok(Some(head.to_string()))
}

fn git_text_without(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = sanitized_git(root)?
        .args(arguments)
        .output()
        .with_context(|| format!("running git {}", arguments.join(" ")))?;
    if !output.status.success() {
        bail!("Git command failed: git {}", arguments.join(" "));
    }
    Ok(String::from_utf8(output.stdout)
        .context("Git output is not UTF-8")?
        .trim_end()
        .to_string())
}

fn sanitized_git(root: &Path) -> Result<Command> {
    let path =
        std::env::var_os("PATH").ok_or_else(|| anyhow::anyhow!("PATH is unavailable for Git"))?;
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .env_clear()
        .env("PATH", path)
        .env("HOME", "/var/empty")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "false");
    Ok(command)
}

fn authenticated_git(root: &Path, remote: &str, token: &str) -> Result<Command> {
    let _ = github_repository(remote)?;
    let authorization =
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    let mut command = sanitized_git(root)?;
    command
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "credential.helper")
        .env("GIT_CONFIG_VALUE_0", "")
        .env("GIT_CONFIG_KEY_1", "http.https://github.com/.extraheader")
        .env(
            "GIT_CONFIG_VALUE_1",
            format!("AUTHORIZATION: basic {authorization}"),
        );
    Ok(command)
}

fn git_object(run: &PackageUpdateRunV1, value: String) -> Result<GitObjectId> {
    let object = GitObjectId {
        algorithm: run.base_commit.algorithm,
        value,
    };
    object.validate()?;
    Ok(object)
}

fn github_repository(remote: &str) -> Result<(&str, &str)> {
    let path = remote.strip_prefix("https://github.com/").ok_or_else(|| {
        anyhow::anyhow!("pull-request publication supports canonical GitHub remotes")
    })?;
    let (owner, repository) = path
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("canonical GitHub remote is malformed"))?;
    if owner.is_empty() || repository.is_empty() || repository.contains('/') {
        bail!("canonical GitHub remote is malformed");
    }
    Ok((owner, repository))
}

fn github_client(token: &str) -> Result<reqwest::Client> {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("aos-maintain/0.1"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}"))
            .context("GitHub token contains invalid header bytes")?,
    );
    headers.insert(
        "x-github-api-version",
        HeaderValue::from_static("2026-03-10"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("constructing isolated GitHub publisher")
}

fn secret_from_environment(name: &str) -> Result<String> {
    validate_environment_name(name)?;
    let value = std::env::var(name).with_context(|| {
        format!("required credential environment variable {name} is unavailable")
    })?;
    if value.is_empty() || value.len() > 8192 || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("credential environment value is empty or invalid");
    }
    Ok(value)
}

fn validate_environment_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
    {
        bail!("credential environment variable name is invalid");
    }
    Ok(())
}

fn validate_ref_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 160
        || value.starts_with('-')
        || value.contains("..")
        || value.contains("@{")
        || value.ends_with('.')
        || value.ends_with('/')
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte == b' '
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        bail!("{label} is not a safe Git ref component");
    }
    Ok(())
}

async fn reconcile_pull_request(
    client: &reqwest::Client,
    owner: &str,
    repository: &str,
    draft: &PullRequestDraft,
) -> Result<PullResponse> {
    let head_filter = format!("{owner}:{}", draft.branch);
    let existing: Vec<PullResponse> = get_json(
        client,
        &format!("/repos/{owner}/{repository}/pulls"),
        Some(&format!(
            "state=open&head={head_filter}&base={}",
            draft.base_branch
        )),
    )
    .await?;
    match existing.as_slice() {
        [] => {
            post_json(
                client,
                &format!("/repos/{owner}/{repository}/pulls"),
                &CreatePull {
                    title: &draft.title,
                    head: &draft.branch,
                    base: &draft.base_branch,
                    body: &draft.body,
                },
            )
            .await
        }
        [pull] => {
            if pull.head.sha != draft.head
                || pull.head.reference != draft.branch
                || pull.base.reference != draft.base_branch
            {
                bail!("the matching open pull request has another exact head or base");
            }
            patch_json(
                client,
                &format!("/repos/{owner}/{repository}/pulls/{}", pull.number),
                &UpdatePull {
                    title: &draft.title,
                    body: &draft.body,
                    base: &draft.base_branch,
                },
            )
            .await
        }
        _ => bail!("more than one open pull request matches the exact source branch and base"),
    }
}

async fn all_check_runs(
    client: &reqwest::Client,
    owner: &str,
    repository: &str,
    head: &str,
) -> Result<Vec<CheckRunResponse>> {
    let path = format!("/repos/{owner}/{repository}/commits/{head}/check-runs?filter=latest");
    paginated(
        client,
        &path,
        Some("application/vnd.github+json"),
        |page: CheckRunsResponse| page.check_runs,
    )
    .await
}

async fn all_statuses(
    client: &reqwest::Client,
    owner: &str,
    repository: &str,
    head: &str,
) -> Result<Vec<CommitStatusResponse>> {
    let path = format!("/repos/{owner}/{repository}/commits/{head}/status");
    paginated(client, &path, None, |page: StatusResponse| page.statuses).await
}

async fn all_reviews(
    client: &reqwest::Client,
    owner: &str,
    repository: &str,
    pull_request: u64,
) -> Result<Vec<ReviewResponse>> {
    let path = format!("/repos/{owner}/{repository}/pulls/{pull_request}/reviews");
    paginated(client, &path, None, |page: Vec<ReviewResponse>| page).await
}

async fn paginated<T, U, F>(
    client: &reqwest::Client,
    path: &str,
    accept: Option<&str>,
    project: F,
) -> Result<Vec<U>>
where
    T: serde::de::DeserializeOwned,
    F: Fn(T) -> Vec<U>,
{
    let mut output = Vec::new();
    for page in 1..=MAX_REMOTE_PAGES {
        let mut request = client
            .get(format!("{GITHUB_API}{path}"))
            .query(&[("per_page", REMOTE_PAGE_SIZE), ("page", page as usize)]);
        if let Some(accept) = accept {
            request = request.header(ACCEPT, accept);
        }
        let values = project(decode_response(request.send().await?).await?);
        let complete = values.len() < REMOTE_PAGE_SIZE;
        output.extend(values);
        if complete {
            return Ok(output);
        }
    }
    bail!("GitHub collection exceeds the bounded pagination limit")
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    path: &str,
    query_or_accept: Option<&str>,
) -> Result<T> {
    let mut request = client.get(format!("{GITHUB_API}{path}"));
    if let Some(value) = query_or_accept {
        if value.contains('=') {
            request = request.query(
                &value
                    .split('&')
                    .filter_map(|part| part.split_once('='))
                    .collect::<Vec<_>>(),
            );
        } else {
            request = request.header(ACCEPT, value);
        }
    }
    decode_response(request.send().await?).await
}

async fn post_json<T: serde::de::DeserializeOwned, B: Serialize + ?Sized>(
    client: &reqwest::Client,
    path: &str,
    body: &B,
) -> Result<T> {
    decode_response(
        client
            .post(format!("{GITHUB_API}{path}"))
            .json(body)
            .send()
            .await?,
    )
    .await
}

async fn patch_json<T: serde::de::DeserializeOwned, B: Serialize + ?Sized>(
    client: &reqwest::Client,
    path: &str,
    body: &B,
) -> Result<T> {
    decode_response(
        client
            .patch(format!("{GITHUB_API}{path}"))
            .json(body)
            .send()
            .await?,
    )
    .await
}

async fn decode_response<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let bytes = response.bytes().await.context("reading GitHub response")?;
    if bytes.len() > MAX_REMOTE_BODY {
        bail!("GitHub response exceeds the maintenance bound");
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<ApiError>(&bytes)
            .map(|error| error.message)
            .unwrap_or_else(|_| "unparseable remote error".to_string());
        bail!("GitHub API returned {status}: {message}");
    }
    serde_json::from_slice(&bytes).context("decoding bounded GitHub response")
}

#[derive(Serialize)]
struct CreatePull<'a> {
    title: &'a str,
    head: &'a str,
    base: &'a str,
    body: &'a str,
}

#[derive(Serialize)]
struct UpdatePull<'a> {
    title: &'a str,
    body: &'a str,
    base: &'a str,
}

#[derive(Deserialize)]
struct PullResponse {
    number: u64,
    html_url: String,
    head: PullRef,
    base: PullRef,
    #[serde(default)]
    mergeable: Option<bool>,
    #[serde(default)]
    merged: bool,
    #[serde(default)]
    merge_commit_sha: Option<String>,
}

#[derive(Deserialize)]
struct PullRef {
    #[serde(rename = "ref")]
    reference: String,
    sha: String,
}

#[derive(Deserialize)]
struct CheckRunsResponse {
    check_runs: Vec<CheckRunResponse>,
}

#[derive(Deserialize)]
struct CheckRunResponse {
    name: String,
    conclusion: Option<String>,
}

#[derive(Deserialize)]
struct StatusResponse {
    statuses: Vec<CommitStatusResponse>,
}

#[derive(Deserialize)]
struct CommitStatusResponse {
    context: String,
    state: String,
}

#[derive(Deserialize)]
struct ReviewResponse {
    id: u64,
    state: String,
    user: Option<ReviewUser>,
}

#[derive(Deserialize)]
struct ReviewUser {
    id: u64,
}

#[derive(Deserialize)]
struct ApiError {
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_credential_names_and_git_refs() {
        assert!(validate_environment_name("AOS_GITHUB_TOKEN").is_ok());
        assert!(validate_environment_name("1TOKEN").is_err());
        assert!(validate_ref_component("dplecki/upgrade-zlib-1-3", "branch").is_ok());
        assert!(validate_ref_component("refs/../main", "branch").is_err());
    }

    #[test]
    fn parses_only_canonical_github_repository_urls() {
        assert_eq!(
            github_repository("https://github.com/andyl-technologies/aos").unwrap(),
            ("andyl-technologies", "aos")
        );
        assert!(github_repository("https://example.com/owner/repo").is_err());
    }

    #[test]
    fn review_reduction_uses_numeric_order_not_response_order() {
        let user = |id| Some(ReviewUser { id });
        let reviews = vec![
            ReviewResponse {
                id: 30,
                state: "dismissed".to_string(),
                user: user(1),
            },
            ReviewResponse {
                id: 50,
                state: "changes_requested".to_string(),
                user: user(2),
            },
            ReviewResponse {
                id: 20,
                state: "approved".to_string(),
                user: user(1),
            },
            ReviewResponse {
                id: 60,
                state: "approved".to_string(),
                user: user(2),
            },
        ];

        assert_eq!(latest_review_counts(reviews).unwrap(), (1, 0));
    }
}

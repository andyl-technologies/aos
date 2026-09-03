//! Exact remote publication and pull-request observation contracts.
//!
//! These records retain public identifiers and exact Git object identities.
//! Credentials are intentionally absent from both schemas.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::envelope::GitObjectId;
use crate::identity::RunId;
use crate::{PACKAGE_UPDATE_PR_OBSERVATION_V1, PACKAGE_UPDATE_PR_PUBLICATION_V1};

/// Records the exact branch and matching pull request created by publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PullRequestPublicationV1 {
    /// Selects the exact closed publication schema.
    pub schema: String,
    /// Run whose reviewed candidate was published.
    pub run_id: RunId,
    /// Canonical uncredentialed repository URL.
    pub remote: String,
    /// Exact source branch updated by the publisher.
    pub branch: String,
    /// Exact protected target branch.
    pub base_branch: String,
    /// Candidate commit now at the remote source branch.
    pub head: GitObjectId,
    /// Remote branch value compared before the atomic update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_remote_head: Option<GitObjectId>,
    /// Digest of the complete local evidence dossier.
    pub evidence_digest: Sha256Digest,
    /// GitHub pull-request number.
    pub pull_request_number: u64,
    /// Canonical public pull-request URL.
    pub pull_request_url: String,
    /// Observation time in Unix seconds.
    pub published_at_unix: u64,
}

impl PullRequestPublicationV1 {
    /// Validates identities, bounds, and public URLs.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, malformed Git identity,
    /// unsafe branch, non-GitHub URL, or absent pull-request number.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_UPDATE_PR_PUBLICATION_V1
            || self.pull_request_number == 0
            || self.branch.is_empty()
            || self.branch.len() > 160
            || self.base_branch.is_empty()
            || self.base_branch.len() > 160
        {
            bail!("pull-request publication header is invalid");
        }
        self.head.validate()?;
        if let Some(previous) = &self.previous_remote_head {
            previous.validate()?;
            if previous.algorithm != self.head.algorithm {
                bail!("remote branch changed Git object format");
            }
        }
        validate_github_url(&self.remote, false)?;
        validate_github_url(&self.pull_request_url, true)
    }
}

/// Outcome retained for one exact remote check name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoteCheck {
    /// Exact check-run or commit-status context name.
    pub name: String,
    /// GitHub source kind: `check-run` or `commit-status`.
    pub source: String,
    /// Normalized terminal conclusion, or `pending`.
    pub conclusion: String,
}

/// Records a bounded, read-only observation of one exact pull-request head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PullRequestObservationV1 {
    /// Selects the exact closed observation schema.
    pub schema: String,
    /// Run whose published pull request was queried.
    pub run_id: RunId,
    /// Pull-request number bound by the publication record.
    pub pull_request_number: u64,
    /// Exact source head returned by GitHub.
    pub head: GitObjectId,
    /// Exact base branch returned by GitHub.
    pub base_branch: String,
    /// Exact required contributor-authorization check name.
    pub authorization_check: String,
    /// Whether that exact check was observed successful for `head`.
    pub authorization_succeeded: bool,
    /// Bounded check-run and commit-status observations.
    pub checks: Vec<RemoteCheck>,
    /// Number of reviewers whose latest review is approval.
    pub approvals: u32,
    /// Number of reviewers whose latest review requests changes.
    pub changes_requested: u32,
    /// GitHub's computed mergeability for the exact head.
    pub mergeable: bool,
    /// Whether every observed check is successful and at least one exists.
    pub checks_succeeded: bool,
    /// Whether GitHub reports the pull request merged.
    pub merged: bool,
    /// Protected merge commit identity, when merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_commit: Option<GitObjectId>,
    /// Observation time in Unix seconds.
    pub observed_at_unix: u64,
}

impl PullRequestObservationV1 {
    /// Validates exact-head observation bounds and internal consistency.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, unbounded check data, a
    /// missing authorization check name, or inconsistent merge fields.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_UPDATE_PR_OBSERVATION_V1
            || self.pull_request_number == 0
            || self.base_branch.is_empty()
            || self.base_branch.len() > 160
            || self.authorization_check.is_empty()
            || self.authorization_check.len() > 256
            || self.checks.len() > 512
        {
            bail!("pull-request observation header is invalid");
        }
        self.head.validate()?;
        let mut identities = std::collections::BTreeSet::new();
        for check in &self.checks {
            if check.name.is_empty()
                || check.name.len() > 256
                || !matches!(check.source.as_str(), "check-run" | "commit-status")
                || check.conclusion.is_empty()
                || check.conclusion.len() > 64
                || !identities.insert((&check.source, &check.name))
            {
                bail!("remote check observation is invalid or duplicated");
            }
        }
        if self.merged != self.merge_commit.is_some() {
            bail!("merged observation and merge commit disagree");
        }
        if let Some(commit) = &self.merge_commit {
            commit.validate()?;
            if commit.algorithm != self.head.algorithm {
                bail!("merge commit uses another Git object format");
            }
        }
        Ok(())
    }

    /// Reports whether every fail-closed merge-eligibility condition passed.
    #[must_use]
    pub fn is_merge_eligible(&self) -> bool {
        self.authorization_succeeded
            && self.checks_succeeded
            && self.mergeable
            && self.approvals > 0
            && self.changes_requested == 0
    }
}

fn validate_github_url(value: &str, allow_pull: bool) -> Result<()> {
    let parsed = url::Url::parse(value)?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (!allow_pull
            && parsed
                .path()
                .split('/')
                .filter(|part| !part.is_empty())
                .count()
                != 2)
    {
        bail!("remote publication URL is not a canonical public GitHub URL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::GitObjectFormat;
    use crate::identity::RunId;

    fn object(character: char) -> GitObjectId {
        GitObjectId {
            algorithm: GitObjectFormat::Sha1,
            value: character.to_string().repeat(40),
        }
    }

    #[test]
    fn publication_contains_no_credential_surface() {
        let publication = PullRequestPublicationV1 {
            schema: PACKAGE_UPDATE_PR_PUBLICATION_V1.to_string(),
            run_id: RunId::parse("run-remote-fixture").unwrap(),
            remote: "https://github.com/andyl-technologies/aos".to_string(),
            branch: "dplecki/upgrade-zlib-1-3".to_string(),
            base_branch: "main".to_string(),
            head: object('a'),
            previous_remote_head: None,
            evidence_digest: Sha256Digest::separated("fixture", "evidence"),
            pull_request_number: 42,
            pull_request_url: "https://github.com/andyl-technologies/aos/pull/42".to_string(),
            published_at_unix: 1,
        };
        publication.validate().unwrap();
        let encoded = serde_json::to_string(&publication).unwrap();
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("credential"));
    }

    #[test]
    fn merge_eligibility_is_fail_closed_across_every_axis() {
        let mut observation = PullRequestObservationV1 {
            schema: PACKAGE_UPDATE_PR_OBSERVATION_V1.to_string(),
            run_id: RunId::parse("run-remote-fixture").unwrap(),
            pull_request_number: 42,
            head: object('a'),
            base_branch: "main".to_string(),
            authorization_check: "contributor-authorization".to_string(),
            authorization_succeeded: true,
            checks: vec![RemoteCheck {
                name: "contributor-authorization".to_string(),
                source: "check-run".to_string(),
                conclusion: "success".to_string(),
            }],
            approvals: 1,
            changes_requested: 0,
            mergeable: true,
            checks_succeeded: true,
            merged: false,
            merge_commit: None,
            observed_at_unix: 1,
        };
        observation.validate().unwrap();
        assert!(observation.is_merge_eligible());
        observation.authorization_succeeded = false;
        assert!(!observation.is_merge_eligible());
        observation.authorization_succeeded = true;
        observation.approvals = 0;
        assert!(!observation.is_merge_eligible());
    }
}

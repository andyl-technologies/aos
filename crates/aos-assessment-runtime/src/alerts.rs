//! Pure alert episode reduction, separate from assessment and release authority.
//!
//! `aos.assessment-alert/v1` retains an open issue when a refresh is uncertain.
//! Acknowledgement belongs to an exact episode; it never resolves a finding or
//! grants release eligibility. The journal commits returned transitions and
//! outbox entries together with the assessment's profile heads.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_assessment::input::Profile;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::validation::{sorted, text};

/// Names the versioned durable attention record.
pub const ASSESSMENT_ALERT_V1: &str = "aos.assessment-alert/v1";

/// Separates security, updates and operational coverage attention.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueFamily {
    /// A raw applicable or potentially applicable advisory claim.
    Vulnerability,
    /// An actionable maintained-stream update.
    PackageUpdate,
    /// Loss of required assessment evidence.
    Coverage,
    /// A scoped provider failure rather than per-package exposure.
    SourceHealth,
}

/// Describes one stable issue without treating a scan outcome as attention state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssueObservation {
    /// Stable issue identity within the journal's tenant/resource partition.
    pub issue_key: Sha256Digest,
    /// Exact subject/component context; replacement names alone cannot match it.
    pub context_digest: Sha256Digest,
    /// Issue category with distinct resolution/notification policy.
    pub family: IssueFamily,
    /// Relevant independently evaluated profile.
    pub profile: Profile,
    /// Sorted lineage IDs; vulnerability aliases exclude related/upstream IDs.
    pub lineage_ids: Vec<String>,
    /// Sorted exact provider/query identities supporting this actionable issue.
    pub source_keys: Vec<Sha256Digest>,
    /// Digest of material severity/exploitation/candidate/applicability state.
    pub material_digest: Sha256Digest,
    /// Retains source uncertainty without resolving prior evidence.
    pub uncertain: bool,
}

impl IssueObservation {
    /// Validates bounded lineage and source support without granting trust.
    ///
    /// # Errors
    /// Returns an error for missing/unsorted support or malformed lineage IDs.
    pub fn validate(&self) -> Result<()> {
        if self.lineage_ids.is_empty()
            || self.lineage_ids.len() > 128
            || self.source_keys.len() > 128
        {
            bail!("alert issue lacks bounded lineage/source scope");
        }
        if (self.family == IssueFamily::Vulnerability && self.profile != Profile::Vulnerabilities)
            || (self.family == IssueFamily::PackageUpdate && self.profile != Profile::Updates)
        {
            bail!("alert issue family differs from its evaluated profile");
        }
        sorted(&self.lineage_ids, "issue lineage IDs")?;
        if self.family != IssueFamily::Coverage && self.source_keys.is_empty() {
            bail!("actionable issue lacks exact source support");
        }
        sorted(&self.source_keys, "issue source keys")?;
        for id in &self.lineage_ids {
            text(id, 128, "issue lineage identity")?;
        }
        Ok(())
    }
}

/// Records an authorized acknowledgement against one exact historical episode.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Acknowledgement {
    /// Original stable issue key, retained through lineage changes.
    pub issue_key: Sha256Digest,
    /// Exact episode acknowledged; later reopenings are independent.
    #[serde(with = "crate::validation::decimal_u64")]
    pub episode: u64,
    /// Authenticated actor reference.
    pub actor_ref: String,
    /// Explicit acknowledgement time.
    pub acknowledged_at: Timestamp,
    /// Optional bounded attention note, unrelated to security disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Separates ongoing attention from freshness, acknowledgement and remediation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttentionState {
    /// An issue remains unresolved, including when currently unconfirmed.
    Open,
    /// Fresh complete exact relevant evidence justified resolution.
    Resolved,
    /// Monitoring ended or lineage merged without claiming remediation.
    Retired,
}

/// Persists one stable issue's episode and retained evidence state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentAlertV1 {
    /// Exact attention schema discriminator.
    pub schema: String,
    /// Stable original issue key, preserved across admitted alias merges.
    pub issue_key: Sha256Digest,
    /// Latest exact raw issue support, independent of acknowledgement.
    pub issue: IssueObservation,
    /// Current attention lifecycle state.
    pub state: AttentionState,
    /// Positive monotonic episode; only definitive resolution permits reopening.
    #[serde(with = "crate::validation::decimal_u64")]
    pub episode: u64,
    /// Positive monotonic transition revision for CAS/acknowledgements.
    #[serde(with = "crate::validation::decimal_u64")]
    pub sequence: u64,
    /// Latest assessment whose admission changed or confirmed this record.
    pub assessment_digest: Sha256Digest,
    /// Exact material update time, independent of raw evidence freshness.
    pub updated_at: Timestamp,
    /// Historical acknowledged episodes, retained through lineage changes.
    pub acknowledgements: Vec<Acknowledgement>,
    /// Prior issue keys incorporated into this lineage, sorted and unique.
    pub lineage_keys: Vec<Sha256Digest>,
}

impl AssessmentAlertV1 {
    /// Validates retained lifecycle, bounded acknowledgement and lineage contracts.
    ///
    /// # Errors
    /// Returns an error for invalid schema, episode/revision, or malformed audit scope.
    pub fn validate(&self) -> Result<()> {
        self.issue.validate()?;
        if self.schema != ASSESSMENT_ALERT_V1
            || self.episode == 0
            || self.sequence == 0
            || self.episode > 9_007_199_254_740_991
            || self.sequence > 9_007_199_254_740_991
            || self.acknowledgements.len() > 128
            || self.lineage_keys.len() > 128
        {
            bail!("invalid alert lifecycle or retained audit bounds");
        }
        sorted(&self.acknowledgements, "alert acknowledgement history")?;
        sorted(&self.lineage_keys, "alert lineage keys")?;
        for acknowledgement in &self.acknowledgements {
            if acknowledgement.episode == 0 || acknowledgement.acknowledged_at > self.updated_at {
                bail!("alert acknowledgement has invalid historical scope");
            }
            text(&acknowledgement.actor_ref, 128, "acknowledgement actor")?;
            if let Some(reason) = &acknowledgement.reason {
                text(reason, 4096, "acknowledgement reason")?;
            }
        }
        Ok(())
    }

    /// Adds an authorized exact-episode acknowledgement with revision checking.
    ///
    /// # Errors
    /// Returns an error for resolved/retired work, stale episode/revision,
    /// invalid actor/time or retained history bounds. The journal checks permission.
    pub fn acknowledge(
        &self,
        expected_sequence: u64,
        acknowledgement: Acknowledgement,
    ) -> Result<Self> {
        self.validate()?;
        if self.state != AttentionState::Open
            || self.sequence != expected_sequence
            || acknowledgement.issue_key != self.issue_key
            || acknowledgement.episode != self.episode
            || acknowledgement.acknowledged_at < self.updated_at
        {
            bail!("acknowledgement differs from the current open episode/revision");
        }
        let mut updated = self.clone();
        updated.updated_at = acknowledgement.acknowledged_at.clone();
        updated.acknowledgements.push(acknowledgement);
        updated.acknowledgements.sort();
        updated.acknowledgements.dedup();
        updated.sequence = increment(updated.sequence)?;
        updated.validate()?;
        Ok(updated)
    }
}

/// Provides externally admitted fresh complete evidence for one exact resolution scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResolutionProof {
    /// Exact prior issue context, including artifact/identity/comparator bindings.
    pub context_digest: Sha256Digest,
    /// Relevant evaluated profile; updates cannot clear security alerts.
    pub profile: Profile,
    /// Sorted exact complete/fresh provider/query keys evaluated in this scope.
    pub checked_source_keys: Vec<Sha256Digest>,
}

/// Names a committed attention transition, independently retryable through outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlertTransitionKind {
    /// Starts the first episode.
    Opened,
    /// Starts a new episode after definitive resolution.
    Reopened,
    /// Changes material issue state without inventing a new episode.
    Changed,
    /// Retains an unresolved issue under missing/stale evidence.
    Unconfirmed,
    /// Resolves through exact fresh complete relevant evidence.
    Resolved,
    /// Records a lineage merge while preserving original episode audit.
    Merged,
    /// Retires a merged branch without claiming remediation.
    Retired,
}

/// Returns a state change for one atomic assessment/head/event transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertTransition {
    /// Complete resulting immutable-revision attention record.
    pub alert: AssessmentAlertV1,
    /// Notification/event class; absent for equivalent evidence confirmation.
    pub event: Option<AlertTransitionKind>,
    /// Expected previous revision, absent only for a newly opened issue.
    pub previous_sequence: Option<u64>,
}

/// Reduces exact admitted evidence while preserving episodes and alias audit lineage.
///
/// # Errors
/// Returns an error for duplicate/excessive scopes, invalid existing records,
/// overlapping inconsistent observations, stale timestamps or revision overflow.
/// Resolution proofs are an admission contract: callers must derive them from
/// fresh complete assessments and verify source/identity authority beforehand.
pub fn reduce(
    prior: &[AssessmentAlertV1],
    observations: &[IssueObservation],
    proofs: &[ResolutionProof],
    assessment_digest: Sha256Digest,
    now: &Timestamp,
) -> Result<Vec<AlertTransition>> {
    if prior.len() > 100_000 || observations.len() > 100_000 || proofs.len() > 100_000 {
        bail!("alert reduction exceeds admitted scope");
    }
    let mut existing = BTreeMap::new();
    let mut lineage = BTreeMap::<_, BTreeSet<_>>::new();
    for alert in prior {
        alert.validate()?;
        if &alert.updated_at > now || existing.insert(alert.issue_key, alert).is_some() {
            bail!("duplicate or future alert state");
        }
        if alert.state != AttentionState::Retired {
            for id in &alert.issue.lineage_ids {
                lineage
                    .entry((alert.issue.context_digest, alert.issue.family, id.as_str()))
                    .or_default()
                    .insert(alert.issue_key);
            }
        }
    }
    let mut resolutions = BTreeMap::new();
    for proof in proofs {
        if proof.checked_source_keys.len() > 128 {
            bail!("resolution source scope exceeds bound");
        }
        sorted(&proof.checked_source_keys, "resolution checked sources")?;
        if resolutions
            .insert((proof.context_digest, proof.profile), proof)
            .is_some()
        {
            bail!("duplicate resolution scope");
        }
    }
    let mut seen = BTreeSet::new();
    let mut observed_lineage = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut changes = Vec::new();
    if observations
        .windows(2)
        .any(|pair| pair[0].issue_key >= pair[1].issue_key)
    {
        bail!("observed alert issues must be sorted and unique");
    }
    for observation in observations {
        observation.validate()?;
        if !seen.insert(observation.issue_key) {
            bail!("duplicate observed issue");
        }
        for id in &observation.lineage_ids {
            if !observed_lineage.insert((observation.context_digest, observation.family, id)) {
                bail!("observed alert lineages overlap without equivalence normalization");
            }
        }
        let mut related = observation
            .lineage_ids
            .iter()
            .flat_map(|id| {
                lineage
                    .get(&(observation.context_digest, observation.family, id.as_str()))
                    .into_iter()
                    .flat_map(|keys| keys.iter().copied())
            })
            .collect::<BTreeSet<_>>();
        if let Some(exact) = existing.get(&observation.issue_key) {
            if exact.issue.context_digest != observation.context_digest
                || exact.issue.family != observation.family
            {
                bail!("alert key changed immutable context/family");
            }
            related.insert(observation.issue_key);
        }
        let available = related
            .iter()
            .filter(|key| !used.contains(*key))
            .copied()
            .collect::<Vec<_>>();
        let original = available.first().and_then(|key| existing.get(key).copied());
        let (mut alert, mut event, previous_sequence) = if let Some(original) = original {
            let mut alert = original.clone();
            let event = if matches!(
                alert.state,
                AttentionState::Resolved | AttentionState::Retired
            ) {
                alert.episode = increment(alert.episode)?;
                Some(AlertTransitionKind::Reopened)
            } else if alert.issue.material_digest != observation.material_digest
                || alert.issue.uncertain != observation.uncertain
            {
                Some(AlertTransitionKind::Changed)
            } else {
                None
            };
            alert.state = AttentionState::Open;
            (alert, event, Some(original.sequence))
        } else {
            let alert = AssessmentAlertV1 {
                schema: ASSESSMENT_ALERT_V1.into(),
                issue_key: observation.issue_key,
                issue: observation.clone(),
                state: AttentionState::Open,
                episode: 1,
                sequence: 1,
                assessment_digest,
                updated_at: now.clone(),
                acknowledgements: vec![],
                lineage_keys: related.iter().copied().collect(),
            };
            (alert, Some(AlertTransitionKind::Opened), None)
        };
        alert.issue = observation.clone();
        alert.assessment_digest = assessment_digest;
        alert.updated_at = now.clone();
        if let Some(sequence) = previous_sequence {
            alert.sequence = increment(sequence)?;
        }
        for key in &available {
            used.insert(*key);
        }
        for key in available.iter().skip(1) {
            let merged = existing
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("merged alert disappeared"))?;
            alert.lineage_keys.push(*key);
            alert.lineage_keys.extend(&merged.lineage_keys);
            alert
                .acknowledgements
                .extend(merged.acknowledgements.iter().cloned());
            let mut retired = (*merged).clone();
            retired.state = AttentionState::Retired;
            retired.sequence = increment(retired.sequence)?;
            retired.assessment_digest = assessment_digest;
            retired.updated_at = now.clone();
            changes.push(AlertTransition {
                alert: retired,
                event: Some(AlertTransitionKind::Retired),
                previous_sequence: Some(merged.sequence),
            });
            event = Some(AlertTransitionKind::Merged);
        }
        // A split retains an explicit parent key rather than rewriting its
        // acknowledgement to cover a newly independent observed branch.
        alert
            .lineage_keys
            .extend(related.into_iter().filter(|key| *key != alert.issue_key));
        alert.lineage_keys.sort();
        alert.lineage_keys.dedup();
        alert.acknowledgements.sort();
        alert.acknowledgements.dedup();
        alert.validate()?;
        changes.push(AlertTransition {
            alert,
            event,
            previous_sequence,
        });
    }
    for original in prior
        .iter()
        .filter(|alert| alert.state == AttentionState::Open && !used.contains(&alert.issue_key))
    {
        let resolved = resolutions
            .get(&(original.issue.context_digest, original.issue.profile))
            .is_some_and(|proof| {
                (original.issue.family == IssueFamily::Coverage
                    || !original.issue.source_keys.is_empty())
                    && original
                        .issue
                        .source_keys
                        .iter()
                        .all(|key| proof.checked_source_keys.binary_search(key).is_ok())
            });
        let mut alert = original.clone();
        alert.state = if resolved {
            AttentionState::Resolved
        } else {
            AttentionState::Open
        };
        alert.issue.uncertain = !resolved;
        alert.assessment_digest = assessment_digest;
        alert.updated_at = now.clone();
        alert.sequence = increment(alert.sequence)?;
        let event = if resolved {
            Some(AlertTransitionKind::Resolved)
        } else if !original.issue.uncertain {
            Some(AlertTransitionKind::Unconfirmed)
        } else {
            None
        };
        changes.push(AlertTransition {
            alert,
            event,
            previous_sequence: Some(original.sequence),
        });
    }
    changes.sort_by_key(|change| change.alert.issue_key);
    if changes
        .windows(2)
        .any(|pair| pair[0].alert.issue_key == pair[1].alert.issue_key)
    {
        bail!("inconsistent alert lineage would mutate one episode twice");
    }
    Ok(changes)
}

fn increment(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| anyhow::anyhow!("portable alert revision exhausted"))
}

//! Non-modeled terminal closure of admitted campaign attempts.
//!
//! Operational failures leave attempts claimable. Only an explicit stable
//! coordinator decision enters this owner transaction and closes the exact
//! admission ordinal without manufacturing modeled observation evidence.

use super::*;

/// Stable response for a non-modeled terminal attempt disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonModeledAttemptResult {
    /// Snapshot used as the transition parent.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot that retained the terminal disposition.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact admitted semantic attempt that was closed.
    pub attempt: AttemptId,
    /// Exact admission ordinal closed by the transition.
    pub ordinal: AdmissionOrdinal,
    /// Explicit non-modeled terminal reason.
    pub disposition: NonModeledAttemptDisposition,
    /// Whether an existing transition was returned.
    pub replayed: bool,
}

impl CampaignRepository {
    /// Closes one admitted attempt without fabricating a modeled observation.
    ///
    /// The execution-basis admission supplies the exact ordinal. Repeating the
    /// same attempt and disposition returns the original transition before
    /// checking snapshot staleness. A different disposition or an existing
    /// canonical observation fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, missing or malformed admission,
    /// an already completed or differently closed attempt, invalid owner
    /// projection, storage failure, or final ref conflict.
    pub fn close_attempt_non_modeled(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        attempt: AttemptId,
        disposition: NonModeledAttemptDisposition,
    ) -> Result<NonModeledAttemptResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let closure_key = non_modeled_attempt_key(attempt);
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, closure_key)?
        {
            let fact = self.read_fact(fact_content)?;
            let CampaignFact::AttemptClosed {
                attempt: prior_attempt,
                ordinal,
                disposition: prior_disposition,
            } = fact
            else {
                return Err(integrity("attempt-closure-index-type-mismatch"));
            };
            if prior_attempt != attempt || prior_disposition != disposition {
                return Err(CampaignRepositoryError::AlreadyExists);
            }
            return self.find_non_modeled_attempt_result(
                current_content,
                attempt,
                ordinal,
                disposition,
            );
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }
        let ordinal = self.validate_non_modeled_attempt_basis(&current, attempt)?;
        if self
            .merkle
            .get(
                current.snapshot.roots().observations,
                map_key_content("observations.attempt", attempt.content_id()),
            )?
            .is_some()
        {
            return Err(CampaignRepositoryError::AlreadyExists);
        }

        let fact = CampaignFact::AttemptClosed {
            attempt,
            ordinal,
            disposition,
        };
        self.validate_strict_completion_order(&current, ordinal)?;
        let policy = self.read_policy(current.snapshot.active_policy().content_id())?;
        let fact_content = self.put_fact(&fact)?;
        let mut upserts = non_modeled_attempt_upserts(attempt, ordinal, fact_content);
        if policy.mode() == CampaignMode::Strict {
            upserts.insert(observation_sequence_key(), fact_content);
        }
        let mut accounting = current.snapshot.roots().accounting;
        for (key, value) in &upserts {
            accounting = self.merkle.insert(accounting, *key, *value)?.content_id();
        }
        let mut roots = current.snapshot.roots();
        roots.accounting = accounting;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;

        let next = CampaignSnapshot::successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            crate::CampaignFactId::from_content_id(fact_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(NonModeledAttemptResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    attempt,
                    ordinal,
                    disposition,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    pub(super) fn validate_attempt_closed_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        attempt: AttemptId,
        ordinal: AdmissionOrdinal,
        disposition: NonModeledAttemptDisposition,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "attempt-closure-transition-changed-campaign-basis",
            ));
        }
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity(
                "attempt-closure-transition-changed-unrelated-root",
            ));
        }
        if self.validate_non_modeled_attempt_basis(parent, attempt)? != ordinal {
            return Err(integrity("attempt-closure-transition-ordinal-mismatch"));
        }
        if self
            .merkle
            .get(
                prior.observations,
                map_key_content("observations.attempt", attempt.content_id()),
            )?
            .is_some()
        {
            return Err(integrity("attempt-closure-transition-already-observed"));
        }
        self.validate_strict_completion_order(parent, ordinal)?;
        let mut upserts = non_modeled_attempt_upserts(attempt, ordinal, transition_content);
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if policy.mode() == CampaignMode::Strict {
            upserts.insert(observation_sequence_key(), transition_content);
        }
        for key in upserts.keys() {
            if *key != observation_sequence_key()
                && self.merkle.get(prior.accounting, *key)?.is_some()
            {
                return Err(integrity("attempt-closure-transition-reused-index"));
            }
        }
        if !self
            .merkle
            .equals_after_upserts(prior.accounting, next.accounting, &upserts)?
        {
            return Err(integrity(
                "attempt-closure-transition-accounting-root-mismatch",
            ));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity(
                "attempt-closure-transition-coordination-root-mismatch",
            ));
        }
        let fact = self.read_fact(transition_content)?;
        if fact
            != (CampaignFact::AttemptClosed {
                attempt,
                ordinal,
                disposition,
            })
        {
            return Err(integrity("attempt-closure-transition-fact-mismatch"));
        }
        Ok(())
    }

    fn validate_non_modeled_attempt_basis(
        &self,
        snapshot: &LoadedSnapshot,
        attempt: AttemptId,
    ) -> Result<AdmissionOrdinal, CampaignRepositoryError> {
        let accounting = snapshot.snapshot.roots().accounting;
        if self.merkle.get(
            accounting,
            map_key_content("accounting.attempt", attempt.content_id()),
        )? != Some(attempt.content_id())
        {
            return Err(integrity("attempt-closure-attempt-is-not-admitted"));
        }
        let basis = self
            .merkle
            .get(
                accounting,
                map_key_content("accounting.attempt-execution-basis", attempt.content_id()),
            )?
            .ok_or_else(|| integrity("attempt-closure-execution-basis-is-missing"))?;
        let admission = self.read_attempt_admission(basis)?;
        match admission.role() {
            AttemptAdmissionRole::ExecutionBasis {
                admission_ordinal, ..
            } if admission.attempt() == attempt => Ok(admission_ordinal),
            _ => Err(integrity("attempt-closure-execution-basis-mismatch")),
        }
    }
}

pub(super) fn non_modeled_attempt_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("accounting.attempt-disposition", attempt.content_id())
}

fn non_modeled_ordinal_key(ordinal: AdmissionOrdinal) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-accounting-admission-disposition.v1",
        &ordinal.value().to_be_bytes(),
    )
}

fn non_modeled_attempt_upserts(
    attempt: AttemptId,
    ordinal: AdmissionOrdinal,
    fact: ContentId,
) -> BTreeMap<CampaignHash, ContentId> {
    BTreeMap::from([
        (non_modeled_attempt_key(attempt), fact),
        (non_modeled_ordinal_key(ordinal), fact),
    ])
}

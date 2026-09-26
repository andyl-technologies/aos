//! Snapshot-bound projection of additive campaign grants and canonical spending.
//!
//! Command keys count grants, proposal keys count planning work, and the dense
//! admission sequence counts unique semantic attempts. Auxiliary indexes never
//! spend or grant budget a second time. Version-3 snapshots authenticate an
//! indexed ledger against every causal transition.

use super::*;
use crate::{CampaignBudgetLedger, CampaignBudgetLedgerId, CampaignRoots};

#[cfg(test)]
thread_local! {
    static BUDGET_STAGE_COUNTS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

pub(super) const MAX_PLANNER_REQUEST_BUDGET_PROPOSALS: usize = 65_536;

struct ComputedBudgetSuccessor {
    ledger: CampaignBudgetLedger,
    closure_growth_upper: usize,
}

/// Expected ledger and growth retained only across one local ref transaction.
#[derive(Clone)]
pub(super) struct ExpectedBudgetSuccessor {
    parent: CampaignSnapshotId,
    child: CampaignSnapshotId,
    transition: CampaignFactId,
    roots: CampaignRoots,
    ledger_id: CampaignBudgetLedgerId,
    ledger: CampaignBudgetLedger,
    closure_growth_upper: usize,
    fact: CampaignFact,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CampaignCommandId;
    use std::time::Instant;

    #[test]
    fn local_budget_witness_uses_one_ledger_derivation_per_successor() {
        for count in [16_usize, 32] {
            let (repository, lineage, policy) = super::super::tests::fixture();
            let name = format!("budget-witness-stage-{count}");
            let created = repository
                .create(&name, &lineage, &policy, &BTreeMap::new())
                .expect("create campaign");
            let mut parent = created.snapshot_id();

            BUDGET_STAGE_COUNTS.with(|counts| counts.set((0, 0)));
            let started = Instant::now();
            for ordinal in 0..count {
                let request = ControlRequest {
                    command: CampaignCommandId::from_hash(CampaignHash::derive(
                        "test.budget-witness-stage",
                        &ordinal.to_be_bytes(),
                    )),
                    expected_snapshot: parent,
                    action: CampaignControlAction::GrantBudget(
                        crate::BudgetGrant::new(1, 1).expect("grant"),
                    ),
                };
                parent = repository
                    .apply_control(&name, &request)
                    .expect("grant successor")
                    .new_snapshot;
            }
            let elapsed = started.elapsed();
            let (derivations, cold_validations) = BUDGET_STAGE_COUNTS.with(|counts| counts.get());
            eprintln!(
                "budget witness N{count}: derivations={derivations} cold_validations={cold_validations} elapsed_ms={:.3}",
                elapsed.as_secs_f64() * 1_000.0
            );
            assert_eq!(derivations, count);
            assert_eq!(cold_validations, 0);
        }
    }

    #[test]
    fn local_budget_witness_rejects_another_child_or_ledger() {
        let (repository, lineage, policy) = super::super::tests::fixture();
        let created = repository
            .create("budget-witness", &lineage, &policy, &BTreeMap::new())
            .expect("create campaign");
        let parent = created.snapshot_id();
        let fact = CampaignFact::ControlRequested(ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "test.budget-witness",
                b"grant",
            )),
            expected_snapshot: parent,
            action: CampaignControlAction::GrantBudget(
                crate::BudgetGrant::new(1, 1).expect("grant"),
            ),
        });
        let transition =
            CampaignFactId::from_content_id(repository.put_fact(&fact).expect("publish fact"))
                .expect("fact id");
        let (snapshot, witness) = repository
            .budgeted_successor(
                parent,
                created.snapshot().lineage(),
                created.snapshot().active_policy(),
                created.snapshot().roots(),
                transition,
            )
            .expect("construct child");
        let child = repository.put_snapshot(&snapshot).expect("publish child");
        let loaded = repository.read_snapshot(child).expect("read child");
        repository
            .validate_local_budget_witness(parent.content_id(), child, &loaded, &witness)
            .expect("matching witness");

        let mut wrong_ledger = witness.clone();
        wrong_ledger.ledger = repository
            .read_budget_ledger(created.snapshot().budget_ledger())
            .expect("genesis ledger");
        assert!(matches!(
            repository.validate_local_budget_witness(
                parent.content_id(),
                child,
                &loaded,
                &wrong_ledger,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "local-successor-budget-witness-mismatch"
            })
        ));

        let forged = CampaignSnapshot::successor(
            parent,
            snapshot.lineage(),
            snapshot.active_policy(),
            snapshot.roots(),
            transition,
            created.snapshot().budget_ledger(),
        )
        .expect("forge child ledger binding");
        let forged_child = repository
            .put_snapshot(&forged)
            .expect("publish forged child");
        assert!(matches!(
            repository.prepare_local_successor_checkpoint(
                parent.content_id(),
                forged_child,
                None,
                MAX_SIMPLE_SUCCESSOR_GROWTH,
                &witness,
            ),
            Err(CampaignRepositoryError::Integrity {
                reason: "local-successor-budget-witness-mismatch"
            })
        ));
        assert!(
            !repository
                .validated_heads
                .lock()
                .expect("checkpoint cache")
                .contains_key(&forged_child)
        );
    }

    #[test]
    fn near_limit_budget_witness_still_uses_complete_validation() {
        let (repository, lineage, policy) = super::super::tests::fixture();
        let created = repository
            .create("budget-witness-limit", &lineage, &policy, &BTreeMap::new())
            .expect("create campaign");
        let parent = created.snapshot_id();
        repository
            .validated_heads
            .lock()
            .expect("checkpoint cache")
            .get_mut(&parent.content_id())
            .expect("genesis checkpoint")
            .closure_objects = MAX_CAMPAIGN_CLOSURE_OBJECTS - 1;
        let request = ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(
                "test.budget-witness",
                b"near-limit-grant",
            )),
            expected_snapshot: parent,
            action: CampaignControlAction::GrantBudget(
                crate::BudgetGrant::new(1, 1).expect("grant"),
            ),
        };

        let advanced = repository
            .apply_control("budget-witness-limit", &request)
            .expect("complete fallback validation");
        let checkpoint = repository
            .validated_heads
            .lock()
            .expect("checkpoint cache")
            .get(&advanced.new_snapshot.content_id())
            .copied()
            .expect("promoted child checkpoint");
        assert!(checkpoint.closure_objects < MAX_CAMPAIGN_CLOSURE_OBJECTS - 1);
        assert_eq!(checkpoint.ancestry_depth, 2);
    }
}

/// Reports campaign grants and spending at one authenticated snapshot.
///
/// Totals use `u128` so distinct valid `u64` grants add exactly without wrapping
/// or silently saturating. Spending may exceed grants in historical snapshots;
/// callers must not infer admission permission from a nonzero grant alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignBudgetProjection {
    /// Immutable snapshot whose grants and spending were projected.
    pub snapshot: CampaignSnapshotId,
    /// Sum of proposal allowances from distinct canonical control commands.
    pub granted_proposals: u128,
    /// Sum of attempt allowances from distinct canonical control commands.
    pub granted_attempts: u128,
    /// Number of canonical proposals, including convergent proposals.
    pub spent_proposals: u64,
    /// Number of unique execution bases, excluding additional causes.
    pub spent_attempts: u64,
}

impl CampaignBudgetProjection {
    /// Returns the unspent proposal allowance, or zero for historical debt.
    #[must_use]
    pub const fn remaining_proposals(self) -> u128 {
        self.granted_proposals
            .saturating_sub(self.spent_proposals as u128)
    }

    /// Returns the unspent unique-attempt allowance, or zero for historical debt.
    #[must_use]
    pub const fn remaining_attempts(self) -> u128 {
        self.granted_attempts
            .saturating_sub(self.spent_attempts as u128)
    }
}

impl CampaignRepository {
    /// Reads authenticated request-local spending from the current ledger index.
    pub(super) fn remaining_request_attempts_before(
        &self,
        snapshot: &LoadedSnapshot,
        request: BranchRequestId,
        _ordinal: u64,
        maximum: u64,
        _work: &mut usize,
    ) -> Result<u64, CampaignRepositoryError> {
        let count =
            self.indexed_request_execution_bases(self.parent_budget_ledger(snapshot)?, request)?;
        Ok(maximum.saturating_sub(count))
    }

    /// Projects additive grants and canonical spending at the current head.
    ///
    /// The result names the immutable snapshot read at entry; a concurrent head
    /// change does not mix grants and spending from different snapshots.
    /// This query does not grant permission or mutate the campaign.
    ///
    /// # Errors
    ///
    /// Returns a repository error for an absent campaign, invalid authenticated
    /// head, or unreadable ledger. A failure never yields partial totals.
    pub fn budget_projection(
        &self,
        name: &str,
    ) -> Result<CampaignBudgetProjection, CampaignRepositoryError> {
        let head = self.head(name)?;
        let snapshot = self.read_snapshot(head.content_id())?;
        self.project_campaign_budget(&snapshot)
    }

    pub(super) fn project_campaign_budget(
        &self,
        snapshot: &LoadedSnapshot,
    ) -> Result<CampaignBudgetProjection, CampaignRepositoryError> {
        let ledger = self.read_budget_ledger(snapshot.snapshot.budget_ledger())?;
        Ok(CampaignBudgetProjection {
            snapshot: snapshot.snapshot.id()?,
            granted_proposals: ledger.granted_proposals(),
            granted_attempts: ledger.granted_attempts(),
            spent_proposals: ledger.spent_proposals(),
            spent_attempts: ledger.spent_attempts(),
        })
    }

    pub(super) fn put_budget_ledger(
        &self,
        ledger: CampaignBudgetLedger,
    ) -> Result<CampaignBudgetLedgerId, CampaignRepositoryError> {
        let envelope = ObjectEnvelope::for_budget_ledger(&ledger)?;
        Ok(CampaignBudgetLedgerId::from_content_id(
            self.put_envelope(envelope)?,
        )?)
    }

    pub(crate) fn read_budget_ledger(
        &self,
        id: CampaignBudgetLedgerId,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let envelope = self.read_envelope(id.content_id())?;
        if envelope.record_kind() != crate::CampaignRecordKind::BudgetLedger {
            return Err(integrity("campaign-budget-ledger-kind-mismatch"));
        }
        Ok(CampaignBudgetLedger::from_canonical_bytes(envelope.body())?)
    }

    pub(super) fn parent_budget_ledger(
        &self,
        parent: &LoadedSnapshot,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        self.read_budget_ledger(parent.snapshot.budget_ledger())
    }

    pub(super) fn ensure_budget_available(
        &self,
        parent: &LoadedSnapshot,
        proposals: u64,
        attempts: u64,
    ) -> Result<(), CampaignRepositoryError> {
        self.parent_budget_ledger(parent)?
            .with_spending(proposals, attempts)?;
        Ok(())
    }

    pub(super) fn accounted_attempts(
        &self,
        accounting: ContentId,
    ) -> Result<u64, CampaignRepositoryError> {
        let Some(content) = self.merkle.get(accounting, admission_sequence_key())? else {
            return Ok(0);
        };
        match self.decode_attempt_admission(content)?.role() {
            AttemptAdmissionRole::ExecutionBasis {
                admission_ordinal, ..
            } => Ok(admission_ordinal.value()),
            AttemptAdmissionRole::AdditionalCause { .. } => Err(integrity(
                "admission-sequence-does-not-name-execution-basis",
            )),
        }
    }

    fn successor_budget_ledger(
        &self,
        parent: &LoadedSnapshot,
        roots: CampaignRoots,
        fact: &CampaignFact,
        publish: bool,
    ) -> Result<ComputedBudgetSuccessor, CampaignRepositoryError> {
        #[cfg(test)]
        BUDGET_STAGE_COUNTS.with(|counts| {
            let (derivations, cold_validations) = counts.get();
            counts.set((derivations + 1, cold_validations));
        });

        let prior_ledger = self.parent_budget_ledger(parent)?;
        let mut ledger = prior_ledger;
        let proposals = match fact {
            CampaignFact::ControlRequested(request) => {
                if let CampaignControlAction::GrantBudget(grant) = request.action {
                    ledger = ledger.with_grant(grant)?;
                }
                0
            }
            CampaignFact::ProposalIssued(_) => 1,
            CampaignFact::PlannerAdvanced(step) => {
                match self.read_planner_step(step.content_id())?.disposition() {
                    PlannerDisposition::Issue {
                        issued_proposals, ..
                    } => u64::try_from(issued_proposals.len())
                        .map_err(|_| integrity("campaign-budget-proposal-count-overflow"))?,
                    PlannerDisposition::ContinueScan { .. } | PlannerDisposition::NoWork => 0,
                }
            }
            CampaignFact::CampaignDerived(_)
            | CampaignFact::ChoiceOpportunityDiscovered { .. }
            | CampaignFact::BranchRequestAccepted { .. }
            | CampaignFact::AttemptAdmitted(_)
            | CampaignFact::AttemptClosed { .. }
            | CampaignFact::ObservationCredited(_)
            | CampaignFact::FindingPublished(_)
            | CampaignFact::ObjectiveEvaluationPublished(_)
            | CampaignFact::PolicyActivated(_)
            | CampaignFact::BudgetGranted(_)
            | CampaignFact::PinChanged(_)
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_)
            | CampaignFact::SavepointCaptureRequested(_)
            | CampaignFact::SavepointCaptureResolved(_)
            | CampaignFact::SavepointContinuationSelected(_) => 0,
        };
        let prior_attempts = self.accounted_attempts(parent.snapshot.roots().accounting)?;
        let attempts = self
            .accounted_attempts(roots.accounting)?
            .checked_sub(prior_attempts)
            .ok_or_else(|| integrity("campaign-budget-admission-sequence-regressed"))?;
        let ledger = ledger.with_spending(proposals, attempts)?;
        let root = self.request_spending_root_after(prior_ledger, roots.accounting, publish)?;
        let (admissions, indexed_proposals) =
            self.request_admissions_root_after(prior_ledger, roots.accounting, fact, publish)?;
        let ledger = CampaignBudgetLedger::from_accounted_totals(
            ledger.granted_proposals(),
            ledger.granted_attempts(),
            ledger.spent_proposals(),
            ledger.spent_attempts(),
            root,
            admissions,
        )?;
        let closure_growth_upper =
            Self::request_budget_closure_growth(prior_ledger, ledger, indexed_proposals)?;
        Ok(ComputedBudgetSuccessor {
            ledger,
            closure_growth_upper,
        })
    }

    /// Publishes the ledger required by every newly written successor.
    pub(super) fn budgeted_successor(
        &self,
        parent: CampaignSnapshotId,
        lineage: CampaignLineageId,
        policy: CampaignPolicyId,
        roots: CampaignRoots,
        transition: CampaignFactId,
    ) -> Result<(CampaignSnapshot, ExpectedBudgetSuccessor), CampaignRepositoryError> {
        let loaded = self.read_snapshot(parent.content_id())?;
        let fact = self.read_fact(transition.content_id())?;
        let computed = self.successor_budget_ledger(&loaded, roots, &fact, true)?;
        let ledger_id = self.put_budget_ledger(computed.ledger)?;
        let snapshot =
            CampaignSnapshot::successor(parent, lineage, policy, roots, transition, ledger_id)?;
        let witness = ExpectedBudgetSuccessor {
            parent,
            child: snapshot.id()?,
            transition,
            roots,
            ledger_id,
            ledger: computed.ledger,
            closure_growth_upper: computed.closure_growth_upper,
            fact,
        };
        Ok((snapshot, witness))
    }

    /// Checks that the stored child names exactly the locally constructed ledger.
    pub(super) fn validate_local_budget_witness<'a>(
        &self,
        parent: ContentId,
        child: ContentId,
        loaded: &LoadedSnapshot,
        witness: &'a ExpectedBudgetSuccessor,
    ) -> Result<(&'a CampaignFact, usize), CampaignRepositoryError> {
        if witness.parent.content_id() != parent
            || witness.child.content_id() != child
            || loaded.snapshot.id()? != witness.child
            || loaded.snapshot.parent() != Some(witness.parent)
            || loaded.snapshot.transition() != Some(witness.transition)
            || loaded.snapshot.roots() != witness.roots
            || loaded.snapshot.budget_ledger() != witness.ledger_id
            || self.read_budget_ledger(witness.ledger_id)? != witness.ledger
        {
            return Err(integrity("local-successor-budget-witness-mismatch"));
        }
        Ok((&witness.fact, witness.closure_growth_upper))
    }

    pub(super) fn validate_budget_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        #[cfg(test)]
        BUDGET_STAGE_COUNTS.with(|counts| {
            let (derivations, cold_validations) = counts.get();
            counts.set((derivations, cold_validations + 1));
        });

        let actual = self.read_budget_ledger(child.snapshot.budget_ledger())?;
        let expected = self.successor_budget_ledger(parent, child.snapshot.roots(), fact, false)?;
        if actual != expected.ledger {
            return Err(integrity("campaign-budget-successor-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_genesis_budget(
        &self,
        snapshot: &CampaignSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        let actual = self.read_budget_ledger(snapshot.budget_ledger())?;
        let expected = CampaignBudgetLedger::empty(MerkleMap::empty_content_id()?)?;
        if actual != expected {
            return Err(integrity("campaign-genesis-budget-is-not-empty"));
        }
        Ok(())
    }
}

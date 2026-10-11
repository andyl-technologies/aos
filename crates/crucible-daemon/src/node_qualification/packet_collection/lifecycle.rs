//! Owns one real packet collection grant through publication and original ACK.
//!
//! This caller consumes an already authenticated opaque collection runtime. It
//! cannot construct ordinary readiness or replace its native owner. Every failed
//! step leaves the same runtime and token in the capsule; dropping the capsule
//! uses the runtime's pre-reserved original custody supervisor.

use std::task::{Context, Poll};

use crucible::node_admission::InstalledConformancePlan;
use crucible::node_contract::{
    ActivationPublisher, BeginResult, ConformanceResultPublisher, ConformanceRuntime,
    EffectKnowledge, OperationToken, Refusal, RuntimeError, RuntimePollFailure,
};
use crucible_node_contract::{Id, U64};

use super::super::{ExactCompletionCase, ProductionConformanceRunner, QualificationError};

const MAXIMUM_CASE_BYTES: usize = 8 * 1024 * 1024;

/// Describes the original owning caller's progress without granting permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketCollectionPhase {
    /// Retains the actual inactive runtime before native Arm.
    Prepared,
    /// Retains every actual original Arm receipt before initial publication.
    Armed,
    /// Retains the authentic published activation before the first grant.
    Active,
    /// Retains the same original operation while completion remains pending.
    Pending,
    /// Retains a validated original completion before independent collection.
    Complete,
    /// Retains the independently collected original unacknowledged completion.
    Collected,
    /// Retains the exact original publication attempt for reconciliation.
    Publishing,
    /// Retains the actual original committed result and native consumed ACK.
    Acknowledged,
    /// Retains both independently collected original ACK dispositions.
    Settled,
    /// Retains failed or uncertain original custody without another Begin.
    Held,
}

/// Retains the authentic runtime when caller installation is refused.
pub struct PacketCollectionInstallationFailure {
    /// Describes the original refusal without claiming native reclamation.
    pub error: QualificationError,
    _runtime: Box<ConformanceRuntime>,
}

/// Separates local phase refusal from actual original lifecycle failures.
pub enum PacketCollectionFailure {
    /// Rejects an operation inappropriate to the retained original phase.
    Phase,
    /// Retains a local runtime or publication refusal.
    Runtime(RuntimeError),
    /// Retains the original provider's positive no-effect refusal.
    Refused(Refusal),
    /// Retains the original token and actual uncertain effect disposition.
    Uncertain(EffectKnowledge),
    /// Retains the original native or acknowledgement failure.
    Native(RuntimePollFailure),
    /// Retains the original attempted case and collection refusal.
    Collection(QualificationError),
}

/// Owns one actual output-only packet grant and its two distinct original cases.
///
/// Installation grants no class or execution authority. The opaque runtime
/// reauthenticates the independently installed Refused plan and actual native
/// owner at every dispatch. The independent runner and durable publisher remain
/// mandatory. Neither the runtime nor its activation can escape this capsule.
#[must_use = "retain the same original caller until authentic custody reclamation"]
pub struct PacketCollectionLifecycle {
    runtime: ConformanceRuntime,
    node: Id,
    operation: Option<Id>,
    horizon: U64,
    token: Option<OperationToken>,
    before_ack: Option<ExactCompletionCase>,
    after_ack: Option<ExactCompletionCase>,
    _original_before_ack: ExactCompletionCase,
    _original_after_ack: ExactCompletionCase,
    phase: PacketCollectionPhase,
}

impl PacketCollectionLifecycle {
    /// Reserves both complete expected case bodies before any caller-side effect.
    ///
    /// # Errors
    /// Retains the original runtime on changed node, duplicate case identity,
    /// mismatched request/outcome/input, incorrect ACK disposition or exhausted
    /// whole-case credit. Native and ordinary qualification remain unchanged.
    pub fn install(
        mut runtime: ConformanceRuntime,
        plan: &InstalledConformancePlan,
        node: Id,
        operation: Id,
        horizon: U64,
        before_ack: ExactCompletionCase,
        after_ack: ExactCompletionCase,
    ) -> Result<Self, PacketCollectionInstallationFailure> {
        let checked = (|| {
            runtime
                .validate_inactive_collection_plan(plan)
                .map_err(|_| QualificationError::Refused("foreign packet original runtime plan"))?;
            if before_ack.case == after_ack.case
                || before_ack.acknowledged
                || !after_ack.acknowledged
                || before_ack.request != after_ack.request
                || before_ack.outcome != after_ack.outcome
                || before_ack.input != after_ack.input
                || before_ack.outcome.node != node
                || before_ack.maximum_bytes == 0
                || before_ack.maximum_bytes > MAXIMUM_CASE_BYTES as u64
                || after_ack.maximum_bytes == 0
                || after_ack.maximum_bytes > MAXIMUM_CASE_BYTES as u64
            {
                return Err(QualificationError::Refused(
                    "packet original pre/post acknowledgement cases",
                ));
            }
            // The borrowed whole tuple includes both complete outcomes and all
            // escaped identifiers before either case is retained by the caller.
            super::scope::encoded_size(
                &(
                    &node,
                    &operation,
                    horizon,
                    case_fields(&before_ack),
                    case_fields(&after_ack),
                    case_fields(&before_ack),
                    case_fields(&after_ack),
                ),
                MAXIMUM_CASE_BYTES,
            )?;
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(PacketCollectionInstallationFailure {
                error,
                _runtime: Box::new(runtime),
            });
        }
        // Runner APIs consume each submitted case even on early refusal. Keep
        // their complete original expectations separately, under the precharged
        // four-case budget, before any Arm or native Begin can occur.
        let original_before_ack = copy_case(&before_ack);
        let original_after_ack = copy_case(&after_ack);
        Ok(Self {
            runtime,
            node,
            operation: Some(operation),
            horizon,
            token: None,
            before_ack: Some(before_ack),
            after_ack: Some(after_ack),
            _original_before_ack: original_before_ack,
            _original_after_ack: original_after_ack,
            phase: PacketCollectionPhase::Prepared,
        })
    }

    /// Reports data-only caller progress while retaining all original custody.
    pub fn phase(&self) -> PacketCollectionPhase {
        self.phase
    }

    pub(super) fn original_plan(&self) -> &InstalledConformancePlan {
        self.runtime.collection_plan()
    }

    /// Arms every actual original owner under the same current collecting plan.
    ///
    /// # Errors
    /// Refuses a repeated Arm or current native/source failure. Unwind or refusal
    /// leaves the complete original caller Held, never a fabricated Ready set.
    pub fn arm(&mut self) -> Result<(), PacketCollectionFailure> {
        self.require(PacketCollectionPhase::Prepared)?;
        self.phase = PacketCollectionPhase::Held;
        self.runtime
            .arm_all()
            .map_err(PacketCollectionFailure::Runtime)?;
        self.phase = PacketCollectionPhase::Armed;
        Ok(())
    }

    /// Publishes the authentic post-Arm coordinator through the installed store.
    ///
    /// # Errors
    /// Refuses missing original Arm, repeated activation, stale scope, insufficient
    /// record credit or failed/uncertain durable publication. Original receipts
    /// remain Held without another activation attempt or predicted Ready body.
    pub fn activate_initial(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
        maximum_record_bytes: usize,
    ) -> Result<(), PacketCollectionFailure> {
        self.require(PacketCollectionPhase::Armed)?;
        self.phase = PacketCollectionPhase::Held;
        self.runtime
            .activate_initial(publisher, maximum_record_bytes)
            .map_err(PacketCollectionFailure::Runtime)?;
        self.phase = PacketCollectionPhase::Active;
        Ok(())
    }

    /// Submits the one predeclared original grant exactly once.
    ///
    /// # Errors
    /// Refuses wrong phase, changed installed grant or native refusal/uncertainty.
    /// The original identity is consumed before dispatch; a retained uncertain
    /// token cannot be replaced by another Begin.
    pub fn begin(&mut self) -> Result<(), PacketCollectionFailure> {
        self.require(PacketCollectionPhase::Active)?;
        let operation = self
            .operation
            .take()
            .ok_or(PacketCollectionFailure::Phase)?;
        self.phase = PacketCollectionPhase::Held;
        match self
            .runtime
            .begin_exact(&self.node, operation, self.horizon)
            .map_err(PacketCollectionFailure::Runtime)?
        {
            BeginResult::Accepted(token) => {
                self.token = Some(token);
                self.phase = PacketCollectionPhase::Pending;
                Ok(())
            }
            BeginResult::Uncertain { token, effects } => {
                self.token = Some(token);
                Err(PacketCollectionFailure::Uncertain(effects))
            }
            BeginResult::Refused(refusal) => Err(PacketCollectionFailure::Refused(refusal)),
        }
    }

    /// Polls only the same original token without exposing or repeating Begin.
    ///
    /// # Errors
    /// Refuses wrong phase, foreign/current native scope or failed original work.
    /// Native failure and unwind preserve the original token and runtime Held.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketCollectionFailure>> {
        if self.phase != PacketCollectionPhase::Pending {
            return Poll::Ready(Err(PacketCollectionFailure::Phase));
        }
        let Some(token) = self.token.as_ref() else {
            return Poll::Ready(Err(PacketCollectionFailure::Phase));
        };
        self.phase = PacketCollectionPhase::Held;
        match self.runtime.poll(token, context) {
            Poll::Pending => {
                self.phase = PacketCollectionPhase::Pending;
                Poll::Pending
            }
            Poll::Ready(Ok(_)) => {
                // The complete outcome remains in the same runtime ledger.
                self.phase = PacketCollectionPhase::Complete;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(PacketCollectionFailure::Native(error))),
        }
    }

    /// Collects the distinct original unacknowledged case through the host runner.
    ///
    /// # Errors
    /// Retains the attempted case and native completion on oracle/source refusal,
    /// missing complete bodies or wrong phase. Failed collection is not retried.
    pub fn collect_before_ack(
        &mut self,
        runner: &mut ProductionConformanceRunner<'_>,
    ) -> Result<(), PacketCollectionFailure> {
        self.require(PacketCollectionPhase::Complete)?;
        self.phase = PacketCollectionPhase::Held;
        let case = self
            .before_ack
            .take()
            .ok_or(PacketCollectionFailure::Phase)?;
        self.collect(runner, case)?;
        self.phase = PacketCollectionPhase::Collected;
        Ok(())
    }

    /// Reconciles the same durable result and commits its original consumed ACK.
    ///
    /// # Errors
    /// Refuses wrong phase, unavailable original roots or native ACK uncertainty.
    /// A failed publication can only retry this same runtime/token and publisher
    /// reconciliation; neither Begin nor semantic effects are repeated.
    pub fn publish_and_acknowledge(
        &mut self,
        publisher: &mut dyn ConformanceResultPublisher,
    ) -> Result<(), PacketCollectionFailure> {
        if !matches!(
            self.phase,
            PacketCollectionPhase::Collected | PacketCollectionPhase::Publishing
        ) {
            return Err(PacketCollectionFailure::Phase);
        }
        let token = self.token.as_ref().ok_or(PacketCollectionFailure::Phase)?;
        self.phase = PacketCollectionPhase::Publishing;
        self.runtime
            .publish_and_acknowledge(token, publisher)
            .map_err(PacketCollectionFailure::Native)?;
        self.phase = PacketCollectionPhase::Acknowledged;
        Ok(())
    }

    /// Collects the distinct case from the same actual acknowledged completion.
    ///
    /// # Errors
    /// Refuses missing original ACK, wrong phase or failed installed oracle/body
    /// custody. The acknowledged operation remains in the same runtime on error.
    pub fn collect_after_ack(
        &mut self,
        runner: &mut ProductionConformanceRunner<'_>,
    ) -> Result<(), PacketCollectionFailure> {
        self.require(PacketCollectionPhase::Acknowledged)?;
        self.phase = PacketCollectionPhase::Held;
        let case = self
            .after_ack
            .take()
            .ok_or(PacketCollectionFailure::Phase)?;
        self.collect(runner, case)?;
        self.phase = PacketCollectionPhase::Settled;
        Ok(())
    }

    fn collect(
        &mut self,
        runner: &mut ProductionConformanceRunner<'_>,
        case: ExactCompletionCase,
    ) -> Result<(), PacketCollectionFailure> {
        let token = self.token.as_ref().ok_or(PacketCollectionFailure::Phase)?;
        let mut witness = self
            .runtime
            .original_witness()
            .map_err(PacketCollectionFailure::Runtime)?;
        runner
            .collect_exact_witness(case, &mut witness, token)
            .map_err(PacketCollectionFailure::Collection)?;
        Ok(())
    }

    fn require(&self, phase: PacketCollectionPhase) -> Result<(), PacketCollectionFailure> {
        if self.phase != phase {
            return Err(PacketCollectionFailure::Phase);
        }
        Ok(())
    }
}

fn case_fields(case: &ExactCompletionCase) -> impl serde::Serialize + '_ {
    (
        &case.case,
        &case.oracle,
        &case.request,
        &case.outcome,
        &case.input,
        case.acknowledged,
        case.maximum_bytes,
    )
}

fn copy_case(case: &ExactCompletionCase) -> ExactCompletionCase {
    ExactCompletionCase {
        case: case.case.clone(),
        oracle: case.oracle.clone(),
        request: case.request.clone(),
        outcome: case.outcome.clone(),
        input: case.input.clone(),
        acknowledged: case.acknowledged,
        maximum_bytes: case.maximum_bytes,
    }
}

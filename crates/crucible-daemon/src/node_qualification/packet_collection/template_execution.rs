//! Retains one packet collection owner under prelaunch semantic case templates.
//!
//! The runner records both exact-case attempts before Arm or Begin. Unpredictable
//! native proof identities are bound from the independently retained source and
//! effect socket before reading a common completion. The immutable population,
//! original runtime, token and publishers remain owned across refusal or unwind.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible::node_adapters::cnp::CnpSemanticSource;
use crucible::node_admission::InstalledConformancePlan;
use crucible::node_contract::{
    ActivationPublisher, BeginResult, ConformanceResultPublisher, ConformanceRuntime,
    OperationToken,
};
use crucible_node_contract::{Id, U64};

use super::{InstalledPacketCollectionAuthority, PacketCollectionFailure, PacketCollectionPhase};
use crate::node_qualification::{
    CollectedConformance, ExactCompletionCase, OriginalRealizedCaseReservation,
    ProductionConformanceRunner, QualificationError, QualificationLimits,
};

const MAXIMUM_CASE_BYTES: u64 = 8 * 1024 * 1024;

/// Retains every original owner and any reserved attempt after installation fails.
pub struct PacketTemplateInstallationFailure<'a, A, R> {
    /// Describes the original source, template or finite-credit refusal.
    pub error: QualificationError,
    /// Retains the same inactive runtime, publishers and attempted population.
    pub original: Box<PacketTemplateExecution<'a, A, R>>,
}

/// Owns one genuine packet lifecycle under two fixed, source-installed templates.
///
/// This capsule grants collection progress only. It exposes neither an ordinary
/// runtime nor accepted qualification. Its caller keeps the capsule outside an
/// unwind guard; Drop delegates native custody to the pre-reserved runtime
/// supervisor. Publishing retries the same durable result without another Begin.
#[must_use = "retain the original execution and its actual custody supervisor"]
pub struct PacketTemplateExecution<'a, A, R> {
    authority: &'a InstalledPacketCollectionAuthority,
    runtime: ConformanceRuntime,
    plan: Rc<InstalledConformancePlan>,
    node: Id,
    operation: Option<Id>,
    horizon: U64,
    before: String,
    after: String,
    before_ticket: Option<OriginalRealizedCaseReservation>,
    after_ticket: Option<OriginalRealizedCaseReservation>,
    before_expectation: Option<ExactCompletionCase>,
    after_expectation: Option<ExactCompletionCase>,
    token: Option<OperationToken>,
    runner: Option<ProductionConformanceRunner<'a>>,
    activation: A,
    result: R,
    maximum_record_bytes: usize,
    phase: PacketCollectionPhase,
    collected: Option<CollectedConformance>,
    report_finalization_failed: bool,
}

impl InstalledPacketCollectionAuthority {
    /// Reserves both original case attempts and publishers before native Arm.
    ///
    /// The semantic programme, complete grant and case/oracle identities must
    /// already belong to this installation's immutable plan. Dynamic native proof
    /// identities are deliberately absent until authenticated original execution.
    ///
    /// # Errors
    /// Retains all supplied ownership and any first reserved attempt on foreign
    /// runtime/plan, altered case pair, revoked installation or insufficient
    /// report/coordinator credit. No Child, Arm or Begin occurs here.
    // crucible-lint: allow rust-allow -- The original runtime, plan, two case identities and both publishers are installed together once.
    #[allow(clippy::too_many_arguments)]
    pub fn template_execution<'a, A: ActivationPublisher, R: ConformanceResultPublisher>(
        &'a self,
        runtime: ConformanceRuntime,
        plan: InstalledConformancePlan,
        node: Id,
        operation: Id,
        horizon: U64,
        before: String,
        after: String,
        activation: A,
        result: R,
        limits: QualificationLimits,
        maximum_record_bytes: usize,
    ) -> Result<PacketTemplateExecution<'a, A, R>, Box<PacketTemplateInstallationFailure<'a, A, R>>>
    {
        self.template_execution_shared(
            runtime,
            Rc::new(plan),
            node,
            operation,
            horizon,
            before,
            after,
            activation,
            result,
            limits,
            maximum_record_bytes,
        )
    }

    /// Retains the same opaque plan shared by this original host's publishers.
    ///
    /// Both case attempts are reserved before Arm or Begin. Sharing the plan
    /// preserves its exact installed identity and never reissues authority.
    ///
    /// # Errors
    /// Retains all original custody under the same conditions as `template_execution`.
    // crucible-lint: allow rust-allow -- One original runtime, shared opaque plan, cases and publishers form the original collection owner.
    #[allow(clippy::too_many_arguments)]
    pub fn template_execution_shared<'a, A: ActivationPublisher, R: ConformanceResultPublisher>(
        &'a self,
        runtime: ConformanceRuntime,
        plan: Rc<InstalledConformancePlan>,
        node: Id,
        operation: Id,
        horizon: U64,
        before: String,
        after: String,
        activation: A,
        result: R,
        limits: QualificationLimits,
        maximum_record_bytes: usize,
    ) -> Result<PacketTemplateExecution<'a, A, R>, Box<PacketTemplateInstallationFailure<'a, A, R>>>
    {
        let mut original = Box::new(PacketTemplateExecution {
            authority: self,
            runtime,
            plan,
            node,
            operation: Some(operation),
            horizon,
            before,
            after,
            before_ticket: None,
            after_ticket: None,
            before_expectation: None,
            after_expectation: None,
            token: None,
            runner: None,
            activation,
            result,
            maximum_record_bytes,
            phase: PacketCollectionPhase::Prepared,
            collected: None,
            report_finalization_failed: false,
        });
        let checked = (|| {
            if maximum_record_bytes == 0
                || maximum_record_bytes > 65_536
                || original.plan.authenticate_authority(self).is_err()
            {
                return Err(QualificationError::Refused(
                    "packet template original plan or coordinator credit",
                ));
            }
            original
                .runtime
                .validate_inactive_collection_plan(&original.plan)
                .map_err(|_| QualificationError::Refused("foreign packet template runtime"))?;
            let operation = original
                .operation
                .as_ref()
                .ok_or(QualificationError::Refused(
                    "original packet operation absent",
                ))?;
            self.oracle.authenticate_case_pair(
                &original.node,
                operation,
                original.horizon,
                &original.before,
                &original.after,
            )?;
            self.current()?;
            // Bound the entire selected tuple before cloning the runner's node,
            // binding and complete plan. The runner separately credits each
            // original observation and immutable case attempt before native work.
            super::scope::encoded_size(
                &(
                    &original.node,
                    operation,
                    horizon,
                    &original.before,
                    &original.after,
                ),
                16_384,
            )?;
            original.runner = Some(ProductionConformanceRunner::new(
                self,
                self.source.installation().descriptor.id.clone(),
                self.source
                    .installation()
                    .binding
                    .compatibility
                    .identity()?,
                &self.plan_bytes,
                &self.plan_reference,
                limits,
            )?);
            let runner = original.runner.as_mut().ok_or(QualificationError::Refused(
                "original packet collector absent",
            ))?;
            original.before_ticket = Some(runner.reserve_exact_case(
                &original.before,
                self.oracle.template_oracle(&original.before)?,
                MAXIMUM_CASE_BYTES,
            )?);
            original.after_ticket = Some(runner.reserve_exact_case(
                &original.after,
                self.oracle.template_oracle(&original.after)?,
                MAXIMUM_CASE_BYTES,
            )?);
            self.current()
        })();
        if let Err(error) = checked {
            original.phase = PacketCollectionPhase::Held;
            return Err(Box::new(PacketTemplateInstallationFailure {
                error,
                original,
            }));
        }
        Ok(*original)
    }
}

impl<A: ActivationPublisher, R: ConformanceResultPublisher> PacketTemplateExecution<'_, A, R> {
    /// Drives at most one phase of the same original collecting execution.
    ///
    /// # Errors
    /// Retains the actual runtime, token, attempts, original expectations and
    /// publishers on refusal or uncertainty. Held never redispatches; Publishing
    /// reconciles only its original result and ACK. Unwind preserves this capsule.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketCollectionFailure>> {
        if self.report_finalization_failed {
            return Poll::Ready(Err(PacketCollectionFailure::Phase));
        }
        let step = match self.phase {
            PacketCollectionPhase::Prepared => self.arm(),
            PacketCollectionPhase::Armed => self.activate(),
            PacketCollectionPhase::Active => self.begin(),
            PacketCollectionPhase::Pending => return self.poll_original(context),
            PacketCollectionPhase::Complete => self.collect(false),
            PacketCollectionPhase::Collected | PacketCollectionPhase::Publishing => {
                self.publish_and_acknowledge()
            }
            PacketCollectionPhase::Acknowledged => self.collect(true),
            PacketCollectionPhase::Settled => {
                if let Some(runner) = self.runner.take() {
                    self.report_finalization_failed = true;
                    self.collected = Some(runner.finish());
                    self.report_finalization_failed = false;
                }
                return Poll::Ready(Ok(()));
            }
            PacketCollectionPhase::Held => return Poll::Ready(Err(PacketCollectionFailure::Phase)),
        };
        if let Err(error) = step {
            return Poll::Ready(Err(error));
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }

    /// Borrows retained complete observations without issuing accepted authority.
    pub fn collected(&self) -> Option<&CollectedConformance> {
        self.collected.as_ref()
    }

    /// Reports data-only progress while retaining all original native ownership.
    pub fn phase(&self) -> PacketCollectionPhase {
        self.phase
    }

    fn arm(&mut self) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketCollectionPhase::Held;
        self.runtime
            .arm_all()
            .map_err(PacketCollectionFailure::Runtime)?;
        self.phase = PacketCollectionPhase::Armed;
        Ok(())
    }

    fn activate(&mut self) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketCollectionPhase::Held;
        self.runtime
            .activate_initial(&mut self.activation, self.maximum_record_bytes)
            .map_err(PacketCollectionFailure::Runtime)?;
        self.phase = PacketCollectionPhase::Active;
        Ok(())
    }

    fn begin(&mut self) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketCollectionPhase::Held;
        let operation = self
            .operation
            .take()
            .ok_or(PacketCollectionFailure::Phase)?;
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

    fn poll_original(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), PacketCollectionFailure>> {
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
                self.phase = PacketCollectionPhase::Complete;
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(PacketCollectionFailure::Native(error))),
        }
    }

    fn collect(&mut self, acknowledged: bool) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketCollectionPhase::Held;
        let case_id = if acknowledged {
            &self.after
        } else {
            &self.before
        };
        // Native/socket inspection and prospective full-case credit precede
        // original_witness: a common completion never supplies its own oracle.
        let case = self
            .authority
            .oracle
            .expected_completion(case_id)
            .map_err(PacketCollectionFailure::Collection)?;
        let retained = copy_case(&case);
        if acknowledged {
            self.after_expectation = Some(retained);
        } else {
            self.before_expectation = Some(retained);
        }
        let ticket = if acknowledged {
            self.after_ticket.take()
        } else {
            self.before_ticket.take()
        }
        .ok_or(PacketCollectionFailure::Phase)?;
        let token = self.token.as_ref().ok_or(PacketCollectionFailure::Phase)?;
        let runner = self.runner.as_mut().ok_or(PacketCollectionFailure::Phase)?;
        let mut witness = self
            .runtime
            .original_witness()
            .map_err(PacketCollectionFailure::Runtime)?;
        runner
            .collect_exact_witness_reserved(ticket, case, &mut witness, token)
            .map_err(PacketCollectionFailure::Collection)?;
        self.phase = if acknowledged {
            PacketCollectionPhase::Settled
        } else {
            PacketCollectionPhase::Collected
        };
        Ok(())
    }

    fn publish_and_acknowledge(&mut self) -> Result<(), PacketCollectionFailure> {
        let token = self.token.as_ref().ok_or(PacketCollectionFailure::Phase)?;
        self.phase = PacketCollectionPhase::Publishing;
        self.runtime
            .publish_and_acknowledge(token, &mut self.result)
            .map_err(PacketCollectionFailure::Native)?;
        self.phase = PacketCollectionPhase::Acknowledged;
        Ok(())
    }
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

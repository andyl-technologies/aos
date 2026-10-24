//! Drives one full three-owner runtime through nine source-authenticated windows.
//!
//! One original reservation capsule records all 54 case attempts before Child or
//! Arm. Attaching a realized runtime keeps that SAME plan, three runners, 27 grant
//! rows and publishers. Every owner begins once per window, all three grants are
//! completed and acknowledged before advancing. Failure or unwind retains the
//! original phase and tokens; publication retries never submit another Begin.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible_engine::{
    node_admission::{ConformanceAdmissionAuthority, InstalledConformancePlan},
    node_contract::{
        ActivationPublisher, BeginResult, ConformanceResultPublisher, ConformanceRuntime,
        OperationToken,
    },
};
use crucible_node_format::ContentRef;

use super::{PacketCollectionFailure, PacketNativeOracle};
use crate::node_qualification::{
    CollectedConformance, ExactCompletionCase, InstalledConformanceAuthority,
    OriginalRealizedCaseReservation, ProductionConformanceRunner, QualificationError,
    QualificationLimits,
};

mod schedule;

pub use schedule::{PacketWorldGrant, PacketWorldSchedule};

const CASE_BYTES: u64 = 8 * 1024 * 1024;

/// Borrows exact prelaunch configuration for one shared original world actor.
pub struct PacketWorldReservationRequest<'a, T> {
    /// Borrows the independently installed SAME whole-world collection authority.
    pub authority: &'a T,
    /// Shares the original opaque complete Refused plan with all three peers.
    pub plan: Rc<InstalledConformancePlan>,
    /// Borrows its exact complete canonical public plan bytes.
    pub plan_bytes: &'a [u8],
    /// Borrows the exact public plan content identity.
    pub plan_reference: &'a ContentRef,
    /// Owns the fixed source-installed nine-window, 27-grant schedule.
    pub schedule: PacketWorldSchedule,
    /// Retains three independent original native/socket observation owners.
    pub oracles: [Rc<PacketNativeOracle>; 3],
    /// Bounds each original population and full native observation body closure.
    pub limits: QualificationLimits,
}

struct OriginalGrant {
    before: Option<OriginalRealizedCaseReservation>,
    after: Option<OriginalRealizedCaseReservation>,
    token: Option<OperationToken>,
    before_expectation: Option<ExactCompletionCase>,
    after_expectation: Option<ExactCompletionCase>,
    attempted: bool,
}

/// Retains original reserved attempts and configuration after prelaunch refusal.
pub struct PacketWorldReservationFailure<'a, T> {
    /// Reports original scope, credit or fixed template refusal.
    pub error: QualificationError,
    /// Retains all original attempts, runners, native/socket oracles and plan.
    pub original: Box<PacketWorldCaseReservations<'a, T>>,
}

/// Owns all 54 original case tickets before native process launch or Arm.
///
/// This is an owning reservation, not an accepted class or Ready token. Drop
/// retains no native process because realization has not yet been attached.
#[must_use = "retain all original reserved attempts when preparation fails"]
pub struct PacketWorldCaseReservations<'a, T> {
    authority: &'a T,
    plan: Rc<InstalledConformancePlan>,
    schedule: PacketWorldSchedule,
    oracles: [Rc<PacketNativeOracle>; 3],
    runners: [Option<ProductionConformanceRunner<'a>>; 3],
    originals: Vec<OriginalGrant>,
}

impl<'a, T: InstalledConformanceAuthority + ConformanceAdmissionAuthority>
    PacketWorldCaseReservations<'a, T>
{
    /// Reserves all case attempts under the exact original source templates.
    ///
    /// No Child, Arm, Begin or publication occurs. Callers must invoke this before
    /// launching the peers, keeping returned failure custody outside unwind guards.
    ///
    /// # Errors
    /// Returns the same complete reservation on foreign plan, altered schedule,
    /// missing source-native template, failed authority or insufficient credit.
    ///
    /// Installed callback unwind returns the same retained reservation and its
    /// original attempted rows. Allocation failures remain outside this contract.
    pub fn reserve(
        request: PacketWorldReservationRequest<'a, T>,
    ) -> Result<Self, Box<PacketWorldReservationFailure<'a, T>>> {
        let mut original = Box::new(Self {
            authority: request.authority,
            plan: request.plan,
            schedule: request.schedule,
            oracles: request.oracles,
            runners: [None, None, None],
            originals: Vec::new(),
        });
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.schedule.validate()?;
            original
                .plan
                .authenticate_authority(original.authority)
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
            let evidence = original.plan.evidence();
            if evidence.plan_bytes != request.plan_bytes
                || evidence.plan_ref != request.plan_reference
                || request.limits.maximum_cases < 436
            {
                return Err(refused());
            }
            // Three complete runner plans and 54 body ceilings are bounded before
            // any runner copies or ticket retention. Each runner also precharges
            // its original 18 cases; backend-private allocator peaks are excluded.
            // The installed runner reserves escaped JSON and reference metadata
            // before reading each original case, in addition to its raw body.
            let encoded_case_bytes = CASE_BYTES
                .checked_mul(6)
                .and_then(|bytes| bytes.checked_add(16_384))
                .ok_or_else(refused)?;
            let credits = encoded_case_bytes
                .checked_mul(54)
                .and_then(|body| {
                    request
                        .plan_reference
                        .length
                        .get()
                        .checked_mul(3)
                        .and_then(|plans| body.checked_add(plans))
                })
                .ok_or_else(refused)?;
            if request.limits.maximum_total_evidence_bytes < credits {
                return Err(refused());
            }
            super::scope::encoded_size(&original.schedule, 1024 * 1024)?;
            original
                .originals
                .try_reserve_exact(27)
                .map_err(|_| refused())?;
            for _ in 0..27 {
                original.originals.push(OriginalGrant {
                    before: None,
                    after: None,
                    token: None,
                    before_expectation: None,
                    after_expectation: None,
                    attempted: false,
                });
            }
            for node in 0..3 {
                original.runners[node] = Some(ProductionConformanceRunner::new(
                    original.authority,
                    original.schedule.nodes[node].clone(),
                    original.schedule.bindings[node].clone(),
                    request.plan_bytes,
                    request.plan_reference,
                    request.limits,
                )?);
                let runner = original.runners[node].as_mut().ok_or_else(refused)?;
                for window in 0..9 {
                    let index = window * 3 + node;
                    let grant = &original.schedule.grants[index];
                    let oracle = &original.oracles[node];
                    oracle.authenticate_world_case_pair(
                        &original.schedule.nodes[node],
                        &original.schedule.bindings[node],
                        &grant.operation,
                        &grant.request,
                        &grant.before,
                        &grant.after,
                    )?;
                    let before = oracle.template_oracle(&grant.before)?;
                    let after = oracle.template_oracle(&grant.after)?;
                    original.originals[index].before =
                        Some(runner.reserve_exact_case(&grant.before, before, CASE_BYTES)?);
                    original.originals[index].after =
                        Some(runner.reserve_exact_case(&grant.after, after, CASE_BYTES)?);
                }
            }
            original
                .plan
                .reauthenticate()
                .map_err(|error| QualificationError::Evidence(error.to_string()))
        }));
        let checked = match checked {
            Ok(result) => result,
            Err(_) => Err(QualificationError::Refused(
                "whole packet world installation callback unwound",
            )),
        };
        if let Err(error) = checked {
            return Err(Box::new(PacketWorldReservationFailure { error, original }));
        }
        Ok(*original)
    }

    pub(super) fn has_original_authority(
        &self,
        authority: &T,
        plan: &Rc<InstalledConformancePlan>,
    ) -> bool {
        std::ptr::eq(self.authority, authority) && Rc::ptr_eq(&self.plan, plan)
    }

    /// Attaches the one realized world without exposing its runtime or participants.
    ///
    /// Failure leaves the same runtime, publishers, attempts and plan in the
    /// returned actor. The caller keeps this owning actor outside catch_unwind.
    ///
    /// # Errors
    /// Refuses foreign or active runtime, exhausted publication credit or revoked
    /// original plan. No Arm or native grant is submitted by this method.
    // Success and failure retain the same generic native/publisher ownership;
    // the complete returned capsule must stay explicit in this public contract.
    #[allow(clippy::type_complexity)]
    pub fn attach<A: ActivationPublisher, R: ConformanceResultPublisher>(
        self,
        runtime: ConformanceRuntime,
        activation: A,
        result: R,
        maximum_coordinator_bytes: usize,
    ) -> Result<PacketWorldActor<'a, T, A, R>, Box<PacketWorldActorFailure<'a, T, A, R>>> {
        let mut actor = Box::new(PacketWorldActor {
            cases: self,
            runtime,
            activation,
            result,
            maximum_coordinator_bytes,
            phase: PacketWorldActorPhase::Prepared,
            window: 0,
            member: 0,
            finalized: [None, None, None],
            finalization_failed: false,
        });
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if maximum_coordinator_bytes == 0 || maximum_coordinator_bytes > 65_536 {
                return Err(refused());
            }
            actor
                .runtime
                .validate_inactive_collection_plan(&actor.cases.plan)
                .map_err(|_| refused())?;
            actor
                .cases
                .plan
                .reauthenticate()
                .map_err(|error| QualificationError::Evidence(error.to_string()))
        }));
        let checked = match checked {
            Ok(result) => result,
            Err(_) => Err(QualificationError::Refused(
                "whole packet world installation callback unwound",
            )),
        };
        if let Err(error) = checked {
            actor.phase = PacketWorldActorPhase::Held;
            return Err(Box::new(PacketWorldActorFailure {
                error,
                original: actor,
            }));
        }
        Ok(*actor)
    }
}

/// Reports original once-only world progress without granting authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketWorldActorPhase {
    /// Retains one inactive full world and every case ticket.
    Prepared,
    /// Retains the actual complete Arm/Ready roster under the same activation.
    Armed,
    /// Submits each of this window's three original grants once.
    Begin,
    /// Polls, collects and acknowledges original grants without redispatch.
    Poll,
    /// Collects the authentic pre-ACK original witness.
    BeforeAck,
    /// Reconciles original durable publication and ACK.
    Publish,
    /// Collects the distinct same-token post-ACK original witness.
    AfterAck,
    /// Retains all 27 operations and 54 collected observations.
    Complete,
    /// Retains original custody after uncertain submission, refusal or unwind.
    Held,
}

/// Retains the complete actor after installation refusal.
pub struct PacketWorldActorFailure<'a, T, A, R> {
    /// Reports the actual installation refusal without losing original owners.
    pub error: QualificationError,
    /// Retains all original runtime, plan, ticket and publication custody.
    pub original: Box<PacketWorldActor<'a, T, A, R>>,
}

/// Owns one full-world runtime and nine windows of three original owner grants.
///
/// All native participants retain the same activation and original prepared
/// capsule. Held never begins again. Publish retries only its original immutable
/// body and ACK. Consuming runner finalization remains a separate unwind limit;
/// native runtime, publishers and original tokens stay owned in this actor.
#[must_use = "retain this complete actor and its preowned native supervisors"]
pub struct PacketWorldActor<'a, T, A, R> {
    cases: PacketWorldCaseReservations<'a, T>,
    runtime: ConformanceRuntime,
    activation: A,
    result: R,
    maximum_coordinator_bytes: usize,
    phase: PacketWorldActorPhase,
    window: usize,
    member: usize,
    finalized: [Option<CollectedConformance>; 3],
    finalization_failed: bool,
}

impl<
    T: InstalledConformanceAuthority + ConformanceAdmissionAuthority,
    A: ActivationPublisher,
    R: ConformanceResultPublisher,
> PacketWorldActor<'_, T, A, R>
{
    /// Transfers native runtime custody while keeping every original report and publisher.
    ///
    /// # Errors
    /// Refuses unsupported borrowed cleanup or unresolved original supervision.
    /// No grant or storage placement is replayed and no class is accepted.
    ///
    /// # Panics
    /// Installed cleanup callbacks may unwind. Keep this same actor outside the
    /// unwind boundary; retirement retains its original runtime shell and data.
    pub fn retire_original(&mut self) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.phase = PacketWorldActorPhase::Held;
        self.runtime.retire_original()
    }

    /// Drives one bounded phase of the same full-world original actor.
    ///
    /// # Errors
    /// Retains all original owners and tokens on native, authority, publication
    /// or witness refusal. Uncertain Begin cannot be retried as Accepted.
    ///
    /// # Panics
    /// Installed source/publisher callbacks may unwind. The phase is sealed Held
    /// before them except Publish, whose same original reconciliation is retryable.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), PacketCollectionFailure>> {
        if self.finalization_failed {
            return Poll::Ready(Err(PacketCollectionFailure::Phase));
        }
        let step = match self.phase {
            PacketWorldActorPhase::Prepared => self.arm(),
            PacketWorldActorPhase::Armed => self.activate(),
            PacketWorldActorPhase::Begin => self.begin(),
            PacketWorldActorPhase::Poll => return self.poll_original(context),
            PacketWorldActorPhase::BeforeAck => self.collect(false),
            PacketWorldActorPhase::Publish => self.publish(),
            PacketWorldActorPhase::AfterAck => self.collect(true),
            PacketWorldActorPhase::Complete => {
                for index in 0..3 {
                    if let Some(runner) = self.cases.runners[index].take() {
                        self.finalization_failed = true;
                        self.finalized[index] = Some(runner.finish());
                        self.finalization_failed = false;
                    }
                }
                return Poll::Ready(Ok(()));
            }
            PacketWorldActorPhase::Held => return Poll::Ready(Err(PacketCollectionFailure::Phase)),
        };
        if let Err(error) = step {
            return Poll::Ready(Err(error));
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }

    /// Reports data-only phase while retaining every original owner.
    pub fn phase(&self) -> PacketWorldActorPhase {
        self.phase
    }

    /// Reports the original phase and zero-based window/member without running callbacks.
    pub fn progress(&self) -> (PacketWorldActorPhase, usize, usize) {
        (self.phase, self.window, self.member)
    }

    /// Borrows complete reports after collection without issuing class acceptance.
    pub fn collected(&self) -> &[Option<CollectedConformance>; 3] {
        &self.finalized
    }

    fn arm(&mut self) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketWorldActorPhase::Held;
        self.runtime
            .arm_all()
            .map_err(PacketCollectionFailure::Runtime)?;
        self.phase = PacketWorldActorPhase::Armed;
        Ok(())
    }

    fn activate(&mut self) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketWorldActorPhase::Held;
        self.runtime
            .activate_initial(&mut self.activation, self.maximum_coordinator_bytes)
            .map_err(PacketCollectionFailure::Runtime)?;
        self.phase = PacketWorldActorPhase::Begin;
        Ok(())
    }

    fn begin(&mut self) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketWorldActorPhase::Held;
        let index = self.window * 3 + self.member;
        let grant = &self.cases.schedule.grants[index];
        let original = &mut self.cases.originals[index];
        if original.attempted || original.token.is_some() {
            return Err(PacketCollectionFailure::Phase);
        }
        original.attempted = true;
        // All operation identities and actor slots exist before native Begin;
        // cloning a bounded Id is before the runtime's effect frontier.
        match self
            .runtime
            .begin_exact(
                &self.cases.schedule.nodes[self.member],
                grant.operation.clone(),
                grant.horizon,
            )
            .map_err(PacketCollectionFailure::Runtime)?
        {
            BeginResult::Accepted(token) => {
                original.token = Some(token);
                self.member += 1;
                if self.member == 3 {
                    self.member = 0;
                    self.phase = PacketWorldActorPhase::Poll;
                } else {
                    self.phase = PacketWorldActorPhase::Begin;
                }
                Ok(())
            }
            BeginResult::Uncertain { token, effects } => {
                original.token = Some(token);
                Err(PacketCollectionFailure::Uncertain(effects))
            }
            BeginResult::Refused(refusal) => Err(PacketCollectionFailure::Refused(refusal)),
        }
    }

    fn poll_original(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), PacketCollectionFailure>> {
        let index = self.window * 3 + self.member;
        self.phase = PacketWorldActorPhase::Held;
        let Some(token) = self.cases.originals[index].token.as_ref() else {
            return Poll::Ready(Err(PacketCollectionFailure::Phase));
        };
        match self.runtime.poll(token, context) {
            Poll::Pending => {
                self.phase = PacketWorldActorPhase::Poll;
                Poll::Pending
            }
            Poll::Ready(Ok(_)) => {
                self.phase = PacketWorldActorPhase::BeforeAck;
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(PacketCollectionFailure::Native(error))),
        }
    }

    fn collect(&mut self, acknowledged: bool) -> Result<(), PacketCollectionFailure> {
        self.phase = PacketWorldActorPhase::Held;
        let index = self.window * 3 + self.member;
        let grant = &self.cases.schedule.grants[index];
        let case = self.cases.oracles[self.member]
            .expected_completion(if acknowledged {
                &grant.after
            } else {
                &grant.before
            })
            .map_err(PacketCollectionFailure::Collection)?;
        // This expectation is derived from authentic native records and the
        // independent socket BEFORE obtaining any common completion witness.
        let original = &mut self.cases.originals[index];
        // Retain the independent expectation before any witness/collector
        // callback. An unwind must not erase its source-native association.
        let expected = if acknowledged {
            &mut original.after_expectation
        } else {
            &mut original.before_expectation
        };
        if expected.is_some() {
            return Err(PacketCollectionFailure::Phase);
        }
        *expected = Some(case);
        let expected = expected.as_ref().ok_or(PacketCollectionFailure::Phase)?;
        let case = copy_case(expected);
        let ticket = if acknowledged {
            original.after.take()
        } else {
            original.before.take()
        }
        .ok_or(PacketCollectionFailure::Phase)?;
        let token = original
            .token
            .as_ref()
            .ok_or(PacketCollectionFailure::Phase)?;
        let runner = self.cases.runners[self.member]
            .as_mut()
            .ok_or(PacketCollectionFailure::Phase)?;
        let mut witness = self
            .runtime
            .original_witness()
            .map_err(PacketCollectionFailure::Runtime)?;
        let collected = runner.collect_exact_witness_reserved(ticket, case, &mut witness, token);
        collected.map_err(PacketCollectionFailure::Collection)?;
        if !acknowledged {
            self.phase = PacketWorldActorPhase::Publish;
            return Ok(());
        }
        self.member += 1;
        if self.member < 3 {
            self.phase = PacketWorldActorPhase::Poll;
        } else {
            self.member = 0;
            self.window += 1;
            self.phase = if self.window == 9 {
                PacketWorldActorPhase::Complete
            } else {
                PacketWorldActorPhase::Begin
            };
        }
        Ok(())
    }

    fn publish(&mut self) -> Result<(), PacketCollectionFailure> {
        let token = self.cases.originals[self.window * 3 + self.member]
            .token
            .as_ref()
            .ok_or(PacketCollectionFailure::Phase)?;
        self.runtime
            .publish_and_acknowledge(token, &mut self.result)
            .map_err(PacketCollectionFailure::Native)?;
        self.phase = PacketWorldActorPhase::AfterAck;
        Ok(())
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("whole packet world actor source/plan/credit unavailable")
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

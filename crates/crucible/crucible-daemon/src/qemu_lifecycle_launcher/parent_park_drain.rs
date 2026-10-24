//! Stores the fixed later original phase inside the real boxed launcher.
//!
//! The factory-issued stage and actor Quiescence exist before Pause, imports or
//! native begin. Every failure is moved into one preadmitted body. The
//! outer facade retains the complete source lifecycle through disposition.

use std::sync::Arc;

use crate::{
    ProductionVmParentParkDrainRefusal as Refusal, ProductionVmParentParkDrainRequest as Request,
};
use crucible_engine::NodeId;
use crucible_engine::owned_decode::DecodeScratch;
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use crucible_qemu_host::{
    OriginalActorParkImportError, OriginalActorParkImports, OriginalActorParkQuiescence,
    OriginalActorParkQuiescenceError, OriginalParkSourceError, QemuNodeSetPreparedHotForkSource,
    QmpParentParkResult,
};

use super::QemuAttemptProductionVmNodeLauncher;
use crate::QemuAttemptProcessResourceGuard;
use crate::qemu_campaign_lifecycle::{ConfiguredStageOperation, StagePrepareError};
use crucible_control_api::LifecycleApiError;

#[derive(Debug, thiserror::Error)]
enum PhaseCause {
    #[error("park provider invariant refused: {0}")]
    Invariant(&'static str),
    #[error(transparent)]
    Stage(#[from] StagePrepareError),
    #[error(transparent)]
    Parent(#[from] crucible_host_resources::ram_policy::HostRamPolicyError),
    #[error(transparent)]
    Actor(#[from] OriginalActorParkQuiescenceError),
    #[error(transparent)]
    Imports(#[from] OriginalActorParkImportError),
    #[error(transparent)]
    Source(#[from] OriginalParkSourceError),
    #[error(transparent)]
    Original(#[from] HostSupervisionError),
    #[error(transparent)]
    Attempt(#[from] LifecycleApiError),
    #[error(transparent)]
    Cleanup(#[from] crucible_qemu_host::QemuVmRealizationError),
    #[error("native park refused: {0:?}")]
    Native(QmpParentParkResult),
}

impl PhaseCause {
    fn failure(&self) -> crate::ProductionVmParentParkDrainCause<'_> {
        use crate::ProductionVmParentParkDrainCause as Cause;
        match self {
            Self::Invariant(reason) => Cause::Invariant(reason),
            Self::Stage(first) => Cause::Stage(first.failure()),
            Self::Parent(first) => Cause::Parent(first),
            Self::Actor(first) => Cause::Actor(first),
            Self::Imports(first) => Cause::Imports(first),
            Self::Source(first) => Cause::Source(first),
            Self::Original(first) => Cause::Original(first),
            Self::Attempt(first) => Cause::Attempt(first),
            Self::Native(first) => Cause::Native(first),
            Self::Cleanup(first) => Cause::Cleanup(first),
        }
    }
}

struct PhaseBody {
    node: NodeId,
    original: Arc<HostOperationGuard>,
    stage: Option<ConfiguredStageOperation>,
    actor: Option<OriginalActorParkQuiescence>,
    imports: Option<OriginalActorParkImports>,
    source_binding: Option<crucible_qemu_host::OriginalParkSourceReborrowBinding>,
    receipt: Option<QmpParentParkResult>,
    cleanup: Option<crucible_qemu_host::OriginalParentParkCleanup>,
    cleanup_after: Option<HostSupervisionError>,
    host_return_after: Option<HostSupervisionError>,
    first: Option<PhaseCause>,
    actor_original_after: Option<HostSupervisionError>,
    actor_after: Option<HostSupervisionError>,
    family_after: Option<HostSupervisionError>,
    family_original_after: Option<HostSupervisionError>,
}

pub(super) struct OriginalParkDrainPhase {
    body: Box<PhaseBody>,
    // All real owners and typed causes close before the external actor credit.
    _body_credit: DecodeScratch,
    _name_credit: DecodeScratch,
}

/// Retains the same paid phase after actual native local closure.
///
/// This move-only disposition owns the original phase body, both entered
/// guards and the existing stage facade. It grants no new stage or deadline.
/// The fixed issuer may validate the retained stage before moving that same
/// facade through the consuming handoff; refusal keeps the entire disposition.
pub(crate) struct OriginalParkDrainDisposition {
    phase: OriginalParkDrainPhase,
}

impl OriginalParkDrainDisposition {
    fn verify_originals(&mut self) -> Result<(), Refusal> {
        if self.phase.body.first.is_some() {
            return Err(Refusal::Retained);
        }
        let receipt = self.phase.body.receipt.ok_or(Refusal::Retained)?;
        if receipt.closed_request.is_none() || receipt.has_operation_failure() {
            self.phase.body.first.get_or_insert(PhaseCause::Invariant(
                "disposition lacks actual native local closure",
            ));
            return Err(Refusal::Retained);
        }
        self.phase.record(Ok(receipt)).map(|_| ())
    }

    /// Moves the same facade through the fixed issuer without making an alias.
    ///
    /// The issuer returns that facade on either outcome. It must verify the
    /// exact retained assignment, parent and current containing process owner;
    /// no new stage, guard, event, control charge or native receipt is issued.
    ///
    /// # Errors
    /// Returns the owning disposition after any precheck, issuer or postcheck
    /// refusal. Its first typed cause and independent postcuts stay retained.
    pub(crate) fn handoff_stage<T>(
        mut self,
        invoke: impl FnOnce(
            ConfiguredStageOperation,
        ) -> (ConfiguredStageOperation, Result<T, StagePrepareError>),
    ) -> Result<(Self, T), Self> {
        if self.verify_originals().is_err() {
            return Err(self);
        }
        let Some(stage) = self.phase.body.stage.take() else {
            self.phase
                .body
                .first
                .get_or_insert(PhaseCause::Invariant("disposition stage facade absent"));
            return Err(self);
        };
        let (stage, outcome) = invoke(stage);
        self.phase.body.stage = Some(stage);
        match outcome {
            Ok(value) => {
                if self.verify_originals().is_err() {
                    return Err(self);
                }
                Ok((self, value))
            }
            Err(first) => {
                let _ = self.phase.record(Err(PhaseCause::Stage(first)));
                Err(self)
            }
        }
    }
}

struct PairedOutcome<T> {
    outcome: Result<T, PhaseCause>,
    actor_after: Option<HostSupervisionError>,
    family_after: Option<HostSupervisionError>,
    family_original_after: Option<HostSupervisionError>,
}

impl<T> PairedOutcome<T> {
    fn refused(first: PhaseCause) -> Self {
        Self {
            outcome: Err(first),
            actor_after: None,
            family_after: None,
            family_original_after: None,
        }
    }
}

impl OriginalParkDrainPhase {
    pub(super) fn failure(&self) -> crate::ProductionVmParentParkDrainFailure<'_> {
        let first = self.body.first.as_ref().map(PhaseCause::failure);
        crate::ProductionVmParentParkDrainFailure {
            first,
            cleanup_after: self.body.cleanup_after.as_ref(),
            host_return_after: self.body.host_return_after.as_ref(),
            actor_original_after: self.body.actor_original_after.as_ref(),
            actor_after: self.body.actor_after.as_ref(),
            family_after: self.body.family_after.as_ref(),
            family_original_after: self.body.family_original_after.as_ref(),
        }
    }

    fn record(
        &mut self,
        outcome: Result<QmpParentParkResult, PhaseCause>,
    ) -> Result<QmpParentParkResult, Refusal> {
        // Preserve each independent cut even when work already refused.
        self.body.actor_original_after =
            self.body
                .actor_original_after
                .or(self.body.original.wait_slice().err());
        if let Some(actor) = &self.body.actor {
            let after = match actor
                .with_quiescence(|guard| guard.check_original_quiescence_cancellation())
            {
                Ok((observed, after)) => observed.err().or(after),
                Err(first) => Some(first),
            };
            self.body.actor_after = self.body.actor_after.or(after);
        }
        if let Some(stage) = &self.body.stage {
            let (phase, outer) = stage.observe_original_cuts();
            self.body.family_after = self.body.family_after.or(phase);
            self.body.family_original_after = self.body.family_original_after.or(outer);
        }
        let receipt = match outcome {
            Ok(receipt) => receipt,
            Err(first) => {
                self.body.first.get_or_insert(first);
                return Err(Refusal::Retained);
            }
        };
        self.body.receipt = Some(receipt);
        self.body.cleanup_after = self.body.cleanup_after.or(receipt.cleanup_after);
        self.body.host_return_after = self.body.host_return_after.or(receipt.host_return_after);

        // A returned native first cause remains primary even if the separate
        // Original or Cleanup observation subsequently refuses.
        let mut native = receipt;
        native.cleanup_after = None;
        native.host_return_after = None;
        if native.has_operation_failure() {
            self.body.first.get_or_insert(PhaseCause::Native(receipt));
        }
        if let Some(first) = self
            .body
            .actor_after
            .or(self.body.actor_original_after)
            .or(self.body.family_after)
            .or(self.body.family_original_after)
            .or(self.body.cleanup_after)
            .or(self.body.host_return_after)
        {
            self.body.first.get_or_insert(PhaseCause::Original(first));
        }
        if self.body.first.is_some() {
            Err(Refusal::Retained)
        } else {
            Ok(receipt)
        }
    }

    fn paired<T>(
        &self,
        invoke: impl for<'guards> FnOnce(
            &'guards HostOperationGuard,
            &'guards HostOperationGuard,
        ) -> Result<T, PhaseCause>,
    ) -> PairedOutcome<T> {
        let Some(actor) = self.body.actor.as_ref() else {
            return PairedOutcome::refused(PhaseCause::Invariant("actor phase absent"));
        };
        let Some(stage) = self.body.stage.as_ref() else {
            return PairedOutcome::refused(PhaseCause::Invariant("family phase absent"));
        };
        let actor_result =
            actor.with_quiescence(|actor| stage.with_quiescence(|family| invoke(actor, family)));
        let (actor_after, family_after, outcome) = match actor_result {
            Err(first) => (Some(first), None, Err(first.into())),
            Ok((Err(first), actor_after)) => (actor_after, Some(first), Err(first.into())),
            Ok((Ok((outcome, family_after)), actor_after)) => (actor_after, family_after, outcome),
        };
        let (phase_after, family_original_after) = stage.observe_original_cuts();
        PairedOutcome {
            outcome,
            actor_after,
            family_after: family_after.or(phase_after),
            family_original_after,
        }
    }

    fn retain_pair<T>(&mut self, result: PairedOutcome<T>) -> Result<T, PhaseCause> {
        self.body.actor_after = self.body.actor_after.or(result.actor_after);
        self.body.family_after = self.body.family_after.or(result.family_after);
        self.body.family_original_after = self
            .body
            .family_original_after
            .or(result.family_original_after);
        // Keep the initiating callback cause and its exact independent posts.
        let value = result.outcome?;
        if let Some(first) = result
            .actor_after
            .or(result.family_after)
            .or(result.family_original_after)
        {
            return Err(first.into());
        }
        Ok(value)
    }
}

impl std::fmt::Debug for OriginalParkDrainPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalParkDrainPhase")
            .field("first", &self.body.first)
            .field("actor_original_after", &self.body.actor_original_after)
            .field("actor_after", &self.body.actor_after)
            .field("family_after", &self.body.family_after)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for OriginalParkDrainPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "first: {:?}; actor phase: {:?}; actor original: {:?}; family phase: {:?}; family original: {:?}",
            self.body.first,
            self.body.actor_after,
            self.body.actor_original_after,
            self.body.family_after,
            self.body.family_original_after
        )
    }
}

impl std::error::Error for OriginalParkDrainPhase {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.body.first {
            Some(first) => Some(first),
            None => None,
        }
    }
}

impl<G: QemuAttemptProcessResourceGuard, F> QemuAttemptProductionVmNodeLauncher<G, F> {
    fn begin_next_parent_park_drain(
        &mut self,
        source: &mut QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        correlation: u64,
    ) -> Result<QmpParentParkResult, Refusal> {
        let mut disposition = self
            .parent_park_disposition
            .take()
            .ok_or(Refusal::Unavailable("closed disposition absent"))?;
        let preflight = (|| {
            if !Arc::ptr_eq(original, &disposition.phase.body.original)
                || source.node() != &disposition.phase.body.node
            {
                return Err(PhaseCause::Invariant(
                    "reborrow changed the original parent",
                ));
            }
            disposition
                .verify_originals()
                .map_err(|_| PhaseCause::Invariant("reborrow original disposition refused"))?;
            source.verify_parent_park_reborrow_binding(
                disposition
                    .phase
                    .body
                    .source_binding
                    .as_ref()
                    .ok_or(PhaseCause::Invariant("reborrow source binding absent"))?,
            )?;
            self.owner
                .check_operational_boundary()
                .map_err(PhaseCause::Attempt)?;
            self.owner
                .verify_parent_park_binding(source, original, decoder)?;
            Ok(())
        })();
        if let Err(first) = preflight {
            let _ = disposition.phase.record(Err(first));
            self.parent_park_phase = Some(disposition.phase);
            return Err(Refusal::Retained);
        }
        let Some(registration) = self.park_drain_registration.as_ref() else {
            let _ = disposition.phase.record(Err(PhaseCause::Invariant(
                "authentic park registration companion absent",
            )));
            self.parent_park_phase = Some(disposition.phase);
            return Err(Refusal::Retained);
        };
        let disposition = match registration.reborrow_stage_for_source(
            &source.node().name,
            source,
            &mut self.owner,
            disposition,
        ) {
            Ok(disposition) => disposition,
            Err(disposition) => {
                self.parent_park_phase = Some(disposition.phase);
                return Err(Refusal::Retained);
            }
        };
        // Occupy the launcher before any Pause or native effect. These are the
        // same entered originals and the sealed first pair, with no renewed end.
        self.parent_park_phase = Some(disposition.phase);
        let phase = self.parent_park_phase.as_mut().ok_or(Refusal::Retained)?;
        let begin = (|| {
            phase
                .body
                .stage
                .as_ref()
                .ok_or(PhaseCause::Invariant("stage absent"))?
                .verify_source_parent(source)?;
            let stopped = phase.paired(|actor, family| {
                Ok(source.pause_parent_park_under_originals(actor, family)?)
            });
            let stopped = phase.retain_pair(stopped)?;
            let imports = phase
                .body
                .imports
                .as_ref()
                .ok_or(PhaseCause::Invariant("imports absent"))?;
            let begun = phase.paired(|actor, family| {
                Ok(source.begin_parent_park_under_originals(
                    imports,
                    correlation,
                    stopped,
                    actor,
                    family,
                )?)
            });
            phase.retain_pair(begun)
        })();
        phase.record(begin)
    }

    pub(super) fn invoke_parent_park_drain(
        &mut self,
        source: &mut QemuNodeSetPreparedHotForkSource<'_>,
        request: Request<'_>,
    ) -> Result<QmpParentParkResult, Refusal> {
        match request {
            Request::Begin {
                original,
                decoder,
                correlation,
            } => {
                if self.parent_park_phase.is_some() {
                    return Err(Refusal::Unavailable("launcher phase already entered"));
                }
                if self.parent_park_disposition.is_some() {
                    return self.begin_next_parent_park_drain(
                        source,
                        original,
                        decoder,
                        correlation,
                    );
                }
                let budget = decoder.budget().map_err(Refusal::Actor)?;
                let control_bytes = 2 * std::mem::size_of::<PhaseBody>()
                    + std::mem::size_of::<OriginalParkDrainPhase>()
                    + 2 * std::mem::size_of::<OriginalParkDrainDisposition>()
                    + 2 * std::mem::size_of::<DecodeScratch>();
                let body_credit = budget.reserve_scratch_array::<u8>(control_bytes)?;
                let name_credit = budget.reserve_scratch_array::<u8>(source.node().name.len())?;
                // The actual string clone and typed failure body are born only
                // after their separate original reservations succeed.
                self.parent_park_phase = Some(OriginalParkDrainPhase {
                    body: Box::new(PhaseBody {
                        node: source.node().clone(),
                        original: Arc::clone(original),
                        stage: None,
                        actor: None,
                        imports: None,
                        source_binding: None,
                        receipt: None,
                        cleanup: None,
                        cleanup_after: None,
                        host_return_after: None,
                        first: None,
                        actor_original_after: None,
                        actor_after: None,
                        family_after: None,
                        family_original_after: None,
                    }),
                    _body_credit: body_credit,
                    _name_credit: name_credit,
                });
                let begin = (|| {
                    self.owner
                        .check_operational_boundary()
                        .map_err(PhaseCause::Attempt)?;
                    // Authenticate the real installed Node, containing host,
                    // decoder and retained Preparation before the family issuer
                    // publishes its terminal stage record.
                    self.owner
                        .verify_parent_park_binding(source, original, decoder)?;
                    let registration =
                        self.park_drain_registration
                            .as_ref()
                            .ok_or(PhaseCause::Invariant(
                                "authentic park registration companion absent",
                            ))?;
                    let stage = registration.prepare_stage_for_source(
                        &source.node().name,
                        source,
                        &mut self.owner,
                    )?;
                    let phase = self
                        .parent_park_phase
                        .as_mut()
                        .ok_or(PhaseCause::Invariant("prepaid phase absent"))?;
                    phase.body.stage = Some(stage);
                    phase
                        .body
                        .stage
                        .as_ref()
                        .ok_or(PhaseCause::Invariant("issued stage absent"))?
                        .verify_source_parent(source)?;
                    let actor = self
                        .owner
                        .enter_parent_park_quiescence(source, original, decoder)?;
                    phase.body.actor = Some(actor);
                    let imports = phase.paired(|actor, family| {
                        Ok(self.owner.prepare_parent_park_imports(
                            source, original, decoder, actor, family,
                        )?)
                    });
                    phase.body.imports = Some(phase.retain_pair(imports)?);
                    let source_binding =
                        phase.paired(|_, _| Ok(source.retain_parent_park_reborrow_binding()?));
                    phase.body.source_binding = Some(phase.retain_pair(source_binding)?);
                    let stopped = phase.paired(|actor, family| {
                        Ok(source.pause_parent_park_under_originals(actor, family)?)
                    });
                    let stopped = phase.retain_pair(stopped)?;
                    let imports = phase
                        .body
                        .imports
                        .as_ref()
                        .ok_or(PhaseCause::Invariant("park imports absent"))?;
                    let begun = phase.paired(|actor, family| {
                        Ok(source.begin_parent_park_under_originals(
                            imports,
                            correlation,
                            stopped,
                            actor,
                            family,
                        )?)
                    });
                    phase.retain_pair(begun)
                })();
                self.parent_park_phase
                    .as_mut()
                    .ok_or(Refusal::Unavailable("phase owner lost"))?
                    .record(begin)
            }
            Request::Return => {
                // Cancellation forbids new work, not physical cleanup by the
                // original paid owner. Retain its one finite phase lazily.
                let phase = self
                    .parent_park_phase
                    .as_mut()
                    .ok_or(Refusal::Unavailable("launcher phase absent"))?;
                if source.node() != &phase.body.node {
                    return Err(Refusal::Retained);
                }
                if let Some(receipt) = phase.body.receipt.filter(|receipt| {
                    receipt.closed_request.is_some() && receipt.host_memberships_returned
                }) {
                    return phase.record(Ok(receipt));
                }
                // Healthy progress borrows the same two entered operations.
                // Cleanup's finite clock starts only after an actual refusal.
                if phase.body.cleanup.is_none() {
                    loop {
                        let observed = phase.paired(|actor, family| {
                            Ok(source.return_parent_park_under_originals(actor, family)?)
                        });
                        if let Ok(receipt) = observed.outcome.as_ref() {
                            phase.body.receipt = Some(*receipt);
                        }
                        let receipt = match phase.retain_pair(observed) {
                            Ok(receipt) => receipt,
                            Err(first) => {
                                phase.body.first.get_or_insert(first);
                                break;
                            }
                        };
                        if receipt.host_return_after.is_some() {
                            let _ = phase.record(Ok(receipt));
                            break;
                        }
                        if receipt.closed_request.is_some() && receipt.host_memberships_returned {
                            let receipt = phase.record(Ok(receipt))?;
                            let phase = self.parent_park_phase.take().ok_or(Refusal::Retained)?;
                            self.parent_park_disposition =
                                Some(OriginalParkDrainDisposition { phase });
                            return Ok(receipt);
                        }
                        let waited = phase.paired(|actor, family| {
                            Ok(actor.wait_for_quiescence_change_with(family)?)
                        });
                        if let Err(first) = phase.retain_pair(waited) {
                            phase.body.first.get_or_insert(first);
                            break;
                        }
                    }
                    // A physical return decoded before a failed post remains
                    // consumed; it needs no second transport or Cleanup entry.
                    if let Some(receipt) = phase.body.receipt.filter(|receipt| {
                        receipt.closed_request.is_some() && receipt.host_memberships_returned
                    }) {
                        return phase.record(Ok(receipt));
                    }
                }
                if phase.body.cleanup.is_none() {
                    match self.owner.retain_parent_park_cleanup() {
                        Ok(cleanup) => phase.body.cleanup = Some(cleanup),
                        Err(first) => return phase.record(Err(first.into())),
                    }
                }
                // Keep the non-Clone phase in the body throughout disposition.
                let cleanup = phase.body.cleanup.as_ref().ok_or(Refusal::Retained)?;
                let outcome = (|| {
                    loop {
                        let receipt = source.return_parent_park_under_cleanup(&cleanup)?;
                        // Keep actual physical evidence before inspecting any
                        // semantic status or independent original postcut.
                        phase.body.receipt = Some(receipt);
                        if receipt.closed_request.is_some() && receipt.host_memberships_returned {
                            return Ok(receipt);
                        }
                        if let Some(first) = receipt.host_return_after {
                            return Err(PhaseCause::Original(first));
                        }
                        if let Some(first) = receipt.cleanup_after {
                            return Err(PhaseCause::Original(first));
                        }
                        cleanup.wait_for_change()?;
                    }
                })();
                let receipt = phase.record(outcome)?;
                if receipt.closed_request.is_none() {
                    return Err(Refusal::Retained);
                }
                let phase = self.parent_park_phase.take().ok_or(Refusal::Retained)?;
                self.parent_park_disposition = Some(OriginalParkDrainDisposition { phase });
                Ok(receipt)
            }
        }
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use crate::ProductionVmParentParkDrainCause as Cause;

    #[test]
    fn typed_failure_view_borrows_same_original_and_native_receipt() {
        let original = PhaseCause::Original(HostSupervisionError::Unavailable);
        let Cause::Original(borrowed) = original.failure() else {
            panic!("original cause lost its typed variant");
        };
        let PhaseCause::Original(retained) = &original else {
            unreachable!()
        };
        assert!(std::ptr::eq(borrowed, retained));

        let receipt = QmpParentParkResult {
            status: -5,
            post_status: -6,
            return_status: -5,
            received: true,
            entered: false,
            pending: false,
            native_returned: false,
            terminal_published: false,
            mapped_metadata_bytes: 4096,
            completed_requests: 0,
            lifetime_first_status: -5,
            lifetime_post_status: -6,
            closed_request: None,
            host_memberships_returned: false,
            host_return_after: None,
            cleanup_after: None,
        };
        let native = PhaseCause::Native(receipt);
        let Cause::Native(borrowed) = native.failure() else {
            panic!("native receipt lost its typed variant");
        };
        let PhaseCause::Native(retained) = &native else {
            unreachable!()
        };
        assert!(std::ptr::eq(borrowed, retained));
        assert_eq!(borrowed.status, -5);
        assert_eq!(borrowed.post_status, -6);
    }
}

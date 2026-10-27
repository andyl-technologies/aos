//! Retains the actual initial Controller peer and whole financial stage.
//!
//! The accepted flight owns the native peer and Startup borrow. Receiving owns
//! a clone of the same initially empty financial reservoir. The producer moves
//! every actual financial result into it only at a terminal returned frontier,
//! including refusal after independently owed posts. This avoids a self-reference
//! and preserves actual failure/history/disposal custody without a paid DTO.

use super::{
    RootCompletedPolicyListenerBorrowV1, RootCompletedPolicyListenerOriginalV1,
    RootStartupProvisionErrorV1, ServiceStageV1,
};
use aos_sandbox_broker::receiving::ObservationLifetimeV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedControllerPeerOriginalV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::ResourceVector;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use std::error::Error;
use std::sync::{Arc, OnceLock};

/// Owns the same listener's native peer and its actual financial producer.
pub struct RootStartupControllerPeerOriginalV1<'startup> {
    listener: RootCompletedPolicyListenerOriginalV1,
    startup: RootSelectedStartupBorrowV1<'startup>,
    working: Option<RootControllerPeerFinancialStateV1>,
    provision: RootControllerPeerProvisionOriginalV1,
    lifetime: Option<ObservationLifetimeV1>,
    native: Option<RootSelectedControllerPeerOriginalV1<'startup>>,
    preparation_entered: bool,
    completion_entered: bool,
    closed: bool,
}

/// Borrows the whole actual completed producer, native peer and mutable Initial.
///
/// Neither the separate financial reservoir nor copied prefix DATA constructs
/// this lender. It retains the same physical and financial owners together.
pub struct RootCurrentWritersPredecessorV1<'peer, 'startup, 'initial> {
    original: &'peer RootStartupControllerPeerOriginalV1<'startup>,
    native: &'peer RootSelectedControllerPeerOriginalV1<'startup>,
    initial: &'initial mut RootInitialReceivingOriginalV1,
}

struct RootControllerPeerFinancialStateV1 {
    entry: Option<RootObservationErrorV1>,
    service: ServiceStageV1,
    initial_traffic_shape: Option<Result<ResourceVector, RootObservationErrorV1>>,
    initial_traffic: Option<Result<(), aos_sandbox_broker::receiving::RootFinancialClosedV1>>,
    capture: Option<Result<(), RootObservationErrorV1>>,
    settlement: Option<Result<(), RootObservationErrorV1>>,
    completion: Option<Result<(), RootObservationErrorV1>>,
}

impl RootControllerPeerFinancialStateV1 {
    fn new() -> Self {
        Self {
            entry: None,
            service: ServiceStageV1::default(),
            initial_traffic_shape: None,
            initial_traffic: None,
            capture: None,
            settlement: None,
            completion: None,
        }
    }

    fn ready_prefix(&self) -> Option<ResourceVector> {
        if self.entry.is_some()
            || !matches!(self.initial_traffic, Some(Ok(())))
            || !matches!(self.capture, Some(Ok(())))
            || !matches!(self.service.after, Some(Ok(())))
            || !matches!(self.settlement, Some(Ok(())))
            || self.service.failure().is_some()
        {
            return None;
        }
        self.service.prefix()
    }

    fn completed_prefix(&self) -> Option<ResourceVector> {
        if !matches!(self.completion, Some(Ok(()))) {
            return None;
        }
        self.ready_prefix()
    }

    fn failure_before_native<'a>(
        &'a self,
        financial: &'a RootJournalFinancialOriginalV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        self.entry
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| {
                self.service
                    .permit
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.initial_traffic_shape
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                if matches!(self.initial_traffic, Some(Err(_))) {
                    financial.failure_v1()
                } else {
                    None
                }
            })
            .or_else(|| {
                self.initial_traffic
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.service
                    .post
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.service
                    .currentness_failure
                    .as_ref()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.service
                    .before
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    fn failure_after_native(&self) -> Option<&(dyn Error + 'static)> {
        self.capture
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.service.failure())
            .or_else(|| {
                self.settlement
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.completion
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

/// Retains the real peer producer's whole terminal financial prefix.
///
/// The native factory alone creates its private reservoir. It is empty while
/// the producer still owes work, then retains actual positive or negative
/// stage results. Presence grants no completed prefix, physical peer or role.
pub struct RootControllerPeerProvisionOriginalV1 {
    financial: RootJournalFinancialOriginalV1,
    terminal: Arc<OnceLock<RootControllerPeerFinancialStateV1>>,
}

impl Clone for RootControllerPeerProvisionOriginalV1 {
    fn clone(&self) -> Self {
        Self {
            financial: self.financial.clone(),
            terminal: Arc::clone(&self.terminal),
        }
    }
}

impl RootControllerPeerProvisionOriginalV1 {
    fn new(financial: &RootJournalFinancialOriginalV1) -> Self {
        Self {
            financial: financial.clone(),
            terminal: Arc::new(OnceLock::new()),
        }
    }

    /// Copies only the real completed permit for this same actual Initial.
    ///
    /// # Errors
    /// Refuses incomplete or failed results and another original. No fresh healthy
    /// gate may suppress an already-owed history worker/post after body refusal.
    pub fn completed_prefix_data_v1(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<ResourceVector, RootObservationErrorV1> {
        let financial = initial
            .financial_diagnostic_original_v1()
            .ok_or(RootObservationErrorV1::Service)?;
        if !financial.same_original_data_v1(&self.financial) {
            return Err(RootObservationErrorV1::Service);
        }
        self.terminal
            .get()
            .and_then(RootControllerPeerFinancialStateV1::completed_prefix)
            .ok_or(RootObservationErrorV1::Service)
    }

    /// Borrows the same actual terminal financial first cause, including refusal.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let state = self.terminal.get()?;
        state
            .failure_before_native(&self.financial)
            .or_else(|| state.failure_after_native())
    }
}

impl RootCompletedPolicyListenerBorrowV1<'_, '_> {
    /// Parks the actual peer producer before its old fixed-Stage once frontier.
    ///
    /// The genuine caller parks this producer and a clone of its private
    /// provision owner before invoking preparation under its real exclusion.
    /// # Errors
    /// Refuses a repeated entry before allocating a provision reservoir.
    pub fn park_controller_peer_once_v1<'startup>(
        self,
        startup: RootSelectedStartupBorrowV1<'startup>,
    ) -> Result<RootStartupControllerPeerOriginalV1<'startup>, RootObservationErrorV1> {
        self.initial.claim_initial_controller_peer_once_v1()?;
        let original = RootStartupControllerPeerOriginalV1 {
            provision: RootControllerPeerProvisionOriginalV1::new(&self.original.financial),
            listener: self.completed.clone(),
            startup,
            working: Some(RootControllerPeerFinancialStateV1::new()),
            lifetime: None,
            native: None,
            preparation_entered: false,
            completion_entered: false,
            closed: false,
        };
        Ok(original)
    }
}

impl<'startup> RootStartupControllerPeerOriginalV1<'startup> {
    /// Requires this same producer's actual resident financial allocation.
    ///
    /// This passive comparison performs no healthy entry or native observation.
    ///
    /// # Errors
    /// Refuses another actual provision reservoir.
    pub fn require_provision_original_v1(
        &self,
        original: &RootControllerPeerProvisionOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        if Arc::ptr_eq(&self.provision.terminal, &original.terminal) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    /// Lends this same producer's provision owner before its first fixed Stage.
    #[must_use]
    pub fn financial_provision_original_v1(&self) -> RootControllerPeerProvisionOriginalV1 {
        self.provision.clone()
    }

    /// Enters the original fixed permit, traffic and service-before exactly once.
    ///
    /// # Errors
    /// Retains every reached result and runs an armed owed post before refusal.
    pub fn prepare_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.preparation_entered {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.preparation_entered = true;
        if self.listener.original.require_initial(initial).is_err()
            || !self
                .startup
                .same_financial_original_data_v1(&self.listener.original.financial)
        {
            self.closed = true;
            if let Some(state) = self.working.as_mut() {
                state.entry = Some(RootObservationErrorV1::Service);
            }
            self.finish_financial_terminal_once_v1()?;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let state = self
            .working
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        let demand = (|| {
            let base = self
                .listener
                .original
                .completed_listener()
                .ok_or_else(RootStartupProvisionErrorV1::closed)?;
            let peer = RootSelectedControllerPeerOriginalV1::fixed_demand()?;
            base.checked_add(
                aos_sandbox_model::component_receiving::without_operation_traffic_v1(peer),
            )
            .map_err(|_| RootStartupProvisionErrorV1::closed())
        })();
        state
            .service
            .stage_once(demand, &self.listener.original.financial, exclusion);
        if matches!(state.service.permit, Some(Ok(_))) {
            state.initial_traffic_shape =
                Some(RootSelectedControllerPeerOriginalV1::fixed_demand());
            if let Some(Ok(peer)) = &state.initial_traffic_shape {
                state.initial_traffic = Some(initial.debit_observer_traffic_v1(
                    aos_sandbox_model::component_receiving::operation_traffic_demand_v1(*peer),
                ));
            }
            if matches!(state.initial_traffic, Some(Ok(()))) {
                state
                    .service
                    .before_once(initial, &self.startup, exclusion, true);
            }
        }
        if matches!(state.service.before, Some(Ok(()))) {
            self.lifetime = Some(ObservationLifetimeV1::begin());
            return Ok(());
        }
        state.service.finish_owed_once(&self.startup, exclusion);
        self.finish_financial_terminal_once_v1()?;
        initial.latch_root_refusal_v1();
        Err(RootObservationErrorV1::Service)
    }

    /// Captures the same accepted native stream outside all receiving guards.
    ///
    /// # Errors
    /// Refuses reentry or incomplete preparation and retains all native partials.
    pub fn capture_once_v1(
        &mut self,
        stream: &RetainedUnixStream,
    ) -> Result<(), RootObservationErrorV1> {
        let state = self
            .working
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        if self.closed || state.capture.is_some() || !matches!(state.service.before, Some(Ok(()))) {
            self.closed = true;
            if state.capture.is_none() {
                state.capture = Some(Err(RootObservationErrorV1::Service));
            }
            return Err(RootObservationErrorV1::Service);
        }
        let Some(lifetime) = self.lifetime.take() else {
            self.closed = true;
            state.capture = Some(Err(RootObservationErrorV1::Service));
            return Err(RootObservationErrorV1::Service);
        };
        self.native = Some(self.startup.new_controller_peer_original_v1(lifetime));
        state.capture = Some(
            self.native
                .as_mut()
                .ok_or(RootObservationErrorV1::Service)?
                .capture_once(stream),
        );
        if matches!(state.capture, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    /// Runs the independent prearmed Root post after the actual capture result.
    ///
    /// # Errors
    /// Preserves failed capture and owed post results without healthy reentry.
    pub fn finish_capture_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let state = self
            .working
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        if state.capture.is_none() || state.service.after.is_some() {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        state.service.finish_owed_once(&self.startup, exclusion);
        if matches!(state.capture, Some(Ok(()))) && matches!(state.service.after, Some(Ok(()))) {
            return Ok(());
        }
        self.finish_financial_terminal_once_v1()?;
        initial.latch_root_refusal_v1();
        Err(RootObservationErrorV1::Service)
    }

    /// Settles the same native qualifier after its original Root post.
    ///
    /// # Errors
    /// Preserves the actual native settlement error outside receiving guards.
    pub fn settle_positive_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        let state = self
            .working
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        if self.closed
            || state.settlement.is_some()
            || !matches!(state.capture, Some(Ok(())))
            || !matches!(state.service.after, Some(Ok(())))
        {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        state.settlement = Some(match self.native.as_mut() {
            Some(native) => native.settle_positive_once(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(state.settlement, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    /// Parks every actual final result before the original completion return.
    ///
    /// # Errors
    /// Retains failed settlement or actual association refusal, and retires the
    /// prearmed sampler only after the same complete positive financial prefix.
    pub fn complete_after_settlement_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        if self.completion_entered {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.completion_entered = true;
        let association = initial
            .financial_diagnostic_original_v1()
            .is_some_and(|actual| actual.same_original_data_v1(&self.listener.original.financial));
        let state = self
            .working
            .as_mut()
            .ok_or(RootObservationErrorV1::Service)?;
        state.completion = Some(if association && state.ready_prefix().is_some() {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        });
        let positive = matches!(state.completion, Some(Ok(())));
        if positive {
            state.service.retire_positive();
        }
        self.finish_financial_terminal_once_v1()?;
        if positive {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(RootObservationErrorV1::Service)
        }
    }

    fn finish_financial_terminal_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        let state = self.working.take().ok_or(RootObservationErrorV1::Service)?;
        if let Err(state) = self.provision.terminal.set(state) {
            self.working = Some(state);
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        Ok(())
    }

    fn financial_state_v1(&self) -> Option<&RootControllerPeerFinancialStateV1> {
        match &self.working {
            Some(state) => Some(state),
            None => self.provision.terminal.get(),
        }
    }

    fn completed_prefix(&self) -> Option<ResourceVector> {
        if self.closed || !self.completion_entered || self.failure_v1().is_some() {
            return None;
        }
        self.financial_state_v1()?.completed_prefix()
    }

    /// Borrows the same native qualifier without a new observation or grant.
    ///
    /// # Errors
    /// Refuses missing actual native custody; it does not assert completion.
    pub fn native_peer_original_v1(
        &self,
    ) -> Result<&RootSelectedControllerPeerOriginalV1<'startup>, RootObservationErrorV1> {
        self.native.as_ref().ok_or(RootObservationErrorV1::Service)
    }

    /// Requires the original complete financial prefix and native peer.
    ///
    /// # Errors
    /// Refuses actual failed or incomplete original custody.
    pub fn require_completed_v1(&self) -> Result<(), RootObservationErrorV1> {
        if self.completed_prefix().is_none() {
            return Err(RootObservationErrorV1::Service);
        }
        self.native_peer_original_v1()?.require_completed()
    }

    /// Lends this whole completed producer and same actual Initial to Current.
    ///
    /// # Errors
    /// Refuses foreign Initial, missing financial/native completion or refusal.
    pub fn borrow_current_writers_predecessor_v1<'peer, 'initial>(
        &'peer self,
        initial: &'initial mut RootInitialReceivingOriginalV1,
    ) -> Result<RootCurrentWritersPredecessorV1<'peer, 'startup, 'initial>, RootObservationErrorV1>
    {
        self.listener
            .original
            .require_initial(initial)
            .map_err(|()| RootObservationErrorV1::Service)?;
        self.require_completed_v1()?;
        Ok(RootCurrentWritersPredecessorV1 {
            original: self,
            native: self.native_peer_original_v1()?,
            initial,
        })
    }

    /// Borrows the actual first financial, service or native qualifier cause.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let state = self.financial_state_v1()?;
        state
            .failure_before_native(&self.listener.original.financial)
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(RootSelectedControllerPeerOriginalV1::failure)
            })
            .or_else(|| state.failure_after_native())
    }
}

impl<'peer, 'startup, 'initial> RootCurrentWritersPredecessorV1<'peer, 'startup, 'initial> {
    /// Splits only actual Initial mutation from its genuine financial borrower.
    pub fn split_initial_v1(
        &mut self,
    ) -> (
        &mut RootInitialReceivingOriginalV1,
        &RootJournalFinancialOriginalV1,
    ) {
        (self.initial, &self.original.listener.original.financial)
    }

    /// Borrows the whole genuine predecessor beyond the transient Initial loan.
    ///
    /// The reference is tied to the actual producer, not to this temporary loan.
    /// Its financial state alone cannot replace the retained native peer.
    pub(in crate::native) fn producer_original_v1(
        &self,
    ) -> &'peer RootStartupControllerPeerOriginalV1<'startup> {
        self.original
    }

    /// Borrows this same completed native Controller qualifier.
    #[must_use]
    pub fn controller_peer_original_v1(&self) -> &RootSelectedControllerPeerOriginalV1<'startup> {
        self.native
    }

    /// Copies the actual completed original permit without creating a grant.
    ///
    /// # Errors
    /// Refuses subsequent same-original failure or unavailable completion.
    pub fn completed_prefix_data_v1(&self) -> Result<ResourceVector, RootObservationErrorV1> {
        self.original
            .listener
            .original
            .require_initial(self.initial)
            .map_err(|()| RootObservationErrorV1::Service)?;
        self.original
            .completed_prefix()
            .ok_or(RootObservationErrorV1::Service)
    }
}

pub(super) fn completion_control_bytes_v1() -> Option<usize> {
    use std::mem::{align_of, size_of};
    let backing = size_of::<OnceLock<RootControllerPeerFinancialStateV1>>()
        .checked_add(2usize.checked_mul(size_of::<usize>())?)?
        .checked_add(align_of::<OnceLock<RootControllerPeerFinancialStateV1>>().checked_sub(1)?)?;
    backing
        .checked_mul(2)?
        .checked_add(size_of::<RootStartupControllerPeerOriginalV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<RootControllerPeerFinancialStateV1>().checked_mul(3)?)?
        .checked_add(size_of::<Option<RootControllerPeerFinancialStateV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootControllerPeerFinancialStateV1>>().checked_mul(3)?)?
        .checked_add(size_of::<RootControllerPeerProvisionOriginalV1>().checked_mul(9)?)?
        .checked_add(
            size_of::<Result<RootStartupControllerPeerOriginalV1<'_>, RootObservationErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                RootCompletedPolicyListenerBorrowV1<'_, '_>,
                RootSelectedStartupBorrowV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(9)?)?
        .checked_add(size_of::<Option<RootJournalFinancialOriginalV1>>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<RootJournalFinancialOriginalV1, RootObservationErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(size_of::<&RootStartupControllerPeerOriginalV1<'_>>().checked_mul(9)?)?
        .checked_add(
            size_of::<(
                &RootControllerPeerProvisionOriginalV1,
                &RootInitialReceivingOriginalV1,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootStartupControllerPeerOriginalV1<'_>,
                &mut RootInitialReceivingOriginalV1,
                &RootUpperMutationGuardV1<'_>,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Result<&RootSelectedControllerPeerOriginalV1<'_>, RootObservationErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Option<&RootSelectedControllerPeerOriginalV1<'_>>>().checked_mul(3)?,
        )?
        .checked_add(size_of::<Option<&RootControllerPeerFinancialStateV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(12)?)?
        .checked_add(
            size_of::<(
                &RootControllerPeerFinancialStateV1,
                &RootJournalFinancialOriginalV1,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<&RootControllerPeerFinancialStateV1>().checked_mul(9)?)?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(12)?)?
        .checked_add(
            size_of::<(
                &RootStartupControllerPeerOriginalV1<'_>,
                &RootControllerPeerProvisionOriginalV1,
            )>()
            .checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, RootObservationErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<ResourceVector>>().checked_mul(6)?)?
        .checked_add(
            size_of::<
                Option<
                    &Result<
                        aos_sandbox_broker::receiving::RootPrearmedHistoryServicePostV1,
                        aos_sandbox_broker::receiving::RootStartupServicePostErrorV1,
                    >,
                >,
            >()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Option<&aos_sandbox_broker::receiving::RootStartupServicePostErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(24)?)
}

impl RootStartupControllerPeerOriginalV1<'_> {
    /// Measures this peer's whole financial reservoir and actual interfaces.
    ///
    /// The real listener fixed Stage pays these memory bytes before any accepted
    /// peer construction, including a later refused peer-specific fixed Stage.
    #[must_use]
    pub fn financial_receiving_control_bytes_v1() -> Option<usize> {
        completion_control_bytes_v1()?
            .checked_add(
                RootInitialReceivingOriginalV1::initial_controller_claim_control_bytes_v1()?,
            )?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
    }
}

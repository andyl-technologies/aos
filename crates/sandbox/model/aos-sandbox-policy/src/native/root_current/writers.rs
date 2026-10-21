//! Owns the genuine completed-peer to two-bare-writer receiving sequence.
//!
//! Authority precedes Policy. The Authority remains a bare native journal:
//! issuer credentials are not captured until the later RootOpen and Ready
//! frontiers. Refusal retains every reached opening and independently owed post.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::native::journal::{
    RootPolicyJournalConstructionOriginalV1, RootPolicyJournalPurposeV1, RootPolicyJournalV1,
};
use crate::native::startup::{
    RootCurrentWritersPredecessorV1,
    RootStartupProvisionErrorV1, ServiceStageV1,
};
use crate::native::target::{RootPolicyTargetConstructionOriginalV1, RootPolicyTargetOriginalV1};
use crate::native::PolicyNativeJournalErrorV1;
use super::preopen_geometry::{ProtectedJournalPreopenReplayExtentV1,
    protected_authority_preopen_replay_extent_for_prefix_v1,
    protected_policy_preopen_replay_extent_for_prefix_v1};

type ProvisionError = RootStartupProvisionErrorV1;

/// Preserves actual variable geometry and a deferred upper compiled supplement.
#[derive(Debug, thiserror::Error)]
pub enum RootCurrentWriterDemandErrorV1 {
    /// Retains the actual native or representation cause.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    /// Retains the actual receiving-stage refusal.
    #[error(transparent)]
    Provision(#[from] RootStartupProvisionErrorV1),
    /// Selects the caller's owning original semantic quote error at its old slot.
    ///
    /// This is negative-only. It cannot authorize a replay without a supplement.
    #[error("the original upper semantic representation quote refused")]
    DeferredUpperSemanticQuote,
}


/// Retains the actual original current writers and cumulative receiving stages.
///
/// The only factory requires a genuine completed Controller peer predecessor.
/// This owner supplies no RootOpen completion, Ready bytes, issuer pins, or
/// publication permission. It cannot adopt a journal or a completed permit.
pub(in crate::native) struct RootCurrentWritersOriginalV1 {
    financial: RootJournalFinancialOriginalV1,
    entry: Result<(), RootObservationErrorV1>,
    authority_service: ServiceStageV1,
    policy_service: ServiceStageV1,
    authority: RootPolicyJournalConstructionOriginalV1,
    policy: RootPolicyTargetConstructionOriginalV1,
    variable: [Option<Result<ResourceVector, RootCurrentWriterDemandErrorV1>>; 2],
    semantic_supplements: [Option<ResourceVector>; 2],
    extents: [Option<Result<ProtectedJournalPreopenReplayExtentV1, PolicyNativeJournalErrorV1>>; 2],
    replay: [Option<Result<(), RootObservationErrorV1>>; 2],
    taken: [Option<Result<(), RootObservationErrorV1>>; 2],
    pair: RootCurrentBarePairV1,
    completion: Option<Result<(), RootObservationErrorV1>>,
}

/// Keeps actual bare-writer custody before the later issuer role exists.
///
/// Fields and constructors stay native-private. No supplied DATA can construct
/// this owner, and no public query exposes a mutable bare journal.
pub(in crate::native) struct RootCurrentBarePairV1 {
    authority: Option<RootPolicyJournalV1>,
    policy: Option<RootPolicyTargetOriginalV1>,
}

impl RootCurrentWritersOriginalV1 {
    /// Enters the original once-only current-writer frontier and retains refusal.
    ///
    /// The caller retains the whole returned owner, including on fixed admission
    /// failure. The actual entered latch precedes the original fixed Stage;
    /// physical writer claims and post arming remain at their later frontiers.
    #[must_use]
    pub(super) fn receive_once_v1(
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
        semantic_supplements: [Option<ResourceVector>; 2],
    ) -> Self {
        let entry = {
            let (initial, _) = predecessor.split_initial_v1();
            initial.enter_current_writers_once_v1(exclusion)
        };
        let prefix = if entry.is_ok() {
            predecessor.completed_prefix_data_v1()
        } else {
            Err(RootObservationErrorV1::Service)
        };
        let (initial, financial) = predecessor.split_initial_v1();
        let mut original = Self {
            financial: financial.clone(),
            entry,
            authority_service: ServiceStageV1::default(),
            policy_service: ServiceStageV1::default(),
            authority: RootPolicyJournalConstructionOriginalV1::new(),
            policy: RootPolicyTargetConstructionOriginalV1::new(),
            variable: [None, None],
            semantic_supplements,
            extents: [None, None],
            replay: [None, None],
            taken: [None, None],
            pair: RootCurrentBarePairV1 { authority: None, policy: None },
            completion: None,
        };
        if original.entry.is_err() {
            return original;
        }
        let fixed = Self::fixed_for_predecessor(prefix, startup, &original.financial);
        original.authority_service.stage_once(fixed, &original.financial, exclusion);
        original.authority_service.before_once(initial, startup, exclusion, true);
        if !original.authority_service.before_positive_v1() {
            initial.latch_root_refusal_v1();
            original.authority_service.finish_owed_once(startup, exclusion);
            original.refuse(initial);
            return original;
        }

        original.receive_authority_once(initial, startup, exclusion);
        if !original.role_positive(0) {
            original.refuse(initial);
            return original;
        }
        // Policy owes its own post but no second service-before observation.
        // Its fixed receiving demand was already included in the shared Stage.
        original.policy_service.arm_owed_once(initial, startup, exclusion);
        if !original.policy_service.post_armed_v1() {
            original.refuse(initial);
            return original;
        }
        original.receive_policy_once(initial, startup, exclusion);
        if original.role_positive(1) {
            original.completion = Some(Ok(()));
        } else {
            original.refuse(initial);
        }
        original
    }

    fn fixed_for_predecessor(
        prefix: Result<ResourceVector, RootObservationErrorV1>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        financial: &RootJournalFinancialOriginalV1,
    ) -> Result<ResourceVector, ProvisionError> {
        let prefix = prefix.map_err(ProvisionError::Root)?;
        if !startup.same_financial_original_data_v1(financial) {
            return Err(closed());
        }
        prefix.checked_add(Self::fixed_preparation_demand_v1()?).map_err(|_| closed())
    }

    fn receive_authority_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        self.authority.prepare_once(initial, RootPolicyJournalPurposeV1::CurrentAuthority);
        if self.authority.failure().is_none() {
            self.extents[0] = self.authority.extent().map(|extent| {
                protected_authority_preopen_replay_extent_for_prefix_v1(extent.limits(), extent.native_bytes())
                    .map_err(PolicyNativeJournalErrorV1::from)
            });
        }
        self.authority.observe_names_before_once();
        self.variable[0] = Some(self.authority_variable_demand_v1(exclusion));
        if matches!(self.variable[0], Some(Err(_))) {
            initial.latch_root_refusal_v1();
        }
        if matches!(self.variable[0], Some(Ok(_))) {
            self.authority.replay_once();
            self.replay[0] = Some(if self.authority.failure().is_none() {
                Ok(())
            } else {
                Err(RootObservationErrorV1::Service)
            });
        }
        if matches!(self.replay[0], Some(Err(_))) {
            initial.latch_root_refusal_v1();
        }
        self.authority.finish_names_once();
        self.authority_service.finish_owed_once(startup, exclusion);
        if !matches!(self.variable[0], Some(Ok(_)))
            || !matches!(self.replay[0], Some(Ok(())))
            || !self.authority_service.post_positive_v1()
            || !self.authority.ready()
        {
            return;
        }
        self.pair.authority = self.authority.take_journal_once();
        self.taken[0] = Some(if self.pair.authority.is_some() {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        });
        if matches!(self.taken[0], Some(Ok(()))) {
            self.authority_service.retire_positive();
        }
    }

    fn receive_policy_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        self.policy.prepare_current_capture_once_v1(initial);
        if self.policy.failure().is_none() {
            self.extents[1] = self.policy.extent().map(|extent| {
                protected_policy_preopen_replay_extent_for_prefix_v1(extent.limits(), extent.native_bytes())
                    .map_err(PolicyNativeJournalErrorV1::from)
            });
        }
        self.policy.observe_current_names_before_once_v1();
        self.variable[1] = Some(self.policy_variable_demand_v1(exclusion));
        if matches!(self.variable[1], Some(Err(_))) {
            initial.latch_root_refusal_v1();
        }
        if matches!(self.variable[1], Some(Ok(_))) {
            self.policy.replay_once();
            self.replay[1] = Some(if self.policy.failure().is_none() {
                Ok(())
            } else {
                Err(RootObservationErrorV1::Service)
            });
        }
        if matches!(self.replay[1], Some(Err(_))) {
            initial.latch_root_refusal_v1();
        }
        self.policy.finish_names_once();
        self.policy_service.finish_owed_once(startup, exclusion);
        if !matches!(self.variable[1], Some(Ok(_)))
            || !matches!(self.replay[1], Some(Ok(())))
            || !self.policy_service.post_positive_v1()
            || !self.policy.replay_ready_v1()
        {
            return;
        }
        self.pair.policy = self.policy.take_target_once();
        self.taken[1] = Some(if self.pair.policy.is_some() {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        });
        if matches!(self.taken[1], Some(Ok(()))) {
            self.policy_service.retire_positive();
        }
    }

    fn authority_variable_demand_v1(
        &self,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, RootCurrentWriterDemandErrorV1> {
        if self.authority.failure().is_some() {
            return Err(PolicyNativeJournalErrorV1::boundary().into());
        }
        let extent = self.extents[0].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(PolicyNativeJournalErrorV1::boundary)?;
        let (native, semantic) = current_replay_components(extent, self.semantic_supplements[0])?;
        let index = self.authority.index_demand_v1()?;
        let base = self.authority_service.permit_data_v1().ok_or_else(closed)?;
        self.admit_variable(base, native, semantic, index, exclusion)
    }

    fn policy_variable_demand_v1(
        &self,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, RootCurrentWriterDemandErrorV1> {
        if self.policy.failure().is_some() {
            return Err(PolicyNativeJournalErrorV1::boundary().into());
        }
        let extent = self.extents[1].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(PolicyNativeJournalErrorV1::boundary)?;
        let (native, semantic) = current_replay_components(extent, self.semantic_supplements[1])?;
        let index = self.policy.index_demand_v1()?;
        let base = self.variable[0].as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or_else(closed)?;
        self.admit_variable(base, native, semantic, index, exclusion)
    }

    fn admit_variable(
        &self,
        base: ResourceVector,
        native: ResourceVector,
        semantic: ResourceVector,
        index: ResourceVector,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, RootCurrentWriterDemandErrorV1> {
        let demand = base.checked_add(native)
            .and_then(|demand| demand.checked_add(semantic))
            .and_then(|demand| demand.checked_add(index)).map_err(|_| closed())?;
        if self.financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, demand).is_err() {
            return Err(PolicyNativeJournalErrorV1::Financial(self.financial.clone()).into());
        }
        Ok(demand)
    }

    fn refuse(&mut self, initial: &mut RootInitialReceivingOriginalV1) {
        self.completion = Some(Err(RootObservationErrorV1::Service));
        initial.latch_root_refusal_v1();
    }

    fn role_positive(&self, index: usize) -> bool {
        matches!(self.variable[index], Some(Ok(_)))
            && matches!(self.replay[index], Some(Ok(())))
            && matches!(self.taken[index], Some(Ok(())))
            && if index == 0 {
                self.authority_service.post_positive_v1() && self.pair.authority.is_some()
            } else {
                self.policy_service.post_positive_v1() && self.pair.policy.is_some()
            }
    }

    /// Prices the original two fixed physical recipes and current stage controls.
    ///
    /// # Errors
    /// Preserves either fixed native supplier and checked representation overflow.
    pub fn fixed_preparation_demand_v1() -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let authority = RootPolicyJournalConstructionOriginalV1::fixed_demand_v1(
            RootPolicyJournalPurposeV1::CurrentAuthority,
        )?;
        let policy = RootPolicyTargetConstructionOriginalV1::fixed_demand_v1()?;
        let bytes = Self::additional_control_bytes_v1().and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(PolicyNativeJournalErrorV1::geometry)?;
        authority.checked_add(policy)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| PolicyNativeJournalErrorV1::geometry())
    }

    /// Prices this actual factory's enclosing owner and receiving/return planes.
    ///
    /// The real earlier attempt constructor consumes this Memory-only term
    /// before calling the factory. It supplies no completed prefix or permission.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        RootInitialReceivingOriginalV1::current_writers_entry_control_bytes_v1()?
            .checked_add(size_of::<Self>().checked_mul(3)?)?
            .checked_add(size_of::<(RootCurrentWritersPredecessorV1<'_, '_, '_>,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>,
                [Option<ResourceVector>; 2])>().checked_mul(3)?)?
            .checked_add(size_of::<(Result<ResourceVector, RootObservationErrorV1>,
                &RootSelectedStartupBorrowV1<'_>, &RootJournalFinancialOriginalV1)>().checked_mul(3)?)?
            // fixed_for_predecessor and fixed_preparation_demand execute before
            // the fixed Stage; their returned quote cannot pay its own controls.
            .checked_add(size_of::<Result<ResourceVector, ProvisionError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<&Self>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&RootPolicyJournalV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&RootPolicyTargetOriginalV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&RootPolicyJournalV1, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&RootPolicyTargetOriginalV1, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1),
                RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(6)?)
    }

    /// Bounds actual additional current-stage controls without a receiving grant.
    ///
    /// The enclosing real current-attempt constructor must also account for the
    /// actual retained owner layout before calling its factory. This DATA does
    /// not replace that original constructor invoice.
    #[must_use]
    pub fn additional_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        super::preopen_geometry::authority_control_bytes_v1()?
            .checked_add(super::preopen_geometry::policy_control_bytes_v1()?)?
            .checked_add(size_of::<(&mut Self, &mut RootInitialReceivingOriginalV1,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(9)?)?
            .checked_add(size_of::<Result<ResourceVector, ProvisionError>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<ResourceVector, RootCurrentWriterDemandErrorV1>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<(ResourceVector, ResourceVector), RootCurrentWriterDemandErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<(&ProtectedJournalPreopenReplayExtentV1, Option<ResourceVector>)>().checked_mul(6)?)?
            .checked_add(size_of::<[Option<ResourceVector>; 2]>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<ResourceVector>>().checked_mul(6)?)?
            .checked_add(size_of::<(&Self, ResourceVector, ResourceVector, ResourceVector,
                ResourceVector, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
            .checked_add(size_of::<(&RootPolicyJournalConstructionOriginalV1,
                Option<&(dyn Error + 'static)>)>().checked_mul(12)?)?
            .checked_add(size_of::<(&RootPolicyTargetConstructionOriginalV1,
                Option<&(dyn Error + 'static)>)>().checked_mul(6)?)?
            .checked_add(size_of::<(&Self, Option<&(dyn Error + 'static)>)>().checked_mul(6)?)?
            .checked_add(size_of::<(&Self, &RootUpperMutationGuardV1<'_>)>().checked_mul(6)?)?
            .checked_add(size_of::<(&RootPolicyJournalV1, Option<&(dyn Error + 'static)>)>().checked_mul(3)?)?
            .checked_add(size_of::<(&RootPolicyTargetOriginalV1, Option<&(dyn Error + 'static)>)>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(12)?)
    }

    pub(super) fn deferred_semantic_quote_role_v1(
        &self,
        selected: &RootCurrentWriterDemandErrorV1,
    ) -> Option<usize> {
        if !matches!(selected, RootCurrentWriterDemandErrorV1::DeferredUpperSemanticQuote) {
            return None;
        }
        for role in 0_usize..2 {
            if let Some(Err(original)) = &self.variable[role] {
                if std::ptr::eq(selected, original) {
                    return Some(role);
                }
            }
        }
        None
    }

    pub(super) fn deferred_semantic_role_control_bytes_v1() -> Option<usize> {
        size_of::<(&Self, &RootCurrentWriterDemandErrorV1)>().checked_mul(3)?
            .checked_add(size_of::<Option<&RootCurrentWriterDemandErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(std::ops::Range<usize>, Option<usize>, usize)>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?
            .checked_add(size_of::<bool>().checked_mul(6)?)
    }

    /// Borrows actual writer causes before receiving markers, as the old owner did.
    #[must_use]
    pub fn concrete_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(authority) = &self.pair.authority {
            if let Some(cause) = authority.retained_selected_failure_v1() { return Some(cause); }
        }
        if let Some(cause) = self.authority.prefix_failure_v1() { return Some(cause); }
        if let Some(Err(cause)) = &self.extents[0] { return Some(cause); }
        if let Some(cause) = self.authority.remaining_failure_v1() { return Some(cause); }
        if let Some(policy) = &self.pair.policy {
            if let Some(cause) = policy.retained_selected_failure_v1() { return Some(cause); }
        }
        if let Some(cause) = self.policy.prefix_failure_v1() { return Some(cause); }
        if let Some(Err(cause)) = &self.extents[1] { return Some(cause); }
        self.policy.remaining_failure_v1()
    }

    /// Borrows the original first failure without another sample or native call.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = self.concrete_failure_v1() { return Some(cause); }
        if let Err(cause) = &self.entry { return Some(cause); }
        if self.authority_service.permit_data_v1().is_none() {
            return self.authority_service.failure();
        }
        if !self.authority_service.before_positive_v1() {
            return self.authority_service.failure();
        }
        for index in 0..2 {
            if let Some(Err(cause)) = &self.extents[index] { return Some(cause); }
            if let Some(Err(cause)) = &self.variable[index] { return Some(cause); }
            if let Some(Err(cause)) = &self.replay[index] {
                return (if index == 0 { self.authority.concrete_failure_v1() }
                    else { self.policy.concrete_failure_v1() }).or(Some(cause));
            }
            let service = if index == 0 { &self.authority_service } else { &self.policy_service };
            if let Some(cause) = service.failure() { return Some(cause); }
            if let Some(cause) = if index == 0 { self.authority.failure() } else { self.policy.failure() } {
                return Some(cause);
            }
            if let Some(Err(cause)) = &self.taken[index] { return Some(cause); }
        }
        self.completion.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
    }

    /// Requires actual complete receiving and both retained bare writers.
    ///
    /// # Errors
    /// Refuses any incomplete or failed actual stage; this supplies no role grant.
    pub fn require_complete_v1(&self) -> Result<(), RootObservationErrorV1> {
        if matches!(self.completion, Some(Ok(()))) && self.role_positive(0)
            && self.role_positive(1) && self.failure_v1().is_none()
        {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(super) fn initial_open_receiving_data_v1(
        &self,
    ) -> Result<super::initial_provision::RootInitialOpenReceivingDataV1<'_>, RootObservationErrorV1> {
        self.require_complete_v1()?;
        let base = match &self.variable[1] {
            Some(Ok(base)) => *base,
            _ => return Err(RootObservationErrorV1::Service),
        };
        let held = match &self.extents[0] {
            Some(Ok(held)) => held,
            _ => return Err(RootObservationErrorV1::Service),
        };
        let supplement = self.semantic_supplements[0].ok_or(RootObservationErrorV1::Service)?;
        Ok(super::initial_provision::RootInitialOpenReceivingDataV1 {
            financial: &self.financial,
            base,
            held,
            supplement,
        })
    }

    // Independently owed INITIAL posts and durable readback retain their same
    // opened writers after later failure. This is not a healthy entry or a new
    // Current completion lender; it never opens or substitutes either writer.
    pub(super) fn opened_pair_v1(
        &mut self,
    ) -> Result<&mut RootCurrentBarePairV1, RootObservationErrorV1> {
        if self.pair.authority.is_none() || self.pair.policy.is_none() {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(&mut self.pair)
    }

    // Passive observations borrow the same opened originals after later
    // refusal. This never upgrades their health, completion or role custody.
    pub(super) fn opened_pair_view_v1(
        &self,
    ) -> Result<(&RootPolicyJournalV1, &RootPolicyTargetOriginalV1), RootObservationErrorV1> {
        let authority = self.pair.authority.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let policy = self.pair.policy.as_ref().ok_or(RootObservationErrorV1::Service)?;
        Ok((authority, policy))
    }

    pub(in crate::native) fn pair_v1(&mut self) -> Result<&mut RootCurrentBarePairV1, RootObservationErrorV1> {
        self.require_complete_v1()?;
        Ok(&mut self.pair)
    }
}

fn closed() -> ProvisionError {
    ProvisionError::Root(RootObservationErrorV1::Service)
}

// Current keeps the exact old full semantic-family quote and its old overflow
// diagnostics. Startup's narrower compiled observer invoice is not equivalence.
fn current_replay_components(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    supplement: Option<ResourceVector>,
) -> Result<(ResourceVector, ResourceVector), RootCurrentWriterDemandErrorV1> {
    let native = extent.dominant_native_receiving_demand_v1()
        .map_err(CanonicalJournalMechanicalErrorV1::from)
        .map_err(PolicyNativeJournalErrorV1::from)?;
    let semantic = extent.dominant_semantic_receiving_demand_v1()
        .map_err(PolicyNativeJournalErrorV1::from)?;
    // Only the original upper compiled layout is supplemental DATA. The native
    // and full Ledger minimum above are independently derived from this capture.
    let supplement = supplement.ok_or(RootCurrentWriterDemandErrorV1::DeferredUpperSemanticQuote)?;
    let semantic = semantic.checked_add(supplement).map_err(|_| {
        PolicyNativeJournalErrorV1::Mechanical(CanonicalJournalMechanicalErrorV1::LimitExceeded(
            "native history observer representation",
        ))
    })?;
    Ok((native, semantic))
}

impl RootCurrentBarePairV1 {
    pub(super) fn authority_and_policy_v1(
        &mut self,
    ) -> Result<(&mut RootPolicyJournalV1, &RootPolicyTargetOriginalV1), RootObservationErrorV1> {
        let authority = self.authority.as_mut().ok_or(RootObservationErrorV1::Service)?;
        let policy = self.policy.as_ref().ok_or(RootObservationErrorV1::Service)?;
        Ok((authority, policy))
    }
}

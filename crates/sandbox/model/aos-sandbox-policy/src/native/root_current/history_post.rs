//! Arms the actual initial history posts from their genuine peer predecessor.
//!
//! This finite lender retains the same cumulative Stage, two original prearmed
//! services and separately charged Root/Controller/Root traffic. A supplied
//! financial vector, native post, peer snapshot or successful Result cannot
//! construct it. Observation remains the sole Broker physical programme.

use std::error::Error;

use aos_sandbox_broker::receiving::{
    ObservationLifetimeV1, RootAcceptedHistoryBorrowerV1, RootFinancialClosedV1,
    RootHistoryObservationOriginalV1, RootHistoryPeerPostNativeOriginalV1, RootJournalFinancialOriginalV1,
    RootObservationErrorV1, RootPrearmedHistoryServicePostV1,
    RootSelectedControllerCurrentSampleV1, RootSelectedControllerPeerOriginalV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_model::component_receiving::{
    operation_traffic_demand_v1, without_operation_traffic_v1,
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use crate::native::startup::{
    RootCurrentWritersPredecessorV1, RootStartupControllerPeerOriginalV1,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum RootCurrentHistoryArmErrorV1 {
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
    #[error(transparent)]
    Financial(#[from] RootFinancialClosedV1),
    #[error("fixed Root history-post receiving geometry is unavailable")]
    Geometry,
}

type ArmError = RootCurrentHistoryArmErrorV1;

/// Retains real initial history-post receiving and native originals together.
///
/// Only the genuine completed producer and same mutable Initial construct this
/// owner. Its private positive accessor checks the retained Stage and traffic;
/// the mechanical Broker post alone does not stand for those admissions.
pub(super) struct RootCurrentHistoryPostOriginalV1 {
    financial: RootJournalFinancialOriginalV1,
    resident: Option<Result<ResourceVector, ArmError>>,
    before: Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>,
    after: Option<Result<RootPrearmedHistoryServicePostV1, RootObservationErrorV1>>,
    traffic_shape: Option<Result<ResourceVector, RootObservationErrorV1>>,
    traffic: Option<Result<(), RootFinancialClosedV1>>,
    native: Option<RootHistoryObservationOriginalV1>,
}

impl RootCurrentHistoryPostOriginalV1 {
    /// Performs the original Stage, two arms and one traffic debit in order.
    ///
    /// Every returned owner retains its reached positive or negative prefix.
    /// The borrowed Initial and its real exclusion are released on return.
    pub(super) fn arm_once_v1(
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Self {
        let prefix = predecessor.completed_prefix_data_v1();
        let (initial, financial) = predecessor.split_initial_v1();
        let mut original = Self {
            financial: financial.clone(),
            resident: None,
            before: None,
            after: None,
            traffic_shape: None,
            traffic: None,
            native: None,
        };

        // The old arm checks these genuine owners before its resident Stage.
        // No worker is entered here and no Current writer claim is repeated.
        let resident = if initial.failure().is_some()
            || !initial.controller_history_worker_idle_data_v1()
            || !startup.same_financial_original_data_v1(&original.financial)
        {
            Err(ArmError::Root(RootObservationErrorV1::Service))
        } else {
            original.stage_resident_v1(prefix, exclusion)
        };
        original.resident = Some(resident);
        if !matches!(original.resident, Some(Ok(_))) {
            initial.latch_root_refusal_v1();
            return original;
        }

        original.before = Some(startup.arm_owed_service_post_once_v1(initial));
        if !matches!(original.before, Some(Ok(_))) {
            return original;
        }
        original.after = Some(startup.arm_owed_service_post_once_v1(initial));
        if !matches!(original.after, Some(Ok(_))) {
            return original;
        }

        original.traffic_shape = Some(RootHistoryObservationOriginalV1::demand_v1());
        let traffic = match &original.traffic_shape {
            Some(Ok(demand)) => initial.debit_observer_traffic_v1(
                operation_traffic_demand_v1(*demand),
            ),
            _ => {
                initial.latch_root_refusal_v1();
                // No native post can be issued when its real supplier refused.
                return original;
            }
        };
        original.traffic = Some(traffic);

        // Both actual native arms remain owned even on the real traffic Err,
        // as in the existing returned post. require_armed prevents observation.
        let before = original.before.take();
        let after = original.after.take();
        if let (Some(Ok(before)), Some(Ok(after))) = (before, after) {
            original.native = Some(RootHistoryObservationOriginalV1::from_native_v1(
                RootHistoryPeerPostNativeOriginalV1::from_originals_v1(
                before,
                after,
                ObservationLifetimeV1::begin(),
            )));
        }
        original
    }

    fn stage_resident_v1(
        &self,
        prefix: Result<ResourceVector, RootObservationErrorV1>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, ArmError> {
        let base = prefix?;
        let resident = Self::additional_resident_demand_v1()?;
        let complete = base.checked_add(resident).map_err(|_| ArmError::Geometry)?;
        self.financial.require_receiving_demand_under_upper_exclusion_v1(
            exclusion,
            complete,
        )?;
        Ok(complete)
    }

    /// Derives the original simultaneous shared-worker peak from its real row.
    ///
    /// The current sample owns exactly one property row; its demand therefore
    /// has the same worker count as the old fixed-property geometry. The
    /// initial qualifier remains the independent paid upper bound comparison.
    pub(super) fn additional_resident_demand_v1() -> Result<ResourceVector, ArmError> {
        let native = RootHistoryObservationOriginalV1::demand_v1()?;
        let current = RootSelectedControllerCurrentSampleV1::demand_v1()?;
        let qualifier = RootSelectedControllerPeerOriginalV1::fixed_demand()?;
        if current.get(D::Pids) > qualifier.get(D::Pids) {
            return Err(ArmError::Geometry);
        }
        let controls = Self::construction_control_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ArmError::Geometry)?;
        let complete = native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, controls))
            .map_err(|_| ArmError::Geometry)?;
        // All three observer rows synchronously join their workers. The same
        // entered initial qualifier pays the shared peak, so the old extra
        // resident Stage has no additional PID liability.
        Ok(without_operation_traffic_v1(complete).with(D::Pids, 0))
    }

    // The old arm returned the whole native post even when its final traffic
    // debit refused. Only the independently owed outer names/clock use this
    // passive custody query; native observation/append still require payment.
    pub(super) fn has_native_original_v1(&self) -> bool {
        self.native.is_some()
    }

    /// Requires the real resident and traffic admissions before lending natives.
    pub(super) fn require_armed_v1(&self) -> Result<(), RootObservationErrorV1> {
        if matches!(self.resident, Some(Ok(_)))
            && matches!(self.traffic, Some(Ok(())))
            && self.native.is_some()
        {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    /// Borrows only this actually paid post and the owned programme's same actual producer.
    ///
    /// The producer and stream are the actual owned accepted originals. The Broker factory
    /// independently rejoins both prearmed originals with that genuine peer.
    pub(super) fn borrow_accepted_v1<'cut, 'startup>(
        &'cut mut self,
        producer: &'cut RootStartupControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
    ) -> Result<RootAcceptedHistoryBorrowerV1<'cut, 'startup>, RootObservationErrorV1> {
        self.require_armed_v1()?;
        let peer = producer.native_peer_original_v1()?;
        self.native.as_mut().ok_or(RootObservationErrorV1::Service)?
            .borrow_accepted_history_v1(peer, stream)
    }

    /// Borrows actual arm/traffic failure without reentering a healthy sampler.
    pub(super) fn arm_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.resident {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.before {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.after {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.traffic_shape {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.traffic {
            return self.financial.failure_v1().or(Some(cause));
        }
        None
    }

    pub(super) fn observation_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.native.as_ref().and_then(RootHistoryObservationOriginalV1::observation_failure_v1)
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.arm_failure_v1().or_else(|| self.observation_failure_v1())
    }

    /// Measures actual owner construction and reached finite method controls.
    ///
    /// The enclosing initial Current constructor must pay this before arm;
    /// its later resident Stage cannot fund its own quote evaluation.
    pub(super) fn construction_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        let diagnostics = size_of::<(&Self, Option<&(dyn Error + 'static)>)>()
            .checked_mul(9)?;

        size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<(&Self, bool)>().checked_mul(3)?)?
            .checked_add(size_of::<(&Option<RootHistoryObservationOriginalV1>, bool)>()
                .checked_mul(3)?)?
            .checked_add(RootHistoryObservationOriginalV1::preparation_control_bytes_v1()?)?
            .checked_add(RootJournalFinancialOriginalV1::receiving_stage_under_exclusion_control_bytes_v1()?)?
            .checked_add(RootSelectedStartupBorrowV1::owed_service_arm_control_bytes_v1()?.checked_mul(2)?)?
            .checked_add(std::mem::size_of::<(&Self, Result<(), RootObservationErrorV1>)>().checked_mul(3)?)?
            // The function item has no environment. Its real observer argument,
            // optional receiver and borrowed result remain separate interfaces.
            .checked_add(std::mem::size_of::<Option<&RootHistoryObservationOriginalV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(&RootHistoryObservationOriginalV1,)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?
            .checked_add(size_of::<(RootCurrentWritersPredecessorV1<'_, '_, '_>,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>()
                .checked_mul(3)?)?
            .checked_add(size_of::<(&Self, Result<ResourceVector, RootObservationErrorV1>,
                &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, ArmError>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<ResourceVector, RootObservationErrorV1>>()
                .checked_mul(12)?)?
            .checked_add(size_of::<Result<(), RootFinancialClosedV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Result<RootPrearmedHistoryServicePostV1,
                RootObservationErrorV1>>().checked_mul(6)?)?
            .checked_add(size_of::<(Option<Result<RootPrearmedHistoryServicePostV1,
                RootObservationErrorV1>>, Option<Result<RootPrearmedHistoryServicePostV1,
                RootObservationErrorV1>>)>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut Self, &RootStartupControllerPeerOriginalV1<'_>, &RetainedUnixStream)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&RootSelectedControllerPeerOriginalV1<'_>,
                RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootAcceptedHistoryBorrowerV1<'_, '_>,
                RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<ObservationLifetimeV1>().checked_mul(3)?)?
            .checked_add(size_of::<&Option<Result<ResourceVector, RootObservationErrorV1>>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(9)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<u64>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(9)?)?
            .checked_add(diagnostics)
    }
}

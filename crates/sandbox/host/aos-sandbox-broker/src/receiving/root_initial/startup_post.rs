//! Shares the original once-resident startup post payment across named stages.
//!
//! Policy retains journal/credential/writer/listener/peer semantic stage order.
//! This same Initial owns only the original Native term and per-post traffic;
//! financial high-water is never interpreted as a completed semantic prefix.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootUpperMutationGuardV1,
};
use crate::receiving::{
    RootPrearmedHistoryServicePostV1, RootServiceCurrentnessOriginalV1, RootStartupNativeOriginalV1,
};

/// Retains the actual first funding or native arm refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootStartupServicePostErrorV1 {
    /// Preserves checked native representation geometry refusal.
    #[error("startup service post representation overflow")]
    Geometry,
    /// Keeps the same existing financial allocation and actual failed operation.
    #[error(transparent)]
    Financial(RootJournalFinancialOriginalV1),
    /// Preserves the actual native association or post construction error.
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
}

impl RootInitialReceivingOriginalV1 {
    pub(in crate::receiving) fn arm_paid_startup_service_post_once_v1(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<RootPrearmedHistoryServicePostV1, RootStartupServicePostErrorV1> {
        if self.failure().is_some() || !self.controller_history_worker_idle_data_v1() {
            self.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service.into());
        }
        let financial = self
            .financial_diagnostic_original_v1()
            .ok_or(RootObservationErrorV1::Service)?;
        if !exclusion.matches_permanent_original_v1(financial.q04_permanent_v1()) {
            exclusion.refuse_v1();
            return Err(RootObservationErrorV1::Service.into());
        }
        if self.startup_post_resident.is_none() {
            let demand = (|| {
                let post = RootPrearmedHistoryServicePostV1::demand_v1()
                    .ok_or(RootStartupServicePostErrorV1::Geometry)?;
                let service = RootServiceCurrentnessOriginalV1::demand()
                    .ok_or(RootStartupServicePostErrorV1::Geometry)?;
                if post.get(D::Pids) > service.get(D::Pids) {
                    return Err(RootStartupServicePostErrorV1::Geometry);
                }
                let resident =
                    aos_sandbox_model::component_receiving::without_operation_traffic_v1(post)
                        .with(D::Pids, 0);
                self.debit_native_representation_v1(resident)
                    .map_err(|_| RootStartupServicePostErrorV1::Financial(financial.clone()))
            })();
            self.startup_post_resident = Some(demand);
        }
        if let Some(Err(cause)) = &self.startup_post_resident {
            let returned = match cause {
                RootStartupServicePostErrorV1::Geometry => RootStartupServicePostErrorV1::Geometry,
                RootStartupServicePostErrorV1::Financial(actual) => {
                    RootStartupServicePostErrorV1::Financial(actual.clone())
                }
                RootStartupServicePostErrorV1::Root(cause) => {
                    RootStartupServicePostErrorV1::Root(*cause)
                }
            };
            self.latch_root_refusal_v1();
            return Err(returned);
        }
        let traffic =
            RootServiceCurrentnessOriginalV1::demand().ok_or(RootObservationErrorV1::Service)?;
        self.debit_observer_traffic_v1(
            aos_sandbox_model::component_receiving::operation_traffic_demand_v1(traffic),
        )
        .map_err(|_| RootStartupServicePostErrorV1::Financial(financial))?;
        self.arm_history_service_post_v1(startup)
            .map_err(Into::into)
    }

    /// Prices new shared-post argument, return and native payment controls.
    ///
    /// The actual Root profile entry consumes this before the first such owner.
    /// Inline Initial storage is counted by its complete existing Self quote.
    #[must_use]
    pub fn startup_post_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<(
            &mut Self,
            &RootStartupNativeOriginalV1,
            &RootUpperMutationGuardV1<'_>,
        )>()
        .checked_mul(3)?
        .checked_add(
            size_of::<Result<RootPrearmedHistoryServicePostV1, RootStartupServicePostErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<Result<(), super::RootFinancialClosedV1>>()
                .checked_mul(6)?
                .checked_add(
                    size_of::<Result<(), RootStartupServicePostErrorV1>>().checked_mul(3)?,
                )?,
        )?
        .checked_add(size_of::<Option<ResourceVector>>().checked_mul(4)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(6)?)?
        .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(3)?)?
        .checked_add(size_of::<Option<RootJournalFinancialOriginalV1>>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<RootJournalFinancialOriginalV1, RootObservationErrorV1>>()
                .checked_mul(3)?,
        )?
        .checked_add(size_of::<RootStartupServicePostErrorV1>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(6)?)
    }
}

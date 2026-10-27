//! Prepays the real selected Q04 native origin from the same consumed Root R.
//!
//! The genuine Initial field supplies native association only after the full
//! fixed constructor and enclosing work demand enter the existing partition.
//! The financial critical section ends before any Q04 clock or peer operation.

use aos_sandbox_broker::receiving::RootQ04TransportOriginalV1;
use aos_sandbox_model::ResourceVector;

use super::{ResourceReservationErrorV1, RootReceivingOriginalV1};
use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};

impl RootReceivingOriginalV1 {
    pub(crate) fn prepare_q04_transport_origin_v1<'startup>(
        &mut self,
        startup: &'startup ProductionNormalRootStartupV1,
        upper: ResourceVector,
    ) -> Result<RootQ04TransportOriginalV1<'startup>, NormalRootStartupErrorV1> {
        if self.failure().is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let native = RootQ04TransportOriginalV1::fixed_demand_v1()
            .and_then(|demand| demand.checked_add(upper).ok());
        let Some(native) = native else {
            self.native_receiving_refusal.get_or_insert_with(|| {
                std::sync::Arc::new(ResourceReservationErrorV1::EnrollmentUnavailable)
            });
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        };
        // Native representation joins the already consumed complete S/F/N
        // liability. It neither replaces prior resident demand nor reuses a
        // successful demand vector as the native association below.
        self.activation
            .debit_native_representation_v1(native)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let mut destination = RootQ04TransportOriginalV1::new(startup.native_startup_original_v1());
        self.activation.arm_q04_transport_origin_once_v1(
            startup.native_startup_original_v1(),
            &mut destination,
        )?;
        Ok(destination)
    }

    pub(crate) fn retire_q04_transport_after_native_posts_v1(
        &mut self,
        destination: &mut RootQ04TransportOriginalV1<'_>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.activation
            .retire_q04_transport_after_native_posts_v1(destination)
            .map_err(NormalRootStartupErrorV1::from)
    }
}

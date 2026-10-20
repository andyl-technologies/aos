//! Admits the actual independent D Source predecessor model before its growth.

use super::*;

impl RootReceivingOriginalV1 {
    pub(crate) fn admit_delete_source_predecessor_v2(
        &mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = (|| {
            self.require_active_policy_flight_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let entered = source.predecessor_receiving_demand_v2()?;
            let previous = challenge.retained_receiving_demand_v1()?;
            let controller = controller.retained_receiving_demand_v1()?;
            let base = self
                .policy_listener_prefix()
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let peer = crate::normal_root::RootDeleteControllerPeerReceivingV1::fixed_demand_v1()?;
            let complete = base
                .checked_add(without_operation_traffic_v1(peer))?
                .checked_add(without_operation_traffic_v1(previous))?
                .checked_add(without_operation_traffic_v1(controller))?
                .checked_add(without_operation_traffic_v1(entered))?;
            // The enclosing Source purpose already debited its entire actual
            // request/response and independently owed Root/C/clock traffic.
            self.require_receiving_demand_v1(complete)
        })();
        if result.is_err() {
            self.activation.latch_root_refusal_v1();
        }
        result
    }
}

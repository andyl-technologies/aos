//! Lends only the active same-R financial original to D's actual Source stage.

use super::*;

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_source_predecessor_v2(
        &mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if source.is_final_read_v2() {
            let phase = source.final_predecessor_phase_v2()?;
            let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
                source.predecessor_receiving_demand_v2()?,
            );
            self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let mut receiving = self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            return match phase {
                crate::policy_compiler::delete_root::RootDeleteSourcePredecessorPhaseV2::Native =>
                    receiving.admit_delete_fresh_source_native_once_v2(demand),
                crate::policy_compiler::delete_root::RootDeleteSourcePredecessorPhaseV2::Semantic =>
                    receiving.admit_delete_fresh_source_semantic_once_v2(demand),
            }.map_err(|_| ResourceReservationErrorV1::Conflict);
        }
        let startup = self
            .delete_cut_startup_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_source_predecessor_v2(challenge, controller, source);
        receiving.finish_returned_v1(returned)
    }
}

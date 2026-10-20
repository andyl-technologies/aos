//! Pays the actual Delete graph phases on the same armed Root purpose.

use super::*;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::policy_compiler::delete_root::{
    RootDeleteCacheCurrentOriginalV2, RootDeleteControllerCurrentOriginalV1,
    RootDeleteSourceCurrentOriginalV1,
    GraphAdmissionPhaseV2, RootDeleteGraphObjectsOriginalV2, RootDeleteGraphComparisonOriginalV2,
};

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_graph_objects_v2(
        &mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        cache: &RootDeleteCacheCurrentOriginalV2,
        owner: &RootDeleteGraphObjectsOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        // These intrinsic getters join completed genuine originals. The stage
        // engine already retains their paid resident planes on this same R;
        // none is replaced with a second ledger or caller-provided baseline.
        challenge.retained_receiving_demand_v1()?;
        controller.retained_receiving_demand_v1()?;
        source.retained_receiving_demand_v1()?;
        cache.retired_cache_files_v2()?;
        let phase = owner.admission_phase_v2()?;
        let demand = RootContinuationDemandV1::from_demand_v1(owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = self.delete_peer_mut_v1()
            .and_then(|peer| peer.stage_receiving_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        match phase {
            GraphAdmissionPhaseV2::Fixed => receiving.admit_delete_graph_fixed_once_v2(demand),
            GraphAdmissionPhaseV2::Objects => receiving.admit_delete_graph_objects_once_v2(demand),
            GraphAdmissionPhaseV2::Models => receiving.admit_delete_graph_models_once_v2(demand),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn admit_delete_graph_comparison_v2(
        &mut self,
        graph: &RootDeleteGraphObjectsOriginalV2,
        owner: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        graph.verified_graph_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = RootContinuationDemandV1::from_demand_v1(owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1()
            .and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_graph_comparison_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

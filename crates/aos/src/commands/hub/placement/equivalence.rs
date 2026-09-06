//! Handles hub placement equivalence commands and their domain-specific request validation.

use crate::cli::HubPlacementEquivalenceCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    delete_topology_resource, new_idempotency_key, topology_mutation, topology_read,
};
use crate::commands::hub::route::surface_message;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub placement equivalence command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn placement_equivalence(
    printer: &Printer,
    command: &HubPlacementEquivalenceCmd,
) -> Result<()> {
    match command {
        HubPlacementEquivalenceCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListPlacementEquivalencesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPlacementEquivalences,
                &hub_types::SurfaceListRequest {
                    surface: Some(surface_message(surface)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPlacementEquivalenceCmd::Confirm {
            access,
            surface,
            placement_a,
            placement_b,
            if_a_version,
            if_b_version,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanConfirmPlacementEquivalence,
                    HubTopologyMethod::ConfirmPlacementEquivalence,
                    &hub_types::PlanPlacementEquivalenceRequest::default(),
                    mutation,
                    apply_topology_plan,
                )
                .await;
            }
            let expected_a_resource_version = if_a_version
                .clone()
                .filter(|value| !value.is_empty())
                .context("placement equivalence confirmation requires --if-a-version")?;
            let expected_b_resource_version = if_b_version
                .clone()
                .filter(|value| !value.is_empty())
                .context("placement equivalence confirmation requires --if-b-version")?;
            topology_mutation::<
                _,
                hub_types::ApplyTopologyPlanRequest,
                hub_types::PlacementEquivalenceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanConfirmPlacementEquivalence,
                HubTopologyMethod::ConfirmPlacementEquivalence,
                &hub_types::PlanPlacementEquivalenceRequest {
                    surface: Some(surface_message(surface)?),
                    placement_a: placement_a.clone(),
                    placement_b: placement_b.clone(),
                    expected_a_resource_version: Some(expected_a_resource_version),
                    expected_b_resource_version: Some(expected_b_resource_version),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: format!(
                        "{}|{}",
                        mutation.if_version.as_deref().unwrap_or_default(),
                        if_b_version.as_deref().unwrap_or_default()
                    ),
                },
                mutation,
                apply_topology_plan,
            )
            .await
        }
        HubPlacementEquivalenceCmd::Remove {
            access,
            equivalence,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                equivalence,
                mutation,
                HubTopologyMethod::PlanDeletePlacementEquivalence,
                HubTopologyMethod::DeletePlacementEquivalence,
            )
            .await
        }
    }
}

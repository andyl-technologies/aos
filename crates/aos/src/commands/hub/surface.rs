//! Handles hub surface commands and their domain-specific request validation.

use crate::cli::HubSurfaceCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use crate::commands::hub::output::print_topology_message;
use crate::commands::hub::route::{route_mode, surface_message};
use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_remote::{HubSurfaceRef, hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub surface command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn surface(printer: &Printer, command: &HubSurfaceCmd) -> Result<()> {
    match command {
        HubSurfaceCmd::Show {
            access,
            surface_ref,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let surface = surface_ref.parse::<HubSurfaceRef>()?;
            let response: hub_types::GetSurfaceTopologyResponse = client
                .call_topology(
                    HubTopologyMethod::GetSurfaceTopology,
                    &hub_types::GetSurfaceTopologyRequest {
                        surface: Some(surface.to_message()),
                    },
                )
                .await?;
            if printer.mode() == OutputMode::Json {
                return print_topology_message(printer, &response);
            }
            printer.header(&surface.to_string());
            printer.kv("placements", &response.placements.len().to_string());
            printer.kv("routes", &response.routes.len().to_string());
            printer.kv(
                "route advertisements",
                &response.route_advertisements.len().to_string(),
            );
            printer.kv(
                "placement policies",
                &response.placement_policies.len().to_string(),
            );
            printer.kv(
                "active operations",
                &response.active_operations.len().to_string(),
            );
            Ok(())
        }
        HubSurfaceCmd::Topology {
            access,
            surface_ref,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response: hub_types::GetSurfaceTopologyResponse = client
                .call_topology(
                    HubTopologyMethod::GetSurfaceTopology,
                    &hub_types::GetSurfaceTopologyRequest {
                        surface: Some(surface_message(surface_ref)?),
                    },
                )
                .await?;
            if printer.mode() == OutputMode::Json {
                return print_topology_message(printer, &response);
            }
            print_surface_topology(printer, surface_ref, &response)
        }
        HubSurfaceCmd::Explain {
            access,
            surface_ref,
            url,
            path,
            access_class,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ExplainSurfaceRequestResponse>(
                printer,
                &client,
                HubTopologyMethod::ExplainSurfaceRequest,
                &hub_types::ExplainSurfaceRequestRequest {
                    surface: Some(surface_message(surface_ref)?),
                    url: url.clone(),
                    machine_path: path.clone().unwrap_or_default(),
                    access_class: access_class.clone(),
                },
            )
            .await
        }
    }
}

fn print_surface_topology(
    printer: &Printer,
    surface_ref: &str,
    topology: &hub_types::GetSurfaceTopologyResponse,
) -> Result<()> {
    printer.header(&format!("topology for {surface_ref}"));
    printer.plain("placements");
    if topology.placements.is_empty() {
        printer.plain("  (none)");
    }
    for placement in &topology.placements {
        let state = placement
            .observation
            .as_ref()
            .map(|observation| observation.state.as_str())
            .unwrap_or("unknown");
        let role = placement
            .status
            .as_ref()
            .map(|status| status.derived_role.as_str())
            .unwrap_or("unknown");
        printer.plain(&format!(
            "  {} [{role}/{state}] -> {}:{}",
            placement.name, placement.binding_name, placement.prefix
        ));
    }
    printer.plain("placement policies");
    if topology.placement_policies.is_empty() {
        printer.plain("  (none)");
    }
    for policy in &topology.placement_policies {
        printer.plain(&format!(
            "  {} [{}] -> revision {}",
            policy.name, policy.kind, policy.current_revision
        ));
    }
    printer.plain("placement equivalences");
    if topology.placement_equivalences.is_empty() {
        printer.plain("  (none)");
    }
    for equivalence in &topology.placement_equivalences {
        printer.plain(&format!(
            "  {} = {} [{}]",
            equivalence.placement_a, equivalence.placement_b, equivalence.state
        ));
    }
    printer.plain("routes");
    if topology.routes.is_empty() {
        printer.plain("  (none)");
    }
    for route in &topology.routes {
        let spec = route
            .spec
            .as_ref()
            .context("the Hub returned a route without a spec")?;
        let health = route
            .observation
            .as_ref()
            .map(|observation| observation.state.as_str())
            .unwrap_or("unknown");
        printer.plain(&format!(
            "  {} [{} / {}] -> endpoint {}@{}{}",
            route.stable_id,
            route_mode(spec)?,
            health,
            spec.endpoint_id,
            spec.endpoint_generation,
            spec.base_path
        ));
    }
    printer.plain("route advertisements");
    if topology.route_advertisements.is_empty() {
        printer.plain("  (none)");
    }
    for canonical in &topology.route_advertisements {
        printer.plain(&format!(
            "  {} -> {}",
            canonical.audience, canonical.route_id
        ));
    }
    printer.plain("canonical endpoints");
    if topology.canonical_endpoints.is_empty() {
        printer.plain("  (none)");
    }
    for endpoint in &topology.canonical_endpoints {
        printer.plain(&format!(
            "  {} -> {}:{} (generation {})",
            endpoint.stable_id,
            endpoint.scheme,
            endpoint.effective_port,
            endpoint.desired_generation
        ));
    }
    printer.plain("active operations");
    if topology.active_operations.is_empty() {
        printer.plain("  (none)");
    }
    for operation in &topology.active_operations {
        printer.plain(&format!(
            "  {} [{} / {}]",
            operation.operation_id, operation.kind, operation.state
        ));
    }
    printer.plain("write authority");
    match &topology.write_authority {
        Some(authority) => printer.plain(&format!(
            "  {} (version {})",
            authority.desired_placement_name, authority.resource_version
        )),
        None => printer.plain("  (read-only)"),
    }
    Ok(())
}

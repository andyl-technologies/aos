//! Dispatches registry-hub control-plane commands through the public ConnectRPC API.
//!
//! Command families own their request construction and presentation. Shared client,
//! output, and mutation modules preserve credential resolution, JSON envelopes,
//! and the reviewed plan/apply protocol.
//!
//! Login uses the shared OAuth device flow and stores rotating credentials in a
//! user-only profile; explicit provisioning grants support automation bootstrap.
//! Desired-state writes use optimistic concurrency and remain plan-only until
//! a reviewed plan ID and confirmation hash are supplied.

use self::access_token::access_token;
use self::auth::login;
use self::binding::binding;
use self::cache::cache;
use self::client::hub_client;
use self::documentation::documentation;
use self::domain::domain;
use self::endpoint::endpoint;
use self::gateway::gateway;
use self::instance::instance;
use self::network_policy::network_policy;
use self::operation::operation;
use self::organization::org;
use self::output::print_hub_json;
use self::placement::equivalence::placement_equivalence;
use self::placement::placement;
use self::placement::policy::placement_policy;
use self::registry::registry;
use self::route::route;
use self::signing_key::signing_key;
use self::surface::surface;
use crate::cli::{HubCmd, HubTopologyCmd, HubTopologyCutoverCmd};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};
pub(super) use client::container_hub_client;
pub(super) use input::parse_duration_seconds;
pub(super) use mutation::{new_idempotency_key, topology_mutation, topology_read};
pub(super) use output::print_topology_message;
pub(crate) use publication::{prepare_registry_publication, upload_registry_publication};

mod access_policy;
mod access_token;
mod audit;
mod auth;
mod binding;
mod cache;
mod client;
mod config;
mod delivery_workflow;
mod documentation;
mod domain;
mod endpoint;
mod gateway;
mod input;
mod instance;
mod mutation;
mod network_policy;
mod operation;
mod organization;
mod output;
mod package;
mod pins;
mod placement;
mod publication;
mod registry;
mod route;
mod signing_key;
mod surface;
mod webhook;

/// Dispatches one `aos hub` subcommand.
///
/// # Errors
///
/// Returns an error if the hub URL is invalid, the hub is unreachable, or an
/// RPC call fails.
pub async fn run(printer: &Printer, command: &HubCmd) -> Result<()> {
    match command {
        HubCmd::Login {
            hub,
            provisioning_token,
            scope,
        } => {
            login(
                printer,
                hub,
                provisioning_token.as_deref(),
                scope.as_deref(),
            )
            .await
        }
        HubCmd::Logout { hub } => {
            let origin = crate::commands::hub_auth::logout(hub.as_deref()).await?;
            if !print_hub_json(
                printer,
                "logout",
                serde_json::json!({ "hub": origin, "revoked": true }),
            ) {
                printer.success(&format!("signed out of {origin}"));
            }
            Ok(())
        }
        HubCmd::Whoami { access } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::WhoAmI,
                &hub_types::WhoAmIRequest {},
            )
            .await
        }
        HubCmd::AccessToken { command } => access_token(printer, command).await,
        HubCmd::Delivery { command } => delivery_workflow::run(printer, command).await,
        HubCmd::Topology { command } => match command {
            HubTopologyCmd::Cutover { command } => match command {
                HubTopologyCutoverCmd::MaterializeVerifier(args) => {
                    crate::commands::hub_cutover_verify::run_materialize_verifier(printer, args)
                }
                HubTopologyCutoverCmd::Generate(args) => {
                    crate::commands::hub_cutover_verify::run_generate(printer, args)
                }
                HubTopologyCutoverCmd::Verify(args) => {
                    crate::commands::hub_cutover_verify::run(printer, args)
                }
            },
        },
        HubCmd::Registry { command } => registry(printer, command).await,
        HubCmd::Docs { command } => documentation(printer, command).await,
        HubCmd::Cache { command } => cache(printer, command).await,
        HubCmd::Placement { command } => placement(printer, command).await,
        HubCmd::PlacementPolicy { command } => placement_policy(printer, command).await,
        HubCmd::PlacementEquivalence { command } => placement_equivalence(printer, command).await,
        HubCmd::Operation { command } => operation(printer, command).await,
        HubCmd::Org { command } => org(printer, command).await,
        HubCmd::SigningKey { command } => signing_key(printer, command).await,
        HubCmd::Binding { command } => binding(printer, command).await,
        HubCmd::Surface { command } => surface(printer, command).await,
        HubCmd::Domain { command } => domain(printer, command).await,
        HubCmd::NetworkPolicy { command } => network_policy(printer, command).await,
        HubCmd::Endpoint { command } => endpoint(printer, command).await,
        HubCmd::Gateway { command } => gateway(printer, command).await,
        HubCmd::Route { command } => route(printer, command).await,
        HubCmd::Instance { command } => instance(printer, command).await,
    }
}

//! `aos hub` — the registry-hub control-plane client (RFC-0004).
//!
//! Drives [`aos_remote::RegistryHubClient`] so the CLI interacts with a running
//! `aos-registry-hub` purely through its public ConnectRPC API, never by
//! touching the hub's database. Read operations here work anonymously against
//! the hub's public browse surface; authenticated and write subcommands follow
//! in later RFC-0004 Phase 5 increments.

use anyhow::Result;

use aos_core::output::Printer;
use aos_remote::RegistryHubClient;

use crate::cli::{HubCmd, HubRegistryCmd};

/// Dispatches one `aos hub` subcommand.
///
/// # Errors
///
/// Returns an error if the hub URL is invalid, the hub is unreachable, or an
/// RPC call fails.
pub async fn run(printer: &Printer, command: &HubCmd) -> Result<()> {
    match command {
        HubCmd::Registry { command } => registry(printer, command).await,
    }
}

/// Handles `aos hub registry …`.
async fn registry(printer: &Printer, command: &HubRegistryCmd) -> Result<()> {
    match command {
        HubRegistryCmd::List { hub } => {
            let client = RegistryHubClient::connect_anonymous(hub)?;
            let registries = client.list_registries().await?;
            if printer.json_if_active(&serde_json::json!({
                "registries": registries
                    .iter()
                    .map(|r| serde_json::json!({
                        "slug": r.slug,
                        "name": r.name,
                        "index_state": r.index_state,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if registries.is_empty() {
                printer.info("no public registries");
                return Ok(());
            }
            printer.header(&format!(
                "{} registr{} on {hub}",
                registries.len(),
                if registries.len() == 1 { "y" } else { "ies" }
            ));
            for registry in &registries {
                let state = if registry.index_state.is_empty() {
                    "unindexed"
                } else {
                    &registry.index_state
                };
                printer.plain(&format!("  {}  [{state}]", registry.slug));
            }
            Ok(())
        }
        HubRegistryCmd::Get { hub, slug } => {
            let client = RegistryHubClient::connect_anonymous(hub)?;
            let registry = client.get_registry(slug).await?;
            if printer.json_if_active(&serde_json::json!({
                "registry": registry.as_ref().map(|r| serde_json::json!({
                    "slug": r.slug,
                    "name": r.name,
                    "description": r.description,
                    "source_url": r.source_url,
                    "index_state": r.index_state,
                })),
            })) {
                return Ok(());
            }
            match registry {
                Some(registry) => {
                    printer.header(&registry.slug);
                    printer.plain(&format!("  name:        {}", registry.name));
                    printer.plain(&format!("  description: {}", registry.description));
                    printer.plain(&format!("  source:      {}", registry.source_url));
                    printer.plain(&format!("  index state: {}", registry.index_state));
                    Ok(())
                }
                None => {
                    printer.info(&format!("no registry '{slug}' (or it is not public)"));
                    Ok(())
                }
            }
        }
    }
}

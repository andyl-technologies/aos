//! Dispatches Hub publication commands through shared registry adapters.

use crate::cli::{HubAccessArgs, HubPublishCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use crate::commands::hub::output::print_topology_message;
use anyhow::Result;
use aos_cli_ui::output::Printer;
use aos_hub_client::{hub_rpc as HubTopologyMethod, hub_types};
use aos_registry_authoring::registry::hub_publication::{
    self, PublicationAccess, begin_registry_publication_chunked,
};
use inventory::publication_manifest_request;

/// Handles the hub publish command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn publish(
    printer: &Printer,
    command: &HubPublishCmd,
) -> Result<()> {
    match command {
        HubPublishCmd::List {
            access,
            registry,
            state,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListRegistryPublicationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRegistryPublications,
                &hub_types::ListRegistryPublicationsRequest {
                    registry: registry.clone(),
                    state: state.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPublishCmd::Upload {
            access,
            registry,
            manifest,
            root,
        } => {
            let committed =
                upload_registry_publication(access, registry, manifest.as_deref(), root, printer)
                    .await?;
            print_topology_message(printer, &committed)
        }
        HubPublishCmd::Begin {
            access,
            registry,
            manifest,
        } => {
            let request = publication_manifest_request(manifest, registry)?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let publication = begin_registry_publication_chunked(&client, &request).await?;
            print_topology_message(printer, &publication)
        }
        HubPublishCmd::Show {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::GetRegistryPublication,
                &hub_types::GetRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
        HubPublishCmd::Commit {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::CommitRegistryPublication,
                &hub_types::CommitRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
        HubPublishCmd::Abort {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::AbortRegistryPublication,
                &hub_types::AbortRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
    }
}

/// Delegates exact publication transfer to the shared registry adapter.
///
/// # Errors
///
/// Returns an error for credential, inventory, transfer, or publication failures.
pub(crate) async fn upload_registry_publication(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    hub_publication::upload_registry_publication(
        &PublicationAccess {
            hub: access.hub.clone(),
            token: access.token.clone(),
        },
        registry,
        manifest,
        root,
        printer,
    )
    .await
}

/// Delegates exact publication transfer to the shared registry adapter.
///
/// # Errors
///
/// Returns an error for credential, inventory, transfer, or publication failures.
pub(crate) async fn prepare_registry_publication(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    hub_publication::prepare_registry_publication(
        &PublicationAccess {
            hub: access.hub.clone(),
            token: access.token.clone(),
        },
        registry,
        manifest,
        root,
        printer,
    )
    .await
}

/// Re-exports shared descriptor-pinned inventory helpers for command consumers.
pub(crate) use aos_registry_authoring::registry::hub_publication::inventory;

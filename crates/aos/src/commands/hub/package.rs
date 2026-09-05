//! Handles hub package commands and their domain-specific request validation.

use crate::cli::{HubChannelCmd, HubPackageCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub package command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn package(printer: &Printer, command: &HubPackageCmd) -> Result<()> {
    match command {
        HubPackageCmd::List {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListPackagesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListPackages,
                &hub_types::ListPackagesRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPackageCmd::Show {
            access,
            registry,
            name,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetPackageResponse>(
                printer,
                &client,
                HubTopologyMethod::GetPackage,
                &hub_types::GetPackageRequest {
                    slug: registry.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
    }
}

/// Handles the hub channel command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn channel(printer: &Printer, command: &HubChannelCmd) -> Result<()> {
    match command {
        HubChannelCmd::List {
            access,
            registry,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListChannelsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListChannels,
                &hub_types::ListChannelsRequest {
                    slug: registry.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubChannelCmd::Show {
            access,
            registry,
            name,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetChannelResponse>(
                printer,
                &client,
                HubTopologyMethod::GetChannel,
                &hub_types::GetChannelRequest {
                    slug: registry.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
    }
}

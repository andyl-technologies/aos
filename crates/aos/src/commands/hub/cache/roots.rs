//! Handles hub cache roots commands and their domain-specific request validation.

use crate::cli::{HubCacheLeaseCmd, HubCacheRootCmd};
use crate::commands::hub::cache::mutation::cache_plan_mutation;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_timestamp;
use crate::commands::hub::mutation::{new_idempotency_key, topology_read};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub cache root command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_root(printer: &Printer, command: &HubCacheRootCmd) -> Result<()> {
    match command {
        HubCacheRootCmd::List {
            access,
            cache,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListRetentionRootsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRetentionRoots,
                &hub_types::ListRetentionRootsRequest {
                    cache_id: cache.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubCacheRootCmd::Show {
            access,
            cache,
            root_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::RetentionRootResponse>(
                printer,
                &client,
                HubTopologyMethod::GetRetentionRoot,
                &hub_types::GetRetentionRootRequest {
                    cache_id: cache.clone(),
                    root_id: root_id.clone(),
                },
            )
            .await
        }
        HubCacheRootCmd::Create {
            access,
            cache,
            store_hash,
            reason,
            lease_until,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::RetentionRootResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanCreateManualRetentionRoot,
                HubTopologyMethod::CreateManualRetentionRoot,
                &hub_types::PlanManualRetentionRootRequest {
                    cache_id: cache.clone(),
                    store_hash: store_hash.clone(),
                    reason: reason.clone(),
                    lease_until: lease_until
                        .as_deref()
                        .map(|value| parse_timestamp(value, "--lease-until"))
                        .transpose()?,
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
            )
            .await
        }
        HubCacheRootCmd::Delete {
            access,
            cache,
            root_id,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::DeleteTopologyResourceResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanDeleteManualRetentionRoot,
                HubTopologyMethod::DeleteManualRetentionRoot,
                &hub_types::PlanDeleteManualRetentionRootRequest {
                    cache_id: cache.clone(),
                    root_id: root_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

/// Handles the hub cache lease command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_lease(printer: &Printer, command: &HubCacheLeaseCmd) -> Result<()> {
    match command {
        HubCacheLeaseCmd::Renew {
            access,
            cache,
            root_id,
            expires,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::RetentionLeaseResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanRenewRetentionLease,
                HubTopologyMethod::RenewRetentionLease,
                &hub_types::PlanRetentionLeaseRequest {
                    cache_id: cache.clone(),
                    root_id: root_id.clone(),
                    lease_id: String::new(),
                    expires_at: Some(parse_timestamp(expires, "--expires")?),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
        HubCacheLeaseCmd::Revoke {
            access,
            cache,
            lease_id,
            mutation,
        } => {
            cache_plan_mutation::<_, hub_types::RetentionLeaseResponse>(
                printer,
                access,
                cache,
                HubTopologyMethod::PlanRevokeRetentionLease,
                HubTopologyMethod::RevokeRetentionLease,
                &hub_types::PlanRevokeRetentionLeaseRequest {
                    cache_id: cache.clone(),
                    lease_id: lease_id.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
            )
            .await
        }
    }
}

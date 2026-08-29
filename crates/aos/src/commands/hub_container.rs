//! Hub OCI container administration commands.
//!
//! This module is kept separate from the broad Hub topology client because
//! container inventory and provenance have their own bounded Connect service.

use anyhow::{Context as _, Result};

use aos_core::output::Printer;
use aos_remote::hub_rpc as Method;
use aos_remote::{HubClient, hub_types};

use crate::cli::{
    HubAccessArgs, HubContainerCmd, HubContainerGcCmd, HubContainerGcPurgeFenceCmd,
    HubContainerGcUntrackedCmd, HubContainerLayerCmd, HubContainerManifestCmd,
    HubContainerPlatformCmd, HubContainerProvenanceCmd, HubContainerPublicationCmd,
    HubContainerReferrerCmd, HubContainerRepositoryCmd, HubContainerRetentionCmd,
    HubContainerTagCmd,
};

use super::hub::{
    container_hub_client, new_idempotency_key, parse_duration_seconds, print_topology_message,
    topology_mutation, topology_read,
};

/// Runs one Hub container-administration command.
///
/// # Errors
///
/// Returns an error when command inputs are incomplete, a reviewed mutation
/// fails validation, or the Hub rejects the Connect request.
pub async fn run(printer: &Printer, command: &HubContainerCmd) -> Result<()> {
    match command {
        HubContainerCmd::Repository { command } => repository(printer, command).await,
        HubContainerCmd::Tag { command } => tag(printer, command).await,
        HubContainerCmd::Manifest { command } => manifest(printer, command).await,
        HubContainerCmd::Platform { command } => platform(printer, command).await,
        HubContainerCmd::Layer { command } => layer(printer, command).await,
        HubContainerCmd::Referrer { command } => referrer(printer, command).await,
        HubContainerCmd::Publication { command } => publication(printer, command).await,
        HubContainerCmd::Provenance { command } => provenance(printer, command).await,
        HubContainerCmd::Retention { command } => retention(printer, command).await,
        HubContainerCmd::Gc { command } => gc(printer, command).await,
    }
}

fn client(access: &HubAccessArgs) -> Result<HubClient> {
    container_hub_client(access)
}

fn apply_request(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyContainerMutationRequest {
    hub_types::ApplyContainerMutationRequest {
        plan_id: plan_id.into(),
        idempotency_key: idempotency_key.into(),
        confirmation_hash: confirmation_hash.into(),
    }
}

fn repair_untracked_apply_request(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
    expected_resource_version: String,
) -> hub_types::RepairContainerUntrackedObjectRequest {
    hub_types::RepairContainerUntrackedObjectRequest {
        plan_id: plan_id.to_string(),
        idempotency_key: idempotency_key.to_string(),
        confirmation_hash: confirmation_hash.to_string(),
        expected_resource_version,
    }
}

fn plan_unset_container_tag_request(
    registry: String,
    repository: String,
    tag: String,
    expected_resource_version: String,
    expected_digest: String,
    idempotency_key: String,
) -> hub_types::PlanUnsetContainerTagRequest {
    hub_types::PlanUnsetContainerTagRequest {
        registry,
        repository,
        tag,
        expected_resource_version,
        expected_digest,
        idempotency_key,
    }
}

fn get_container_platform_request(
    registry: String,
    repository: String,
    root_digest: String,
    selector: &str,
    os_version: Option<&str>,
    os_features: Vec<String>,
) -> Result<hub_types::GetContainerPlatformRequest> {
    let (operating_system, architecture, variant) = parse_platform(selector)?;
    Ok(hub_types::GetContainerPlatformRequest {
        registry,
        repository,
        root_digest,
        operating_system,
        architecture,
        variant,
        os_version: os_version.unwrap_or_default().to_string(),
        os_features,
    })
}

async fn repository(printer: &Printer, command: &HubContainerRepositoryCmd) -> Result<()> {
    match command {
        HubContainerRepositoryCmd::List {
            access,
            registry,
            repository_prefix,
            pagination,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ListContainerRepositoriesResponse>(
                printer,
                &client,
                Method::ListContainerRepositories,
                &hub_types::ListContainerRepositoriesRequest {
                    registry: registry.clone(),
                    repository_prefix: repository_prefix.clone().unwrap_or_default(),
                    lifecycle_state: String::new(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubContainerRepositoryCmd::Show {
            access,
            registry,
            repository,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerRepositoryResponse>(
                printer,
                &client,
                Method::GetContainerRepository,
                &hub_types::GetContainerRepositoryRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                },
            )
            .await
        }
        HubContainerRepositoryCmd::Create {
            access,
            registry,
            repository,
            description,
            mutation,
        } => {
            let client = client(access)?;
            let request = if mutation.plan_id.is_some() {
                hub_types::PlanCreateContainerRepositoryRequest::default()
            } else {
                hub_types::PlanCreateContainerRepositoryRequest {
                    registry: registry
                        .clone()
                        .context("repository create requires REGISTRY when creating a plan")?,
                    repository: repository
                        .clone()
                        .context("repository create requires REPOSITORY when creating a plan")?,
                    description: description.clone().unwrap_or_default(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                }
            };
            topology_mutation(
                printer,
                &client,
                Method::PlanCreateContainerRepository,
                Method::CreateContainerRepository,
                &request,
                mutation,
                apply_request,
            )
            .await
        }
        HubContainerRepositoryCmd::Update {
            access,
            registry,
            repository,
            description,
            clear_description,
            mutation,
        } => {
            let client = client(access)?;
            let request = if mutation.plan_id.is_some() {
                hub_types::PlanUpdateContainerRepositoryRequest::default()
            } else {
                anyhow::ensure!(
                    description.is_some() || *clear_description,
                    "repository update requires --description or --clear-description"
                );
                hub_types::PlanUpdateContainerRepositoryRequest {
                    registry: registry
                        .clone()
                        .context("repository update requires REGISTRY when creating a plan")?,
                    repository: repository
                        .clone()
                        .context("repository update requires REPOSITORY when creating a plan")?,
                    description: description.clone().unwrap_or_default(),
                    update_mask: vec!["description".into()],
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                }
            };
            topology_mutation(
                printer,
                &client,
                Method::PlanUpdateContainerRepository,
                Method::UpdateContainerRepository,
                &request,
                mutation,
                apply_request,
            )
            .await
        }
        HubContainerRepositoryCmd::Delete {
            access,
            registry,
            repository,
            mutation,
        } => {
            let client = client(access)?;
            let request = if mutation.plan_id.is_some() {
                hub_types::PlanDeleteContainerRepositoryRequest::default()
            } else {
                hub_types::PlanDeleteContainerRepositoryRequest {
                    registry: registry
                        .clone()
                        .context("repository delete requires REGISTRY when creating a plan")?,
                    repository: repository
                        .clone()
                        .context("repository delete requires REPOSITORY when creating a plan")?,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                }
            };
            topology_mutation(
                printer,
                &client,
                Method::PlanDeleteContainerRepository,
                Method::DeleteContainerRepository,
                &request,
                mutation,
                apply_request,
            )
            .await
        }
    }
}

async fn tag(printer: &Printer, command: &HubContainerTagCmd) -> Result<()> {
    match command {
        HubContainerTagCmd::List {
            access,
            registry,
            repository,
            tag_prefix,
            pagination,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ListContainerTagsResponse>(
                printer,
                &client,
                Method::ListContainerTags,
                &hub_types::ListContainerTagsRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    tag_prefix: tag_prefix.clone().unwrap_or_default(),
                    ownership_kind: String::new(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubContainerTagCmd::Show {
            access,
            registry,
            repository,
            tag,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerTagResponse>(
                printer,
                &client,
                Method::GetContainerTag,
                &hub_types::GetContainerTagRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    tag: tag.clone(),
                },
            )
            .await
        }
        HubContainerTagCmd::Resolve {
            access,
            registry,
            repository,
            reference,
        } => {
            let client = client(access)?;
            if reference.starts_with("sha256:") {
                topology_read::<_, hub_types::ContainerManifestResponse>(
                    printer,
                    &client,
                    Method::GetContainerManifest,
                    &hub_types::GetContainerManifestRequest {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        digest: reference.clone(),
                    },
                )
                .await
            } else {
                topology_read::<_, hub_types::ContainerTagResolutionResponse>(
                    printer,
                    &client,
                    Method::ResolveContainerTag,
                    &hub_types::ResolveContainerTagRequest {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        tag: reference.clone(),
                        operating_system: String::new(),
                        architecture: String::new(),
                        variant: String::new(),
                        os_version: String::new(),
                        os_features: Vec::new(),
                    },
                )
                .await
            }
        }
        HubContainerTagCmd::History {
            access,
            registry,
            repository,
            tag,
            pagination,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ListContainerTagHistoryResponse>(
                printer,
                &client,
                Method::ListContainerTagHistory,
                &hub_types::ListContainerTagHistoryRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    tag: tag.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubContainerTagCmd::Set {
            access,
            registry,
            repository,
            tag,
            digest,
            if_digest,
            mutation,
        } => {
            let client = client(access)?;
            let request = if mutation.plan_id.is_some() {
                hub_types::PlanSetContainerTagRequest::default()
            } else {
                hub_types::PlanSetContainerTagRequest {
                    registry: registry
                        .clone()
                        .context("tag set requires REGISTRY when creating a plan")?,
                    repository: repository
                        .clone()
                        .context("tag set requires REPOSITORY when creating a plan")?,
                    tag: tag
                        .clone()
                        .context("tag set requires TAG when creating a plan")?,
                    target_digest: digest
                        .clone()
                        .context("tag set requires --digest when creating a plan")?,
                    expected_resource_version: mutation.if_version.clone(),
                    expected_digest: if_digest.clone(),
                    idempotency_key: new_idempotency_key(),
                }
            };
            topology_mutation(
                printer,
                &client,
                Method::PlanSetContainerTag,
                Method::SetContainerTag,
                &request,
                mutation,
                apply_request,
            )
            .await
        }
        HubContainerTagCmd::Unset {
            access,
            registry,
            repository,
            tag,
            if_digest,
            mutation,
        } => {
            let client = client(access)?;
            let request = if mutation.plan_id.is_some() {
                hub_types::PlanUnsetContainerTagRequest::default()
            } else {
                plan_unset_container_tag_request(
                    registry
                        .clone()
                        .context("tag unset requires REGISTRY when creating a plan")?,
                    repository
                        .clone()
                        .context("tag unset requires REPOSITORY when creating a plan")?,
                    tag.clone()
                        .context("tag unset requires TAG when creating a plan")?,
                    mutation.if_version.clone().unwrap_or_default(),
                    if_digest
                        .clone()
                        .context("tag unset requires --if-digest when creating a plan")?,
                    new_idempotency_key(),
                )
            };
            topology_mutation(
                printer,
                &client,
                Method::PlanUnsetContainerTag,
                Method::UnsetContainerTag,
                &request,
                mutation,
                apply_request,
            )
            .await
        }
    }
}

async fn manifest(printer: &Printer, command: &HubContainerManifestCmd) -> Result<()> {
    let HubContainerManifestCmd::Show {
        access,
        registry,
        repository,
        reference,
    } = command;
    let client = client(access)?;
    if reference.starts_with("sha256:") {
        topology_read::<_, hub_types::ContainerManifestResponse>(
            printer,
            &client,
            Method::GetContainerManifest,
            &hub_types::GetContainerManifestRequest {
                registry: registry.clone(),
                repository: repository.clone(),
                digest: reference.clone(),
            },
        )
        .await
    } else {
        topology_read::<_, hub_types::ContainerTagResolutionResponse>(
            printer,
            &client,
            Method::ResolveContainerTag,
            &hub_types::ResolveContainerTagRequest {
                registry: registry.clone(),
                repository: repository.clone(),
                tag: reference.clone(),
                operating_system: String::new(),
                architecture: String::new(),
                variant: String::new(),
                os_version: String::new(),
                os_features: Vec::new(),
            },
        )
        .await
    }
}

fn parse_platform(value: &str) -> Result<(String, String, String)> {
    let parts = value.split('/').collect::<Vec<_>>();
    anyhow::ensure!(
        matches!(parts.as_slice(), [_, _] | [_, _, _]) && parts.iter().all(|part| !part.is_empty()),
        "platform must be OS/ARCHITECTURE[/VARIANT]"
    );
    Ok((
        parts[0].into(),
        parts[1].into(),
        parts.get(2).copied().unwrap_or_default().into(),
    ))
}

async fn platform(printer: &Printer, command: &HubContainerPlatformCmd) -> Result<()> {
    match command {
        HubContainerPlatformCmd::List {
            access,
            registry,
            repository,
            reference,
            pagination,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ListContainerPlatformsResponse>(
                printer,
                &client,
                Method::ListContainerPlatforms,
                &hub_types::ListContainerPlatformsRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    root_digest: reference.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubContainerPlatformCmd::Show {
            access,
            registry,
            repository,
            reference,
            platform,
            os_version,
            os_features,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerPlatformResponse>(
                printer,
                &client,
                Method::GetContainerPlatform,
                &get_container_platform_request(
                    registry.clone(),
                    repository.clone(),
                    reference.clone(),
                    platform,
                    os_version.as_deref(),
                    os_features.clone(),
                )?,
            )
            .await
        }
    }
}

async fn layer(printer: &Printer, command: &HubContainerLayerCmd) -> Result<()> {
    match command {
        HubContainerLayerCmd::List {
            access,
            registry,
            repository,
            reference,
            platform,
            os_version,
            os_features,
            pagination,
        } => {
            let client = client(access)?;
            let manifest_digest = if let Some(platform) = platform {
                client
                    .call_topology(
                        Method::GetContainerPlatform,
                        &get_container_platform_request(
                            registry.clone(),
                            repository.clone(),
                            reference.clone(),
                            platform,
                            os_version.as_deref(),
                            os_features.clone(),
                        )?,
                    )
                    .await?
                    .platform
                    .ok_or_else(|| anyhow::anyhow!("Hub returned no container platform"))?
                    .manifest_digest
            } else {
                reference.clone()
            };
            topology_read::<_, hub_types::ListContainerLayersResponse>(
                printer,
                &client,
                Method::ListContainerLayers,
                &hub_types::ListContainerLayersRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    manifest_digest,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    root_digest: reference.clone(),
                },
            )
            .await
        }
        HubContainerLayerCmd::Show {
            access,
            registry,
            repository,
            root,
            manifest,
            digest,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerLayerResponse>(
                printer,
                &client,
                Method::GetContainerLayer,
                &hub_types::GetContainerLayerRequest {
                    registry: registry.clone(),
                    repository: repository.clone(),
                    manifest_digest: manifest.clone(),
                    digest: digest.clone(),
                    root_digest: root.clone(),
                },
            )
            .await
        }
    }
}

async fn referrer(printer: &Printer, command: &HubContainerReferrerCmd) -> Result<()> {
    let HubContainerReferrerCmd::List {
        access,
        registry,
        repository,
        subject,
        artifact_type,
        pagination,
    } = command;
    let client = client(access)?;
    topology_read::<_, hub_types::ListContainerReferrersResponse>(
        printer,
        &client,
        Method::ListContainerReferrers,
        &hub_types::ListContainerReferrersRequest {
            registry: registry.clone(),
            repository: repository.clone(),
            subject_digest: subject.clone(),
            artifact_type: artifact_type.clone().unwrap_or_default(),
            page_size: pagination.page_size.unwrap_or_default(),
            page_token: pagination.page_token.clone().unwrap_or_default(),
        },
    )
    .await
}

async fn publication(printer: &Printer, command: &HubContainerPublicationCmd) -> Result<()> {
    match command {
        HubContainerPublicationCmd::List {
            access,
            registry,
            repository,
            state,
            pagination,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ListContainerPublicationsResponse>(
                printer,
                &client,
                Method::ListContainerPublications,
                &hub_types::ListContainerPublicationsRequest {
                    registry: registry.clone(),
                    repository: repository.clone().unwrap_or_default(),
                    state: state.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubContainerPublicationCmd::Show {
            access,
            registry,
            publication_id,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerPublication>(
                printer,
                &client,
                Method::GetContainerPublication,
                &hub_types::GetContainerPublicationRequest {
                    publication_id: publication_id.clone(),
                    registry: registry.clone(),
                },
            )
            .await
        }
    }
}

async fn provenance(printer: &Printer, command: &HubContainerProvenanceCmd) -> Result<()> {
    let HubContainerProvenanceCmd::Show {
        access,
        registry,
        repository,
        reference,
        release,
    } = command;
    let client = client(access)?;
    topology_read::<_, hub_types::ContainerProvenanceResponse>(
        printer,
        &client,
        Method::GetContainerProvenance,
        &hub_types::GetContainerProvenanceRequest {
            registry: registry.clone(),
            repository: repository.clone(),
            root_digest: reference.clone(),
            release: release.clone(),
        },
    )
    .await
}

async fn retention(printer: &Printer, command: &HubContainerRetentionCmd) -> Result<()> {
    match command {
        HubContainerRetentionCmd::Show { access, registry } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerRetentionPolicyResponse>(
                printer,
                &client,
                Method::GetContainerRetentionPolicy,
                &hub_types::GetContainerRetentionPolicyRequest {
                    registry: registry.clone(),
                },
            )
            .await
        }
        HubContainerRetentionCmd::Set {
            access,
            registry,
            untagged_grace,
            deleted_tag_history,
            recent_manual_tag_revisions,
            retain_referrers,
            mutation,
        } => {
            let client = client(access)?;
            let request = if mutation.plan_id.is_some() {
                hub_types::PlanSetContainerRetentionPolicyRequest::default()
            } else {
                let registry = registry
                    .clone()
                    .context("retention set requires REGISTRY when creating a plan")?;
                let current: hub_types::ContainerRetentionPolicyResponse = client
                    .call_topology(
                        Method::GetContainerRetentionPolicy,
                        &hub_types::GetContainerRetentionPolicyRequest {
                            registry: registry.clone(),
                        },
                    )
                    .await?;
                let mut desired = current
                    .policy
                    .context("the Hub returned no container retention policy")?;
                if let Some(value) = untagged_grace {
                    desired.untagged_grace_period_secs = duration(value, "--untagged-grace")?;
                }
                if let Some(value) = deleted_tag_history {
                    desired.deleted_tag_history_period_secs =
                        duration(value, "--deleted-tag-history")?;
                }
                if let Some(value) = recent_manual_tag_revisions {
                    desired.recent_manual_tag_revisions = *value;
                }
                if let Some(value) = retain_referrers {
                    desired.retain_referrers = value == "enabled";
                }
                hub_types::PlanSetContainerRetentionPolicyRequest {
                    registry,
                    expected_resource_version: mutation
                        .if_version
                        .clone()
                        .unwrap_or_else(|| desired.resource_version.clone()),
                    policy: Some(desired),
                    idempotency_key: new_idempotency_key(),
                }
            };
            topology_mutation(
                printer,
                &client,
                Method::PlanSetContainerRetentionPolicy,
                Method::SetContainerRetentionPolicy,
                &request,
                mutation,
                apply_request,
            )
            .await
        }
    }
}

fn duration(value: &str, flag: &str) -> Result<u64> {
    u64::try_from(parse_duration_seconds(value, flag)?)
        .with_context(|| format!("{flag} must not be negative"))
}

async fn gc(printer: &Printer, command: &HubContainerGcCmd) -> Result<()> {
    match command {
        HubContainerGcCmd::Plan {
            access,
            registry,
            if_version,
            idempotency_key,
        } => {
            let client = client(access)?;
            let response: hub_types::ContainerGcPlanResponse = client
                .call_topology(
                    Method::PlanRunContainerGc,
                    &hub_types::PlanRunContainerGcRequest {
                        registry: registry.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: idempotency_key
                            .clone()
                            .unwrap_or_else(new_idempotency_key),
                    },
                )
                .await?;
            print_topology_message(printer, &response)
        }
        HubContainerGcCmd::Apply {
            access,
            plan_id,
            confirm_hash,
            idempotency_key,
            yes,
        } => {
            let client = client(access)?;
            if !*yes {
                anyhow::bail!("--yes is required to apply a reviewed garbage-collection plan");
            }
            let response: hub_types::OperationResponse = client
                .call_topology(
                    Method::RunContainerGc,
                    &hub_types::ApplyContainerMutationRequest {
                        plan_id: plan_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                        confirmation_hash: confirm_hash.clone(),
                    },
                )
                .await?;
            print_topology_message(printer, &response)
        }
        HubContainerGcCmd::Requeue {
            access,
            registry,
            run_id,
            action_id,
            if_version,
            idempotency_key,
            yes,
        } => {
            let client = client(access)?;
            if !*yes {
                anyhow::bail!("--yes is required to requeue a failed garbage-collection action");
            }
            let response: hub_types::ContainerGcPlacementActionResponse = client
                .call_topology(
                    Method::RequeueContainerGcPlacementAction,
                    &hub_types::RequeueContainerGcPlacementActionRequest {
                        registry: registry.clone(),
                        run_id: run_id.clone(),
                        action_id: action_id.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                )
                .await?;
            print_topology_message(printer, &response)
        }
        HubContainerGcCmd::Untracked { command } => match command {
            HubContainerGcUntrackedCmd::List {
                access,
                registry,
                pagination,
            } => {
                let client = client(access)?;
                topology_read::<_, hub_types::ListContainerUntrackedInventoryResponse>(
                    printer,
                    &client,
                    Method::ListContainerUntrackedInventory,
                    &hub_types::ListContainerUntrackedInventoryRequest {
                        registry: registry.clone(),
                        page_size: pagination.page_size.unwrap_or_default(),
                        page_token: pagination.page_token.clone().unwrap_or_default(),
                    },
                )
                .await
            }
            HubContainerGcUntrackedCmd::Repair {
                access,
                registry,
                placement_id,
                inventory_generation_id,
                object_key,
                mutation,
            } => {
                let client = client(access)?;
                let expected_resource_version = mutation
                    .if_version
                    .clone()
                    .context("--if-version is required for an untracked repair plan or apply")?;
                let request = if mutation.plan_id.is_some() {
                    hub_types::PlanRepairContainerUntrackedObjectRequest::default()
                } else {
                    hub_types::PlanRepairContainerUntrackedObjectRequest {
                        registry: registry.clone().context(
                            "untracked repair requires REGISTRY when creating a plan",
                        )?,
                        placement_id: placement_id.context(
                            "--placement-id is required when creating an untracked repair plan",
                        )?,
                        inventory_generation_id: inventory_generation_id.clone().context(
                            "--inventory-generation-id is required when creating an untracked repair plan",
                        )?,
                        object_key: object_key.clone().context(
                            "--object-key is required when creating an untracked repair plan",
                        )?,
                        expected_resource_version: expected_resource_version.clone(),
                        idempotency_key: String::new(),
                    }
                };
                topology_mutation(
                    printer,
                    &client,
                    Method::PlanRepairContainerUntrackedObject,
                    Method::RepairContainerUntrackedObject,
                    &request,
                    mutation,
                    move |plan_id, idempotency_key, confirmation_hash| {
                        repair_untracked_apply_request(
                            plan_id,
                            idempotency_key,
                            confirmation_hash,
                            expected_resource_version.clone(),
                        )
                    },
                )
                .await
            }
            HubContainerGcUntrackedCmd::RepairStatus { access, plan_id } => {
                let client = client(access)?;
                topology_read::<_, hub_types::ContainerUntrackedRepairResponse>(
                    printer,
                    &client,
                    Method::GetContainerUntrackedRepair,
                    &hub_types::GetContainerUntrackedRepairRequest {
                        plan_id: plan_id.clone(),
                    },
                )
                .await
            }
        },
        HubContainerGcCmd::PurgeFence { command } => match command {
            HubContainerGcPurgeFenceCmd::Plan {
                access,
                registry,
                action,
                if_version,
                idempotency_key,
            } => {
                let client = client(access)?;
                let action = match action.as_str() {
                    "begin" => hub_types::ContainerRegistryPurgeFenceAction::Begin as i32,
                    "abort" => hub_types::ContainerRegistryPurgeFenceAction::Abort as i32,
                    _ => anyhow::bail!("purge-fence action must be begin or abort"),
                };
                topology_read::<_, hub_types::TopologyPlanResponse>(
                    printer,
                    &client,
                    Method::PlanContainerRegistryPurgeFence,
                    &hub_types::PlanContainerRegistryPurgeFenceRequest {
                        registry: registry.clone(),
                        action,
                        expected_resource_version: if_version.clone(),
                        idempotency_key: idempotency_key
                            .clone()
                            .unwrap_or_else(new_idempotency_key),
                    },
                )
                .await
            }
            HubContainerGcPurgeFenceCmd::Apply {
                access,
                plan_id,
                confirm_hash,
                if_version,
                idempotency_key,
                yes,
            } => {
                if !*yes {
                    anyhow::bail!("--yes is required to apply a registry purge fence plan");
                }
                let client = client(access)?;
                topology_read::<_, hub_types::ContainerRegistryPurgeFenceResponse>(
                    printer,
                    &client,
                    Method::ApplyContainerRegistryPurgeFence,
                    &hub_types::ApplyContainerRegistryPurgeFenceRequest {
                        plan_id: plan_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                        confirmation_hash: confirm_hash.clone(),
                        expected_resource_version: if_version.clone(),
                    },
                )
                .await
            }
            HubContainerGcPurgeFenceCmd::Status { access, plan_id } => {
                let client = client(access)?;
                topology_read::<_, hub_types::ContainerRegistryPurgeFenceResponse>(
                    printer,
                    &client,
                    Method::GetContainerRegistryPurgeFence,
                    &hub_types::GetContainerRegistryPurgeFenceRequest {
                        plan_id: plan_id.clone(),
                    },
                )
                .await
            }
        },
        HubContainerGcCmd::Get {
            access,
            registry,
            id,
        } => {
            let client = client(access)?;
            topology_read::<_, hub_types::ContainerGcRunResponse>(
                printer,
                &client,
                Method::GetContainerGcRun,
                &hub_types::GetContainerGcRunRequest {
                    registry: registry.clone(),
                    run_id: id.clone(),
                },
            )
            .await
        }
        HubContainerGcCmd::List {
            access,
            registry,
            resource,
            run_id,
            state,
            pagination,
        } => {
            let client = client(access)?;
            match resource.as_str() {
                "runs" => {
                    if run_id.is_some() {
                        anyhow::bail!("--run-id is invalid for --resource runs");
                    }
                    topology_read::<_, hub_types::ListContainerGcRunsResponse>(
                        printer,
                        &client,
                        Method::ListContainerGcRuns,
                        &hub_types::ListContainerGcRunsRequest {
                            registry: registry.clone(),
                            state: state.clone().unwrap_or_default(),
                            page_size: pagination.page_size.unwrap_or_default(),
                            page_token: pagination.page_token.clone().unwrap_or_default(),
                        },
                    )
                    .await
                }
                "candidates" => {
                    let run_id = run_id.as_deref().context("--run-id is required")?;
                    if state.is_some() {
                        anyhow::bail!("--state is valid only for runs and placement-actions");
                    }
                    topology_read::<_, hub_types::ListContainerGcCandidatesResponse>(
                        printer,
                        &client,
                        Method::ListContainerGcCandidates,
                        &hub_types::ListContainerGcCandidatesRequest {
                            registry: registry.clone(),
                            run_id: run_id.to_string(),
                            page_size: pagination.page_size.unwrap_or_default(),
                            page_token: pagination.page_token.clone().unwrap_or_default(),
                        },
                    )
                    .await
                }
                "blockers" => {
                    let run_id = run_id.as_deref().context("--run-id is required")?;
                    if state.is_some()
                        || pagination.page_size.is_some()
                        || pagination.page_token.is_some()
                    {
                        anyhow::bail!("blocker lists do not accept state or pagination filters");
                    }
                    topology_read::<_, hub_types::ListContainerGcBlockersResponse>(
                        printer,
                        &client,
                        Method::ListContainerGcBlockers,
                        &hub_types::ListContainerGcBlockersRequest {
                            registry: registry.clone(),
                            run_id: run_id.to_string(),
                        },
                    )
                    .await
                }
                "placement-actions" => {
                    let run_id = run_id.as_deref().context("--run-id is required")?;
                    topology_read::<_, hub_types::ListContainerGcPlacementActionsResponse>(
                        printer,
                        &client,
                        Method::ListContainerGcPlacementActions,
                        &hub_types::ListContainerGcPlacementActionsRequest {
                            registry: registry.clone(),
                            run_id: run_id.to_string(),
                            state: state.clone().unwrap_or_default(),
                            page_size: pagination.page_size.unwrap_or_default(),
                            page_token: pagination.page_token.clone().unwrap_or_default(),
                        },
                    )
                    .await
                }
                _ => unreachable!("clap validates GC list resources"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        get_container_platform_request, parse_platform, plan_unset_container_tag_request,
        repair_untracked_apply_request,
    };

    #[test]
    fn platform_selector_is_exact() {
        assert_eq!(
            parse_platform("linux/amd64").unwrap(),
            ("linux".into(), "amd64".into(), String::new())
        );
        assert_eq!(
            parse_platform("linux/arm64/v8").unwrap(),
            ("linux".into(), "arm64".into(), "v8".into())
        );
        assert!(parse_platform("linux").is_err());
        assert!(parse_platform("linux//v8").is_err());
        assert!(parse_platform("linux/arm64/v8/extra").is_err());
    }

    #[test]
    fn manual_tag_unset_request_preserves_both_cas_inputs() {
        let request = plan_unset_container_tag_request(
            "andyl/main".to_string(),
            "aos".to_string(),
            "manual".to_string(),
            "7".to_string(),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            "unset-retry".to_string(),
        );

        assert_eq!(request.expected_resource_version, "7");
        assert_eq!(
            request.expected_digest,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(request.idempotency_key, "unset-retry");
    }

    #[test]
    fn complete_platform_request_preserves_ordered_oci_identity() {
        let request = get_container_platform_request(
            "andyl/main".to_string(),
            "aos".to_string(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "windows/amd64",
            Some("10.0.20348.2402"),
            vec!["win32k".to_string(), "containers".to_string()],
        )
        .unwrap();

        assert_eq!(request.operating_system, "windows");
        assert_eq!(request.architecture, "amd64");
        assert_eq!(request.os_version, "10.0.20348.2402");
        assert_eq!(request.os_features, ["win32k", "containers"]);
    }

    #[test]
    fn untracked_repair_apply_preserves_review_and_cas_identity() {
        let request = repair_untracked_apply_request(
            "repair-plan",
            "repair-apply-key",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1".to_string(),
        );

        assert_eq!(request.plan_id, "repair-plan");
        assert_eq!(request.idempotency_key, "repair-apply-key");
        assert_eq!(
            request.confirmation_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(request.expected_resource_version, "1");
    }
}

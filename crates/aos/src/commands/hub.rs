//! `aos hub` — the registry-hub control-plane client (RFC-0004).
//!
//! Drives [`aos_remote::RegistryHubClient`] so the CLI interacts with a running
//! `aos-registry-hub` purely through its public ConnectRPC API, never by
//! touching the hub's database. `login` exchanges a provisioning secret for a
//! hub access JWT via the REST `POST /oauth2/token` endpoint
//! ([`aos_remote::exchange_token`]); read operations run anonymously by default
//! and accept an optional `--token` (that JWT) for authenticated reads. The
//! tenancy writes (`org`/`project`/`binding create`) take that JWT too; further
//! write subcommands follow in later RFC-0004 Phase 5 increments.

use anyhow::Result;

use aos_core::output::Printer;
use aos_remote::RegistryHubClient;

use crate::cli::{
    HubBindingCmd, HubCmd, HubOrgCmd, HubProjectCmd, HubRegistryCmd, HubWebhookCmd,
};

/// Handles `aos hub login`: exchanges a provisioning secret for an access JWT.
async fn login(printer: &Printer, hub: &str, provisioning_token: &str) -> Result<()> {
    let grant = aos_remote::exchange_token(hub, provisioning_token).await?;
    if printer.json_if_active(&serde_json::json!({
        "access_token": grant.access_token,
        "token_type": grant.token_type,
        "expires_in": grant.expires_in,
    })) {
        return Ok(());
    }
    // The access token is the deliverable; print it on its own line (plain, not
    // a styled header) so it is easy to capture into `--token` or a variable.
    printer.info(&format!(
        "access token issued ({}, expires in {}s):",
        grant.token_type, grant.expires_in
    ));
    printer.plain(&grant.access_token);
    Ok(())
}

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
        } => login(printer, hub, provisioning_token).await,
        HubCmd::Registry { command } => registry(printer, command).await,
        HubCmd::Org { command } => org(printer, command).await,
        HubCmd::Project { command } => project(printer, command).await,
        HubCmd::Binding { command } => binding(printer, command).await,
        HubCmd::Webhook { command } => webhook(printer, command).await,
        HubCmd::Audit { hub, token, scope } => {
            audit(printer, hub, token.as_deref(), scope).await
        }
        HubCmd::Changesets { hub, token, scope } => {
            changesets(printer, hub, token.as_deref(), scope).await
        }
    }
}

/// Renders a scope path for display, naming the empty root scope.
fn scope_label(scope: &str) -> &str {
    if scope.is_empty() {
        "<instance root>"
    } else {
        scope
    }
}

/// Handles `aos hub org …`.
async fn org(printer: &Printer, command: &HubOrgCmd) -> Result<()> {
    match command {
        HubOrgCmd::List { hub, token } => {
            let client = hub_client(hub, token.as_deref())?;
            let orgs = client.list_orgs().await?;
            if printer.json_if_active(&serde_json::json!({
                "orgs": orgs
                    .iter()
                    .map(|o| serde_json::json!({
                        "slug": o.slug,
                        "name": o.name,
                        "created_at": o.created_at,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if orgs.is_empty() {
                printer.info("no organizations visible (authenticate with --token?)");
                return Ok(());
            }
            printer.header(&format!("{} org(s) on {hub}", orgs.len()));
            for org in &orgs {
                printer.plain(&format!("  {}  {}", org.slug, org.name));
            }
            Ok(())
        }
        HubOrgCmd::Create {
            hub,
            token,
            slug,
            name,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            let org = client.create_org(slug, name).await?;
            if printer.json_if_active(&serde_json::json!({
                "org": { "slug": org.slug, "name": org.name, "created_at": org.created_at },
            })) {
                return Ok(());
            }
            printer.success(&format!("created org '{}' ({})", org.slug, org.name));
            Ok(())
        }
    }
}

/// Handles `aos hub project …`.
async fn project(printer: &Printer, command: &HubProjectCmd) -> Result<()> {
    match command {
        HubProjectCmd::List { hub, token, org } => {
            let client = hub_client(hub, token.as_deref())?;
            let projects = client.list_projects(org).await?;
            if printer.json_if_active(&serde_json::json!({
                "projects": projects
                    .iter()
                    .map(|p| serde_json::json!({
                        "org_slug": p.org_slug,
                        "path": p.path,
                        "name": p.name,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if projects.is_empty() {
                printer.info(&format!("no projects in org '{org}'"));
                return Ok(());
            }
            printer.header(&format!("{} project(s) in {org}", projects.len()));
            for project in &projects {
                let path = if project.path.is_empty() {
                    "<org root>"
                } else {
                    &project.path
                };
                printer.plain(&format!("  {path}  {}", project.name));
            }
            Ok(())
        }
        HubProjectCmd::Create {
            hub,
            token,
            org,
            path,
            name,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            let project = client.create_project(org, path, name).await?;
            if printer.json_if_active(&serde_json::json!({
                "project": {
                    "org_slug": project.org_slug,
                    "path": project.path,
                    "name": project.name,
                },
            })) {
                return Ok(());
            }
            let where_ = if project.path.is_empty() {
                "<org root>".to_string()
            } else {
                project.path.clone()
            };
            printer.success(&format!(
                "created project '{}' at {where_} in org '{org}'",
                project.name
            ));
            Ok(())
        }
    }
}

/// Handles `aos hub binding …`.
async fn binding(printer: &Printer, command: &HubBindingCmd) -> Result<()> {
    match command {
        HubBindingCmd::List { hub, token, org } => {
            let client = hub_client(hub, token.as_deref())?;
            let bindings = client.list_bindings(org).await?;
            if printer.json_if_active(&serde_json::json!({
                "bindings": bindings
                    .iter()
                    .map(|b| serde_json::json!({
                        "org_slug": b.org_slug,
                        "name": b.name,
                        "kind": b.kind,
                        "root": b.root,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if bindings.is_empty() {
                printer.info(&format!("no storage bindings in org '{org}'"));
                return Ok(());
            }
            printer.header(&format!("{} binding(s) in {org}", bindings.len()));
            for binding in &bindings {
                printer.plain(&format!(
                    "  {}  [{}]  {}",
                    binding.name, binding.kind, binding.root
                ));
            }
            Ok(())
        }
        HubBindingCmd::Create {
            hub,
            token,
            org,
            name,
            kind,
            root,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            let binding = client.create_binding(org, name, kind, root).await?;
            if printer.json_if_active(&serde_json::json!({
                "binding": {
                    "org_slug": binding.org_slug,
                    "name": binding.name,
                    "kind": binding.kind,
                    "root": binding.root,
                },
            })) {
                return Ok(());
            }
            printer.success(&format!(
                "created binding '{}' [{}] -> {} in org '{org}'",
                binding.name, binding.kind, binding.root
            ));
            Ok(())
        }
    }
}

/// Handles `aos hub webhook …`.
async fn webhook(printer: &Printer, command: &HubWebhookCmd) -> Result<()> {
    match command {
        HubWebhookCmd::List { hub, token, org } => {
            let client = hub_client(hub, token.as_deref())?;
            let webhooks = client.list_webhooks(org).await?;
            if printer.json_if_active(&serde_json::json!({
                "webhooks": webhooks
                    .iter()
                    .map(|w| serde_json::json!({
                        "id": w.id,
                        "url": w.url,
                        "events": w.events,
                        "active": w.active,
                        "created_at": w.created_at,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if webhooks.is_empty() {
                printer.info(&format!("no webhooks in org '{org}'"));
                return Ok(());
            }
            printer.header(&format!("{} webhook(s) in {org}", webhooks.len()));
            for webhook in &webhooks {
                let events = if webhook.events.is_empty() {
                    "all events".to_string()
                } else {
                    webhook.events.join(",")
                };
                let state = if webhook.active { "active" } else { "inactive" };
                printer.plain(&format!(
                    "  #{}  {}  [{events}]  ({state})",
                    webhook.id, webhook.url
                ));
            }
            Ok(())
        }
        HubWebhookCmd::Create {
            hub,
            token,
            org,
            url,
            event,
            secret,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            let (webhook, signing_secret) =
                client.create_webhook(org, url, event.clone(), secret).await?;
            if printer.json_if_active(&serde_json::json!({
                "webhook": {
                    "id": webhook.id,
                    "url": webhook.url,
                    "events": webhook.events,
                    "active": webhook.active,
                },
                "secret": signing_secret,
            })) {
                return Ok(());
            }
            printer.success(&format!(
                "created webhook #{} -> {} in org '{org}'",
                webhook.id, webhook.url
            ));
            // The HMAC signing secret is shown exactly once.
            printer.info("HMAC signing secret (shown once — store it now):");
            printer.plain(&signing_secret);
            Ok(())
        }
        HubWebhookCmd::Delete { hub, token, id } => {
            let client = hub_client(hub, token.as_deref())?;
            let deleted = client.delete_webhook(*id).await?;
            if printer.json_if_active(&serde_json::json!({ "deleted": deleted })) {
                return Ok(());
            }
            if deleted {
                printer.success(&format!("deleted webhook #{id}"));
            } else {
                printer.info(&format!("no webhook #{id} to delete"));
            }
            Ok(())
        }
    }
}

/// Handles `aos hub audit [--scope <s>]`.
async fn audit(printer: &Printer, hub: &str, token: Option<&str>, scope: &str) -> Result<()> {
    let client = hub_client(hub, token)?;
    let entries = client.list_audit(scope).await?;
    if printer.json_if_active(&serde_json::json!({
        "entries": entries
            .iter()
            .map(|e| serde_json::json!({
                "change_id": e.change_id,
                "actor_label": e.actor_label,
                "action": e.action,
                "scope": e.scope,
                "detail": e.detail,
                "created_at": e.created_at,
            }))
            .collect::<Vec<_>>(),
    })) {
        return Ok(());
    }
    if entries.is_empty() {
        printer.info(&format!(
            "no audit entries at scope {}",
            scope_label(scope)
        ));
        return Ok(());
    }
    printer.header(&format!(
        "{} audit entr{} at scope {}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        scope_label(scope)
    ));
    for entry in &entries {
        printer.plain(&format!(
            "  {}  {}  {}",
            entry.actor_label, entry.action, entry.scope
        ));
    }
    Ok(())
}

/// Handles `aos hub changesets [--scope <s>]`.
async fn changesets(printer: &Printer, hub: &str, token: Option<&str>, scope: &str) -> Result<()> {
    let client = hub_client(hub, token)?;
    let changesets = client.list_changesets(scope).await?;
    if printer.json_if_active(&serde_json::json!({
        "changesets": changesets
            .iter()
            .map(|c| serde_json::json!({
                "change_id": c.change_id,
                "actor_label": c.actor_label,
                "scope": c.scope,
                "status": c.status,
                "summary": c.summary,
                "created_at": c.created_at,
            }))
            .collect::<Vec<_>>(),
    })) {
        return Ok(());
    }
    if changesets.is_empty() {
        printer.info(&format!(
            "no change-sets at scope {}",
            scope_label(scope)
        ));
        return Ok(());
    }
    printer.header(&format!(
        "{} change-set(s) at scope {}",
        changesets.len(),
        scope_label(scope)
    ));
    for changeset in &changesets {
        printer.plain(&format!(
            "  {}  [{}]  {}",
            changeset.change_id, changeset.status, changeset.summary
        ));
    }
    Ok(())
}

/// Builds a hub client: token-authenticated when a JWT is supplied, else
/// anonymous (public reads only).
fn hub_client(hub: &str, token: Option<&str>) -> Result<RegistryHubClient> {
    match token {
        Some(token) => RegistryHubClient::connect_with_token(hub, token),
        None => RegistryHubClient::connect_anonymous(hub),
    }
}

/// Handles `aos hub registry …`.
async fn registry(printer: &Printer, command: &HubRegistryCmd) -> Result<()> {
    match command {
        HubRegistryCmd::List { hub, token } => {
            let client = hub_client(hub, token.as_deref())?;
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
        HubRegistryCmd::Get { hub, token, slug } => {
            let client = hub_client(hub, token.as_deref())?;
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
        HubRegistryCmd::Releases { hub, token, slug } => {
            let client = hub_client(hub, token.as_deref())?;
            let releases = client.list_releases(slug).await?;
            if printer.json_if_active(&serde_json::json!({
                "releases": releases
                    .iter()
                    .map(|r| serde_json::json!({
                        "semver": r.semver,
                        "commit_oid": r.commit_oid,
                        "tag_oid": r.tag_oid,
                        "tagged_at": r.tagged_at,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if releases.is_empty() {
                printer.info(&format!("no verified releases for '{slug}'"));
                return Ok(());
            }
            printer.header(&format!("{} release(s) for {slug}", releases.len()));
            for release in &releases {
                printer.plain(&format!("  {}  {}", release.semver, release.commit_oid));
            }
            Ok(())
        }
        HubRegistryCmd::Packages { hub, token, slug } => {
            let client = hub_client(hub, token.as_deref())?;
            let packages = client.list_packages(slug).await?;
            if printer.json_if_active(&serde_json::json!({
                "packages": packages
                    .iter()
                    .map(|p| serde_json::json!({
                        "name": p.name,
                        "description": p.description,
                        "license": p.license,
                        "latest_version": p.latest_version,
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if packages.is_empty() {
                printer.info(&format!("no packages in '{slug}'"));
                return Ok(());
            }
            printer.header(&format!("{} package(s) in {slug}", packages.len()));
            for package in &packages {
                let version = if package.latest_version.is_empty() {
                    "—"
                } else {
                    &package.latest_version
                };
                printer.plain(&format!("  {}  {version}", package.name));
            }
            Ok(())
        }
        HubRegistryCmd::Channels { hub, token, slug } => {
            let client = hub_client(hub, token.as_deref())?;
            let channels = client.list_channels(slug).await?;
            if printer.json_if_active(&serde_json::json!({
                "channels": channels
                    .iter()
                    .map(|c| serde_json::json!({
                        "name": c.name,
                        "frontier": c.frontier,
                        "assigned_partitions": c.partitions.len(),
                    }))
                    .collect::<Vec<_>>(),
            })) {
                return Ok(());
            }
            if channels.is_empty() {
                printer.info(&format!("no channels in '{slug}'"));
                return Ok(());
            }
            printer.header(&format!("{} channel(s) in {slug}", channels.len()));
            for channel in &channels {
                let frontier = if channel.frontier.is_empty() {
                    "unset"
                } else {
                    &channel.frontier
                };
                printer.plain(&format!(
                    "  {}  frontier={frontier}  ({}/256 partitions)",
                    channel.name,
                    channel.partitions.len()
                ));
            }
            Ok(())
        }
        HubRegistryCmd::Create {
            hub,
            token,
            org,
            project_path,
            name,
            visibility,
            binding,
            prefix,
            trust_key,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            let registry = client
                .create_registry(
                    org,
                    project_path,
                    name,
                    visibility,
                    binding,
                    prefix,
                    trust_key.clone(),
                )
                .await?;
            if printer.json_if_active(&serde_json::json!({
                "registry": {
                    "slug": registry.slug,
                    "name": registry.name,
                    "index_state": registry.index_state,
                },
            })) {
                return Ok(());
            }
            printer.success(&format!(
                "created registry '{}' ({visibility}) in org '{org}'",
                registry.slug
            ));
            Ok(())
        }
    }
}

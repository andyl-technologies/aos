//! Scope-owned access-token inventory, issuance, and retirement.
//!
//! Tokens are listed by immutable authorization scope, not registry slug.
//! Issuance returns the secret once after an explicit reviewed apply; the
//! browser holds it only in component memory until the operator reloads.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{EmptyState, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

use super::organization_scope::organization_authorization_scope;

/// One console resource whose immutable token scope must be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AccessTokenSurface {
    /// Deployment-wide credentials.
    Instance,
    /// Organization-owned credentials.
    Organization(String),
    /// Registry-owned credentials.
    Registry(String),
    /// Binary-cache-owned credentials.
    Cache(String),
}

/// Renders access-token controls for one immutable resource scope.
#[component]
pub(super) fn AccessTokenWorkflow(client: ApiClient, surface: AccessTokenSurface) -> impl IntoView {
    let read_client = client.clone();
    let scope = LocalResource::new(move || {
        let client = read_client.clone();
        let surface = surface.clone();
        async move { resolve_token_scope(&client, surface).await }
    });
    let view_client = client;

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving token scope…"</p> }>
            {move || {
                let client = view_client.clone();
                Suspend::new(async move {
                    match scope.await.as_ref() {
                        Ok(scope) => view! {
                            <AccessTokenSettings client=client scope=scope.clone()/>
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

async fn resolve_token_scope(
    client: &ApiClient,
    surface: AccessTokenSurface,
) -> Result<String, String> {
    let scope = match surface {
        AccessTokenSurface::Instance => "instance".to_string(),
        AccessTokenSurface::Organization(slug) => {
            organization_authorization_scope(client, slug).await?
        }
        AccessTokenSurface::Registry(slug) => {
            let response = client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            response
                .registry
                .ok_or_else(|| "the Hub omitted the registry".to_string())?
                .authorization_scope_key
        }
        AccessTokenSurface::Cache(cache_id) => {
            let response = client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_BINARY_CACHE_PATH,
                    &aos_proto_types::GetBinaryCacheRequest { cache_id },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            response
                .cache
                .ok_or_else(|| "the Hub omitted the binary cache".to_string())?
                .authorization_scope_key
        }
    };
    if scope.is_empty() {
        return Err("the Hub omitted the immutable token scope".to_string());
    }
    Ok(scope)
}

#[component]
fn AccessTokenSettings(client: ApiClient, scope: String) -> impl IntoView {
    let can_list = client.allows("tokens.manage");
    let list_client = client.clone();
    let list_scope = scope.clone();
    let tokens = LocalResource::new(move || {
        let client = list_client.clone();
        let scope = list_scope.clone();
        async move {
            if !can_list {
                return Ok(Vec::new());
            }
            client
                .collect_pages::<_, aos_proto_types::ListAccessTokensResponse, _, _, _>(
                    aos_proto_types::IDENTITY_SERVICE_LIST_ACCESS_TOKENS_PATH,
                    move |page_token| aos_proto_types::ListAccessTokensRequest {
                        scope: scope.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.tokens, response.next_page_token),
                )
                .await
                .map_err(|failure| failure.to_string())
        }
    });
    let default_owner = client
        .session()
        .principal
        .map(|principal| format!("user:{}", principal.email))
        .unwrap_or_default();
    let inventory_client = client.clone();
    let can_issue = client.allows("tokens.self") || client.allows("tokens.manage");
    let issue_client = client;

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"Scoped credentials"</p>
                        <h2>"Access tokens"</h2>
                        <p>
                            "Token authority is bounded by both this resource scope and the owner's current grants."
                        </p>
                    </div>
                </div>
                <div class="resource-identity">
                    <div><span>"Authorization scope"</span><code>{scope.clone()}</code></div>
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading tokens…"</p> }>
                    {move || {
                        let client = inventory_client.clone();
                        Suspend::new(async move {
                            match tokens.await.as_ref() {
                                Ok(_) if !can_list => view! {
                                    <p class="muted">"You can create a token for yourself below. Listing all tokens for this resource requires token-management permission."</p>
                                }.into_any(),
                                Ok(tokens) if tokens.is_empty() => view! {
                                    <EmptyState
                                        title="No access tokens".to_string()
                                        detail="Issue a short-lived credential for a user or service account."
                                            .to_string()
                                        action_label=None
                                        action=None
                                    />
                                }
                                .into_any(),
                                Ok(tokens) => view! {
                                    <div class="binding-list">
                                        {tokens.iter().cloned().map(|token| view! {
                                            <AccessTokenCard client=client.clone() token=token/>
                                        }).collect_view()}
                                    </div>
                                }
                                .into_any(),
                                Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
                {can_issue.then(|| view! {
                    <details class="advanced-controls">
                        <summary>"Issue an access token"</summary>
                        <IssueAccessToken client=issue_client scope=scope default_owner=default_owner/>
                    </details>
                })}
            </section>
        </div>
    }
}

#[component]
fn AccessTokenCard(client: ApiClient, token: aos_proto_types::TokenInfo) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let active = token.resource_version == "active";
    let plan_client = client.clone();
    let plan_token_id = token.token_id.clone();
    let plan_version = token.resource_version.clone();

    let on_plan_retire = move |_| {
        if !active {
            return;
        }
        let key = idempotency_key("access-token-retire");
        let request = aos_proto_types::PlanRetireAccessTokenRequest {
            token_id: plan_token_id.clone(),
            expected_resource_version: plan_version.clone(),
            idempotency_key: key.clone(),
        };
        begin_plan(
            plan_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_RETIRE_ACCESS_TOKEN_PATH,
            request,
            key,
            pending,
            error,
            busy,
        );
    };
    let apply = apply_retirement(client, pending, error, busy);

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{display_or(&token.comment, "Access token")}</strong>
                    <code>{token.token_id}</code>
                </div>
                <StatusBadge state=token.resource_version.clone() positive=active/>
            </div>
            <div class="resource-identity">
                <div><span>"Owner"</span><code>{token.owner}</code></div>
                <div><span>"Created"</span><strong>{display_timestamp(token.created_at, "Not recorded")}</strong></div>
                <div><span>"Expires"</span><strong>{display_timestamp(token.expires_at, "never")}</strong></div>
                <div><span>"Last used"</span><strong>{display_timestamp(token.last_used_at, "never")}</strong></div>
            </div>
            <details>
                <summary>"Permissions"</summary>
                <ul>{token.permissions.into_iter().map(|permission| view! { <li><code>{permission}</code></li> }).collect_view()}</ul>
            </details>
            <button
                class="danger-button"
                type="button"
                disabled=move || busy.get() || !active
                on:click=on_plan_retire
            >
                "Review retirement"
            </button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <PlanReview pending=pending busy=busy on_apply=apply/>
        </article>
    }
}

#[component]
fn IssueAccessToken(client: ApiClient, scope: String, default_owner: String) -> impl IntoView {
    let can_choose_owner = client.allows("tokens.manage");
    let owner = RwSignal::new(default_owner);
    let permissions = RwSignal::new("read".to_string());
    let ttl_seconds = RwSignal::new("3600".to_string());
    let comment = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let issued = RwSignal::new(None::<aos_proto_types::AccessTokenResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();

        let permissions = match parse_permissions(&permissions.get_untracked()) {
            Ok(permissions) => permissions,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let ttl_secs = match parse_ttl(&ttl_seconds.get_untracked()) {
            Ok(ttl) => ttl,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let owner = owner.get_untracked().trim().to_string();
        if !owner.starts_with("user:") && !owner.starts_with("service_account:") {
            error.set(Some(
                "Owner must be user:EMAIL or service_account:ORG/NAME".to_string(),
            ));
            return;
        }

        let key = idempotency_key("access-token-issue");
        let request = aos_proto_types::PlanIssueAccessTokenRequest {
            owner,
            scope: scope.clone(),
            permissions,
            ttl_secs,
            expected_resource_version: String::new(),
            idempotency_key: key.clone(),
            comment: comment.get_untracked().trim().to_string(),
        };
        issued.set(None);
        begin_plan(
            plan_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_ISSUE_ACCESS_TOKEN_PATH,
            request,
            key,
            pending,
            error,
            busy,
        );
    };

    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        error.set(None);

        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::AccessTokenResponse>(
                    aos_proto_types::IDENTITY_SERVICE_ISSUE_ACCESS_TOKEN_PATH,
                    &reviewed.topology_apply(),
                )
                .await
            {
                Ok(response) if response.secret.is_empty() => {
                    error.set(Some(
                        "The Hub omitted the one-time token secret".to_string(),
                    ));
                }
                Ok(response) => {
                    pending.set(None);
                    issued.set(Some(response));
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow">
            <h4>"Issue access token"</h4>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Owner"</span>
                    <input
                        required
                        prop:value=move || owner.get()
                        readonly=!can_choose_owner
                        on:input=move |event| owner.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"Permissions"</span>
                    <textarea
                        required
                        prop:value=move || permissions.get()
                        on:input=move |event| permissions.set(event_target_value(&event))
                    ></textarea>
                    <small>"Separate permissions with commas or spaces. The token cannot exceed your current permissions."</small>
                </label>
                <label>
                    <span>"Lifetime (seconds)"</span>
                    <input
                        required
                        type="number"
                        min="0"
                        prop:value=move || ttl_seconds.get()
                        on:input=move |event| ttl_seconds.set(event_target_value(&event))
                    />
                    <small>"3600 = one hour; 86400 = one day. Use 0 for the Hub default."</small>
                </label>
                <label>
                    <span>"Purpose (non-secret)"</span>
                    <input
                        prop:value=move || comment.get()
                        on:input=move |event| comment.set(event_target_value(&event))
                    />
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Review token issuance"
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <PlanReview pending=pending busy=busy on_apply=on_apply/>
            {move || issued.get().map(|token| view! { <IssuedToken token=token/> })}
        </section>
    }
}

#[component]
fn IssuedToken(token: aos_proto_types::AccessTokenResponse) -> impl IntoView {
    view! {
        <section class="panel warning-list" role="status">
            <p class="section-kicker">"One-time credential"</p>
            <h3>"Copy this token now"</h3>
            <p>"The Hub cannot return this secret again after this browser session leaves the page."</p>
            <div class="resource-identity">
                <div><span>"Token ID"</span><code>{token.token_id}</code></div>
                <div><span>"Secret"</span><code>{token.secret}</code></div>
            </div>
            <button class="secondary-button" type="button" on:click=move |_| reload()>
                "I stored the secret"
            </button>
        </section>
    }
}

fn parse_permissions(value: &str) -> Result<Vec<String>, String> {
    let mut permissions = value
        .split(|character: char| character == ',' || character.is_whitespace())
        .map(str::trim)
        .filter(|permission| !permission.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    permissions.sort();
    permissions.dedup();
    if permissions.is_empty() {
        return Err("At least one permission verb is required".to_string());
    }
    Ok(permissions)
}

fn parse_ttl(value: &str) -> Result<i64, String> {
    value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|ttl| *ttl >= 0)
        .ok_or_else(|| "Token lifetime must be a non-negative number".to_string())
}

fn begin_plan<RequestMessage>(
    client: ApiClient,
    path: &'static str,
    request: RequestMessage,
    key: String,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) where
    RequestMessage: serde::Serialize + 'static,
{
    error.set(None);
    pending.set(None);
    busy.set(true);

    spawn_local(async move {
        let result = client
            .call(path, &request)
            .await
            .map_err(|failure| failure.to_string())
            .and_then(|response| PendingPlan::from_response(response, key));
        match result {
            Ok(reviewed) => pending.set(Some(reviewed)),
            Err(detail) => error.set(Some(detail)),
        }
        busy.set(false);
    });
}

fn apply_retirement(
    client: ApiClient,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()> {
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);

        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::AccessTokenRetirementResponse>(
                    aos_proto_types::IDENTITY_SERVICE_RETIRE_ACCESS_TOKEN_PATH,
                    &reviewed.topology_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

#[component]
fn PlanReview(
    pending: RwSignal<Option<PendingPlan>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! {
        {move || pending.get().map(|reviewed| view! {
            <ReviewedPlanCard
                plan=reviewed.plan
                applying=busy.get()
                on_apply=on_apply
                on_cancel=Callback::new(move |()| pending.set(None))
            />
        })}
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn display_timestamp(value: i64, fallback: &str) -> String {
    crate::components::format_timestamp(value, fallback)
}

fn reload() {
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_editor_canonicalizes_repeated_separators() {
        assert_eq!(
            parse_permissions("write, read\nwrite"),
            Ok(vec!["read".to_string(), "write".to_string()])
        );
        assert!(parse_permissions(" , \n").is_err());
    }
}

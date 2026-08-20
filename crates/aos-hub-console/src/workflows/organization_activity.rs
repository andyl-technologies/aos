//! Organization webhook automation and append-only audit history.
//!
//! Webhook signing material is referenced by immutable secret-provider version
//! and verified fingerprint; plaintext never enters the Hub API. Audit entries
//! and webhook inventory are fully paginated and preserve their stable change,
//! commit, and tag cross-references.

use std::collections::BTreeSet;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{EmptyState, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders the selected organization automation or audit page.
#[component]
pub(super) fn OrganizationActivity(
    client: ApiClient,
    organization: String,
    page: &'static str,
) -> impl IntoView {
    match page {
        "webhooks" => view! {
            <OrganizationWebhooks client=client organization=organization/>
        }
        .into_any(),
        "audit" => view! {
            <OrganizationAudit client=client organization=organization/>
        }
        .into_any(),
        _ => view! { <InlineError detail="Unknown organization activity page".to_string()/> }
            .into_any(),
    }
}

#[derive(Clone, Debug, Default)]
struct WebhookInventory {
    webhooks: Vec<aos_proto_types::Webhook>,
    event_types: Vec<String>,
}

#[component]
fn OrganizationWebhooks(client: ApiClient, organization: String) -> impl IntoView {
    let read_client = client.clone();
    let read_org = organization.clone();
    let inventory = LocalResource::new(move || {
        let client = read_client.clone();
        let organization = read_org.clone();
        async move { load_webhooks(&client, &organization).await }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Signed event delivery"</p>
                    <h2>"Webhooks"</h2>
                    <p>
                        "Subscriptions resolve an immutable secret version only while signing outbound deliveries."
                    </p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading webhooks…"</p> }>
                {move || {
                    let client = client.clone();
                    let organization = organization.clone();
                    Suspend::new(async move {
                        match inventory.await.as_ref() {
                            Ok(inventory) => view! {
                                <WebhookList
                                    client=client.clone()
                                    webhooks=inventory.webhooks.clone()
                                />
                                <CreateWebhook
                                    client=client
                                    organization=organization
                                    event_types=inventory.event_types.clone()
                                />
                            }
                            .into_any(),
                            Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
        </section>
    }
}

async fn load_webhooks(client: &ApiClient, organization: &str) -> Result<WebhookInventory, String> {
    let mut page_token = String::new();
    let mut seen = BTreeSet::new();
    let mut inventory = WebhookInventory::default();

    loop {
        let response = client
            .call::<_, aos_proto_types::ListWebhooksResponse>(
                aos_proto_types::WEBHOOK_SERVICE_LIST_WEBHOOKS_PATH,
                &aos_proto_types::ListWebhooksRequest {
                    org_slug: organization.to_string(),
                    page_size: 100,
                    page_token,
                },
            )
            .await
            .map_err(|failure| failure.to_string())?;
        inventory.webhooks.extend(response.webhooks);
        if inventory.event_types.is_empty() {
            inventory.event_types = response.supported_event_types;
        }
        if response.next_page_token.is_empty() {
            return Ok(inventory);
        }
        if !seen.insert(response.next_page_token.clone()) {
            return Err("the Hub repeated a webhook pagination token".to_string());
        }
        page_token = response.next_page_token;
    }
}

#[component]
fn WebhookList(client: ApiClient, webhooks: Vec<aos_proto_types::Webhook>) -> impl IntoView {
    if webhooks.is_empty() {
        return view! {
            <EmptyState
                title="No webhooks".to_string()
                detail="Create a signed subscription for registry and topology events.".to_string()
                action_label=None
                action=None
            />
        }
        .into_any();
    }

    view! {
        <div class="binding-list">
            {webhooks.into_iter().map(|webhook| view! {
                <WebhookCard client=client.clone() webhook=webhook/>
            }).collect_view()}
        </div>
    }
    .into_any()
}

#[component]
fn WebhookCard(client: ApiClient, webhook: aos_proto_types::Webhook) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let webhook_id = webhook.id;
    let version = webhook.resource_version.clone();

    let on_plan_delete = move |_| {
        let key = idempotency_key("webhook-delete");
        let request = aos_proto_types::PlanDeleteWebhookRequest {
            id: webhook_id,
            expected_resource_version: version.clone(),
            idempotency_key: key.clone(),
        };
        begin_plan(
            plan_client.clone(),
            aos_proto_types::WEBHOOK_SERVICE_PLAN_DELETE_WEBHOOK_PATH,
            request,
            key,
            pending,
            error,
            busy,
        );
    };
    let apply = apply_webhook::<aos_proto_types::DeleteTopologyResourceResponse>(
        client,
        aos_proto_types::WEBHOOK_SERVICE_DELETE_WEBHOOK_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{webhook.url}</strong><code>{webhook.id}</code></div>
                <StatusBadge
                    state=if webhook.active { "active" } else { "disabled" }.to_string()
                    positive=webhook.active
                />
            </div>
            <div class="resource-identity">
                <div><span>"Secret version"</span><code>{webhook.secret_version_ref}</code></div>
                <div><span>"Credential fingerprint"</span><code>{webhook.credential_fingerprint}</code></div>
                <div><span>"Created"</span><strong>{webhook.created_at}</strong></div>
                <div><span>"Version"</span><code>{webhook.resource_version}</code></div>
            </div>
            <details>
                <summary>"Subscribed events"</summary>
                {if webhook.events.is_empty() {
                    view! { <p>"All supported events"</p> }.into_any()
                } else {
                    view! {
                        <ul>{webhook.events.into_iter().map(|event| view! { <li><code>{event}</code></li> }).collect_view()}</ul>
                    }
                    .into_any()
                }}
            </details>
            <button
                class="danger-button"
                type="button"
                disabled=move || busy.get()
                on:click=on_plan_delete
            >
                "Review deletion"
            </button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <PlanReview pending=pending busy=busy on_apply=apply/>
        </article>
    }
}

#[component]
fn CreateWebhook(
    client: ApiClient,
    organization: String,
    event_types: Vec<String>,
) -> impl IntoView {
    let url = RwSignal::new(String::new());
    let secret_version_ref = RwSignal::new(String::new());
    let fingerprint = RwSignal::new(String::new());
    let selected = RwSignal::new(BTreeSet::<String>::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let url = match validate_webhook_url(&url.get_untracked()) {
            Ok(url) => url,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let fingerprint = fingerprint.get_untracked().trim().to_ascii_lowercase();
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            error.set(Some(
                "Credential fingerprint must be 64 hexadecimal SHA-256 characters".to_string(),
            ));
            return;
        }

        let key = idempotency_key("webhook-create");
        let request = aos_proto_types::PlanCreateWebhookRequest {
            org_slug: organization.clone(),
            url,
            events: selected.get_untracked().into_iter().collect(),
            idempotency_key: key.clone(),
            secret_version_ref: secret_version_ref.get_untracked().trim().to_string(),
            credential_fingerprint: fingerprint,
            expected_resource_version: String::new(),
        };
        begin_plan(
            plan_client.clone(),
            aos_proto_types::WEBHOOK_SERVICE_PLAN_CREATE_WEBHOOK_PATH,
            request,
            key,
            pending,
            error,
            busy,
        );
    };
    let apply = apply_webhook::<aos_proto_types::CreateWebhookResponse>(
        client,
        aos_proto_types::WEBHOOK_SERVICE_CREATE_WEBHOOK_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <section class="subworkflow">
            <h4>"Create webhook"</h4>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Public HTTP(S) destination"</span>
                    <input
                        required
                        type="url"
                        prop:value=move || url.get()
                        on:input=move |event| url.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"Immutable secret version reference"</span>
                    <input
                        required
                        prop:value=move || secret_version_ref.get()
                        on:input=move |event| secret_version_ref.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"Resolved secret SHA-256 fingerprint"</span>
                    <input
                        required
                        prop:value=move || fingerprint.get()
                        on:input=move |event| fingerprint.set(event_target_value(&event))
                    />
                </label>
                <fieldset>
                    <legend>"Event filter (none selected means all)"</legend>
                    <div class="checkbox-grid">
                        {event_types.into_iter().map(|event_type| {
                            let checked_event = event_type.clone();
                            let changed_event = event_type.clone();
                            view! {
                                <label class="checkbox-field">
                                    <input
                                        type="checkbox"
                                        prop:checked=move || selected.get().contains(&checked_event)
                                        on:change=move |event| {
                                            let mut values = selected.get_untracked();
                                            if event_target_checked(&event) {
                                                values.insert(changed_event.clone());
                                            } else {
                                                values.remove(&changed_event);
                                            }
                                            selected.set(values);
                                        }
                                    />
                                    <span>{event_type}</span>
                                </label>
                            }
                        }).collect_view()}
                    </div>
                </fieldset>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Review webhook"
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <PlanReview pending=pending busy=busy on_apply=apply/>
        </section>
    }
}

fn validate_webhook_url(value: &str) -> Result<String, String> {
    let parsed = leptos::web_sys::Url::new(value.trim())
        .map_err(|_| "Webhook destination is malformed".to_string())?;
    if !matches!(parsed.protocol().as_str(), "http:" | "https:")
        || parsed.host().is_empty()
        || !parsed.username().is_empty()
        || !parsed.password().is_empty()
        || !parsed.hash().is_empty()
    {
        return Err(
            "Webhook destination must be a public HTTP(S) URL without credentials or a fragment"
                .to_string(),
        );
    }
    Ok(parsed.href())
}

#[component]
fn OrganizationAudit(client: ApiClient, organization: String) -> impl IntoView {
    let audit = LocalResource::new(move || {
        let client = client.clone();
        let organization = organization.clone();
        async move {
            let response = client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_GET_ORGANIZATION_PATH,
                    &aos_proto_types::GetOrganizationRequest { slug: organization },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let scope = response
                .organization
                .map(|organization| organization.authorization_scope_key)
                .filter(|scope| !scope.is_empty())
                .ok_or_else(|| {
                    "the Hub omitted the organization authorization scope".to_string()
                })?;
            client
                .collect_pages::<_, aos_proto_types::ListAuditResponse, _, _, _>(
                    aos_proto_types::AUDIT_SERVICE_LIST_AUDIT_PATH,
                    move |page_token| aos_proto_types::ListAuditRequest {
                        scope: scope.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.entries, response.next_page_token),
                )
                .await
                .map_err(|failure| failure.to_string())
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Append-only history"</p>
                    <h2>"Audit log"</h2>
                    <p>"Entries link semantic changesets to signed Git history where applicable."</p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading audit history…"</p> }>
                {move || Suspend::new(async move {
                    match audit.await.as_ref() {
                        Ok(entries) if entries.is_empty() => view! {
                            <EmptyState
                                title="No audit entries".to_string()
                                detail="No retained control-plane activity has been recorded at this scope."
                                    .to_string()
                                action_label=None
                                action=None
                            />
                        }
                        .into_any(),
                        Ok(entries) => view! {
                            <div class="binding-list">
                                {entries.iter().cloned().map(|entry| view! {
                                    <AuditCard entry=entry/>
                                }).collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn AuditCard(entry: aos_proto_types::AuditEntry) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{entry.action}</strong><code>{entry.change_id}</code></div>
                <span>{entry.created_at}</span>
            </div>
            <div class="resource-identity">
                <div><span>"Actor"</span><strong>{entry.actor_label}</strong></div>
                <div><span>"Scope"</span><code>{entry.scope}</code></div>
                <div><span>"Result commit"</span><code>{display_or(&entry.result_commit, "none")}</code></div>
                <div><span>"Result tag"</span><code>{display_or(&entry.result_tag, "none")}</code></div>
            </div>
            {(!entry.detail.is_empty()).then(|| view! {
                <details><summary>"Detail"</summary><pre>{entry.detail}</pre></details>
            })}
        </article>
    }
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

fn apply_webhook<ResponseMessage>(
    client: ApiClient,
    path: &'static str,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()>
where
    ResponseMessage: serde::de::DeserializeOwned + 'static,
{
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        let request = aos_proto_types::ApplyWebhookMutationRequest {
            plan_id: reviewed.plan.plan_id,
            idempotency_key: reviewed.idempotency_key,
            confirmation_hash: reviewed.plan.confirmation_hash,
        };
        busy.set(true);

        spawn_local(async move {
            match client.call::<_, ResponseMessage>(path, &request).await {
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

fn reload() {
    crate::app::refresh();
}

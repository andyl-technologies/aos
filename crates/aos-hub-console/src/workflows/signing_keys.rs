//! Signing-key lifecycle and exact consumer-generation associations.
//!
//! The editor resolves immutable authorization and infrastructure-owner scopes
//! from typed resource responses. It never derives a scope from a mutable slug.
//! Public Ed25519 material may be enrolled or rotated; private key bytes remain
//! in external custody. Registry and cache consumers pin one exact generation
//! through a separately versioned usage association.

use std::collections::BTreeMap;

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{EmptyState, HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::{ApiClient, TransportError};

/// Identifies the resource whose signing settings are being edited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SigningKeyTarget {
    /// One organization slug.
    Organization(String),
    /// One registry path.
    Registry(String),
    /// One binary-cache public identifier.
    Cache(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SigningContext {
    authorization_scope: String,
    owner_scope: String,
    consumer: Option<SigningConsumer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SigningConsumer {
    stable_id: String,
    purpose: String,
    label: String,
}

/// Renders signing-key inventory, lifecycle controls, and consumer usage.
#[component]
pub(super) fn SigningKeyWorkflow(client: ApiClient, target: SigningKeyTarget) -> impl IntoView {
    let read_client = client.clone();
    let context = LocalResource::new(move || {
        let client = read_client.clone();
        let target = target.clone();
        async move { load_context(&client, target).await }
    });
    let view_client = client;

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving signing scopes…"</p> }>
            {move || {
                let client = view_client.clone();
                Suspend::new(async move {
                    match context.await.as_ref() {
                        Ok(context) => view! {
                            <SigningSettings client=client context=context.clone()/>
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

async fn load_context(
    client: &ApiClient,
    target: SigningKeyTarget,
) -> Result<SigningContext, String> {
    match target {
        SigningKeyTarget::Organization(slug) => {
            let response = client
                .call::<_, aos_proto_types::OrganizationResponse>(
                    aos_proto_types::ORGANIZATION_SERVICE_GET_ORGANIZATION_PATH,
                    &aos_proto_types::GetOrganizationRequest { slug },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let organization = response
                .organization
                .ok_or_else(|| "the Hub omitted the organization".to_string())?;
            require_scope(&organization.authorization_scope_key)?;
            Ok(SigningContext {
                authorization_scope: organization.authorization_scope_key.clone(),
                owner_scope: organization.authorization_scope_key,
                consumer: None,
            })
        }
        SigningKeyTarget::Registry(slug) => {
            let response = client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let registry = response
                .registry
                .ok_or_else(|| "the Hub omitted the registry".to_string())?;
            require_scope(&registry.authorization_scope_key)?;
            require_scope(&registry.owner_scope_key)?;
            Ok(SigningContext {
                authorization_scope: registry.authorization_scope_key,
                owner_scope: registry.owner_scope_key,
                consumer: Some(SigningConsumer {
                    stable_id: registry.stable_id,
                    purpose: "registry_publication".to_string(),
                    label: "Registry publication".to_string(),
                }),
            })
        }
        SigningKeyTarget::Cache(cache_id) => {
            let response = client
                .call::<_, aos_proto_types::BinaryCacheResponse>(
                    aos_proto_types::BINARY_CACHE_SERVICE_GET_BINARY_CACHE_PATH,
                    &aos_proto_types::GetBinaryCacheRequest { cache_id },
                )
                .await
                .map_err(|failure| failure.to_string())?;
            let cache = response
                .cache
                .ok_or_else(|| "the Hub omitted the binary cache".to_string())?;
            require_scope(&cache.authorization_scope_key)?;
            require_scope(&cache.owner_scope_key)?;
            Ok(SigningContext {
                authorization_scope: cache.authorization_scope_key,
                owner_scope: cache.owner_scope_key,
                consumer: Some(SigningConsumer {
                    stable_id: cache.stable_id,
                    purpose: "narinfo".to_string(),
                    label: "NAR metadata".to_string(),
                }),
            })
        }
    }
}

fn require_scope(value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err("the Hub omitted an immutable authorization scope".to_string())
    } else {
        Ok(())
    }
}

#[component]
fn SigningSettings(client: ApiClient, context: SigningContext) -> impl IntoView {
    let keys = signing_keys_resource(client.clone(), context.clone());

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading">
                    <div>
                        <p class="section-kicker">"External custody"</p>
                        <h2>"Signing keys"</h2>
                        <p>
                            "Only public Ed25519 generations are stored. "
                            "Existing consumers remain pinned during rotation."
                        </p>
                    </div>
                </div>
                <div class="resource-identity">
                    <div>
                        <span>"Resource scope"</span>
                        <code>{context.authorization_scope.clone()}</code>
                    </div>
                    <div>
                        <span>"Infrastructure owner"</span>
                        <code>{context.owner_scope.clone()}</code>
                    </div>
                </div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading signing keys…"</p> }>
                    {move || {
                        let client = client.clone();
                        let context = context.clone();
                        Suspend::new(async move {
                            match keys.await.as_ref() {
                                Ok(keys) => view! {
                                    <SigningKeyInventory keys=keys.clone()/>
                                    {client.allows("keys.manage").then(|| view! {
                                        <details class="advanced-controls"><summary>"Enroll a public signing key"</summary>
                                            <EnrollKey client=client.clone() context=context.clone()/>
                                        </details>
                                        <details class="advanced-controls"><summary>"Rotate or retire a key"</summary>
                                            <KeyLifecycle client=client.clone() keys=keys.clone()/>
                                        </details>
                                    })}
                                    {context.consumer.clone().map(|consumer| view! {
                                        <SigningUsage
                                            client=client
                                            consumer=consumer
                                            keys=keys.clone()
                                        />
                                    })}
                                }
                                .into_any(),
                                Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
        </div>
    }
}

fn signing_keys_resource(
    client: ApiClient,
    context: SigningContext,
) -> LocalResource<Result<Vec<aos_proto_types::SigningKey>, String>> {
    LocalResource::new(move || {
        let client = client.clone();
        let context = context.clone();
        async move {
            let mut scopes = vec![context.authorization_scope];
            if context.owner_scope != scopes[0] {
                scopes.push(context.owner_scope);
            }

            let mut keys = BTreeMap::new();
            for scope in scopes {
                let page = client
                    .collect_pages::<_, aos_proto_types::ListSigningKeysResponse, _, _, _>(
                        aos_proto_types::SIGNING_KEY_SERVICE_LIST_SIGNING_KEYS_PATH,
                        move |page_token| aos_proto_types::ListSigningKeysRequest {
                            scope_key: scope.clone(),
                            page_size: 100,
                            page_token,
                        },
                        |response| (response.signing_keys, response.next_page_token),
                    )
                    .await
                    .map_err(|failure| failure.to_string())?;
                for key in page {
                    keys.insert(key.stable_id.clone(), key);
                }
            }
            Ok(keys.into_values().collect())
        }
    })
}

#[component]
fn SigningKeyInventory(keys: Vec<aos_proto_types::SigningKey>) -> impl IntoView {
    if keys.is_empty() {
        return view! {
            <EmptyState
                title="No signing keys".to_string()
                detail="Enroll public verification material before attaching a signing usage."
                    .to_string()
                action_label=None
                action=None
            />
        }
        .into_any();
    }

    view! {
        <div class="binding-list">
            {keys
                .into_iter()
                .map(|key| view! { <SigningKeyCard signing_key=key/> })
                .collect_view()}
        </div>
    }
    .into_any()
}

#[component]
fn SigningKeyCard(signing_key: aos_proto_types::SigningKey) -> impl IntoView {
    let generation = signing_key.latest_generation.unwrap_or_default();

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{signing_key.name}</strong>
                    <code>{signing_key.stable_id}</code>
                </div>
                <StatusBadge
                    state=generation.state.clone()
                    positive=generation.state == "active"
                />
            </div>
            <div class="resource-identity">
                <div>
                    <span>"Owner scope"</span>
                    <code>{signing_key.scope_key}</code>
                </div>
                <div>
                    <span>"Generation"</span>
                    <strong>{generation.generation}</strong>
                </div>
                <div>
                    <span>"Algorithm"</span>
                    <strong>{generation.algorithm}</strong>
                </div>
                <div>
                    <span>"Custody"</span>
                    <strong>{generation.custody}</strong>
                </div>
                <div>
                    <span>"Fingerprint"</span>
                    <HashValue value=generation.public_key_fingerprint/>
                </div>
                <div>
                    <span>"Version"</span>
                    <code>{signing_key.resource_version}</code>
                </div>
            </div>
            <details>
                <summary>"Public key"</summary>
                <code>{generation.public_key}</code>
            </details>
        </article>
    }
}

#[component]
fn EnrollKey(client: ApiClient, context: SigningContext) -> impl IntoView {
    let scope = RwSignal::new(context.authorization_scope.clone());
    let name = RwSignal::new(String::new());
    let public_key = RwSignal::new(String::new());
    let fingerprint = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let key = idempotency_key("signing-key-enroll");
        let request = aos_proto_types::PlanSigningKeyMutationRequest {
            scope_key: scope.get_untracked(),
            name: name.get_untracked().trim().to_string(),
            public_key: public_key.get_untracked().trim().to_string(),
            public_key_fingerprint: fingerprint.get_untracked().trim().to_string(),
            custody: "external".to_string(),
            expected_resource_version: String::new(),
            idempotency_key: key.clone(),
        };
        begin_plan(
            plan_client.clone(),
            aos_proto_types::SIGNING_KEY_SERVICE_PLAN_ENROLL_SIGNING_KEY_PATH,
            request,
            key,
            pending,
            error,
            busy,
        );
    };
    let apply = apply::<aos_proto_types::SigningKeyResponse>(
        client,
        aos_proto_types::SIGNING_KEY_SERVICE_ENROLL_SIGNING_KEY_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <section class="subworkflow">
            <h4>"Enroll public key"</h4>
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Owning scope"</span>
                    <select
                        prop:value=move || scope.get()
                        on:change=move |event| scope.set(event_target_value(&event))
                    >
                        <option value=context.authorization_scope.clone()>"Resource scope"</option>
                        {(context.owner_scope != context.authorization_scope).then(|| view! {
                            <option value=context.owner_scope>"Infrastructure owner scope"</option>
                        })}
                    </select>
                </label>
                <label>
                    <span>"Stable name"</span>
                    <input
                        required
                        prop:value=move || name.get()
                        on:input=move |event| name.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"Canonical unpadded-base64 Ed25519 public key"</span>
                    <textarea
                        required
                        prop:value=move || public_key.get()
                        on:input=move |event| public_key.set(event_target_value(&event))
                    ></textarea>
                </label>
                <label>
                    <span>"SHA-256 fingerprint of public-key bytes"</span>
                    <input
                        required
                        prop:value=move || fingerprint.get()
                        on:input=move |event| fingerprint.set(event_target_value(&event))
                    />
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Review enrollment"
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <PlanReview pending=pending busy=busy on_apply=apply/>
        </section>
    }
}

#[component]
fn KeyLifecycle(client: ApiClient, keys: Vec<aos_proto_types::SigningKey>) -> impl IntoView {
    let can_manage = client.allows("keys.manage");
    let active = keys
        .into_iter()
        .filter(|key| {
            key.latest_generation
                .as_ref()
                .is_some_and(|generation| generation.state == "active")
        })
        .collect::<Vec<_>>();
    if active.is_empty() {
        return view! { <p class="muted">"No active signing-key head can be rotated or retired."</p> }
            .into_any();
    }

    let selected = RwSignal::new(active[0].stable_id.clone());
    let public_key = RwSignal::new(String::new());
    let fingerprint = RwSignal::new(String::new());
    let rotate_pending = RwSignal::new(None::<PendingPlan>);
    let retire_pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let rotate_client = client.clone();
    let rotate_keys = active.clone();
    let on_plan_rotate = move |event: SubmitEvent| {
        event.prevent_default();
        let Some(current) = selected_key(&rotate_keys, &selected.get_untracked()) else {
            error.set(Some("Select an active signing key".to_string()));
            return;
        };
        let key = idempotency_key("signing-key-rotate");
        let request = aos_proto_types::PlanSigningKeyMutationRequest {
            scope_key: current.scope_key.clone(),
            name: current.name.clone(),
            public_key: public_key.get_untracked().trim().to_string(),
            public_key_fingerprint: fingerprint.get_untracked().trim().to_string(),
            custody: "external".to_string(),
            expected_resource_version: current.resource_version.clone(),
            idempotency_key: key.clone(),
        };
        retire_pending.set(None);
        begin_plan(
            rotate_client.clone(),
            aos_proto_types::SIGNING_KEY_SERVICE_PLAN_ROTATE_SIGNING_KEY_PATH,
            request,
            key,
            rotate_pending,
            error,
            busy,
        );
    };

    let retire_client = client.clone();
    let retire_keys = active.clone();
    let on_plan_retire = move |_| {
        let Some(current) = selected_key(&retire_keys, &selected.get_untracked()) else {
            error.set(Some("Select an active signing key".to_string()));
            return;
        };
        let key = idempotency_key("signing-key-retire");
        let request = aos_proto_types::PlanRetireSigningKeyRequest {
            scope_key: current.scope_key.clone(),
            name: current.name.clone(),
            expected_resource_version: current.resource_version.clone(),
            idempotency_key: key.clone(),
        };
        rotate_pending.set(None);
        begin_plan(
            retire_client.clone(),
            aos_proto_types::SIGNING_KEY_SERVICE_PLAN_RETIRE_SIGNING_KEY_PATH,
            request,
            key,
            retire_pending,
            error,
            busy,
        );
    };

    let apply_rotate = apply::<aos_proto_types::SigningKeyResponse>(
        client.clone(),
        aos_proto_types::SIGNING_KEY_SERVICE_ROTATE_SIGNING_KEY_PATH,
        rotate_pending,
        error,
        busy,
    );
    let apply_retire = apply::<aos_proto_types::SigningKeyResponse>(
        client,
        aos_proto_types::SIGNING_KEY_SERVICE_RETIRE_SIGNING_KEY_PATH,
        retire_pending,
        error,
        busy,
    );

    view! {
        <section class="subworkflow">
            <h4>"Rotate or retire key"</h4>
            <label>
                <span>"Active key"</span>
                <select
                    prop:value=move || selected.get()
                    on:change=move |event| selected.set(event_target_value(&event))
                >
                    {active.into_iter().map(|key| view! {
                        <option value=key.stable_id>{format!("{} · {}", key.name, key.scope_key)}</option>
                    }).collect_view()}
                </select>
            </label>
            <form class="editor-form" on:submit=on_plan_rotate>
                <label>
                    <span>"Successor public key"</span>
                    <textarea
                        required
                        prop:value=move || public_key.get()
                        on:input=move |event| public_key.set(event_target_value(&event))
                    ></textarea>
                </label>
                <label>
                    <span>"Successor SHA-256 fingerprint"</span>
                    <input
                        required
                        prop:value=move || fingerprint.get()
                        on:input=move |event| fingerprint.set(event_target_value(&event))
                    />
                </label>
                <div class="form-actions">
                    <button class="secondary-button" type="submit" disabled=move || busy.get()>
                        "Review rotation"
                    </button>
                    <button
                        class="danger-button"
                        type="button"
                        disabled=move || busy.get()
                        on:click=on_plan_retire
                    >
                        "Review retirement"
                    </button>
                </div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            <PlanReview pending=rotate_pending busy=busy on_apply=apply_rotate/>
            <PlanReview pending=retire_pending busy=busy on_apply=apply_retire/>
        </section>
    }
    .into_any()
}

fn selected_key<'a>(
    keys: &'a [aos_proto_types::SigningKey],
    stable_id: &str,
) -> Option<&'a aos_proto_types::SigningKey> {
    keys.iter().find(|key| key.stable_id == stable_id)
}

#[component]
fn SigningUsage(
    client: ApiClient,
    consumer: SigningConsumer,
    keys: Vec<aos_proto_types::SigningKey>,
) -> impl IntoView {
    let read_client = client.clone();
    let read_consumer = consumer.clone();
    let usage = LocalResource::new(move || {
        let client = read_client.clone();
        let consumer = read_consumer.clone();
        async move {
            match client
                .call::<_, aos_proto_types::SigningKeyUsageResponse>(
                    aos_proto_types::SIGNING_KEY_SERVICE_GET_SIGNING_KEY_USAGE_PATH,
                    &aos_proto_types::GetSigningKeyUsageRequest {
                        consumer_stable_id: consumer.stable_id,
                        purpose: consumer.purpose,
                    },
                )
                .await
            {
                Ok(response) => Ok(response.usage),
                Err(TransportError::Http { status: 404, .. }) => Ok(None),
                Err(failure) => Err(failure.to_string()),
            }
        }
    });

    view! {
        <section class="subworkflow">
            <h4>{consumer.label.clone()}</h4>
            <p>"The consumer pins one exact immutable generation; key rotation never moves it implicitly."</p>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading signing usage…"</p> }>
                {move || {
                    let client = client.clone();
                    let consumer = consumer.clone();
                    let keys = keys.clone();
                    Suspend::new(async move {
                        match usage.await.as_ref() {
                            Ok(current) => view! {
                                <SigningUsageEditor
                                    client=client
                                    consumer=consumer
                                    keys=keys
                                    current=current.clone()
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

#[component]
fn SigningUsageEditor(
    client: ApiClient,
    consumer: SigningConsumer,
    keys: Vec<aos_proto_types::SigningKey>,
    current: Option<aos_proto_types::SigningKeyUsage>,
) -> impl IntoView {
    let can_manage = client.allows("keys.manage");
    let active = keys
        .into_iter()
        .filter(|key| {
            key.latest_generation
                .as_ref()
                .is_some_and(|generation| generation.state == "active")
        })
        .collect::<Vec<_>>();
    let initial = current
        .as_ref()
        .map(|usage| usage.signing_key_stable_id.clone())
        .filter(|stable_id| active.iter().any(|key| key.stable_id == *stable_id))
        .or_else(|| active.first().map(|key| key.stable_id.clone()))
        .unwrap_or_default();
    let selected = RwSignal::new(initial);
    let state = RwSignal::new(
        current
            .as_ref()
            .map(|usage| usage.state.clone())
            .unwrap_or_else(|| "active".to_string()),
    );
    let expected_version = current
        .as_ref()
        .map(|usage| usage.resource_version.clone())
        .unwrap_or_else(|| "absent".to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_keys = active.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let Some(key_head) = selected_key(&plan_keys, &selected.get_untracked()) else {
            error.set(Some("Select an active signing-key generation".to_string()));
            return;
        };
        let Some(generation) = key_head.latest_generation.as_ref() else {
            error.set(Some(
                "The selected key omitted its active generation".to_string(),
            ));
            return;
        };
        let key = idempotency_key("signing-key-usage");
        let request = aos_proto_types::PlanSigningKeyUsageRequest {
            consumer_stable_id: consumer.stable_id.clone(),
            purpose: consumer.purpose.clone(),
            signing_key_stable_id: key_head.stable_id.clone(),
            signing_key_generation: generation.generation,
            state: state.get_untracked(),
            expected_resource_version: expected_version.clone(),
            idempotency_key: key.clone(),
        };
        begin_plan(
            plan_client.clone(),
            aos_proto_types::SIGNING_KEY_SERVICE_PLAN_SET_SIGNING_KEY_USAGE_PATH,
            request,
            key,
            pending,
            error,
            busy,
        );
    };
    let apply = apply::<aos_proto_types::SigningKeyUsageResponse>(
        client,
        aos_proto_types::SIGNING_KEY_SERVICE_SET_SIGNING_KEY_USAGE_PATH,
        pending,
        error,
        busy,
    );

    view! {
        {current.clone().map(|usage| view! {
            <div class="resource-identity">
                <div><span>"State"</span><StatusBadge state=usage.state.clone() positive=usage.state == "active"/></div>
                <div><span>"Key"</span><code>{usage.signing_key_stable_id}</code></div>
                <div><span>"Generation"</span><strong>{usage.signing_key_generation}</strong></div>
                <div><span>"Version"</span><code>{usage.resource_version}</code></div>
            </div>
        })}
        {(active.is_empty()).then(|| view! {
            <p class="muted">
                "Enroll an active compatible signing key before attaching this usage."
            </p>
        })}
        {(can_manage && !active.is_empty()).then(|| view! {
            <form class="editor-form" on:submit=on_plan>
                <label>
                    <span>"Signing-key generation"</span>
                    <select
                        prop:value=move || selected.get()
                        on:change=move |event| selected.set(event_target_value(&event))
                    >
                        {active.into_iter().map(|key| {
                            let generation = key.latest_generation.unwrap_or_default();
                            view! {
                                <option value=key.stable_id>
                                    {format!(
                                        "{} · generation {} · {}",
                                        key.name,
                                        generation.generation,
                                        key.scope_key,
                                    )}
                                </option>
                            }
                        }).collect_view()}
                    </select>
                </label>
                <label>
                    <span>"Association state"</span>
                    <select
                        prop:value=move || state.get()
                        on:change=move |event| state.set(event_target_value(&event))
                    >
                        <option value="active">"Active"</option>
                        <option value="detached" disabled=current.is_none()>"Detached"</option>
                    </select>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Review signing usage"
                </button>
            </form>
        })}
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        <PlanReview pending=pending busy=busy on_apply=apply/>
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

fn apply<ResponseMessage>(
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
        busy.set(true);

        spawn_local(async move {
            match client
                .call::<_, ResponseMessage>(path, &reviewed.topology_apply())
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

fn reload() {
    crate::app::refresh();
}

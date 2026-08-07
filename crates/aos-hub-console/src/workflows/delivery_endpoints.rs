//! Delivery-endpoint identity, generation, health, and grant workflows.
//!
//! Endpoint scheme/host/port identity is stable. Listener, TLS, probe, and
//! boundary-revision intent advances through staged immutable generations.

use std::net::IpAddr;
use std::str::FromStr;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::organization_scope::organization_authorization_scope;
use super::storage_gateways::StorageGatewayWorkflow;

/// Renders endpoint workflows and delegates unrelated pages onward.
#[component]
pub(super) fn DeliveryEndpointWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "endpoints") => view! {
            <DeliveryEndpoints client=client owner_scope_key="instance".to_string()/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "endpoints") => view! {
            <OrganizationDeliveryEndpoints client=client organization=slug.clone()/>
        }
        .into_any(),
        _ => view! { <StorageGatewayWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn OrganizationDeliveryEndpoints(client: ApiClient, organization: String) -> impl IntoView {
    let resolve_client = client.clone();
    let scope = LocalResource::new(move || {
        let client = resolve_client.clone();
        let slug = organization.clone();
        async move { organization_authorization_scope(&client, slug).await }
    });

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving organization scope…"</p> }>
            {move || {
                let client = client.clone();
                Suspend::new(async move {
                    match scope.await.as_ref() {
                        Ok(owner_scope_key) => view! {
                            <DeliveryEndpoints client=client owner_scope_key=owner_scope_key.clone()/>
                        }
                        .into_any(),
                        Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
fn DeliveryEndpoints(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let list_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListDeliveryEndpointsResponse, _, _, _>(
                    aos_proto_types::DELIVERY_SERVICE_LIST_DELIVERY_ENDPOINTS_PATH,
                    move |page_token| aos_proto_types::ListTopologyResourcesRequest {
                        owner_scope_key: owner_scope_key.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.delivery_endpoints, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    view! { <div class="workflow-stack"><section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Client ingress"</p><h2>"Delivery endpoints"</h2><p>"Endpoints bind one stable host identity to exact network-boundary and listener/TLS generations."</p></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading delivery endpoints…"</p> }>{move || { let client = view_client.clone(); Suspend::new(async move { match inventory.await.as_ref() { Ok(endpoints) if endpoints.is_empty() => view! { <p class="muted">"No delivery endpoints in this scope."</p> }.into_any(), Ok(endpoints) => view! { <div class="binding-list">{endpoints.iter().cloned().map(|endpoint| view! { <DeliveryEndpointCard client=client.clone() endpoint=endpoint/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section><DeliveryEndpointCreate client=client owner_scope_key=owner_scope_key/></div> }
}

#[derive(Clone, Debug)]
struct EndpointRevisionDraft {
    boundary_revision: i64,
    ingress_kind: i32,
    listener_ref: String,
    tls: aos_proto_types::TlsConfiguration,
    probe_ref: String,
}

#[component]
fn DeliveryEndpointCreate(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let stable_id = RwSignal::new(String::new());
    let scheme = RwSignal::new("https".to_string());
    let host_kind = RwSignal::new("domain".to_string());
    let host = RwSignal::new(String::new());
    let port = RwSignal::new("443".to_string());
    let boundary_id = RwSignal::new(String::new());
    let boundary_revision = RwSignal::new(String::new());
    let ingress = RwSignal::new("hub".to_string());
    let listener_ref = RwSignal::new(String::new());
    let tls_provider = RwSignal::new("hub".to_string());
    let certificate_ref = RwSignal::new(String::new());
    let require_client_certificate = RwSignal::new(false);
    let probe_ref = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let endpoint_host = match endpoint_host(&host_kind.get_untracked(), &host.get_untracked()) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let effective_port = match port.get_untracked().parse::<u32>() {
            Ok(value) if (1..=65535).contains(&value) => value,
            _ => {
                error.set(Some(
                    "Endpoint port must be between 1 and 65535".to_string(),
                ));
                return;
            }
        };
        let revision = match endpoint_revision(
            &boundary_revision.get_untracked(),
            &ingress.get_untracked(),
            &listener_ref.get_untracked(),
            &tls_provider.get_untracked(),
            &certificate_ref.get_untracked(),
            require_client_certificate.get_untracked(),
            &probe_ref.get_untracked(),
        ) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("endpoint-create");
        let request = aos_proto_types::PlanDeliveryEndpointMutationRequest {
            stable_id: stable_id.get_untracked().trim().to_string(),
            owner_scope_key: owner_scope_key.clone(),
            scheme: scheme.get_untracked(),
            host: Some(endpoint_host),
            effective_port,
            network_boundary_id: boundary_id.get_untracked().trim().to_string(),
            revision: Some(revision_message(revision)),
            carry_forward_consumer_scopes: Vec::new(),
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
            update_mask: vec!["identity".into(), "revision".into()],
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_CREATE_DELIVERY_ENDPOINT_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeliveryEndpointResponse>(
                    aos_proto_types::DELIVERY_SERVICE_CREATE_DELIVERY_ENDPOINT_PATH,
                    &reviewed.delivery_endpoint_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><h2>"Create delivery endpoint"</h2><form class="editor-form" on:submit=on_plan><label><span>"Stable ID"</span><input required prop:value=move || stable_id.get() on:input=move |event| stable_id.set(event_target_value(&event))/></label><label><span>"Scheme"</span><select prop:value=move || scheme.get() on:change=move |event| scheme.set(event_target_value(&event))><option value="https">"HTTPS"</option><option value="http">"HTTP"</option></select></label><label><span>"Host kind"</span><select prop:value=move || host_kind.get() on:change=move |event| host_kind.set(event_target_value(&event))><option value="domain">"Managed domain ID"</option><option value="ipv4">"IPv4 address"</option><option value="ipv6">"IPv6 address"</option></select></label><label><span>"Host value"</span><input required prop:value=move || host.get() on:input=move |event| host.set(event_target_value(&event))/></label><label><span>"Port"</span><input required type="number" min="1" max="65535" prop:value=move || port.get() on:input=move |event| port.set(event_target_value(&event))/></label><label><span>"Network boundary stable ID"</span><input required prop:value=move || boundary_id.get() on:input=move |event| boundary_id.set(event_target_value(&event))/></label><EndpointRevisionFields boundary_revision=boundary_revision ingress=ingress listener_ref=listener_ref tls_provider=tls_provider certificate_ref=certificate_ref require_client_certificate=require_client_certificate probe_ref=probe_ref/><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn EndpointRevisionFields(
    boundary_revision: RwSignal<String>,
    ingress: RwSignal<String>,
    listener_ref: RwSignal<String>,
    tls_provider: RwSignal<String>,
    certificate_ref: RwSignal<String>,
    require_client_certificate: RwSignal<bool>,
    probe_ref: RwSignal<String>,
) -> impl IntoView {
    view! { <label><span>"Boundary revision"</span><input required type="number" min="1" prop:value=move || boundary_revision.get() on:input=move |event| boundary_revision.set(event_target_value(&event))/></label><label><span>"Ingress kind"</span><select prop:value=move || ingress.get() on:change=move |event| ingress.set(event_target_value(&event))><option value="hub">"AOS Hub"</option><option value="external">"External ingress"</option><option value="layer7">"Layer 7 provider"</option></select></label><label><span>"Listener configuration reference"</span><input required prop:value=move || listener_ref.get() on:input=move |event| listener_ref.set(event_target_value(&event))/></label><label><span>"TLS provider"</span><input required prop:value=move || tls_provider.get() on:input=move |event| tls_provider.set(event_target_value(&event))/></label><label><span>"Certificate reference"</span><input required prop:value=move || certificate_ref.get() on:input=move |event| certificate_ref.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || require_client_certificate.get() on:change=move |event| require_client_certificate.set(event_target_checked(&event))/><span>"Require client certificate"</span></label><label class="full-field"><span>"Probe configuration reference"</span><input prop:value=move || probe_ref.get() on:input=move |event| probe_ref.set(event_target_value(&event))/></label> }
}

#[component]
fn DeliveryEndpointCard(
    client: ApiClient,
    endpoint: aos_proto_types::DeliveryEndpoint,
) -> impl IntoView {
    let observed = endpoint.observed.clone().unwrap_or_default();
    let identity = endpoint_identity(&endpoint);
    let positive = observed.state == "ready" && observed.listener_observed && observed.tls_observed;
    view! { <details class="binding-card"><summary><div><span class="resource-kind">{endpoint.scheme.clone()}</span><h3>{identity}</h3><code>{endpoint.stable_id.clone()}</code></div><div class="binding-summary-state"><StatusBadge state=if observed.state.is_empty() { "unknown".to_string() } else { observed.state.clone() } positive=positive/></div></summary><div class="binding-details"><div class="resource-identity"><div><span>"Boundary"</span><code>{format!("{}@{}", endpoint.network_boundary_id, endpoint.desired.as_ref().map(|value| value.boundary_revision).unwrap_or_default())}</code></div><div><span>"Desired generation"</span><strong>{endpoint.desired_generation}</strong></div><div><span>"Observed generation"</span><strong>{observed.observed_generation}</strong></div><div><span>"Version"</span><code>{endpoint.resource_version.clone()}</code></div></div>{(!observed.error.is_empty()).then(|| view! { <InlineError detail=observed.error/> })}<EndpointGenerations client=client.clone() endpoint=endpoint.clone()/><div class="subworkflow-grid"><EndpointStage client=client.clone() endpoint=endpoint.clone()/><EndpointGrants client=client.clone() endpoint=endpoint.clone()/></div><EndpointDelete client=client endpoint=endpoint/></div></details> }
}

#[component]
fn EndpointGenerations(
    client: ApiClient,
    endpoint: aos_proto_types::DeliveryEndpoint,
) -> impl IntoView {
    let endpoint_id = endpoint.stable_id;
    let endpoint_version = endpoint.resource_version;
    let read_client = client.clone();
    let generations = LocalResource::new(move || {
        let client = read_client.clone();
        let endpoint_id = endpoint_id.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListDeliveryEndpointGenerationsResponse>(
                    aos_proto_types::DELIVERY_SERVICE_LIST_DELIVERY_ENDPOINT_GENERATIONS_PATH,
                    &aos_proto_types::ListDeliveryEndpointGenerationsRequest {
                        endpoint_id,
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
        }
    });
    view! { <section class="subworkflow"><h4>"Endpoint generations"</h4><Suspense fallback=move || view! { <p class="loading-row">"Loading generations…"</p> }>{move || { let client = client.clone(); let endpoint_version = endpoint_version.clone(); Suspend::new(async move { match generations.await.as_ref() { Ok(response) => view! { <div class="compact-list">{response.generations.iter().cloned().map(|generation| view! { <EndpointGenerationRow client=client.clone() generation=generation endpoint_version=endpoint_version.clone()/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section> }
}

#[component]
fn EndpointGenerationRow(
    client: ApiClient,
    generation: aos_proto_types::DeliveryEndpointGeneration,
    endpoint_version: String,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let request_generation = generation.clone();
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("endpoint-activate");
        let request = aos_proto_types::PlanActivateDeliveryEndpointGenerationRequest {
            endpoint_id: request_generation.endpoint_id.clone(),
            generation: request_generation.generation,
            expected_resource_version: endpoint_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client.call::<_, aos_proto_types::TopologyPlanResponse>(aos_proto_types::DELIVERY_SERVICE_PLAN_ACTIVATE_DELIVERY_ENDPOINT_GENERATION_PATH, &request).await.map_err(|failure| failure.to_string()).and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeliveryEndpointGenerationResponse>(
                    aos_proto_types::DELIVERY_SERVICE_ACTIVATE_DELIVERY_ENDPOINT_GENERATION_PATH,
                    &reviewed.delivery_endpoint_generation_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <div class="revision-card"><div class="compact-list-row"><div><strong>{format!("Generation {}", generation.generation)}</strong><span>{format!("boundary revision {}", generation.desired.as_ref().map(|value| value.boundary_revision).unwrap_or_default())}</span><code>{generation.content_digest}</code></div>{if generation.selected { view! { <StatusBadge state="selected".to_string() positive=true/> }.into_any() } else { view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review activation"</button> }.into_any() }}</div>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</div> }
}

#[component]
fn EndpointStage(client: ApiClient, endpoint: aos_proto_types::DeliveryEndpoint) -> impl IntoView {
    let desired = endpoint.desired.clone().unwrap_or_default();
    let boundary_revision = RwSignal::new(desired.boundary_revision.to_string());
    let ingress = RwSignal::new(ingress_name(desired.ingress_kind).to_string());
    let listener_ref = RwSignal::new(desired.listener_configuration_ref);
    let tls = desired.tls.unwrap_or_default();
    let tls_provider = RwSignal::new(tls.provider);
    let certificate_ref = RwSignal::new(tls.certificate_ref);
    let require_client_certificate = RwSignal::new(tls.require_client_certificate);
    let probe_ref = RwSignal::new(desired.probe_configuration_ref);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let endpoint_id = endpoint.stable_id;
    let version = endpoint.resource_version;
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let revision = match endpoint_revision(
            &boundary_revision.get_untracked(),
            &ingress.get_untracked(),
            &listener_ref.get_untracked(),
            &tls_provider.get_untracked(),
            &certificate_ref.get_untracked(),
            require_client_certificate.get_untracked(),
            &probe_ref.get_untracked(),
        ) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("endpoint-stage");
        let request = aos_proto_types::PlanStageDeliveryEndpointGenerationRequest {
            endpoint_id: endpoint_id.clone(),
            revision: Some(revision_message(revision)),
            carry_forward_consumer_scopes: Vec::new(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            update_mask: vec!["revision".into()],
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_STAGE_DELIVERY_ENDPOINT_GENERATION_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeliveryEndpointGenerationResponse>(
                    aos_proto_types::DELIVERY_SERVICE_STAGE_DELIVERY_ENDPOINT_GENERATION_PATH,
                    &reviewed.delivery_endpoint_generation_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow"><h4>"Stage generation"</h4><form class="stacked-form" on:submit=on_plan><EndpointRevisionFields boundary_revision=boundary_revision ingress=ingress listener_ref=listener_ref tls_provider=tls_provider certificate_ref=certificate_ref require_client_certificate=require_client_certificate probe_ref=probe_ref/><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review generation"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn EndpointGrants(client: ApiClient, endpoint: aos_proto_types::DeliveryEndpoint) -> impl IntoView {
    let scope = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let endpoint_id = endpoint.stable_id.clone();
    let generation = endpoint.desired_generation;
    let version = endpoint.resource_version;
    let plan_client = client.clone();
    let row_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("endpoint-grant");
        let request = grant_request(
            &endpoint_id,
            generation,
            &scope.get_untracked(),
            &version,
            idempotency_key.clone(),
        );
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_GRANT_DELIVERY_ENDPOINT_SCOPE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ConsumerScopeGrantResponse>(
                    aos_proto_types::DELIVERY_SERVICE_GRANT_DELIVERY_ENDPOINT_SCOPE_PATH,
                    &reviewed.consumer_grant_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow"><h4>"Consumer scopes"</h4><div class="compact-list">{endpoint.grants.into_iter().filter(|grant| grant.state == "active").map(|grant| view! { <EndpointGrantRow client=row_client.clone() grant=grant/> }).collect_view()}</div><form class="stacked-form" on:submit=on_plan><label><span>"Consumer scope key"</span><input required prop:value=move || scope.get() on:input=move |event| scope.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review grant"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn EndpointGrantRow(
    client: ApiClient,
    grant: aos_proto_types::ConsumerScopeGrant,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let request_grant = grant.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("endpoint-revoke");
        let request = grant_request(
            &request_grant.resource_stable_id,
            request_grant.resource_generation,
            &request_grant.consumer_scope_key,
            &request_grant.resource_version,
            idempotency_key.clone(),
        );
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_REVOKE_DELIVERY_ENDPOINT_SCOPE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::ConsumerScopeGrantResponse>(
                    aos_proto_types::DELIVERY_SERVICE_REVOKE_DELIVERY_ENDPOINT_SCOPE_PATH,
                    &reviewed.consumer_grant_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <div class="compact-list-row"><div><code>{grant.consumer_scope_key}</code><span>{format!("generation {} · {} live pins", grant.resource_generation, grant.live_pin_count)}</span></div><button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review revoke"</button></div>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} }
}

#[component]
fn EndpointDelete(client: ApiClient, endpoint: aos_proto_types::DeliveryEndpoint) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = endpoint.stable_id;
    let version = endpoint.resource_version;
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("endpoint-delete");
        let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.clone(),
            expected_resource_version: Some(version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_DELETE_DELIVERY_ENDPOINT_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                    aos_proto_types::DELIVERY_SERVICE_DELETE_DELIVERY_ENDPOINT_PATH,
                    &reviewed.delete_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow danger-subworkflow"><h4>"Delete endpoint"</h4><p>"Deletion remains blocked by routes, defaults, gateways, grants, and live generation pins."</p><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review deletion"</button>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

fn endpoint_host(kind: &str, value: &str) -> Result<aos_proto_types::EndpointHost, String> {
    use aos_proto_types::endpoint_host::Host;
    let host = match kind {
        "domain" if !value.trim().is_empty() => Host::DomainId(value.trim().to_string()),
        "ipv4" => match IpAddr::from_str(value.trim())
            .map_err(|_| "Host is not a valid IPv4 address".to_string())?
        {
            IpAddr::V4(address) => Host::Ipv4(address.octets().to_vec()),
            IpAddr::V6(_) => return Err("Host is not an IPv4 address".to_string()),
        },
        "ipv6" => match IpAddr::from_str(value.trim())
            .map_err(|_| "Host is not a valid IPv6 address".to_string())?
        {
            IpAddr::V6(address) => Host::Ipv6(address.octets().to_vec()),
            IpAddr::V4(_) => return Err("Host is not an IPv6 address".to_string()),
        },
        "domain" => return Err("Managed domain ID is required".to_string()),
        _ => return Err("Unsupported endpoint host kind".to_string()),
    };
    Ok(aos_proto_types::EndpointHost { host: Some(host) })
}
fn endpoint_revision(
    boundary_revision: &str,
    ingress: &str,
    listener_ref: &str,
    tls_provider: &str,
    certificate_ref: &str,
    require_client_certificate: bool,
    probe_ref: &str,
) -> Result<EndpointRevisionDraft, String> {
    let boundary_revision = boundary_revision
        .parse::<i64>()
        .map_err(|_| "Boundary revision must be an integer".to_string())?;
    if boundary_revision <= 0
        || listener_ref.trim().is_empty()
        || tls_provider.trim().is_empty()
        || certificate_ref.trim().is_empty()
    {
        return Err("Boundary revision, listener reference, TLS provider, and certificate reference are required".to_string());
    }
    let ingress_kind = match ingress {
        "hub" => aos_proto_types::EndpointIngressKind::Hub as i32,
        "external" => aos_proto_types::EndpointIngressKind::External as i32,
        "layer7" => aos_proto_types::EndpointIngressKind::Layer7 as i32,
        _ => return Err("Unsupported endpoint ingress kind".to_string()),
    };
    Ok(EndpointRevisionDraft {
        boundary_revision,
        ingress_kind,
        listener_ref: listener_ref.trim().to_string(),
        tls: aos_proto_types::TlsConfiguration {
            provider: tls_provider.trim().to_string(),
            certificate_ref: certificate_ref.trim().to_string(),
            require_client_certificate,
        },
        probe_ref: probe_ref.trim().to_string(),
    })
}
fn revision_message(draft: EndpointRevisionDraft) -> aos_proto_types::DeliveryEndpointRevisionSpec {
    aos_proto_types::DeliveryEndpointRevisionSpec {
        boundary_revision: draft.boundary_revision,
        ingress_kind: draft.ingress_kind,
        listener_configuration_ref: draft.listener_ref,
        tls: Some(draft.tls),
        probe_configuration_ref: draft.probe_ref,
    }
}
fn ingress_name(value: i32) -> &'static str {
    match aos_proto_types::EndpointIngressKind::try_from(value)
        .unwrap_or(aos_proto_types::EndpointIngressKind::Unspecified)
    {
        aos_proto_types::EndpointIngressKind::Hub => "hub",
        aos_proto_types::EndpointIngressKind::External => "external",
        aos_proto_types::EndpointIngressKind::Layer7 => "layer7",
        aos_proto_types::EndpointIngressKind::Unspecified => "hub",
    }
}
fn endpoint_identity(endpoint: &aos_proto_types::DeliveryEndpoint) -> String {
    let host = endpoint
        .host
        .as_ref()
        .and_then(|value| value.host.as_ref())
        .map(|host| match host {
            aos_proto_types::endpoint_host::Host::DomainId(value) => value.clone(),
            aos_proto_types::endpoint_host::Host::Ipv4(bytes) => bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("."),
            aos_proto_types::endpoint_host::Host::Ipv6(_) => "IPv6 endpoint".to_string(),
        })
        .unwrap_or_else(|| "unknown host".to_string());
    format!("{}://{}:{}", endpoint.scheme, host, endpoint.effective_port)
}
fn grant_request(
    endpoint_id: &str,
    generation: i64,
    scope: &str,
    version: &str,
    idempotency_key: String,
) -> aos_proto_types::PlanConsumerScopeGrantRequest {
    aos_proto_types::PlanConsumerScopeGrantRequest {
        resource_kind: "delivery_endpoint".to_string(),
        resource_stable_id: endpoint_id.to_string(),
        resource_generation: generation,
        consumer_scope_key: scope.trim().to_string(),
        expected_resource_version: version.to_string(),
        idempotency_key,
        pin_resolutions: Vec::new(),
    }
}
fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}

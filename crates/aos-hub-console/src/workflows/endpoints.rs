//! Delivery-endpoint identity, generation, health, and grant workflows.
//!
//! Endpoint scheme/host/port identity is stable. Listener, TLS, probe, and
//! boundary-revision intent advances through staged immutable generations.

use std::net::IpAddr;
use std::str::FromStr;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{HashValue, HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::gateways::GatewayWorkflow;
use super::organization_scope::organization_authorization_scope;

/// Renders endpoint workflows and delegates unrelated pages onward.
#[component]
pub(super) fn EndpointWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "endpoints") => view! {
            <Endpoints client=client owner_scope_key="instance".to_string()/>
        }
        .into_any(),
        (ConsoleScope::Instance, "endpoints-new") => view! {
            <Endpoints client=client owner_scope_key="instance".to_string() creation_only=true/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "endpoints") => view! {
            <OrganizationEndpoints client=client organization=slug.clone() creation_only=false/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "endpoints-new") => view! {
            <OrganizationEndpoints client=client organization=slug.clone() creation_only=true/>
        }
        .into_any(),
        _ => view! { <GatewayWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn OrganizationEndpoints(
    client: ApiClient,
    organization: String,
    creation_only: bool,
) -> impl IntoView {
    let resolve_client = client.clone();
    let view_organization = organization.clone();
    let scope = LocalResource::new(move || {
        let client = resolve_client.clone();
        let slug = organization.clone();
        async move { organization_authorization_scope(&client, slug).await }
    });

    view! {
        <Suspense fallback=move || view! { <p class="loading-row">"Resolving organization scope…"</p> }>
            {move || {
                let client = client.clone();
                let organization = view_organization.clone();
                Suspend::new(async move {
                    match scope.await.as_ref() {
                        Ok(owner_scope_key) => view! {
        <Endpoints client=client owner_scope_key=owner_scope_key.clone() organization=organization.clone() creation_only=creation_only/>
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
fn Endpoints(
    client: ApiClient,
    owner_scope_key: String,
    #[prop(optional)] organization: Option<String>,
    #[prop(optional)] creation_only: bool,
) -> impl IntoView {
    let can_create = client.allows("endpoint.manage");
    let create_href = can_create.then(|| {
        organization.as_ref().map_or_else(
            || "/-/instance/endpoints/new".to_string(),
            |slug| format!("/-/org/{slug}/endpoints/new"),
        )
    });
    let list_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListEndpointsResponse, _, _, _>(
                    aos_proto_types::DELIVERY_SERVICE_LIST_ENDPOINTS_PATH,
                    move |page_token| aos_proto_types::ListTopologyResourcesRequest {
                        owner_scope_key: owner_scope_key.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.endpoints, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    view! { <div class="workflow-stack">{(!creation_only).then(|| view! { <section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Client ingress"</p><div class="section-title"><h2>"Endpoints"</h2><HelpTooltip term="Endpoints" summary="Endpoints bind one stable host identity to exact network-boundary and listener or TLS generations."/></div></div>{create_href.map(|href| view! { <a class="button" href=href>"Create endpoint"</a> })}</div><Suspense fallback=move || view! { <p class="loading-row">"Loading endpoints…"</p> }>{move || { let client = view_client.clone(); Suspend::new(async move { match inventory.await.as_ref() { Ok(endpoints) if endpoints.is_empty() => view! { <p class="muted">"No endpoints in this scope."</p> }.into_any(), Ok(endpoints) => view! { <div class="binding-list">{endpoints.iter().cloned().map(|endpoint| view! { <EndpointCard client=client.clone() endpoint=endpoint/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section> })}{creation_only.then(|| view! { <EndpointCreate client=client owner_scope_key=owner_scope_key/> })}</div> }
}

#[derive(Clone, Debug)]
struct EndpointRevisionDraft {
    boundary_revision: i64,
    ingress_kind: i32,
    listener_ref: String,
    tls: aos_proto_types::TlsConfiguration,
    probe_ref: String,
}

#[derive(Clone, Debug)]
struct EndpointCreateChoices {
    domains: Vec<aos_proto_types::Domain>,
    boundaries: Vec<aos_proto_types::NetworkPolicy>,
}

#[component]
fn EndpointCreate(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let choices_client = client.clone();
    let choices_scope = owner_scope_key.clone();
    let choices = LocalResource::new(move || {
        let client = choices_client.clone();
        let owner_scope_key = choices_scope.clone();
        async move { load_endpoint_create_choices(&client, owner_scope_key).await }
    });

    view! {
        <Suspense fallback=move || view! { <section class="panel editor-panel"><p class="loading-row">"Loading domains and network policies…"</p></section> }>
            {move || {
                let client = client.clone();
                let owner_scope_key = owner_scope_key.clone();
                Suspend::new(async move {
                    match choices.await.as_ref() {
                        Ok(choices) => view! {
                            <EndpointCreateForm
                                client=client
                                owner_scope_key=owner_scope_key
                                choices=choices.clone()
                            />
                        }.into_any(),
                        Err(detail) => view! { <section class="panel editor-panel"><InlineError detail=detail.clone()/></section> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

async fn load_endpoint_create_choices(
    client: &ApiClient,
    owner_scope_key: String,
) -> Result<EndpointCreateChoices, String> {
    let domain_scope = owner_scope_key.clone();
    let domains = client
        .collect_pages::<_, aos_proto_types::ListDomainsResponse, _, _, _>(
            aos_proto_types::DOMAIN_SERVICE_LIST_DOMAINS_PATH,
            move |page_token| aos_proto_types::ListDomainsRequest {
                owner_scope_key: domain_scope.clone(),
                page_size: 100,
                page_token,
            },
            |response| (response.domains, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;
    let boundaries = client
        .collect_pages::<_, aos_proto_types::ListNetworkPoliciesResponse, _, _, _>(
            aos_proto_types::NETWORK_POLICY_SERVICE_LIST_NETWORK_POLICIES_PATH,
            move |page_token| aos_proto_types::ListTopologyResourcesRequest {
                owner_scope_key: owner_scope_key.clone(),
                page_size: 100,
                page_token,
            },
            |response| (response.network_policies, response.next_page_token),
        )
        .await
        .map_err(|failure| failure.to_string())?;

    Ok(EndpointCreateChoices {
        domains,
        boundaries,
    })
}

#[component]
fn EndpointCreateForm(
    client: ApiClient,
    owner_scope_key: String,
    choices: EndpointCreateChoices,
) -> impl IntoView {
    let stable_id = RwSignal::new(String::new());
    let scheme = RwSignal::new("https".to_string());
    let host_kind = RwSignal::new("domain".to_string());
    let host = RwSignal::new(
        choices
            .domains
            .first()
            .map(|domain| domain.stable_id.clone())
            .unwrap_or_default(),
    );
    let port = RwSignal::new("443".to_string());
    let boundary_id = RwSignal::new(
        choices
            .boundaries
            .first()
            .map(|boundary| boundary.stable_id.clone())
            .unwrap_or_default(),
    );
    let boundary_revision = RwSignal::new(
        choices
            .boundaries
            .first()
            .map(|boundary| boundary.default_revision.to_string())
            .unwrap_or_default(),
    );
    let ingress = RwSignal::new("external".to_string());
    let listener_ref = RwSignal::new(host.get_untracked());
    let (initial_tls_provider, initial_certificate_ref) = choices
        .domains
        .first()
        .map(domain_tls_defaults)
        .unwrap_or_else(|| ("external".to_string(), String::new()));
    let tls_provider = RwSignal::new(initial_tls_provider);
    let certificate_ref = RwSignal::new(initial_certificate_ref);
    let require_client_certificate = RwSignal::new(false);
    let probe_ref = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let domain_choices = choices.domains.clone();
    let boundary_choices = choices.boundaries.clone();
    let selected_domains = choices.domains.clone();
    let host_domains = choices.domains;
    let selected_boundaries = choices.boundaries;
    let on_scheme_change = move |event| {
        let value = event_target_value(&event);
        port.set(if value == "https" { "443" } else { "80" }.to_string());
        scheme.set(value);
    };
    let on_host_kind_change = move |event| {
        let value = event_target_value(&event);
        host_kind.set(value.clone());
        if value == "domain" {
            if let Some(domain) = selected_domains.first() {
                host.set(domain.stable_id.clone());
                listener_ref.set(domain.stable_id.clone());
                let (provider, certificate) = domain_tls_defaults(domain);
                tls_provider.set(provider);
                certificate_ref.set(certificate);
            } else {
                host.set(String::new());
                listener_ref.set(String::new());
            }
        } else {
            host.set(String::new());
            listener_ref.set(String::new());
        }
    };
    let on_domain_change = Callback::new(move |value: String| {
        host.set(value.clone());
        listener_ref.set(value.clone());
        if let Some(domain) = host_domains.iter().find(|domain| domain.stable_id == value) {
            let (provider, certificate) = domain_tls_defaults(domain);
            tls_provider.set(provider);
            certificate_ref.set(certificate);
        }
    });
    let on_boundary_change = move |event| {
        let value = event_target_value(&event);
        boundary_id.set(value.clone());
        let revision = selected_boundaries
            .iter()
            .find(|boundary| boundary.stable_id == value)
            .map(|boundary| boundary.default_revision.to_string())
            .unwrap_or_default();
        boundary_revision.set(revision);
    };
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
            &scheme.get_untracked(),
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
        let request = aos_proto_types::PlanEndpointMutationRequest {
            stable_id: stable_id.get_untracked().trim().to_string(),
            owner_scope_key: owner_scope_key.clone(),
            scheme: scheme.get_untracked(),
            host: Some(endpoint_host),
            effective_port,
            network_policy_id: boundary_id.get_untracked().trim().to_string(),
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
                    aos_proto_types::DELIVERY_SERVICE_PLAN_CREATE_ENDPOINT_PATH,
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
                .call::<_, aos_proto_types::EndpointResponse>(
                    aos_proto_types::DELIVERY_SERVICE_CREATE_ENDPOINT_PATH,
                    &reviewed.endpoint_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! {
        <section class="panel editor-panel">
            <div class="section-heading"><div><p class="section-kicker">"Guided setup"</p><h2>"Create endpoint"</h2><p>"Choose resources by name. The endpoint pins their immutable identifiers and current generations for you."</p></div></div>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Endpoint name"</span><input required prop:value=move || stable_id.get() on:input=move |event| stable_id.set(event_target_value(&event))/></label>
                <label><span>"Scheme"</span><select prop:value=move || scheme.get() on:change=on_scheme_change><option value="https">"HTTPS"</option><option value="http">"HTTP"</option></select></label>
                <label><span>"Host kind"</span><select prop:value=move || host_kind.get() on:change=on_host_kind_change><option value="domain">"Managed domain"</option><option value="ipv4">"IPv4 address"</option><option value="ipv6">"IPv6 address"</option></select></label>
                {move || if host_kind.get() == "domain" {
                    let on_domain_change = on_domain_change.clone();
                    view! { <label><span>"Domain"</span><select required prop:value=move || host.get() on:change=move |event| on_domain_change.run(event_target_value(&event))>{domain_choices.iter().map(|domain| view! { <option value=domain.stable_id.clone()>{domain.hostname.clone()}</option> }).collect_view()}</select>{domain_choices.is_empty().then(|| view! { <small>"No domains exist in this scope. Add one from Infrastructure → Domains first."</small> })}</label> }.into_any()
                } else {
                    view! { <label><span>"IP address"</span><input required prop:value=move || host.get() on:input=move |event| host.set(event_target_value(&event))/></label> }.into_any()
                }}
                <label><span>"Port"</span><input readonly aria-readonly="true" prop:value=move || port.get()/><small>"Uses the selected scheme's standard port."</small></label>
                <label><span>"Network policy"</span><select required prop:value=move || boundary_id.get() on:change=on_boundary_change>{boundary_choices.iter().map(|boundary| view! { <option value=boundary.stable_id.clone()>{format!("{} · {}", boundary.name, boundary.kind)}</option> }).collect_view()}</select>{boundary_choices.is_empty().then(|| view! { <small>"No network policies exist in this scope. Create one before adding an endpoint."</small> })}</label>
                <label><span>"Boundary revision"</span><input readonly aria-readonly="true" prop:value=move || boundary_revision.get()/><small>"Pins the boundary's current default revision."</small></label>
                <label><span>"Ingress kind"</span><select prop:value=move || ingress.get() on:change=move |event| ingress.set(event_target_value(&event))><option value="external">"External ingress (CDN or object storage)"</option><option value="hub">"AOS Hub"</option><option value="layer7">"Layer 7 provider"</option></select></label>
                <label><span>"Listener reference"</span><input required prop:value=move || listener_ref.get() on:input=move |event| listener_ref.set(event_target_value(&event))/></label>
                {move || (scheme.get() == "https").then(|| view! {
                    <label><span>"TLS provider"</span><input required prop:value=move || tls_provider.get() on:input=move |event| tls_provider.set(event_target_value(&event))/></label>
                    <label><span>"Certificate reference"</span><input required prop:value=move || certificate_ref.get() on:input=move |event| certificate_ref.set(event_target_value(&event))/></label>
                    <label class="checkbox-field"><input type="checkbox" prop:checked=move || require_client_certificate.get() on:change=move |event| require_client_certificate.set(event_target_checked(&event))/><span>"Require client certificate"</span></label>
                })}
                <label class="full-field"><span>"Probe configuration reference"</span><input prop:value=move || probe_ref.get() on:input=move |event| probe_ref.set(event_target_value(&event))/></label>
                <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get() || host.get().is_empty() || boundary_id.get().is_empty()>"Review creation"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

fn domain_tls_defaults(domain: &aos_proto_types::Domain) -> (String, String) {
    use aos_proto_types::certificate_configuration::Configuration;

    match domain
        .desired
        .as_ref()
        .and_then(|desired| desired.certificate_configuration.as_ref())
        .and_then(|certificate| certificate.configuration.as_ref())
    {
        Some(Configuration::HubManaged(configuration)) => {
            (configuration.issuer.clone(), domain.stable_id.clone())
        }
        Some(Configuration::External(configuration)) => (
            "external".to_string(),
            configuration.certificate_secret_ref.clone(),
        ),
        None => ("external".to_string(), domain.stable_id.clone()),
    }
}

#[component]
fn EndpointRevisionFields(
    is_https: bool,
    boundary_revision: RwSignal<String>,
    ingress: RwSignal<String>,
    listener_ref: RwSignal<String>,
    tls_provider: RwSignal<String>,
    certificate_ref: RwSignal<String>,
    require_client_certificate: RwSignal<bool>,
    probe_ref: RwSignal<String>,
    #[prop(default = true)] show_boundary: bool,
) -> impl IntoView {
    view! { {show_boundary.then(|| view! { <label><span>"Boundary revision"</span><input required type="number" min="1" prop:value=move || boundary_revision.get() on:input=move |event| boundary_revision.set(event_target_value(&event))/></label> })}<label><span>"Ingress kind"</span><select prop:value=move || ingress.get() on:change=move |event| ingress.set(event_target_value(&event))><option value="hub">"AOS Hub"</option><option value="external">"External ingress"</option><option value="layer7">"Layer 7 provider"</option></select></label><label><span>"Listener configuration reference"</span><input required prop:value=move || listener_ref.get() on:input=move |event| listener_ref.set(event_target_value(&event))/></label>{is_https.then(|| view! { <label><span>"TLS provider"</span><input required prop:value=move || tls_provider.get() on:input=move |event| tls_provider.set(event_target_value(&event))/></label><label><span>"Certificate reference"</span><input required prop:value=move || certificate_ref.get() on:input=move |event| certificate_ref.set(event_target_value(&event))/></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || require_client_certificate.get() on:change=move |event| require_client_certificate.set(event_target_checked(&event))/><span>"Require client certificate"</span></label> })}<label class="full-field"><span>"Probe configuration reference"</span><input prop:value=move || probe_ref.get() on:input=move |event| probe_ref.set(event_target_value(&event))/></label> }
}

#[component]
fn EndpointCard(client: ApiClient, endpoint: aos_proto_types::Endpoint) -> impl IntoView {
    let observed = endpoint.observed.clone().unwrap_or_default();
    let identity = endpoint_identity(&endpoint);
    let positive = observed.state == "ready" && observed.listener_observed && observed.tls_observed;
    view! { <details class="binding-card"><summary><div><span class="resource-kind">{endpoint.scheme.clone()}</span><h3>{identity}</h3><code>{endpoint.stable_id.clone()}</code></div><div class="binding-summary-state"><StatusBadge state=if observed.state.is_empty() { "unknown".to_string() } else { observed.state.clone() } positive=positive/></div></summary><div class="binding-details"><div class="resource-identity"><div><span>"Boundary"</span><code>{format!("{}@{}", endpoint.network_policy_id, endpoint.desired.as_ref().map(|value| value.boundary_revision).unwrap_or_default())}</code></div><div><span>"Desired generation"</span><strong>{endpoint.desired_generation}</strong></div><div><span>"Observed generation"</span><strong>{observed.observed_generation}</strong></div><div><span>"Version"</span><code>{endpoint.resource_version.clone()}</code></div></div>{(!observed.error.is_empty()).then(|| view! { <InlineError detail=observed.error/> })}<EndpointGenerations client=client.clone() endpoint=endpoint.clone()/><div class="subworkflow-grid"><EndpointStage client=client.clone() endpoint=endpoint.clone()/><EndpointGrants client=client.clone() endpoint=endpoint.clone()/></div><EndpointDelete client=client endpoint=endpoint/></div></details> }
}

#[component]
fn EndpointGenerations(client: ApiClient, endpoint: aos_proto_types::Endpoint) -> impl IntoView {
    let endpoint_id = endpoint.stable_id;
    let endpoint_version = endpoint.resource_version;
    let read_client = client.clone();
    let generations = LocalResource::new(move || {
        let client = read_client.clone();
        let endpoint_id = endpoint_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListEndpointGenerationsResponse, _, _, _>(
                    aos_proto_types::DELIVERY_SERVICE_LIST_ENDPOINT_GENERATIONS_PATH,
                    move |page_token| aos_proto_types::ListEndpointGenerationsRequest {
                        endpoint_id: endpoint_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.generations, response.next_page_token),
                )
                .await
        }
    });
    view! { <section class="subworkflow"><h4>"Endpoint generations"</h4><Suspense fallback=move || view! { <p class="loading-row">"Loading generations…"</p> }>{move || { let client = client.clone(); let endpoint_version = endpoint_version.clone(); Suspend::new(async move { match generations.await.as_ref() { Ok(generations) => view! { <div class="compact-list">{generations.iter().cloned().map(|generation| view! { <EndpointGenerationRow client=client.clone() generation=generation endpoint_version=endpoint_version.clone()/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section> }
}

#[component]
fn EndpointGenerationRow(
    client: ApiClient,
    generation: aos_proto_types::EndpointGeneration,
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
        let request = aos_proto_types::PlanActivateEndpointGenerationRequest {
            endpoint_id: request_generation.endpoint_id.clone(),
            generation: request_generation.generation,
            expected_resource_version: endpoint_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_ACTIVATE_ENDPOINT_GENERATION_PATH,
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
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::EndpointGenerationResponse>(
                    aos_proto_types::DELIVERY_SERVICE_ACTIVATE_ENDPOINT_GENERATION_PATH,
                    &reviewed.endpoint_generation_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <div class="revision-card"><div class="compact-list-row"><div><strong>{format!("Generation {}", generation.generation)}</strong><span>{format!("boundary revision {}", generation.desired.as_ref().map(|value| value.boundary_revision).unwrap_or_default())}</span><HashValue value=generation.content_digest/></div>{if generation.selected { view! { <StatusBadge state="selected".to_string() positive=true/> }.into_any() } else { view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review activation"</button> }.into_any() }}</div>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</div> }
}

#[component]
fn EndpointStage(client: ApiClient, endpoint: aos_proto_types::Endpoint) -> impl IntoView {
    let scheme = endpoint.scheme.clone();
    let is_https = scheme == "https";
    let desired = endpoint.desired.clone().unwrap_or_default();
    let revisions_client = client.clone();
    let revisions_boundary = endpoint.network_policy_id.clone();
    let boundary_revisions = LocalResource::new(move || {
        let client = revisions_client.clone();
        let boundary_id = revisions_boundary.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListNetworkPolicyRevisionsResponse, _, _, _>(
                    aos_proto_types::NETWORK_POLICY_SERVICE_LIST_NETWORK_POLICY_REVISIONS_PATH,
                    move |page_token| aos_proto_types::ListNetworkPolicyRevisionsRequest {
                        boundary_id: boundary_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.revisions, response.next_page_token),
                )
                .await
        }
    });
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
            &scheme,
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
        let request = aos_proto_types::PlanStageEndpointGenerationRequest {
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
                    aos_proto_types::DELIVERY_SERVICE_PLAN_STAGE_ENDPOINT_GENERATION_PATH,
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
                .call::<_, aos_proto_types::EndpointGenerationResponse>(
                    aos_proto_types::DELIVERY_SERVICE_STAGE_ENDPOINT_GENERATION_PATH,
                    &reviewed.endpoint_generation_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow"><h4>"Stage generation"</h4><form class="stacked-form" on:submit=on_plan><label><span>"Network policy revision"</span><select required prop:value=move || boundary_revision.get() on:change=move |event| boundary_revision.set(event_target_value(&event))><Suspense fallback=move || view! { <option value=boundary_revision.get_untracked()>"Loading boundary revisions…"</option> }>{move || Suspend::new(async move { match boundary_revisions.await.as_ref() { Ok(revisions) => revisions.iter().map(|revision| { let lifecycle = revision.lifecycle.as_ref().map(|value| value.state.as_str()).unwrap_or("unknown"); view! { <option value=revision.revision.to_string()>{format!("Revision {} · {}", revision.revision, lifecycle)}</option> } }).collect_view().into_any(), Err(_) => view! { <option value=boundary_revision.get_untracked()>"Current pinned revision"</option> }.into_any() } })}</Suspense></select></label><EndpointRevisionFields is_https=is_https boundary_revision=boundary_revision ingress=ingress listener_ref=listener_ref tls_provider=tls_provider certificate_ref=certificate_ref require_client_certificate=require_client_certificate probe_ref=probe_ref show_boundary=false/><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review generation"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn EndpointGrants(client: ApiClient, endpoint: aos_proto_types::Endpoint) -> impl IntoView {
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
                    aos_proto_types::DELIVERY_SERVICE_PLAN_GRANT_ENDPOINT_SCOPE_PATH,
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
                    aos_proto_types::DELIVERY_SERVICE_GRANT_ENDPOINT_SCOPE_PATH,
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
                    aos_proto_types::DELIVERY_SERVICE_PLAN_REVOKE_ENDPOINT_SCOPE_PATH,
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
                    aos_proto_types::DELIVERY_SERVICE_REVOKE_ENDPOINT_SCOPE_PATH,
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
fn EndpointDelete(client: ApiClient, endpoint: aos_proto_types::Endpoint) -> impl IntoView {
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
                    aos_proto_types::DELIVERY_SERVICE_PLAN_DELETE_ENDPOINT_PATH,
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
                    aos_proto_types::DELIVERY_SERVICE_DELETE_ENDPOINT_PATH,
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
    scheme: &str,
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
    if boundary_revision <= 0 || listener_ref.trim().is_empty() {
        return Err("Boundary revision and listener reference are required".to_string());
    }
    let is_https = match scheme {
        "https" => true,
        "http" => false,
        _ => return Err("Unsupported endpoint scheme".to_string()),
    };
    if is_https && (tls_provider.trim().is_empty() || certificate_ref.trim().is_empty()) {
        return Err("HTTPS endpoints require a TLS provider and certificate reference".to_string());
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
            provider: is_https
                .then(|| tls_provider.trim().to_string())
                .unwrap_or_default(),
            certificate_ref: is_https
                .then(|| certificate_ref.trim().to_string())
                .unwrap_or_default(),
            require_client_certificate: is_https && require_client_certificate,
        },
        probe_ref: probe_ref.trim().to_string(),
    })
}
fn revision_message(draft: EndpointRevisionDraft) -> aos_proto_types::EndpointRevisionSpec {
    aos_proto_types::EndpointRevisionSpec {
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
fn endpoint_identity(endpoint: &aos_proto_types::Endpoint) -> String {
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
        resource_kind: "endpoint".to_string(),
        resource_stable_id: endpoint_id.to_string(),
        resource_generation: generation,
        consumer_scope_key: scope.trim().to_string(),
        expected_resource_version: version.to_string(),
        idempotency_key,
        pin_resolutions: Vec::new(),
    }
}
fn reload() {
    crate::app::refresh();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_endpoint_revision_clears_tls_fields() {
        let revision = endpoint_revision(
            "http",
            "3",
            "external",
            "listener:cdn",
            "ignored",
            "ignored",
            true,
            "",
        )
        .expect("HTTP endpoint revision");
        assert_eq!(revision.boundary_revision, 3);
        assert!(revision.tls.provider.is_empty());
        assert!(revision.tls.certificate_ref.is_empty());
        assert!(!revision.tls.require_client_certificate);
    }

    #[test]
    fn https_endpoint_revision_requires_tls_identity() {
        let error = endpoint_revision("https", "1", "external", "listener:cdn", "", "", false, "")
            .expect_err("missing HTTPS TLS identity must fail");
        assert!(error.contains("TLS provider"));
    }

    #[test]
    fn external_domain_supplies_endpoint_tls_defaults() {
        let domain = aos_proto_types::Domain {
            stable_id: "domain:cdn".to_string(),
            desired: Some(aos_proto_types::DomainDesiredState {
                certificate_configuration: Some(aos_proto_types::CertificateConfiguration {
                    configuration: Some(
                        aos_proto_types::certificate_configuration::Configuration::External(
                            aos_proto_types::ExternalCertificateConfiguration {
                                certificate_secret_ref: "secret:cdn-cert".to_string(),
                            },
                        ),
                    ),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            domain_tls_defaults(&domain),
            ("external".to_string(), "secret:cdn-cert".to_string())
        );
    }
}

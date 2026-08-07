//! Domain and revisioned delivery-network workflows.
//!
//! A domain is naming and certificate intent. Network boundaries, delivery
//! endpoints, and storage gateways are separate resources layered above it;
//! this module never presents them as one overloaded frontend.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::network_boundaries::NetworkBoundaryWorkflow;
use super::organization_scope::organization_authorization_scope;

/// Renders networking workflows for instance and organization scopes.
#[component]
pub(super) fn NetworkingWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "domains") => {
            view! { <Domains client=client owner_scope_key="instance".to_string()/> }.into_any()
        }
        (ConsoleScope::Instance, "domains-new") => view! {
            <Domains client=client owner_scope_key="instance".to_string() creation_only=true/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "domains") => {
            view! { <OrganizationDomains client=client organization=slug.clone() creation_only=false/> }.into_any()
        }
        (ConsoleScope::Organization { slug }, "domains-new") => {
            view! { <OrganizationDomains client=client organization=slug.clone() creation_only=true/> }.into_any()
        }
        _ => view! { <NetworkBoundaryWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn OrganizationDomains(
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
        <Domains client=client owner_scope_key=owner_scope_key.clone() organization=organization.clone() creation_only=creation_only/>
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
fn Domains(
    client: ApiClient,
    owner_scope_key: String,
    #[prop(optional)] organization: Option<String>,
    #[prop(optional)] creation_only: bool,
) -> impl IntoView {
    let can_create = client.allows("domain.manage");
    let create_href = can_create.then(|| {
        organization.as_ref().map_or_else(
            || "/-/instance/domains/new".to_string(),
            |slug| format!("/-/org/{slug}/domains/new"),
        )
    });
    let list_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListDomainsResponse, _, _, _>(
                    aos_proto_types::DOMAIN_SERVICE_LIST_DOMAINS_PATH,
                    move |page_token| aos_proto_types::ListDomainsRequest {
                        owner_scope_key: owner_scope_key.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.domains, response.next_page_token),
                )
                .await
        }
    });
    let inventory_client = client.clone();

    view! {
        <div class="workflow-stack">
            {(!creation_only).then(|| view! { <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Naming and certificates"</p><h2>"Domains"</h2><p>"Domains capture DNS and certificate intent. Endpoints choose a domain and a network boundary independently."</p></div>{create_href.map(|href| view! { <a class="button" href=href>"Add domain"</a> })}</div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading domains…"</p> }>
                    {move || { let client = inventory_client.clone(); Suspend::new(async move {
                        match inventory.await.as_ref() {
                            Ok(domains) if domains.is_empty() => view! { <p class="muted">"No managed domains in this scope."</p> }.into_any(),
                            Ok(domains) => view! { <div class="binding-list">{domains.iter().cloned().map(|domain| view! { <DomainCard client=client.clone() domain=domain/> }).collect_view()}</div> }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    }) }}
                </Suspense>
            </section> })}
            {creation_only.then(|| view! { <DomainCreate client=client owner_scope_key=owner_scope_key/> })}
        </div>
    }
}

#[component]
fn DomainCreate(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let hostname = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();

    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("domain-create");
        let request = aos_proto_types::PlanDomainMutationRequest {
            owner_scope_key: owner_scope_key.clone(),
            hostname: hostname.get_untracked().trim().to_ascii_lowercase(),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: String::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DOMAIN_SERVICE_PLAN_CREATE_DOMAIN_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some(reviewed)),
                Err(detail) => error.set(Some(detail)),
            }
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
                .call::<_, aos_proto_types::DomainResponse>(
                    aos_proto_types::DOMAIN_SERVICE_CREATE_DOMAIN_PATH,
                    &reviewed.domain_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });

    view! { <section class="panel editor-panel"><h2>"Add domain"</h2><form class="editor-form" on:submit=on_plan><label class="full-field"><span>"Hostname"</span><input required placeholder="packages.example.com" autocomplete="off" prop:value=move || hostname.get() on:input=move |event| hostname.set(event_target_value(&event))/><small>"Hostname identity is immutable. Configure DNS and certificates after creation."</small></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn DomainCard(client: ApiClient, domain: aos_proto_types::Domain) -> impl IntoView {
    let observed = domain.observed.clone().unwrap_or_default();
    let positive = observed.dns_state == "verified" && observed.certificate_state == "ready";
    view! { <details class="binding-card"><summary><div><span class="resource-kind">"Domain"</span><h3>{domain.hostname.clone()}</h3><code>{domain.stable_id.clone()}</code></div><div class="binding-summary-state"><StatusBadge state=format!("DNS {} · TLS {}", state_or_unknown(&observed.dns_state), state_or_unknown(&observed.certificate_state)) positive=positive/></div></summary><div class="binding-details"><div class="resource-identity"><div><span>"Owner"</span><code>{domain.owner_scope_key.clone()}</code></div><div><span>"Version"</span><code>{domain.resource_version.clone()}</code></div><div><span>"Observed"</span><strong>{format_timestamp(observed.observed_at)}</strong></div></div>{(!observed.error.is_empty()).then(|| view! { <InlineError detail=observed.error/> })}<div class="subworkflow-grid"><DomainDnsEditor client=client.clone() domain=domain.clone()/><DomainCertificateEditor client=client.clone() domain=domain.clone()/></div><div class="subworkflow-grid"><DomainVerify client=client.clone() domain=domain.clone()/><DomainDelete client=client domain=domain/></div></div></details> }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DomainConfigurationKind {
    Dns,
    Certificate,
}

#[component]
fn DomainDnsEditor(client: ApiClient, domain: aos_proto_types::Domain) -> impl IntoView {
    let mode = RwSignal::new("external".to_string());
    let expected_target = RwSignal::new(String::new());
    let provider = RwSignal::new(String::new());
    let zone_id = RwSignal::new(String::new());
    let record_mode = RwSignal::new("cname".to_string());
    let target = RwSignal::new(String::new());
    let ttl = RwSignal::new("300".to_string());
    let pending = RwSignal::new(None::<(PendingPlan, DomainConfigurationKind)>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let stable_id = domain.stable_id;
    let version = domain.resource_version;
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let configuration = if mode.get_untracked() == "external" {
            aos_proto_types::dns_configuration::Configuration::External(
                aos_proto_types::ExternalDnsConfiguration {
                    expected_target: expected_target.get_untracked().trim().to_string(),
                },
            )
        } else {
            let ttl_seconds = match ttl.get_untracked().parse::<u32>() {
                Ok(value) => value,
                Err(_) => {
                    error.set(Some("DNS TTL must be an unsigned integer".to_string()));
                    return;
                }
            };
            aos_proto_types::dns_configuration::Configuration::HubManaged(
                aos_proto_types::HubManagedDnsConfiguration {
                    provider: provider.get_untracked().trim().to_string(),
                    zone_id: zone_id.get_untracked().trim().to_string(),
                    record_mode: record_mode.get_untracked(),
                    target: target.get_untracked().trim().to_string(),
                    ttl_seconds,
                },
            )
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("domain-dns");
        let request = aos_proto_types::PlanDomainDnsRequest {
            stable_id: stable_id.clone(),
            configuration: Some(aos_proto_types::DnsConfiguration {
                configuration: Some(configuration),
            }),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DOMAIN_SERVICE_PLAN_CONFIGURE_DOMAIN_DNS_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some((reviewed, DomainConfigurationKind::Dns))),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = domain_configuration_apply(client, pending, error, busy);
    view! { <section class="subworkflow"><h4>"DNS intent"</h4><form class="stacked-form" on:submit=on_plan><label><span>"Management"</span><select prop:value=move || mode.get() on:change=move |event| mode.set(event_target_value(&event))><option value="external">"External DNS"</option><option value="hub">"Hub-managed DNS"</option></select></label>{move || if mode.get() == "external" { view! { <label><span>"Expected target"</span><input required prop:value=move || expected_target.get() on:input=move |event| expected_target.set(event_target_value(&event))/></label> }.into_any() } else { view! { <label><span>"Provider"</span><input required prop:value=move || provider.get() on:input=move |event| provider.set(event_target_value(&event))/></label><label><span>"Zone ID"</span><input required prop:value=move || zone_id.get() on:input=move |event| zone_id.set(event_target_value(&event))/></label><label><span>"Record mode"</span><select prop:value=move || record_mode.get() on:change=move |event| record_mode.set(event_target_value(&event))><option value="cname">"CNAME"</option><option value="a_aaaa">"A / AAAA"</option></select></label><label><span>"Target"</span><input required prop:value=move || target.get() on:input=move |event| target.set(event_target_value(&event))/></label><label><span>"TTL seconds"</span><input type="number" min="30" prop:value=move || ttl.get() on:input=move |event| ttl.set(event_target_value(&event))/></label> }.into_any() }}<button class="secondary-button" type="submit" disabled=move || busy.get()>"Review DNS change"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|(reviewed, _)| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn DomainCertificateEditor(client: ApiClient, domain: aos_proto_types::Domain) -> impl IntoView {
    let mode = RwSignal::new("hub".to_string());
    let issuer = RwSignal::new("acme".to_string());
    let challenge_provider = RwSignal::new(String::new());
    let secret_ref = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<(PendingPlan, DomainConfigurationKind)>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let stable_id = domain.stable_id;
    let version = domain.resource_version;
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let configuration = if mode.get_untracked() == "external" {
            aos_proto_types::certificate_configuration::Configuration::External(
                aos_proto_types::ExternalCertificateConfiguration {
                    certificate_secret_ref: secret_ref.get_untracked().trim().to_string(),
                },
            )
        } else {
            aos_proto_types::certificate_configuration::Configuration::HubManaged(
                aos_proto_types::HubManagedCertificateConfiguration {
                    issuer: issuer.get_untracked().trim().to_string(),
                    dns_challenge_provider: challenge_provider.get_untracked().trim().to_string(),
                },
            )
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("domain-certificate");
        let request = aos_proto_types::PlanDomainCertificateRequest {
            stable_id: stable_id.clone(),
            configuration: Some(aos_proto_types::CertificateConfiguration {
                configuration: Some(configuration),
            }),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DOMAIN_SERVICE_PLAN_CONFIGURE_DOMAIN_CERTIFICATE_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some((reviewed, DomainConfigurationKind::Certificate))),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    };
    let on_apply = domain_configuration_apply(client, pending, error, busy);
    view! { <section class="subworkflow"><h4>"Certificate intent"</h4><form class="stacked-form" on:submit=on_plan><label><span>"Management"</span><select prop:value=move || mode.get() on:change=move |event| mode.set(event_target_value(&event))><option value="hub">"Hub-managed certificate"</option><option value="external">"External certificate secret"</option></select></label>{move || if mode.get() == "external" { view! { <label><span>"Certificate secret reference"</span><input required autocomplete="off" prop:value=move || secret_ref.get() on:input=move |event| secret_ref.set(event_target_value(&event))/></label> }.into_any() } else { view! { <label><span>"Issuer"</span><input required prop:value=move || issuer.get() on:input=move |event| issuer.set(event_target_value(&event))/></label><label><span>"DNS challenge provider"</span><input required prop:value=move || challenge_provider.get() on:input=move |event| challenge_provider.set(event_target_value(&event))/></label> }.into_any() }}<button class="secondary-button" type="submit" disabled=move || busy.get()>"Review certificate change"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|(reviewed, _)| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

fn domain_configuration_apply(
    client: ApiClient,
    pending: RwSignal<Option<(PendingPlan, DomainConfigurationKind)>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()> {
    Callback::new(move |()| {
        let Some((reviewed, kind)) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        let path = match kind {
            DomainConfigurationKind::Dns => {
                aos_proto_types::DOMAIN_SERVICE_CONFIGURE_DOMAIN_DNS_PATH
            }
            DomainConfigurationKind::Certificate => {
                aos_proto_types::DOMAIN_SERVICE_CONFIGURE_DOMAIN_CERTIFICATE_PATH
            }
        };
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DomainResponse>(
                    path,
                    &reviewed.domain_configuration_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    })
}

#[component]
fn DomainVerify(client: ApiClient, domain: aos_proto_types::Domain) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = domain.stable_id;
    let version = domain.resource_version;
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("domain-verify");
        let request = aos_proto_types::PlanVerifyDomainRequest {
            stable_id: stable_id.clone(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DOMAIN_SERVICE_PLAN_VERIFY_DOMAIN_PATH,
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
                .call::<_, aos_proto_types::DomainResponse>(
                    aos_proto_types::DOMAIN_SERVICE_VERIFY_DOMAIN_PATH,
                    &reviewed.topology_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow"><h4>"Verify observations"</h4><p>"Probe configured DNS and certificate state; a click cannot assert success."</p><button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review verification"</button>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn DomainDelete(client: ApiClient, domain: aos_proto_types::Domain) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = domain.stable_id;
    let version = domain.resource_version;
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("domain-delete");
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
                    aos_proto_types::DOMAIN_SERVICE_PLAN_DELETE_DOMAIN_PATH,
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
                    aos_proto_types::DOMAIN_SERVICE_DELETE_DOMAIN_PATH,
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
    view! { <section class="subworkflow danger-subworkflow"><h4>"Delete domain"</h4><p>"Deletion fails while defaults, endpoints, routes, or live pins reference this identity."</p><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review deletion"</button>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

fn state_or_unknown(state: &str) -> &str {
    if state.is_empty() {
        "unknown"
    } else {
        state
    }
}
fn format_timestamp(value: i64) -> String {
    if value <= 0 {
        "Not observed".to_string()
    } else {
        format!("Unix {value}")
    }
}
fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}

//! Coordinated delivery-destination setup and activation.
//!
//! The workflow turns one operator intent into durable endpoint, gateway,
//! route, verification, and advertisement steps. Resource-specific editors
//! remain available from the route inventory for advanced inspection.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, watch_draft, PendingPlan};
use crate::route::{
    delivery_draft_prerequisites, delivery_public_path, delivery_workflow_action,
    DeliverySetupAccess, DeliveryWorkflowAction,
};
use crate::transport::ApiClient;

use super::access_policy::{AccessPolicyFields, AccessPolicySignals};
use super::gateways::endpoint_option_label;
use super::routes::RouteCreateChoices;

/// Renders durable delivery setup, progress, and activation for one surface.
#[component]
pub(super) fn DeliveryDestinationWorkflows(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    choices: LocalResource<Result<Option<RouteCreateChoices>, String>>,
    choices_requested: RwSignal<bool>,
    access: DeliverySetupAccess,
) -> impl IntoView {
    let can_manage = client.allows("route.manage");
    let list_client = client.clone();
    let list_surface = surface.clone();
    let workflows = LocalResource::new(move || {
        let client = list_client.clone();
        let surface = list_surface.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListDeliveryWorkflowsResponse, _, _, _>(
                    aos_proto_types::DELIVERY_SERVICE_LIST_DELIVERY_WORKFLOWS_PATH,
                    move |page_token| aos_proto_types::ListDeliveryWorkflowsRequest {
                        surface: Some(surface.clone()),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.workflows, response.next_page_token),
                )
                .await
        }
    });
    let list_view_client = client.clone();

    view! {
        <section class="panel delivery-workflows" aria-labelledby="delivery-workflows-title">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Guided delivery"</p>
                    <h2 id="delivery-workflows-title">"Delivery destinations"</h2>
                    <p>"Provision, verify, and activate one complete destination without losing progress."</p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading delivery progress…"</p> }>
                {move || {
                    let client = list_view_client.clone();
                    Suspend::new(async move {
                        match workflows.await.as_ref() {
                            Ok(workflows) if workflows.is_empty() => view! { <p class="muted">"No delivery setup is in progress."</p> }.into_any(),
                            Ok(workflows) => view! { <div class="binding-list">{workflows.iter().cloned().map(|workflow| view! { <DeliveryWorkflowCard client=client.clone() workflow=workflow can_manage=can_manage access=access/> }).collect_view()}</div> }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            {access.can_start().then(|| view! {
                <details class="guided-workflow" on:toggle=move |_| choices_requested.set(true)>
                    <summary>"Add delivery destination"</summary>
                    <Suspense fallback=move || view! { <p class="loading-row">"Loading available infrastructure…"</p> }>
                        {move || {
                            let client = client.clone();
                            let surface = surface.clone();
                            Suspend::new(async move {
                                match choices.await.as_ref() {
                                    Ok(Some(choices)) => view! { <DeliveryDestinationForm client=client surface=surface choices=choices.clone() access=access/> }.into_any(),
                                    Ok(None) => ().into_any(),
                                    Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                                }
                            })
                        }}
                    </Suspense>
                </details>
            })}
            {(!access.can_start()).then(|| view! {
                <p class="muted">"Creating a destination requires route and gateway management plus read access to its storage and endpoint. Creating a hostname also requires endpoint, domain, and network-policy access."</p>
            })}
        </section>
    }
}

#[component]
fn DeliveryDestinationForm(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    choices: RouteCreateChoices,
    access: DeliverySetupAccess,
) -> impl IntoView {
    let endpoint_mode = RwSignal::new(
        if access.can_use_existing_endpoint && !choices.endpoints.is_empty() {
            "existing".to_string()
        } else if access.can_create_hostname_endpoint {
            "new".to_string()
        } else {
            "domain".to_string()
        },
    );
    let endpoint_id = RwSignal::new(
        choices
            .endpoints
            .first()
            .map(|endpoint| endpoint.stable_id.clone())
            .unwrap_or_default(),
    );
    let hostname = RwSignal::new(String::new());
    let domain_id = RwSignal::new(
        choices
            .domains
            .first()
            .map(|domain| domain.stable_id.clone())
            .unwrap_or_default(),
    );
    let network_policy_id = RwSignal::new(
        choices
            .boundaries
            .first()
            .map(|boundary| boundary.stable_id.clone())
            .unwrap_or_default(),
    );
    let listener_ref = RwSignal::new(String::new());
    let tls_provider = RwSignal::new(String::new());
    let certificate_ref = RwSignal::new(String::new());
    let probe_ref = RwSignal::new(String::new());
    let placement_name = RwSignal::new(
        choices
            .placements
            .first()
            .map(|placement| placement.name.clone())
            .unwrap_or_default(),
    );
    let client_base_path = RwSignal::new("/".to_string());
    let serves_git = RwSignal::new(surface_is_registry(&surface));
    let serves_cache = RwSignal::new(surface_is_cache(&surface));
    let serves_web = RwSignal::new(surface_is_registry(&surface));
    let serves_oci = RwSignal::new(false);
    let advertise_git = RwSignal::new(surface_is_registry(&surface));
    let advertise_cache = RwSignal::new(surface_is_cache(&surface));
    let advertise_web = RwSignal::new(surface_is_registry(&surface));
    let access = AccessPolicySignals::public();
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = delivery_draft_key(
                endpoint_mode,
                endpoint_id,
                hostname,
                domain_id,
                network_policy_id,
                listener_ref,
                tls_provider,
                certificate_ref,
                probe_ref,
                placement_name,
                client_base_path,
                serves_git,
                serves_cache,
                serves_web,
                serves_oci,
                advertise_git,
                advertise_cache,
                advertise_web,
                access,
            );
        },
        pending,
        error,
    );

    let endpoint_choices = choices.endpoints.clone();
    let selected_endpoints = choices.endpoints;
    let domain_choices = choices.domains.clone();
    let selected_domains = choices.domains;
    let placement_choices = choices.placements.clone();
    let preview_placements = choices.placements;
    let boundary_choices = choices.boundaries.clone();
    let selected_boundaries = choices.boundaries;
    let boundaries_for_access = selected_boundaries.clone();
    let on_boundary_change = move |event| {
        network_policy_id.set(event_target_value(&event));
    };
    let plan_client = client.clone();
    let owner_scope_key = choices.owner_scope_key;
    let plan_surface = surface;
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        error.set(None);

        let intent = match build_delivery_intent(
            plan_surface.clone(),
            &owner_scope_key,
            &selected_endpoints,
            &selected_boundaries,
            endpoint_mode,
            endpoint_id,
            hostname,
            domain_id,
            &selected_domains,
            network_policy_id,
            listener_ref,
            tls_provider,
            certificate_ref,
            probe_ref,
            placement_name,
            client_base_path,
            serves_git,
            serves_cache,
            serves_web,
            serves_oci,
            advertise_git,
            advertise_cache,
            advertise_web,
            access,
        ) {
            Ok(intent) => intent,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let planned_epoch = draft_epoch.get_untracked();
        let idempotency_key = idempotency_key("delivery-destination");
        let request = aos_proto_types::PlanDeliveryDestinationRequest {
            intent: Some(intent),
            idempotency_key: idempotency_key.clone(),
            ..Default::default()
        };
        let client = plan_client.clone();
        busy.set(true);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_DELIVERY_DESTINATION_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) if draft_epoch.get_untracked() == planned_epoch => {
                    pending.set(Some(reviewed));
                }
                Ok(_) => {}
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
                .call::<_, aos_proto_types::DeliveryWorkflowResponse>(
                    aos_proto_types::DELIVERY_SERVICE_APPLY_DELIVERY_DESTINATION_PATH,
                    &reviewed.delivery_workflow_apply(),
                )
                .await
            {
                Ok(_) => super::routes::reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="workflow-editor">
            <p>"Choose the desired public result. Hub will retain the exact resources, grants, verification steps, and activation boundary underneath."</p>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Storage placement"</span><select required prop:value=move || placement_name.get() on:change=move |event| placement_name.set(event_target_value(&event))>{placement_choices.iter().map(|placement| view! { <option value=placement.name.clone()>{format!("{} · {}", placement.name, placement.binding_name)}</option> }).collect_view()}</select><small>"The destination reads bytes from this existing placement."</small></label>
                <label><span>"Endpoint"</span><select prop:value=move || endpoint_mode.get() on:change=move |event| endpoint_mode.set(event_target_value(&event))>{access.can_use_existing_endpoint.then(|| view! { <option value="existing">"Use existing endpoint"</option> })}{access.can_create_hostname_endpoint.then(|| view! { <option value="new">"Configure new CDN hostname"</option> })}{(access.can_create_managed_domain_endpoint && !domain_choices.is_empty()).then(|| view! { <option value="domain">"Use managed domain for new endpoint"</option> })}</select></label>
                {move || if endpoint_mode.get() == "existing" {
                    let endpoint_choices = endpoint_choices.clone();
                    view! { <label><span>"Existing endpoint"</span><select required prop:value=move || endpoint_id.get() on:change=move |event| endpoint_id.set(event_target_value(&event))>{endpoint_choices.iter().map(|endpoint| view! { <option value=endpoint.stable_id.clone()>{endpoint_option_label(endpoint)}</option> }).collect_view()}</select>{endpoint_choices.is_empty().then(|| view! { <small>"No endpoint is available. Configure a new CDN hostname here instead."</small> })}</label> }.into_any()
                } else {
                    let domain_choices = domain_choices.clone();
                    view! {
                        <fieldset class="choice-field">
                            <legend>"New CDN endpoint"</legend>
                            {move || if endpoint_mode.get() == "domain" {
                                view! { <label><span>"Managed domain"</span><select required prop:value=move || domain_id.get() on:change=move |event| domain_id.set(event_target_value(&event))>{domain_choices.iter().map(|domain| view! { <option value=domain.stable_id.clone()>{domain.hostname.clone()}</option> }).collect_view()}</select></label> }.into_any()
                            } else {
                                view! { <label><span>"Public hostname"</span><input required placeholder="cdn.example.com" prop:value=move || hostname.get() on:input=move |event| hostname.set(event_target_value(&event))/><small>"Hub creates the domain identity and waits for provider verification."</small></label> }.into_any()
                            }}
                            <label><span>"Network policy"</span><select required prop:value=move || network_policy_id.get() on:change=on_boundary_change>{boundary_choices.iter().map(|boundary| view! { <option value=boundary.stable_id.clone()>{format!("{} · revision {}", boundary.name, boundary.default_revision)}</option> }).collect_view()}</select>{boundary_choices.is_empty().then(|| view! { <small>"No network policy is available to this surface. Its infrastructure owner must provide or grant one."</small> })}</label>
                            <label><span>"Provider listener"</span><input required prop:value=move || listener_ref.get() on:input=move |event| listener_ref.set(event_target_value(&event))/><small>"The exact CDN or ingress attachment reference Hub will verify."</small></label>
                            <label><span>"TLS provider"</span><input required prop:value=move || tls_provider.get() on:input=move |event| tls_provider.set(event_target_value(&event))/></label>
                            <label><span>"TLS certificate"</span><input required prop:value=move || certificate_ref.get() on:input=move |event| certificate_ref.set(event_target_value(&event))/></label>
                            <label><span>"Provider probe"</span><input required prop:value=move || probe_ref.get() on:input=move |event| probe_ref.set(event_target_value(&event))/><small>"The provider-specific probe Hub observes before activation."</small></label>
                        </fieldset>
                    }.into_any()
                }}
                <label><span>"CDN URL prefix"</span><input required prop:value=move || client_base_path.get() on:input=move |event| client_base_path.set(event_target_value(&event))/><small>"The selected placement's storage prefix is appended to this path for the final public URL."</small></label>
                <div class="field-note"><span>"Final public path"</span><code>{move || { let placement_prefix = preview_placements.iter().find(|placement| placement.name == placement_name.get()).map(|placement| placement.prefix.as_str()).unwrap_or_default(); delivery_public_path(&client_base_path.get(), placement_prefix) }}</code></div>
                <AccessPolicyFields signals=access allow_hub_auth=false boundaries=boundaries_for_access/>
                <fieldset class="choice-field"><legend>"Capabilities"</legend><label class="choice-row"><input type="checkbox" prop:checked=move || serves_git.get() on:change=move |event| serves_git.set(event_target_checked(&event))/><span>"Git"</span></label><label class="choice-row"><input type="checkbox" prop:checked=move || serves_cache.get() on:change=move |event| serves_cache.set(event_target_checked(&event))/><span>"Nix cache"</span></label><label class="choice-row"><input type="checkbox" prop:checked=move || serves_web.get() on:change=move |event| serves_web.set(event_target_checked(&event))/><span>"Web"</span></label><label class="choice-row"><input type="checkbox" prop:checked=move || serves_oci.get() on:change=move |event| serves_oci.set(event_target_checked(&event))/><span>"OCI"</span></label></fieldset>
                <fieldset class="choice-field"><legend>"Make canonical for"</legend><label class="choice-row"><input type="checkbox" prop:checked=move || advertise_git.get() on:change=move |event| advertise_git.set(event_target_checked(&event))/><span>"Git clients"</span></label><label class="choice-row"><input type="checkbox" prop:checked=move || advertise_cache.get() on:change=move |event| advertise_cache.set(event_target_checked(&event))/><span>"Nix clients"</span></label><label class="choice-row"><input type="checkbox" prop:checked=move || advertise_web.get() on:change=move |event| advertise_web.set(event_target_checked(&event))/><span>"Web clients"</span></label></fieldset>
                <DeliveryPrerequisites endpoint_mode=endpoint_mode endpoint_id=endpoint_id hostname=hostname domain_id=domain_id network_policy_id=network_policy_id listener_ref=listener_ref tls_provider=tls_provider certificate_ref=certificate_ref probe_ref=probe_ref placement_name=placement_name/>
                <div class="form-actions"><button class="button" type="submit" disabled=move || { let mode = endpoint_mode.get(); busy.get() || !delivery_draft_prerequisites( !placement_name.get().is_empty(), !endpoint_id.get().is_empty(), mode != "existing", if mode == "domain" { !domain_id.get().is_empty() } else { !hostname.get().is_empty() }, !network_policy_id.get().is_empty(), !listener_ref.get().is_empty() && !tls_provider.get().is_empty() && !certificate_ref.get().is_empty() && !probe_ref.get().is_empty()).is_empty() }>"Review destination"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </div>
    }
}

#[component]
fn DeliveryPrerequisites(
    endpoint_mode: RwSignal<String>,
    endpoint_id: RwSignal<String>,
    hostname: RwSignal<String>,
    domain_id: RwSignal<String>,
    network_policy_id: RwSignal<String>,
    listener_ref: RwSignal<String>,
    tls_provider: RwSignal<String>,
    certificate_ref: RwSignal<String>,
    probe_ref: RwSignal<String>,
    placement_name: RwSignal<String>,
) -> impl IntoView {
    move || {
        let mode = endpoint_mode.get();
        let missing = delivery_draft_prerequisites(
            !placement_name.get().is_empty(),
            !endpoint_id.get().is_empty(),
            mode != "existing",
            if mode == "domain" {
                !domain_id.get().is_empty()
            } else {
                !hostname.get().is_empty()
            },
            !network_policy_id.get().is_empty(),
            !listener_ref.get().is_empty()
                && !tls_provider.get().is_empty()
                && !certificate_ref.get().is_empty()
                && !probe_ref.get().is_empty(),
        );
        (!missing.is_empty()).then(|| view! {
            <div class="workflow-prerequisites" role="status"><strong>"Before review"</strong><ul>{missing.into_iter().map(|message| view! { <li>{message}</li> }).collect_view()}</ul></div>
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_delivery_intent(
    surface: aos_proto_types::SurfaceRef,
    owner_scope_key: &str,
    endpoints: &[aos_proto_types::Endpoint],
    boundaries: &[aos_proto_types::NetworkPolicy],
    endpoint_mode: RwSignal<String>,
    endpoint_id: RwSignal<String>,
    hostname: RwSignal<String>,
    domain_id: RwSignal<String>,
    domains: &[aos_proto_types::Domain],
    network_policy_id: RwSignal<String>,
    listener_ref: RwSignal<String>,
    tls_provider: RwSignal<String>,
    certificate_ref: RwSignal<String>,
    probe_ref: RwSignal<String>,
    placement_name: RwSignal<String>,
    client_base_path: RwSignal<String>,
    serves_git: RwSignal<bool>,
    serves_cache: RwSignal<bool>,
    serves_web: RwSignal<bool>,
    serves_oci: RwSignal<bool>,
    advertise_git: RwSignal<bool>,
    advertise_cache: RwSignal<bool>,
    advertise_web: RwSignal<bool>,
    access: AccessPolicySignals,
) -> Result<aos_proto_types::DeliveryDestinationIntent, String> {
    use aos_proto_types::delivery_destination_intent::Endpoint;
    use aos_proto_types::delivery_endpoint_input::HostnameSource;

    let endpoint_mode = endpoint_mode.get_untracked();
    let new_endpoint = endpoint_mode != "existing";
    let prerequisites = delivery_draft_prerequisites(
        !placement_name.get_untracked().is_empty(),
        !endpoint_id.get_untracked().is_empty(),
        new_endpoint,
        if endpoint_mode == "domain" {
            !domain_id.get_untracked().is_empty()
        } else {
            !hostname.get_untracked().is_empty()
        },
        !network_policy_id.get_untracked().is_empty(),
        !listener_ref.get_untracked().is_empty()
            && !tls_provider.get_untracked().is_empty()
            && !certificate_ref.get_untracked().is_empty()
            && !probe_ref.get_untracked().is_empty(),
    );
    if !prerequisites.is_empty() {
        return Err(prerequisites.join(" "));
    }

    let endpoint = if new_endpoint {
        let boundary = boundaries
            .iter()
            .find(|boundary| boundary.stable_id == network_policy_id.get_untracked())
            .ok_or_else(|| "The selected network policy is no longer available.".to_string())?;
        let hostname_source = if endpoint_mode == "domain" {
            let domain = domains
                .iter()
                .find(|domain| domain.stable_id == domain_id.get_untracked())
                .ok_or_else(|| "The selected managed domain is no longer available.".to_string())?;
            HostnameSource::DomainId(domain.stable_id.clone())
        } else {
            HostnameSource::Hostname(hostname.get_untracked().trim().to_string())
        };
        Endpoint::NewEndpoint(aos_proto_types::DeliveryEndpointInput {
            hostname_source: Some(hostname_source),
            network_policy_id: boundary.stable_id.clone(),
            revision: Some(aos_proto_types::EndpointRevisionSpec {
                boundary_revision: boundary.default_revision,
                ingress_kind: aos_proto_types::EndpointIngressKind::External as i32,
                listener_configuration_ref: listener_ref.get_untracked().trim().to_string(),
                tls: Some(aos_proto_types::TlsConfiguration {
                    provider: tls_provider.get_untracked().trim().to_string(),
                    certificate_ref: certificate_ref.get_untracked().trim().to_string(),
                    require_client_certificate: false,
                }),
                probe_configuration_ref: probe_ref.get_untracked().trim().to_string(),
            }),
        })
    } else {
        let endpoint = endpoints
            .iter()
            .find(|candidate| candidate.stable_id == endpoint_id.get_untracked())
            .ok_or_else(|| "The selected endpoint is no longer available.".to_string())?;
        Endpoint::ExistingEndpoint(aos_proto_types::DeliveryEndpointReference {
            endpoint_id: endpoint.stable_id.clone(),
            generation: endpoint.desired_generation,
        })
    };
    let capabilities = aos_proto_types::RouteCapabilities {
        serves_git: serves_git.get_untracked(),
        serves_cache: serves_cache.get_untracked(),
        serves_web: serves_web.get_untracked(),
        serves_oci: serves_oci.get_untracked(),
    };
    if !capabilities.serves_git
        && !capabilities.serves_cache
        && !capabilities.serves_web
        && !capabilities.serves_oci
    {
        return Err("Select at least one capability for this destination.".to_string());
    }
    let mut audiences = Vec::new();
    if advertise_git.get_untracked() {
        audiences.push("git".to_string());
    }
    if advertise_cache.get_untracked() {
        audiences.push("nix_cache".to_string());
    }
    if advertise_web.get_untracked() {
        audiences.push("web".to_string());
    }

    Ok(aos_proto_types::DeliveryDestinationIntent {
        surface: Some(surface),
        owner_scope_key: owner_scope_key.to_string(),
        endpoint: Some(endpoint),
        placement_name: placement_name.get_untracked(),
        client_base_path: client_base_path.get_untracked(),
        access_policy: Some(access.build()?),
        capabilities: Some(capabilities),
        audiences,
    })
}

#[allow(clippy::too_many_arguments)]
fn delivery_draft_key(
    endpoint_mode: RwSignal<String>,
    endpoint_id: RwSignal<String>,
    hostname: RwSignal<String>,
    domain_id: RwSignal<String>,
    network_policy_id: RwSignal<String>,
    listener_ref: RwSignal<String>,
    tls_provider: RwSignal<String>,
    certificate_ref: RwSignal<String>,
    probe_ref: RwSignal<String>,
    placement_name: RwSignal<String>,
    client_base_path: RwSignal<String>,
    serves_git: RwSignal<bool>,
    serves_cache: RwSignal<bool>,
    serves_web: RwSignal<bool>,
    serves_oci: RwSignal<bool>,
    advertise_git: RwSignal<bool>,
    advertise_cache: RwSignal<bool>,
    advertise_web: RwSignal<bool>,
    access: AccessPolicySignals,
) -> String {
    [
        endpoint_mode.get(),
        endpoint_id.get(),
        hostname.get(),
        domain_id.get(),
        network_policy_id.get(),
        listener_ref.get(),
        tls_provider.get(),
        certificate_ref.get(),
        probe_ref.get(),
        placement_name.get(),
        client_base_path.get(),
        serves_git.get().to_string(),
        serves_cache.get().to_string(),
        serves_web.get().to_string(),
        serves_oci.get().to_string(),
        advertise_git.get().to_string(),
        advertise_cache.get().to_string(),
        advertise_web.get().to_string(),
        access.draft_key(),
    ]
    .join("\u{1f}")
}

#[component]
fn DeliveryWorkflowCard(
    client: ApiClient,
    workflow: aos_proto_types::DeliveryWorkflow,
    can_manage: bool,
    access: DeliverySetupAccess,
) -> impl IntoView {
    let state = if workflow.state.is_empty() {
        "unknown".to_string()
    } else {
        workflow.state.clone()
    };
    let positive = state == "ready" || state == "active";
    let action = delivery_workflow_action(&state);
    let resumes_new_endpoint = workflow.intent.as_ref().is_some_and(|intent| {
        matches!(
            intent.endpoint.as_ref(),
            Some(aos_proto_types::delivery_destination_intent::Endpoint::NewEndpoint(_))
        )
    });
    let can_resume = if resumes_new_endpoint {
        access.can_resume_new
    } else {
        access.can_resume_existing
    };
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let workflow_id = workflow.workflow_id.clone();
    let version = workflow.resource_version.clone();
    let refresh_client = client.clone();
    let refresh_id = workflow.workflow_id.clone();
    let on_refresh = move |_| {
        let client = refresh_client.clone();
        let request = aos_proto_types::GetDeliveryWorkflowRequest {
            workflow_id: refresh_id.clone(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeliveryWorkflowResponse>(
                    aos_proto_types::DELIVERY_SERVICE_GET_DELIVERY_WORKFLOW_PATH,
                    &request,
                )
                .await
            {
                Ok(_) => super::routes::reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let action_client = client.clone();
    let on_resume = move |_| {
        let client = action_client.clone();
        let request = aos_proto_types::ResumeDeliveryDestinationRequest {
            workflow_id: workflow_id.clone(),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key("delivery-resume"),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeliveryWorkflowResponse>(
                    aos_proto_types::DELIVERY_SERVICE_RESUME_DELIVERY_DESTINATION_PATH,
                    &request,
                )
                .await
            {
                Ok(_) => super::routes::reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    let activate_client = client.clone();
    let activate_id = workflow.workflow_id.clone();
    let activate_version = workflow.resource_version.clone();
    let on_plan_activate = move |_| {
        let client = activate_client.clone();
        let idempotency_key = idempotency_key("delivery-activate");
        let request = aos_proto_types::PlanActivateDeliveryDestinationRequest {
            workflow_id: activate_id.clone(),
            expected_resource_version: activate_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        pending.set(None);
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::DELIVERY_SERVICE_PLAN_ACTIVATE_DELIVERY_DESTINATION_PATH,
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
    let apply_client = client;
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = apply_client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::DeliveryWorkflowResponse>(
                    aos_proto_types::DELIVERY_SERVICE_ACTIVATE_DELIVERY_DESTINATION_PATH,
                    &reviewed.delivery_workflow_apply(),
                )
                .await
            {
                Ok(_) => super::routes::reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <article class="workflow-card">
            <div class="workflow-card-heading"><div><span class="resource-kind">"Delivery workflow"</span><h3>{workflow.canonical_url.clone().is_empty().then(|| "Pending destination".to_string()).unwrap_or_else(|| workflow.canonical_url.clone())}</h3><code>{workflow.workflow_id.clone()}</code></div><StatusBadge state=state positive=positive/></div>
            <ol class="workflow-steps">{workflow.steps.into_iter().map(|step| { let operation = step.operation; view! { <li class=format!("workflow-step {}", step.state)><strong>{step.label}</strong><span>{step.detail}</span>{(!step.resource_id.is_empty()).then(|| view! { <code>{step.resource_id}</code> })}{operation.map(|operation| view! { <span class="workflow-operation"><code>{operation.operation_id}</code>{format!("{} · {}", operation.kind, operation.state)}</span> })}</li> } }).collect_view()}</ol>
            {(!workflow.blockers.is_empty()).then(|| view! { <div class="workflow-blockers"><strong>"Waiting on"</strong><ul>{workflow.blockers.into_iter().map(|blocker| view! { <li>{blocker}</li> }).collect_view()}</ul></div> })}
            {(!workflow.next_actions.is_empty()).then(|| view! { <div class="workflow-next-actions"><strong>"Next actions"</strong><ul>{workflow.next_actions.into_iter().map(|next| view! { <li>{next}</li> }).collect_view()}</ul></div> })}
            {can_manage.then(|| match action {
                Some(DeliveryWorkflowAction::Resume) if can_resume => view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_resume>"Check and continue"</button> }.into_any(),
                Some(DeliveryWorkflowAction::Resume) => view! { <p class="muted">"Continuing this workflow requires gateway management and binding read access; new endpoints also require endpoint management."</p> }.into_any(),
                Some(DeliveryWorkflowAction::ReviewActivation) => view! { <button class="button" type="button" disabled=move || busy.get() on:click=on_plan_activate>"Review activation"</button> }.into_any(),
                None => ().into_any(),
            })}
            <button class="table-action" type="button" disabled=move || busy.get() on:click=on_refresh>"Refresh status"</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
            <details class="advanced-controls"><summary>"Inspect workflow resources"</summary><div class="resource-identity"><div><span>"Domain"</span><code>{workflow.domain_id}</code></div><div><span>"Endpoint"</span><code>{format!("{}@{}", workflow.endpoint_id, workflow.endpoint_generation)}</code></div><div><span>"Gateway"</span><code>{workflow.gateway_id}</code></div><div><span>"Route"</span><code>{workflow.route_id}</code></div><div><span>"Version"</span><code>{workflow.resource_version}</code></div></div></details>
        </article>
    }
}

fn surface_is_registry(surface: &aos_proto_types::SurfaceRef) -> bool {
    matches!(
        surface.target.as_ref(),
        Some(aos_proto_types::surface_ref::Target::RegistrySlug(_))
    )
}

fn surface_is_cache(surface: &aos_proto_types::SurfaceRef) -> bool {
    matches!(
        surface.target.as_ref(),
        Some(aos_proto_types::surface_ref::Target::CacheSlug(_))
    )
}

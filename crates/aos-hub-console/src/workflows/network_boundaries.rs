//! Revisioned network-boundary identity and policy workflows.
//!
//! Stable boundary identity is edited separately from immutable policy
//! revisions. Activation and retirement remain explicit lifecycle operations,
//! so an editor cannot silently replace policy used by live endpoints.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::delivery_endpoints::DeliveryEndpointWorkflow;

/// Renders boundary workflows and delegates unrelated pages onward.
#[component]
pub(super) fn NetworkBoundaryWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Instance, "boundaries") => view! {
            <NetworkBoundaries client=client owner_scope_key="instance".to_string()/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "boundaries") => view! {
            <NetworkBoundaries client=client owner_scope_key=format!("org:{slug}")/>
        }
        .into_any(),
        _ => view! { <DeliveryEndpointWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn NetworkBoundaries(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let list_client = client.clone();
    let list_scope = owner_scope_key.clone();
    let inventory = LocalResource::new(move || {
        let client = list_client.clone();
        let owner_scope_key = list_scope.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListNetworkBoundariesResponse>(
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_LIST_NETWORK_BOUNDARIES_PATH,
                    &aos_proto_types::ListTopologyResourcesRequest {
                        owner_scope_key,
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
        }
    });
    let view_client = client.clone();
    view! { <div class="workflow-stack"><section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Trust and reachability"</p><h2>"Network boundaries"</h2><p>"Boundaries name verifiable network identity. Immutable revisions hold protected-transport, trusted-ingress, source, and probe policy."</p></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading network boundaries…"</p> }>{move || { let client = view_client.clone(); Suspend::new(async move { match inventory.await.as_ref() { Ok(response) if response.network_boundaries.is_empty() => view! { <p class="muted">"No network boundaries in this scope."</p> }.into_any(), Ok(response) => view! { <div class="binding-list">{response.network_boundaries.iter().cloned().map(|boundary| view! { <NetworkBoundaryCard client=client.clone() boundary=boundary/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section><NetworkBoundaryCreate client=client owner_scope_key=owner_scope_key/></div> }
}

#[component]
fn NetworkBoundaryCreate(client: ApiClient, owner_scope_key: String) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let kind = RwSignal::new("vpn".to_string());
    let provider = RwSignal::new(String::new());
    let account = RwSignal::new(String::new());
    let resource_id = RwSignal::new(String::new());
    let listener_id = RwSignal::new(String::new());
    let allowlist_id = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let identity = match boundary_identity(
            &kind.get_untracked(),
            &provider.get_untracked(),
            &account.get_untracked(),
            &resource_id.get_untracked(),
            &listener_id.get_untracked(),
            &allowlist_id.get_untracked(),
        ) {
            Ok(identity) => identity,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("network-boundary-create");
        let request = aos_proto_types::PlanNetworkBoundaryMutationRequest {
            stable_id: String::new(),
            owner_scope_key: owner_scope_key.clone(),
            name: name.get_untracked().trim().to_string(),
            kind: kind.get_untracked(),
            identity: Some(aos_proto_types::NetworkBoundaryIdentity {
                identity: Some(identity),
            }),
            initial_revision: Some(default_boundary_revision()),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: String::new(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_CREATE_NETWORK_BOUNDARY_PATH,
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
                .call::<_, aos_proto_types::NetworkBoundaryResponse>(
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_CREATE_NETWORK_BOUNDARY_PATH,
                    &reviewed.network_boundary_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="panel editor-panel"><h2>"Create network boundary"</h2><form class="editor-form" on:submit=on_plan><label><span>"Name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label><label><span>"Identity kind"</span><select prop:value=move || kind.get() on:change=move |event| kind.set(event_target_value(&event))><option value="vpn">"VPN"</option><option value="vpc">"Provider network / VPC"</option><option value="tunnel">"Tunnel"</option><option value="source-allowlist">"Source allowlist"</option><option value="trusted-ingress">"Trusted ingress"</option></select></label>{move || if kind.get() == "source-allowlist" { view! { <label class="full-field"><span>"Allowlist resource ID"</span><input required prop:value=move || allowlist_id.get() on:input=move |event| allowlist_id.set(event_target_value(&event))/></label> }.into_any() } else { let needs_listener = matches!(kind.get().as_str(), "vpc" | "trusted-ingress"); view! { <label><span>"Provider"</span><input required prop:value=move || provider.get() on:input=move |event| provider.set(event_target_value(&event))/></label><label><span>"Account or tenant"</span><input required prop:value=move || account.get() on:input=move |event| account.set(event_target_value(&event))/></label><label><span>"Provider resource ID"</span><input required prop:value=move || resource_id.get() on:input=move |event| resource_id.set(event_target_value(&event))/></label>{needs_listener.then(|| view! { <label><span>"Listener ID"</span><input required prop:value=move || listener_id.get() on:input=move |event| listener_id.set(event_target_value(&event))/></label> })} }.into_any() }}<div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn NetworkBoundaryCard(
    client: ApiClient,
    boundary: aos_proto_types::NetworkBoundary,
) -> impl IntoView {
    let has_default_revision = boundary.default_revision > 0;
    view! { <details class="binding-card"><summary><div><span class="resource-kind">{boundary.kind.clone()}</span><h3>{boundary.name.clone()}</h3><code>{boundary.stable_id.clone()}</code></div><div class="binding-summary-state"><StatusBadge state=format!("revision {}", boundary.default_revision) positive=has_default_revision/></div></summary><div class="binding-details"><div class="resource-identity"><div><span>"Owner"</span><code>{boundary.owner_scope_key.clone()}</code></div><div><span>"Identity fingerprint"</span><code>{boundary.identity_fingerprint.clone()}</code></div><div><span>"Version"</span><code>{boundary.resource_version.clone()}</code></div></div><BoundaryRevisions client=client.clone() boundary=boundary.clone()/><div class="subworkflow-grid"><BoundaryRevisionCreate client=client.clone() boundary=boundary.clone()/><BoundaryGrants client=client.clone() boundary=boundary.clone()/></div><BoundaryDelete client=client boundary=boundary/></div></details> }
}

#[component]
fn BoundaryRevisions(
    client: ApiClient,
    boundary: aos_proto_types::NetworkBoundary,
) -> impl IntoView {
    let boundary_id = boundary.stable_id;
    let read_client = client.clone();
    let revisions = LocalResource::new(move || {
        let client = read_client.clone();
        let boundary_id = boundary_id.clone();
        async move {
            client
                .call::<_, aos_proto_types::ListNetworkBoundaryRevisionsResponse>(
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_LIST_NETWORK_BOUNDARY_REVISIONS_PATH,
                    &aos_proto_types::ListNetworkBoundaryRevisionsRequest {
                        boundary_id,
                        page_size: 100,
                        page_token: String::new(),
                    },
                )
                .await
        }
    });
    view! { <section class="subworkflow"><h4>"Immutable revisions"</h4><Suspense fallback=move || view! { <p class="loading-row">"Loading revisions…"</p> }>{move || { let client = client.clone(); Suspend::new(async move { match revisions.await.as_ref() { Ok(response) => view! { <div class="compact-list">{response.revisions.iter().cloned().map(|revision| view! { <BoundaryRevisionRow client=client.clone() revision=revision/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section> }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryLifecycleAction {
    Activate,
    Retire,
}

#[component]
fn BoundaryRevisionRow(
    client: ApiClient,
    revision: aos_proto_types::NetworkBoundaryRevision,
) -> impl IntoView {
    let lifecycle = revision.lifecycle.clone().unwrap_or_default();
    let observation = revision.observation.clone().unwrap_or_default();
    let mode = RwSignal::new("overlap".to_string());
    let make_default = RwSignal::new(true);
    let pending = RwSignal::new(None::<(PendingPlan, BoundaryLifecycleAction)>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let request_revision = revision.clone();
    let lifecycle_version = lifecycle.resource_version.clone();
    let plan_action = Callback::new(move |action: BoundaryLifecycleAction| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key(match action {
            BoundaryLifecycleAction::Activate => "boundary-activate",
            BoundaryLifecycleAction::Retire => "boundary-retire",
        });
        let request = aos_proto_types::PlanNetworkBoundaryLifecycleRequest {
            boundary_id: request_revision.boundary_id.clone(),
            revision: request_revision.revision,
            activation_mode: if action == BoundaryLifecycleAction::Activate {
                mode.get_untracked()
            } else {
                String::new()
            },
            default_for_new_plans: action == BoundaryLifecycleAction::Activate
                && make_default.get_untracked(),
            expected_resource_version: lifecycle_version.clone(),
            idempotency_key: idempotency_key.clone(),
            pin_resolutions: Vec::new(),
        };
        let path = match action { BoundaryLifecycleAction::Activate => aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_ACTIVATE_NETWORK_BOUNDARY_REVISION_PATH, BoundaryLifecycleAction::Retire => aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_RETIRE_NETWORK_BOUNDARY_REVISION_PATH };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(path, &request)
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, idempotency_key));
            match result {
                Ok(reviewed) => pending.set(Some((reviewed, action))),
                Err(detail) => error.set(Some(detail)),
            };
            busy.set(false);
        });
    });
    let on_apply = Callback::new(move |()| {
        let Some((reviewed, action)) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        let path = match action {
            BoundaryLifecycleAction::Activate => {
                aos_proto_types::NETWORK_BOUNDARY_SERVICE_ACTIVATE_NETWORK_BOUNDARY_REVISION_PATH
            }
            BoundaryLifecycleAction::Retire => {
                aos_proto_types::NETWORK_BOUNDARY_SERVICE_RETIRE_NETWORK_BOUNDARY_REVISION_PATH
            }
        };
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::NetworkBoundaryRevisionResponse>(
                    path,
                    &reviewed.network_boundary_lifecycle_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <div class="revision-card"><div class="compact-list-row"><div><strong>{format!("Revision {}", revision.revision)}</strong><span>{format!("{} · observation {}", lifecycle.state, observation.state)}</span><code>{revision.content_digest}</code></div><StatusBadge state=lifecycle.state.clone() positive=lifecycle.state == "active"/></div>{matches!(lifecycle.state.as_str(), "staged" | "active" | "retiring").then(|| view! { <div class="inline-controls">{(lifecycle.state == "staged").then(|| view! { <select prop:value=move || mode.get() on:change=move |event| mode.set(event_target_value(&event))><option value="overlap">"Overlap"</option><option value="coordinated">"Coordinated"</option></select><label class="inline-check"><input type="checkbox" prop:checked=move || make_default.get() on:change=move |event| make_default.set(event_target_checked(&event))/><span>"Default for new plans"</span></label><button class="secondary-button" type="button" disabled=move || busy.get() on:click=move |_| plan_action.run(BoundaryLifecycleAction::Activate)>"Review activation"</button> })}{matches!(lifecycle.state.as_str(), "active" | "retiring").then(|| view! { <button class="danger-button" type="button" disabled=move || busy.get() on:click=move |_| plan_action.run(BoundaryLifecycleAction::Retire)>"Review retirement"</button> })}</div> })}{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|(reviewed, _)| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</div> }
}

#[component]
fn BoundaryRevisionCreate(
    client: ApiClient,
    boundary: aos_proto_types::NetworkBoundary,
) -> impl IntoView {
    let protected = RwSignal::new(true);
    let trusted = RwSignal::new("none".to_string());
    let ca_ref = RwSignal::new(String::new());
    let sans = RwSignal::new(String::new());
    let issuer = RwSignal::new(String::new());
    let audience = RwSignal::new(String::new());
    let verification_ref = RwSignal::new(String::new());
    let cidrs = RwSignal::new(String::new());
    let probe_ref = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let boundary_id = boundary.stable_id;
    let version = boundary.resource_version;
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let trusted_ingress = match trusted_ingress(
            &trusted.get_untracked(),
            &ca_ref.get_untracked(),
            &sans.get_untracked(),
            &issuer.get_untracked(),
            &audience.get_untracked(),
            &verification_ref.get_untracked(),
        ) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("boundary-revision");
        let request = aos_proto_types::PlanNetworkBoundaryRevisionRequest {
            boundary_id: boundary_id.clone(),
            spec: Some(aos_proto_types::NetworkBoundaryRevisionSpec {
                protected_transport_required: protected.get_untracked(),
                trusted_ingress: Some(trusted_ingress),
                source_allowlist_cidrs: split_values(&cidrs.get_untracked()),
                probe_location_configuration_ref: probe_ref.get_untracked().trim().to_string(),
            }),
            expected_resource_version: version.clone(),
            idempotency_key: idempotency_key.clone(),
            update_mask: vec![
                "protected_transport_required".into(),
                "trusted_ingress".into(),
                "source_allowlist_cidrs".into(),
                "probe_location_configuration_ref".into(),
            ],
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_REVISE_NETWORK_BOUNDARY_PATH,
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
                .call::<_, aos_proto_types::NetworkBoundaryRevisionResponse>(
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_REVISE_NETWORK_BOUNDARY_PATH,
                    &reviewed.network_boundary_revision_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            };
            busy.set(false);
        });
    });
    view! { <section class="subworkflow"><h4>"Stage new revision"</h4><form class="stacked-form" on:submit=on_plan><label class="inline-check"><input type="checkbox" prop:checked=move || protected.get() on:change=move |event| protected.set(event_target_checked(&event))/><span>"Require protected transport"</span></label><label><span>"Trusted ingress"</span><select prop:value=move || trusted.get() on:change=move |event| trusted.set(event_target_value(&event))><option value="none">"None"</option><option value="mtls">"mTLS"</option><option value="signed-assertion">"Signed assertion"</option></select></label>{move || match trusted.get().as_str() { "mtls" => view! { <label><span>"CA secret reference"</span><input required prop:value=move || ca_ref.get() on:input=move |event| ca_ref.set(event_target_value(&event))/></label><label><span>"Allowed client SANs"</span><textarea rows="3" prop:value=move || sans.get() on:input=move |event| sans.set(event_target_value(&event))></textarea></label> }.into_any(), "signed-assertion" => view! { <label><span>"Issuer"</span><input required prop:value=move || issuer.get() on:input=move |event| issuer.set(event_target_value(&event))/></label><label><span>"Audience"</span><input required prop:value=move || audience.get() on:input=move |event| audience.set(event_target_value(&event))/></label><label><span>"Verification-key secret reference"</span><input required prop:value=move || verification_ref.get() on:input=move |event| verification_ref.set(event_target_value(&event))/></label> }.into_any(), _ => ().into_any() }}<label><span>"Source CIDRs (one per line)"</span><textarea rows="4" prop:value=move || cidrs.get() on:input=move |event| cidrs.set(event_target_value(&event))></textarea></label><label><span>"Probe-location configuration reference"</span><input prop:value=move || probe_ref.get() on:input=move |event| probe_ref.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review revision"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn BoundaryGrants(client: ApiClient, boundary: aos_proto_types::NetworkBoundary) -> impl IntoView {
    let scope = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let boundary_id = boundary.stable_id.clone();
    let version = boundary.resource_version.clone();
    let plan_client = client.clone();
    let row_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("boundary-grant");
        let request = grant_request(
            "network_boundary",
            &boundary_id,
            0,
            &scope.get_untracked(),
            &version,
            idempotency_key.clone(),
        );
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client.call::<_, aos_proto_types::TopologyPlanResponse>(aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_GRANT_NETWORK_BOUNDARY_SCOPE_PATH, &request).await.map_err(|failure| failure.to_string()).and_then(|response| PendingPlan::from_response(response, idempotency_key));
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
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_GRANT_NETWORK_BOUNDARY_SCOPE_PATH,
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
    view! { <section class="subworkflow"><h4>"Consumer scopes"</h4><div class="compact-list">{boundary.grants.into_iter().filter(|grant| grant.state == "active").map(|grant| view! { <BoundaryGrantRow client=row_client.clone() grant=grant/> }).collect_view()}</div><form class="stacked-form" on:submit=on_plan><label><span>"Consumer scope key"</span><input required prop:value=move || scope.get() on:input=move |event| scope.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review grant"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

#[component]
fn BoundaryGrantRow(
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
        let idempotency_key = idempotency_key("boundary-revoke");
        let request = grant_request(
            &request_grant.resource_kind,
            &request_grant.resource_stable_id,
            request_grant.resource_generation,
            &request_grant.consumer_scope_key,
            &request_grant.resource_version,
            idempotency_key.clone(),
        );
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let result = client.call::<_, aos_proto_types::TopologyPlanResponse>(aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_REVOKE_NETWORK_BOUNDARY_SCOPE_PATH, &request).await.map_err(|failure| failure.to_string()).and_then(|response| PendingPlan::from_response(response, idempotency_key));
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
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_REVOKE_NETWORK_BOUNDARY_SCOPE_PATH,
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
    view! { <div class="compact-list-row"><div><code>{grant.consumer_scope_key}</code><span>{format!("{} live pins", grant.live_pin_count)}</span></div><button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review revoke"</button></div>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} }
}

#[component]
fn BoundaryDelete(client: ApiClient, boundary: aos_proto_types::NetworkBoundary) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let stable_id = boundary.stable_id;
    let version = boundary.resource_version;
    let plan_client = client.clone();
    let on_plan = move |_| {
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("boundary-delete");
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
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_PLAN_DELETE_NETWORK_BOUNDARY_PATH,
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
                    aos_proto_types::NETWORK_BOUNDARY_SERVICE_DELETE_NETWORK_BOUNDARY_PATH,
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
    view! { <section class="subworkflow danger-subworkflow"><h4>"Delete boundary"</h4><p>"Public identity is permanent; other boundaries remain blocked by endpoints, grants, routes, or live pins."</p><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_plan>"Review deletion"</button>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}</section> }
}

fn boundary_identity(
    kind: &str,
    provider: &str,
    account: &str,
    resource_id: &str,
    listener_id: &str,
    allowlist_id: &str,
) -> Result<aos_proto_types::network_boundary_identity::Identity, String> {
    use aos_proto_types::network_boundary_identity::Identity;
    if kind == "source-allowlist" {
        if allowlist_id.trim().is_empty() {
            return Err("Source allowlist identity requires an allowlist resource ID".to_string());
        }
        return Ok(Identity::SourceAllowlistId(allowlist_id.trim().to_string()));
    }
    if provider.trim().is_empty() || account.trim().is_empty() || resource_id.trim().is_empty() {
        return Err(
            "Provider boundary identity requires provider, account/tenant, and resource ID"
                .to_string(),
        );
    }
    let resource = aos_proto_types::ProviderResourceIdentity {
        provider: provider.trim().to_string(),
        account_or_tenant: account.trim().to_string(),
        resource_id: resource_id.trim().to_string(),
    };
    match kind {
        "vpn" => Ok(Identity::Vpn(resource)),
        "tunnel" => Ok(Identity::Tunnel(resource)),
        "vpc" | "trusted-ingress" => {
            if listener_id.trim().is_empty() {
                return Err("Provider-network identity requires a listener ID".to_string());
            }
            let network = aos_proto_types::ProviderNetworkIdentity {
                provider: provider.trim().to_string(),
                account_or_tenant: account.trim().to_string(),
                resource_id: resource_id.trim().to_string(),
                listener_id: listener_id.trim().to_string(),
            };
            if kind == "vpc" {
                Ok(Identity::ProviderNetwork(network))
            } else {
                Ok(Identity::TrustedIngress(network))
            }
        }
        _ => Err("Unsupported network-boundary kind".to_string()),
    }
}
fn default_boundary_revision() -> aos_proto_types::NetworkBoundaryRevisionSpec {
    aos_proto_types::NetworkBoundaryRevisionSpec {
        protected_transport_required: true,
        trusted_ingress: Some(aos_proto_types::TrustedIngressConfiguration {
            configuration: Some(
                aos_proto_types::trusted_ingress_configuration::Configuration::None(true),
            ),
        }),
        source_allowlist_cidrs: Vec::new(),
        probe_location_configuration_ref: String::new(),
    }
}
fn trusted_ingress(
    kind: &str,
    ca_ref: &str,
    sans: &str,
    issuer: &str,
    audience: &str,
    verification_ref: &str,
) -> Result<aos_proto_types::TrustedIngressConfiguration, String> {
    use aos_proto_types::trusted_ingress_configuration::Configuration;
    let configuration = match kind {
        "none" => Configuration::None(true),
        "mtls" if !ca_ref.trim().is_empty() => {
            Configuration::Mtls(aos_proto_types::MtlsTrustedIngress {
                ca_secret_ref: ca_ref.trim().to_string(),
                client_sans: split_values(sans),
            })
        }
        "signed-assertion"
            if !issuer.trim().is_empty()
                && !audience.trim().is_empty()
                && !verification_ref.trim().is_empty() =>
        {
            Configuration::SignedAssertion(aos_proto_types::SignedAssertionTrustedIngress {
                issuer: issuer.trim().to_string(),
                audience: audience.trim().to_string(),
                verification_key_secret_ref: verification_ref.trim().to_string(),
            })
        }
        "mtls" => return Err("mTLS trusted ingress requires a CA secret reference".to_string()),
        "signed-assertion" => {
            return Err(
                "Signed-assertion ingress requires issuer, audience, and verification key"
                    .to_string(),
            )
        }
        _ => return Err("Unsupported trusted-ingress mode".to_string()),
    };
    Ok(aos_proto_types::TrustedIngressConfiguration {
        configuration: Some(configuration),
    })
}
fn grant_request(
    resource_kind: &str,
    resource_id: &str,
    generation: i64,
    scope: &str,
    version: &str,
    idempotency_key: String,
) -> aos_proto_types::PlanConsumerScopeGrantRequest {
    aos_proto_types::PlanConsumerScopeGrantRequest {
        resource_kind: resource_kind.to_string(),
        resource_stable_id: resource_id.to_string(),
        resource_generation: generation,
        consumer_scope_key: scope.trim().to_string(),
        expected_resource_version: version.to_string(),
        idempotency_key,
        pin_resolutions: Vec::new(),
    }
}
fn split_values(value: &str) -> Vec<String> {
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}
fn reload() {
    if let Some(window) = leptos::web_sys::window() {
        let _ = window.location().reload();
    }
}

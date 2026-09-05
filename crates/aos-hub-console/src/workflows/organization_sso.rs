//! Organization OIDC and verified email-domain workflows.
//!
//! Client credentials enter only the reviewed set request and are never
//! repopulated from API responses. Domain verification operates against the
//! exact DNS challenge revision displayed to the operator.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::{ApiClient, TransportError};

use super::placements::PlacementWorkflow;

/// Renders organization SSO workflows and delegates unrelated pages onward.
#[component]
pub(super) fn OrganizationSsoWorkflow(route: ConsoleRoute, client: ApiClient) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Organization { slug }, "sso") => view! {
            <OrganizationSso client=client organization=slug.clone()/>
        }
        .into_any(),
        _ => view! { <PlacementWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn OrganizationSso(client: ApiClient, organization: String) -> impl IntoView {
    view! {
        <div class="workflow-stack">
            <IdentityProviderEditor client=client.clone() organization=organization.clone()/>
            <OrganizationDomains client=client organization=organization/>
        </div>
    }
}

#[component]
fn IdentityProviderEditor(client: ApiClient, organization: String) -> impl IntoView {
    let read_client = client.clone();
    let read_org = organization.clone();
    let provider = LocalResource::new(move || {
        let client = read_client.clone();
        let org_slug = read_org.clone();
        async move {
            match client
                .call::<_, aos_proto_types::IdentityProviderResponse>(
                    aos_proto_types::IDENTITY_SERVICE_GET_IDENTITY_PROVIDER_PATH,
                    &aos_proto_types::GetIdentityProviderRequest { org_slug },
                )
                .await
            {
                Ok(response) => Ok(response.identity_provider),
                Err(TransportError::Http { status: 404, .. }) => Ok(None),
                Err(failure) => Err(failure.to_string()),
            }
        }
    });

    view! {
        <section class="panel editor-panel">
            <p class="section-kicker">"Federated identity"</p><h2>"OIDC identity provider"</h2>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading identity provider…"</p> }>
                {move || {
                    let client = client.clone();
                    let organization = organization.clone();
                    Suspend::new(async move {
                        match provider.await.as_ref() {
                            Ok(current) => view! { <IdentityProviderForm client=client organization=organization current=current.clone()/> }.into_any(),
                            Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
        </section>
    }
}

#[component]
fn IdentityProviderForm(
    client: ApiClient,
    organization: String,
    current: Option<aos_proto_types::IdentityProvider>,
) -> impl IntoView {
    let existing = current.clone().unwrap_or_default();
    let configured = current.is_some();
    let issuer = RwSignal::new(existing.issuer);
    let authorization_endpoint = RwSignal::new(existing.authorization_endpoint);
    let token_endpoint = RwSignal::new(existing.token_endpoint);
    let jwks_uri = RwSignal::new(existing.jwks_uri);
    let client_id = RwSignal::new(existing.client_id);
    let client_secret = RwSignal::new(String::new());
    let replace_client_secret = RwSignal::new(false);
    let scopes = RwSignal::new(if existing.scopes.is_empty() {
        "openid email profile".to_string()
    } else {
        existing.scopes
    });
    let groups_claim = RwSignal::new(existing.groups_claim);
    let role_map_json = RwSignal::new(if existing.role_map_json.is_empty() {
        "{}".to_string()
    } else {
        existing.role_map_json
    });
    let allow_jit = RwSignal::new(existing.allow_jit);
    let enforce_sso = RwSignal::new(existing.enforce_sso);
    let default_role = RwSignal::new(if existing.default_role.is_empty() {
        "viewer".to_string()
    } else {
        existing.default_role
    });
    let expected_version = current
        .as_ref()
        .map(|value| value.resource_version.clone())
        .unwrap_or_else(|| "absent".to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let remove_pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let plan_org = organization.clone();
    let plan_version = expected_version.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        if serde_json::from_str::<serde_json::Value>(&role_map_json.get_untracked())
            .map(|value| !value.is_object())
            .unwrap_or(true)
        {
            error.set(Some("Role mapping must be a JSON object".to_string()));
            return;
        }
        let idempotency_key = idempotency_key("identity-provider-set");
        let request = aos_proto_types::PlanSetIdentityProviderRequest {
            org_slug: plan_org.clone(),
            issuer: issuer.get_untracked().trim().to_string(),
            authorization_endpoint: authorization_endpoint.get_untracked().trim().to_string(),
            token_endpoint: token_endpoint.get_untracked().trim().to_string(),
            jwks_uri: jwks_uri.get_untracked().trim().to_string(),
            client_id: client_id.get_untracked().trim().to_string(),
            client_secret: client_secret.get_untracked(),
            replace_client_secret: replace_client_secret.get_untracked(),
            scopes: scopes.get_untracked().trim().to_string(),
            groups_claim: groups_claim.get_untracked().trim().to_string(),
            role_map_json: role_map_json.get_untracked(),
            allow_jit: allow_jit.get_untracked(),
            enforce_sso: enforce_sso.get_untracked(),
            default_role: default_role.get_untracked(),
            expected_resource_version: plan_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_SET_IDENTITY_PROVIDER_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let remove_client = client.clone();
    let remove_org = organization;
    let remove_version = expected_version;
    let on_remove = move |_| {
        let idempotency_key = idempotency_key("identity-provider-remove");
        let request = aos_proto_types::PlanRemoveIdentityProviderRequest {
            org_slug: remove_org.clone(),
            expected_resource_version: remove_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            remove_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_REMOVE_IDENTITY_PROVIDER_PATH,
            request,
            idempotency_key,
            remove_pending,
            error,
            busy,
        );
    };
    let on_apply = apply::<aos_proto_types::IdentityProviderResponse>(
        client.clone(),
        aos_proto_types::IDENTITY_SERVICE_SET_IDENTITY_PROVIDER_PATH,
        pending,
        error,
        busy,
    );
    let remove_apply = apply::<aos_proto_types::DeleteTopologyResourceResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_REMOVE_IDENTITY_PROVIDER_PATH,
        remove_pending,
        error,
        busy,
    );

    view! {
        <section class="subworkflow"><h4>"Effective sign-in policy"</h4><div class="resource-identity"><div><span>"Provider"</span><strong>{if configured { "Configured" } else { "Not configured" }}</strong></div><div><span>"Client secret"</span><strong>{if existing_client_secret(current.as_ref()) { "Configured" } else { "Not configured" }}</strong></div><div><span>"SSO enforcement"</span><strong>{if enforce_sso.get_untracked() { "Required" } else { "Optional" }}</strong></div><div><span>"Just-in-time accounts"</span><strong>{if allow_jit.get_untracked() { "Enabled" } else { "Disabled" }}</strong></div></div>{current.is_some().then(|| view! { <details><summary>"Provider metadata"</summary><div class="resource-identity"><div><span>"Version"</span><code>{current.as_ref().map(|value| value.resource_version.clone()).unwrap_or_default()}</code></div></div></details> })}</section>
        <form class="editor-form" on:submit=on_plan>
            <label><span>"Issuer"</span><input required type="url" prop:value=move || issuer.get() on:input=move |event| issuer.set(event_target_value(&event))/></label>
            <label><span>"Authorization endpoint"</span><input required type="url" prop:value=move || authorization_endpoint.get() on:input=move |event| authorization_endpoint.set(event_target_value(&event))/></label>
            <label><span>"Token endpoint"</span><input required type="url" prop:value=move || token_endpoint.get() on:input=move |event| token_endpoint.set(event_target_value(&event))/></label>
            <label><span>"JWKS URI"</span><input required type="url" prop:value=move || jwks_uri.get() on:input=move |event| jwks_uri.set(event_target_value(&event))/></label>
            <label><span>"Client ID"</span><input required prop:value=move || client_id.get() on:input=move |event| client_id.set(event_target_value(&event))/></label>
            <label><span>"New client secret"</span><input type="password" autocomplete="new-password" prop:value=move || client_secret.get() on:input=move |event| client_secret.set(event_target_value(&event))/></label>
            <label class="checkbox-field"><input type="checkbox" prop:checked=move || replace_client_secret.get() on:change=move |event| replace_client_secret.set(event_target_checked(&event))/><span>"Replace or clear the current client secret"</span></label>
            <label class="checkbox-field"><input type="checkbox" prop:checked=move || enforce_sso.get() on:change=move |event| enforce_sso.set(event_target_checked(&event))/><span>"Enforce SSO for this organization"</span></label>
            <details class="advanced-controls full-field"><summary>"Advanced claims and account mapping"</summary><div class="editor-form"><label><span>"Scopes"</span><input required prop:value=move || scopes.get() on:input=move |event| scopes.set(event_target_value(&event))/></label><label><span>"Groups claim"</span><input prop:value=move || groups_claim.get() on:input=move |event| groups_claim.set(event_target_value(&event))/></label><label><span>"Default role"</span><select prop:value=move || default_role.get() on:change=move |event| default_role.set(event_target_value(&event))><option value="owner">"Owner"</option><option value="admin">"Admin"</option><option value="maintainer">"Maintainer"</option><option value="developer">"Developer"</option><option value="viewer">"Viewer"</option></select></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || allow_jit.get() on:change=move |event| allow_jit.set(event_target_checked(&event))/><span>"Allow just-in-time user creation"</span></label><label class="full-field"><span>"Group-to-role mapping (JSON object)"</span><textarea required prop:value=move || role_map_json.get() on:input=move |event| role_map_json.set(event_target_value(&event))></textarea></label></div></details>
            <div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review OIDC configuration"</button>{current.is_some().then(|| view! { <button class="danger-button" type="button" disabled=move || busy.get() on:click=on_remove>"Review removal"</button> })}</div>
        </form>
        <PlanReview pending=pending error=error busy=busy on_apply=on_apply/>
        <PlanReview pending=remove_pending error=error busy=busy on_apply=remove_apply/>
    }
}

#[component]
fn OrganizationDomains(client: ApiClient, organization: String) -> impl IntoView {
    let list_client = client.clone();
    let list_org = organization.clone();
    let domains = LocalResource::new(move || {
        let client = list_client.clone();
        let org_slug = list_org.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListOrganizationDomainsResponse, _, _, _>(
                    aos_proto_types::IDENTITY_SERVICE_LIST_ORGANIZATION_DOMAINS_PATH,
                    move |page_token| aos_proto_types::ListOrganizationDomainsRequest {
                        org_slug: org_slug.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.domains, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let claim_org = organization.clone();

    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Identity ownership"</p><h2>"Organization email domains"</h2><p>"Verified DNS claims bind email domains to this organization's SSO and invitation policy."</p></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading email domains…"</p> }>
                {move || {
                    let client = view_client.clone();
                    Suspend::new(async move {
                        match domains.await.as_ref() {
                            Ok(domains) if domains.is_empty() => view! { <p class="muted">"No email domains claimed."</p> }.into_any(),
                            Ok(domains) => view! { <div class="binding-list">{domains.iter().cloned().map(|domain| view! { <OrganizationDomainCard client=client.clone() domain=domain/> }).collect_view()}</div> }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            <details class="advanced-controls"><summary>"Claim another email domain"</summary><DomainClaim client=client organization=claim_org/></details>
        </section>
    }
}

#[component]
fn DomainClaim(client: ApiClient, organization: String) -> impl IntoView {
    let domain = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let idempotency_key = idempotency_key("organization-domain-claim");
        let request = aos_proto_types::PlanClaimOrganizationDomainRequest {
            org_slug: organization.clone(),
            domain: domain.get_untracked().trim().to_lowercase(),
            expected_resource_version: "absent".to_string(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_CLAIM_ORGANIZATION_DOMAIN_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply::<aos_proto_types::OrganizationDomainResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_CLAIM_ORGANIZATION_DOMAIN_PATH,
        pending,
        error,
        busy,
    );

    view! {
        <section class="subworkflow"><h4>"Claim email domain"</h4><form class="stacked-form" on:submit=on_plan><label><span>"Domain"</span><input required prop:value=move || domain.get() on:input=move |event| domain.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review claim"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
    }
}

#[component]
fn OrganizationDomainCard(
    client: ApiClient,
    domain: aos_proto_types::OrganizationDomain,
) -> impl IntoView {
    let verify_pending = RwSignal::new(None::<PendingPlan>);
    let rotate_pending = RwSignal::new(None::<PendingPlan>);
    let release_pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let verify_client = client.clone();
    let verify_domain = domain.clone();
    let on_verify = move |_| {
        let idempotency_key = idempotency_key("organization-domain-verify");
        let request = aos_proto_types::PlanVerifyOrganizationDomainRequest {
            org_slug: verify_domain.org_slug.clone(),
            domain: verify_domain.domain.clone(),
            expected_resource_version: verify_domain.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            verify_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_VERIFY_ORGANIZATION_DOMAIN_PATH,
            request,
            idempotency_key,
            verify_pending,
            error,
            busy,
        );
    };
    let rotate_client = client.clone();
    let rotate_domain = domain.clone();
    let on_rotate = move |_| {
        let idempotency_key = idempotency_key("organization-domain-rotate");
        let request = aos_proto_types::PlanClaimOrganizationDomainRequest {
            org_slug: rotate_domain.org_slug.clone(),
            domain: rotate_domain.domain.clone(),
            expected_resource_version: rotate_domain.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            rotate_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_CLAIM_ORGANIZATION_DOMAIN_PATH,
            request,
            idempotency_key,
            rotate_pending,
            error,
            busy,
        );
    };
    let release_client = client.clone();
    let release_domain = domain.clone();
    let on_release = move |_| {
        let idempotency_key = idempotency_key("organization-domain-release");
        let request = aos_proto_types::PlanReleaseOrganizationDomainRequest {
            org_slug: release_domain.org_slug.clone(),
            domain: release_domain.domain.clone(),
            expected_resource_version: release_domain.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan(
            release_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_RELEASE_ORGANIZATION_DOMAIN_PATH,
            request,
            idempotency_key,
            release_pending,
            error,
            busy,
        );
    };
    let verify_apply = apply::<aos_proto_types::OrganizationDomainResponse>(
        client.clone(),
        aos_proto_types::IDENTITY_SERVICE_VERIFY_ORGANIZATION_DOMAIN_PATH,
        verify_pending,
        error,
        busy,
    );
    let rotate_apply = apply::<aos_proto_types::OrganizationDomainResponse>(
        client.clone(),
        aos_proto_types::IDENTITY_SERVICE_CLAIM_ORGANIZATION_DOMAIN_PATH,
        rotate_pending,
        error,
        busy,
    );
    let release_apply = apply::<aos_proto_types::DeleteTopologyResourceResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_RELEASE_ORGANIZATION_DOMAIN_PATH,
        release_pending,
        error,
        busy,
    );
    let pending_state = domain.state == "pending";

    view! {
        <details class="binding-card"><summary><div><span class="resource-kind">"email domain"</span><h3>{domain.domain}</h3><code>{domain.resource_version}</code></div><StatusBadge state=domain.state.clone() positive=domain.state == "verified"/></summary><div class="binding-details">{pending_state.then(|| view! { <section class="subworkflow"><h4>"DNS TXT challenge"</h4><code>{domain.txt_challenge}</code><p>"Publish this exact value before requesting verification."</p></section> })}<div class="form-actions">{pending_state.then(|| view! { <button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_verify>"Review verification"</button> })}<button class="secondary-button" type="button" disabled=move || busy.get() on:click=on_rotate>"Review challenge rotation"</button><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_release>"Review release"</button></div><PlanReview pending=verify_pending error=error busy=busy on_apply=verify_apply/><PlanReview pending=rotate_pending error=error busy=busy on_apply=rotate_apply/><PlanReview pending=release_pending error=error busy=busy on_apply=release_apply/></div></details>
    }
}

#[component]
fn PlanReview(
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! {
        {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
        {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
    }
}

fn plan<Req>(
    client: ApiClient,
    path: &'static str,
    request: Req,
    idempotency_key: String,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) where
    Req: serde::Serialize + 'static,
{
    busy.set(true);
    error.set(None);
    spawn_local(async move {
        let result = client
            .call::<_, aos_proto_types::TopologyPlanResponse>(path, &request)
            .await
            .map_err(|failure| failure.to_string())
            .and_then(|response| PendingPlan::from_response(response, idempotency_key));
        match result {
            Ok(reviewed) => pending.set(Some(reviewed)),
            Err(detail) => error.set(Some(detail)),
        }
        busy.set(false);
    });
}

fn apply<Resp>(
    client: ApiClient,
    path: &'static str,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) -> Callback<()>
where
    Resp: serde::de::DeserializeOwned + 'static,
{
    Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, Resp>(path, &reviewed.topology_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

fn existing_client_secret(provider: Option<&aos_proto_types::IdentityProvider>) -> bool {
    provider.is_some_and(|value| value.client_secret_configured)
}

fn reload() {
    crate::app::refresh();
}

//! Organization service-account, membership, and invitation workflows.
//!
//! Memberships are point-addressed by principal and scope in the API. The UI
//! therefore performs an exact lookup before exposing reviewed replacement or
//! removal, while service accounts and invitations use normal inventories.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HelpTooltip, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::route::{ConsoleRoute, ConsoleScope};
use crate::transport::ApiClient;

use super::organization_sso::OrganizationSsoWorkflow;

/// Renders organization IAM workflows and delegates unrelated pages onward.
#[component]
pub(super) fn OrganizationIdentityWorkflow(
    route: ConsoleRoute,
    client: ApiClient,
) -> impl IntoView {
    match (&route.scope, route.page.key) {
        (ConsoleScope::Organization { slug }, "identity") => view! {
            <ServiceAccounts client=client organization=slug.clone()/>
        }
        .into_any(),
        (ConsoleScope::Organization { slug }, "members") => view! {
            <OrganizationMembers client=client organization=slug.clone()/>
        }
        .into_any(),
        _ => view! { <OrganizationSsoWorkflow route=route client=client/> }.into_any(),
    }
}

#[component]
fn ServiceAccounts(client: ApiClient, organization: String) -> impl IntoView {
    let can_manage = client.allows("members.manage");
    let list_client = client.clone();
    let list_org = organization.clone();
    let accounts = LocalResource::new(move || {
        let client = list_client.clone();
        let org_slug = list_org.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListServiceAccountsResponse, _, _, _>(
                    aos_proto_types::IDENTITY_SERVICE_LIST_SERVICE_ACCOUNTS_PATH,
                    move |page_token| aos_proto_types::ListServiceAccountsRequest {
                        org_slug: org_slug.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.service_accounts, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let create_org = organization.clone();

    view! {
        <div class="workflow-stack">
            <section class="panel resource-panel">
                <div class="section-heading"><div><p class="section-kicker">"Machine identity"</p><h2>"Service accounts"<HelpTooltip term="Service accounts" summary="Non-human principals receive scoped memberships and issue separately revocable access tokens."/></h2></div></div>
                <Suspense fallback=move || view! { <p class="loading-row">"Loading service accounts…"</p> }>
                    {move || {
                        let client = view_client.clone();
                        Suspend::new(async move {
                            match accounts.await.as_ref() {
                                Ok(accounts) if accounts.is_empty() => view! { <p class="muted">"No service accounts in this organization."</p> }.into_any(),
                                Ok(accounts) => view! { <div class="binding-list">{accounts.iter().cloned().map(|account| view! { <ServiceAccountCard client=client.clone() account=account can_manage=can_manage/> }).collect_view()}</div> }.into_any(),
                                Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                            }
                        })
                    }}
                </Suspense>
            </section>
            {if can_manage { view! { <details class="panel advanced-controls"><summary>"Create service account"</summary><ServiceAccountCreate client=client organization=create_org/></details> }.into_any() } else { view! { <section class="panel"><p class="muted">"You have read-only access to organization identity."</p></section> }.into_any() }}
        </div>
    }
}

#[component]
fn ServiceAccountCreate(client: ApiClient, organization: String) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let client = plan_client.clone();
        let idempotency_key = idempotency_key("service-account-create");
        let request = aos_proto_types::PlanCreateServiceAccountRequest {
            org_slug: organization.clone(),
            name: name.get_untracked().trim().to_string(),
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
        };
        plan_identity(
            client,
            aos_proto_types::IDENTITY_SERVICE_PLAN_CREATE_SERVICE_ACCOUNT_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply_topology::<aos_proto_types::ServiceAccountResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_CREATE_SERVICE_ACCOUNT_PATH,
        pending,
        error,
        busy,
        true,
    );

    view! {
        <section class="subworkflow"><h4>"New machine identity"</h4><p>"Create a non-human principal here, then grant its membership from the Members page and issue credentials from Access tokens."</p><form class="editor-form" on:submit=on_plan><label><span>"Name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Review creation"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
    }
}

#[component]
fn ServiceAccountCard(
    client: ApiClient,
    account: aos_proto_types::ServiceAccount,
    can_manage: bool,
) -> impl IntoView {
    let new_name = RwSignal::new(account.name.clone());
    let update_pending = RwSignal::new(None::<PendingPlan>);
    let delete_pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let update_client = client.clone();
    let update_account = account.clone();
    let on_update = move |event: SubmitEvent| {
        event.prevent_default();
        let idempotency_key = idempotency_key("service-account-update");
        let request = aos_proto_types::PlanUpdateServiceAccountRequest {
            org_slug: update_account.org_slug.clone(),
            name: update_account.name.clone(),
            new_name: new_name.get_untracked().trim().to_string(),
            expected_resource_version: update_account.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan_identity(
            update_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_UPDATE_SERVICE_ACCOUNT_PATH,
            request,
            idempotency_key,
            update_pending,
            error,
            busy,
        );
    };
    let delete_client = client.clone();
    let delete_account = account.clone();
    let on_delete = move |_| {
        let idempotency_key = idempotency_key("service-account-delete");
        let request = aos_proto_types::PlanDeleteServiceAccountRequest {
            org_slug: delete_account.org_slug.clone(),
            name: delete_account.name.clone(),
            expected_resource_version: delete_account.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan_identity(
            delete_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_DELETE_SERVICE_ACCOUNT_PATH,
            request,
            idempotency_key,
            delete_pending,
            error,
            busy,
        );
    };
    let update_apply = apply_topology::<aos_proto_types::ServiceAccountResponse>(
        client.clone(),
        aos_proto_types::IDENTITY_SERVICE_UPDATE_SERVICE_ACCOUNT_PATH,
        update_pending,
        error,
        busy,
        true,
    );
    let delete_apply = apply_topology::<aos_proto_types::DeleteTopologyResourceResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_DELETE_SERVICE_ACCOUNT_PATH,
        delete_pending,
        error,
        busy,
        true,
    );

    view! {
        <details class="binding-card"><summary><div><span class="resource-kind">"service account"</span><h3>{account.name}</h3><code>{format!("principal id {}", account.id)}</code></div><StatusBadge state="active".to_string() positive=true/></summary><div class="binding-details"><div class="resource-identity"><div><span>"Version"</span><code>{account.resource_version}</code></div></div>{if can_manage { view! { <div class="subworkflow-grid"><section class="subworkflow"><h4>"Rename"</h4><form class="stacked-form" on:submit=on_update><label><span>"New name"</span><input required prop:value=move || new_name.get() on:input=move |event| new_name.set(event_target_value(&event))/></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review rename"</button></form><PlanReview pending=update_pending error=error busy=busy on_apply=update_apply/></section><section class="subworkflow danger-subworkflow"><h4>"Delete service account"</h4><p>"Deletion also removes this principal's direct memberships."</p><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_delete>"Review deletion"</button><PlanReview pending=delete_pending error=error busy=busy on_apply=delete_apply/></section></div> }.into_any() } else { view! { <p class="muted">"You can inspect this service account but cannot change it."</p> }.into_any() }}</div></details>
    }
}

#[component]
fn OrganizationMembers(client: ApiClient, organization: String) -> impl IntoView {
    let can_manage = client.allows("members.manage");
    view! {
        <div class="workflow-stack">
            <MembershipLookup client=client.clone() organization=organization.clone() can_manage=can_manage/>
            <Invitations client=client organization=organization can_manage=can_manage/>
        </div>
    }
}

#[component]
fn MembershipLookup(client: ApiClient, organization: String, can_manage: bool) -> impl IntoView {
    let principal_kind = RwSignal::new("user".to_string());
    let principal_ref = RwSignal::new(String::new());
    let scope = RwSignal::new(organization);
    let loaded = RwSignal::new(None::<aos_proto_types::MembershipResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let lookup_client = client.clone();
    let on_lookup = move |event: SubmitEvent| {
        event.prevent_default();
        let client = lookup_client.clone();
        let request = aos_proto_types::GetMembershipRequest {
            principal_kind: principal_kind.get_untracked(),
            principal_ref: principal_ref.get_untracked().trim().to_string(),
            scope: scope.get_untracked().trim().to_string(),
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::MembershipResponse>(
                    aos_proto_types::IDENTITY_SERVICE_GET_MEMBERSHIP_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => loaded.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel editor-panel"><div class="section-heading"><div><p class="section-kicker">"Direct access"</p><h2>"Members"<HelpTooltip term="Members" summary="Look up a user or service account at this organization or one of its child scopes. Role changes replace the exact direct grant."/></h2></div></div><form class="editor-form" on:submit=on_lookup><label><span>"Principal kind"</span><select prop:value=move || principal_kind.get() on:change=move |event| principal_kind.set(event_target_value(&event))><option value="user">"User"</option><option value="service_account">"Service account"</option></select></label><label><span>"Email or service-account path"</span><input required placeholder="person@example.com or org/name" prop:value=move || principal_ref.get() on:input=move |event| principal_ref.set(event_target_value(&event))/></label><label><span>"Resource scope"</span><input prop:value=move || scope.get() on:input=move |event| scope.set(event_target_value(&event))/><small>"Use the organization slug for organization-wide access, or a child resource's canonical scope."</small></label><div class="form-actions"><button class="button" type="submit" disabled=move || busy.get()>"Load membership"</button></div></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || loaded.get().map(|membership| view! { <MembershipEditor client=client.clone() membership=membership can_manage=can_manage/> })}</section>
    }
}

#[component]
fn MembershipEditor(
    client: ApiClient,
    membership: aos_proto_types::MembershipResponse,
    can_manage: bool,
) -> impl IntoView {
    let role = RwSignal::new(if membership.role.is_empty() {
        "viewer".to_string()
    } else {
        membership.role.clone()
    });
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let set_client = client.clone();
    let set_membership = membership.clone();
    let on_set = move |event: SubmitEvent| {
        event.prevent_default();
        plan_membership(
            set_client.clone(),
            &set_membership,
            role.get_untracked(),
            "membership-set",
            pending,
            error,
            busy,
        );
    };
    let remove_client = client.clone();
    let remove_membership = membership.clone();
    let on_remove = move |_| {
        plan_membership(
            remove_client.clone(),
            &remove_membership,
            String::new(),
            "membership-remove",
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply_topology::<aos_proto_types::MembershipResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_SET_MEMBERSHIP_PATH,
        pending,
        error,
        busy,
        true,
    );

    view! {
        <section class="subworkflow"><div class="resource-identity"><div><span>"Principal"</span><code>{format!("{}:{}", membership.principal_kind, membership.principal_ref)}</code></div><div><span>"Scope"</span><code>{membership.scope}</code></div><div><span>"Current role"</span><strong>{if membership.role.is_empty() { "absent".to_string() } else { membership.role }}</strong></div><div><span>"Version"</span><code>{membership.resource_version}</code></div></div>{if can_manage { view! { <form class="stacked-form" on:submit=on_set><label><span>"Replacement role"</span><select prop:value=move || role.get() on:change=move |event| role.set(event_target_value(&event))><option value="owner">"Owner"</option><option value="admin">"Admin"</option><option value="maintainer">"Maintainer"</option><option value="developer">"Developer"</option><option value="viewer">"Viewer"</option></select></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review role"</button><button class="danger-button" type="button" disabled=move || busy.get() on:click=on_remove>"Review removal"</button></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/> }.into_any() } else { view! { <p class="muted">"You can inspect this direct membership but cannot change it."</p> }.into_any() }}</section>
    }
}

#[component]
fn Invitations(client: ApiClient, organization: String, can_manage: bool) -> impl IntoView {
    let list_client = client.clone();
    let list_org = organization.clone();
    let invitations = LocalResource::new(move || {
        let client = list_client.clone();
        let org_slug = list_org.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListInvitationsResponse, _, _, _>(
                    aos_proto_types::IDENTITY_SERVICE_LIST_INVITATIONS_PATH,
                    move |page_token| aos_proto_types::ListInvitationsRequest {
                        org_slug: org_slug.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.invitations, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let create_org = organization.clone();

    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Human onboarding"</p><h2>"Invitations"<HelpTooltip term="Invitations" summary="Invitation secrets are displayed once after reviewed creation and delivered out of band."/></h2></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading invitations…"</p> }>
                {move || {
                    let client = view_client.clone();
                    Suspend::new(async move {
                        match invitations.await.as_ref() {
                            Ok(invitations) if invitations.is_empty() => view! { <p class="muted">"No invitation history."</p> }.into_any(),
                            Ok(invitations) => view! { <div class="compact-list">{invitations.iter().cloned().map(|invitation| view! { <InvitationRow client=client.clone() invitation=invitation can_manage=can_manage/> }).collect_view()}</div> }.into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            {if can_manage { view! { <details class="advanced-controls"><summary>"Invite a member"</summary><InvitationCreate client=client organization=create_org/></details> }.into_any() } else { view! { <p class="muted">"You can inspect invitations but cannot create or cancel them."</p> }.into_any() }}
        </section>
    }
}

#[component]
fn InvitationCreate(client: ApiClient, organization: String) -> impl IntoView {
    let email = RwSignal::new(String::new());
    let scope = RwSignal::new(organization.clone());
    let role = RwSignal::new("viewer".to_string());
    let ttl = RwSignal::new("0".to_string());
    let pending = RwSignal::new(None::<PendingPlan>);
    let secret = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let ttl_secs = match ttl.get_untracked().parse::<i64>() {
            Ok(value) if value >= 0 => value,
            _ => {
                error.set(Some(
                    "Invitation lifetime must be a non-negative integer".to_string(),
                ));
                return;
            }
        };
        let idempotency_key = idempotency_key("invitation-create");
        let request = aos_proto_types::PlanCreateInvitationRequest {
            org_slug: organization.clone(),
            email: email.get_untracked().trim().to_lowercase(),
            scope: scope.get_untracked().trim().to_string(),
            role: role.get_untracked(),
            ttl_secs,
            expected_resource_version: String::new(),
            idempotency_key: idempotency_key.clone(),
        };
        plan_identity(
            plan_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_CREATE_INVITATION_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = Callback::new(move |()| {
        let Some(reviewed) = pending.get_untracked() else {
            return;
        };
        let client = client.clone();
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::InvitationResponse>(
                    aos_proto_types::IDENTITY_SERVICE_CREATE_INVITATION_PATH,
                    &reviewed.topology_apply(),
                )
                .await
            {
                Ok(response) => {
                    secret.set(Some(response.secret));
                    pending.set(None);
                }
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <section class="subworkflow"><h4>"Create invitation"</h4><form class="editor-form" on:submit=on_plan><label><span>"Email"</span><input required type="email" prop:value=move || email.get() on:input=move |event| email.set(event_target_value(&event))/></label><label><span>"Granted scope"</span><input prop:value=move || scope.get() on:input=move |event| scope.set(event_target_value(&event))/></label><label><span>"Role"</span><select prop:value=move || role.get() on:change=move |event| role.set(event_target_value(&event))><option value="owner">"Owner"</option><option value="admin">"Admin"</option><option value="maintainer">"Maintainer"</option><option value="developer">"Developer"</option><option value="viewer">"Viewer"</option></select></label><label><span>"Lifetime seconds (0 uses default)"</span><input type="number" min="0" prop:value=move || ttl.get() on:input=move |event| ttl.set(event_target_value(&event))/></label><div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review invitation"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/>{move || secret.get().map(|value| view! { <div class="credential-reveal"><strong>"Invitation secret — copy it now"</strong><code>{value}</code><p>"This secret cannot be retrieved again."</p></div> })}</section>
    }
}

#[component]
fn InvitationRow(
    client: ApiClient,
    invitation: aos_proto_types::Invitation,
    can_manage: bool,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let cancellable = can_manage && invitation.state == "pending";
    let request_invitation = invitation.clone();
    let plan_client = client.clone();
    let on_plan = move |_| {
        let idempotency_key = idempotency_key("invitation-cancel");
        let request = aos_proto_types::PlanCancelInvitationRequest {
            org_slug: request_invitation.org_slug.clone(),
            invitation_id: request_invitation.invitation_id,
            expected_resource_version: request_invitation.resource_version.clone(),
            idempotency_key: idempotency_key.clone(),
        };
        plan_identity(
            plan_client.clone(),
            aos_proto_types::IDENTITY_SERVICE_PLAN_CANCEL_INVITATION_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply_topology::<aos_proto_types::InvitationResponse>(
        client,
        aos_proto_types::IDENTITY_SERVICE_CANCEL_INVITATION_PATH,
        pending,
        error,
        busy,
        true,
    );

    view! {
        <div class="revision-card"><div class="compact-list-row"><div><strong>{invitation.email}</strong><span>{format!("{} on {} · expires {}", invitation.role, invitation.scope, invitation.expires_at)}</span><code>{format!("invitation {}", invitation.invitation_id)}</code></div><StatusBadge state=invitation.state.clone() positive=invitation.state == "accepted"/>{cancellable.then(|| view! { <button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review cancel"</button> })}</div><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></div>
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

fn plan_membership(
    client: ApiClient,
    membership: &aos_proto_types::MembershipResponse,
    role: String,
    action: &'static str,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) {
    let idempotency_key = idempotency_key(action);
    let request = aos_proto_types::PlanSetMembershipRequest {
        principal_kind: membership.principal_kind.clone(),
        principal_ref: membership.principal_ref.clone(),
        scope: membership.scope.clone(),
        role,
        expected_resource_version: membership.resource_version.clone(),
        idempotency_key: idempotency_key.clone(),
    };
    plan_identity(
        client,
        aos_proto_types::IDENTITY_SERVICE_PLAN_SET_MEMBERSHIP_PATH,
        request,
        idempotency_key,
        pending,
        error,
        busy,
    );
}

fn plan_identity<Req>(
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

fn apply_topology<Resp>(
    client: ApiClient,
    path: &'static str,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    reload_after: bool,
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
                Ok(_) if reload_after => reload(),
                Ok(_) => pending.set(None),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

fn reload() {
    crate::app::refresh();
}

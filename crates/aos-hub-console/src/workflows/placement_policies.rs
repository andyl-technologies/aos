//! Placement selection policies and equivalence evidence.
//!
//! Policies advance through immutable revisions independently of physical
//! placement state. Equivalence records are explicit, reviewable evidence;
//! they are never inferred merely because two placements currently agree.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, PendingPlan};
use crate::transport::ApiClient;

/// Renders placement-policy inventory, revision, and test workflows.
#[component]
pub(super) fn PlacementPolicyPanel(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
) -> impl IntoView {
    let read_client = client.clone();
    let read_surface = surface.clone();
    let policies = LocalResource::new(move || {
        let client = read_client.clone();
        let surface = read_surface.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPlacementPoliciesResponse, _, _, _>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_PLACEMENT_POLICIES_PATH,
                    move |page_token| aos_proto_types::SurfaceListRequest {
                        surface: Some(surface.clone()),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.policies, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_surface = surface.clone();

    view! {
        <section class="panel resource-panel">
            <div class="section-heading"><div><p class="section-kicker">"Read selection"</p><h2>"Placement policies"</h2><p>"Immutable policy revisions select replicas by ordered failover, locality, or hash partition."</p></div></div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading placement policies…"</p> }>
                {move || { let client = view_client.clone(); let surface = view_surface.clone(); Suspend::new(async move {
                    match policies.await.as_ref() {
                        Ok(policies) if policies.is_empty() => view! { <p class="muted">"No placement policies for this surface."</p> }.into_any(),
                        Ok(policies) => view! { <div class="binding-list">{policies.iter().cloned().map(|policy| view! { <PolicyCard client=client.clone() surface=surface.clone() policy=policy/> }).collect_view()}</div> }.into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                }) }}
            </Suspense>
            <PolicyMutationForm client=client surface=surface policy=None/>
        </section>
    }
}

#[component]
fn PolicyCard(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    policy: aos_proto_types::PlacementPolicy,
) -> impl IntoView {
    let revisions_client = client.clone();
    let revisions_surface = surface.clone();
    let policy_id = policy.stable_id.clone();
    let revisions = LocalResource::new(move || {
        let client = revisions_client.clone();
        let surface = revisions_surface.clone();
        let policy_id = policy_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPlacementPolicyRevisionsResponse, _, _, _>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_PLACEMENT_POLICY_REVISIONS_PATH,
                    move |page_token| aos_proto_types::ListPlacementPolicyRevisionsRequest {
                        surface: Some(surface.clone()),
                        policy_id: policy_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.revisions, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <details class="binding-card"><summary><div><span class="resource-kind">{policy.kind.clone()}</span><h3>{policy.name.clone()}</h3><code>{policy.stable_id.clone()}</code></div><StatusBadge state=format!("revision {}", policy.current_revision) positive=true/></summary><div class="binding-details"><div class="resource-identity"><div><span>"Current digest"</span><code>{policy.current_content_digest.clone()}</code></div><div><span>"Version"</span><code>{policy.resource_version.clone()}</code></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading policy revisions…"</p> }>{move || Suspend::new(async move { match revisions.await.as_ref() { Ok(revisions) => view! { <div class="compact-list">{revisions.iter().map(|revision| view! { <div class="compact-list-row"><div><strong>{format!("Revision {}", revision.revision)}</strong><code>{revision.content_digest.clone()}</code><span>{format!("created by {}", revision.created_by)}</span></div></div> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } })}</Suspense><div class="subworkflow-grid"><PolicyMutationForm client=client.clone() surface=surface.clone() policy=Some(policy.clone())/><PolicyTest client=client surface=surface policy=policy/></div></div></details>
    }
}

#[derive(Clone, Copy)]
struct PolicySignals {
    kind: RwSignal<String>,
    members: RwSignal<String>,
    local: RwSignal<String>,
    remote: RwSignal<String>,
    boundary: RwSignal<String>,
    ranges: RwSignal<String>,
    fallback: RwSignal<String>,
    allow_remote_fallback: RwSignal<bool>,
    retry_on: RwSignal<String>,
}

impl PolicySignals {
    fn new(kind: String) -> Self {
        let kind = kind.replace('_', "-");
        Self {
            kind: RwSignal::new(if kind.is_empty() {
                "ordered-failover".to_string()
            } else {
                kind
            }),
            members: RwSignal::new(String::new()),
            local: RwSignal::new(String::new()),
            remote: RwSignal::new(String::new()),
            boundary: RwSignal::new(String::new()),
            ranges: RwSignal::new(String::new()),
            fallback: RwSignal::new(String::new()),
            allow_remote_fallback: RwSignal::new(false),
            retry_on: RwSignal::new(
                "connect-failure\ntimeout-before-headers\norigin-502\norigin-503\norigin-504"
                    .to_string(),
            ),
        }
    }
}

#[component]
fn PolicyMutationForm(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    policy: Option<aos_proto_types::PlacementPolicy>,
) -> impl IntoView {
    let policy_id = RwSignal::new(
        policy
            .as_ref()
            .map(|value| value.stable_id.clone())
            .unwrap_or_default(),
    );
    let name = RwSignal::new(
        policy
            .as_ref()
            .map(|value| value.name.clone())
            .unwrap_or_default(),
    );
    let signals = PolicySignals::new(
        policy
            .as_ref()
            .map(|value| value.kind.clone())
            .unwrap_or_default(),
    );
    let expected_version = policy
        .as_ref()
        .map(|value| value.resource_version.clone())
        .unwrap_or_else(|| "absent".to_string());
    let revising = policy.is_some();
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let desired = match build_policy(signals) {
            Ok(value) => value,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let idempotency_key = idempotency_key(if revising {
            "policy-revise"
        } else {
            "policy-create"
        });
        let request = aos_proto_types::PlanPlacementPolicyMutationRequest {
            surface: Some(surface.clone()),
            policy_id: policy_id.get_untracked().trim().to_string(),
            name: if revising {
                String::new()
            } else {
                name.get_untracked().trim().to_string()
            },
            desired: Some(desired),
            expected_resource_version: Some(expected_version.clone()),
            idempotency_key: idempotency_key.clone(),
        };
        let path = if revising {
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_REVISE_PLACEMENT_POLICY_PATH
        } else {
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_CREATE_PLACEMENT_POLICY_PATH
        };
        plan(
            plan_client.clone(),
            path,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let apply_path = if revising {
        aos_proto_types::TOPOLOGY_SERVICE_REVISE_PLACEMENT_POLICY_PATH
    } else {
        aos_proto_types::TOPOLOGY_SERVICE_CREATE_PLACEMENT_POLICY_PATH
    };
    let on_apply = apply(client, apply_path, pending, error, busy);

    view! {
        <section class=if revising { "subworkflow" } else { "subworkflow policy-create" }><h4>{if revising { "Create policy revision" } else { "Create placement policy" }}</h4><form class="editor-form" on:submit=on_plan>{(!revising).then(|| view! { <label><span>"Policy ID"</span><input required prop:value=move || policy_id.get() on:input=move |event| policy_id.set(event_target_value(&event))/></label><label><span>"Display name"</span><input required prop:value=move || name.get() on:input=move |event| name.set(event_target_value(&event))/></label> })}<PolicyFields signals=signals/><div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>{if revising { "Review revision" } else { "Review policy" }}</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section>
    }
}

#[component]
fn PolicyFields(signals: PolicySignals) -> impl IntoView {
    view! {
        <label><span>"Selection kind"</span><select prop:value=move || signals.kind.get() on:change=move |event| signals.kind.set(event_target_value(&event))><option value="ordered-failover">"Ordered failover"</option><option value="local-then-remote">"Local then remote"</option><option value="hash-partition">"Hash partition"</option></select></label>
        {move || match signals.kind.get().as_str() {
            "ordered-failover" => view! { <label class="full-field"><span>"Placements in failover order (one per line)"</span><textarea required prop:value=move || signals.members.get() on:input=move |event| signals.members.set(event_target_value(&event))></textarea></label> }.into_any(),
            "local-then-remote" => view! { <label><span>"Local boundary (stable-id@revision)"</span><input required prop:value=move || signals.boundary.get() on:input=move |event| signals.boundary.set(event_target_value(&event))/></label><label class="full-field"><span>"Local placements (one per line)"</span><textarea required prop:value=move || signals.local.get() on:input=move |event| signals.local.set(event_target_value(&event))></textarea></label><label class="full-field"><span>"Remote placements (one per line)"</span><textarea required prop:value=move || signals.remote.get() on:input=move |event| signals.remote.set(event_target_value(&event))></textarea></label><label class="checkbox-field"><input type="checkbox" prop:checked=move || signals.allow_remote_fallback.get() on:change=move |event| signals.allow_remote_fallback.set(event_target_checked(&event))/><span>"Allow remote fallback"</span></label> }.into_any(),
            "hash-partition" => view! { <label class="full-field"><span>"Ranges (start-end=primary,replica; one per line)"</span><textarea required prop:value=move || signals.ranges.get() on:input=move |event| signals.ranges.set(event_target_value(&event))></textarea></label><label class="full-field"><span>"Complete fallback placements (one per line)"</span><textarea prop:value=move || signals.fallback.get() on:input=move |event| signals.fallback.set(event_target_value(&event))></textarea></label> }.into_any(),
            _ => ().into_any(),
        }}
        <label class="full-field"><span>"Retry conditions (one per line)"</span><textarea prop:value=move || signals.retry_on.get() on:input=move |event| signals.retry_on.set(event_target_value(&event))></textarea></label>
    }
}

#[component]
fn PolicyTest(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    policy: aos_proto_types::PlacementPolicy,
) -> impl IntoView {
    let object_ref = RwSignal::new(String::new());
    let access_class = RwSignal::new("unspecified".to_string());
    let result = RwSignal::new(None::<aos_proto_types::TestPlacementPolicyRevisionResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_test = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let request = aos_proto_types::TestPlacementPolicyRevisionRequest {
            surface: Some(surface.clone()),
            policy_id: policy.stable_id.clone(),
            revision: policy.current_revision,
            object_ref: object_ref.get_untracked().trim().to_string(),
            access_class: match access_class.get_untracked().as_str() {
                "local" => aos_proto_types::AccessClass::Local as i32,
                "remote" => aos_proto_types::AccessClass::Remote as i32,
                _ => aos_proto_types::AccessClass::Unspecified as i32,
            },
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::TestPlacementPolicyRevisionResponse>(
                    aos_proto_types::TOPOLOGY_SERVICE_TEST_PLACEMENT_POLICY_REVISION_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => result.set(Some(response)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };
    view! { <section class="subworkflow"><h4>"Test current revision"</h4><form class="stacked-form" on:submit=on_test><label><span>"Object reference"</span><input required prop:value=move || object_ref.get() on:input=move |event| object_ref.set(event_target_value(&event))/></label><label><span>"Access class"</span><select prop:value=move || access_class.get() on:change=move |event| access_class.set(event_target_value(&event))><option value="unspecified">"Unspecified"</option><option value="local">"Local"</option><option value="remote">"Remote"</option></select></label><button class="secondary-button" type="submit" disabled=move || busy.get()>"Resolve selection"</button></form>{move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || result.get().map(|value| view! { <div class="resource-identity"><div><span>"Hash bucket"</span><strong>{value.bucket}</strong></div><div><span>"Selected placements"</span><code>{value.selected_placements.join(", ")}</code></div><div><span>"Decisions"</span><span>{value.decisions.join(" · ")}</span></div></div> })}</section> }
}

fn build_policy(
    signals: PolicySignals,
) -> Result<aos_proto_types::PlacementPolicyRevisionSpec, String> {
    use aos_proto_types::placement_policy_revision_spec::Selector;
    let selector = match signals.kind.get_untracked().as_str() {
        "ordered-failover" => {
            let members = lines(&signals.members.get_untracked());
            if members.is_empty() {
                return Err("Ordered failover requires at least one placement".to_string());
            }
            Selector::OrderedFailover(aos_proto_types::OrderedFailoverPlacementPolicy {
                replica_groups: members
                    .into_iter()
                    .map(|name| {
                        replica_group(vec![name], aos_proto_types::AccessClass::Unspecified, None)
                    })
                    .collect(),
            })
        }
        "local-then-remote" => {
            let local = lines(&signals.local.get_untracked());
            let remote = lines(&signals.remote.get_untracked());
            if local.is_empty() || remote.is_empty() {
                return Err("Local-then-remote requires local and remote placements".to_string());
            }
            let (boundary_id, revision) =
                generation_ref(&signals.boundary.get_untracked(), "Local boundary")?;
            let replica_groups = local
                .into_iter()
                .map(|name| replica_group(vec![name], aos_proto_types::AccessClass::Local, None))
                .chain(remote.into_iter().map(|name| {
                    replica_group(vec![name], aos_proto_types::AccessClass::Remote, None)
                }))
                .collect();
            Selector::LocalThenRemote(aos_proto_types::LocalThenRemotePlacementPolicy {
                replica_groups,
                local_boundary: Some(aos_proto_types::NetworkBoundaryRevisionRef {
                    boundary_id,
                    revision,
                }),
                allow_remote_fallback: signals.allow_remote_fallback.get_untracked(),
            })
        }
        "hash-partition" => {
            let ranges = lines(&signals.ranges.get_untracked())
                .into_iter()
                .map(|line| parse_range_group(&line))
                .collect::<Result<Vec<_>, _>>()?;
            if ranges.is_empty() {
                return Err("Hash partition requires at least one range".to_string());
            }
            Selector::HashPartition(aos_proto_types::HashPartitionPlacementPolicy {
                ranges,
                complete_fallback_placements: lines(&signals.fallback.get_untracked()),
            })
        }
        _ => return Err("Unsupported placement policy kind".to_string()),
    };
    let retry_on = lines(&signals.retry_on.get_untracked())
        .into_iter()
        .map(|condition| retry_condition(&condition))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(aos_proto_types::PlacementPolicyRevisionSpec {
        selector: Some(selector),
        failure_contract: Some(aos_proto_types::PolicyFailureContract { retry_on }),
    })
}

fn replica_group(
    names: Vec<String>,
    access: aos_proto_types::AccessClass,
    hash_range: Option<aos_proto_types::HashRangeV1>,
) -> aos_proto_types::PlacementPolicyReplicaGroup {
    aos_proto_types::PlacementPolicyReplicaGroup {
        placement_names: names,
        access_class: access as i32,
        hash_range,
    }
}

fn parse_range_group(line: &str) -> Result<aos_proto_types::PlacementPolicyReplicaGroup, String> {
    let (bounds, names) = line
        .split_once('=')
        .ok_or_else(|| "Hash ranges use start-end=primary,replica".to_string())?;
    let (start, end) = bounds
        .split_once('-')
        .ok_or_else(|| "Hash range bounds use start-end".to_string())?;
    let start = start
        .parse::<u32>()
        .map_err(|_| "Hash range start must be an integer".to_string())?;
    let end = end
        .parse::<u32>()
        .map_err(|_| "Hash range end must be an integer".to_string())?;
    let placements = names
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if start >= end || end > 65_536 || placements.is_empty() {
        return Err(
            "Hash range must satisfy 0 <= start < end <= 65536 and name placements".to_string(),
        );
    }
    Ok(replica_group(
        placements,
        aos_proto_types::AccessClass::Unspecified,
        Some(aos_proto_types::HashRangeV1 { start, end }),
    ))
}

fn retry_condition(value: &str) -> Result<i32, String> {
    let condition = match value {
        "connect-failure" => aos_proto_types::PolicyRetryCondition::ConnectFailure,
        "timeout-before-headers" => aos_proto_types::PolicyRetryCondition::TimeoutBeforeHeaders,
        "origin-429" => aos_proto_types::PolicyRetryCondition::Origin429,
        "origin-502" => aos_proto_types::PolicyRetryCondition::Origin502,
        "origin-503" => aos_proto_types::PolicyRetryCondition::Origin503,
        "origin-504" => aos_proto_types::PolicyRetryCondition::Origin504,
        "presence-mismatch" => aos_proto_types::PolicyRetryCondition::PresenceMismatch,
        "verified-corruption" => aos_proto_types::PolicyRetryCondition::VerifiedCorruption,
        _ => return Err(format!("Unsupported retry condition '{value}'")),
    };
    Ok(condition as i32)
}

/// Renders explicit placement-equivalence evidence and confirmation.
#[component]
pub(super) fn PlacementEquivalencePanel(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
) -> impl IntoView {
    let read_client = client.clone();
    let read_surface = surface.clone();
    let equivalences = LocalResource::new(move || {
        let client = read_client.clone();
        let surface = read_surface.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPlacementEquivalencesResponse, _, _, _>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_PLACEMENT_EQUIVALENCES_PATH,
                    move |page_token| aos_proto_types::SurfaceListRequest {
                        surface: Some(surface.clone()),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.equivalences, response.next_page_token),
                )
                .await
        }
    });
    let placements_client = client.clone();
    let placements_surface = surface.clone();
    let placements = LocalResource::new(move || {
        let client = placements_client.clone();
        let surface = placements_surface.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPlacementsResponse, _, _, _>(
                    aos_proto_types::TOPOLOGY_SERVICE_LIST_PLACEMENTS_PATH,
                    move |page_token| aos_proto_types::ListPlacementsRequest {
                        surface: Some(surface.clone()),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.placements, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_surface = surface.clone();

    view! {
        <section class="panel resource-panel"><div class="section-heading"><div><p class="section-kicker">"Migration evidence"</p><h2>"Placement equivalence"</h2><p>"Equivalence is confirmed from exact placement revisions and retained as explicit evidence for safe topology changes."</p></div></div><Suspense fallback=move || view! { <p class="loading-row">"Loading equivalence evidence…"</p> }>{move || { let client = view_client.clone(); Suspend::new(async move { match equivalences.await.as_ref() { Ok(equivalences) if equivalences.is_empty() => view! { <p class="muted">"No confirmed placement equivalences."</p> }.into_any(), Ok(equivalences) => view! { <div class="compact-list">{equivalences.iter().cloned().map(|equivalence| view! { <EquivalenceRow client=client.clone() equivalence=equivalence/> }).collect_view()}</div> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense><Suspense fallback=move || view! { <p class="loading-row">"Loading placement revisions…"</p> }>{move || { let client = client.clone(); let surface = view_surface.clone(); Suspend::new(async move { match placements.await.as_ref() { Ok(placements) => view! { <EquivalenceCreate client=client surface=surface placements=placements.clone()/> }.into_any(), Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any() } }) }}</Suspense></section>
    }
}

#[component]
fn EquivalenceCreate(
    client: ApiClient,
    surface: aos_proto_types::SurfaceRef,
    placements: Vec<aos_proto_types::Placement>,
) -> impl IntoView {
    let initial = placements
        .first()
        .map(|value| value.name.clone())
        .unwrap_or_default();
    let placement_a = RwSignal::new(initial.clone());
    let placement_b = RwSignal::new(initial);
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let request_placements = placements.clone();
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        let a = placement_a.get_untracked();
        let b = placement_b.get_untracked();
        if a == b {
            error.set(Some(
                "Equivalence requires two different placements".to_string(),
            ));
            return;
        }
        let version = |name: &str| {
            request_placements
                .iter()
                .find(|placement| placement.name == name)
                .map(|placement| placement.resource_version.clone())
        };
        let (Some(a_version), Some(b_version)) = (version(&a), version(&b)) else {
            error.set(Some("Select two current placements".to_string()));
            return;
        };
        let idempotency_key = idempotency_key("placement-equivalence-confirm");
        let request = aos_proto_types::PlanPlacementEquivalenceRequest {
            surface: Some(surface.clone()),
            placement_a: a,
            placement_b: b,
            expected_a_resource_version: Some(a_version.clone()),
            expected_b_resource_version: Some(b_version.clone()),
            idempotency_key: idempotency_key.clone(),
            expected_resource_version: format!("{a_version}|{b_version}"),
        };
        plan(
            plan_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_CONFIRM_PLACEMENT_EQUIVALENCE_PATH,
            request,
            idempotency_key,
            pending,
            error,
            busy,
        );
    };
    let on_apply = apply(
        client,
        aos_proto_types::TOPOLOGY_SERVICE_CONFIRM_PLACEMENT_EQUIVALENCE_PATH,
        pending,
        error,
        busy,
    );
    view! { <section class="subworkflow"><h4>"Confirm equivalence"</h4><form class="editor-form" on:submit=on_plan><label><span>"Placement A"</span><select prop:value=move || placement_a.get() on:change=move |event| placement_a.set(event_target_value(&event))>{placements.iter().map(|placement| view! { <option value=placement.name.clone()>{placement.name.clone()}</option> }).collect_view()}</select></label><label><span>"Placement B"</span><select prop:value=move || placement_b.get() on:change=move |event| placement_b.set(event_target_value(&event))>{placements.iter().map(|placement| view! { <option value=placement.name.clone()>{placement.name.clone()}</option> }).collect_view()}</select></label><div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get() || placements.len() < 2>"Review confirmation"</button></div></form><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></section> }
}

#[component]
fn EquivalenceRow(
    client: ApiClient,
    equivalence: aos_proto_types::PlacementEquivalence,
) -> impl IntoView {
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let request = aos_proto_types::PlanDeleteTopologyResourceRequest {
        stable_id: equivalence.stable_id.clone(),
        expected_resource_version: Some(equivalence.resource_version.clone()),
        idempotency_key: idempotency_key("placement-equivalence-delete"),
    };
    let idempotency = request.idempotency_key.clone();
    let plan_client = client.clone();
    let on_plan = move |_| {
        plan(
            plan_client.clone(),
            aos_proto_types::TOPOLOGY_SERVICE_PLAN_DELETE_PLACEMENT_EQUIVALENCE_PATH,
            request.clone(),
            idempotency.clone(),
            pending,
            error,
            busy,
        )
    };
    let on_apply = apply(
        client,
        aos_proto_types::TOPOLOGY_SERVICE_DELETE_PLACEMENT_EQUIVALENCE_PATH,
        pending,
        error,
        busy,
    );
    view! { <div class="revision-card"><div class="compact-list-row"><div><strong>{format!("{} ↔ {}", equivalence.placement_a, equivalence.placement_b)}</strong><code>{equivalence.evidence_digest}</code></div><StatusBadge state=equivalence.state positive=true/><button class="table-action" type="button" disabled=move || busy.get() on:click=on_plan>"Review removal"</button></div><PlanReview pending=pending error=error busy=busy on_apply=on_apply/></div> }
}

#[component]
fn PlanReview(
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    on_apply: Callback<()>,
) -> impl IntoView {
    view! { {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}{move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })} }
}

fn plan<Req: serde::Serialize + 'static>(
    client: ApiClient,
    path: &'static str,
    request: Req,
    idempotency_key: String,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
) {
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

fn apply(
    client: ApiClient,
    path: &'static str,
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
                .call::<_, serde_json::Value>(path, &reviewed.topology_apply())
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    })
}

fn generation_ref(value: &str, field: &str) -> Result<(String, i64), String> {
    let (id, revision) = value
        .trim()
        .rsplit_once('@')
        .ok_or_else(|| format!("{field} uses stable-id@revision"))?;
    let revision = revision
        .parse::<i64>()
        .map_err(|_| format!("{field} revision must be a positive integer"))?;
    if id.is_empty() || revision <= 0 {
        return Err(format!("{field} uses stable-id@positive-revision"));
    }
    Ok((id.to_string(), revision))
}

fn lines(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    for value in value
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
    values
}
fn reload() {
    crate::app::refresh();
}

//! Proactive registry-to-cache population and coverage workflows.
//!
//! Population targets state whether cache coverage is best-effort or required.
//! They record and validate availability intent; publication does not currently
//! consume the required bit as a release-visibility gate.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HashValue, InlineError, ReviewedPlanCard, StatusBadge};
use crate::mutation::{idempotency_key, watch_draft, PendingPlan};
use crate::transport::ApiClient;

/// Renders population targets, observed coverage, and the reviewed set editor.
#[component]
pub(super) fn CachePopulation(client: ApiClient, cache_id: String) -> impl IntoView {
    let can_manage = client.allows("registry.configure");
    let read_client = client.clone();
    let read_cache = cache_id.clone();
    let targets = LocalResource::new(move || {
        let client = read_client.clone();
        let cache_id = read_cache.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListPopulationTargetsResponse, _, _, _>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_LIST_POPULATION_TARGETS_PATH,
                    move |page_token| aos_proto_types::ListPopulationTargetsRequest {
                        cache_id: cache_id.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.targets, response.next_page_token),
                )
                .await
        }
    });
    let view_client = client.clone();
    let view_cache = cache_id.clone();

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Release availability"</p>
                    <h2>"Population and coverage"</h2>
                    <p>
                        "Required targets record availability policy and expose coverage failures. Publication visibility is not currently gated by this setting."
                    </p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading population targets…"</p> }>
                {move || {
                    let client = view_client.clone();
                    let cache_id = view_cache.clone();
                    Suspend::new(async move {
                        match targets.await.as_ref() {
                            Ok(targets) if targets.is_empty() => view! {
                                <div class="empty-state"><h3>"No proactive population targets"</h3><p>"Add a target when this cache must copy and verify selected registry content ahead of demand."</p></div>
                            }
                            .into_any(),
                            Ok(targets) => view! {
                                <div class="binding-list">
                                    {targets.iter().cloned().map(|target| view! {
                                        <PopulationTargetCard client=client.clone() cache_id=cache_id.clone() target=target can_manage=can_manage/>
                                    }).collect_view()}
                                </div>
                            }
                            .into_any(),
                            Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                        }
                    })
                }}
            </Suspense>
            {can_manage.then(|| view! { <PopulationEditor client=client cache_id=cache_id/> })}
        </section>
    }
}

#[component]
fn PopulationTargetCard(
    client: ApiClient,
    cache_id: String,
    target: aos_proto_types::PopulationTarget,
    can_manage: bool,
) -> impl IntoView {
    let edit_target = target.clone();
    let registry_id = target.registry_id.clone();
    let coverage_client = client.clone();
    let coverage_cache = cache_id.clone();
    let coverage_registry = registry_id.clone();
    let coverage = LocalResource::new(move || {
        let client = coverage_client.clone();
        let cache_id = coverage_cache.clone();
        let registry_id = coverage_registry.clone();
        async move {
            client
                .call::<_, aos_proto_types::CoverageResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_GET_COVERAGE_PATH,
                    &aos_proto_types::GetPopulationTargetRequest {
                        cache_id,
                        registry_id,
                    },
                )
                .await
        }
    });
    let desired = target.desired.clone().unwrap_or_default();
    let version = target.resource_version.clone();

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div><strong>{target.registry_id}</strong><code>{target.target_id}</code></div>
                <StatusBadge state=target.state.clone() positive=target.state == "ready"/>
            </div>
            <div class="resource-identity">
                <div><span>"Guarantee"</span><strong>{if desired.required { "required" } else { "best effort" }}</strong></div>
                <div><span>"Trigger"</span><strong>{desired.trigger}</strong></div>
                <div><span>"Validation gate"</span><strong>{desired.validation_gate}</strong></div>
                <div><span>"Placement policy"</span><code>{display_or(&desired.placement_policy_revision_id, "default")}</code></div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading coverage…"</p> }>
                {move || Suspend::new(async move {
                    match coverage.await.as_ref() {
                        Ok(response) => view! {
                            <div class="compact-list-row">
                                <span>{format!("{} / {} required objects present", response.present_objects, response.required_objects)}</span>
                                <StatusBadge state=response.state.clone() positive=response.missing_store_hashes.is_empty()/>
                            </div>
                            {(!response.missing_store_hashes.is_empty()).then(|| view! {
                                <details><summary>"Missing store hashes"</summary><div class="compact-list">
                                    {response.missing_store_hashes.iter().map(|hash| view! { <HashValue value=hash.clone()/> }).collect_view()}
                                </div></details>
                            })}
                        }
                        .into_any(),
                        Err(failure) => view! { <InlineError detail=failure.to_string()/> }.into_any(),
                    }
                })}
            </Suspense>
            {can_manage.then(|| view! { <div class="form-actions">
                <PopulationAction client=client.clone() cache_id=cache_id.clone() registry_id=registry_id.clone() version=version.clone() action=PopulationActionKind::Run/>
                <PopulationAction client=client.clone() cache_id=cache_id.clone() registry_id=registry_id.clone() version=version.clone() action=PopulationActionKind::Validate/>
                <PopulationAction client=client.clone() cache_id=cache_id.clone() registry_id=registry_id.clone() version=version.clone() action=PopulationActionKind::Repair/>
                <PopulationAction client=client.clone() cache_id=cache_id.clone() registry_id=registry_id.clone() version=version.clone() action=PopulationActionKind::Delete/>
            </div>
            <details>
                <summary>"Edit this population target"</summary>
                <PopulationEditor client=client cache_id=cache_id initial=edit_target/>
            </details> })}
        </article>
    }
}

#[derive(Clone, Copy)]
enum PopulationActionKind {
    Run,
    Validate,
    Repair,
    Delete,
}

impl PopulationActionKind {
    fn label(self) -> &'static str {
        match self {
            Self::Run => "Review population",
            Self::Validate => "Review validation",
            Self::Repair => "Review repair",
            Self::Delete => "Review deletion",
        }
    }
}

#[component]
fn PopulationAction(
    client: ApiClient,
    cache_id: String,
    registry_id: String,
    version: String,
    action: PopulationActionKind,
) -> impl IntoView {
    let release_tag = RwSignal::new(String::new());
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = release_tag.get();
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let on_plan = move |_| {
        let key = idempotency_key(match action {
            PopulationActionKind::Run => "population-run",
            PopulationActionKind::Validate => "coverage-validate",
            PopulationActionKind::Repair => "coverage-repair",
            PopulationActionKind::Delete => "population-delete",
        });
        let client = plan_client.clone();
        let cache_id = cache_id.clone();
        let registry_id = registry_id.clone();
        let version = version.clone();
        let tag = nonempty(&release_tag.get_untracked());
        let planned_epoch = draft_epoch.get_untracked();
        error.set(None);
        pending.set(None);
        busy.set(true);
        spawn_local(async move {
            let response = match action {
                PopulationActionKind::Run => client.call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_RUN_POPULATION_PATH,
                    &aos_proto_types::PlanRunPopulationRequest { cache_id, registry_id, release_tag: tag, idempotency_key: key.clone(), expected_resource_version: version },
                ).await,
                PopulationActionKind::Validate | PopulationActionKind::Repair => {
                    let path = if matches!(action, PopulationActionKind::Validate) {
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_RUN_COVERAGE_VALIDATION_PATH
                    } else {
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_RUN_COVERAGE_REPAIR_PATH
                    };
                    client.call::<_, aos_proto_types::TopologyPlanResponse>(path, &aos_proto_types::PlanCoverageOperationRequest {
                        cache_id, registry_id, expected_resource_version: version, idempotency_key: key.clone(),
                    }).await
                }
                PopulationActionKind::Delete => client.call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_DELETE_POPULATION_TARGET_PATH,
                    &aos_proto_types::PlanDeletePopulationTargetRequest { cache_id, registry_id, expected_resource_version: version, idempotency_key: key.clone() },
                ).await,
            };
            let result = response
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, key));
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
            let result = match action {
                PopulationActionKind::Delete => client
                    .call::<_, aos_proto_types::DeleteTopologyResourceResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_DELETE_POPULATION_TARGET_PATH,
                        &reviewed.cache_plan_apply(),
                    )
                    .await
                    .map(|_| ()),
                PopulationActionKind::Run => client
                    .call::<_, aos_proto_types::OperationResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_RUN_POPULATION_PATH,
                        &reviewed.topology_apply(),
                    )
                    .await
                    .map(|_| ()),
                PopulationActionKind::Validate => client
                    .call::<_, aos_proto_types::OperationResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_RUN_COVERAGE_VALIDATION_PATH,
                        &reviewed.topology_apply(),
                    )
                    .await
                    .map(|_| ()),
                PopulationActionKind::Repair => client
                    .call::<_, aos_proto_types::OperationResponse>(
                        aos_proto_types::CACHE_INTEGRATION_SERVICE_RUN_COVERAGE_REPAIR_PATH,
                        &reviewed.topology_apply(),
                    )
                    .await
                    .map(|_| ()),
            };
            match result {
                Ok(()) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="subworkflow">
            {matches!(action, PopulationActionKind::Run).then(|| view! {
                <label><span>"Release tag (optional)"</span><input prop:value=move || release_tag.get() on:input=move |event| release_tag.set(event_target_value(&event))/></label>
            })}
            <button class=if matches!(action, PopulationActionKind::Delete) { "danger-button" } else { "table-action" } type="button" disabled=move || busy.get() on:click=on_plan>{action.label()}</button>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! {
                <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/>
            })}
        </div>
    }
}

#[component]
fn PopulationEditor(
    client: ApiClient,
    cache_id: String,
    #[prop(optional)] initial: Option<aos_proto_types::PopulationTarget>,
) -> impl IntoView {
    let editing = initial.is_some();
    let desired = initial
        .as_ref()
        .and_then(|target| target.desired.clone())
        .unwrap_or_else(|| aos_proto_types::PopulationTargetSpec {
            trigger: "release".to_string(),
            required: false,
            placement_policy_revision_id: String::new(),
            validation_gate: "integrity".to_string(),
        });
    let registry_id = RwSignal::new(
        initial
            .as_ref()
            .map(|target| target.registry_id.clone())
            .unwrap_or_default(),
    );
    let trigger = RwSignal::new(desired.trigger);
    let required = RwSignal::new(desired.required);
    let placement_policy = RwSignal::new(desired.placement_policy_revision_id);
    let validation_gate = RwSignal::new(desired.validation_gate);
    let expected_version = RwSignal::new(
        initial
            .as_ref()
            .map(|target| target.resource_version.clone())
            .unwrap_or_default(),
    );
    let pending = RwSignal::new(None::<PendingPlan>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let draft_epoch = watch_draft(
        move || {
            let _ = (
                registry_id.get(),
                trigger.get(),
                required.get(),
                placement_policy.get(),
                validation_gate.get(),
                expected_version.get(),
            );
        },
        pending,
        error,
    );
    let plan_client = client.clone();
    let on_plan = move |event: SubmitEvent| {
        event.prevent_default();
        pending.set(None);
        let registry = registry_id.get_untracked().trim().to_string();
        if registry.is_empty() {
            error.set(Some("Registry stable ID is required".to_string()));
            return;
        }
        let key = idempotency_key("population-set");
        let request = aos_proto_types::PlanPopulationTargetRequest {
            cache_id: cache_id.clone(),
            registry_id: registry,
            desired: Some(aos_proto_types::PopulationTargetSpec {
                trigger: trigger.get_untracked(),
                required: required.get_untracked(),
                placement_policy_revision_id: placement_policy.get_untracked().trim().to_string(),
                validation_gate: validation_gate.get_untracked().trim().to_string(),
            }),
            expected_resource_version: expected_version.get_untracked().trim().to_string(),
            idempotency_key: key.clone(),
        };
        let client = plan_client.clone();
        let planned_epoch = draft_epoch.get_untracked();
        error.set(None);
        pending.set(None);
        busy.set(true);
        spawn_local(async move {
            let result = client
                .call::<_, aos_proto_types::TopologyPlanResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_PLAN_SET_POPULATION_TARGET_PATH,
                    &request,
                )
                .await
                .map_err(|failure| failure.to_string())
                .and_then(|response| PendingPlan::from_response(response, key));
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
                .call::<_, aos_proto_types::PopulationTargetResponse>(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_SET_POPULATION_TARGET_PATH,
                    &reviewed.cache_plan_apply(),
                )
                .await
            {
                Ok(_) => reload(),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    });
    view! {
        <section class="subworkflow">
            <h4>{if editing { "Edit population target" } else { "Create population target" }}</h4>
            <form class="editor-form" on:submit=on_plan>
                <label><span>"Registry stable ID"</span><input required prop:value=move || registry_id.get() on:input=move |event| registry_id.set(event_target_value(&event))/></label>
                <label><span>"Expected version (empty when creating)"</span><input prop:value=move || expected_version.get() on:input=move |event| expected_version.set(event_target_value(&event))/></label>
                <label>
                    <span>"Trigger"</span>
                    <select
                        prop:value=move || trigger.get()
                        on:change=move |event| trigger.set(event_target_value(&event))
                    >
                        <option value="release">"Release"</option>
                        <option value="continuous">"Continuous"</option>
                        <option value="manual">"Manual"</option>
                    </select>
                </label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || required.get()
                        on:change=move |event| required.set(event_target_checked(&event))
                    />
                    <span>"Required coverage target"</span>
                </label>
                <label><span>"Placement policy revision (optional)"</span><input prop:value=move || placement_policy.get() on:input=move |event| placement_policy.set(event_target_value(&event))/></label>
                <label><span>"Validation gate"</span><input required prop:value=move || validation_gate.get() on:input=move |event| validation_gate.set(event_target_value(&event))/></label>
                <div class="form-actions"><button class="secondary-button" type="submit" disabled=move || busy.get()>"Review population target"</button></div>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || pending.get().map(|reviewed| view! { <ReviewedPlanCard plan=reviewed.plan applying=busy.get() on_apply=on_apply on_cancel=Callback::new(move |()| pending.set(None))/> })}
        </section>
    }
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
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

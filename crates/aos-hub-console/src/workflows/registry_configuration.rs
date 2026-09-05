//! Registry configuration history, semantic changesets, and draft requests.
//!
//! Committed Git history and SQL-backed retained-control changesets are
//! read-only audit views. Draft Git change requests remain separate because
//! promotion is performed by the signed `apr change merge` workflow.

use crate::mutation::spawn_workflow_task as spawn_local;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use crate::components::{HashValue, InlineError, StatusBadge};
use crate::transport::ApiClient;

/// Renders committed configuration history or draft change requests.
#[component]
pub(super) fn RegistryConfiguration(
    client: ApiClient,
    registry_id: String,
    page: &'static str,
) -> impl IntoView {
    match page {
        "configuration" => view! {
            <ConfigurationHistory client=client registry_id=registry_id/>
        }
        .into_any(),
        "changes" => view! {
            <ChangeRequests client=client registry_id=registry_id/>
        }
        .into_any(),
        _ => view! { <InlineError detail="Unknown configuration page".to_string()/> }.into_any(),
    }
}

#[component]
fn ConfigurationHistory(client: ApiClient, registry_id: String) -> impl IntoView {
    let can_audit = client.allows("audit.read");
    view! {
        <div class="workflow-stack">
            <GitHistory client=client.clone() registry_id=registry_id.clone()/>
            <details class="panel advanced-controls"><summary>"Compare two commits"</summary>
                <GitDiffInspector client=client.clone() registry_id=registry_id.clone()/>
            </details>
            {can_audit.then(|| view! { <Changesets client=client registry_id=registry_id/> })}
        </div>
    }
}

#[component]
fn GitHistory(client: ApiClient, registry_id: String) -> impl IntoView {
    let commits = LocalResource::new(move || {
        let client = client.clone();
        let registry = registry_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::GitLogResponse, _, _, _>(
                    aos_proto_types::GIT_SERVICE_GIT_LOG_PATH,
                    move |page_token| aos_proto_types::GitLogRequest {
                        slug: registry.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.commits, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Committed source of truth"</p>
                    <h2>"Configuration history"</h2>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading commits…"</p> }>
                {move || Suspend::new(async move {
                    match commits.await.as_ref() {
                        Ok(commits) if commits.is_empty() => view! {
                            <p class="muted">"No committed configuration history."</p>
                        }
                        .into_any(),
                        Ok(commits) => view! {
                            <div class="binding-list">
                                {commits
                                    .iter()
                                    .cloned()
                                    .map(|commit| view! { <CommitCard commit=commit/> })
                                    .collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! {
                            <InlineError detail=failure.to_string()/>
                        }
                        .into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn CommitCard(commit: aos_proto_types::GitCommit) -> impl IntoView {
    let summary = commit
        .message
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let source = if commit.change_id.is_empty() {
        "direct"
    } else {
        "change request"
    };

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{summary}</strong>
                    <HashValue value=commit.oid/>
                </div>
                <StatusBadge state=source.to_string() positive=!commit.change_id.is_empty()/>
            </div>
            <div class="resource-identity">
                <div>
                    <span>"Author"</span>
                    <strong>{commit.author}</strong>
                </div>
                <div>
                    <span>"Committed"</span>
                    <strong>{commit.when}</strong>
                </div>
                <div>
                    <span>"Parents"</span>
                    <strong>{commit.parents.len()}</strong>
                </div>
                <div>
                    <span>"Change ID"</span>
                    <code>{display_or(&commit.change_id, "none")}</code>
                </div>
            </div>
            <details>
                <summary>"Commit message"</summary>
                <pre>{commit.message}</pre>
            </details>
        </article>
    }
}

#[component]
fn GitDiffInspector(client: ApiClient, registry_id: String) -> impl IntoView {
    let from = RwSignal::new(String::new());
    let to = RwSignal::new(String::new());
    let diff = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let client = client.clone();
        let request = aos_proto_types::GitDiffRequest {
            slug: registry_id.clone(),
            from_oid: from.get_untracked().trim().to_string(),
            to_oid: to.get_untracked().trim().to_string(),
        };
        error.set(None);
        diff.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call::<_, aos_proto_types::GitDiffResponse>(
                    aos_proto_types::GIT_SERVICE_GIT_DIFF_PATH,
                    &request,
                )
                .await
            {
                Ok(response) => diff.set(Some(response.diff)),
                Err(failure) => error.set(Some(failure.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Committed files"</p>
                    <h2>"Configuration diff"</h2>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"From commit (empty for whole tree)"</span>
                    <input
                        prop:value=move || from.get()
                        on:input=move |event| from.set(event_target_value(&event))
                    />
                </label>
                <label>
                    <span>"To commit (empty for HEAD)"</span>
                    <input
                        prop:value=move || to.get()
                        on:input=move |event| to.set(event_target_value(&event))
                    />
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Load diff"
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || diff.get().map(|value| view! { <pre class="diff-view">{value}</pre> })}
        </section>
    }
}

#[component]
fn Changesets(client: ApiClient, registry_id: String) -> impl IntoView {
    let list_client = client.clone();
    let changesets = LocalResource::new(move || {
        let client = list_client.clone();
        let slug = registry_id.clone();
        async move {
            let registry = client
                .call::<_, aos_proto_types::GetRegistryResponse>(
                    aos_proto_types::REGISTRY_SERVICE_GET_REGISTRY_PATH,
                    &aos_proto_types::GetRegistryRequest { slug },
                )
                .await?
                .registry
                .ok_or_else(|| {
                    crate::transport::TransportError::Response(
                        "the Hub omitted the registry".to_string(),
                    )
                })?;
            if registry.authorization_scope_key.is_empty() {
                return Err(crate::transport::TransportError::Response(
                    "the Hub omitted the registry authorization scope".to_string(),
                ));
            }
            let scope = registry.authorization_scope_key;
            client
                .collect_pages::<_, aos_proto_types::ListChangesetsResponse, _, _, _>(
                    aos_proto_types::REGISTRY_CONFIGURATION_SERVICE_LIST_CHANGESETS_PATH,
                    move |page_token| aos_proto_types::ListChangesetsRequest {
                        scope: scope.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.changesets, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Settings audit"</p>
                    <h2>"Configuration changes"</h2>
                    <p>"Reviewed settings changes recorded by the Hub, alongside the registry's Git history above."</p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading changesets…"</p> }>
                {move || Suspend::new(async move {
                    match changesets.await.as_ref() {
                        Ok(changesets) if changesets.is_empty() => view! {
                            <p class="muted">"No settings changes have been recorded for this registry."</p>
                        }
                        .into_any(),
                        Ok(changesets) => view! {
                            <div class="binding-list">
                                {changesets
                                    .iter()
                                    .cloned()
                                    .map(|changeset| view! {
                                        <ChangesetSummary changeset=changeset/>
                                    })
                                    .collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! {
                            <InlineError detail=failure.to_string()/>
                        }
                        .into_any(),
                    }
                })}
            </Suspense>
            <ChangesetInspector client=client/>
        </section>
    }
}

#[component]
fn ChangesetSummary(changeset: aos_proto_types::Changeset) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{changeset.summary}</strong>
                    <code>{changeset.change_id}</code>
                </div>
                <StatusBadge
                    state=changeset.status.clone()
                    positive=changeset.status == "applied"
                />
            </div>
            <div class="resource-identity">
                <div>
                    <span>"Actor"</span>
                    <strong>{changeset.actor_label}</strong>
                </div>
                <div>
                    <span>"Scope"</span>
                    <code>{changeset.scope}</code>
                </div>
                <div>
                    <span>"Created"</span>
                    <strong>{changeset.created_at}</strong>
                </div>
                <div>
                    <span>"Applied"</span>
                    <strong>{changeset.applied_at}</strong>
                </div>
            </div>
        </article>
    }
}

#[component]
fn ChangesetInspector(client: ApiClient) -> impl IntoView {
    let change_id = RwSignal::new(String::new());
    let result = RwSignal::new(None::<aos_proto_types::GetChangesetResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();

        let id = change_id.get_untracked().trim().to_string();
        if id.is_empty() {
            error.set(Some("Change ID is required".to_string()));
            return;
        }

        let client = client.clone();
        error.set(None);
        result.set(None);
        busy.set(true);

        spawn_local(async move {
            let request = aos_proto_types::GetChangesetRequest { change_id: id };
            match client
                .call::<_, aos_proto_types::GetChangesetResponse>(
                    aos_proto_types::REGISTRY_CONFIGURATION_SERVICE_GET_CHANGESET_PATH,
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

    view! {
        <details class="advanced-controls">
            <summary>"Find a change by ID"</summary>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"Change ID"</span>
                    <input
                        required
                        prop:value=move || change_id.get()
                        on:input=move |event| change_id.set(event_target_value(&event))
                    />
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    "Load changeset"
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || result.get().map(|result| view! { <ChangesetDetail result=result/> })}
        </details>
    }
}

#[component]
fn ChangesetDetail(result: aos_proto_types::GetChangesetResponse) -> impl IntoView {
    view! {
        <div class="binding-list">
            {result
                .revisions
                .into_iter()
                .map(|revision| view! { <RevisionCard revision=revision/> })
                .collect_view()}
        </div>
    }
}

#[component]
fn RevisionCard(revision: aos_proto_types::Revision) -> impl IntoView {
    let operation = revision.op.clone();

    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{revision.object_type}</strong>
                    <code>{revision.object_id}</code>
                </div>
                <StatusBadge state=operation.clone() positive=operation != "delete"/>
            </div>
            <div class="compact-list">
                {revision
                    .diffs
                    .into_iter()
                    .map(|diff| view! {
                        <div class="compact-list-row">
                            <strong>{diff.field}</strong>
                            <code>{diff.old}</code>
                            <span>"→"</span>
                            <code>{diff.new}</code>
                        </div>
                    })
                    .collect_view()}
            </div>
        </article>
    }
}

#[component]
fn ChangeRequests(client: ApiClient, registry_id: String) -> impl IntoView {
    let requests = LocalResource::new(move || {
        let client = client.clone();
        let registry = registry_id.clone();
        async move {
            client
                .collect_pages::<_, aos_proto_types::ListChangeRequestsResponse, _, _, _>(
                    aos_proto_types::GIT_SERVICE_LIST_CHANGE_REQUESTS_PATH,
                    move |page_token| aos_proto_types::ListChangeRequestsRequest {
                        slug: registry.clone(),
                        page_size: 100,
                        page_token,
                    },
                    |response| (response.change_requests, response.next_page_token),
                )
                .await
        }
    });

    view! {
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Proposed registry changes"</p>
                    <h2>"Change requests"</h2>
                    <p>
                        "Review proposed file changes here. To publish an approved change, use the signed "
                        <code>"apr change merge"</code>" command shown on its request."
                    </p>
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="loading-row">"Loading change requests…"</p> }>
                {move || Suspend::new(async move {
                    match requests.await.as_ref() {
                        Ok(requests) if requests.is_empty() => view! {
                            <p class="muted">"No draft change requests."</p>
                        }
                        .into_any(),
                        Ok(requests) => view! {
                            <div class="binding-list">
                                {requests
                                    .iter()
                                    .cloned()
                                    .map(|request| view! {
                                        <ChangeRequestCard request=request/>
                                    })
                                    .collect_view()}
                            </div>
                        }
                        .into_any(),
                        Err(failure) => view! {
                            <InlineError detail=failure.to_string()/>
                        }
                        .into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn ChangeRequestCard(request: aos_proto_types::ChangeRequest) -> impl IntoView {
    view! {
        <article class="revision-card">
            <div class="compact-list-row">
                <div>
                    <strong>{request.summary}</strong>
                    <code>{request.change_id}</code>
                </div>
                <StatusBadge
                    state=request.status.clone()
                    positive=request.status == "applied"
                />
            </div>
            <div class="resource-identity">
                <div>
                    <span>"Actor"</span>
                    <strong>{request.actor_label}</strong>
                </div>
                <div>
                    <span>"Draft ref"</span>
                    <code>{request.git_ref}</code>
                </div>
                <div>
                    <span>"Draft commit"</span>
                    <HashValue value=request.git_commit/>
                </div>
                <div>
                    <span>"Created"</span>
                    <strong>{request.created_at}</strong>
                </div>
            </div>
            <div class="compact-list-row">
                <span>"Promotion command"</span>
                <code>{request.merge_command}</code>
            </div>
            {request
                .file_diffs
                .into_iter()
                .map(|file| view! {
                    <details>
                        <summary>{file.path}</summary>
                        <pre class="diff-view">{file.diff}</pre>
                    </details>
                })
                .collect_view()}
        </article>
    }
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

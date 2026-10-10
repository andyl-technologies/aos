//! Pinned scan requests and durable operation controls in the registry console.

use aos_assessment::input::FreshnessMode;
use aos_assessment_runtime::application::{AssessmentStatusV1, ScanReceiptV1};
use aos_assessment_runtime::control::{
    ScanCancellationV1, ScanListQueryV1, ScanListV1, ScanLookupV1, ScanRetryV1, ScanSubmissionV1,
};
use aos_assessment_runtime::scan::ScanLimits;
use leptos::prelude::*;

use super::assessments::{start_status_poll, AssessmentReadGuard};
use crate::components::InlineError;
use crate::mutation::{idempotency_key, scoped_workflow_tasks};
use crate::transport::ApiClient;

/// Renders controls for the explicitly displayed inventory page and scan history.
#[component]
pub(super) fn AssessmentScanControls(
    client: ApiClient,
    slug: String,
    status: AssessmentStatusV1,
) -> impl IntoView {
    let can_scan = client.allows("assessment.scan");
    let tasks = scoped_workflow_tasks();
    let context = StoredValue::new((client, slug));
    let scope = StoredValue::new(status);
    let epoch = RwSignal::new(0_u64);
    let polling = RwSignal::new(true);
    let active_reads = RwSignal::new(0_u32);
    let position = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let failure = RwSignal::new(None::<String>);
    let selected = RwSignal::new(None::<ScanReceiptV1>);
    let request_key = RwSignal::new(idempotency_key("assessment-scan"));
    let freshness = RwSignal::new(FreshnessMode::RefreshStale);

    let history = LocalResource::new(move || {
        let _ = epoch.get();
        let (client, registry_slug) = context.get_value();
        let after_scan = position.get();
        let inspected = selected.get_untracked();
        let read = AssessmentReadGuard::new(active_reads);
        async move {
            let _read = read;
            let outcome = async {
                let query = ScanListQueryV1 {
                    schema: "aos.assessment-scan-list-query/v1".into(),
                    limit: 50,
                    after_scan,
                };
                let document_json =
                    serde_json::to_vec(&query).map_err(|error| error.to_string())?;
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::SCAN_SERVICE_LIST_SCANS_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug: registry_slug.clone(),
                            document_json,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let page = ScanListV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if let Some(inspected) = inspected {
                    let query = ScanLookupV1 {
                        schema: "aos.assessment-scan-lookup/v1".into(),
                        scan_id: inspected.scan_id,
                    };
                    let response = client
                        .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                            aos_proto_types::SCAN_SERVICE_GET_SCAN_PATH,
                            &aos_proto_types::AssessmentControlRequest {
                                registry_slug,
                                document_json: serde_json::to_vec(&query)
                                    .map_err(|error| error.to_string())?,
                            },
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    let receipt = ScanReceiptV1::from_slice(&response.document_json)
                        .map_err(|error| error.to_string())?;
                    selected.update(|current| {
                        if current.as_ref().is_some_and(|current| {
                            current.scan_id == receipt.scan_id
                                && current.resource_version <= receipt.resource_version
                        }) {
                            *current = Some(receipt);
                        }
                    });
                }
                Ok::<_, String>(page)
            }
            .await;
            if outcome.is_err() {
                polling.set(false);
            }
            outcome
        }
    });
    start_status_poll(epoch, polling, active_reads);

    let submit = move |_| {
        if busy.get_untracked() || !can_scan {
            return;
        }
        let status = scope.get_value();
        let mut profiles = status
            .subjects
            .iter()
            .flat_map(|subject| subject.profiles.iter().map(|profile| profile.profile))
            .collect::<Vec<_>>();
        profiles.sort();
        profiles.dedup();
        let submission = ScanSubmissionV1 {
            schema: "aos.assessment-scan-submission/v1".into(),
            inventory_revision: status.inventory_revision,
            inventory_digest: status.inventory_digest,
            policy_digest: status.policy_digest,
            subjects: status
                .subjects
                .into_iter()
                .map(|subject| subject.subject_ref)
                .collect(),
            profiles,
            freshness: freshness.get_untracked(),
            idempotency_key: request_key.get_untracked(),
            limits: ScanLimits::default(),
        };
        let document_json = match serde_json::to_vec(&submission) {
            Ok(bytes) => bytes,
            Err(error) => {
                failure.set(Some(error.to_string()));
                return;
            }
        };
        let (client, registry_slug) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let result = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::SCAN_SERVICE_REQUEST_SCAN_PATH,
                    &aos_proto_types::AssessmentControlRequest {
                        registry_slug,
                        document_json,
                    },
                )
                .await;
            match result {
                Ok(response) => match ScanReceiptV1::from_slice(&response.document_json) {
                    Ok(receipt) => {
                        selected.set(Some(receipt));
                        request_key.set(idempotency_key("assessment-scan"));
                        epoch.update(|value| *value = value.wrapping_add(1));
                    }
                    Err(error) => failure.set(Some(error.to_string())),
                },
                Err(error) => failure.set(Some(error.to_string())),
            }
            busy.set(false);
        });
    };

    let inspect = move |scan_id: String| {
        if busy.get_untracked() {
            return;
        }
        let query = ScanLookupV1 {
            schema: "aos.assessment-scan-lookup/v1".into(),
            scan_id,
        };
        let document_json = match serde_json::to_vec(&query) {
            Ok(bytes) => bytes,
            Err(error) => {
                failure.set(Some(error.to_string()));
                return;
            }
        };
        let (client, registry_slug) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let result = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::SCAN_SERVICE_GET_SCAN_PATH,
                    &aos_proto_types::AssessmentControlRequest {
                        registry_slug,
                        document_json,
                    },
                )
                .await;
            match result {
                Ok(response) => match ScanReceiptV1::from_slice(&response.document_json) {
                    Ok(receipt) => selected.set(Some(receipt)),
                    Err(error) => failure.set(Some(error.to_string())),
                },
                Err(error) => failure.set(Some(error.to_string())),
            }
            busy.set(false);
        });
    };

    let transition = move |retry: bool| {
        if busy.get_untracked() || !can_scan {
            return;
        }
        let Some(receipt) = selected.get_untracked() else {
            return;
        };
        let (path, encoded) = if retry {
            (
                aos_proto_types::SCAN_SERVICE_RETRY_SCAN_PATH,
                serde_json::to_vec(&ScanRetryV1 {
                    schema: "aos.assessment-scan-retry/v1".into(),
                    scan_id: receipt.scan_id,
                    idempotency_key: request_key.get_untracked(),
                }),
            )
        } else {
            (
                aos_proto_types::SCAN_SERVICE_CANCEL_SCAN_PATH,
                serde_json::to_vec(&ScanCancellationV1 {
                    schema: "aos.assessment-scan-cancellation/v1".into(),
                    scan_id: receipt.scan_id,
                    expected_revision: receipt.resource_version,
                }),
            )
        };
        let document_json = match encoded {
            Ok(bytes) => bytes,
            Err(error) => {
                failure.set(Some(error.to_string()));
                return;
            }
        };
        let (client, registry_slug) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let result = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    path,
                    &aos_proto_types::AssessmentControlRequest {
                        registry_slug,
                        document_json,
                    },
                )
                .await;
            match result {
                Ok(response) => match ScanReceiptV1::from_slice(&response.document_json) {
                    Ok(receipt) => {
                        selected.set(Some(receipt));
                        if retry {
                            request_key.set(idempotency_key("assessment-scan"));
                        }
                        epoch.update(|value| *value = value.wrapping_add(1));
                    }
                    Err(error) => failure.set(Some(error.to_string())),
                },
                Err(error) => failure.set(Some(error.to_string())),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="assessment-scan-controls">
            <h3>"Scans"</h3>
            <p>"Requests select only the packages and checks displayed on this page. Inventory changes require a fresh status page."</p>
            {can_scan.then(|| view! {
                <label>"Source evidence "<select disabled=move || busy.get() on:change=move |event| {
                    freshness.set(match event_target_value(&event).as_str() {
                        "refresh" => FreshnessMode::Refresh,
                        "cached" => FreshnessMode::Cached,
                        "offline" => FreshnessMode::Offline,
                        _ => FreshnessMode::RefreshStale,
                    });
                }>
                    <option value="refresh-stale">"Refresh missing or expired evidence"</option>
                    <option value="refresh">"Revalidate source evidence"</option>
                    <option value="cached">"Use admitted cached evidence"</option>
                    <option value="offline">"Use evidence without provider access"</option>
                </select></label>
                <button disabled=move || busy.get() || scope.get_value().subjects.is_empty() on:click=submit>"Scan displayed packages"</button>
            })}
            <button class="secondary-button" on:click=move |_| {
                polling.set(true);
                epoch.update(|value| *value = value.wrapping_add(1));
            }>"Refresh scans"</button>
            {move || failure.get().map(|detail| view! { <InlineError detail/> })}
            <Suspense fallback=move || view! { <p>"Loading scan history…"</p> }>
                {move || Suspend::new(async move {
                    match history.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(page) => {
                            let rows = page.scans.iter().map(|scan| {
                                let scan_id = scan.scan_id.clone();
                                view! { <tr><td>{scan.scan_id.clone()}</td><td>{format!("{:?}", scan.state)}</td><td>{scan.created_at.to_string()}</td><td><button disabled=move || busy.get() on:click=move |_| inspect(scan_id.clone())>"Inspect"</button></td></tr> }
                            }).collect_view();
                            let next = page.next_scan.clone();
                            view! { <table><thead><tr><th>"Scan"</th><th>"State"</th><th>"Requested at"</th><th>"Details"</th></tr></thead><tbody>{rows}</tbody></table>
                                {next.map(|next| view! { <button on:click=move |_| position.set(Some(next.clone()))>"Next scans"</button> })}
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
            {move || selected.get().map(|receipt| {
                let terminal = receipt.state.is_terminal();
                view! { <article><h4>{format!("Scan {}", receipt.scan_id)}</h4>
                    <p>{format!("{:?}; generation {}; revision {}; {} provider requests consumed", receipt.state, receipt.generation, receipt.resource_version, receipt.usage.provider_requests)}</p>
                    <p>{format!("{} subjects; profiles {:?}; source intent {:?}", receipt.request.subjects.len(), receipt.request.profiles, receipt.request.freshness)}</p>
                    {receipt.failure_code.map(|code| view! { <p>{format!("Reason: {code}")}</p> })}
                    {can_scan.then(|| if terminal {
                        view! { <button disabled=move || busy.get() on:click=move |_| transition(true)>"Retry exact selection"</button> }.into_any()
                    } else {
                        view! { <button disabled=move || busy.get() on:click=move |_| transition(false)>"Cancel scan"</button> }.into_any()
                    })}
                </article> }
            })}
        </div>
    }
}

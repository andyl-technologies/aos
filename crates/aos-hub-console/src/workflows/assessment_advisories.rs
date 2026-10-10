//! Explicit cached advisory lookup with exact optional historical assessment context.

use aos_assessment_runtime::advisories::{AdvisoryPageV1, AdvisoryQueryV1};
use aos_contract::Sha256Digest;
use leptos::prelude::*;

use crate::components::InlineError;
use crate::transport::ApiClient;

/// Shows admitted CVE/advisory revisions without starting scans or refreshing sources.
#[component]
pub(super) fn RegistryAssessmentAdvisories(client: ApiClient, slug: String) -> impl IntoView {
    let context = StoredValue::new((client, slug));
    let identifier = RwSignal::new(String::new());
    let assessment = RwSignal::new(String::new());
    let subject = RwSignal::new(String::new());
    let selected = RwSignal::new(None::<Result<AdvisoryQueryV1, String>>);
    let page = LocalResource::new(move || {
        let selected = selected.get();
        let (client, registry_slug) = context.get_value();
        async move {
            let Some(query) = selected else {
                return Ok(None);
            };
            let query = query?;
            let response = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::ASSESSMENT_SERVICE_GET_ADVISORY_PATH,
                    &aos_proto_types::AssessmentControlRequest {
                        registry_slug,
                        document_json: serde_json::to_vec(&query)
                            .map_err(|error| error.to_string())?,
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            let page = AdvisoryPageV1::from_slice(&response.document_json)
                .map_err(|error| error.to_string())?;
            page.validate_for(&query)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(Some(page))
        }
    });

    view! {
        <div class="assessment-advisories">
            <h3>"CVE and advisory evidence"</h3>
            <p>"Look up retained revisions by exact CVE or source identifier. A cache miss does not mean a package is unaffected. Historical findings use the selected assessment’s original snapshot and evaluation time."</p>
            <label>"CVE or advisory ID"<input prop:value=move || identifier.get() on:input=move |event| identifier.set(event_target_value(&event))/></label>
            <label>"Assessment digest (optional)"<input prop:value=move || assessment.get() on:input=move |event| assessment.set(event_target_value(&event))/></label>
            <label>"Subject in that assessment (optional)"<input prop:value=move || subject.get() on:input=move |event| subject.set(event_target_value(&event))/></label>
            <button class="secondary-button" on:click=move |_| {
                let query = (|| {
                    let digest = assessment.get_untracked().trim().to_owned();
                    let subject = subject.get_untracked().trim().to_owned();
                    let query = AdvisoryQueryV1 {
                        schema: "aos.assessment-advisory-query/v1".into(),
                        advisory_id: identifier.get_untracked().trim().to_owned(),
                        resource_scope: None,
                        assessment_digest: if digest.is_empty() { None } else { Some(Sha256Digest::parse(&digest).map_err(|error| error.to_string())?) },
                        subject_ref: (!subject.is_empty()).then_some(subject),
                        after_record: None,
                        limit: 5,
                    };
                    query.validate().map_err(|error| error.to_string())?;
                    Ok::<_, String>(query)
                })();
                selected.set(Some(query));
            }>"Look up cached evidence"</button>
            <Suspense fallback=move || view! { <p>"Reading retained advisory revisions…"</p> }>
                {move || Suspend::new(async move { match page.await.as_ref() {
                    Err(detail) => view! { <InlineError detail=detail.clone()/> }.into_any(),
                    Ok(None) => ().into_any(),
                    Ok(Some(page)) => {
                        let resource = page.resource_scope.clone();
                        let rows = page.revisions.iter().cloned().map(|revision| {
                            let record = revision.record;
                            let severity = record.severity.into_iter().map(|severity| view! {
                                <li>{format!("{} / {}: {}", severity.source, severity.scheme, severity.value)}</li>
                            }).collect_view();
                            let links = revision.finding_links.into_iter().map(|link| view! {
                                <li>{format!("{} / {}: {:?} · finding {}", link.subject_ref, link.component_ref, link.applicability, link.finding_key)}</li>
                            }).collect_view();
                            let claims = serde_json::to_string_pretty(&record.affected)
                                .unwrap_or_else(|_| "Source version ranges could not be rendered.".into());
                            view! { <article>
                                <h4>{format!("{} / {}", record.provider, record.id)}</h4>
                                <p>{format!("Modified {} · record {}", record.modified, revision.record_digest)}</p>
                                {record.withdrawn.map(|time| view! { <p>{format!("Withdrawn at {time}")}</p> })}
                                <p>{record.summary}</p><p>{format!("Equivalent identifiers: {}", record.aliases.join(", "))}</p>
                                <ul>{severity}</ul><ul>{links}</ul>
                                <details><summary>"Source version ranges and upstream fix claims"</summary><pre>{claims}</pre></details>
                            </article> }
                        }).collect_view();
                        view! {
                            <p>{format!("Retained evidence read at {}", page.as_of)}</p>
                            {page.assessment_context.as_ref().map(|context| view! {
                                <p>{format!("Historical assessment {} · evaluated {} · snapshot {}", context.assessment_digest, context.evaluated_at, context.snapshot_digest)}</p>
                            })}
                            {page.revisions.is_empty().then(|| view! { <p>"No matching retained revisions in this selection."</p> })}
                            {rows}
                            {page.next_record.map(|next| view! {
                                <button class="secondary-button" on:click=move |_| selected.update(|selected| {
                                    if let Some(Ok(query)) = selected { query.resource_scope = Some(resource.clone()); query.after_record = Some(next); }
                                })>"Next retained revisions"</button>
                            })}
                        }.into_any()
                    }
                } })}
            </Suspense>
        </div>
    }
}

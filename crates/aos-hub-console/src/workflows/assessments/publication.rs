//! Exact publication availability, including outputs without scan metadata.

use aos_assessment_runtime::publication::{
    PublicationAvailability, PublicationQueryV1, PublicationStatusV1,
};
use leptos::prelude::*;

use super::AssessmentReadGuard;
use crate::components::InlineError;
use crate::transport::{ApiClient, TransportError};

fn first_page() -> PublicationQueryV1 {
    PublicationQueryV1 {
        schema: "aos.assessment-publication-query/v1".into(),
        limit: 100,
        after_output: None,
        publication_digest: None,
        resource_scope: None,
    }
}

/// Displays current metadata availability without requesting scans or providers.
#[component]
pub(super) fn RegistryAssessmentPublication(
    client: ApiClient,
    slug: String,
    epoch: RwSignal<u64>,
    polling: RwSignal<bool>,
    active_reads: RwSignal<u32>,
) -> impl IntoView {
    let query = RwSignal::new(first_page());
    let resource = LocalResource::new(move || {
        let _ = epoch.get();
        let query = query.get();
        let client = client.clone();
        let registry_slug = slug.clone();
        let read = AssessmentReadGuard::new(active_reads);
        async move {
            let _read = read;
            let response = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::ASSESSMENT_SERVICE_GET_PUBLICATION_STATUS_PATH,
                    &aos_proto_types::AssessmentControlRequest {
                        registry_slug,
                        document_json: serde_json::to_vec(&query)
                            .map_err(|error| error.to_string())?,
                    },
                )
                .await;
            if matches!(
                &response,
                Err(TransportError::Http {
                    status: 401 | 403 | 404,
                    ..
                }) | Err(TransportError::SessionExpired)
            ) {
                polling.set(false);
            }
            let response = response.map_err(|error| error.to_string())?;
            let status = PublicationStatusV1::from_slice(&response.document_json)
                .map_err(|error| error.to_string())?;
            status
                .validate_for(&query)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(status)
        }
    });
    view! {
        <div class="assessment-publication">
            <div class="section-heading"><h3>"Publication availability"</h3>
                <button class="secondary-button" on:click=move |_| {
                    query.set(first_page());
                    polling.set(true);
                    epoch.update(|value| *value = value.wrapping_add(1));
                }>"Latest publication"</button>
            </div>
            <Suspense fallback=move || view! { <p>"Loading publication metadata…"</p> }>
                {move || Suspend::new(async move {
                    match resource.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(status) => {
                            let description = match &status.availability {
                                PublicationAvailability::NoPublication => "No authenticated release is indexed.".into(),
                                PublicationAvailability::AwaitingProjection { release } => format!(
                                    "Package metadata for release {} is incomplete. Checks await a complete publication.", release.release),
                                PublicationAvailability::InvalidProjection { release } => format!(
                                    "Package metadata for release {} could not be verified. Its assessment status is unknown.", release.release),
                                PublicationAvailability::Unassessable { unsupported_count, .. } => format!(
                                    "No declared scan inventory is available. {unsupported_count} published outputs lack scan metadata."),
                                PublicationAvailability::Ready { declared_outputs, unsupported_count, active_inventory_revision, .. } => format!(
                                    "{declared_outputs} outputs have scan declarations. {unsupported_count} lack scan metadata.{}",
                                    if active_inventory_revision.is_none() { " The assessment inventory awaits activation." } else { "" }),
                            };
                            let rows = status.unsupported_outputs.iter().map(|output| view! {
                                <tr><td>{output.package_name.clone()}</td><td>{output.version.clone()}</td>
                                    <td>{output.platform.clone()}</td><td>"Scan metadata unavailable"</td></tr>
                            }).collect_view();
                            let next = status.next_output;
                            let digest = status.publication_digest;
                            let scope = status.resource_scope.clone();
                            view! {
                                <p>{description}</p>
                                {(!status.unsupported_outputs.is_empty()).then(|| view! {
                                    <table><thead><tr><th>"Package"</th><th>"Version"</th><th>"Platform"</th><th>"Availability"</th></tr></thead>
                                        <tbody>{rows}</tbody></table>
                                })}
                                {next.map(|position| view! {
                                    <button class="secondary-button" on:click=move |_| query.update(|query| {
                                        query.after_output = Some(position);
                                        query.publication_digest = digest;
                                        query.resource_scope = Some(scope.clone());
                                    })>"Next outputs without metadata"</button>
                                })}
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

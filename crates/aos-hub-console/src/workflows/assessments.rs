//! Package assessment status and canonical result inspection in the registry UI.

use aos_assessment::input::Profile;
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::application::{AssessmentStatusV1, StatusQueryV1};
use leptos::prelude::*;

use crate::components::InlineError;
use crate::transport::ApiClient;
use super::assessment_scans::AssessmentScanControls;

/// Renders authorized current status and retained result details for a registry.
#[component]
pub(super) fn RegistryAssessments(client: ApiClient, slug: String) -> impl IntoView {
    if !client.allows("assessment.read") {
        return view! { <section class="panel"><h2>"Package assessments"</h2><p>"Assessment read access is required to view package checks."</p></section> }.into_any();
    }
    let epoch = RwSignal::new(0_u64);
    let controls = StoredValue::new((client.clone(), slug.clone()));
    let query = RwSignal::new(StatusQueryV1 {
        schema: "aos.assessment-status-query/v1".into(),
        profiles: vec![Profile::Updates, Profile::Vulnerabilities],
        limit: 100,
        after_subject: None,
        inventory_digest: None,
        policy_digest: None,
    });
    let selected = RwSignal::new(None::<String>);
    let status_client = client.clone();
    let status_slug = slug.clone();
    let resource = LocalResource::new(move || {
        let _ = epoch.get();
        let query = query.get();
        let client = status_client.clone();
        let registry_slug = status_slug.clone();
        async move {
            let query_json = serde_json::to_vec(&query).map_err(|error| error.to_string())?;
            let response = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::ASSESSMENT_SERVICE_GET_STATUS_PATH,
                    &aos_proto_types::AssessmentStatusRequest {
                        registry_slug,
                        query_json,
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            AssessmentStatusV1::from_slice(&response.document_json)
                .map_err(|error| error.to_string())
        }
    });
    let result_client = client;
    let result_slug = slug;
    let detail = LocalResource::new(move || {
        let selected = selected.get();
        let client = result_client.clone();
        let registry_slug = result_slug.clone();
        async move {
            let Some(assessment_digest) = selected else {
                return Ok(None);
            };
            let response = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::ASSESSMENT_SERVICE_GET_ASSESSMENT_PATH,
                    &aos_proto_types::AssessmentObjectRequest {
                        registry_slug,
                        assessment_digest,
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            PackageAssessmentV1::from_slice(&response.document_json)
                .map(Some)
                .map_err(|error| error.to_string())
        }
    });

    view! {
        <section class="panel assessment-panel">
            <div class="section-heading"><div><h2>"Package assessments"</h2>
                <p>"Current package checks, evidence freshness and pending scans."</p>
            </div><button class="secondary-button" on:click=move |_| {
                query.update(|query| { query.after_subject = None; query.inventory_digest = None; query.policy_digest = None; });
                epoch.update(|value| *value = value.wrapping_add(1));
            }>"Refresh"</button></div>
            <Suspense fallback=move || view! { <p>"Loading package checks…"</p> }>
                {move || Suspend::new(async move {
                    match resource.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(status) => {
                            let rows = status.subjects.iter().flat_map(|subject| subject.profiles.iter().map(|profile| {
                                let digest = profile.assessment_digest.map(|digest| digest.to_string());
                                let package = subject.package_coordinate.clone();
                                let version = subject.version.clone();
                                let platform = subject.platform.clone();
                                let profile_name = match profile.profile { Profile::Updates => "Updates", Profile::Vulnerabilities => "Vulnerabilities", Profile::LicenseSignals => "License signals" };
                                let evidence = if profile.committed_generation == 0 { "Unassessed" } else if profile.fresh { "Complete and fresh" } else { "Incomplete or expired" };
                                let pending = profile.pending;
                                view! { <tr><td>{package}</td><td>{version}</td><td>{platform}</td><td>{profile_name}</td><td>{evidence}{pending.then(|| view! { <span>" · Scan pending"</span> })}</td><td>{digest.map(|digest| view! { <button class="secondary-button" on:click=move |_| selected.set(Some(digest.clone()))>"View result"</button> })}</td></tr> }
                            })).collect_view();
                            let next = status.next_subject.clone();
                            let inventory_digest = status.inventory_digest;
                            let policy_digest = status.policy_digest;
                            view! {
                                <p class="field-note">{format!("Observed at {}", status.as_of)}</p>
                                <table><thead><tr><th>"Package"</th><th>"Version"</th><th>"Platform"</th><th>"Check"</th><th>"Evidence"</th><th>"Result"</th></tr></thead><tbody>{rows}</tbody></table>
                                {next.map(|position| view! { <button class="secondary-button" on:click=move |_| query.update(|query| {
                                    query.after_subject = Some(position.clone()); query.inventory_digest = Some(inventory_digest); query.policy_digest = Some(policy_digest);
                                })>"Next packages"</button> })}
                                <AssessmentScanControls client=controls.get_value().0 slug=controls.get_value().1 status=status.clone()/>
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
            <Suspense fallback=move || view! { <p>"Loading retained assessment…"</p> }>
                {move || Suspend::new(async move {
                    match detail.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(None) => ().into_any(),
                        Ok(Some(assessment)) => view! { <AssessmentDetails assessment=assessment.clone()/> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }.into_any()
}

#[component]
fn AssessmentDetails(assessment: PackageAssessmentV1) -> impl IntoView {
    let subject_count = assessment.subject_results.len();
    let subjects = assessment.subject_results.into_iter().take(100).map(|subject| {
        let coverage = subject.coverage.into_iter().map(|coverage| view! {
            <p>{format!("{:?}: {:?}; {} of {} components evaluated", coverage.profile, coverage.state, coverage.counts.evaluated, coverage.counts.declared)}</p>
        }).collect_view();
        let findings = subject.findings.into_iter().map(|finding| view! {
            <li><strong>{finding.advisory_ids.join(", ")}</strong>{format!(" — {:?}", finding.applicability)}
                {(!finding.exploit_signals.is_empty()).then(|| view! { <span>" · Known exploitation reported"</span> })}
            </li>
        }).collect_view();
        let versions = subject.versions.into_iter().map(|version| view! {
            <li>{format!("{}: {:?}", version.current.comparison_version, version.decision)}
                {version.eligible.map(|candidate| view! { <span>{format!(" · Eligible update {}", candidate.comparison_version)}</span> })}
            </li>
        }).collect_view();
        view! { <article><h3>{subject.subject_ref}</h3>{coverage}<ul>{versions}</ul><ul>{findings}</ul></article> }
    }).collect_view();
    view! { <div class="assessment-details"><h3>"Retained assessment"</h3>
        <p>"Coverage describes what the evidence establishes. Incomplete evidence can still contain vulnerability findings."</p>
        {(subject_count > 100).then(|| view! { <p>"Showing the first 100 subjects in this assessment."</p> })}
        {subjects}
    </div> }
}

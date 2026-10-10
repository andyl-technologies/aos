//! Package assessment status and canonical result inspection in the registry UI.

mod publication;

use publication::RegistryAssessmentPublication;
use aos_assessment::input::Profile;
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::application::{AssessmentStatusV1, StatusQueryV1};
use leptos::prelude::*;

use super::assessment_scans::AssessmentScanControls;
use super::assessment_schedules::RegistryAssessmentSchedules;
use super::assessment_notifications::RegistryAssessmentNotifications;
use super::assessment_attention::RegistryAssessmentAttention;
use super::assessment_advisories::RegistryAssessmentAdvisories;
use crate::components::InlineError;
use crate::transport::{ApiClient, TransportError};

/// Renders authorized current status and retained result details for a registry.
#[component]
pub(super) fn RegistryAssessments(client: ApiClient, slug: String) -> impl IntoView {
    if !client.allows("assessment.read") {
        return view! { <section class="panel"><h2>"Package assessments"</h2><p>"Assessment read access is required to view package checks."</p></section> }.into_any();
    }
    let epoch = RwSignal::new(0_u64);
    let polling = RwSignal::new(true);
    let active_reads = RwSignal::new(0_u32);
    let displayed = RwSignal::new(None::<AssessmentStatusV1>);
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
        let read = AssessmentReadGuard::new(active_reads);
        async move {
            let _read = read;
            let query_json = serde_json::to_vec(&query).map_err(|error| error.to_string())?;
            let response = client
                .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                    aos_proto_types::ASSESSMENT_SERVICE_GET_STATUS_PATH,
                    &aos_proto_types::AssessmentStatusRequest {
                        registry_slug,
                        query_json,
                    },
                )
                .await;
            let awaiting_publication = query.after_subject.is_none()
                && query.inventory_digest.is_none() && query.policy_digest.is_none()
                && matches!(&response, Err(TransportError::Http { status: 400, .. }));
            let status = response
                .map_err(|error| error.to_string())
                .and_then(|response| {
                    AssessmentStatusV1::from_slice(&response.document_json)
                        .map_err(|error| error.to_string())
                });
            match &status {
                Ok(status) => displayed.set(Some(status.clone())),
                Err(_) => {
                    if !awaiting_publication {
                        polling.set(false);
                    }
                    displayed.set(None);
                }
            }
            status
        }
    });
    start_status_poll(epoch, polling, active_reads);
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
                polling.set(true);
                query.update(|query| { query.after_subject = None; query.inventory_digest = None; query.policy_digest = None; });
                epoch.update(|value| *value = value.wrapping_add(1));
            }>"Refresh"</button></div>
            <RegistryAssessmentPublication client=controls.get_value().0 slug=controls.get_value().1
                epoch=epoch polling=polling active_reads=active_reads/>
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
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
            // Keep mutation controls mounted across status polls. Changing the
            // displayed inventory or selector disposes their owned tasks.
            <For each={move || displayed.get().into_iter().collect::<Vec<_>>()}
                key={|status| (status.inventory_digest, status.inventory_revision, status.policy_digest,
                    status.subjects.iter().map(|subject| subject.subject_ref.clone()).collect::<Vec<_>>())}
                children={move |status| view! {
                    <AssessmentScanControls client=controls.get_value().0 slug=controls.get_value().1 status=status/>
                }}
            />
            <RegistryAssessmentAttention client=controls.get_value().0 slug=controls.get_value().1/>
            <RegistryAssessmentSchedules client=controls.get_value().0 slug=controls.get_value().1/>
            <RegistryAssessmentNotifications client=controls.get_value().0 slug=controls.get_value().1/>
            <RegistryAssessmentAdvisories client=controls.get_value().0 slug=controls.get_value().1/>
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

/// Retains one read's lifetime so periodic refresh cannot overlap it.
pub(super) struct AssessmentReadGuard {
    active: RwSignal<u32>,
}

impl AssessmentReadGuard {
    /// Registers a read until completion, cancellation or owner disposal.
    pub(super) fn new(active: RwSignal<u32>) -> Self {
        active.update(|count| *count = count.saturating_add(1));
        Self { active }
    }
}

impl Drop for AssessmentReadGuard {
    fn drop(&mut self) {
        self.active
            .try_update(|count| *count = count.saturating_sub(1));
    }
}

/// Polls visible assessment views while preserving in-flight work and owners.
pub(super) fn start_status_poll(
    epoch: RwSignal<u64>,
    enabled: RwSignal<bool>,
    active: RwSignal<u32>,
) {
    if let Ok(interval) = leptos::leptos_dom::helpers::set_interval_with_handle(
        move || {
            if enabled.get_untracked() && !document().hidden() && active.get_untracked() == 0 {
                epoch.update(|value| *value = value.wrapping_add(1));
            }
        },
        std::time::Duration::from_secs(5),
    ) {
        on_cleanup(move || interval.clear());
    }
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

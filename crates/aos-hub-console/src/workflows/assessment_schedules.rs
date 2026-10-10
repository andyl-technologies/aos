//! Recurring review inspection and revision-bound schedule forms.

use aos_assessment::input::{FreshnessMode, Profile};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::scan::ScanLimits;
use aos_assessment_runtime::schedules::{
    ScheduleConfigurationV1, SchedulePageV1, ScheduleQueryV1, ScheduleV1, ScheduleWriteV1,
};
use leptos::prelude::*;

use super::assessments::{start_status_poll, AssessmentReadGuard};
use crate::components::InlineError;
use crate::mutation::{idempotency_key, scoped_workflow_tasks, PendingPlan};
use crate::transport::ApiClient;

/// Shows credential-bounded recurring reviews and their current due state.
#[component]
pub(super) fn RegistryAssessmentSchedules(client: ApiClient, slug: String) -> impl IntoView {
    let can_review = client.allows("assessment.schedule.manage")
        && client.allows("assessment.scan")
        && client.allows("assessment.read");
    let context = StoredValue::new((client, slug));
    let tasks = scoped_workflow_tasks();
    let epoch = RwSignal::new(0_u64);
    let polling = RwSignal::new(true);
    let live_poll = RwSignal::new(true);
    let active = RwSignal::new(0_u32);
    let scope = RwSignal::new(None::<String>);
    let after = RwSignal::new(None::<String>);
    let selected = RwSignal::new(None::<ScheduleV1>);
    let identity = RwSignal::new(String::new());
    let packages = RwSignal::new(String::new());
    let cadence = RwSignal::new("3600".to_owned());
    let continuous = RwSignal::new(false);
    let expiry = RwSignal::new(String::new());
    let use_service = RwSignal::new(false);
    let service_credential = RwSignal::new(String::new());
    let updates = RwSignal::new(true);
    let vulnerabilities = RwSignal::new(true);
    let licenses = RwSignal::new(false);
    let enabled = RwSignal::new(true);
    let busy = RwSignal::new(false);
    let failure = RwSignal::new(None::<String>);
    let pending = RwSignal::new(None::<(PendingPlan, ScheduleWriteV1)>);

    let page = LocalResource::new(move || {
        let _ = epoch.get();
        let query = ScheduleQueryV1 {
            schema: "aos.assessment-schedule-query/v1".into(),
            limit: 10,
            resource_scope: scope.get_untracked(),
            schedule_id: None,
            after_schedule: after.get(),
        };
        let (client, registry_slug) = context.get_value();
        let read = AssessmentReadGuard::new(active);
        async move {
            let _read = read;
            let outcome = async {
                let response = client
                    .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_LIST_SCHEDULES_PATH,
                        &aos_proto_types::AssessmentControlRequest {
                            registry_slug,
                            document_json: serde_json::to_vec(&query)
                                .map_err(|error| error.to_string())?,
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let page = SchedulePageV1::from_slice(&response.document_json)
                    .map_err(|error| error.to_string())?;
                if query
                    .resource_scope
                    .as_ref()
                    .is_some_and(|scope| scope != &page.resource_scope)
                {
                    return Err(
                        "The recurring-review resource changed. Refresh before editing.".to_owned(),
                    );
                }
                scope.set(Some(page.resource_scope.clone()));
                // Hold paginated reviews until refresh instead of consuming a
                // new retained capture on every periodic first-page read.
                if page.next_schedule.is_some() || query.after_schedule.is_some() {
                    live_poll.set(false);
                }
                Ok::<_, String>(page)
            }
            .await;
            if outcome.is_err() {
                polling.set(false);
                live_poll.set(false);
            }
            outcome
        }
    });
    start_status_poll(epoch, live_poll, active);

    let review = move |_| {
        if busy.get_untracked() || !can_review || !polling.get_untracked() {
            return;
        }
        let Some(resource_scope) = scope.get_untracked() else {
            return;
        };
        let construct = || -> Result<ScheduleWriteV1, String> {
            let mut coordinates = packages
                .get_untracked()
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            coordinates.sort();
            let mut profiles = Vec::new();
            if updates.get_untracked() {
                profiles.push(Profile::Updates);
            }
            if vulnerabilities.get_untracked() {
                profiles.push(Profile::Vulnerabilities);
            }
            if licenses.get_untracked() {
                profiles.push(Profile::LicenseSignals);
            }
            profiles.sort();
            let existing = selected.get_untracked();
            let request = ScheduleWriteV1 {
                service_credential_id: if use_service.get_untracked() && enabled.get_untracked() {
                    let credential = service_credential.get_untracked().trim().to_owned();
                    aos_assessment_runtime::service_authority::validate_service_credential_id(
                        &credential,
                    )
                    .map_err(|_| {
                        "Enter the existing service credential identity for this exact review"
                            .to_owned()
                    })?;
                    Some(credential)
                } else {
                    None
                },
                schema: "aos.assessment-schedule-write/v1".into(),
                resource_scope,
                schedule_id: identity.get_untracked().trim().to_owned(),
                expected_revision: existing.as_ref().map_or(0, |schedule| schedule.revision),
                enabled: enabled.get_untracked(),
                configuration: ScheduleConfigurationV1 {
                    continuous: continuous.get_untracked(),
                    schema: "aos.assessment-schedule-configuration/v1".into(),
                    packages: coordinates,
                    profiles,
                    freshness: existing
                        .as_ref()
                        .map_or(FreshnessMode::RefreshStale, |schedule| {
                            schedule.configuration.freshness
                        }),
                    cadence_seconds: cadence.get_untracked().parse().map_err(|_| {
                        "Enter a whole number of seconds for the interval".to_owned()
                    })?,
                    review_expires_at: Timestamp::parse(expiry.get_untracked().trim())
                        .map_err(|error| error.to_string())?,
                    limits: existing
                        .as_ref()
                        .map_or_else(ScanLimits::default, |schedule| {
                            schedule.configuration.limits.clone()
                        }),
                },
            };
            request.validate().map_err(|error| error.to_string())?;
            Ok(request)
        };
        let request = match construct() {
            Ok(request) => request,
            Err(error) => {
                failure.set(Some(error));
                return;
            }
        };
        let document_json = match serde_json::to_vec(&request) {
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
            let result = async {
                let key = idempotency_key("assessment-review");
                let response = client
                    .call::<_, aos_proto_types::TopologyPlanResponse>(
                        aos_proto_types::ASSESSMENT_SERVICE_PLAN_WRITE_SCHEDULE_PATH,
                        &aos_proto_types::PlanAssessmentReviewRequest {
                            registry_slug,
                            document_json: document_json,
                            expected_resource_version: request.expected_revision.to_string(),
                            idempotency_key: key.clone(),
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let plan = PendingPlan::from_response(response, key)?;
                Ok::<_, String>((plan, request))
            }
            .await;
            busy.set(false);
            match result {
                Ok(review) => {
                    if scope.get_untracked().as_ref() == Some(&review.1.resource_scope) {
                        pending.set(Some(review));
                    }
                }
                Err(error) => failure.set(Some(error)),
            }
        });
    };

    let apply = move |_| {
        if busy.get_untracked() || !can_review || !polling.get_untracked() {
            return;
        }
        let Some((plan, request)) = pending.get_untracked() else {
            return;
        };
        if scope.get_untracked().as_ref() != Some(&request.resource_scope) {
            pending.set(None);
            failure.set(Some(
                "The reviewed resource changed. Plan again before applying.".into(),
            ));
            return;
        }
        let (client, _) = context.get_value();
        busy.set(true);
        failure.set(None);
        tasks.spawn(async move {
            let outcome =
                async {
                    let response = client
                        .call::<_, aos_proto_types::AssessmentDocumentResponse>(
                            aos_proto_types::ASSESSMENT_SERVICE_WRITE_SCHEDULE_PATH,
                            &plan.registry_apply(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    let admitted = ScheduleV1::from_slice(&response.document_json)
                        .map_err(|error| error.to_string())?;
                    if admitted.resource_scope != request.resource_scope
                    || admitted.schedule_id != request.schedule_id
                    || admitted.enabled != request.enabled
                    || admitted.configuration != request.configuration
                    || admitted.service_authority.as_ref().map(|authority| authority.credential_ref)
                        != request.service_credential_id.as_deref()
                            .map(aos_assessment_runtime::service_authority::service_credential_ref)
                            .transpose().map_err(|error| error.to_string())?
                    || request.expected_revision.checked_add(1) != Some(admitted.revision)
                {
                    return Err(
                        "The receipt differs from the exact reviewed configuration".to_owned()
                    );
                }
                    Ok::<_, String>(admitted)
                }
                .await;
            busy.set(false);
            match outcome {
                Ok(admitted) => {
                    if scope.get_untracked().as_ref() == Some(&request.resource_scope) {
                        selected.set(Some(admitted));
                        pending.set(None);
                        after.set(None);
                        live_poll.set(true);
                        epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
                    }
                }
                Err(error) => failure.set(Some(error)),
            }
        });
    };

    view! {
        <section class="assessment-schedules">
            <div class="section-heading"><h3>"Recurring scans"</h3><button class="secondary-button" on:click=move |_| {
                pending.set(None); selected.set(None); scope.set(None); after.set(None); polling.set(true); live_poll.set(true);
                epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
            }>"Refresh schedules"</button></div>
            <Suspense fallback=move || view! { <p>"Loading recurring reviews…"</p> }>
                {move || Suspend::new(async move {
                    match page.await.as_ref() {
                        Err(error) => view! { <InlineError detail=error.clone()/> }.into_any(),
                        Ok(page) => {
                            let observed_at = page.as_of.to_string();
                            let now = page.as_of.clone();
                            let rows = page.schedules.iter().cloned().map(move |schedule| {
                                let label = schedule.schedule_id.clone();
                                let state = if !schedule.enabled { "Disabled" } else if schedule.authority_expires_at <= now { "Review expired" } else { "Enabled" };
                                let due = schedule.next_due_at.to_string();
                                let deadline = schedule.authority_expires_at.to_string();
                                view! { <tr><td>{label}</td><td>{state}</td><td>{due}</td><td>{deadline}</td><td>
                                    {can_review.then(|| view! { <button class="secondary-button" disabled=move || (busy.get() || pending.get().is_some()) on:click=move |_| {
                                        identity.set(schedule.schedule_id.clone()); packages.set(schedule.configuration.packages.join("\n"));
                                        cadence.set(schedule.configuration.cadence_seconds.to_string()); expiry.set(schedule.configuration.review_expires_at.to_string());
                                        continuous.set(schedule.configuration.continuous);
                                        use_service.set(schedule.service_authority.is_some()); service_credential.set(String::new());
                                        updates.set(schedule.configuration.profiles.contains(&Profile::Updates)); vulnerabilities.set(schedule.configuration.profiles.contains(&Profile::Vulnerabilities));
                                        licenses.set(schedule.configuration.profiles.contains(&Profile::LicenseSignals));
                                        enabled.set(schedule.enabled); selected.set(Some(schedule.clone())); failure.set(None);
                                    }>"Edit review"</button> })}
                                </td></tr> }
                            }).collect_view();
                            let next = page.next_schedule.clone();
                            view! { <p>"Observed at "{observed_at}</p><table><thead><tr><th>"Schedule"</th><th>"State"</th><th>"Next due"</th><th>"Authority expires"</th><th>"Review"</th></tr></thead><tbody>{rows}</tbody></table>
                                {next.map(|identity| view! { <button class="secondary-button" on:click=move |_| after.set(Some(identity.clone()))>"Next schedules"</button> })}
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
            {can_review.then(|| view! {
                <div class="assessment-schedule-form">
                    <h4>"Review recurring scan"</h4>
                    <label>"Schedule name"<input prop:value=move || identity.get() disabled=move || (busy.get() || pending.get().is_some()) || selected.get().is_some() on:input=move |event| identity.set(event_target_value(&event))/></label>
                    <label>"Packages (one exact coordinate per line)"<textarea prop:value=move || packages.get() disabled=move || (busy.get() || pending.get().is_some()) on:input=move |event| packages.set(event_target_value(&event))/></label>
                    <label>"Interval in seconds"<input type="number" min="60" max="2592000" prop:value=move || cadence.get() disabled=move || (busy.get() || pending.get().is_some()) on:input=move |event| cadence.set(event_target_value(&event))/></label>
                    <label><input type="checkbox" prop:checked=move || continuous.get() disabled=move || busy.get() || pending.get().is_some() on:change=move |event| continuous.set(event_target_checked(&event))/>"Also assess admitted inventory and policy changes"</label>
                    <label>"Review expires (UTC)"<input placeholder="2026-10-10T00:00:00Z" prop:value=move || expiry.get() disabled=move || (busy.get() || pending.get().is_some()) on:input=move |event| expiry.set(event_target_value(&event))/></label>
                    <label><input type="checkbox" prop:checked=move || updates.get() disabled=move || (busy.get() || pending.get().is_some()) on:change=move |event| updates.set(event_target_checked(&event))/>"Package updates"</label>
                    <label><input type="checkbox" prop:checked=move || vulnerabilities.get() disabled=move || (busy.get() || pending.get().is_some()) on:change=move |event| vulnerabilities.set(event_target_checked(&event))/>"Vulnerabilities"</label>
                    <label><input type="checkbox" prop:checked=move || licenses.get() disabled=move || (busy.get() || pending.get().is_some()) on:change=move |event| licenses.set(event_target_checked(&event))/>"License signals"</label>
                    <label><input type="checkbox" prop:checked=move || enabled.get() disabled=move || (busy.get() || pending.get().is_some()) on:change=move |event| enabled.set(event_target_checked(&event))/>"Enable due scans"</label>
                    <label><input type="checkbox" prop:checked=move || use_service.get() disabled=move || (busy.get() || pending.get().is_some()) on:change=move |event| use_service.set(event_target_checked(&event))/>"Review an existing service credential for recurring execution"</label>
                    {move || use_service.get().then(|| view! {
                        <label>"Service credential identity"<input prop:value=move || service_credential.get() disabled=move || (busy.get() || pending.get().is_some()) on:input=move |event| service_credential.set(event_target_value(&event))/></label>
                        <p>"Use the credential identity from the registry organization, not its secret. Service reviews expire within thirty days; replacement requires selecting the credential again."</p>
                    })}
                    <button class="primary-button" disabled=move || (busy.get() || pending.get().is_some()) || !polling.get() || scope.get().is_none() on:click=review>"Plan schedule review"</button>
                    <button class="secondary-button" disabled=move || (busy.get() || pending.get().is_some()) on:click=move |_| { selected.set(None); identity.set(String::new()); use_service.set(false); service_credential.set(String::new()); continuous.set(false); failure.set(None); }>"New schedule"</button>

                    {move || pending.get().map(|(review, _)| {
                        let effects = review.plan.effects.join("\n");
                        let warnings = review.plan.warnings.join("\n");
                        view! {
                            <div class="assessment-review-confirmation">
                                <h4>"Confirm exact configuration"</h4>
                                <pre>{effects}</pre><p>{warnings}</p>
                                <p>{format!("Plan {} · expires {} · commitment {}", review.plan.plan_id, review.plan.expires_at, review.plan.confirmation_hash)}</p>
                                <button class="primary-button" disabled=move || busy.get() || !polling.get() on:click=apply>"Apply exact reviewed configuration"</button>
                                <button class="secondary-button" disabled=move || busy.get() on:click=move |_| pending.set(None)>"Discard review"</button>
                            </div>
                        }
                    })}
                    {move || failure.get().map(|detail| view! { <InlineError detail=detail/> })}
                </div>
            })}
        </section>
    }
}

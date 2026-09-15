//! Cross-resource cache integration preview editor.
//!
//! Publication, retention, and population remain separate durable resources.
//! This editor previews their combined topology effects without creating an
//! unsigned aggregate or implying that one relationship owns the others.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::{InlineError, HelpTooltip};
use crate::transport::ApiClient;

#[derive(Clone, Copy)]
struct PreviewSignals {
    registry_id: RwSignal<String>,
    use_for_clients: RwSignal<bool>,
    retain_current: RwSignal<bool>,
    retain_recent: RwSignal<String>,
    retain_all: RwSignal<bool>,
    population_mode: RwSignal<String>,
    population_trigger: RwSignal<String>,
}

impl PreviewSignals {
    fn new() -> Self {
        Self {
            registry_id: RwSignal::new(String::new()),
            use_for_clients: RwSignal::new(false),
            retain_current: RwSignal::new(false),
            retain_recent: RwSignal::new(String::new()),
            retain_all: RwSignal::new(false),
            population_mode: RwSignal::new("none".to_string()),
            population_trigger: RwSignal::new("release".to_string()),
        }
    }

    fn request(
        self,
        cache_id: &str,
    ) -> Result<aos_proto_types::PreviewCacheIntegrationRequest, String> {
        let registry_id = required(self.registry_id.get_untracked(), "Registry stable ID")?;
        let publication = self.use_for_clients.get_untracked().then(|| {
            let entry_id = crate::mutation::idempotency_key("cache-stack-entry");
            aos_proto_types::ConsumerCacheChange {
                operation: "add".to_string(),
                entry_id: String::new(),
                desired: Some(aos_proto_types::ConsumerCacheStackEntry {
                    entry_id,
                    source: Some(
                        aos_proto_types::consumer_cache_stack_entry::Source::BinaryCacheId(
                            cache_id.to_string(),
                        ),
                    ),
                    priority: 0,
                    mirror_group_id: String::new(),
                }),
                before_entry_id: String::new(),
                mirror_with_entry_id: String::new(),
            }
        });
        let retention = self.retention()?;
        let population = self.population();
        if publication.is_none() && retention.is_none() && population.is_none() {
            return Err(
                "Select at least one publication, retention, or population relationship"
                    .to_string(),
            );
        }

        Ok(aos_proto_types::PreviewCacheIntegrationRequest {
            cache_id: cache_id.to_string(),
            registry_id,
            publication,
            retention,
            population,
        })
    }

    fn retention(self) -> Result<Option<aos_proto_types::RetentionSubscriptionSpec>, String> {
        let recent = optional_u32(&self.retain_recent.get_untracked(), "Recent release count")?;
        let current_catalog = self.retain_current.get_untracked();
        let all_releases = self.retain_all.get_untracked();
        if !current_catalog && recent.is_none() && !all_releases {
            return Ok(None);
        }
        Ok(Some(aos_proto_types::RetentionSubscriptionSpec {
            selector: Some(aos_proto_types::RetentionSelector {
                current_catalog,
                channel_targets: None,
                recent_releases: recent.map(|count| aos_proto_types::RecentReleaseSelector {
                    count,
                    include_prereleases: false,
                }),
                release_tags: Vec::new(),
                semver: None,
                all_releases,
            }),
            removal_grace_seconds: 0,
        }))
    }

    fn population(self) -> Option<aos_proto_types::PopulationTargetSpec> {
        let mode = self.population_mode.get_untracked();
        (mode != "none").then(|| aos_proto_types::PopulationTargetSpec {
            trigger: self.population_trigger.get_untracked(),
            required: mode == "required",
            placement_policy_revision_id: String::new(),
            validation_gate: "integrity".to_string(),
        })
    }
}

/// Renders a preview-only editor for all cache-to-registry relationships.
#[component]
pub(super) fn CacheIntegrationPreview(client: ApiClient, cache_id: String) -> impl IntoView {
    let fields = PreviewSignals::new();
    let result = RwSignal::new(None::<aos_proto_types::PreviewCacheIntegrationResponse>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let on_submit = move |event: SubmitEvent| {
        event.prevent_default();
        let request = match fields.request(&cache_id) {
            Ok(request) => request,
            Err(detail) => {
                error.set(Some(detail));
                return;
            }
        };
        let client = client.clone();
        error.set(None);
        result.set(None);
        busy.set(true);
        spawn_local(async move {
            match client
                .call(
                    aos_proto_types::CACHE_INTEGRATION_SERVICE_PREVIEW_CACHE_INTEGRATION_PATH,
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
        <section class="panel resource-panel">
            <div class="section-heading">
                <div>
                    <p class="section-kicker">"Cross-resource preview"</p>
                    <h2>"Plan an integration"<HelpTooltip term="Plan an integration" summary="Preview publication, retention roots, and proactive population together. Apply each relationship from its owning settings page."/></h2>
                </div>
            </div>
            <form class="editor-form" on:submit=on_submit>
                <label>
                    <span>"Registry stable ID"</span>
                    <input
                        required
                        prop:value=move || fields.registry_id.get()
                        on:input=move |event| fields.registry_id.set(event_target_value(&event))
                    />
                </label>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || fields.use_for_clients.get()
                        on:change=move |event| fields.use_for_clients.set(event_target_checked(&event))
                    />
                    <span>"Publish this cache in the registry's signed consumer stack"</span>
                </label>
                <fieldset>
                    <legend>"Retention roots"</legend>
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || fields.retain_current.get()
                            on:change=move |event| fields.retain_current.set(event_target_checked(&event))
                        />
                        <span>"Current signed catalog"</span>
                    </label>
                    <label>
                        <span>"Recent releases (optional)"</span>
                        <input
                            type="number"
                            min="1"
                            prop:value=move || fields.retain_recent.get()
                            on:input=move |event| fields.retain_recent.set(event_target_value(&event))
                        />
                    </label>
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || fields.retain_all.get()
                            on:change=move |event| fields.retain_all.set(event_target_checked(&event))
                        />
                        <span>"All signed releases"</span>
                    </label>
                </fieldset>
                <label>
                    <span>"Population guarantee"</span>
                    <select
                        prop:value=move || fields.population_mode.get()
                        on:change=move |event| fields.population_mode.set(event_target_value(&event))
                    >
                        <option value="none">"Do not populate"</option>
                        <option value="optional">"Best effort"</option>
                        <option value="required">"Required coverage target"</option>
                    </select>
                </label>
                <label>
                    <span>"Population trigger"</span>
                    <select
                        prop:value=move || fields.population_trigger.get()
                        disabled=move || fields.population_mode.get() == "none"
                        on:change=move |event| fields.population_trigger.set(event_target_value(&event))
                    >
                        <option value="release">"Release"</option>
                        <option value="continuous">"Continuous"</option>
                        <option value="manual">"Manual"</option>
                    </select>
                </label>
                <button class="secondary-button" type="submit" disabled=move || busy.get()>
                    {move || if busy.get() { "Previewing…" } else { "Preview integration" }}
                </button>
            </form>
            {move || error.get().map(|detail| view! { <InlineError detail=detail/> })}
            {move || result.get().map(|response| view! {
                <div class="review-columns">
                    <PlanSummary title="Publication" plan=response.publication_plan/>
                    <PlanSummary title="Retention" plan=response.retention_plan/>
                    <PlanSummary title="Population" plan=response.population_plan/>
                </div>
            })}
        </section>
    }
}

#[component]
fn PlanSummary(title: &'static str, plan: Option<aos_proto_types::TopologyPlan>) -> impl IntoView {
    view! {
        <div class="revision-card">
            <h3>{title}</h3>
            {match plan {
                Some(plan) => view! {
                    <ul>
                        {plan.effects.into_iter().map(|effect| view! { <li>{effect}</li> }).collect_view()}
                    </ul>
                    {(!plan.warnings.is_empty()).then(|| view! {
                        <div class="warning-list">
                            {plan.warnings.into_iter().map(|warning| view! { <p>{warning}</p> }).collect_view()}
                        </div>
                    })}
                }
                .into_any(),
                None => view! { <p class="muted">"No change selected."</p> }.into_any(),
            }}
        </div>
    }
}

fn required(value: String, label: &str) -> Result<String, String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(value)
    }
}

fn optional_u32(value: &str, label: &str) -> Result<Option<u32>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed > 0)
        .map(Some)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_counts_are_positive() {
        assert_eq!(optional_u32("", "Count"), Ok(None));
        assert_eq!(optional_u32("2", "Count"), Ok(Some(2)));
        assert!(optional_u32("0", "Count").is_err());
        assert!(optional_u32("many", "Count").is_err());
    }
}

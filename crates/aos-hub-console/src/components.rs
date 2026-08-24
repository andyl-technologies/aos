//! Reusable visual primitives for typed control-plane workflows.
//!
//! Resource pages compose these primitives rather than inventing page-local
//! review, error, empty, and status treatments. In particular, every durable
//! mutation presents the server-issued effects and warnings through
//! [`ReviewedPlanCard`] before invoking apply.

use leptos::prelude::*;

use aos_hub_console_contract::HashPresentation;

/// Renders a compact hash with the shared full-value tooltip and copy action.
#[component]
pub fn HashValue(
    /// Complete hash retained for the tooltip and clipboard action.
    value: String,
) -> impl IntoView {
    let presentation = HashPresentation::new(&value);
    let compact = presentation.compact;
    view! {
        <span class="hash-control">
            <span class="hash-value" data-hash-value=value.clone() tabindex="0">
                <code aria-label=value.clone()>{compact}</code>
                <span class="hash-tooltip" role="tooltip">{value.clone()}</span>
            </span>
            <button
                type="button"
                class="hash-copy"
                data-copy-value=value
                aria-label="Copy full hash"
            >
                "copy"
            </button>
        </span>
    }
}

/// Renders secondary guidance through the shared attached-help popover.
///
/// The concise heading remains visible while the explanation stays available
/// on hover, keyboard focus, or click. The `title` attribute provides a native
/// fallback when JavaScript is unavailable.
#[component]
pub fn HelpTooltip(
    /// Human-readable name for the concept being explained.
    term: &'static str,
    /// Concise explanation shown in the help card.
    summary: &'static str,
) -> impl IntoView {
    view! {
        <span class="help">
            <button
                type="button"
                class="help-mark"
                aria-label=format!("About {term}")
                aria-expanded="false"
                title=summary
            >
                "?"
            </button>
            <span class="help-card" role="tooltip">
                <span class="help-head">
                    {term}
                    <span class="help-tag">"about"</span>
                </span>
                <span class="help-sum">{summary}</span>
            </span>
        </span>
    }
}

/// Renders one compact lifecycle or health state.
#[component]
pub fn StatusBadge(
    /// Stable machine state rendered as visible text.
    state: String,
    /// Whether the state is healthy or complete.
    #[prop(default = false)]
    positive: bool,
) -> impl IntoView {
    let class = if positive {
        "status-badge positive"
    } else {
        "status-badge"
    };
    view! { <span class=class>{state}</span> }
}

/// Renders a bounded error adjacent to the action that failed.
#[component]
pub fn InlineError(
    /// User-safe failure detail returned by the typed transport.
    detail: String,
) -> impl IntoView {
    view! {
        <div class="inline-error" role="alert">
            <strong>"Request failed"</strong>
            <p>{detail}</p>
        </div>
    }
}

/// Renders an intentional empty inventory with one optional next action.
#[component]
pub fn EmptyState(
    /// Concise empty-state heading.
    title: String,
    /// Explanation of what the resource represents.
    detail: String,
    /// Optional action label.
    action_label: Option<String>,
    /// Optional action callback.
    action: Option<Callback<()>>,
) -> impl IntoView {
    view! {
        <div class="empty-state">
            <h2>{title}</h2>
            <p>{detail}</p>
            {action_label.zip(action).map(|(label, action)| view! {
                <button class="button" type="button" on:click=move |_| action.run(())>{label}</button>
            })}
        </div>
    }
}

/// Presents the immutable server-issued effects before an explicit apply.
#[component]
pub fn ReviewedPlanCard(
    /// Exact plan returned by the planning API.
    plan: aos_proto_types::TopologyPlan,
    /// Whether an apply request is currently in flight.
    applying: bool,
    /// Explicit apply action for this exact plan and confirmation hash.
    on_apply: Callback<()>,
    /// Action that discards the current plan and returns to editing.
    on_cancel: Callback<()>,
) -> impl IntoView {
    let apply_label = if applying {
        "Applying…"
    } else {
        "Apply plan"
    };
    view! {
        <section class="panel review-card" aria-labelledby="review-plan-title">
            <div class="review-heading">
                <div>
                    <p class="section-kicker">"Immutable review"</p>
                    <h2 id="review-plan-title">"Confirm these effects"</h2>
                </div>
                <code>{plan.plan_id}</code>
            </div>
            <div class="review-columns">
                <div>
                    <h3>"Effects"</h3>
                    <ul>
                        {plan.effects.into_iter().map(|effect| view! { <li>{effect}</li> }).collect_view()}
                    </ul>
                </div>
                {(!plan.warnings.is_empty()).then(|| view! {
                    <div class="warning-list">
                        <h3>"Warnings"</h3>
                        <ul>
                            {plan.warnings.into_iter().map(|warning| view! { <li>{warning}</li> }).collect_view()}
                        </ul>
                    </div>
                })}
            </div>
            <div class="review-actions">
                <button class="secondary-button" type="button" disabled=applying on:click=move |_| on_cancel.run(())>
                    "Back to editor"
                </button>
                <button class="button" type="button" disabled=applying on:click=move |_| on_apply.run(())>
                    {apply_label}
                </button>
            </div>
        </section>
    }
}

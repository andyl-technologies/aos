//! Bounded artifact review tables shared by current and replacement candidates.
//!
//! Filtering scans the immutable inventory once, while each render creates at
//! most fifty rows. Missing-object membership uses one set for the review.

use std::collections::BTreeSet;

use aos_registry_format::staging::StageObject;
use leptos::prelude::*;

use crate::components::{HashValue, StatusBadge};
use crate::staging::{INVENTORY_PAGE_SIZE, artifact_label, inventory_page};

/// Renders a searchable, paginated exact inventory with optional upload status.
#[component]
pub(super) fn StageInventory(
    inventory: Vec<StageObject>,
    #[prop(optional)] missing_paths: Option<Vec<String>>,
) -> impl IntoView {
    let show_status = missing_paths.is_some();
    let missing = StoredValue::new(
        missing_paths
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>(),
    );
    let inventory = StoredValue::new(inventory);
    let query = RwSignal::new(String::new());
    let page = RwSignal::new(0_usize);
    let window = Memo::new(move |_| {
        inventory.with_value(|objects| inventory_page(objects, &query.get(), page.get()))
    });

    view! {
        <div class="stage-inventory">
            <label><span>"Filter artifact paths or types"</span><input type="search" prop:value=move || query.get() on:input=move |event| { query.set(event_target_value(&event)); page.set(0); }/></label>
            <p class="muted" role="status">{move || {
                let window = window.get();
                if window.matched == 0 {
                    "No matching artifacts.".to_string()
                } else {
                    let start = page.get() * INVENTORY_PAGE_SIZE;
                    format!("{}–{} of {} matching artifacts", start + 1, start + window.indices.len(), window.matched)
                }
            }}</p>
            <table class="resource-table">
                <thead><tr><th>"Artifact"</th><th>"Path"</th><th>"Bytes"</th><th>"SHA-256"</th>{show_status.then(|| view! { <th>"Upload"</th> })}</tr></thead>
                <tbody>{move || {
                    let indices = window.get().indices;
                    inventory.with_value(|objects| indices.into_iter().map(|index| {
                        // The indices and rows share this immutable inventory.
                        let object = objects[index].clone();
                        let absent = missing.with_value(|paths| paths.contains(&object.path));
                        view! {
                            <tr><td>{artifact_label(&object.kind)}</td><td><code>{object.path}</code></td><td>{object.byte_size}</td><td><HashValue value=object.sha256/></td>{show_status.then(|| view! {
                                <td><StatusBadge state=if absent { "Upload needed".to_string() } else { "Verified".to_string() } positive=!absent/></td>
                            })}</tr>
                        }
                    }).collect_view())
                }}</tbody>
            </table>
            <div class="form-actions">
                <button class="secondary-button" type="button" disabled=move || page.get() == 0 on:click=move |_| page.update(|value| *value = value.saturating_sub(1))>"Previous artifacts"</button>
                <span>{move || format!("Page {} of {}", page.get() + 1, window.get().pages)}</span>
                <button class="secondary-button" type="button" disabled=move || page.get() + 1 >= window.get().pages on:click=move |_| page.update(|value| *value += 1)>"Next artifacts"</button>
            </div>
        </div>
    }
}

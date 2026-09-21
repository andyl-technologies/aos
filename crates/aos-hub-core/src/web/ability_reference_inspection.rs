//! Shared checked-graph projection for authenticated package browse data.

use std::fmt::Write as _;

use anyhow::{Context as _, Result};
#[cfg(test)]
use aos_ability_inspect::{GraphQuery, ReferenceGraphSlice};
use aos_ability_inspect::{ReferenceInspectionInput, ReferenceInspectionView};

use super::ability_reference_page::PackageAbilityReferencePanel;
use super::render::escape;

/// Queries the shared public inspector after rechecking the signed projection.
///
/// # Errors
///
/// Returns an error if locator identity or canonical bytes differ from the
/// decoded reference, or if inspection checking or querying fails.
#[cfg(test)]
pub(super) fn checked_slice(
    panel: &PackageAbilityReferencePanel,
    query: &GraphQuery,
) -> Result<ReferenceGraphSlice> {
    checked_view(panel)?.query(query).map_err(Into::into)
}

fn checked_view(panel: &PackageAbilityReferencePanel) -> Result<ReferenceInspectionView> {
    panel
        .projection
        .validate()
        .context("validating authenticated package reference")?;
    let input = ReferenceInspectionInput::new(panel.projection.ability_reference.clone())?;
    let digest = aos_contract::Sha256Digest::of_bytes(&input.canonical_bytes()?);
    let checked = input.check(Some(digest))?;
    ReferenceInspectionView::from_checked(&checked).map_err(Into::into)
}

/// Renders the canonical shared graph summary used as the page's primary map.
pub(super) fn section(panel: &PackageAbilityReferencePanel) -> Result<String> {
    let slice = checked_view(panel)?.complete_slice()?;

    let mut html = String::from(
        "<h3>Checked public contract graph</h3><p class=\"dim\">This bounded graph uses the same typed identities and relationship meanings as <code>aos ability inspect</code> and editor tooling.</p>",
    );
    html.push_str("<table><thead><tr><th>node</th><th>typed identity</th></tr></thead><tbody>");
    for node in slice.nodes() {
        let key = aos_contract::canonical::to_vec(&node.key())
            .context("encoding public inspection node identity")?;
        let key = std::str::from_utf8(&key).context("inspection identity is not UTF-8")?;
        let _ = write!(
            html,
            "<tr><td>{}</td><td><code>{}</code></td></tr>",
            escape(node_kind(node)),
            escape(key),
        );
    }
    html.push_str("</tbody></table>");

    if !slice.edges().is_empty() {
        html.push_str("<h4>Relationships</h4><ul>");
        for edge in slice.edges() {
            let from = canonical_text(&edge.from)?;
            let to = canonical_text(&edge.to)?;
            let relation = canonical_text(&edge.relation)?;
            let _ = write!(
                html,
                "<li><code>{}</code> {} <code>{}</code></li>",
                escape(&from),
                escape(relation.trim_matches('"')),
                escape(&to),
            );
        }
        html.push_str("</ul>");
    }

    html.push_str("<h4>Inspection limits</h4><ul class=\"dim\">");
    for diagnostic in slice.diagnostics() {
        let code = canonical_text(&diagnostic.code)?;
        let _ = write!(
            html,
            "<li><code>{}</code>: {}</li>",
            escape(code.trim_matches('"')),
            escape(&diagnostic.message),
        );
    }
    html.push_str("</ul>");
    Ok(html)
}

fn canonical_text(value: &impl serde::Serialize) -> Result<String> {
    let bytes = aos_contract::canonical::to_vec(value)?;
    String::from_utf8(bytes).context("canonical inspection value is not UTF-8")
}

fn node_kind(node: &aos_ability_inspect::InspectionNode) -> &'static str {
    match node {
        aos_ability_inspect::InspectionNode::Package { .. } => "package",
        aos_ability_inspect::InspectionNode::Implementation { .. } => "implementation",
        aos_ability_inspect::InspectionNode::Interface { .. } => "interface",
        aos_ability_inspect::InspectionNode::InterfaceReference { .. } => "interface reference",
        _ => "deployment-only node",
    }
}

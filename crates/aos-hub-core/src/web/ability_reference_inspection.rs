//! Shared checked-graph projection for authenticated package browse data.

use std::fmt::Write as _;

use anyhow::{Context as _, Result, ensure};
use aos_ability_inspect::{
    GraphQuery, NodeKey, ReferenceGraphSlice, ReferenceInspectionInput, ReferenceInspectionView,
};

use super::ability_reference_page::PackageAbilityReferencePanel;
use super::render::escape;

/// Queries the shared public inspector after rechecking the panel's locator.
///
/// The locator came from the selected signed registry commit. This function
/// binds its retained canonical bytes and identities to the graph input before
/// adding the external input-digest anchor.
///
/// # Errors
///
/// Returns an error if locator identity or canonical bytes differ from the
/// decoded reference, or if inspection checking or querying fails.
pub(super) fn checked_slice(
    panel: &PackageAbilityReferencePanel,
    query: &GraphQuery,
) -> Result<ReferenceGraphSlice> {
    let reference_bytes = panel
        .reference
        .canonical_json()
        .context("encoding authenticated package ability reference")?;
    ensure!(
        panel.locator.indexed_commit == panel.indexed_commit
            && panel.locator.platform == panel.platform
            && panel.locator.package_name == panel.reference.package.as_str()
            && panel.locator.package_version == panel.reference.version
            && panel.locator.manifest_sha256 == panel.reference.manifest_sha256.to_string()
            && panel.locator.package_digest == panel.reference.package_digest.to_string()
            && panel.locator.canonical_json == reference_bytes,
        "ability reference panel differs from its authenticated registry locator"
    );

    let input = ReferenceInspectionInput::new(panel.reference.clone())?;
    let digest = aos_contract::Sha256Digest::of_bytes(&input.canonical_bytes()?);
    let checked = input.check(Some(digest))?;
    let view = ReferenceInspectionView::from_checked(&checked)?;
    view.query(query).map_err(Into::into)
}

/// Renders the canonical shared graph summary used as the page's primary map.
pub(super) fn section(panel: &PackageAbilityReferencePanel) -> Result<String> {
    let root = NodeKey::Package(panel.reference.manifest_sha256);
    let max_nodes = 1usize
        .saturating_add(panel.reference.exports.len())
        .saturating_add(
            panel
                .reference
                .requirements
                .iter()
                .map(|requirement| requirement.accepted_interfaces.len())
                .sum::<usize>(),
        )
        .min(aos_ability_inspect::INSPECTION_QUERY_MAX_NODES);
    let query = GraphQuery::new([root], 1, max_nodes.max(1));
    let slice = checked_slice(panel, &query)?;

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
        aos_ability_inspect::InspectionNode::Interface { .. } => "interface",
        aos_ability_inspect::InspectionNode::InterfaceReference { .. } => "interface reference",
        _ => "deployment-only node",
    }
}

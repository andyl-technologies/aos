//! Deterministic text and graph renderers for portable inspection data.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use aos_ability_model::PlanId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GraphSlice, InspectionEdge, InspectionNode, InspectionRelation, InspectionView, NodeKey,
    ViewAnchor,
};

/// Selects one stable inspection output representation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderFormat {
    /// Emits a line-oriented human-readable report.
    #[default]
    Text,
    /// Emits the complete portable DTO as canonical JSON.
    Json,
    /// Emits a directed Graphviz graph.
    Dot,
    /// Emits a Mermaid flowchart.
    Mermaid,
}

/// Reports why a stable inspection representation could not be produced.
#[derive(Debug, Error)]
pub enum RenderError {
    /// Canonical JSON encoding failed.
    #[error("inspection rendering failed: {0}")]
    Encoding(#[source] anyhow::Error),
    /// A graph references a node absent from its node set.
    #[error("inspection graph contains an edge with an absent endpoint")]
    MissingEndpoint,
}

/// Renders a complete checked-plan view in the selected stable format.
///
/// # Errors
///
/// Returns an error if canonical serialization fails or the view contains an
/// edge whose endpoint is absent.
pub fn render(view: &InspectionView, format: RenderFormat) -> Result<String, RenderError> {
    if format == RenderFormat::Json {
        return canonical_json(view);
    }
    render_parts(
        GraphParts {
            anchor: view.anchor(),
            plan: view.plan(),
            binding_plan: view.binding_plan(),
            executable: view.is_executable(),
            truncated: None,
            nodes: view.nodes(),
            edges: view.edges(),
        },
        format,
    )
}

/// Renders a bounded graph slice in the selected stable format.
///
/// # Errors
///
/// Returns an error if canonical serialization fails or the slice contains an
/// edge whose endpoint is absent.
pub fn render_slice(slice: &GraphSlice, format: RenderFormat) -> Result<String, RenderError> {
    if format == RenderFormat::Json {
        return canonical_json(slice);
    }
    render_parts(
        GraphParts {
            anchor: slice.anchor(),
            plan: slice.plan(),
            binding_plan: slice.binding_plan(),
            executable: slice.is_executable(),
            truncated: Some(slice.is_truncated()),
            nodes: slice.nodes(),
            edges: slice.edges(),
        },
        format,
    )
}

struct GraphParts<'a> {
    anchor: &'a ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    executable: bool,
    truncated: Option<bool>,
    nodes: &'a [InspectionNode],
    edges: &'a [InspectionEdge],
}

fn render_parts(parts: GraphParts<'_>, format: RenderFormat) -> Result<String, RenderError> {
    match format {
        RenderFormat::Text => render_text(&parts),
        RenderFormat::Dot => render_dot(&parts),
        RenderFormat::Mermaid => render_mermaid(&parts),
        RenderFormat::Json => unreachable!("JSON is rendered from its complete DTO"),
    }
}

fn render_text(parts: &GraphParts<'_>) -> Result<String, RenderError> {
    let node_indices = node_indices(parts.nodes);
    validate_edges(parts.edges, &node_indices)?;

    let mut output = String::new();
    writeln!(output, "Ability inspection")?;
    writeln!(output, "anchor: {}", anchor_label(parts.anchor))?;
    writeln!(output, "plan: {}", plan_label(parts.plan))?;
    writeln!(output, "binding plan: {}", plan_label(parts.binding_plan))?;
    writeln!(output, "executable: {}", parts.executable)?;
    if let Some(truncated) = parts.truncated {
        writeln!(output, "query truncated: {truncated}")?;
    }
    writeln!(output, "nodes: {}", parts.nodes.len())?;
    for (index, node) in parts.nodes.iter().enumerate() {
        writeln!(output, "  n{index}: {}", canonical_value(node)?)?;
    }
    writeln!(output, "edges: {}", parts.edges.len())?;
    for edge in parts.edges {
        let from = node_indices
            .get(&edge.from)
            .ok_or(RenderError::MissingEndpoint)?;
        let to = node_indices
            .get(&edge.to)
            .ok_or(RenderError::MissingEndpoint)?;
        writeln!(
            output,
            "  n{from} -[{}]-> n{to}",
            relation_label(edge.relation)
        )?;
    }
    Ok(output)
}

fn render_dot(parts: &GraphParts<'_>) -> Result<String, RenderError> {
    let node_indices = node_indices(parts.nodes);
    validate_edges(parts.edges, &node_indices)?;

    let mut output = String::from("digraph ability_inspection {\n");
    writeln!(
        output,
        "  graph [label=\"{}\", labelloc=t];",
        dot_escape(&graph_label(parts))
    )?;
    for (index, node) in parts.nodes.iter().enumerate() {
        let label = format!("{}\\n{}", node_kind(node), canonical_value(&node.key())?);
        writeln!(output, "  n{index} [label=\"{}\"];", dot_escape(&label))?;
    }
    for edge in parts.edges {
        let from = node_indices
            .get(&edge.from)
            .ok_or(RenderError::MissingEndpoint)?;
        let to = node_indices
            .get(&edge.to)
            .ok_or(RenderError::MissingEndpoint)?;
        writeln!(
            output,
            "  n{from} -> n{to} [label=\"{}\"];",
            relation_label(edge.relation)
        )?;
    }
    output.push_str("}\n");
    Ok(output)
}

fn render_mermaid(parts: &GraphParts<'_>) -> Result<String, RenderError> {
    let node_indices = node_indices(parts.nodes);
    validate_edges(parts.edges, &node_indices)?;

    let mut output = String::from("flowchart TD\n");
    writeln!(
        output,
        "  %% {}",
        mermaid_comment_escape(&graph_label(parts))
    )?;
    for (index, node) in parts.nodes.iter().enumerate() {
        let label = format!("{}: {}", node_kind(node), canonical_value(&node.key())?);
        writeln!(output, "  n{index}[\"{}\"]", mermaid_escape(&label))?;
    }
    for edge in parts.edges {
        let from = node_indices
            .get(&edge.from)
            .ok_or(RenderError::MissingEndpoint)?;
        let to = node_indices
            .get(&edge.to)
            .ok_or(RenderError::MissingEndpoint)?;
        writeln!(
            output,
            "  n{from} -->|{}| n{to}",
            relation_label(edge.relation)
        )?;
    }
    Ok(output)
}

fn canonical_json(value: &impl Serialize) -> Result<String, RenderError> {
    let bytes = aos_contract::canonical::to_vec(value).map_err(RenderError::Encoding)?;
    // Canonical JSON emitted by serde_json is always UTF-8.
    String::from_utf8(bytes).map_err(|error| RenderError::Encoding(error.into()))
}

fn canonical_value(value: &impl Serialize) -> Result<String, RenderError> {
    canonical_json(value)
}

fn node_indices(nodes: &[InspectionNode]) -> BTreeMap<NodeKey, usize> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.key(), index))
        .collect()
}

fn validate_edges(
    edges: &[InspectionEdge],
    nodes: &BTreeMap<NodeKey, usize>,
) -> Result<(), RenderError> {
    if edges
        .iter()
        .any(|edge| !nodes.contains_key(&edge.from) || !nodes.contains_key(&edge.to))
    {
        return Err(RenderError::MissingEndpoint);
    }
    Ok(())
}

fn graph_label(parts: &GraphParts<'_>) -> String {
    let truncated = parts
        .truncated
        .map(|value| format!(", query truncated: {value}"))
        .unwrap_or_default();
    format!(
        "ability plan {}, {}, executable: {}{}",
        plan_label(parts.plan),
        anchor_label(parts.anchor),
        parts.executable,
        truncated
    )
}

fn plan_label(plan: PlanId) -> String {
    plan.0.to_string()
}

fn anchor_label(anchor: &ViewAnchor) -> String {
    match anchor {
        ViewAnchor::LocallyChecked => "locally checked; no portable external anchor".to_string(),
        ViewAnchor::UnanchoredBundle { digest } => {
            format!("bundle {digest}; semantically checked but externally unanchored")
        }
        ViewAnchor::ExternallyAnchoredBundle { digest } => {
            format!(
                "bundle {digest}; matched supplied external digest; current policy not established"
            )
        }
    }
}

fn node_kind(node: &InspectionNode) -> &'static str {
    match node {
        InspectionNode::Interface { .. } => "interface",
        InspectionNode::Package { .. } => "package",
        InspectionNode::Request { .. } => "request",
        InspectionNode::Binding { .. } => "binding",
        InspectionNode::Provider { .. } => "provider",
        InspectionNode::Aggregate { .. } => "aggregate",
        InspectionNode::Operation { .. } => "operation",
        InspectionNode::Decision { .. } => "decision",
        InspectionNode::Merge { .. } => "merge",
        InspectionNode::Resource { .. } => "resource",
        InspectionNode::Obligation { .. } => "obligation",
    }
}

fn relation_label(relation: InspectionRelation) -> &'static str {
    match relation {
        InspectionRelation::ConsumesRequest => "consumes-request",
        InspectionRelation::AcceptsInterface => "accepts-interface",
        InspectionRelation::SelectsBinding => "selects-binding",
        InspectionRelation::SelectsProvider => "selects-provider",
        InspectionRelation::SuppliesInterface => "supplies-interface",
        InspectionRelation::BackedByPackage => "backed-by-package",
        InspectionRelation::ContributesToAggregate => "contributes-to-aggregate",
        InspectionRelation::OwnsAggregate => "owns-aggregate",
        InspectionRelation::UsesBinding => "uses-binding",
        InspectionRelation::InvokesInterface => "invokes-interface",
        InspectionRelation::ReadsResource => "reads-resource",
        InspectionRelation::SharedWritesResource => "shared-writes-resource",
        InspectionRelation::ExclusivelyWritesResource => "exclusively-writes-resource",
        InspectionRelation::ControlsResource => "controls-resource",
        InspectionRelation::EstablishesProviderReadiness => "establishes-provider-readiness",
        InspectionRelation::HasObligation => "has-obligation",
        InspectionRelation::Data => "data",
        InspectionRelation::RequiredSuccess => "required-success",
        InspectionRelation::OrderingOnly => "ordering-only",
        InspectionRelation::Readiness => "readiness",
        InspectionRelation::BranchGuard => "branch-guard",
        InspectionRelation::BranchMerge => "branch-merge",
        InspectionRelation::Retention => "retention",
        InspectionRelation::Communication => "communication",
    }
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "")
        .replace('\n', "\\n")
}

fn mermaid_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace(['\r', '\n'], " ")
}

fn mermaid_comment_escape(value: &str) -> String {
    value.replace(['\r', '\n'], " ").replace("%%", "% %")
}

impl From<std::fmt::Error> for RenderError {
    fn from(error: std::fmt::Error) -> Self {
        Self::Encoding(error.into())
    }
}

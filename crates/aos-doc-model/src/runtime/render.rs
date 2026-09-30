//! Shared terminal and HTML views of native declarations and execution paths.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use aos_ability_plan::module_graph::Handler;

use super::{DefinitionSource, ModuleReference, Source};
use crate::OptionType;

pub(super) fn type_label(option: &OptionType) -> String {
    match option {
        OptionType::Bool => "bool".into(),
        OptionType::Integer {
            min: None,
            max: None,
        } => "int".into(),
        OptionType::String {
            pattern: None,
            max_length: None,
        } => "str".into(),
        OptionType::Path => "path".into(),
        OptionType::Opaque { signature } => signature.clone(),
        // Preserve all bounds and structured constraints in the portable notation.
        other => serde_json::to_string(other).unwrap_or_else(|_| format!("{other:?}")),
    }
}

fn owners(definitions: &[DefinitionSource]) -> String {
    definitions
        .iter()
        .map(|definition| definition.owner.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn plain(source: &Source) -> String {
    let mut output = String::new();
    match source {
        Source::ModuleReference(reference) => {
            let _ = writeln!(
                output,
                "Module documentation: {} ({})",
                reference.scope.join(" / "),
                reference.system
            );
            output
                .push_str("Declarations and configured uses; no live runtime state.\n\nPackages\n");
            for package in &reference.packages {
                let _ = writeln!(output, "  {} {}", package.name, package.version);
            }
            for (ability, operations) in &reference.abilities {
                for (operation, contract) in operations {
                    let _ = writeln!(
                        output,
                        "\n{ability}.{operation}\n  Declares input: {}\n  Declares result: {}\n  Handles: {}\n  Configures effects: {}\n  Handler selected: {}\n  Configured instances: {}",
                        owners(&contract.sources.input),
                        owners(&contract.sources.result),
                        owners(&contract.sources.handler),
                        owners(&contract.sources.effects),
                        contract.handler_available,
                        contract.configured_effects.join(", ")
                    );
                    for (label, fields) in
                        [("Input", &contract.input), ("Result", &contract.result)]
                    {
                        for (name, field) in fields {
                            let _ = writeln!(
                                output,
                                "  {label} {name}: {}\n    {}",
                                type_label(&field.option_type),
                                field.description
                            );
                        }
                    }
                }
            }
            output.push_str("\nOptions\n");
            for option in &reference.options {
                let _ = writeln!(
                    output,
                    "  {} [{}]: {}\n    {}",
                    option.path.join("."),
                    option.owner,
                    type_label(&option.option_type),
                    option.description
                );
            }
        }
        Source::Transaction {
            scope,
            system,
            graph,
        } => {
            let _ = writeln!(
                output,
                "Deferred transaction: {} ({system})",
                scope.join(" / ")
            );
            output.push_str("Selected execution path; not an observation or activation receipt.\n");
            for (position, id) in graph.graph().order.iter().enumerate() {
                let effect = &graph.graph().nodes[id];
                let _ = writeln!(
                    output,
                    "\n{}. {}\n   Owner: {}\n   Lifetime: {:?}\n   Depends on: {}",
                    position + 1,
                    effect.identity.join(" / "),
                    effect.owner,
                    effect.lifetime,
                    effect.dependencies.join(", ")
                );
                match &effect.handler {
                    Handler::Process { executable, .. } => {
                        let _ = writeln!(output, "   Program: {executable}");
                    }
                    Handler::Composition { children, .. } => {
                        let _ = writeln!(output, "   Composes: {}", children.join(", "));
                    }
                }
                let _ = writeln!(output, "   Revision: {}", effect.revision);
            }
        }
    }
    output
}

fn escape(value: &str) -> String {
    let mut escaped = String::new();
    crate::escape_html_into(value, &mut escaped);
    escaped
}

fn operation_anchor(ability: &str, operation: &str) -> String {
    // Length framing keeps dotted ability/operation names distinct.
    crate::documentation_anchor(
        "runtime-operation",
        &format!("{}:{ability}{operation}", ability.len()),
    )
}

fn owner_links(definitions: &[DefinitionSource]) -> String {
    definitions
        .iter()
        .map(|definition| definition.owner.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|owner| {
            format!(
                "<a href=\"#{}\">{}</a>",
                crate::documentation_anchor("runtime-owner", owner),
                escape(owner)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Derives the inverse links once, avoiding a scan of every operation per owner.
fn owner_relations(reference: &ModuleReference) -> BTreeMap<&str, BTreeSet<(&str, &str, &str)>> {
    let mut owners = BTreeMap::<&str, BTreeSet<(&str, &str, &str)>>::new();
    for package in &reference.packages {
        owners.entry(&package.name).or_default();
    }
    for option in &reference.options {
        owners.entry(&option.owner).or_default();
    }
    for (ability, operations) in &reference.abilities {
        for (name, operation) in operations {
            for (role, definitions) in [
                ("Declares", &operation.sources.input),
                ("Returns", &operation.sources.result),
                ("Handles", &operation.sources.handler),
                ("Configures", &operation.sources.effects),
            ] {
                for definition in definitions {
                    owners
                        .entry(&definition.owner)
                        .or_default()
                        .insert((role, ability, name));
                }
            }
        }
    }
    owners
}

pub(super) fn html(source: &Source) -> String {
    let mut html = String::from(
        "<section class=\"runtime-documentation\"><h2>Runtime abilities</h2><p>Imported configuration document; not live runtime state.</p>",
    );
    let (scope, system) = match source {
        Source::ModuleReference(reference) => (&reference.scope, &reference.system),
        Source::Transaction { scope, system, .. } => (scope, system),
    };
    let _ = write!(
        html,
        "<p>Scope: <strong>{}</strong>. Target: <code>{}</code>.</p>",
        escape(&scope.join(" / ")),
        escape(system)
    );

    match source {
        Source::ModuleReference(reference) => {
            let versions: BTreeMap<_, _> = reference
                .packages
                .iter()
                .map(|package| (package.name.as_str(), package.version.as_str()))
                .collect();
            html.push_str("<h3>Packages and environment</h3>");
            for (owner, relations) in owner_relations(reference) {
                let _ = write!(
                    html,
                    "<details id=\"{}\"><summary>{}</summary><ul>",
                    crate::documentation_anchor("runtime-owner", owner),
                    escape(owner)
                );
                for (role, ability, operation) in relations {
                    let _ = write!(
                        html,
                        "<li>{role} <a href=\"#{}\">{}</a></li>",
                        operation_anchor(ability, operation),
                        escape(&format!("{ability}.{operation}"))
                    );
                }
                html.push_str("</ul>");
                if let Some(version) = versions.get(owner) {
                    let _ = write!(html, "<p>PackageIdentity version: {}</p>", escape(version));
                }
                html.push_str("</details>");
            }
            for (ability, operations) in &reference.abilities {
                for (name, operation) in operations {
                    let anchor = operation_anchor(ability, name);
                    let name = format!("{ability}.{name}");
                    let _ = write!(
                        html,
                        "<article id=\"{}\"><h3>{}</h3><dl><dt>Input declared by</dt><dd>{}</dd><dt>Result declared by</dt><dd>{}</dd><dt>Handled by</dt><dd>{}</dd><dt>Effects configured by</dt><dd>{}</dd><dt>Handler selected</dt><dd>{}</dd></dl>",
                        anchor,
                        escape(&name),
                        owner_links(&operation.sources.input),
                        owner_links(&operation.sources.result),
                        owner_links(&operation.sources.handler),
                        owner_links(&operation.sources.effects),
                        operation.handler_available
                    );
                    let _ = write!(
                        html,
                        "<p>Configured instances: {}</p>",
                        escape(&operation.configured_effects.join(", "))
                    );
                    for (label, fields) in
                        [("Inputs", &operation.input), ("Results", &operation.result)]
                    {
                        let _ = write!(
                            html,
                            "<h4>{label}</h4><table><thead><tr><th>Option</th><th>Type</th><th>Description</th></tr></thead><tbody>"
                        );
                        for (name, field) in fields {
                            let _ = write!(
                                html,
                                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                                escape(name),
                                escape(&type_label(&field.option_type)),
                                escape(&field.description)
                            );
                        }
                        html.push_str("</tbody></table>");
                    }
                    html.push_str("</article>");
                }
            }
        }
        Source::Transaction { graph, .. } => {
            html.push_str("<h3>Execution path</h3><ol>");
            for id in &graph.graph().order {
                let effect = &graph.graph().nodes[id];
                let _ = write!(
                    html,
                    "<li id=\"{}\"><strong>{}</strong><p>Owner: {}. Lifetime: {:?}.</p>",
                    crate::documentation_anchor("runtime-effect", id),
                    escape(&effect.identity.join(" / ")),
                    escape(&effect.owner),
                    effect.lifetime
                );
                match &effect.handler {
                    Handler::Process { executable, .. } => {
                        let _ = write!(html, "<p>Program: <code>{}</code></p>", escape(executable));
                    }
                    Handler::Composition { children, .. } => {
                        let _ = write!(html, "<p>Composes {} child effects.</p>", children.len());
                    }
                }
                if !effect.dependencies.is_empty() {
                    html.push_str("<p>After: ");
                    for dependency in &effect.dependencies {
                        let _ = write!(
                            html,
                            "<a href=\"#{}\">{}</a> ",
                            crate::documentation_anchor("runtime-effect", dependency),
                            escape(&graph.graph().nodes[dependency].identity.join(" / "))
                        );
                    }
                    html.push_str("</p>");
                }
                html.push_str("</li>");
            }
            html.push_str("</ol>");
        }
    }
    let _ = write!(
        html,
        "<details><summary>Full text reference</summary><pre>{}</pre></details></section>",
        escape(&plain(source))
    );
    html
}

//! Shared terminal and HTML views of native declarations and execution paths.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use aos_ability_plan::module_graph::Handler;

use super::{DefinitionSource, ModuleReference, ModuleRequirement, NativeOption, Source};
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
                if let Some(requirement) = &package.version_requirement {
                    let _ = writeln!(output, "    Compatibility requirement: {requirement}");
                }
            }
            if let Some(release) = &reference.os_release {
                let _ = writeln!(output, "\nOS release: {} {}", release.name, release.version);
            }
            if !reference.module_requirements.is_empty() {
                output.push_str(
                    "\nModule requirements (declared constraints; not a resolution result)\n",
                );
                for requirement in &reference.module_requirements {
                    let _ = writeln!(
                        output,
                        "  {} requires {}\n    Package version requirement: {}",
                        requirement.owner, requirement.package, requirement.package_version
                    );
                }
            }
            if !reference.os_requirements.is_empty() {
                output.push_str("\nOS requirements (base-provided interfaces)\n");
                for requirement in &reference.os_requirements {
                    let _ = writeln!(
                        output,
                        "  {} requires OS version: {}",
                        requirement.owner, requirement.os_version
                    );
                }
            }
            for (ability, operations) in &reference.abilities {
                for (operation, contract) in operations {
                    let _ = writeln!(
                        output,
                        "\n{ability}.{operation}\n  Exposes input: {}\n  Exposes result: {}\n  Handles: {}\n  Consumes (configured effects): {}\n  Handler selected: {}\n  Configured instances: {}\n  Complete input contract: {}\n  Complete result contract: {}",
                        owners(&contract.sources.input),
                        owners(&contract.sources.result),
                        owners(&contract.sources.handler),
                        owners(&contract.sources.effects),
                        contract.handler_available,
                        contract.configured_effects.join(", "),
                        type_label(&contract.input_type),
                        type_label(&contract.result_type)
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
            for option in reference
                .options
                .iter()
                .filter(|option| option.visibility != crate::Visibility::Hidden)
            {
                let _ = writeln!(
                    output,
                    "  {} [{}]: {} (read-only: {}, extensible: {})\n    {}",
                    option.path.join("."),
                    option.owner,
                    type_label(&option.option_type),
                    option.read_only,
                    option.extensible,
                    option.description
                );
            }
        }
        Source::Transaction {
            scope,
            system,
            graph,
            retire,
        } => {
            let _ = writeln!(
                output,
                "Deferred transaction: {} ({system})",
                scope.join(" / ")
            );
            output.push_str("Selected execution path; not an observation or activation receipt.\n");
            output.push_str("Explicit retirement decisions (desired intent):\n");
            for identity in retire {
                let _ = writeln!(output, "  {identity}");
            }

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
                for (name, contract) in &effect.results {
                    let _ = writeln!(output, "   Result {name}: {}", type_label(contract));
                }
                let _ = writeln!(
                    output,
                    "   Logical ID: {id}\n   Revision: {}\n   Input: {}\n   Complete input contract: {}",
                    effect.revision,
                    effect.input,
                    type_label(&effect.input_type)
                );
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

fn scoped_anchor(namespace: &str, kind: &str, key: &str) -> String {
    format!("{namespace}-{}", crate::documentation_anchor(kind, key))
}

fn operation_anchor(namespace: &str, ability: &str, operation: &str) -> String {
    // Length framing keeps dotted ability/operation names distinct.
    scoped_anchor(
        namespace,
        "runtime-operation",
        &format!("{}:{ability}{operation}", ability.len()),
    )
}

fn owner_links(namespace: &str, definitions: &[DefinitionSource]) -> String {
    definitions
        .iter()
        .map(|definition| definition.owner.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|owner| {
            format!(
                "<a href=\"#{}\">{}</a>",
                scoped_anchor(namespace, "runtime-owner", owner),
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
    for option in reference
        .options
        .iter()
        .filter(|option| option.visibility != crate::Visibility::Hidden)
    {
        owners.entry(&option.owner).or_default();
    }
    for requirement in &reference.os_requirements {
        owners.entry(&requirement.owner).or_default();
    }
    for requirement in &reference.module_requirements {
        owners.entry(&requirement.owner).or_default();
        owners.entry(&requirement.package).or_default();
    }
    for (ability, operations) in &reference.abilities {
        for (name, operation) in operations {
            for (role, definitions) in [
                ("Exposes input", &operation.sources.input),
                ("Exposes result", &operation.sources.result),
                ("Handles", &operation.sources.handler),
                ("Consumes", &operation.sources.effects),
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

/// Frames identities so references embedded together retain distinct fragments.
fn document_namespace(source: &Source) -> String {
    let (scope, system) = match source {
        Source::ModuleReference(reference) => (&reference.scope, &reference.system),
        Source::Transaction { scope, system, .. } => (scope, system),
    };
    let mut identity = format!("scope:{}:", scope.len());
    for segment in scope {
        let _ = write!(identity, "{}:{segment}", segment.len());
    }
    let _ = write!(identity, "system:{}:{system}", system.len());
    match source {
        Source::ModuleReference(reference) => {
            let _ = write!(identity, "packages:{}:", reference.packages.len());
            for package in &reference.packages {
                let _ = write!(
                    identity,
                    "{}:{}{}:{}",
                    package.name.len(),
                    package.name,
                    package.version.len(),
                    package.version
                );
            }
        }
        Source::Transaction { graph, retire, .. } => {
            let _ = write!(identity, "effects:{}:", graph.graph().order.len());
            for id in &graph.graph().order {
                let revision = &graph.graph().nodes[id].revision;
                let _ = write!(identity, "{}:{id}{revision}", id.len());
            }
            let _ = write!(identity, "retire:{}:", retire.len());
            for id in retire {
                let _ = write!(identity, "{}:{id}", id.len());
            }
        }
    }
    crate::documentation_anchor("runtime-document", &identity)
}

fn option_key(path: &[String]) -> String {
    let mut key = String::new();
    for segment in path {
        let _ = write!(key, "{}:{segment}", segment.len());
    }
    key
}

pub(super) fn html(source: &Source) -> String {
    let namespace = document_namespace(source);
    let namespace = namespace.as_str();
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
                .map(|package| (package.name.as_str(), package))
                .collect();
            let mut options_by_owner = BTreeMap::<&str, Vec<&NativeOption>>::new();
            for option in reference
                .options
                .iter()
                .filter(|option| option.visibility != crate::Visibility::Hidden)
            {
                options_by_owner
                    .entry(&option.owner)
                    .or_default()
                    .push(option);
            }
            let mut requirements_by_owner = BTreeMap::<&str, Vec<&ModuleRequirement>>::new();
            let mut requesters_by_package = BTreeMap::<&str, Vec<&ModuleRequirement>>::new();
            for requirement in &reference.module_requirements {
                requirements_by_owner
                    .entry(&requirement.owner)
                    .or_default()
                    .push(requirement);
                requesters_by_package
                    .entry(&requirement.package)
                    .or_default()
                    .push(requirement);
            }
            html.push_str("<h3>Packages and environment</h3><p>Exposed contracts come from input/result declarations; consumed operations come from configured effects. Handler definitions link implementation ownership; Handler selected records availability in this fixed point. Configured instances may be disabled; only a checked transaction identifies the selected execution path.</p>");
            for (owner, relations) in owner_relations(reference) {
                let _ = write!(
                    html,
                    "<details id=\"{}\"><summary>{}</summary><ul>",
                    scoped_anchor(namespace, "runtime-owner", owner),
                    escape(owner)
                );
                for (role, ability, operation) in relations {
                    let _ = write!(
                        html,
                        "<li>{role} <a href=\"#{}\">{}</a></li>",
                        operation_anchor(namespace, ability, operation),
                        escape(&format!("{ability}.{operation}"))
                    );
                }
                for option in options_by_owner.get(owner).into_iter().flatten() {
                    let _ = write!(
                        html,
                        "<li>Option <a href=\"#{}\">{}</a></li>",
                        scoped_anchor(namespace, "runtime-option", &option_key(&option.path)),
                        escape(&option.path.join("."))
                    );
                }
                for requirement in requirements_by_owner.get(owner).into_iter().flatten() {
                    let _ = write!(
                        html,
                        "<li>Requires module <a href=\"#{}\">{}</a></li>",
                        scoped_anchor(namespace, "runtime-owner", &requirement.package),
                        escape(&requirement.package)
                    );
                }
                for requirement in requesters_by_package.get(owner).into_iter().flatten() {
                    let _ = write!(
                        html,
                        "<li>Required by <a href=\"#{}\">{}</a></li>",
                        scoped_anchor(namespace, "runtime-owner", &requirement.owner),
                        escape(&requirement.owner)
                    );
                }
                html.push_str("</ul>");
                if owner == "@base" {
                    html.push_str("<p>Base module declarations.</p>");
                } else if owner.starts_with('@') {
                    html.push_str("<p>Environment module declarations.</p>");
                }
                if let Some(package) = versions.get(owner) {
                    let _ = write!(html, "<p>Package version: {}</p>", escape(&package.version));
                    if let Some(requirement) = &package.version_requirement {
                        let _ = write!(
                            html,
                            "<p>Compatibility requirement: <code>{}</code></p>",
                            escape(requirement)
                        );
                    }
                }
                html.push_str("</details>");
            }
            if let Some(release) = &reference.os_release {
                let _ = write!(
                    html,
                    "<p>OS release: {} <code>{}</code></p>",
                    escape(&release.name),
                    escape(&release.version)
                );
            }
            if !reference.module_requirements.is_empty() {
                html.push_str("<h3>Module requirements</h3><p>Declared constraints; not a dependency resolution result.</p><table><thead><tr><th>Requester</th><th>Dependency package</th><th>Required package version</th></tr></thead><tbody>");
                for requirement in &reference.module_requirements {
                    let _ = write!(
                        html,
                        "<tr><td><a href=\"#{}\">{}</a></td><td><a href=\"#{}\">{}</a></td><td><code>{}</code></td></tr>",
                        scoped_anchor(namespace, "runtime-owner", &requirement.owner),
                        escape(&requirement.owner),
                        scoped_anchor(namespace, "runtime-owner", &requirement.package),
                        escape(&requirement.package),
                        escape(&requirement.package_version)
                    );
                }
                html.push_str("</tbody></table>");
            }
            if !reference.os_requirements.is_empty() {
                html.push_str("<h3>OS requirements</h3><p>Base-provided interfaces use the OS release version.</p><table><thead><tr><th>Requester</th><th>Required OS version</th></tr></thead><tbody>");
                for requirement in &reference.os_requirements {
                    let _ = write!(
                        html,
                        "<tr><td><a href=\"#{}\">{}</a></td><td><code>{}</code></td></tr>",
                        scoped_anchor(namespace, "runtime-owner", &requirement.owner),
                        escape(&requirement.owner),
                        escape(&requirement.os_version)
                    );
                }
                html.push_str("</tbody></table>");
            }
            for ability in reference.abilities.keys() {
                let _ = write!(
                    html,
                    "<section id=\"{}\"><h3>Ability {}</h3>",
                    scoped_anchor(namespace, "runtime-ability", ability),
                    escape(ability)
                );
                for (name, operation) in reference.abilities.get(ability).into_iter().flatten() {
                    let anchor = operation_anchor(namespace, ability, name);
                    let name = format!("{ability}.{name}");
                    let _ = write!(
                        html,
                        "<article id=\"{}\"><h3>{}</h3><dl><dt>Input declared by</dt><dd>{}</dd><dt>Result declared by</dt><dd>{}</dd><dt>Handled by</dt><dd>{}</dd><dt>Effects configured by</dt><dd>{}</dd><dt>Handler selected</dt><dd>{}</dd></dl>",
                        anchor,
                        escape(&name),
                        owner_links(namespace, &operation.sources.input),
                        owner_links(namespace, &operation.sources.result),
                        owner_links(namespace, &operation.sources.handler),
                        owner_links(namespace, &operation.sources.effects),
                        operation.handler_available
                    );
                    let _ = write!(
                        html,
                        "<p>Configured instances: {}</p>",
                        escape(&operation.configured_effects.join(", "))
                    );
                    for (label, contract) in [
                        ("Complete input contract", &operation.input_type),
                        ("Complete result contract", &operation.result_type),
                    ] {
                        let _ = write!(
                            html,
                            "<details><summary>{label}</summary><pre>{}</pre></details>",
                            escape(
                                &serde_json::to_string_pretty(contract)
                                    .unwrap_or_else(|_| type_label(contract))
                            )
                        );
                    }
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
                html.push_str("</section>");
            }
            html.push_str("<h3>Generated options</h3><table><thead><tr><th>Option</th><th>Owner</th><th>Type</th><th>Read-only</th><th>Extensible</th><th>Description</th></tr></thead><tbody>");
            for option in reference
                .options
                .iter()
                .filter(|option| option.visibility != crate::Visibility::Hidden)
            {
                let _ = write!(
                    html,
                    "<tr id=\"{}\"><td>{}<br><small>Segments: <code>{}</code></small></td><td><a href=\"#{}\">{}</a></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    scoped_anchor(namespace, "runtime-option", &option_key(&option.path)),
                    escape(&option.path.join(".")),
                    escape(
                        &serde_json::to_string(&option.path)
                            .unwrap_or_else(|_| format!("{:?}", option.path))
                    ),
                    scoped_anchor(namespace, "runtime-owner", &option.owner),
                    escape(&option.owner),
                    escape(&type_label(&option.option_type)),
                    option.read_only,
                    option.extensible,
                    escape(&option.description)
                );
            }
            html.push_str("</tbody></table>");
        }
        Source::Transaction { graph, retire, .. } => {
            html.push_str("<h3>Explicit retirement decisions</h3><p>Desired intent; no live-state verification.</p><ul>");
            for identity in retire {
                let _ = write!(html, "<li><code>{}</code></li>", escape(identity));
            }
            html.push_str("</ul>");
            html.push_str("<h3>Execution path</h3><ol>");
            for id in &graph.graph().order {
                let effect = &graph.graph().nodes[id];
                let _ = write!(
                    html,
                    "<li id=\"{}\"><strong>{}</strong><p>Owner: {}. Lifetime: {:?}.</p>",
                    scoped_anchor(namespace, "runtime-effect", id),
                    escape(&effect.identity.join(" / ")),
                    escape(&effect.owner),
                    effect.lifetime
                );
                let _ = write!(
                    html,
                    "<p>Logical ID: <code>{}</code>. Desired revision: <code>{}</code>. Attempt timeout: {} ms.</p><details><summary>Selected input</summary><pre>{}</pre></details><details><summary>Complete input contract</summary><pre>{}</pre></details>",
                    escape(id),
                    escape(&effect.revision),
                    effect.timeout_ms,
                    escape(
                        &serde_json::to_string_pretty(&effect.input)
                            .unwrap_or_else(|_| effect.input.to_string())
                    ),
                    escape(
                        &serde_json::to_string_pretty(&effect.input_type)
                            .unwrap_or_else(|_| type_label(&effect.input_type))
                    )
                );
                let _ = write!(
                    html,
                    "<details><summary>Declared result contract</summary><pre>{}</pre></details>",
                    escape(
                        &serde_json::to_string_pretty(&effect.results)
                            .unwrap_or_else(|_| format!("{:?}", effect.results))
                    )
                );
                match &effect.handler {
                    Handler::Process { executable, .. } => {
                        let _ = write!(html, "<p>Program: <code>{}</code></p>", escape(executable));
                    }
                    Handler::Composition { children, exports } => {
                        html.push_str("<p>Composes: ");
                        for child in children {
                            let _ = write!(
                                html,
                                "<a href=\"#{}\">{}</a> ",
                                scoped_anchor(namespace, "runtime-effect", child),
                                escape(&graph.graph().nodes[child].identity.join(" / "))
                            );
                        }
                        html.push_str("</p><ul>");
                        for (name, reference) in exports {
                            let child =
                                aos_ability_plan::module_graph::identity_key(&reference.identity);
                            if let Ok(child) = child {
                                let _ = write!(
                                    html,
                                    "<li>Result {} from <a href=\"#{}\">{} / {}</a></li>",
                                    escape(name),
                                    scoped_anchor(namespace, "runtime-effect", &child),
                                    escape(&reference.identity.join(" / ")),
                                    escape(&reference.output)
                                );
                            }
                        }
                        html.push_str("</ul>");
                    }
                }
                if !effect.dependencies.is_empty() {
                    html.push_str("<p>After: ");
                    for dependency in &effect.dependencies {
                        let _ = write!(
                            html,
                            "<a href=\"#{}\">{}</a> ",
                            scoped_anchor(namespace, "runtime-effect", dependency),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeDocument;
    use serde_json::json;

    fn document(value: serde_json::Value) -> RuntimeDocument {
        RuntimeDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn reference(package: &str) -> RuntimeDocument {
        let source = |owner: &str| json!({"owner":owner,"file":"module.nix","priority":100,"provenance":"module"});
        let nested = json!({"kind":"submodule","fields":{
            "addresses":{"kind":"list","element":{"kind":"string"},"max_items":8}
        },"open":false});
        let option = |path: &str, visibility: &str| {
            json!({"path":["aos",path],"owner":"@base","description":"A <declaration>",
                "type":nested,"visibility":visibility,"readOnly":true,"extensible":false})
        };
        let field = json!({"description":"Nested settings","type":nested});
        document(json!({
            "schema":"aos.module.documentation","scope":["package",package],
            "system":"x86_64-linux","packages":[{"name":package,"version":"1"}],
            "options":[option("settings","public"),option("secret-plumbing","hidden")],
            "abilities":{"network":{"configure":{
                "input":{"settings":field},"result":{},
                "inputType":{"kind":"submodule","fields":{"settings":nested},"open":false},
                "resultType":{"kind":"submodule","fields":{},"open":false},
                "handlerAvailable":true,"configuredEffects":["main"],
                "sources":{"input":[source("@base")],"result":[source("@base")],
                    "handler":[source("implementation")],"effects":[source(package)]}
            }}}
        }))
    }

    fn attribute_values<'a>(html: &'a str, attribute: &str) -> Vec<&'a str> {
        html.split(attribute)
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap())
            .collect()
    }

    fn require_fragment_links_resolve(html: &str) {
        let ids = attribute_values(html, "id=\"");
        let unique: BTreeSet<_> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len(), "embedded documents repeat an ID");
        for link in attribute_values(html, "href=\"#") {
            assert!(unique.contains(link), "missing fragment target {link}");
        }
    }

    #[test]
    fn recursive_reference_shows_options_contracts_and_inverse_owner_roles() {
        let document = reference("consumer");
        let html = document.render_html();
        for label in [
            "Generated options",
            "Read-only",
            "Extensible",
            "Complete input contract",
            "Complete result contract",
            "Exposes input",
            "Exposes result",
            "Consumes",
            "Handles",
            "Base module declarations.",
            "aos.settings",
            "addresses",
            "max_items",
        ] {
            assert!(html.contains(label), "missing {label}");
        }
        assert!(html.contains("A &lt;declaration&gt;"));
        assert!(!html.contains("A <declaration>"));
        assert!(!html.contains("secret-plumbing"));
        let plain = document.render_plain();
        assert!(plain.contains("read-only: true, extensible: false"));
        assert!(plain.contains("Complete input contract:"));
        assert!(plain.contains("max_items"));
        assert!(!plain.contains("secret-plumbing"));
        require_fragment_links_resolve(&html);
    }

    #[test]
    fn shared_base_and_operation_links_stay_inside_each_package_reference() {
        let first = reference("first").render_html();
        let second = reference("second").render_html();
        require_fragment_links_resolve(&format!("{first}{second}"));
        let first_ids: BTreeSet<_> = attribute_values(&first, "id=\"").into_iter().collect();
        let second_ids: BTreeSet<_> = attribute_values(&second, "id=\"").into_iter().collect();
        assert!(first_ids.is_disjoint(&second_ids));
        require_fragment_links_resolve(&first);
        require_fragment_links_resolve(&second);
    }

    #[test]
    fn package_and_os_requirements_link_the_same_reference() {
        let mut value = reference("web-server").value().clone();
        value["packages"] = json!([{"name":"interface-package","version":"7.4.0"}]);
        value["moduleRequirements"] =
            json!([{"owner":"web-server","package":"interface-package","packageVersion":"<8"}]);
        value["osRequirements"] = json!([{"owner":"web-server","osVersion":"^1"}]);
        value["osRelease"] = json!({"name":"aos","version":"1.0.0"});
        let document = document(value);
        let plain = document.render_plain();
        for text in [
            "web-server requires interface-package",
            "Package version requirement: <8",
            "web-server requires OS version: ^1",
            "OS release: aos 1.0.0",
        ] {
            assert!(plain.contains(text), "missing {text}");
        }
        let html = document.render_html();
        for text in [
            "Package version: 7.4.0",
            "Declared constraints; not a dependency resolution result",
            "Required by",
            "&lt;8",
            "OS requirements",
            "OS release: aos",
        ] {
            assert!(html.contains(text), "missing {text}");
        }
        require_fragment_links_resolve(&html);
        assert_eq!(
            document.reference().unwrap().module_requirements[0].owner,
            "web-server"
        );
    }

    #[test]
    fn checked_selection_shows_actual_inputs_revisions_and_composed_result_links() {
        let mut child = json!({
            "identity":["host","main","test","echo","child"],"owner":"@environment",
            "input":{"message":"<chosen>"},
            "inputs":{"message":{"description":"Selected text","type":{"kind":"string"}}},
            "input_type":{"kind":"submodule","fields":{"message":{"kind":"string"}}},
            "after":[],"results":{"value":{"kind":"string"}},
            "handler":{"kind":"process","artifact":"/nix/store/00000000000000000000000000000000-handler",
                "executable":"/nix/store/00000000000000000000000000000000-handler/bin/run"},
            "dependencies":[],"lifetime":"instance","timeout_ms":1000
        });
        let child_identity: Vec<String> =
            serde_json::from_value(child["identity"].clone()).unwrap();
        let child_id = aos_ability_plan::module_graph::identity_key(&child_identity).unwrap();
        let mut parent = child.clone();
        parent["identity"][4] = "parent".into();
        parent["handler"] = json!({"kind":"composition","children":[child_id],
            "exports":{"value":{"_type":"aos-effect-output","identity":child_identity,
                "output":"value","schema":{"kind":"string"}}}});
        parent["dependencies"] = json!([child_id]);
        let parent_id = aos_ability_plan::module_graph::identity_key(
            &serde_json::from_value::<Vec<String>>(parent["identity"].clone()).unwrap(),
        )
        .unwrap();
        for node in [&mut child, &mut parent] {
            let mut semantic = node.as_object().unwrap().clone();
            for key in ["inputs", "dependencies"] {
                semantic.remove(key);
            }
            node["revision"] =
                aos_contract::Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap())
                    .hex()
                    .into();
        }
        let document = document(json!({
            "schema":"aos.package.transaction","scope":["host","main"],"system":"x86_64-linux",
            "retire":["previous-instance"],"graph":{"schema":"aos.activation.graph",
                "order":[child_id,parent_id],"nodes":{(child_id.clone()):child,(parent_id.clone()):parent}}
        }));
        let html = document.render_html();
        for label in [
            "Selected input",
            "&lt;chosen&gt;",
            "Logical ID",
            "Desired revision",
            "Attempt timeout: 1000 ms",
            "Composes:",
            "Result value from",
            "previous-instance",
        ] {
            assert!(html.contains(label), "missing {label}");
        }
        assert!(!html.contains("<chosen>"));
        assert!(
            document
                .render_plain()
                .contains("Input: {\"message\":\"<chosen>\"}")
        );
        require_fragment_links_resolve(&html);
        // Rendering never substitutes a reference catalog for the selected graph.
        assert_eq!(
            document.value()["graph"]["order"],
            json!([child_id, parent_id])
        );
    }
}

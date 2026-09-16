//! Safe terminal, HTML, and roff rendering for static package ability declarations.
//!
//! These views describe only the checked signed package declaration. They
//! deliberately omit activation, provider selection,
//! assignments, health, and observed runtime state.

use std::fmt::Write as _;

use crate::PackageAbilityReference;
use aos_ability_model::{RequirementDeclaration, RequirementStrength, ValueSchema};

const SCOPE_NOTICE: &str = concat!(
    "Authenticated static package declaration. This section does not report activation, ",
    "provider selection, assignments, health, or observed runtime state. Operator ",
    "configuration sections show public schemas only, never deployed instance values."
);

pub(crate) fn plain(reference: &PackageAbilityReference) -> String {
    let mut output = String::from("\nDECLARED ABILITIES\n------------------\n");
    let _ = writeln!(output, "{SCOPE_NOTICE}");
    let _ = writeln!(output, "manifest identity\t{}", reference.manifest_sha256);
    let _ = writeln!(
        output,
        "package contract identity\t{}",
        reference.package_digest
    );

    output.push_str("\nPACKAGE INTERFACES\n");
    if reference.interfaces.is_empty() {
        output.push_str("No package-owned interfaces are declared.\n");
    }
    for (alias, document) in &reference.interfaces {
        let interface = &document.interface;
        let _ = writeln!(
            output,
            "declared interface\t{}\t{}\tABI {}\t{}",
            alias.as_str(),
            interface.name.as_str(),
            interface.abi,
            interface.description,
        );
        output.push_str("  declared request or contribution schema\n");
        indented_schema(&mut output, &interface.request, "    ");
        for (name, declared_output) in &interface.outputs {
            let _ = writeln!(
                output,
                "  declared aggregate output\t{}\t{}",
                name.as_str(),
                declared_output.description,
            );
        }
        for (name, method) in &interface.methods {
            let _ = writeln!(
                output,
                "  declared method\t{}\t{}",
                name.as_str(),
                method.description,
            );
            for (output_name, declared_output) in &method.outputs {
                let _ = writeln!(
                    output,
                    "    declared method output\t{}\t{}",
                    output_name.as_str(),
                    declared_output.description,
                );
            }
        }
    }

    output.push_str("\nPROVIDER IMPLEMENTATIONS\n");
    if reference.implementations.is_empty() {
        output.push_str("No provider implementations are declared.\n");
    }
    for implementation in &reference.implementations {
        let _ = writeln!(
            output,
            "declared implementation\t{}\t{}\t{}",
            implementation.name.as_str(),
            implementation.interface.name.as_str(),
            implementation.description
        );
    }

    output.push_str("\nEXECUTION GUARANTEES\n");
    if reference.guarantees.is_empty() {
        output.push_str("No package-owned execution guarantees are declared.\n");
    }
    for (alias, guarantee) in &reference.guarantees {
        let _ = writeln!(
            output,
            "declared guarantee\t{}\t{} v{}\t{}",
            alias.as_str(),
            guarantee.name.as_str(),
            guarantee.version,
            guarantee.description
        );
        let _ = writeln!(output, "  semantics\t{}", guarantee.semantics);
    }

    output.push_str("\nPROVIDED ABILITIES\n");
    if reference.exports.is_empty() {
        output.push_str("No provider interfaces are declared.\n");
    }
    for export in &reference.exports {
        let Ok(interface_document) = reference.interface_for_export(export) else {
            let _ = writeln!(
                output,
                "declared export\t{}\tretained interface document unavailable",
                export.name.as_str()
            );
            continue;
        };
        let interface = &interface_document.interface;
        let descriptor = export.interface.descriptor;
        let _ = writeln!(
            output,
            "declared export\t{}\t{}\tABI {}",
            export.name.as_str(),
            interface.name.as_str(),
            interface.abi
        );
        let _ = writeln!(output, "  description\t{}", interface.description);
        let _ = writeln!(output, "  descriptor identity\t{descriptor}");
        let _ = writeln!(
            output,
            "  implementation identity\t{}",
            export.implementation
        );
        output.push_str("  declared request or contribution schema\n");
        indented_schema(&mut output, &interface.request, "    ");
        if let Some(configuration) = &interface.configuration {
            output.push_str("  declared operator-owned provider instance configuration schema\n");
            indented_schema(&mut output, configuration, "    ");
        } else {
            output.push_str("  no operator-owned provider instance configuration is declared\n");
        }

        for (name, declared_output) in &interface.outputs {
            let _ = writeln!(
                output,
                "  declared aggregate output\t{}\t{}\t{}\t{}",
                name.as_str(),
                scalar(&declared_output.phase),
                scalar(&declared_output.visibility),
                scalar(&declared_output.lifetime)
            );
            let _ = writeln!(output, "    description\t{}", declared_output.description);
        }
        for (name, method) in &interface.methods {
            let operations = method
                .permitted_operations
                .iter()
                .map(|operation| operation.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                output,
                "  declared method\t{}\t{}\ttarget {}\toperations [{}]",
                name.as_str(),
                scalar(&method.semantics),
                method.target_resource.as_str(),
                operations
            );
            let _ = writeln!(output, "    description\t{}", method.description);
            for (output_name, declared_output) in &method.outputs {
                let _ = writeln!(
                    output,
                    "    declared method output\t{}\t{}",
                    output_name.as_str(),
                    declared_output.description
                );
            }
        }

        let lifecycle = &interface.lifecycle;
        if let Some(method) = &lifecycle.persistent_delete_method {
            let _ = writeln!(
                output,
                "  declared persistent deletion method\t{}",
                method.as_str()
            );
        }
        let aggregation = &interface.aggregation;
        let _ = writeln!(
            output,
            "  declared contribution aggregation\tkey {}\tcontroller group {}\tslot collisions {}",
            aggregation.key.as_str(),
            aggregation.controller_group.as_str(),
            if aggregation.reject_slot_collisions {
                "rejected"
            } else {
                "allowed"
            }
        );
    }

    output.push_str("\nCONSUMED ABILITIES\n");
    if reference.requirements.is_empty()
        && reference
            .exports
            .iter()
            .all(|export| export.requirements.is_empty())
    {
        output.push_str("No consumed ability requirements are declared.\n");
    }
    for requirement in &reference.requirements {
        plain_requirement(&mut output, "package", requirement);
    }
    for export in &reference.exports {
        let consumer = format!("export {}", export.name.as_str());
        for requirement in &export.requirements {
            plain_requirement(&mut output, &consumer, requirement);
        }
    }

    if !reference.handlers.is_empty() {
        output.push_str("\nDECLARED STRUCTURED EFFECT HANDLERS\n");
        for handler in &reference.handlers {
            let entry_point = safe_plain_text(&handler.entry_point);
            let _ = writeln!(
                output,
                "declared handler\t{}\tentry point {}",
                handler.name.as_str(),
                entry_point
            );
            output.push_str("  declared arguments schema\n");
            indented_schema(&mut output, &handler.arguments, "    ");
            output.push_str("  declared result schema\n");
            indented_schema(&mut output, &handler.result, "    ");
        }
    }

    output
}

pub(crate) fn plain_absent() -> String {
    concat!(
        "\nDECLARED ABILITIES\n------------------\n",
        "No checked signed ability projection is available for this package.\n",
        "\nPROVIDED ABILITIES\n",
        "No provided abilities are declared.\n",
        "\nCONSUMED ABILITIES\n",
        "No consumed abilities are declared.\n",
    )
    .to_string()
}

pub(crate) fn html(reference: &PackageAbilityReference) -> String {
    let mut output =
        String::from("<section id=\"declared-abilities\"><h2>Declared abilities</h2><p>");
    escape_html_into(SCOPE_NOTICE, &mut output);
    output.push_str("</p><dl><dt>Manifest identity</dt><dd><code>");
    escape_html_into(&reference.manifest_sha256.to_string(), &mut output);
    output.push_str("</code></dd><dt>Package contract identity</dt><dd><code>");
    escape_html_into(&reference.package_digest.to_string(), &mut output);
    output.push_str("</code></dd></dl>");

    output.push_str("<h3>Package interfaces</h3>");
    if reference.interfaces.is_empty() {
        output.push_str("<p>No package-owned interfaces are declared.</p>");
    }
    for (alias, document) in &reference.interfaces {
        let interface = &document.interface;
        output.push_str("<article><h4><code>");
        escape_html_into(alias.as_str(), &mut output);
        output.push_str("</code>: <code>");
        escape_html_into(interface.name.as_str(), &mut output);
        let _ = write!(output, "</code> ABI {}</h4><p>", interface.abi);
        escape_html_into(&interface.description, &mut output);
        output.push_str("</p><h5>Request or contribution schema</h5>");
        schema_html(&mut output, &interface.request);
        if !interface.outputs.is_empty() {
            output.push_str("<h5>Aggregate outputs</h5><ul>");
            for (name, declared_output) in &interface.outputs {
                output.push_str("<li><code>");
                escape_html_into(name.as_str(), &mut output);
                output.push_str("</code> — ");
                escape_html_into(&declared_output.description, &mut output);
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }
        if !interface.methods.is_empty() {
            output.push_str("<h5>Methods</h5><ul>");
            for (name, method) in &interface.methods {
                output.push_str("<li><code>");
                escape_html_into(name.as_str(), &mut output);
                output.push_str("</code> — ");
                escape_html_into(&method.description, &mut output);
                for (output_name, declared_output) in &method.outputs {
                    output.push_str("; output <code>");
                    escape_html_into(output_name.as_str(), &mut output);
                    output.push_str("</code>: ");
                    escape_html_into(&declared_output.description, &mut output);
                }
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }
        output.push_str("</article>");
    }

    output.push_str("<h3>Provider implementations</h3>");
    if reference.implementations.is_empty() {
        output.push_str("<p>No provider implementations are declared.</p>");
    }
    for implementation in &reference.implementations {
        output.push_str("<article><h4><code>");
        escape_html_into(implementation.name.as_str(), &mut output);
        output.push_str("</code></h4><p>");
        escape_html_into(&implementation.description, &mut output);
        output.push_str("</p><p>Implements <code>");
        escape_html_into(implementation.interface.name.as_str(), &mut output);
        output.push_str("</code>.</p></article>");
    }

    output.push_str("<h3>Execution guarantees</h3>");
    if reference.guarantees.is_empty() {
        output.push_str("<p>No package-owned execution guarantees are declared.</p>");
    }
    for (alias, guarantee) in &reference.guarantees {
        output.push_str("<article><h4><code>");
        escape_html_into(alias.as_str(), &mut output);
        output.push_str("</code></h4><p>");
        escape_html_into(&guarantee.description, &mut output);
        output.push_str("</p><p><code>");
        escape_html_into(guarantee.name.as_str(), &mut output);
        let _ = write!(output, "</code> v{}: ", guarantee.version);
        escape_html_into(&guarantee.semantics, &mut output);
        output.push_str("</p></article>");
    }

    output.push_str("<h3>Provided abilities</h3>");

    if reference.exports.is_empty() {
        output.push_str("<p>No provider interfaces are declared.</p>");
    }
    for export in &reference.exports {
        let Ok(interface_document) = reference.interface_for_export(export) else {
            output.push_str("<p>The checked export has no retained interface document.</p>");
            continue;
        };
        let interface = &interface_document.interface;
        let descriptor = export.interface.descriptor;
        output.push_str("<article><h4>Declared export <code>");
        escape_html_into(export.name.as_str(), &mut output);
        output.push_str("</code></h4><dl><dt>Interface</dt><dd><code>");
        escape_html_into(interface.name.as_str(), &mut output);
        let _ = write!(output, "</code> ABI {}</dd>", interface.abi);
        output.push_str("<dt>Description</dt><dd>");
        escape_html_into(&interface.description, &mut output);
        output.push_str("</dd>");
        output.push_str("<dt>Descriptor identity</dt><dd><code>");
        escape_html_into(&descriptor.to_string(), &mut output);
        output.push_str("</code></dd><dt>Implementation identity</dt><dd><code>");
        escape_html_into(&export.implementation.to_string(), &mut output);
        output.push_str("</code></dd></dl><h5>Declared request or contribution schema</h5>");
        schema_html(&mut output, &interface.request);
        if let Some(configuration) = &interface.configuration {
            output.push_str(
                "<h5>Declared operator-owned provider instance configuration schema</h5>",
            );
            schema_html(&mut output, configuration);
        } else {
            output
                .push_str("<p>No operator-owned provider instance configuration is declared.</p>");
        }

        if !interface.outputs.is_empty() {
            output.push_str("<h5>Declared aggregate outputs</h5><ul>");
            for (name, declared_output) in &interface.outputs {
                output.push_str("<li><code>");
                escape_html_into(name.as_str(), &mut output);
                output.push_str("</code> - ");
                escape_html_into(&scalar(&declared_output.phase), &mut output);
                output.push_str(", ");
                escape_html_into(&scalar(&declared_output.visibility), &mut output);
                output.push_str(", ");
                escape_html_into(&scalar(&declared_output.lifetime), &mut output);
                output.push_str(" - ");
                escape_html_into(&declared_output.description, &mut output);
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }
        if !interface.methods.is_empty() {
            output.push_str("<h5>Declared methods</h5><ul>");
            for (name, method) in &interface.methods {
                output.push_str("<li><code>");
                escape_html_into(name.as_str(), &mut output);
                output.push_str("</code> - ");
                escape_html_into(&scalar(&method.semantics), &mut output);
                output.push_str(" - ");
                escape_html_into(&method.description, &mut output);
                output.push_str(" targeting <code>");
                escape_html_into(method.target_resource.as_str(), &mut output);
                output.push_str("</code>");
                if !method.permitted_operations.is_empty() {
                    output.push_str("; operations: ");
                    for (index, operation) in method.permitted_operations.iter().enumerate() {
                        if index > 0 {
                            output.push_str(", ");
                        }
                        output.push_str("<code>");
                        escape_html_into(operation.as_str(), &mut output);
                        output.push_str("</code>");
                    }
                }
                for (output_name, declared_output) in &method.outputs {
                    output.push_str("; output <code>");
                    escape_html_into(output_name.as_str(), &mut output);
                    output.push_str("</code>: ");
                    escape_html_into(&declared_output.description, &mut output);
                }
                output.push_str("</li>");
            }
            output.push_str("</ul>");
        }

        let lifecycle = &interface.lifecycle;
        output.push_str("<h5>Declared lifecycle contract</h5><ul>");
        if let Some(method) = &lifecycle.persistent_delete_method {
            output.push_str("<li>Declared persistent deletion method: <code>");
            escape_html_into(method.as_str(), &mut output);
            output.push_str("</code></li>");
        } else {
            output.push_str("<li>No persistent deletion method declared.</li>");
        }
        output.push_str("</ul>");

        let aggregation = &interface.aggregation;
        output.push_str("<h5>Declared contribution aggregation</h5><p>Key <code>");
        escape_html_into(aggregation.key.as_str(), &mut output);
        output.push_str("</code>; controller group <code>");
        escape_html_into(aggregation.controller_group.as_str(), &mut output);
        output.push_str("</code>; slot collisions are ");
        output.push_str(if aggregation.reject_slot_collisions {
            "rejected"
        } else {
            "allowed"
        });
        output.push_str(".</p>");
        output.push_str("</article>");
    }

    output.push_str("<h3>Consumed abilities</h3>");
    if reference.requirements.is_empty()
        && reference
            .exports
            .iter()
            .all(|export| export.requirements.is_empty())
    {
        output.push_str("<p>No consumed ability requirements are declared.</p>");
    } else {
        output.push_str("<ul>");
        for requirement in &reference.requirements {
            html_requirement(&mut output, "package", requirement);
        }
        for export in &reference.exports {
            let consumer = format!("export {}", export.name.as_str());
            for requirement in &export.requirements {
                html_requirement(&mut output, &consumer, requirement);
            }
        }
        output.push_str("</ul>");
    }

    if !reference.handlers.is_empty() {
        output.push_str("<h3>Declared structured effect handlers</h3>");
        for handler in &reference.handlers {
            output.push_str("<article><h4>Declared handler <code>");
            escape_html_into(handler.name.as_str(), &mut output);
            output.push_str("</code></h4><p>Authenticated entry point <code>");
            escape_html_into(&handler.entry_point, &mut output);
            output.push_str("</code></p><h5>Declared arguments schema</h5>");
            schema_html(&mut output, &handler.arguments);
            output.push_str("<h5>Declared result schema</h5>");
            schema_html(&mut output, &handler.result);
            output.push_str("</article>");
        }
    }

    output.push_str("</section>");
    output
}

pub(crate) fn html_absent() -> String {
    concat!(
        "<section id=\"declared-abilities\"><h2>Declared abilities</h2>",
        "<p>No checked signed ability projection is available for this package.</p>",
        "<h3>Provided abilities</h3><p>No provided abilities are declared.</p>",
        "<h3>Consumed abilities</h3><p>No consumed abilities are declared.</p>",
        "</section>",
    )
    .to_string()
}

pub(crate) fn roff(reference: &PackageAbilityReference) -> String {
    plain_to_roff(&plain(reference))
}

pub(crate) fn roff_absent() -> String {
    plain_to_roff(&plain_absent())
}

fn plain_to_roff(plain: &str) -> String {
    let mut output = String::from(".SH \"DECLARED ABILITIES\"\n.nf\n");
    for line in plain
        .strip_prefix("\nDECLARED ABILITIES\n------------------\n")
        .unwrap_or(plain)
        .lines()
    {
        if line.starts_with('.') || line.starts_with('\'') {
            output.push_str("\\&");
        }
        for character in line.chars() {
            if character == '\\' {
                output.push_str("\\e");
            } else {
                output.push(character);
            }
        }
        output.push('\n');
    }
    output.push_str(".fi\n");
    output
}

fn plain_requirement(output: &mut String, consumer: &str, requirement: &RequirementDeclaration) {
    let _ = writeln!(
        output,
        "declared requirement\t{}\t{}\tconsumed by {}",
        requirement.alias.as_str(),
        requirement_strength(requirement.strength),
        consumer,
    );
    let _ = writeln!(output, "  description\t{}", requirement.description);
    for accepted in &requirement.accepted_interfaces {
        let descriptor = accepted.descriptor.map_or_else(
            || "any compatible descriptor".to_string(),
            |digest| digest.to_string(),
        );
        let _ = writeln!(
            output,
            "  accepted interface\t{}\tABI {}\t{}",
            accepted.name.as_str(),
            accepted.abi,
            descriptor,
        );
    }
    if !requirement.methods.is_empty() {
        let methods = requirement
            .methods
            .iter()
            .map(|method| method.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(output, "  declared methods\t{methods}");
    }
    if requirement.fallback.is_some() {
        output.push_str("  authenticated fallback output contract declared\n");
    }
}

fn html_requirement(output: &mut String, consumer: &str, requirement: &RequirementDeclaration) {
    output.push_str("<li>Declared requirement <strong>");
    escape_html_into(requirement.alias.as_str(), output);
    output.push_str("</strong> (");
    output.push_str(requirement_strength(requirement.strength));
    output.push_str(") consumed by <code>");
    escape_html_into(consumer, output);
    output.push_str("</code> — ");
    escape_html_into(&requirement.description, output);
    output.push_str("<ul>");
    for accepted in &requirement.accepted_interfaces {
        output.push_str("<li>Accepted interface <code>");
        escape_html_into(accepted.name.as_str(), output);
        let _ = write!(output, "</code> ABI {} - <code>", accepted.abi);
        let descriptor = accepted.descriptor.map_or_else(
            || "any compatible descriptor".to_string(),
            |digest| digest.to_string(),
        );
        escape_html_into(&descriptor, output);
        output.push_str("</code></li>");
    }
    if !requirement.methods.is_empty() {
        output.push_str("<li>Declared methods: ");
        for (index, method) in requirement.methods.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str("<code>");
            escape_html_into(method.as_str(), output);
            output.push_str("</code>");
        }
        output.push_str("</li>");
    }
    if requirement.fallback.is_some() {
        output.push_str("<li>Authenticated fallback output contract declared.</li>");
    }
    output.push_str("</ul></li>");
}

fn indented_schema(output: &mut String, schema: &ValueSchema, indent: &str) {
    let rendered = serde_json::to_string_pretty(schema)
        .unwrap_or_else(|_| "{\"kind\":\"unavailable\"}".to_string());
    for line in rendered.lines() {
        let _ = writeln!(output, "{indent}{line}");
    }
}

fn schema_html(output: &mut String, schema: &ValueSchema) {
    let rendered = serde_json::to_string_pretty(schema)
        .unwrap_or_else(|_| "{\"kind\":\"unavailable\"}".to_string());
    output.push_str("<pre>");
    escape_html_into(&rendered, output);
    output.push_str("</pre>");
}

fn scalar(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value)
        .map(|encoded| encoded.trim_matches('"').to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
}

fn safe_plain_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

const fn requirement_strength(strength: RequirementStrength) -> &'static str {
    match strength {
        RequirementStrength::Required => "required",
        RequirementStrength::Advisory => "advisory",
    }
}

fn escape_html_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            character if character.is_control() => {
                let _ = write!(output, "&#x{:x};", u32::from(character));
            }
            _ => output.push(character),
        }
    }
}
